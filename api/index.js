const express = require("express");
const cors = require("cors");
const { query } = require("../lib/db");
const { signToken } = require("../lib/auth");
const { jsonError, requireAuth, requireRole, rateLimit } = require("../lib/middleware");

const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(rateLimit({ windowMs: 60_000, max: 180 }));

// CORS: restrict to the frontend domain(s)
const origins = (process.env.FRONTEND_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function(origin, cb) {
    // In production, block requests without Origin to reduce abuse.
    // In local dev, allow tools like curl/postman.
    if (!origin) {
      if ((process.env.NODE_ENV || '').toLowerCase() === 'production') return cb(new Error('Not allowed by CORS'));
      return cb(null, true);
    }
    if (origins.length === 0) return cb(null, true);
    if (origins.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: false,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Root (help)
app.get("/", (req, res) => {
  res.json({ ok: true, service: "svfit-backend", health: "/api/health" });
});

// Basic health
app.get("/api/health", async (req, res) => {
  try {
    const r = await query("select now() as now");
    res.json({ ok: true, db_time: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: "DB not reachable" });
  }
});

// ---- AUTH ----
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return jsonError(res, 400, "email and password required");

  const sql = `
    select id, email, full_name, role
    from users
    where email = $1
      and password_hash = crypt($2, password_hash)
    limit 1
  `;
  const r = await query(sql, [String(email).toLowerCase(), String(password)]);
  if (r.rowCount === 0) return jsonError(res, 401, "Invalid credentials");

  const u = r.rows[0];
  const token = signToken({ sub: u.id, email: u.email, role: u.role, name: u.full_name });

  res.json({ ok: true, token, user: { id: u.id, email: u.email, role: u.role, name: u.full_name } });
});

// Open registration for members only (admin users should be created via seed and managed inside app)
app.post("/api/auth/register", async (req, res) => {
  const { full_name, email, password, phone } = req.body || {};
  if (!full_name || !email || !password) return jsonError(res, 400, "full_name, email, password required");

  const emailNorm = String(email).toLowerCase().trim();
  if (String(password).length < 8) return jsonError(res, 400, "Password must be at least 8 characters");

  try {
    const sql = `
      insert into users (email, full_name, role, password_hash)
      values ($1, $2, 'member', crypt($3, gen_salt('bf', 10)))
      returning id, email, full_name, role
    `;
    const r = await query(sql, [emailNorm, String(full_name).trim(), String(password)]);
    const u = r.rows[0];

    // Create a member record linked to the user
    await query(
      `insert into members (user_id, full_name, phone, email, status, join_date)
       values ($1, $2, $3, $4, 'active', now()::date)`,
      [u.id, u.full_name, phone ? String(phone) : null, u.email]
    );

    const token = signToken({ sub: u.id, email: u.email, role: u.role, name: u.full_name });
    res.status(201).json({ ok: true, token, user: { id: u.id, email: u.email, role: u.role, name: u.full_name } });
  } catch (err) {
    if ((err.message || "").includes("users_email_key")) {
      return jsonError(res, 409, "Email already registered");
    }
    return jsonError(res, 500, "Registration failed");
  }
});

app.get("/api/me", requireAuth, async (req, res) => {
  const r = await query("select id, email, full_name, role, created_at from users where id=$1", [req.user.sub]);
  if (r.rowCount === 0) return jsonError(res, 404, "User not found");
  res.json({ ok: true, user: r.rows[0] });
});

// ---- DASHBOARD ----
app.get("/api/dashboard/summary", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const sql = `
    select
      (select count(*)::int from members where status='active') as active_members,
      (select count(*)::int from attendance where checkin_at::date = now()::date) as checkins_today,
      (select coalesce(sum(amount_mxn),0)::numeric(12,2) from payments where paid_at::date = now()::date) as revenue_today,
      (select count(*)::int from classes where starts_at >= now() and starts_at < now() + interval '7 days') as classes_next_7_days
  `;
  const r = await query(sql);
  res.json({ ok: true, summary: r.rows[0] });
});

// ---- MEMBERS ----
app.get("/api/members", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const q = (req.query.q || "").toString().trim();
  const params = [];
  let where = "where 1=1";
  if (q) {
    params.push(`%${q.toLowerCase()}%`);
    where += ` and (lower(full_name) like $${params.length} or lower(email) like $${params.length} or phone like $${params.length})`;
  }

  const r = await query(
    `select id, full_name, phone, email, status, join_date, notes
     from members ${where}
     order by join_date desc, full_name asc
     limit 200`,
    params
  );
  res.json({ ok: true, members: r.rows });
});

app.post("/api/members", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const { full_name, phone, email, status, join_date, notes } = req.body || {};
  if (!full_name) return jsonError(res, 400, "full_name required");

  const r = await query(
    `insert into members (full_name, phone, email, status, join_date, notes)
     values ($1, $2, $3, $4, coalesce($5::date, now()::date), $6)
     returning id, full_name, phone, email, status, join_date, notes`,
    [
      String(full_name).trim(),
      phone ? String(phone).trim() : null,
      email ? String(email).toLowerCase().trim() : null,
      status ? String(status) : "active",
      join_date ? String(join_date) : null,
      notes ? String(notes) : null
    ]
  );

  res.status(201).json({ ok: true, member: r.rows[0] });
});


app.get("/api/members/:id", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const id = req.params.id;
  const r = await query(`select * from members where id=$1`, [id]);
  if (r.rowCount === 0) return jsonError(res, 404, "Member not found");
  res.json({ ok: true, member: r.rows[0] });
});

app.put("/api/members/:id", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const id = req.params.id;
  const { full_name, phone, email, status, join_date, notes } = req.body || {};

  // For consistent behavior, the frontend should send the full member payload on save.
  const r = await query(
    `update members
     set full_name = coalesce($2, full_name),
         phone = $3,
         email = $4,
         status = coalesce($5, status),
         join_date = coalesce($6::date, join_date),
         notes = $7,
         updated_at = now()
     where id = $1
     returning id, full_name, phone, email, status, join_date, notes, updated_at`,
    [
      id,
      full_name ? String(full_name).trim() : null,
      phone === "" ? null : (phone ? String(phone).trim() : null),
      email === "" ? null : (email ? String(email).toLowerCase().trim() : null),
      status ? String(status) : null,
      join_date ? String(join_date) : null,
      notes === "" ? null : (notes ? String(notes) : null)
    ]
  );
  if (r.rowCount === 0) return jsonError(res, 404, "Member not found");
  res.json({ ok: true, member: r.rows[0] });
});


app.delete("/api/members/:id", requireAuth, requireRole(["admin"]), async (req, res) => {
  const id = req.params.id;
  const r = await query("delete from members where id=$1 returning id", [id]);
  if (r.rowCount === 0) return jsonError(res, 404, "Member not found");
  res.json({ ok: true });
});

// ---- ATTENDANCE ----
app.post("/api/attendance/checkin", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const { member_id, method } = req.body || {};
  if (!member_id) return jsonError(res, 400, "member_id required");

  const m = await query("select id, full_name from members where id=$1 and status='active'", [member_id]);
  if (m.rowCount === 0) return jsonError(res, 404, "Active member not found");

  const r = await query(
    `insert into attendance (member_id, method) values ($1, $2)
     returning id, member_id, checkin_at, method`,
    [member_id, method ? String(method) : "manual"]
  );
  res.status(201).json({ ok: true, checkin: r.rows[0] });
});

app.get("/api/attendance", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const member_id = req.query.member_id ? String(req.query.member_id) : null;
  const from = req.query.from ? String(req.query.from) : null;
  const to = req.query.to ? String(req.query.to) : null;

  const params = [];
  let where = "where 1=1";
  if (member_id) { params.push(member_id); where += ` and a.member_id = $${params.length}`; }
  if (from) { params.push(from); where += ` and a.checkin_at::date >= $${params.length}::date`; }
  if (to) { params.push(to); where += ` and a.checkin_at::date <= $${params.length}::date`; }

  const r = await query(
    `select a.id, a.checkin_at, a.method, m.id as member_id, m.full_name as member_name
     from attendance a
     join members m on m.id = a.member_id
     ${where}
     order by a.checkin_at desc
     limit 500`,
    params
  );
  res.json({ ok: true, attendance: r.rows });
});

// ---- PAYMENTS ----
app.post("/api/payments", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const { member_id, amount_mxn, method, reference } = req.body || {};
  if (!member_id || amount_mxn === undefined) return jsonError(res, 400, "member_id and amount_mxn required");

  const r = await query(
    `insert into payments (member_id, amount_mxn, method, reference)
     values ($1, $2, $3, $4)
     returning id, member_id, amount_mxn, paid_at, method, reference`,
    [member_id, Number(amount_mxn), method ? String(method) : "cash", reference ? String(reference) : null]
  );
  res.status(201).json({ ok: true, payment: r.rows[0] });
});

app.get("/api/payments", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const member_id = req.query.member_id ? String(req.query.member_id) : null;

  const params = [];
  let where = "where 1=1";
  if (member_id) { params.push(member_id); where += ` and p.member_id=$${params.length}`; }

  const r = await query(
    `select p.id, p.amount_mxn, p.paid_at, p.method, p.reference,
            m.id as member_id, m.full_name as member_name
     from payments p
     join members m on m.id = p.member_id
     ${where}
     order by p.paid_at desc
     limit 500`,
    params
  );
  res.json({ ok: true, payments: r.rows });
});

// ---- CLASSES ----
app.get("/api/classes", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const r = await query(
    `select c.*,
            (select count(*)::int from class_enrollments e where e.class_id=c.id and e.status='enrolled') as enrolled
     from classes c
     order by c.starts_at asc
     limit 200`
  );
  res.json({ ok: true, classes: r.rows });
});

app.post("/api/classes", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const { title, coach_name, starts_at, ends_at, capacity } = req.body || {};
  if (!title || !starts_at || !ends_at) return jsonError(res, 400, "title, starts_at, ends_at required");

  const r = await query(
    `insert into classes (title, coach_name, starts_at, ends_at, capacity)
     values ($1, $2, $3::timestamptz, $4::timestamptz, $5)
     returning *`,
    [
      String(title).trim(),
      coach_name ? String(coach_name).trim() : null,
      String(starts_at),
      String(ends_at),
      capacity === undefined ? 20 : Number(capacity)
    ]
  );
  res.status(201).json({ ok: true, klass: r.rows[0] });
});

app.post("/api/classes/:id/enroll", requireAuth, requireRole(["admin", "coach"]), async (req, res) => {
  const class_id = req.params.id;
  const { member_id } = req.body || {};
  if (!member_id) return jsonError(res, 400, "member_id required");

  const cls = await query("select id, capacity from classes where id=$1", [class_id]);
  if (cls.rowCount === 0) return jsonError(res, 404, "Class not found");

  const enrolled = await query(
    "select count(*)::int as c from class_enrollments where class_id=$1 and status='enrolled'",
    [class_id]
  );
  if (enrolled.rows[0].c >= cls.rows[0].capacity) return jsonError(res, 409, "Class is full");

  try {
    const r = await query(
      `insert into class_enrollments (class_id, member_id, status)
       values ($1, $2, 'enrolled')
       on conflict (class_id, member_id) do update set status='enrolled', updated_at=now()
       returning *`,
      [class_id, member_id]
    );
    res.status(201).json({ ok: true, enrollment: r.rows[0] });
  } catch (err) {
    return jsonError(res, 500, "Enrollment failed");
  }
});

// ---- ERROR HANDLING ----
app.use((err, req, res, next) => {
  if (err && err.message === "Not allowed by CORS") {
    return res.status(403).json({ ok: false, error: "CORS blocked: origin not allowed" });
  }
  console.error(err);
  return res.status(500).json({ ok: false, error: "Internal error" });
});

module.exports = app;

// Local dev support (node api/index.js)
if (require.main === module) {
  const port = process.env.PORT || 3001;
  app.listen(port, () => console.log(`SVFIT backend listening on http://localhost:${port}`));
}
