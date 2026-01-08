const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { z } = require('zod');

const db = require('../lib/db');
const { signToken, authMiddleware } = require('../lib/auth');
const { requireRole } = require('../lib/rbac');

const app = express();

// ---- CORS ----
// Nota: CORS solo afecta a navegadores. Permitimos requests sin Origin (curl / health checks).
function parseAllowedOrigins() {
  const raw = process.env.FRONTEND_ORIGINS || '';
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function originAllowed(origin, allowed) {
  if (!origin) return true;

  if (allowed.includes(origin)) return true;

  const hasWildcard = allowed.includes('*.vercel.app');
  if (hasWildcard) {
    try {
      const u = new URL(origin);
      if (u.hostname.endsWith('.vercel.app')) return true;
    } catch {}
  }
  return false;
}

app.use(cors({
  origin: function(origin, cb) {
    const allowed = parseAllowedOrigins();
    if (originAllowed(origin, allowed)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));

// Friendly CORS error
app.use((err, req, res, next) => {
  if (err && String(err.message).includes('Not allowed by CORS')) {
    return res.status(403).json({ ok: false, error: 'CORS blocked: origin not allowed' });
  }
  next(err);
});

// ---- Helpers ----
async function getUserByEmail(email) {
  const r = await db.query('SELECT * FROM users WHERE email=$1 AND active=TRUE', [email]);
  return r.rows[0] || null;
}

async function getUserById(id) {
  const r = await db.query('SELECT id,email,name,role,member_id,active,created_at FROM users WHERE id=$1', [id]);
  return r.rows[0] || null;
}

// ---- Health ----
app.get('/api/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ ok: true, service: 'svfit-backend', time: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'DB not reachable' });
  }
});

// ---- Setup (one-time) ----
app.post('/api/setup', async (req, res) => {
  const schema = z.object({ setupKey: z.string().min(6) });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const expected = process.env.SETUP_KEY;
  if (!expected) return res.status(403).json({ ok: false, error: 'SETUP_KEY not configured on server' });
  if (parsed.data.setupKey !== expected) return res.status(403).json({ ok: false, error: 'Invalid setupKey' });

  const s = await db.query("SELECT value FROM settings WHERE key='setup_done'");
  if (s.rows[0]?.value === 'true') return res.json({ ok: true, message: 'Setup already done' });

  // Create demo member
  const member = await db.query(
    "INSERT INTO members(first_name,last_name,email,phone,notes) VALUES ($1,$2,$3,$4,$5) RETURNING id",
    ['Carlos', 'Miembro', 'member@svfit.mx', '0000000000', 'Usuario demo']
  );
  const memberId = member.rows[0].id;

  // Create demo users
  const users = [
    { email: 'admin@svfit.mx', name: 'Admin SVFIT', role: 'admin', pass: 'Admin123!', member_id: null },
    { email: 'staff@svfit.mx', name: 'Staff SVFIT', role: 'staff', pass: 'Staff123!', member_id: null },
    { email: 'coach@svfit.mx', name: 'Coach SVFIT', role: 'coach', pass: 'Coach123!', member_id: null },
    { email: 'member@svfit.mx', name: 'Carlos Miembro', role: 'member', pass: 'Member123!', member_id: memberId }
  ];

  for (const u of users) {
    const existing = await db.query('SELECT id FROM users WHERE email=$1', [u.email]);
    if (existing.rows.length) continue;

    const hash = await bcrypt.hash(u.pass, 10);
    await db.query(
      'INSERT INTO users(email,name,password_hash,role,member_id) VALUES ($1,$2,$3,$4,$5)',
      [u.email, u.name, hash, u.role, u.member_id]
    );
  }

  // Seed plans (unique by name)
  const plans = [
    { name: 'Mensual', duration_days: 30, price_cents: 69900 },
    { name: 'Trimestral', duration_days: 90, price_cents: 189900 },
    { name: 'Anual', duration_days: 365, price_cents: 599900 }
  ];
  for (const p of plans) {
    await db.query(
      'INSERT INTO plans(name,duration_days,price_cents,active) VALUES ($1,$2,$3,TRUE) ON CONFLICT (name) DO NOTHING',
      [p.name, p.duration_days, p.price_cents]
    );
  }

  // Seed products (unique by sku)
  const products = [
    { sku: 'AGUA-600', name: 'Agua 600ml', price_cents: 2500, cost_cents: 1200, stock: 48 },
    { sku: 'BARRA-PRO', name: 'Barra Proteína', price_cents: 3500, cost_cents: 2000, stock: 24 }
  ];
  for (const pr of products) {
    await db.query(
      'INSERT INTO products(sku,name,price_cents,cost_cents,stock,active) VALUES ($1,$2,$3,$4,$5,TRUE) ON CONFLICT (sku) DO NOTHING',
      [pr.sku, pr.name, pr.price_cents, pr.cost_cents, pr.stock]
    );
  }

  await db.query(
    "INSERT INTO settings(key,value) VALUES ('setup_done','true') " +
    "ON CONFLICT (key) DO UPDATE SET value='true', updated_at=now()"
  );

  res.json({ ok: true, message: 'Setup completed. Remove SETUP_KEY now.' });
});

// ---- Auth ----
app.post('/api/auth/login', async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(4)
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const user = await getUserByEmail(parsed.data.email.toLowerCase());
  if (!user) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

  const ok = await bcrypt.compare(parsed.data.password, user.password_hash);
  if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

  const token = signToken({ sub: user.id, role: user.role, email: user.email, member_id: user.member_id || null });
  res.json({ ok: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role, member_id: user.member_id } });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const u = await getUserById(req.auth.sub);
  res.json({ ok: true, user: u });
});

// ---- Users (admin/staff) ----
app.get('/api/users', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const r = await db.query('SELECT id,email,name,role,member_id,active,created_at FROM users ORDER BY created_at DESC');
  res.json({ ok: true, users: r.rows });
});

app.post('/api/users', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    name: z.string().min(2),
    role: z.enum(['admin','staff','coach','member']),
    password: z.string().min(6),
    member_id: z.number().int().nullable().optional()
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  if (req.auth.role === 'staff' && parsed.data.role === 'admin') {
    return res.status(403).json({ ok: false, error: 'Staff cannot create admin users' });
  }

  const hash = await bcrypt.hash(parsed.data.password, 10);
  try {
    const r = await db.query(
      'INSERT INTO users(email,name,password_hash,role,member_id) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [parsed.data.email.toLowerCase(), parsed.data.name, hash, parsed.data.role, parsed.data.member_id ?? null]
    );
    res.json({ ok: true, id: r.rows[0].id });
  } catch (e) {
    res.status(400).json({ ok: false, error: 'Email already exists or invalid data' });
  }
});

app.put('/api/users/:id', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'Invalid id' });

  const schema = z.object({
    name: z.string().min(2).optional(),
    role: z.enum(['admin','staff','coach','member']).optional(),
    active: z.boolean().optional(),
    password: z.string().min(6).optional()
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  if (req.auth.role === 'staff' && parsed.data.role === 'admin') {
    return res.status(403).json({ ok: false, error: 'Staff cannot promote to admin' });
  }

  const fields = [];
  const params = [];
  let i = 1;

  if (parsed.data.name !== undefined) { fields.push(`name=$${i++}`); params.push(parsed.data.name); }
  if (parsed.data.role !== undefined) { fields.push(`role=$${i++}`); params.push(parsed.data.role); }
  if (parsed.data.active !== undefined) { fields.push(`active=$${i++}`); params.push(parsed.data.active); }
  if (parsed.data.password !== undefined) {
    const hash = await bcrypt.hash(parsed.data.password, 10);
    fields.push(`password_hash=$${i++}`); params.push(hash);
  }

  if (!fields.length) return res.json({ ok: true, message: 'No changes' });

  params.push(id);
  await db.query(`UPDATE users SET ${fields.join(', ')} WHERE id=$${i}`, params);
  res.json({ ok: true });
});

// ---- Members ----
app.get('/api/members', authMiddleware, requireRole(['admin','staff','coach']), async (req, res) => {
  const q = (req.query.q || '').toString().trim().toLowerCase();
  if (q) {
    const r = await db.query(
      `SELECT * FROM members
       WHERE active=TRUE AND (
         lower(first_name) LIKE $1 OR lower(last_name) LIKE $1 OR lower(coalesce(email,'')) LIKE $1 OR lower(coalesce(phone,'')) LIKE $1
       )
       ORDER BY created_at DESC LIMIT 50`,
      [`%${q}%`]
    );
    return res.json({ ok: true, members: r.rows });
  }
  const r = await db.query('SELECT * FROM members WHERE active=TRUE ORDER BY created_at DESC LIMIT 200');
  res.json({ ok: true, members: r.rows });
});

app.post('/api/members', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({
    first_name: z.string().min(2),
    last_name: z.string().min(2),
    email: z.string().email().optional().nullable(),
    phone: z.string().optional().nullable(),
    notes: z.string().optional().nullable()
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const r = await db.query(
    'INSERT INTO members(first_name,last_name,email,phone,notes) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [parsed.data.first_name, parsed.data.last_name, parsed.data.email || null, parsed.data.phone || null, parsed.data.notes || null]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.put('/api/members/:id', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: 'Invalid id' });

  const schema = z.object({
    first_name: z.string().min(2).optional(),
    last_name: z.string().min(2).optional(),
    email: z.string().email().nullable().optional(),
    phone: z.string().nullable().optional(),
    notes: z.string().nullable().optional(),
    active: z.boolean().optional()
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const fields = [];
  const params = [];
  let i = 1;
  for (const k of ['first_name','last_name','email','phone','notes','active']) {
    if (parsed.data[k] !== undefined) {
      fields.push(`${k}=$${i++}`);
      params.push(parsed.data[k]);
    }
  }
  if (!fields.length) return res.json({ ok: true, message: 'No changes' });
  params.push(id);
  await db.query(`UPDATE members SET ${fields.join(', ')} WHERE id=$${i}`, params);
  res.json({ ok: true });
});

// ---- Plans ----
app.get('/api/plans', authMiddleware, requireRole(['admin','staff','coach']), async (req, res) => {
  const r = await db.query('SELECT * FROM plans WHERE active=TRUE ORDER BY price_cents ASC');
  res.json({ ok: true, plans: r.rows });
});

app.post('/api/plans', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    duration_days: z.number().int().min(1),
    price_cents: z.number().int().min(0)
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });
  const r = await db.query(
    'INSERT INTO plans(name,duration_days,price_cents,active) VALUES ($1,$2,$3,TRUE) RETURNING id',
    [parsed.data.name, parsed.data.duration_days, parsed.data.price_cents]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

// ---- Memberships ----
app.get('/api/members/:id/memberships', authMiddleware, requireRole(['admin','staff','coach']), async (req, res) => {
  const memberId = Number(req.params.id);
  const r = await db.query(
    `SELECT m.*, p.name as plan_name, p.duration_days, p.price_cents
     FROM memberships m
     JOIN plans p ON p.id=m.plan_id
     WHERE m.member_id=$1
     ORDER BY m.start_date DESC`,
    [memberId]
  );
  res.json({ ok: true, memberships: r.rows });
});

app.post('/api/members/:id/membership', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const memberId = Number(req.params.id);
  const schema = z.object({
    plan_id: z.number().int(),
    start_date: z.string().optional() // YYYY-MM-DD
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const start = parsed.data.start_date ? new Date(parsed.data.start_date) : new Date();
  if (isNaN(start.getTime())) return res.status(400).json({ ok: false, error: 'Invalid start_date' });

  const plan = await db.query('SELECT * FROM plans WHERE id=$1 AND active=TRUE', [parsed.data.plan_id]);
  if (!plan.rows[0]) return res.status(404).json({ ok: false, error: 'Plan not found' });

  const duration = plan.rows[0].duration_days;
  const end = new Date(start);
  end.setDate(end.getDate() + duration);

  await db.query(
    `UPDATE memberships SET status='expired'
     WHERE member_id=$1 AND status='active' AND end_date >= $2::date`,
    [memberId, start.toISOString().slice(0,10)]
  );

  const r = await db.query(
    `INSERT INTO memberships(member_id,plan_id,start_date,end_date,status,created_by)
     VALUES ($1,$2,$3::date,$4::date,'active',$5) RETURNING id`,
    [memberId, parsed.data.plan_id, start.toISOString().slice(0,10), end.toISOString().slice(0,10), req.auth.sub]
  );
  res.json({ ok: true, id: r.rows[0].id, end_date: end.toISOString().slice(0,10) });
});

app.get('/api/memberships/expiring', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const days = Math.max(1, Math.min(60, Number(req.query.days || 7)));
  const r = await db.query(
    `SELECT m.id as membership_id, m.member_id, m.end_date, mem.first_name, mem.last_name, mem.phone, mem.email, p.name as plan_name
     FROM memberships m
     JOIN members mem ON mem.id=m.member_id
     JOIN plans p ON p.id=m.plan_id
     WHERE m.status='active'
       AND m.end_date BETWEEN CURRENT_DATE AND (CURRENT_DATE + ($1 || ' days')::interval)
     ORDER BY m.end_date ASC`,
    [days]
  );
  res.json({ ok: true, expiring: r.rows, days });
});

// ---- Attendance ----
app.post('/api/members/:id/checkin', authMiddleware, requireRole(['admin','staff','coach']), async (req, res) => {
  const memberId = Number(req.params.id);
  const schema = z.object({ method: z.string().optional() });
  const parsed = schema.safeParse(req.body || {});
  const method = parsed.success ? (parsed.data.method || 'manual') : 'manual';

  await db.query(
    'INSERT INTO attendance(member_id,method,created_by) VALUES ($1,$2,$3)',
    [memberId, method, req.auth.sub]
  );
  res.json({ ok: true });
});

// ---- Products (inventory) admin/staff ----
app.get('/api/products', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const r = await db.query('SELECT * FROM products WHERE active=TRUE ORDER BY created_at DESC');
  res.json({ ok: true, products: r.rows });
});

app.post('/api/products', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({
    sku: z.string().optional().nullable(),
    name: z.string().min(2),
    price_cents: z.number().int().min(0),
    cost_cents: z.number().int().min(0).optional().default(0),
    stock: z.number().int().optional().default(0)
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const r = await db.query(
    'INSERT INTO products(sku,name,price_cents,cost_cents,stock,active) VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING id',
    [parsed.data.sku || null, parsed.data.name, parsed.data.price_cents, parsed.data.cost_cents, parsed.data.stock]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.put('/api/products/:id', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  const schema = z.object({
    sku: z.string().nullable().optional(),
    name: z.string().min(2).optional(),
    price_cents: z.number().int().min(0).optional(),
    cost_cents: z.number().int().min(0).optional(),
    stock: z.number().int().optional(),
    active: z.boolean().optional()
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const fields = [];
  const params = [];
  let i = 1;
  for (const k of ['sku','name','price_cents','cost_cents','stock','active']) {
    if (parsed.data[k] !== undefined) {
      fields.push(`${k}=$${i++}`);
      params.push(parsed.data[k]);
    }
  }
  if (!fields.length) return res.json({ ok: true, message: 'No changes' });
  fields.push('updated_at=now()');
  params.push(id);
  await db.query(`UPDATE products SET ${fields.join(', ')} WHERE id=$${i}`, params);
  res.json({ ok: true });
});

app.delete('/api/products/:id', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  await db.query('UPDATE products SET active=FALSE, updated_at=now() WHERE id=$1', [id]);
  res.json({ ok: true });
});

app.post('/api/products/:id/adjust', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  const schema = z.object({ delta: z.number().int(), note: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const pr = await db.query('SELECT * FROM products WHERE id=$1 AND active=TRUE', [id]);
  if (!pr.rows[0]) return res.status(404).json({ ok: false, error: 'Product not found' });

  await db.query('UPDATE products SET stock = stock + $1, updated_at=now() WHERE id=$2', [parsed.data.delta, id]);
  await db.query(
    'INSERT INTO inventory_movements(product_id,type,quantity,note,created_by) VALUES ($1,$2,$3,$4,$5)',
    [id, 'adjustment', parsed.data.delta, parsed.data.note || null, req.auth.sub]
  );
  res.json({ ok: true });
});

// ---- Cash sessions (corte de caja) admin/staff ----
app.get('/api/cash-sessions/open', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const r = await db.query("SELECT * FROM cash_sessions WHERE status='open' ORDER BY opened_at DESC LIMIT 1");
  res.json({ ok: true, session: r.rows[0] || null });
});

app.post('/api/cash-sessions/open', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({ opening_cash_cents: z.number().int().min(0).default(0), note: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const existing = await db.query("SELECT id FROM cash_sessions WHERE status='open' LIMIT 1");
  if (existing.rows[0]) return res.status(400).json({ ok: false, error: 'There is already an open cash session' });

  const r = await db.query(
    "INSERT INTO cash_sessions(status,opening_cash_cents,opened_by,note) VALUES ('open',$1,$2,$3) RETURNING id",
    [parsed.data.opening_cash_cents, req.auth.sub, parsed.data.note || null]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.post('/api/cash-sessions/:id/close', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);
  const schema = z.object({ closing_cash_cents: z.number().int().min(0), note: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  await db.query(
    "UPDATE cash_sessions SET status='closed', closed_at=now(), closing_cash_cents=$1, closed_by=$2, note=COALESCE($3,note) WHERE id=$4 AND status='open'",
    [parsed.data.closing_cash_cents, req.auth.sub, parsed.data.note || null, id]
  );
  res.json({ ok: true });
});

app.get('/api/cash-sessions/:id/summary', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const id = Number(req.params.id);

  const session = await db.query('SELECT * FROM cash_sessions WHERE id=$1', [id]);
  if (!session.rows[0]) return res.status(404).json({ ok: false, error: 'Session not found' });

  const sums = await db.query(
    `SELECT method, COALESCE(SUM(total_cents),0) as total_cents, COUNT(*) as count
     FROM sales WHERE cash_session_id=$1
     GROUP BY method`,
    [id]
  );

  const total = await db.query(
    `SELECT COALESCE(SUM(total_cents),0) as total_cents, COUNT(*) as count
     FROM sales WHERE cash_session_id=$1`,
    [id]
  );

  const cashRow = sums.rows.find(r => r.method === 'cash');
  const cashSales = Number(cashRow?.total_cents || 0);
  const opening = Number(session.rows[0].opening_cash_cents || 0);
  const expectedCash = opening + cashSales;

  res.json({
    ok: true,
    session: session.rows[0],
    by_method: sums.rows.map(r => ({ method: r.method, total_cents: Number(r.total_cents), count: Number(r.count) })),
    totals: { total_cents: Number(total.rows[0].total_cents), count: Number(total.rows[0].count) },
    expected_cash_cents: expectedCash
  });
});

// ---- Sales (admin/staff) ----
app.post('/api/sales', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const schema = z.object({
    method: z.enum(['cash','card','transfer']),
    note: z.string().optional().nullable(),
    items: z.array(z.object({
      product_id: z.number().int(),
      quantity: z.number().int().min(1)
    })).min(1)
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'Invalid body' });

  const openSession = await db.query("SELECT * FROM cash_sessions WHERE status='open' LIMIT 1");
  const open = openSession.rows[0] || null;

  if (parsed.data.method === 'cash' && !open) {
    return res.status(400).json({ ok: false, error: 'No open cash session. Open cash session before cash sales.' });
  }

  const ids = parsed.data.items.map(i => i.product_id);
  const products = await db.query('SELECT id,name,price_cents,stock FROM products WHERE active=TRUE AND id = ANY($1)', [ids]);
  const map = new Map(products.rows.map(p => [p.id, p]));

  for (const it of parsed.data.items) {
    const p = map.get(it.product_id);
    if (!p) return res.status(404).json({ ok: false, error: `Product not found: ${it.product_id}` });
    if (p.stock < it.quantity) return res.status(400).json({ ok: false, error: `Not enough stock for ${p.name}` });
  }

  let totalCents = 0;
  const lines = parsed.data.items.map(it => {
    const p = map.get(it.product_id);
    const lineTotal = Number(p.price_cents) * it.quantity;
    totalCents += lineTotal;
    return { product_id: it.product_id, quantity: it.quantity, unit_price_cents: Number(p.price_cents), line_total_cents: lineTotal };
  });

  const pool = db.getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sale = await client.query(
      'INSERT INTO sales(total_cents,method,note,created_by,cash_session_id) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [totalCents, parsed.data.method, parsed.data.note || null, req.auth.sub, open ? open.id : null]
    );
    const saleId = sale.rows[0].id;

    for (const ln of lines) {
      await client.query(
        'INSERT INTO sale_items(sale_id,product_id,quantity,unit_price_cents,line_total_cents) VALUES ($1,$2,$3,$4,$5)',
        [saleId, ln.product_id, ln.quantity, ln.unit_price_cents, ln.line_total_cents]
      );
      await client.query('UPDATE products SET stock=stock-$1, updated_at=now() WHERE id=$2', [ln.quantity, ln.product_id]);
      await client.query(
        'INSERT INTO inventory_movements(product_id,type,quantity,note,created_by,sale_id) VALUES ($1,$2,$3,$4,$5,$6)',
        [ln.product_id, 'sale', -ln.quantity, 'Sale', req.auth.sub, saleId]
      );
    }

    await client.query('COMMIT');
    res.json({ ok: true, sale_id: saleId, total_cents: totalCents, cash_session_id: open ? open.id : null });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ ok: false, error: 'Failed to create sale' });
  } finally {
    client.release();
  }
});

app.get('/api/sales', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const r = await db.query(
    `SELECT s.*, u.name as created_by_name
     FROM sales s
     LEFT JOIN users u ON u.id=s.created_by
     ORDER BY s.sold_at DESC
     LIMIT 200`
  );
  res.json({ ok: true, sales: r.rows });
});

app.get('/api/sales/summary', authMiddleware, requireRole(['admin','staff']), async (req, res) => {
  const from = (req.query.from || '').toString();
  const to = (req.query.to || '').toString();

  let where = '';
  const params = [];
  if (from && to) {
    where = 'WHERE sold_at::date BETWEEN $1::date AND $2::date';
    params.push(from, to);
  }

  const r = await db.query(
    `SELECT method, COALESCE(SUM(total_cents),0) as total_cents, COUNT(*) as count
     FROM sales ${where}
     GROUP BY method`,
    params
  );
  res.json({ ok: true, by_method: r.rows.map(x => ({ method: x.method, total_cents: Number(x.total_cents), count: Number(x.count) })) });
});

// ---- Member portal ----
app.get('/api/member/summary', authMiddleware, requireRole(['member']), async (req, res) => {
  const memberId = req.auth.member_id;
  if (!memberId) return res.status(400).json({ ok: false, error: 'Member not linked' });

  const mem = await db.query('SELECT * FROM members WHERE id=$1', [memberId]);
  const membership = await db.query(
    `SELECT m.*, p.name as plan_name
     FROM memberships m JOIN plans p ON p.id=m.plan_id
     WHERE m.member_id=$1 AND m.status='active'
     ORDER BY m.end_date DESC LIMIT 1`,
    [memberId]
  );
  const lastAttendance = await db.query(
    'SELECT checkin_at FROM attendance WHERE member_id=$1 ORDER BY checkin_at DESC LIMIT 1',
    [memberId]
  );

  res.json({
    ok: true,
    member: mem.rows[0] || null,
    active_membership: membership.rows[0] || null,
    last_checkin_at: lastAttendance.rows[0]?.checkin_at || null
  });
});

app.get('/api/member/membership', authMiddleware, requireRole(['member']), async (req, res) => {
  const memberId = req.auth.member_id;
  const r = await db.query(
    `SELECT m.*, p.name as plan_name, p.duration_days, p.price_cents
     FROM memberships m JOIN plans p ON p.id=m.plan_id
     WHERE m.member_id=$1
     ORDER BY m.start_date DESC`,
    [memberId]
  );
  res.json({ ok: true, memberships: r.rows });
});

app.get('/api/member/payments', authMiddleware, requireRole(['member']), async (req, res) => {
  const memberId = req.auth.member_id;
  const r = await db.query(
    'SELECT * FROM payments WHERE member_id=$1 ORDER BY paid_at DESC LIMIT 200',
    [memberId]
  );
  res.json({ ok: true, payments: r.rows });
});

app.get('/api/member/attendance', authMiddleware, requireRole(['member']), async (req, res) => {
  const memberId = req.auth.member_id;
  const r = await db.query(
    'SELECT * FROM attendance WHERE member_id=$1 ORDER BY checkin_at DESC LIMIT 200',
    [memberId]
  );
  res.json({ ok: true, attendance: r.rows });
});

// Default error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: 'Server error' });
});

module.exports = app;
