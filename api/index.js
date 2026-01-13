const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "1mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : undefined,
});

const json = (res, status, payload) => res.status(status).json(payload);

function originToHost(origin) { try { return origin ? new URL(origin).host.toLowerCase() : null; } catch { return null; } }
function hostFromReq(req) {
  const xf = req.headers["x-forwarded-host"];
  const host = (Array.isArray(xf) ? xf[0] : xf) || req.headers.host;
  return host ? String(host).split(",")[0].trim().toLowerCase() : null;
}
function cleanDomain(input) {
  return input ? String(input).trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").toLowerCase() : null;
}
function setCors(res, origin) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}
async function isAllowedDomain(domain) {
  if (!domain) return false;
  const r = await pool.query(
    "SELECT 1 FROM tenant_domains WHERE lower(domain)=lower($1) AND COALESCE(is_active,true)=true LIMIT 1",
    [domain]
  );
  return r.rowCount > 0;
}
async function resolveTenant(domain) {
  if (!domain) return null;
  const r = await pool.query(
    "SELECT t.* FROM tenant_domains d JOIN tenants t ON t.id=d.tenant_id WHERE lower(d.domain)=lower($1) AND COALESCE(d.is_active,true)=true AND COALESCE(t.is_active,true)=true LIMIT 1",
    [domain]
  );
  return r.rows[0] || null;
}
function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 16) throw new Error("Missing/weak JWT_SECRET");
  return jwt.sign(payload, secret, { expiresIn: "8h" });
}
function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return json(res, 401, { ok: false, error: "Missing Bearer token" });
  try { req.auth = jwt.verify(m[1], process.env.JWT_SECRET); return next(); }
  catch { return json(res, 401, { ok: false, error: "Invalid token" }); }
}
const requireRole = (...roles) => (req, res, next) => {
  if (!req.auth?.role) return json(res, 401, { ok: false, error: "No auth" });
  if (!roles.includes(req.auth.role)) return json(res, 403, { ok: false, error: "Forbidden" });
  next();
};
async function loadUserByIdCode(id_code) {
  const r = await pool.query("SELECT id, id_code, role, tenant_id, is_active FROM users WHERE id_code=$1 LIMIT 1", [id_code]);
  return r.rows[0] || null;
}

// ---- CORS + allowlist ----
app.use(async (req, res, next) => {
  try {
    const origin = req.headers.origin;
    const originHost = originToHost(origin);
    const host = hostFromReq(req);

    if (req.path === "/api/health" || req.path === "/health") {
      if (origin && originHost) setCors(res, origin);
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    const isSetup = req.path === "/api/admin/setup" || req.path === "/admin/setup";
    if (isSetup && process.env.SETUP_KEY) {
      if (origin && originHost) setCors(res, origin);
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    if (req.method === "OPTIONS") {
      const allowed = await isAllowedDomain(originHost);
      if (allowed && origin) { setCors(res, origin); return res.status(204).end(); }
      return res.status(403).end();
    }

    const domainToCheck = originHost || host;
    const allowed = await isAllowedDomain(domainToCheck);
    if (!allowed) return json(res, 403, { ok: false, error: "CORS blocked: origin not allowed", domain: domainToCheck });

    if (origin && originHost) setCors(res, origin);
    req.tenant = await resolveTenant(domainToCheck);
    next();
  } catch (e) {
    console.error("middleware error", e);
    json(res, 500, { ok: false, error: "Server error" });
  }
});
function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: "Missing token" });

    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ ok: false, error: "Missing JWT_SECRET" });

    const payload = jwt.verify(token, secret);
    req.user = payload; // { sub, role, tenant_id, ... }
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}

// ---- base ----
app.get(
  ["/me", "/api/me", "/auth/me", "/api/auth/me"],
  requireAuth,
  async (req, res) => {
    try {
      const idCode = req.user?.sub;
      const r = await pool.query(
        `SELECT id_code, role, tenant_id, is_active
         FROM users
         WHERE id_code=$1
         LIMIT 1`,
        [idCode]
      );

      if (r.rowCount === 0) return res.status(404).json({ ok: false, error: "User not found" });

      const u = r.rows[0];
      return res.json({
        ok: true,
        user: {
          id_code: u.id_code,
          role: u.role,
          tenant_id: u.tenant_id
        }
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: "Failed to load session" });
    }
  }
);

app.get(["/health", "/api/health"], (req, res) => json(res, 200, { ok: true, ts: new Date().toISOString() }));

app.get(["/tenant", "/api/tenant"], (req, res) => {
  if (!req.tenant) return json(res, 404, { ok: false, error: "Tenant not found for this domain" });
  const t = req.tenant;
  json(res, 200, { ok: true, tenant: { id: t.id, code: t.code, name: t.name, accent_color: t.accent_color || "#39FF14", logo_url: t.logo_url || null } });
});

// ---- setup (temporary) ----
app.post(["/admin/setup", "/api/admin/setup"], async (req, res) => {
  try {
    const envKey = process.env.SETUP_KEY;
    if (!envKey) return json(res, 403, { ok: false, error: "Setup disabled" });

    const { setupKey, adminPassword, tenantCode, tenantName, tenantDomain } = req.body || {};
    if (!setupKey || setupKey !== envKey) return json(res, 403, { ok: false, error: "Invalid setupKey" });
    if (!adminPassword || String(adminPassword).length < 6) return json(res, 400, { ok: false, error: "adminPassword must be >= 6 chars" });

    const code = String(tenantCode || "").toUpperCase();
    if (code.length !== 2) return json(res, 400, { ok: false, error: "tenantCode must be 2 letters" });

    const domain = cleanDomain(tenantDomain);
    if (!domain) return json(res, 400, { ok: false, error: "tenantDomain is required" });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const t = await client.query(
        `INSERT INTO tenants (code, name, accent_color, is_active, next_seq)
         VALUES ($1, $2, '#39FF14', true, 1)
         ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, is_active=true
         RETURNING *`,
        [code, tenantName || code]
      );
      const tenant = t.rows[0];

      await client.query(
        `INSERT INTO tenant_domains (tenant_id, domain, is_active)
         VALUES ($1, $2, true)
         ON CONFLICT (tenant_id, domain) DO UPDATE SET is_active=true`,
        [tenant.id, domain]
      );

      const adminHash = await bcrypt.hash(String(adminPassword), 10);
      await client.query(
        `INSERT INTO users (id_code, role, password_hash, tenant_id, is_active)
         VALUES ('admin','admin',$1,NULL,true)
         ON CONFLICT (id_code) DO UPDATE SET role='admin', password_hash=EXCLUDED.password_hash, is_active=true`,
        [adminHash]
      );

      const seqRow = await client.query("SELECT next_seq FROM tenants WHERE id=$1 FOR UPDATE", [tenant.id]);
      const seq = Number(seqRow.rows[0]?.next_seq || 1);
      const adminTenantId = `${code}${String(seq).padStart(4, "0")}`;
      const tempPassword = "Admin123!";
      const tempHash = await bcrypt.hash(tempPassword, 10);

      await client.query(
        `INSERT INTO users (id_code, role, password_hash, tenant_id, is_active)
         VALUES ($1,'admin_tenant',$2,$3,true)
         ON CONFLICT (id_code) DO UPDATE SET role='admin_tenant', tenant_id=$3, password_hash=$2, is_active=true`,
        [adminTenantId, tempHash, tenant.id]
      );
      await client.query("UPDATE tenants SET next_seq=$1 WHERE id=$2", [seq + 1, tenant.id]);

      await client.query(
        `INSERT INTO membership_plans (tenant_id, code, name, description, is_active)
         VALUES
           ($1,'STD','Membresía estándar','Acceso general',true),
           ($1,'PER','Membresía con personalizado','Incluye personalizado',true),
           ($1,'TEEN','Membresía teens','Soft rule horario',true)
         ON CONFLICT (tenant_id, code) DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, is_active=true`,
        [tenant.id]
      );

      await client.query("COMMIT");
      json(res, 200, { ok: true, adminTenant: { id_code: adminTenantId, tempPassword }, note: "Delete SETUP_KEY after setup." });
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error("setup error", e);
    json(res, 500, { ok: false, error: "Setup failed", detail: String(e.message || e) });
  }
});

// ---- auth ----
app.post(["/auth/login", "/api/auth/login"], async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) return json(res, 400, { ok: false, error: "identifier and password required" });

    const r = await pool.query(
      "SELECT id, id_code, role, tenant_id, password_hash, is_active FROM users WHERE id_code=$1 LIMIT 1",
      [String(identifier).trim()]
    );
    if (r.rowCount === 0) return json(res, 401, { ok: false, error: "Invalid credentials" });

    const u = r.rows[0];
    if (u.is_active === false) return json(res, 403, { ok: false, error: "User disabled" });

    const ok = await bcrypt.compare(String(password), u.password_hash);
    if (!ok) return json(res, 401, { ok: false, error: "Invalid credentials" });

    if (u.role !== "admin") {
      if (!req.tenant) return json(res, 403, { ok: false, error: "Tenant not resolved" });
      if (String(u.tenant_id) !== String(req.tenant.id)) return json(res, 403, { ok: false, error: "User does not belong to this tenant" });
    }

    const token = signToken({ sub: u.id_code, role: u.role, tenant_id: u.tenant_id || null });
    json(res, 200, { ok: true, token, user: { id_code: u.id_code, role: u.role } });
  } catch (e) {
    console.error("login error", e);
    json(res, 500, { ok: false, error: "Login failed" });
  }
});

app.get(["/me", "/api/me"], authRequired, async (req, res) => {
  const u = await loadUserByIdCode(req.auth.sub);
  json(res, 200, { ok: true, user: u });
});
// Alias for clients that expect /api/auth/me
app.get(["/auth/me", "/api/auth/me"], authRequired, async (req, res) => {
  const u = await loadUserByIdCode(req.auth.sub);
  json(res, 200, { ok: true, user: u });
});

// Self-service password change
app.post(["/auth/change-password", "/api/auth/change-password"], authRequired, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) return json(res, 400, { ok: false, error: "oldPassword and newPassword required" });
    if (String(newPassword).length < 6) return json(res, 400, { ok: false, error: "newPassword must be >= 6 chars" });

    const r = await pool.query(
      "SELECT id_code, role, tenant_id, password_hash, is_active FROM users WHERE id_code=$1 LIMIT 1",
      [req.auth.sub]
    );
    if (r.rowCount === 0) return json(res, 404, { ok: false, error: "User not found" });
    const u = r.rows[0];
    if (u.is_active === false) return json(res, 403, { ok: false, error: "User disabled" });

    const ok = await bcrypt.compare(String(oldPassword), u.password_hash);
    if (!ok) return json(res, 401, { ok: false, error: "Invalid old password" });

    const hash = await bcrypt.hash(String(newPassword), 10);
    await pool.query("UPDATE users SET password_hash=$1 WHERE id_code=$2", [hash, u.id_code]);

    json(res, 200, { ok: true });
  } catch (e) {
    console.error("change-password error", e);
    json(res, 500, { ok: false, error: "Change password failed" });
  }
});

// Forgot password: creates a reset request (handled by staff/admin in portal)
app.post(["/auth/forgot", "/api/auth/forgot"], async (req, res) => {
  try {
    if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
    const { identifier } = req.body || {};
    const id = String(identifier || "").trim();
    if (!id) return json(res, 400, { ok: false, error: "identifier required" });

    // Avoid user enumeration: always return ok:true even if user doesn't exist
    const u = await pool.query("SELECT id_code, role, tenant_id, is_active FROM users WHERE id_code=$1 LIMIT 1", [id]);
    if (u.rowCount === 0) return json(res, 200, { ok: true, message: "Si el usuario existe, se generó una solicitud de recuperación." });

    const user = u.rows[0];
    if (user.is_active === false) return json(res, 200, { ok: true, message: "Si el usuario existe, se generó una solicitud de recuperación." });
    if (user.role !== "admin" && String(user.tenant_id) !== String(req.tenant.id)) {
      return json(res, 200, { ok: true, message: "Si el usuario existe, se generó una solicitud de recuperación." });
    }

    const ip = (req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "").toString().slice(0, 64);
    const r = await pool.query(
      "INSERT INTO password_reset_requests (tenant_id, id_code, request_ip, status) VALUES ($1,$2,$3,'pending') RETURNING id",
      [req.tenant.id, user.id_code, ip || null]
    );

    json(res, 200, { ok: true, request_id: r.rows[0].id, message: "Solicitud creada. Pide al staff que te ayude a restablecer tu contraseña." });
  } catch (e) {
    console.error("forgot error", e);
    json(res, 500, { ok: false, error: "Forgot password failed" });
  }
});

function genTempPassword(){
  // 8 chars easy to type
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let out = "";
  for (let i=0;i<8;i++) out += chars[Math.floor(Math.random()*chars.length)];
  return out;
}

// Staff/Admin: list pending reset requests
app.get(["/admin/reset-requests", "/api/admin/reset-requests"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  try {
    if (req.auth.role !== "admin" && !req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
    const tenantId = req.auth.role === "admin" ? null : req.tenant.id;

    const r = tenantId
      ? await pool.query(
          "SELECT * FROM password_reset_requests WHERE tenant_id=$1 ORDER BY requested_at DESC LIMIT 200",
          [tenantId]
        )
      : await pool.query(
          "SELECT * FROM password_reset_requests ORDER BY requested_at DESC LIMIT 200"
        );

    json(res, 200, { ok: true, requests: r.rows });
  } catch (e) {
    console.error("reset-requests error", e);
    json(res, 500, { ok: false, error: "Failed to list reset requests" });
  }
});

// Staff/Admin: reset password for a user in this tenant
app.post(["/admin/reset-password", "/api/admin/reset-password"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  try {
    const { id_code, newPassword } = req.body || {};
    const id = String(id_code || "").trim();
    if (!id) return json(res, 400, { ok: false, error: "id_code required" });

    const r = await pool.query("SELECT id_code, role, tenant_id, is_active FROM users WHERE id_code=$1 LIMIT 1", [id]);
    if (r.rowCount === 0) return json(res, 404, { ok: false, error: "User not found" });
    const user = r.rows[0];

    // Non-global admin can only reset within current tenant and cannot reset the global admin
    if (req.auth.role !== "admin") {
      if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
      if (user.role === "admin") return json(res, 403, { ok: false, error: "Cannot reset global admin" });
      if (String(user.tenant_id) !== String(req.tenant.id)) return json(res, 403, { ok: false, error: "User does not belong to this tenant" });
    }

    const temp = newPassword && String(newPassword).trim() ? String(newPassword).trim() : genTempPassword();
    if (temp.length < 6) return json(res, 400, { ok: false, error: "Password must be >= 6 chars" });

    const hash = await bcrypt.hash(temp, 10);
    await pool.query("UPDATE users SET password_hash=$1, is_active=true WHERE id_code=$2", [hash, user.id_code]);

    // Mark pending requests as resolved
    if (req.tenant) {
      await pool.query(
        "UPDATE password_reset_requests SET status='resolved', resolved_at=NOW(), resolved_by=$1 WHERE tenant_id=$2 AND id_code=$3 AND status='pending'",
        [req.auth.sub, req.tenant.id, user.id_code]
      );
    }

    json(res, 200, { ok: true, id_code: user.id_code, tempPassword: temp });
  } catch (e) {
    console.error("reset-password error", e);
    json(res, 500, { ok: false, error: "Reset password failed" });
  }
});


// ---- ops: plans ----
app.get(["/plans", "/api/plans"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const r = await pool.query("SELECT * FROM membership_plans WHERE tenant_id=$1 ORDER BY code", [req.tenant.id]);
  json(res, 200, { ok: true, plans: r.rows });
});

// ---- ops: members ----
app.get(["/members", "/api/members"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const q = String(req.query.q || "").trim().toLowerCase();
  const params = [req.tenant.id];
  let where = "tenant_id=$1";
  if (q) {
    params.push(`%${q}%`);
    where += " AND (lower(first_name) LIKE $2 OR lower(last_name) LIKE $2 OR lower(email) LIKE $2 OR lower(phone) LIKE $2)";
  }
  const r = await pool.query(`SELECT * FROM members WHERE ${where} ORDER BY created_at DESC LIMIT 200`, params);
  json(res, 200, { ok: true, members: r.rows });
});

app.post(["/members/preregister", "/api/members/preregister"], authRequired, requireRole("admin_tenant", "staff"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const { first_name, last_name, phone, email, notes, plan_code } = req.body || {};
  if (!first_name || !last_name) return json(res, 400, { ok: false, error: "first_name and last_name required" });
  const r = await pool.query(
    `INSERT INTO members (tenant_id, first_name, last_name, phone, email, notes, plan_code, access_active)
     VALUES ($1,$2,$3,$4,$5,$6,$7,false) RETURNING *`,
    [req.tenant.id, first_name, last_name, phone || null, email || null, notes || null, plan_code || null]
  );
  json(res, 200, { ok: true, member: r.rows[0] });
});

app.post(["/members/:id/activate", "/api/members/:id/activate"], authRequired, requireRole("admin_tenant", "staff"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const memberId = Number(req.params.id);
  const { password, plan_code, duration_days } = req.body || {};
  if (!password || String(password).length < 6) return json(res, 400, { ok: false, error: "password must be >= 6 chars" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const m = await client.query("SELECT * FROM members WHERE id=$1 AND tenant_id=$2 FOR UPDATE", [memberId, req.tenant.id]);
    if (m.rowCount === 0) return json(res, 404, { ok: false, error: "Member not found" });

    const tRow = await client.query("SELECT code, next_seq FROM tenants WHERE id=$1 FOR UPDATE", [req.tenant.id]);
    const code = tRow.rows[0].code;
    const seq = Number(tRow.rows[0].next_seq || 1);
    const id_code = `${code}${String(seq).padStart(4, "0")}`;

    const hash = await bcrypt.hash(String(password), 10);
    const u = await client.query(
      "INSERT INTO users (id_code, role, password_hash, tenant_id, is_active) VALUES ($1,'member',$2,$3,true) RETURNING id, id_code, role, tenant_id",
      [id_code, hash, req.tenant.id]
    );

    const startDate = new Date();
    const start = startDate.toISOString().slice(0, 10);
    const days = Number(duration_days || 30);
    const endDate = new Date(startDate.getTime() + days * 24 * 60 * 60 * 1000);
    const end = endDate.toISOString().slice(0, 10);

    await client.query(
      "UPDATE members SET user_id=$1, access_active=true, plan_code=COALESCE($2, plan_code), membership_start=$3, membership_end=$4, updated_at=NOW() WHERE id=$5",
      [u.rows[0].id, plan_code || null, start, end, memberId]
    );

    await client.query("UPDATE tenants SET next_seq=$1 WHERE id=$2", [seq + 1, req.tenant.id]);
    await client.query("COMMIT");

    json(res, 200, { ok: true, user: u.rows[0], member_id: memberId, membership: { start, end } });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("activate error", e);
    json(res, 500, { ok: false, error: "Activate failed", detail: String(e.message || e) });
  } finally {
    client.release();
  }
});

// ---- ops: products ----
app.get(["/products", "/api/products"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const r = await pool.query("SELECT * FROM products WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 500", [req.tenant.id]);
  json(res, 200, { ok: true, products: r.rows });
});

app.post(["/products", "/api/products"], authRequired, requireRole("admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const { sku, name, price_mxn, stock } = req.body || {};
  if (!name) return json(res, 400, { ok: false, error: "name required" });
  const r = await pool.query(
    "INSERT INTO products (tenant_id, sku, name, price_mxn, stock, is_active) VALUES ($1,$2,$3,$4,$5,true) RETURNING *",
    [req.tenant.id, sku || null, name, Number(price_mxn || 0), Number(stock || 0)]
  );
  json(res, 200, { ok: true, product: r.rows[0] });
});

app.put(["/products/:id", "/api/products/:id"], authRequired, requireRole("admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const id = Number(req.params.id);
  const { sku, name, price_mxn, stock, is_active } = req.body || {};
  const r = await pool.query(
    `UPDATE products SET
      sku=COALESCE($1, sku),
      name=COALESCE($2, name),
      price_mxn=COALESCE($3, price_mxn),
      stock=COALESCE($4, stock),
      is_active=COALESCE($5, is_active),
      updated_at=NOW()
     WHERE id=$6 AND tenant_id=$7
     RETURNING *`,
    [sku ?? null, name ?? null, (price_mxn !== undefined ? Number(price_mxn) : null), (stock !== undefined ? Number(stock) : null), (is_active !== undefined ? !!is_active : null), id, req.tenant.id]
  );
  if (r.rowCount === 0) return json(res, 404, { ok: false, error: "Product not found" });
  json(res, 200, { ok: true, product: r.rows[0] });
});

// ---- ops: cash ----
app.get(["/cash/current", "/api/cash/current"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const r = await pool.query("SELECT * FROM cash_sessions WHERE tenant_id=$1 AND status='open' ORDER BY opened_at DESC LIMIT 1", [req.tenant.id]);
  json(res, 200, { ok: true, cash: r.rows[0] || null });
});

app.post(["/cash/open", "/api/cash/open"], authRequired, requireRole("admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const { opening_cash } = req.body || {};
  const existing = await pool.query("SELECT 1 FROM cash_sessions WHERE tenant_id=$1 AND status='open' LIMIT 1", [req.tenant.id]);
  if (existing.rowCount > 0) return json(res, 400, { ok: false, error: "Cash session already open" });
  const u = await loadUserByIdCode(req.auth.sub);
  const r = await pool.query(
    "INSERT INTO cash_sessions (tenant_id, opening_cash, opened_by, status) VALUES ($1,$2,$3,'open') RETURNING *",
    [req.tenant.id, Number(opening_cash || 0), u?.id || null]
  );
  json(res, 200, { ok: true, cash: r.rows[0] });
});

app.post(["/cash/close", "/api/cash/close"], authRequired, requireRole("admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const { closing_cash } = req.body || {};
  const u = await loadUserByIdCode(req.auth.sub);
  const r = await pool.query(
    "UPDATE cash_sessions SET closing_cash=$2, closed_at=NOW(), closed_by=$3, status='closed' WHERE tenant_id=$1 AND status='open' RETURNING *",
    [req.tenant.id, Number(closing_cash || 0), u?.id || null]
  );
  if (r.rowCount === 0) return json(res, 400, { ok: false, error: "No open cash session" });
  json(res, 200, { ok: true, cash: r.rows[0] });
});

// ---- ops: sales ----
app.post(["/sales", "/api/sales"], authRequired, requireRole("admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const { items, payment_method, note } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) return json(res, 400, { ok: false, error: "items required" });

  const cash = await pool.query("SELECT * FROM cash_sessions WHERE tenant_id=$1 AND status='open' LIMIT 1", [req.tenant.id]);
  if (cash.rowCount === 0) return json(res, 400, { ok: false, error: "Open cash session required" });

  const u = await loadUserByIdCode(req.auth.sub);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const sale = await client.query(
      "INSERT INTO sales (tenant_id, cash_session_id, created_by, payment_method, total, note) VALUES ($1,$2,$3,$4,0,$5) RETURNING *",
      [req.tenant.id, cash.rows[0].id, u?.id || null, payment_method || "cash", note || null]
    );
    const saleId = sale.rows[0].id;

    let total = 0;
    for (const it of items) {
      const pid = Number(it.product_id);
      const qty = Number(it.qty || 0);
      if (!pid || qty <= 0) throw new Error("Invalid item");

      const p = await client.query("SELECT id, stock, price_mxn FROM products WHERE id=$1 AND tenant_id=$2 AND is_active=true FOR UPDATE", [pid, req.tenant.id]);
      if (p.rowCount === 0) throw new Error("Product not found");
      if (p.rows[0].stock < qty) throw new Error("Insufficient stock");

      const unit = Number(p.rows[0].price_mxn);
      const line = unit * qty;
      total += line;

      await client.query("UPDATE products SET stock=stock-$1, updated_at=NOW() WHERE id=$2", [qty, pid]);
      await client.query("INSERT INTO sale_items (sale_id, product_id, qty, unit_price, line_total) VALUES ($1,$2,$3,$4,$5)", [saleId, pid, qty, unit, line]);
    }
    await client.query("UPDATE sales SET total=$1 WHERE id=$2", [total, saleId]);
    await client.query("COMMIT");

    json(res, 200, { ok: true, sale_id: saleId, total });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("sale error", e);
    json(res, 500, { ok: false, error: "Sale failed", detail: String(e.message || e) });
  } finally {
    client.release();
  }
});

app.get(["/sales/today", "/api/sales/today"], authRequired, requireRole("admin", "admin_tenant", "staff", "coach"), async (req, res) => {
  if (!req.tenant) return json(res, 400, { ok: false, error: "Tenant not resolved" });
  const r = await pool.query("SELECT * FROM sales WHERE tenant_id=$1 AND created_at::date = (NOW()::date) ORDER BY created_at DESC LIMIT 200", [req.tenant.id]);
  json(res, 200, { ok: true, sales: r.rows });
});

app.all("*", (req, res) => json(res, 404, { ok: false, error: "Not found" }));

module.exports = app;
