/* SVFIT Backend v2 - Minimal core for setup + auth + tenant + health
 * - Multi-tenant resolved by Origin (browser) or Host (server-to-server)
 * - Strict CORS for normal endpoints
 * - /api/admin/setup allowed only while SETUP_KEY exists (temporary)
 */

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ------------------- DB -------------------
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  // Fail early but keep a readable message in Vercel logs
  console.error("Missing env DATABASE_URL");
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && DATABASE_URL.includes("sslmode=require") ? { rejectUnauthorized: false } : undefined,
});

// ------------------- Helpers -------------------
function safeJson(res, status, obj) {
  res.status(status).json(obj);
}

function parseDomainFromOrigin(origin) {
  try {
    if (!origin) return null;
    const u = new URL(origin);
    return (u.host || "").toLowerCase();
  } catch {
    return null;
  }
}

function parseDomainFromHost(req) {
  const xfHost = req.headers["x-forwarded-host"];
  const host = (Array.isArray(xfHost) ? xfHost[0] : xfHost) || req.headers.host;
  if (!host) return null;
  return String(host).split(",")[0].trim().toLowerCase();
}

// Accept /api/* and non-/api paths (depending on Vercel routing)
function pathMatches(reqPath, target) {
  return reqPath === target || reqPath === `/api${target}` || reqPath.startsWith(`/api${target}/`);
}

function isSetupRoute(req) {
  return pathMatches(req.path, "/admin/setup");
}

async function resolveTenantByDomain(domain) {
  if (!domain) return null;
  const q = `
    SELECT t.*
    FROM tenant_domains d
    JOIN tenants t ON t.id = d.tenant_id
    WHERE lower(d.domain) = lower($1)
      AND COALESCE(d.is_active, true) = true
      AND COALESCE(t.is_active, true) = true
    LIMIT 1
  `;
  const r = await pool.query(q, [domain]);
  return r.rows[0] || null;
}

async function isAllowedDomain(domain) {
  if (!domain) return false;
  const q = `
    SELECT 1
    FROM tenant_domains
    WHERE lower(domain) = lower($1)
      AND COALESCE(is_active, true) = true
    LIMIT 1
  `;
  const r = await pool.query(q, [domain]);
  return r.rowCount > 0;
}

function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error("Missing or weak JWT_SECRET (set a long random string).");
  }
  return jwt.sign(payload, secret, { expiresIn: "8h" });
}

function setCorsHeaders(res, origin) {
  // If origin is allowed, echo it back (required when using credentials)
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// ------------------- CORS + Tenant Gate -------------------
app.use(async (req, res, next) => {
  try {
    const origin = req.headers.origin;
    const originDomain = parseDomainFromOrigin(origin);
    const hostDomain = parseDomainFromHost(req);

    // 1) HEALTH should never be blocked
    if (pathMatches(req.path, "/health")) {
      if (origin && originDomain) {
        // Allow health from anywhere (debug-friendly)
        setCorsHeaders(res, origin);
      }
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    // 2) SETUP route: allow preflight + allow call while SETUP_KEY exists
    //    (setupKey validation happens inside the route handler)
    if (isSetupRoute(req) && process.env.SETUP_KEY) {
      if (origin && originDomain) {
        setCorsHeaders(res, origin);
      }
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    // 3) Normal routes: strict domain allow-list
    //    If Origin exists -> must be allowed
    //    If no Origin -> use Host (server-to-server)
    const domainToCheck = originDomain || hostDomain;

    const allowed = await isAllowedDomain(domainToCheck);
    if (!allowed) {
      // For browsers, CORS header will be missing on purpose (so frontend sees blocked)
      return safeJson(res, 403, { ok: false, error: "CORS blocked: origin not allowed", domain: domainToCheck });
    }

    // If browser request, we MUST set CORS headers so it can read the response
    if (origin && originDomain) setCorsHeaders(res, origin);

    // Handle OPTIONS preflight for allowed domains
    if (req.method === "OPTIONS") return res.status(204).end();

    // Attach tenant to request for downstream handlers
    const tenant = await resolveTenantByDomain(domainToCheck);
    req.tenant = tenant;

    return next();
  } catch (err) {
    console.error("CORS/Tenant middleware error:", err);
    return safeJson(res, 500, { ok: false, error: "Server error in middleware" });
  }
});

// ------------------- Routes -------------------

// Health
app.get(["/health", "/api/health"], (req, res) => {
  safeJson(res, 200, { ok: true, service: "svfit-backend", ts: new Date().toISOString() });
});

// Tenant branding/info for frontend
app.get(["/tenant", "/api/tenant"], async (req, res) => {
  try {
    if (!req.tenant) return safeJson(res, 404, { ok: false, error: "Tenant not found for this domain" });

    const t = req.tenant;
    return safeJson(res, 200, {
      ok: true,
      tenant: {
        id: t.id,
        code: t.code,
        name: t.name,
        accent_color: t.accent_color || "#39FF14",
        logo_url: t.logo_url || null,
      },
    });
  } catch (err) {
    console.error(err);
    return safeJson(res, 500, { ok: false, error: "Failed to load tenant" });
  }
});

// Setup (creates global admin + tenant admin + default plans). TEMPORARY: requires env SETUP_KEY.
app.post(["/admin/setup", "/api/admin/setup"], async (req, res) => {
  try {
    const envKey = process.env.SETUP_KEY;
    if (!envKey) return safeJson(res, 403, { ok: false, error: "Setup disabled (SETUP_KEY not set)" });

    const { setupKey, adminPassword, tenantCode, tenantName, tenantDomain } = req.body || {};
    if (!setupKey || setupKey !== envKey) return safeJson(res, 403, { ok: false, error: "Invalid setupKey" });
    if (!adminPassword || String(adminPassword).length < 6) {
      return safeJson(res, 400, { ok: false, error: "adminPassword must be at least 6 chars" });
    }
    if (!tenantCode || String(tenantCode).length !== 2) {
      return safeJson(res, 400, { ok: false, error: "tenantCode must be 2 letters (e.g. SV)" });
    }
    if (!tenantName) return safeJson(res, 400, { ok: false, error: "tenantName is required" });
    if (!tenantDomain) return safeJson(res, 400, { ok: false, error: "tenantDomain is required (e.g. svfit.vercel.app)" });

    const code = String(tenantCode).toUpperCase();
    const domain = String(tenantDomain).replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();

    // Upsert tenant
    const upTenant = await pool.query(
      `
      INSERT INTO tenants (code, name, accent_color, is_active, next_seq)
      VALUES ($1, $2, $3, true, 1)
      ON CONFLICT (code)
      DO UPDATE SET name = EXCLUDED.name
      RETURNING *
      `,
      [code, tenantName, "#39FF14"]
    );
    const tenant = upTenant.rows[0];

    // Upsert domain
    await pool.query(
      `
      INSERT INTO tenant_domains (tenant_id, domain, is_active)
      VALUES ($1, $2, true)
      ON CONFLICT (tenant_id, domain)
      DO UPDATE SET is_active = true
      `,
      [tenant.id, domain]
    );

    // Ensure global admin exists
    const adminHash = await bcrypt.hash(String(adminPassword), 10);
    await pool.query(
      `
      INSERT INTO users (id_code, role, password_hash, tenant_id, is_active)
      VALUES ('admin', 'admin', $1, NULL, true)
      ON CONFLICT (id_code)
      DO UPDATE SET role='admin', password_hash=EXCLUDED.password_hash, is_active=true
      `,
      [adminHash]
    );

    // Ensure tenant admin exists: e.g. SV0001 with temp password
    const adminTenantIdCode = `${code}0001`;
    const adminTenantTempPassword = "Admin123!"; // temporary default
    const adminTenantHash = await bcrypt.hash(adminTenantTempPassword, 10);

    await pool.query(
      `
      INSERT INTO users (id_code, role, password_hash, tenant_id, is_active)
      VALUES ($1, 'admin_tenant', $2, $3, true)
      ON CONFLICT (id_code)
      DO UPDATE SET role='admin_tenant', tenant_id=$3, password_hash=$2, is_active=true
      `,
      [adminTenantIdCode, adminTenantHash, tenant.id]
    );

    // Seed membership plans (basic)
    // (If your schema uses different table/columns, adjust here.)
    await pool.query(
      `
      INSERT INTO membership_plans (tenant_id, code, name, description, is_active)
      VALUES
        ($1, 'STD', 'Membresía estándar', 'Acceso general', true),
        ($1, 'PER', 'Membresía con personalizado', 'Incluye entrenamiento personalizado', true),
        ($1, 'TEEN', 'Membresía teens', 'Soft rule: advertencia de horario', true)
      ON CONFLICT (tenant_id, code)
      DO UPDATE SET name=EXCLUDED.name, description=EXCLUDED.description, is_active=true
      `,
      [tenant.id]
    );

    return safeJson(res, 200, {
      ok: true,
      tenant: { id: tenant.id, code: tenant.code, name: tenant.name, domain },
      admin: { id_code: "admin" },
      adminTenant: { id_code: adminTenantIdCode, tempPassword: adminTenantTempPassword },
      note: "After setup, DELETE SETUP_KEY from Vercel env vars.",
    });
  } catch (err) {
    console.error("setup error:", err);
    return safeJson(res, 500, { ok: false, error: "Setup failed", detail: String(err.message || err) });
  }
});

// Login
app.post(["/auth/login", "/api/auth/login"], async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) return safeJson(res, 400, { ok: false, error: "identifier and password required" });

    const id = String(identifier).trim();

    const r = await pool.query(`SELECT id, id_code, role, tenant_id, password_hash, is_active FROM users WHERE id_code=$1 LIMIT 1`, [id]);
    if (r.rowCount === 0) return safeJson(res, 401, { ok: false, error: "Invalid credentials" });

    const u = r.rows[0];
    if (u.is_active === false) return safeJson(res, 403, { ok: false, error: "User disabled" });

    const ok = await bcrypt.compare(String(password), u.password_hash);
    if (!ok) return safeJson(res, 401, { ok: false, error: "Invalid credentials" });

    // If user is not global admin, require tenant to be resolved
    if (u.role !== "admin") {
      if (!req.tenant) return safeJson(res, 403, { ok: false, error: "Tenant not resolved for this domain" });
      if (String(u.tenant_id) !== String(req.tenant.id)) {
        return safeJson(res, 403, { ok: false, error: "User does not belong to this tenant" });
      }
    }

    const token = signToken({
      sub: u.id_code,
      role: u.role,
      tenant_id: u.tenant_id || null,
    });

    return safeJson(res, 200, {
      ok: true,
      token,
      user: { id_code: u.id_code, role: u.role, tenant_id: u.tenant_id || null },
      tenant: req.tenant ? { id: req.tenant.id, code: req.tenant.code, name: req.tenant.name } : null,
    });
  } catch (err) {
    console.error("login error:", err);
    return safeJson(res, 500, { ok: false, error: "Login failed", detail: String(err.message || err) });
  }
});

// Default
app.all("*", (req, res) => {
  safeJson(res, 404, { ok: false, error: "Not found" });
});

// Export for Vercel Serverless
module.exports = app;
