const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "1mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : undefined,
});

function originHost(origin) {
  try {
    if (!origin) return null;
    return new URL(origin).host.toLowerCase();
  } catch {
    return null;
  }
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
    `SELECT 1
     FROM tenant_domains
     WHERE lower(domain)=lower($1) AND COALESCE(is_active,true)=true
     LIMIT 1`,
    [domain]
  );
  return r.rowCount > 0;
}

async function resolveTenantByDomain(domain) {
  if (!domain) return null;
  const r = await pool.query(
    `SELECT t.*
     FROM tenant_domains d
     JOIN tenants t ON t.id = d.tenant_id
     WHERE lower(d.domain)=lower($1)
       AND COALESCE(d.is_active,true)=true
       AND COALESCE(t.is_active,true)=true
     LIMIT 1`,
    [domain]
  );
  return r.rows[0] || null;
}

// ---- CORS + Preflight (critical for "Failed to fetch") ----
app.use(async (req, res, next) => {
  try {
    const origin = req.headers.origin;
    const oHost = originHost(origin);

    // Always allow health (debug)
    if (req.path === "/api/health" || req.path === "/health") {
      if (origin && oHost) setCors(res, origin);
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    // Browser calls MUST have Origin. We'll allow only if domain exists in tenant_domains.
    if (req.method === "OPTIONS") {
      const allowed = await isAllowedDomain(oHost);
      if (allowed && origin) {
        setCors(res, origin);
        return res.status(204).end();
      }
      return res.status(403).end();
    }

    // For non-OPTIONS requests: if Origin exists, enforce allowlist.
    if (origin && oHost) {
      const allowed = await isAllowedDomain(oHost);
      if (!allowed) {
        return res.status(403).json({ ok: false, error: "CORS blocked: origin not allowed", domain: oHost });
      }
      setCors(res, origin);
      req.tenant = await resolveTenantByDomain(oHost);
      return next();
    }

    // No Origin (server-to-server). Allow only for health.
    return res.status(403).json({ ok: false, error: "CORS blocked: origin required" });
  } catch (e) {
    console.error("cors middleware error:", e);
    return res.status(500).json({ ok: false, error: "Server middleware error" });
  }
});

// ---- Auth helper ----
function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    if (!token) return res.status(401).json({ ok: false, error: "Missing token" });

    const secret = process.env.JWT_SECRET;
    if (!secret || secret.length < 16) return res.status(500).json({ ok: false, error: "Missing/weak JWT_SECRET" });

    req.user = jwt.verify(token, secret);
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}

// ---- Routes ----
app.get(["/health", "/api/health"], (req, res) => {
  return res.json({ ok: true, ts: new Date().toISOString() });
});

app.get(["/tenant", "/api/tenant"], async (req, res) => {
  try {
    if (!req.tenant) return res.status(404).json({ ok: false, error: "Tenant not found for this domain" });
    const t = req.tenant;
    return res.json({
      ok: true,
      tenant: {
        id: t.id,
        code: t.code,
        name: t.name,
        accent_color: t.accent_color || "#39FF14",
        logo_url: t.logo_url || null,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Failed to load tenant" });
  }
});

app.post(["/auth/login", "/api/auth/login"], async (req, res) => {
  try {
    const { identifier, password } = req.body || {};
    if (!identifier || !password) return res.status(400).json({ ok: false, error: "identifier and password required" });

    const id = String(identifier).trim();
    const r = await pool.query(
      `SELECT id_code, role, tenant_id, password_hash, is_active
       FROM users
       WHERE id_code=$1
       LIMIT 1`,
      [id]
    );

    if (r.rowCount === 0) return res.status(401).json({ ok: false, error: "Invalid credentials" });

    const u = r.rows[0];
    if (u.is_active === false) return res.status(403).json({ ok: false, error: "User disabled" });

    const ok = await bcrypt.compare(String(password), u.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "Invalid credentials" });

    // For non-global admin, require tenant match
    if (u.role !== "admin") {
      if (!req.tenant) return res.status(403).json({ ok: false, error: "Tenant not resolved for this domain" });
      if (String(u.tenant_id) !== String(req.tenant.id)) {
        return res.status(403).json({ ok: false, error: "User does not belong to this tenant" });
      }
    }

    const token = jwt.sign(
      { sub: u.id_code, role: u.role, tenant_id: u.tenant_id || null },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    return res.json({
      ok: true,
      token,
      user: { id_code: u.id_code, role: u.role, tenant_id: u.tenant_id || null },
      tenant: req.tenant ? { id: req.tenant.id, code: req.tenant.code, name: req.tenant.name } : null,
    });
  } catch (e) {
    console.error("login error:", e);
    return res.status(500).json({ ok: false, error: "Login failed" });
  }
});

app.get(["/me", "/api/me"], requireAuth, async (req, res) => {
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

    return res.json({ ok: true, user: r.rows[0] });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Failed to load session" });
  }
});

// default
app.all("*", (req, res) => {
  return res.status(404).json({ ok: false, error: "Not found" });
});

module.exports = app;
