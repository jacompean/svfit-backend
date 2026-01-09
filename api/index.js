// api/index.js
// SVFIT Backend v2 - routing + CORS preflight + tenant by domain + setup + login + tenant endpoint

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------- DB ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : undefined,
});

// ---------- Helpers ----------
function json(res, status, payload) {
  return res.status(status).json(payload);
}

function originToHost(origin) {
  try {
    if (!origin) return null;
    return new URL(origin).host.toLowerCase();
  } catch {
    return null;
  }
}

function hostFromReq(req) {
  const xfHost = req.headers["x-forwarded-host"];
  const host = (Array.isArray(xfHost) ? xfHost[0] : xfHost) || req.headers.host;
  if (!host) return null;
  return String(host).split(",")[0].trim().toLowerCase();
}

function cleanDomain(input) {
  if (!input) return null;
  return String(input)
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
}

function setCors(res, origin) {
  // origin must be echoed when credentials are used
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

function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 16) throw new Error("Missing/weak JWT_SECRET");
  return jwt.sign(payload, secret, { expiresIn: "8h" });
}

// ---------- CORS + Preflight + Tenant gate (IMPORTANT: before routes) ----------
app.use(async (req, res, next) => {
  try {
    const origin = req.headers.origin;
    const originHost = originToHost(origin);
    const host = hostFromReq(req);

    // Allow /api/health always (debug-friendly)
    if (req.path === "/api/health" || req.path === "/health") {
      if (origin && originHost) setCors(res, origin);
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    // Setup route: allow CORS only while SETUP_KEY exists (preflight too)
    const isSetup =
      req.path === "/api/admin/setup" || req.path === "/admin/setup";
    if (isSetup && process.env.SETUP_KEY) {
      if (origin && originHost) setCors(res, origin);
      if (req.method === "OPTIONS") return res.status(204).end();
      return next();
    }

    // Preflight for normal endpoints:
    // Browser sends OPTIONS with Origin. We must respond 204 if allowed.
    if (req.method === "OPTIONS") {
      // Only accept if Origin host is in tenant_domains
      const allowed = await isAllowedDomain(originHost);
      if (allowed && origin) {
        setCors(res, origin);
        return res.status(204).end();
      }
      return res.status(403).end();
    }

    // Normal calls: strict allowlist
    // If Origin exists -> use it. Otherwise fall back to Host (useful for server-to-server).
    const domainToCheck = originHost || host;
    const allowed = await isAllowedDomain(domainToCheck);

    if (!allowed) {
      // Intentionally no CORS headers so browser treats it as blocked.
      return json(res, 403, {
        ok: false,
        error: "CORS blocked: origin not allowed",
        domain: domainToCheck,
      });
    }

    // If browser call, echo CORS headers
    if (origin && originHost) setCors(res, origin);

    // Attach tenant (for non-admin users)
    req.tenant = await resolveTenantByDomain(domainToCheck);

    return next();
  } catch (err) {
    console.error("middleware error:", err);
    return json(res, 500, { ok: false, error: "Server error in middleware" });
  }
});

// ---------- Routes ----------

// Health
app.get(["/health", "/api/health"], (req, res) => {
  return json(res, 200, {
    ok: true,
    service: "svfit-backend",
    ts: new Date().toISOString(),
  });
});

// Tenant info (frontend branding)
app.get(["/tenant", "/api/tenant"], async (req, res) => {
  try {
    if (!req.tenant) {
      return json(res, 404, { ok: false, error: "Tenant not found for this domain" });
    }
    const t = req.tenant;

    return json(res, 200, {
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
    console.error("tenant error:", err);
    return json(res, 500, { ok: false, error: "Failed to load tenant" });
  }
});

// Setup (TEMPORARY) - requires env SETUP_KEY
app.post(["/admin/setup", "/api/admin/setup"], async (req, res) => {
  try {
    const envKey = process.env.SETUP_KEY;
    if (!envKey) return json(res, 403, { ok: false, error: "Setup disabled" });

    const { setupKey, adminPassword, tenantCode, tenantName, tenantDomain } = req.body || {};

    if (!setupKey || setupKey !== envKey) return json(res, 403, { ok: false, error: "Invalid setupKey" });
    if (!adminPassword || String(adminPassword).length < 6) return json(res, 400, { ok: false, error: "adminPassword must be >= 6 chars" });

    const code = String(tenantCode || "").toUpperCase();
    if (code.length !== 2) return json(res, 400, { ok: false, error: "tenantCode must be 2 letters (e.g. SV)" });

    if (!tenantName) return json(res, 400, { ok: f
