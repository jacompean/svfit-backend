const { verifyToken, getBearerToken } = require("./auth");

function jsonError(res, status, message, extra = {}) {
  return res.status(status).json({ ok: false, error: message, ...extra });
}

function requireAuth(req, res, next) {
  try {
    const token = getBearerToken(req);
    if (!token) return jsonError(res, 401, "Missing Authorization: Bearer token");
    const decoded = verifyToken(token);
    req.user = decoded;
    return next();
  } catch (err) {
    return jsonError(res, 401, "Invalid or expired token");
  }
}

function requireRole(roles) {
  const allowed = Array.isArray(roles) ? roles : [roles];
  return (req, res, next) => {
    if (!req.user) return jsonError(res, 401, "Unauthorized");
    if (!allowed.includes(req.user.role)) return jsonError(res, 403, "Forbidden");
    return next();
  };
}

// Very small in-memory rate limiter. Works best for low traffic.
// NOTE: On serverless, memory isn't shared across instances.
function rateLimit({ windowMs = 60_000, max = 120 } = {}) {
  const hits = new Map(); // ip -> {count, resetAt}
  return (req, res, next) => {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString().split(",")[0].trim();
    const now = Date.now();
    const rec = hits.get(ip);
    if (!rec || rec.resetAt <= now) {
      hits.set(ip, { count: 1, resetAt: now + windowMs });
      return next();
    }
    rec.count += 1;
    if (rec.count > max) {
      const retryAfter = Math.ceil((rec.resetAt - now) / 1000);
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).json({ ok: false, error: "Too many requests" });
    }
    return next();
  };
}

module.exports = { jsonError, requireAuth, requireRole, rateLimit };
