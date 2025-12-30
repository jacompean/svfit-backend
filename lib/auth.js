const jwt = require("jsonwebtoken");

function assertJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET is not set");
  }
}

function signToken(payload, options = {}) {
  assertJwtSecret();
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "8h", ...options });
}

function verifyToken(token) {
  assertJwtSecret();
  return jwt.verify(token, process.env.JWT_SECRET);
}

function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const [scheme, token] = h.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || !token) return null;
  return token;
}

module.exports = { signToken, verifyToken, getBearerToken };
