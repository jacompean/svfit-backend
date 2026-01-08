const jwt = require('jsonwebtoken');

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) throw new Error('JWT_SECRET missing or too short (min 32 chars)');
  return s;
}

function signToken(payload, expiresIn = '12h') {
  return jwt.sign(payload, getJwtSecret(), { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, getJwtSecret());
}

function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: 'Missing Bearer token' });
  try {
    req.auth = verifyToken(token);
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: 'Invalid token' });
  }
}

module.exports = { signToken, verifyToken, authMiddleware };
