function requireRole(allowedRoles) {
  return (req, res, next) => {
    const role = req.auth?.role;
    if (!role) return res.status(401).json({ ok: false, error: 'Unauthorized' });
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }
    next();
  };
}

module.exports = { requireRole };
