module.exports = (req, res) => {
  res.status(200).json({ ok: true, message: 'SVFIT API is running. Try /api/health' });
};
