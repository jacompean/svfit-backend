function pad4(n) {
  const s = String(n);
  return s.length >= 4 ? s : ('0000' + s).slice(-4);
}

function parseIdCode(id) {
  const v = (id || '').trim().toUpperCase();
  if (!/^[A-Z]{2}\d{4}$/.test(v)) return null;
  return { code: v.slice(0,2), num: parseInt(v.slice(2), 10) };
}

module.exports = { pad4, parseIdCode };
