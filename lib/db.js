const { Pool } = require('pg');

let _pool;

function getPool() {
  if (!_pool) {
    const cs = process.env.DATABASE_URL;
    if (!cs) throw new Error('DATABASE_URL missing');
    _pool = new Pool({
      connectionString: cs,
      ssl: cs.includes('sslmode=require') ? { rejectUnauthorized: false } : undefined
    });
  }
  return _pool;
}

async function query(text, params) {
  const pool = getPool();
  return pool.query(text, params);
}

module.exports = { getPool, query };
