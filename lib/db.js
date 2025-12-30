const { Pool } = require("pg");

let pool;

/**
 * Singleton Pool for serverless-friendly usage.
 */
function getPool() {
  if (!pool) {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is not set");
    }
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      // Neon needs SSL; connection string typically includes sslmode=require.
      // If your string doesn't, uncomment below:
      // ssl: { rejectUnauthorized: false },
      max: 5
    });
  }
  return pool;
}

async function query(text, params) {
  const p = getPool();
  return p.query(text, params);
}

module.exports = { getPool, query };
