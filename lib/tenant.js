const { query } = require('./db');

function normalizeDomain(domain) {
  if (!domain) return '';
  return domain.toLowerCase().replace(/^https?:\/\//, '').replace(/:\d+$/, '').replace(/\/$/, '');
}

async function resolveTenantFromOrigin(origin) {
  const d = normalizeDomain(origin);
  if (!d) return null;
  const r = await query(
    `SELECT t.* 
     FROM tenant_domains td
     JOIN tenants t ON t.id = td.tenant_id
     WHERE td.is_active = true AND t.is_active = true AND td.domain = $1
     LIMIT 1`,
    [d]
  );
  return r.rows[0] || null;
}

async function isOriginAllowedForTenant(origin, tenantId) {
  const d = normalizeDomain(origin);
  if (!d) return false;
  const r = await query(
    `SELECT 1 FROM tenant_domains 
     WHERE tenant_id = $1 AND is_active = true AND domain = $2
     LIMIT 1`,
    [tenantId, d]
  );
  return r.rowCount > 0;
}

module.exports = { normalizeDomain, resolveTenantFromOrigin, isOriginAllowedForTenant };
