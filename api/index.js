const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const { query } = require('../lib/db');
const { requireAuth, requireRole } = require('../lib/auth');
const { resolveTenantFromOrigin, resolveTenantFromCode, normalizeDomain } = require('../lib/tenant');
const { pad4, parseIdCode } = require('../lib/utils');

const app = express();
app.use(express.json({ limit: '2mb' }));

// Tenant + Origin enforcement middleware
app.use(async (req, res, next) => {
  try {
    // Allow health without tenant
    if (req.path === '/api/health') return next();

    const origin = req.headers.origin || '';
    const headerDomain = req.headers['x-tenant-domain'] || '';
    const headerCode = req.headers['x-tenant-code'] || '';

    let tenant = null;
    let originDomain = '';

    if (origin) {
      tenant = await resolveTenantFromOrigin(origin);
      originDomain = normalizeDomain(origin);
    } else if (headerDomain) {
      tenant = await resolveTenantFromOrigin(headerDomain);
      originDomain = normalizeDomain(headerDomain);
    } else if (headerCode) {
      tenant = await resolveTenantFromCode(headerCode);
    }

    if (origin && !tenant) {
      return res.status(403).json({ ok: false, error: 'CORS blocked: origin not configured' });
    }

    req.tenant = tenant || null;
    req.originDomain = originDomain || '';
    return next();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Tenant resolution failed' });
  }
});

// CORS headers (strict - only allow configured origin)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && req.tenant) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  return next();
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ===== Setup (run once) =====
app.post('/api/admin/setup', async (req, res) => {
  const schema = z.object({
    setupKey: z.string().min(1),
    adminPassword: z.string().min(6),
    tenantCode: z.string().regex(/^[A-Z]{2}$/),
    tenantName: z.string().min(2),
    tenantDomain: z.string().min(3) // e.g. svfit.vercel.app (no protocol)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: parsed.error.issues });
  if (!process.env.SETUP_KEY || parsed.data.setupKey !== process.env.SETUP_KEY) {
    return res.status(403).json({ ok: false, error: 'Invalid setup key' });
  }

  try {
    // Create global admin if not exists
    const existingAdmin = await query(`SELECT id FROM users WHERE username = 'admin' LIMIT 1`);
    if (existingAdmin.rowCount === 0) {
      const hash = await bcrypt.hash(parsed.data.adminPassword, 10);
      await query(
        `INSERT INTO users (role, username, password_hash, is_active) VALUES ('admin', 'admin', $1, true)`,
        [hash]
      );
    }

    // Create tenant if not exists
    const tCode = parsed.data.tenantCode.toUpperCase();
    const existingTenant = await query(`SELECT id FROM tenants WHERE code = $1 LIMIT 1`, [tCode]);
    let tenantId;
    if (existingTenant.rowCount === 0) {
      const ins = await query(
        `INSERT INTO tenants (code, name) VALUES ($1, $2) RETURNING id`,
        [tCode, parsed.data.tenantName]
      );
      tenantId = ins.rows[0].id;
    } else {
      tenantId = existingTenant.rows[0].id;
    }

    // Add domain
    const domain = parsed.data.tenantDomain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
    await query(
      `INSERT INTO tenant_domains (tenant_id, domain, is_active) VALUES ($1, $2, true)
       ON CONFLICT (tenant_id, domain) DO UPDATE SET is_active = true`,
      [tenantId, domain]
    );

    // Create initial admin_tenant if not exists
    const existingAdminTenant = await query(
      `SELECT id FROM users WHERE tenant_id = $1 AND role = 'admin_tenant' LIMIT 1`,
      [tenantId]
    );
    if (existingAdminTenant.rowCount === 0) {
      // allocate id_code
      const t = await query(`SELECT code, next_seq FROM tenants WHERE id = $1`, [tenantId]);
      const nextSeq = t.rows[0].next_seq;
      const idCode = `${t.rows[0].code}${pad4(nextSeq)}`;
      const pwdTemp = 'Admin123!'; // user can change later
      const hash = await bcrypt.hash(pwdTemp, 10);

      await query('BEGIN');
      await query(
        `INSERT INTO users (tenant_id, role, id_code, password_hash, is_active)
         VALUES ($1, 'admin_tenant', $2, $3, true)`,
        [tenantId, idCode, hash]
      );
      await query(`UPDATE tenants SET next_seq = next_seq + 1 WHERE id = $1`, [tenantId]);
      await query('COMMIT');

      // Seed default plans if none
      const planCount = await query(`SELECT 1 FROM plans WHERE tenant_id = $1 LIMIT 1`, [tenantId]);
      if (planCount.rowCount === 0) {
        await query(
          `INSERT INTO plans (tenant_id, name, price_cents, duration_days, includes_personalized)
           VALUES 
            ($1, 'Membresía Estándar', 0, 30, false),
            ($1, 'Membresía con Personalizado', 0, 30, true),
            ($1, 'Membresía Teens', 0, 30, false)`,
          [tenantId]
        );
      }

      return res.json({ ok: true, message: 'Setup complete', adminTenantIdCode: idCode, adminTenantTempPassword: pwdTemp });
    }

    return res.json({ ok: true, message: 'Setup complete (already initialized)' });
  } catch (e) {
    console.error(e);
    try { await query('ROLLBACK'); } catch {}
    return res.status(500).json({ ok: false, error: 'Setup failed' });
  }
});

// ===== Auth =====
app.post('/api/auth/login', async (req, res) => {
  const schema = z.object({
    identifier: z.string().min(1),
    password: z.string().min(6)
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: parsed.error.issues });

  const identifier = parsed.data.identifier.trim();
  const password = parsed.data.password;

  try {
    if (identifier.toLowerCase() === 'admin') {
      const r = await query(`SELECT id, role, username, password_hash, is_active FROM users WHERE username='admin' LIMIT 1`);
      if (r.rowCount === 0) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      const u = r.rows[0];
      if (!u.is_active) return res.status(403).json({ ok: false, error: 'User disabled' });
      const ok = await bcrypt.compare(password, u.password_hash);
      if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

      const token = jwt.sign({ uid: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '12h' });
      return res.json({ ok: true, token, user: { role: u.role, username: 'admin' } });
    }

    // Must have tenant from origin
    const tenant = req.tenant;
    if (!tenant) return res.status(403).json({ ok: false, error: 'Tenant required' });

    const idInfo = parseIdCode(identifier);
    if (!idInfo || idInfo.code !== tenant.code) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }

    const r = await query(
      `SELECT id, role, id_code, password_hash, is_active, tenant_id
       FROM users
       WHERE tenant_id = $1 AND id_code = $2
       LIMIT 1`,
      [tenant.id, identifier.toUpperCase()]
    );
    if (r.rowCount === 0) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    const u = r.rows[0];
    if (!u.is_active) return res.status(403).json({ ok: false, error: 'User disabled' });

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

    const token = jwt.sign(
      { uid: u.id, role: u.role, tenant_id: tenant.id, tenant_code: tenant.code },
      process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    return res.json({ ok: true, token, user: { role: u.role, id_code: u.id_code, tenant: { id: tenant.id, code: tenant.code, name: tenant.name } } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Login failed' });
  }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      return res.json({ ok: true, user: { role: 'admin', username: 'admin' } });
    }
    const r = await query(
      `SELECT id, role, id_code, tenant_id FROM users WHERE id = $1`,
      [req.user.uid]
    );
    if (r.rowCount === 0) return res.status(404).json({ ok: false, error: 'Not found' });
    return res.json({ ok: true, user: r.rows[0] });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Failed' });
  }
});

// ===== Admin Global: Tenants =====
app.get('/api/admin/tenants', requireAuth, requireRole(['admin']), async (req, res) => {
  const r = await query(`SELECT * FROM tenants ORDER BY created_at DESC`);
  return res.json({ ok: true, tenants: r.rows });
});

app.post('/api/admin/tenants', requireAuth, requireRole(['admin']), async (req, res) => {
  const schema = z.object({
    code: z.string().regex(/^[A-Z]{2}$/),
    name: z.string().min(2),
    accent_color: z.string().optional(),
    logo_url: z.string().url().optional().or(z.literal(''))
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const d = p.data;
  const ins = await query(
    `INSERT INTO tenants (code, name, accent_color, logo_url) VALUES ($1,$2,$3,$4) RETURNING *`,
    [d.code.toUpperCase(), d.name, d.accent_color || '#39FF14', d.logo_url || null]
  );
  return res.json({ ok: true, tenant: ins.rows[0] });
});

app.put('/api/admin/tenants/:id', requireAuth, requireRole(['admin']), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2).optional(),
    accent_color: z.string().optional(),
    logo_url: z.string().url().optional().or(z.literal('')),
    is_active: z.boolean().optional()
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const d = p.data;
  const upd = await query(
    `UPDATE tenants 
     SET name = COALESCE($2, name),
         accent_color = COALESCE($3, accent_color),
         logo_url = COALESCE(NULLIF($4,''), logo_url),
         is_active = COALESCE($5, is_active)
     WHERE id = $1
     RETURNING *`,
    [req.params.id, d.name || null, d.accent_color || null, d.logo_url ?? '', d.is_active ?? null]
  );
  if (upd.rowCount === 0) return res.status(404).json({ ok: false, error: 'Tenant not found' });
  return res.json({ ok: true, tenant: upd.rows[0] });
});

// domains
app.get('/api/admin/tenants/:id/domains', requireAuth, requireRole(['admin']), async (req, res) => {
  const r = await query(`SELECT * FROM tenant_domains WHERE tenant_id = $1 ORDER BY created_at DESC`, [req.params.id]);
  return res.json({ ok: true, domains: r.rows });
});

app.post('/api/admin/tenants/:id/domains', requireAuth, requireRole(['admin']), async (req, res) => {
  const schema = z.object({ domain: z.string().min(3) });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const domain = p.data.domain.toLowerCase().replace(/^https?:\/\//,'').replace(/\/$/,'');
  const ins = await query(
    `INSERT INTO tenant_domains (tenant_id, domain, is_active) VALUES ($1,$2,true)
     ON CONFLICT (tenant_id, domain) DO UPDATE SET is_active = true
     RETURNING *`,
    [req.params.id, domain]
  );
  return res.json({ ok: true, domain: ins.rows[0] });
});

app.put('/api/admin/domains/:domainId', requireAuth, requireRole(['admin']), async (req, res) => {
  const schema = z.object({ is_active: z.boolean() });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const upd = await query(`UPDATE tenant_domains SET is_active = $2 WHERE id = $1 RETURNING *`, [req.params.domainId, p.data.is_active]);
  if (upd.rowCount === 0) return res.status(404).json({ ok: false, error: 'Domain not found' });
  return res.json({ ok: true, domain: upd.rows[0] });
});

// Create admin_tenant for a tenant
app.post('/api/admin/tenants/:id/create-admin-tenant', requireAuth, requireRole(['admin']), async (req, res) => {
  const schema = z.object({ temp_password: z.string().min(6).optional() });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  const t = await query(`SELECT id, code, next_seq FROM tenants WHERE id = $1`, [req.params.id]);
  if (t.rowCount === 0) return res.status(404).json({ ok: false, error: 'Tenant not found' });
  const tenant = t.rows[0];

  const existing = await query(`SELECT id, id_code FROM users WHERE tenant_id = $1 AND role = 'admin_tenant' LIMIT 1`, [tenant.id]);
  if (existing.rowCount > 0) {
    return res.json({ ok: true, message: 'Already exists', id_code: existing.rows[0].id_code });
  }

  const idCode = `${tenant.code}${pad4(tenant.next_seq)}`;
  const pwdTemp = p.data.temp_password || 'Admin123!';
  const hash = await bcrypt.hash(pwdTemp, 10);

  await query('BEGIN');
  try {
    await query(
      `INSERT INTO users (tenant_id, role, id_code, password_hash, is_active)
       VALUES ($1, 'admin_tenant', $2, $3, true)`,
      [tenant.id, idCode, hash]
    );
    await query(`UPDATE tenants SET next_seq = next_seq + 1 WHERE id = $1`, [tenant.id]);
    await query('COMMIT');
  } catch (e) {
    await query('ROLLBACK');
    throw e;
  }

  return res.json({ ok: true, id_code: idCode, temp_password: pwdTemp });
});

// ===== Tenant Branding endpoint =====
app.get('/api/tenant', async (req, res) => {
  const t = req.tenant;
  if (!t) return res.status(404).json({ ok: false, error: 'Tenant not resolved' });
  return res.json({ ok: true, tenant: { id: t.id, code: t.code, name: t.name, accent_color: t.accent_color, logo_url: t.logo_url } });
});

// ===== Users (admin_tenant/admin/staff can create staff/coach) =====
app.post('/api/users', requireAuth, requireRole(['admin','admin_tenant','staff']), async (req, res) => {
  // global admin can create for any tenant by providing tenant_id; others only for their tenant
  const schema = z.object({
    tenant_id: z.string().uuid().optional(),
    role: z.enum(['admin_tenant','staff','coach']),
    password: z.string().min(6)
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  let tenantId = req.user.role === 'admin' ? (p.data.tenant_id || req.tenant?.id) : req.user.tenant_id;
  if (!tenantId) return res.status(400).json({ ok: false, error: 'tenant_id required' });

  const t = await query(`SELECT id, code, next_seq FROM tenants WHERE id = $1`, [tenantId]);
  if (t.rowCount === 0) return res.status(404).json({ ok: false, error: 'Tenant not found' });
  const tenant = t.rows[0];

  const idCode = `${tenant.code}${pad4(tenant.next_seq)}`;
  const hash = await bcrypt.hash(p.data.password, 10);

  await query('BEGIN');
  try {
    await query(
      `INSERT INTO users (tenant_id, role, id_code, password_hash, is_active)
       VALUES ($1, $2, $3, $4, true)`,
      [tenant.id, p.data.role, idCode, hash]
    );
    await query(`UPDATE tenants SET next_seq = next_seq + 1 WHERE id = $1`, [tenant.id]);
    await query('COMMIT');
  } catch (e) {
    await query('ROLLBACK');
    throw e;
  }
  return res.json({ ok: true, id_code: idCode });
});

// ===== Members =====
app.post('/api/members', requireAuth, requireRole(['admin','admin_tenant','staff']), async (req, res) => {
  const schema = z.object({
    full_name: z.string().min(2),
    phone: z.string().optional(),
    email: z.string().optional(),
    notes: z.string().optional()
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const ins = await query(
    `INSERT INTO members (tenant_id, full_name, phone, email, notes)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [tenantId, p.data.full_name, p.data.phone || null, p.data.email || null, p.data.notes || null]
  );
  return res.json({ ok: true, member: ins.rows[0] });
});

// Activate member access (creates user member)
app.post('/api/members/:id/activate', requireAuth, requireRole(['admin','admin_tenant','staff']), async (req, res) => {
  const schema = z.object({ password: z.string().min(6) });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const m = await query(`SELECT id, tenant_id, user_id FROM members WHERE id = $1 AND tenant_id = $2`, [req.params.id, tenantId]);
  if (m.rowCount === 0) return res.status(404).json({ ok: false, error: 'Member not found' });
  if (m.rows[0].user_id) return res.json({ ok: true, message: 'Already activated' });

  const t = await query(`SELECT id, code, next_seq FROM tenants WHERE id = $1`, [tenantId]);
  const tenant = t.rows[0];
  const idCode = `${tenant.code}${pad4(tenant.next_seq)}`;
  const hash = await bcrypt.hash(p.data.password, 10);

  await query('BEGIN');
  try {
    const uins = await query(
      `INSERT INTO users (tenant_id, role, id_code, password_hash, is_active)
       VALUES ($1, 'member', $2, $3, true)
       RETURNING id, id_code`,
      [tenant.id, idCode, hash]
    );
    await query(`UPDATE tenants SET next_seq = next_seq + 1 WHERE id = $1`, [tenant.id]);
    await query(`UPDATE members SET user_id = $2 WHERE id = $1`, [m.rows[0].id, uins.rows[0].id]);
    await query('COMMIT');
    return res.json({ ok: true, id_code: uins.rows[0].id_code });
  } catch (e) {
    await query('ROLLBACK');
    throw e;
  }
});

// ===== Plans =====
app.get('/api/plans', requireAuth, async (req, res) => {
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const r = await query(`SELECT * FROM plans WHERE tenant_id = $1 ORDER BY created_at DESC`, [tenantId]);
  return res.json({ ok: true, plans: r.rows });
});

app.post('/api/plans', requireAuth, requireRole(['admin','admin_tenant']), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    price_cents: z.number().int().min(0).default(0),
    duration_days: z.number().int().min(1).default(30),
    includes_personalized: z.boolean().default(false),
    sessions_included: z.number().int().min(0).optional(),
    teens_allowed_start: z.string().optional(),
    teens_allowed_end: z.string().optional(),
    teens_warning_message: z.string().optional()
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const ins = await query(
    `INSERT INTO plans (tenant_id, name, price_cents, duration_days, includes_personalized, sessions_included, teens_allowed_start, teens_allowed_end, teens_warning_message)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [tenantId, p.data.name, p.data.price_cents, p.data.duration_days, p.data.includes_personalized, p.data.sessions_included || null,
     p.data.teens_allowed_start || null, p.data.teens_allowed_end || null, p.data.teens_warning_message || null]
  );
  return res.json({ ok: true, plan: ins.rows[0] });
});

// ===== Membership assign =====
app.post('/api/members/:id/membership', requireAuth, requireRole(['admin','admin_tenant','staff']), async (req, res) => {
  const schema = z.object({
    plan_id: z.string().uuid(),
    start_date: z.string().optional() // YYYY-MM-DD
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });

  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const plan = await query(`SELECT * FROM plans WHERE id = $1 AND tenant_id = $2`, [p.data.plan_id, tenantId]);
  if (plan.rowCount === 0) return res.status(404).json({ ok: false, error: 'Plan not found' });

  const start = p.data.start_date ? new Date(p.data.start_date) : new Date();
  const end = new Date(start);
  end.setDate(end.getDate() + plan.rows[0].duration_days);

  const ins = await query(
    `INSERT INTO memberships (tenant_id, member_id, plan_id, start_date, end_date, status)
     VALUES ($1,$2,$3,$4,$5,'active') RETURNING *`,
    [tenantId, req.params.id, p.data.plan_id, start.toISOString().slice(0,10), end.toISOString().slice(0,10)]
  );
  return res.json({ ok: true, membership: ins.rows[0] });
});

app.get('/api/memberships/expiring', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const days = parseInt(req.query.days || '7', 10);
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const r = await query(
    `SELECT m.id as membership_id, m.end_date, mem.id as member_id, mem.full_name
     FROM memberships m
     JOIN members mem ON mem.id = m.member_id
     WHERE m.tenant_id = $1 AND m.status='active' AND m.end_date <= (CURRENT_DATE + $2::int)
     ORDER BY m.end_date ASC`,
    [tenantId, days]
  );
  return res.json({ ok: true, expiring: r.rows });
});

// ===== Attendance (soft warning for teens) =====
app.post('/api/members/:id/checkin', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const membership = await query(
    `SELECT m.*, p.teens_allowed_start, p.teens_allowed_end, p.teens_warning_message, p.name as plan_name
     FROM memberships m
     JOIN plans p ON p.id = m.plan_id
     WHERE m.tenant_id = $1 AND m.member_id = $2 AND m.status='active'
     ORDER BY m.end_date DESC LIMIT 1`,
    [tenantId, req.params.id]
  );

  let warned = false;
  let warning_message = null;

  if (membership.rowCount > 0) {
    const row = membership.rows[0];
    const today = new Date();
    const endDate = new Date(row.end_date);
    // Membership expired?
    if (endDate < new Date(today.toISOString().slice(0,10))) {
      warned = true;
      warning_message = 'Membresía vencida';
    }
    // Teens soft rule
    if (row.plan_name.toLowerCase().includes('teens') && row.teens_allowed_start && row.teens_allowed_end) {
      const hhmm = today.toTimeString().slice(0,5);
      const start = row.teens_allowed_start.slice(0,5);
      const end = row.teens_allowed_end.slice(0,5);
      if (!(hhmm >= start && hhmm <= end)) {
        warned = true;
        warning_message = row.teens_warning_message || 'Teens: fuera de horario recomendado';
      }
    }
  } else {
    warned = true;
    warning_message = 'Sin membresía activa';
  }

  const ins = await query(
    `INSERT INTO attendance (tenant_id, member_id, method, warned, warning_message)
     VALUES ($1,$2,'id',$3,$4) RETURNING *`,
    [tenantId, req.params.id, warned, warning_message]
  );
  return res.json({ ok: true, attendance: ins.rows[0] });
});

// ===== Inventory =====
app.get('/api/products', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const r = await query(`SELECT * FROM products WHERE tenant_id = $1 AND is_active=true ORDER BY name`, [tenantId]);
  return res.json({ ok: true, products: r.rows });
});

app.post('/api/products', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    sku: z.string().optional(),
    price_cents: z.number().int().min(0),
    stock: z.number().int().min(0).default(0)
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const ins = await query(
    `INSERT INTO products (tenant_id, name, sku, price_cents, stock) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [tenantId, p.data.name, p.data.sku || null, p.data.price_cents, p.data.stock]
  );
  return res.json({ ok: true, product: ins.rows[0] });
});

app.put('/api/products/:id', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({
    name: z.string().min(2).optional(),
    sku: z.string().optional(),
    price_cents: z.number().int().min(0).optional(),
    is_active: z.boolean().optional()
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const upd = await query(
    `UPDATE products
     SET name = COALESCE($3, name),
         sku = COALESCE($4, sku),
         price_cents = COALESCE($5, price_cents),
         is_active = COALESCE($6, is_active)
     WHERE id = $1 AND tenant_id = $2
     RETURNING *`,
    [req.params.id, tenantId, p.data.name || null, p.data.sku || null, p.data.price_cents ?? null, p.data.is_active ?? null]
  );
  if (upd.rowCount === 0) return res.status(404).json({ ok: false, error: 'Product not found' });
  return res.json({ ok: true, product: upd.rows[0] });
});

app.delete('/api/products/:id', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const upd = await query(
    `UPDATE products SET is_active=false WHERE id=$1 AND tenant_id=$2 RETURNING *`,
    [req.params.id, tenantId]
  );
  if (upd.rowCount === 0) return res.status(404).json({ ok: false, error: 'Product not found' });
  return res.json({ ok: true });
});

app.post('/api/products/:id/adjust', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({ delta: z.number().int(), reason: z.string().min(2) });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok: false, error: p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  await query('BEGIN');
  try {
    const prod = await query(`SELECT stock FROM products WHERE id=$1 AND tenant_id=$2 FOR UPDATE`, [req.params.id, tenantId]);
    if (prod.rowCount === 0) { await query('ROLLBACK'); return res.status(404).json({ ok:false, error:'Product not found' }); }
    const newStock = prod.rows[0].stock + p.data.delta;
    if (newStock < 0) { await query('ROLLBACK'); return res.status(400).json({ ok:false, error:'Stock cannot go negative' }); }
    await query(`UPDATE products SET stock=$3 WHERE id=$1 AND tenant_id=$2`, [req.params.id, tenantId, newStock]);
    await query(
      `INSERT INTO inventory_movements (tenant_id, product_id, delta, reason, created_by) VALUES ($1,$2,$3,$4,$5)`,
      [tenantId, req.params.id, p.data.delta, p.data.reason, req.user.uid]
    );
    await query('COMMIT');
    return res.json({ ok:true, stock: newStock });
  } catch (e) {
    await query('ROLLBACK');
    console.error(e);
    return res.status(500).json({ ok:false, error:'Adjust failed' });
  }
});

// ===== Cash sessions =====
app.post('/api/cash-sessions/open', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({ opening_cash_cents: z.number().int().min(0).default(0) });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error:p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const open = await query(`SELECT id FROM cash_sessions WHERE tenant_id=$1 AND status='open' LIMIT 1`, [tenantId]);
  if (open.rowCount > 0) return res.status(400).json({ ok:false, error:'Cash session already open' });

  const ins = await query(
    `INSERT INTO cash_sessions (tenant_id, opened_by, opening_cash_cents, status) VALUES ($1,$2,$3,'open') RETURNING *`,
    [tenantId, req.user.uid, p.data.opening_cash_cents]
  );
  return res.json({ ok:true, cash_session: ins.rows[0] });
});

app.post('/api/cash-sessions/:id/close', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({ closing_cash_cents: z.number().int().min(0) });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error:p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  const upd = await query(
    `UPDATE cash_sessions 
     SET status='closed', closed_at=now(), closed_by=$3, closing_cash_cents=$4
     WHERE id=$1 AND tenant_id=$2 AND status='open'
     RETURNING *`,
    [req.params.id, tenantId, req.user.uid, p.data.closing_cash_cents]
  );
  if (upd.rowCount === 0) return res.status(404).json({ ok:false, error:'Open cash session not found' });
  return res.json({ ok:true, cash_session: upd.rows[0] });
});

app.get('/api/cash-sessions/:id/summary', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;
  const cs = await query(`SELECT * FROM cash_sessions WHERE id=$1 AND tenant_id=$2`, [req.params.id, tenantId]);
  if (cs.rowCount === 0) return res.status(404).json({ ok:false, error:'Not found' });

  const sales = await query(
    `SELECT payment_method, SUM(total_cents)::int as total_cents, COUNT(*)::int as count
     FROM sales
     WHERE tenant_id=$1 AND cash_session_id=$2
     GROUP BY payment_method`,
    [tenantId, req.params.id]
  );

  return res.json({ ok:true, cash_session: cs.rows[0], sales_by_method: sales.rows });
});

// ===== Sales =====
app.post('/api/sales', requireAuth, requireRole(['admin','admin_tenant','staff','coach']), async (req, res) => {
  const schema = z.object({
    payment_method: z.enum(['cash','card','transfer']),
    items: z.array(z.object({
      product_id: z.string().uuid(),
      qty: z.number().int().min(1)
    })).min(1),
    note: z.string().optional()
  });
  const p = schema.safeParse(req.body);
  if (!p.success) return res.status(400).json({ ok:false, error:p.error.issues });
  const tenantId = req.user.role === 'admin' ? req.tenant.id : req.user.tenant_id;

  let cashSessionId = null;
  if (p.data.payment_method === 'cash') {
    const open = await query(`SELECT id FROM cash_sessions WHERE tenant_id=$1 AND status='open' LIMIT 1`, [tenantId]);
    if (open.rowCount === 0) return res.status(400).json({ ok:false, error:'No open cash session' });
    cashSessionId = open.rows[0].id;
  }

  // lock products & compute totals
  await query('BEGIN');
  try {
    let total = 0;
    const lineItems = [];
    for (const it of p.data.items) {
      const pr = await query(`SELECT id, price_cents, stock FROM products WHERE id=$1 AND tenant_id=$2 AND is_active=true FOR UPDATE`, [it.product_id, tenantId]);
      if (pr.rowCount === 0) throw new Error('Product not found');
      const prod = pr.rows[0];
      if (prod.stock < it.qty) throw new Error('Insufficient stock');
      const lineTotal = prod.price_cents * it.qty;
      total += lineTotal;
      lineItems.push({ product_id: prod.id, qty: it.qty, unit_price_cents: prod.price_cents, line_total_cents: lineTotal });
      await query(`UPDATE products SET stock = stock - $3 WHERE id=$1 AND tenant_id=$2`, [prod.id, tenantId, it.qty]);
      await query(
        `INSERT INTO inventory_movements (tenant_id, product_id, delta, reason, created_by)
         VALUES ($1,$2,$3,$4,$5)`,
        [tenantId, prod.id, -it.qty, 'sale', req.user.uid]
      );
    }

    const s = await query(
      `INSERT INTO sales (tenant_id, cash_session_id, sold_by, payment_method, total_cents, note)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [tenantId, cashSessionId, req.user.uid, p.data.payment_method, total, p.data.note || null]
    );
    for (const li of lineItems) {
      await query(
        `INSERT INTO sale_items (sale_id, product_id, qty, unit_price_cents, line_total_cents)
         VALUES ($1,$2,$3,$4,$5)`,
        [s.rows[0].id, li.product_id, li.qty, li.unit_price_cents, li.line_total_cents]
      );
    }
    await query('COMMIT');
    return res.json({ ok:true, sale: s.rows[0] });
  } catch (e) {
    await query('ROLLBACK');
    return res.status(400).json({ ok:false, error: e.message });
  }
});

// ===== Member portal endpoints =====
app.get('/api/member/summary', requireAuth, requireRole(['member']), async (req, res) => {
  const tenantId = req.user.tenant_id;
  const mem = await query(
    `SELECT mem.*, u.id_code
     FROM members mem
     JOIN users u ON u.id = mem.user_id
     WHERE mem.user_id = $1 AND mem.tenant_id = $2
     LIMIT 1`,
    [req.user.uid, tenantId]
  );
  if (mem.rowCount === 0) return res.status(404).json({ ok:false, error:'Member profile not found' });

  const membership = await query(
    `SELECT m.*, p.name as plan_name FROM memberships m JOIN plans p ON p.id=m.plan_id
     WHERE m.tenant_id=$1 AND m.member_id=$2 ORDER BY m.end_date DESC LIMIT 1`,
    [tenantId, mem.rows[0].id]
  );

  const attendanceCount = await query(
    `SELECT COUNT(*)::int as cnt FROM attendance WHERE tenant_id=$1 AND member_id=$2 AND created_at >= (now() - interval '30 days')`,
    [tenantId, mem.rows[0].id]
  );

  return res.json({
    ok:true,
    member: { id: mem.rows[0].id, full_name: mem.rows[0].full_name, id_code: mem.rows[0].id_code },
    membership: membership.rows[0] || null,
    attendance_last_30_days: attendanceCount.rows[0].cnt
  });
});

// ===== Start (local dev) =====
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log('SVFIT backend v2 listening on', port));
}

module.exports = app;
