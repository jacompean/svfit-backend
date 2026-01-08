# SVFIT Backend v2 (Multi-tenant)

This backend supports:
- Multi-tenant (one tenant = one gym), resolved by request Origin domain.
- Login by ID: two-letter gym code + 4 digits (e.g. SV0001), plus special global admin username `admin`.
- Roles: admin (global), admin_tenant, staff, coach, member
- Membership plans + memberships + expiring list
- Attendance with soft warnings (Teens plan rules)
- Inventory + sales + cash sessions (one open cash session per tenant)
- Workout routines + member progress (simple)

## Required env vars
- DATABASE_URL (Neon Postgres, include sslmode=require)
- JWT_SECRET (>= 32 chars)
- SETUP_KEY (temporary; used once to initialize)
