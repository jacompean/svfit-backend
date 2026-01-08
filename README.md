# SVFIT Backend (Vercel + Neon)

Backend serverless para SVFIT: autenticación, roles (admin/staff/coach/member), miembros, membresías, asistencia, pagos, inventario, ventas y corte de caja.

## Requisitos
- Vercel (Node 20)
- Neon (Postgres)

## Variables de entorno (Vercel)
- DATABASE_URL = connection string de Neon (incluye sslmode=require)
- JWT_SECRET = cadena larga (mínimo 32 chars)
- FRONTEND_ORIGINS = lista separada por comas. Ej:
  - https://svfit.vercel.app,*.vercel.app,http://localhost:5173
- SETUP_KEY = (temporal) clave para ejecutar setup inicial (BORRAR después)

## Instalación en Neon (SQL)
1) En Neon -> SQL Editor ejecuta:
   - sql/001_schema.sql

## Setup inicial (sin usar SQL de seed)
1) En Vercel (backend) agrega SETUP_KEY (una clave que tú elijas).
2) Haz Deploy/Redeploy.
3) Ejecuta el setup con un POST:

   POST https://svfit-backend.vercel.app/api/setup
   Body JSON:
   {
     "setupKey": "TU_SETUP_KEY"
   }

4) Si responde ok=true, ve a Vercel y **BORRA** SETUP_KEY (por seguridad).
5) Inicia sesión (credenciales demo, cámbialas):
   - admin@svfit.mx / Admin123!
   - staff@svfit.mx / Staff123!
   - coach@svfit.mx / Coach123!
   - member@svfit.mx / Member123!

## Endpoints principales
- GET /api/health
- POST /api/auth/login
- GET /api/me

Admin/Staff:
- CRUD usuarios: /api/users
- CRUD miembros (crear/editar): /api/members
- Planes y membresías: /api/plans, /api/members/:id/membership, /api/memberships/expiring
- Inventario: /api/products, /api/products/:id/adjust
- Ventas: /api/sales, /api/sales/summary
- Corte de caja: /api/cash-sessions/open, /api/cash-sessions/:id/close, /api/cash-sessions/:id/summary

Coach:
- Ver miembros: GET /api/members
- Asistencia: POST /api/members/:id/checkin

Member:
- Resumen: GET /api/member/summary
- Membresía: GET /api/member/membership
- Pagos: GET /api/member/payments
- Asistencia: GET /api/member/attendance
