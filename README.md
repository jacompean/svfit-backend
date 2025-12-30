# SVFIT Backend (Vercel + Neon)

Backend serverless con Express desplegable en Vercel y Postgres en Neon.

## Requisitos
- Node.js 18+ (para desarrollo local opcional)
- Base de datos Postgres en Neon (DB: `SVFIT`)

## Variables de entorno (Vercel)
- `DATABASE_URL` (Neon connection string, con `sslmode=require`)
- `JWT_SECRET` (cadena fuerte)
- `FRONTEND_ORIGINS` (por ejemplo: `https://svfit.vercel.app,http://localhost:5173`)

> No uses `vercel.json` para declarar envs tipo `@SECRET`. En su lugar, configúralas desde Vercel Dashboard.

## Inicialización de base de datos (sin "init")
En Neon (SQL Editor) ejecuta:
1) `sql/001_schema.sql`
2) `sql/002_seed.sql`

Usuarios demo:
- admin@svfit.mx / Admin123!
- coach@svfit.mx / Coach123!

## Endpoints principales
- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/auth/register` (crea usuario con rol `member`)
- `GET /api/me`
- `GET /api/dashboard/summary` (admin/coach)
- `GET/POST/PUT/DELETE /api/members` (delete solo admin)
- `POST /api/attendance/checkin`
- `GET /api/attendance`
- `POST /api/payments` / `GET /api/payments`
- `GET /api/classes`
- `POST /api/classes`
- `POST /api/classes/:id/enroll`

## Dev local (opcional)
```bash
npm install
cp .env.example .env
npm run dev
```


## Nota de seguridad
En `NODE_ENV=production`, el backend bloquea requests sin header `Origin` (para que no sea fácil invocarlo desde scripts externos). Para pruebas con Postman/curl, usa `NODE_ENV=development` o agrega un Origin permitido.
