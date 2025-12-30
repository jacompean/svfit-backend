-- SVFIT seed data
-- Run after 001_schema.sql

-- IMPORTANT: Change default passwords after first login.

-- Admin user (password: Admin123!)
insert into users (email, full_name, role, password_hash)
values ('admin@svfit.mx', 'SVFIT Admin', 'admin', crypt('Admin123!', gen_salt('bf', 10)))
on conflict (email) do nothing;

-- Coach user (password: Coach123!)
insert into users (email, full_name, role, password_hash)
values ('coach@svfit.mx', 'SVFIT Coach', 'coach', crypt('Coach123!', gen_salt('bf', 10)))
on conflict (email) do nothing;

-- Plans
insert into membership_plans (name, price_mxn, duration_days)
values
  ('Mensual', 699.00, 30),
  ('Trimestral', 1899.00, 90),
  ('Anual', 6999.00, 365)
on conflict do nothing;

-- Members
insert into members (full_name, phone, email, status, join_date, notes)
values
  ('Carlos Pérez', '55-1111-2222', 'carlos@example.com', 'active', now()::date - 20, 'Preferencia: mañanas'),
  ('María López', '55-3333-4444', 'maria@example.com', 'active', now()::date - 45, 'Objetivo: bajar grasa'),
  ('Luis Hernández', '55-5555-6666', 'luis@example.com', 'active', now()::date - 10, 'Lesión previa: rodilla')
on conflict do nothing;

-- Attendance sample (last 5 days)
insert into attendance (member_id, checkin_at, method)
select m.id, (now() - (g.i || ' days')::interval) + interval '10 hours', 'seed'
from members m
cross join (values (0),(1),(2),(3),(4)) g(i)
where m.email in ('carlos@example.com','maria@example.com')
on conflict do nothing;

-- Payments sample
insert into payments (member_id, amount_mxn, paid_at, method, reference)
select m.id, 699.00, now() - interval '2 days', 'transfer', 'NEON-SEED-001'
from members m
where m.email = 'carlos@example.com'
on conflict do nothing;

-- Classes sample
insert into classes (title, coach_name, starts_at, ends_at, capacity)
values
  ('HIIT', 'SVFIT Coach', now() + interval '1 day' + interval '18 hours', now() + interval '1 day' + interval '19 hours', 18),
  ('Fuerza', 'SVFIT Coach', now() + interval '3 days' + interval '7 hours', now() + interval '3 days' + interval '8 hours', 20)
on conflict do nothing;
