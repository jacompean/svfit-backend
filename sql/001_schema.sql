-- SVFIT schema (Neon Postgres)
-- Run this first.

create extension if not exists pgcrypto;

-- USERS (login accounts)
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  full_name text not null,
  role text not null check (role in ('admin','coach','member')),
  password_hash text not null,
  created_at timestamptz not null default now()
);

-- MEMBERS (gym clients) - can be linked to a user account (optional)
create table if not exists members (
  id uuid primary key default gen_random_uuid(),
  user_id uuid null references users(id) on delete set null,
  full_name text not null,
  phone text null,
  email text null,
  status text not null default 'active' check (status in ('active','inactive')),
  join_date date not null default now()::date,
  notes text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz null
);

create index if not exists idx_members_name on members (full_name);
create index if not exists idx_members_status on members (status);

-- PLANS
create table if not exists membership_plans (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_mxn numeric(12,2) not null,
  duration_days int not null,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

-- MEMBER -> PLAN assignment
create table if not exists member_memberships (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references members(id) on delete cascade,
  plan_id uuid not null references membership_plans(id) on delete restrict,
  start_date date not null,
  end_date date not null,
  status text not null default 'active' check (status in ('active','expired','canceled')),
  created_at timestamptz not null default now()
);

create index if not exists idx_member_memberships_member on member_memberships(member_id);

-- ATTENDANCE
create table if not exists attendance (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references members(id) on delete cascade,
  checkin_at timestamptz not null default now(),
  method text not null default 'manual'
);

create index if not exists idx_attendance_member on attendance(member_id);
create index if not exists idx_attendance_checkin on attendance(checkin_at);

-- PAYMENTS
create table if not exists payments (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references members(id) on delete cascade,
  amount_mxn numeric(12,2) not null,
  paid_at timestamptz not null default now(),
  method text not null default 'cash',
  reference text null
);

create index if not exists idx_payments_member on payments(member_id);
create index if not exists idx_payments_paid_at on payments(paid_at);

-- CLASSES
create table if not exists classes (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  coach_name text null,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  capacity int not null default 20,
  created_at timestamptz not null default now()
);

create index if not exists idx_classes_starts_at on classes(starts_at);

-- ENROLLMENTS
create table if not exists class_enrollments (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references classes(id) on delete cascade,
  member_id uuid not null references members(id) on delete cascade,
  status text not null default 'enrolled' check (status in ('enrolled','canceled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz null,
  unique (class_id, member_id)
);

create index if not exists idx_enrollments_class on class_enrollments(class_id);
