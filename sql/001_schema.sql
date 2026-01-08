-- SVFIT schema v1 (roles + membresías + inventario/ventas + corte de caja)
-- Compatible con Neon Postgres

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN
  CREATE TYPE user_role AS ENUM ('admin','staff','coach','member');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE payment_method AS ENUM ('cash','card','transfer');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE membership_status AS ENUM ('active','expired','cancelled');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE inventory_movement_type AS ENUM ('adjustment','sale','restock');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE cash_session_status AS ENUM ('open','closed');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role user_role NOT NULL,
  member_id BIGINT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS members (
  id BIGSERIAL PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NULL,
  phone TEXT NULL,
  notes TEXT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_users_member') THEN
    ALTER TABLE users
      ADD CONSTRAINT fk_users_member
      FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE SET NULL;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS plans (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  duration_days INT NOT NULL CHECK (duration_days > 0),
  price_cents INT NOT NULL CHECK (price_cents >= 0),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'plans_name_unique') THEN
    ALTER TABLE plans ADD CONSTRAINT plans_name_unique UNIQUE (name);
  END IF;
END $$;


CREATE TABLE IF NOT EXISTS memberships (
  id BIGSERIAL PRIMARY KEY,
  member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  plan_id BIGINT NOT NULL REFERENCES plans(id),
  start_date DATE NOT NULL,
  end_date DATE NOT NULL,
  status membership_status NOT NULL DEFAULT 'active',
  created_by BIGINT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_memberships_member_id ON memberships(member_id);
CREATE INDEX IF NOT EXISTS idx_memberships_end_date ON memberships(end_date);
CREATE INDEX IF NOT EXISTS idx_memberships_status ON memberships(status);

CREATE TABLE IF NOT EXISTS payments (
  id BIGSERIAL PRIMARY KEY,
  member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  amount_cents INT NOT NULL CHECK (amount_cents >= 0),
  method payment_method NOT NULL,
  reference TEXT NULL,
  note TEXT NULL,
  paid_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by BIGINT NULL REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_payments_paid_at ON payments(paid_at);
CREATE INDEX IF NOT EXISTS idx_payments_member_id ON payments(member_id);

CREATE TABLE IF NOT EXISTS attendance (
  id BIGSERIAL PRIMARY KEY,
  member_id BIGINT NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  checkin_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  method TEXT NOT NULL DEFAULT 'manual',
  created_by BIGINT NULL REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_attendance_checkin_at ON attendance(checkin_at);
CREATE INDEX IF NOT EXISTS idx_attendance_member_id ON attendance(member_id);

-- Inventory / POS
CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  sku TEXT NULL,
  name TEXT NOT NULL,
  price_cents INT NOT NULL CHECK (price_cents >= 0),
  cost_cents INT NOT NULL DEFAULT 0 CHECK (cost_cents >= 0),
  stock INT NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'products_sku_unique') THEN
    ALTER TABLE products ADD CONSTRAINT products_sku_unique UNIQUE (sku);
  END IF;
END $$;


CREATE INDEX IF NOT EXISTS idx_products_active ON products(active);

-- Corte de caja
CREATE TABLE IF NOT EXISTS cash_sessions (
  id BIGSERIAL PRIMARY KEY,
  status cash_session_status NOT NULL DEFAULT 'open',
  opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at TIMESTAMPTZ NULL,
  opening_cash_cents INT NOT NULL DEFAULT 0,
  closing_cash_cents INT NULL,
  opened_by BIGINT NULL REFERENCES users(id),
  closed_by BIGINT NULL REFERENCES users(id),
  note TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_cash_sessions_status ON cash_sessions(status);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_open_cash_session ON cash_sessions(status) WHERE status='open';

CREATE TABLE IF NOT EXISTS sales (
  id BIGSERIAL PRIMARY KEY,
  sold_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  total_cents INT NOT NULL CHECK (total_cents >= 0),
  method payment_method NOT NULL,
  note TEXT NULL,
  created_by BIGINT NULL REFERENCES users(id),
  cash_session_id BIGINT NULL REFERENCES cash_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_sales_sold_at ON sales(sold_at);
CREATE INDEX IF NOT EXISTS idx_sales_cash_session_id ON sales(cash_session_id);

CREATE TABLE IF NOT EXISTS sale_items (
  id BIGSERIAL PRIMARY KEY,
  sale_id BIGINT NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
  product_id BIGINT NOT NULL REFERENCES products(id),
  quantity INT NOT NULL CHECK (quantity > 0),
  unit_price_cents INT NOT NULL CHECK (unit_price_cents >= 0),
  line_total_cents INT NOT NULL CHECK (line_total_cents >= 0)
);

CREATE TABLE IF NOT EXISTS inventory_movements (
  id BIGSERIAL PRIMARY KEY,
  product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  type inventory_movement_type NOT NULL,
  quantity INT NOT NULL,
  note TEXT NULL,
  created_by BIGINT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sale_id BIGINT NULL REFERENCES sales(id)
);

CREATE INDEX IF NOT EXISTS idx_inventory_movements_product_id ON inventory_movements(product_id);
CREATE INDEX IF NOT EXISTS idx_inventory_movements_created_at ON inventory_movements(created_at);
