-- migrations/004_users.sql
-- Run: psql $DATABASE_URL -f migrations/004_users.sql

CREATE TABLE IF NOT EXISTS users (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  email         VARCHAR(255) UNIQUE NOT NULL,   -- always stored lowercase
  password_hash TEXT         NOT NULL,           -- "salt:scrypt_derived_key" format
  role          VARCHAR(20)  NOT NULL DEFAULT 'user'
                             CHECK (role IN ('user','admin')),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ                      -- updated on every successful login
);

-- Fast lookup by email on every login
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
