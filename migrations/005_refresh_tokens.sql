-- migrations/005_refresh_tokens.sql
-- Run after 004_users.sql

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  TEXT        UNIQUE NOT NULL,  -- SHA-256 of the raw token
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked     BOOLEAN     NOT NULL DEFAULT false,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fast lookup by hash on every POST /auth/refresh
CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens (token_hash);

-- List active tokens per user (for revoke-all on logout/change-password)
CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens (user_id, revoked);

-- Cleanup job: delete expired or revoked tokens daily
-- Run as a cron or Azure Function:
--   DELETE FROM refresh_tokens
--   WHERE expires_at < NOW() OR revoked = true;
