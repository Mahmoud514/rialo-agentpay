-- Rialo AgentPay — Worker auth schema (V7)
--
-- Additive only. No DELETE, UPDATE, RENAME, or backfill of existing rows.
-- This file is a proposal for review. It is NOT applied by this change.
--
-- V7 is used because the pending fair-review worktree already contains an
-- unmerged V6. Do not apply this file until the migration owner confirms the
-- final version order and a disposable/test database has been approved.

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS session_hash TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_method TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS csrf_hash TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_hash
    ON sessions (session_hash)
    WHERE session_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS wallet_nonces (
    nonce_hash   TEXT PRIMARY KEY,
    address      TEXT NOT NULL,
    purpose      TEXT NOT NULL CHECK (purpose IN ('login', 'link')),
    user_id      BIGINT,
    -- Template only. The raw nonce is never stored; the verifier substitutes
    -- the client-supplied nonce after looking up nonce_hash.
    message      TEXT NOT NULL,
    domain       TEXT NOT NULL,
    chain_id     BIGINT,
    issued_at    BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL,
    consumed_at  BIGINT
);

CREATE INDEX IF NOT EXISTS idx_wallet_nonces_address
    ON wallet_nonces (address, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_wallet_nonces_expiry
    ON wallet_nonces (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_identities (
    provider     TEXT NOT NULL CHECK (provider IN ('github', 'wallet')),
    subject      TEXT NOT NULL,
    user_id      BIGINT NOT NULL,
    login        TEXT,
    verified_at  BIGINT NOT NULL,
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_auth_identities_user
    ON auth_identities (user_id, provider);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
    rate_key      TEXT PRIMARY KEY,
    window_start  BIGINT NOT NULL,
    count         INTEGER NOT NULL
);

INSERT INTO schema_migrations (version, applied_at)
SELECT 7, EXTRACT(EPOCH FROM NOW())::BIGINT
WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 7);
