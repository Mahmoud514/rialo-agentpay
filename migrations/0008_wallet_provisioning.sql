-- Rialo AgentPay — V8 wallet provisioning outbox
--
-- Design/proposal only. NOT applied by this worktree and NOT wired into the
-- Rust startup migration runner.
--
-- Order: V6 (fair-review) -> V7 (Worker auth sessions) -> V8 (this file).
-- This table contains coordination metadata only. It must never contain
-- private keys, seed phrases, wallet file contents, signatures, or RPC data.

CREATE TABLE IF NOT EXISTS wallet_provision_requests (
    user_id          BIGINT PRIMARY KEY,
    state            TEXT NOT NULL CHECK (
        state IN ('pending', 'provisioning', 'ready', 'failed', 'wallet_missing')
    ),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  BIGINT NOT NULL,
    lease_until      BIGINT,
    worker_id        TEXT,
    last_error_code  TEXT,
    requested_at     BIGINT NOT NULL,
    updated_at       BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wallet_provision_claim
    ON wallet_provision_requests (state, next_attempt_at, requested_at);

CREATE INDEX IF NOT EXISTS idx_wallet_provision_lease
    ON wallet_provision_requests (lease_until)
    WHERE state = 'provisioning';

-- Seed only the version marker; no user rows and no wallet data.
INSERT INTO schema_migrations (version, applied_at)
SELECT 8, EXTRACT(EPOCH FROM NOW())::BIGINT
WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 8);
