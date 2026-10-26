-- G1156 isolated D1 auth schema (Cloudflare-only wallet auth).
-- Test/preview only until an operator reviews a production binding.
CREATE TABLE IF NOT EXISTS wallet_nonces (
  nonce_hash TEXT PRIMARY KEY,
  address TEXT NOT NULL,
  purpose TEXT NOT NULL,
  user_id TEXT,
  message TEXT NOT NULL,
  domain TEXT NOT NULL,
  chain_id INTEGER,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE TABLE IF NOT EXISTS auth_identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL,
  login TEXT NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  session_hash TEXT,
  user_id TEXT NOT NULL,
  login TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  auth_method TEXT,
  csrf_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(session_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS user_wallets (
  user_id TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wallet_provision_requests (
  user_id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  requested_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);
