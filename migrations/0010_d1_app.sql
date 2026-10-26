-- G1156 Cloudflare D1 application projection.
--
-- This is an isolated, Cloudflare-only data plane for the preview. It does not
-- contain wallet keys, seeds, or signing authority. Payment/faucet execution
-- remains unavailable until a reviewed signer boundary exists.
CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft',
  schema_version INTEGER NOT NULL DEFAULT 1,
  wallet_address TEXT,
  auth_public_key TEXT,
  policy_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agents_owner_idx ON agents(owner_user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  owner_name TEXT NOT NULL DEFAULT '',
  agent_id TEXT,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  acceptance_criteria TEXT NOT NULL DEFAULT '',
  reward_kelvin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',
  worker_id TEXT,
  worker_name TEXT,
  payout_address TEXT,
  submission_url TEXT,
  submission_notes TEXT,
  review_notes TEXT,
  payment_tx_signature TEXT,
  payment_error TEXT,
  attachments_json TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  claimed_at INTEGER,
  submitted_at INTEGER,
  reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS tasks_status_idx ON tasks(status, created_at DESC);
CREATE INDEX IF NOT EXISTS tasks_owner_idx ON tasks(owner_user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS tasks_worker_idx ON tasks(worker_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS task_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT NOT NULL,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  actor_user_id TEXT,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS task_events_task_idx ON task_events(task_id, at DESC, event_id DESC);

CREATE TABLE IF NOT EXISTS payment_intents (
  intent_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  owner_user_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  amount_kelvin INTEGER NOT NULL DEFAULT 0,
  recipient TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS payment_intents_agent_idx ON payment_intents(agent_id, created_at DESC);
