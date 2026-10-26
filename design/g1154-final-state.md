# G1154 — final local execution state

## Baseline

- Base commit: `32c3f4d626e446093e54655450fe8781a810d1b5`
- Worktree: `/home/mahmoud/g1154-final-completion` (detached)
- Previous worktree `g1153-agentpay-completion` was read only and not modified.
- All previous worktrees (g1142, g1143, g1145–g1153) remain untouched.

## What changed in G1154

- Added a durable, public-only v1 wallet operation journal
  (`src/bin/server/wallet_file_safety.rs`) and wired it into
  `load_wallet_strict`. It never stores key material and never replaces a
  completed result.
- Added an explicit recovery operation journal and recovery-first lookup. The
  old journal remains immutable; a recovered wallet is not masked by it.
- Made agent-wallet provisioning idempotent for a repeated agent id: an
  existing valid wallet returns its public address; an invalid pre-existing
  file is refused. Added `fsync`.
- Added the login/link V8 enqueue (`enqueueProvisioning`) as an idempotent,
  best-effort Neon insert that cannot fail authentication.
- Added an opt-in V8 worker (`AGENTPAY_WALLET_PROVISIONING=1`) with its own
  PostgreSQL client/runtime, supporting claim, lease/fencing, retry/backoff,
  restart recovery, existing-wallet short-circuit, and terminal
  `wallet_missing`.
- Made `PgProvisionStore.mark_ready` require both the worker lease and a public
  `user_wallets` row, so a signer success cannot be reported ready without the
  registry.
- Added a deployment preflight (`npm run check:functions`) that requires a
  valid `BACKEND` for proxy routes and `DATABASE_URL` when worker auth/neon
  tasks are enabled; it never prints values.
- Added local Pages runtime verification with Wrangler/Miniflare and documented
  the unproven external steps.

## Architecture and data flow

```
browser / EOA wallet
   |  nonce, EIP-191 signature
   v
Cloudflare Pages Function (Worker auth)
   |-- Neon: wallet_nonces, auth_identities, sessions
   |-- best-effort INSERT wallet_provision_requests (V8)
   |-- GET /api/me: Neon session + user_wallets + provisioning state only
   |
   +--> static assets (dist/static) with no BACKEND required

Rust AgentPay backend (still behind proxy for unmigrated routes)
   |-- task/agent/payment/RPC authority
   |-- signer / wallet files / Rialo CLI

V8 worker (opt-in, Rust server process)
   |-- claim wallet_provision_requests FOR UPDATE SKIP LOCKED
   |-- v1 strict load/mint (journal + no-replace file)
   |-- public user_wallets registry update
   `-- ready only with lease + registry
```

## Migration order and rollback

Order is fixed: `0006` (fair review/session compatibility), `0007` (worker
session hash), `0008` (V8 outbox). Local disposable-PostgreSQL tests apply the
sequence twice and retain rows. No migration was applied to production or a
real Neon branch.

Rollback of the application switch is provider-side: set `AUTH_MODE=proxy`
and `TASKS_MODE=proxy`; leave the V8 worker unset. This removes Worker-owned
auth/task reads from the request path and does not silently create wallets.
Database migrations are additive; this document does not claim a lossless
schema rollback. A production rollback must be reviewed by an operator.

## Test evidence

Commands and exact counts are in the G1154 final report. Summary:

- Node worker-auth + Functions: **42 passed / 0 failed**.
- Node HTTP/PG integration: **1 passed / 0 failed**.
- Signer lib: **298 passed / 0 failed**; all targets: **304 passed**.
- G89 loopback: **19 passed**; wallet safety: **15 passed**.
- Rust server (serial): **759 passed / 0 failed / 7 ignored** (766 total).
- Disposable PostgreSQL integration: **14 passed / 0 failed**.
- Static build, Functions bundle, and local Pages runtime smoke: pass.
- Real Cloudflare Pages/Workers + Neon branch: **NOT RUN** (no test credentials
  or approved test environment).

## Honest limits

- Wallet auth, `/api/me`, `/api/tasks/open`, V8 enqueue, and the V8 worker
  boundary are implemented; the rest of the product is still backed by the
  Rust backend/Blitz namespace.
- The V8 worker's local signer adapter is the v1 strict load/mint boundary,
  not the isolated signer v2 transport. Production wiring of v2 remains open.
- No real signing, payment, transfer, wallet creation, or migration was run.
- `TxSigner::User` remains absent; Latch/default-deny/payment policy/spend
  limits were not changed.
