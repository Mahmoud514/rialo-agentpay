# Migration and rollback plan

## Order

1. `migrations/0006_fair_review.sql` — reviewed fair-review schema.
2. `migrations/0007_worker_auth.sql` — Worker auth nonce/identity/rate-limit
   and the transitional `sessions.session_hash` / CSRF columns.
3. `migrations/0008_wallet_provisioning.sql` — V8 outbox (coordination only).

The V8 file is a proposal. It is not applied by startup and is not wired into a
route or scheduler in this tree. The local test runner applies the exact files
to a disposable embedded PostgreSQL instance, twice, and checks the version
markers and preservation of pre-existing rows.

## Safety properties

- All three files are additive. They do not delete a session, wallet, task, or
  agent row.
- Existing sessions remain readable through the raw fallback while
  `session_hash IS NULL`.
- The outbox has no key, seed, file-content, signature, or RPC columns.
- The V8 claim uses `FOR UPDATE SKIP LOCKED`, a lease, and a `worker_id`
  predicate. The advisory lock is a second layer, never the only proof.
- A missing/corrupt registered wallet maps to `wallet_missing`; no migration
  or worker mints a replacement.

## Rollback

Before any production application:

1. Keep the previous application image and a database backup/point-in-time
   restore window.
2. Disable Worker auth by removing `AUTH_MODE=worker` (or setting the old
   value). The proxy lane remains available; no schema drop is required.
3. Keep dual-read session code deployed. Do not switch to hash-only storage
   until every reader/logout/OAuth/recovery path is verified.
4. If V8 is later enabled and must be disabled, stop its worker, leave the
   table in place, and set the feature gate off. Do not drop the table while a
   lease is active.
5. A schema rollback that drops `wallet_provision_requests` or the new session
   columns is **not** part of this local change and requires a separate
   migration review.

## Explicit non-actions

- No production or Neon migration was applied.
- No DNS, Cloudflare project, secret, deployment, or Git integration was
  changed.
- No real wallet file or key was read, written, moved, or recreated.
