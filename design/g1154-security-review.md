# G1154 — security review of the new changes

Scope: the G1154 diff only. This is not a claim that the whole repository is
secure or production-approved.

## Findings ordered by severity

### HIGH — raw session fallback remains

`sessions.session_hash` is used first. The raw `session_id` comparison is still
accepted when `session_hash IS NULL` (legacy rows). A database reader could
therefore use a raw session token for those legacy rows. This is intentional
transitional compatibility, but a hash-only cutover was **not** performed. Do
not treat session storage as hash-only until all consumers and legacy rows are
migrated and verified.

### HIGH — the V8 worker's local signer adapter is v1, not isolated signer v2

The opt-in V8 worker calls the existing `strict_wallet_load_or_mint` v1
workflow. That workflow is protected by the v1 journal and no-replace writer,
but it is not the isolated signer v2 transport. Enabling the worker in a real
deployment requires a reviewed v2 signer adapter and a separate signer
availability/fencing test. The worker is disabled unless
`AGENTPAY_WALLET_PROVISIONING=1` for this reason.

### MEDIUM — recovery completion is best-effort after registry replacement

The recovery file and the registry row are updated before the recovery journal
result is written. If the process crashes in that narrow window, the next
strict load sees an `InProgress` recovery and completes from the same file (it
never mints). If the journal itself is unwritable, the operation remains
`InProgress` and requires operator attention. No automatic replacement is
performed.

### MEDIUM — agent wallets have a documented journal exception

Agent wallets use O_EXCL, mode 0600, `fsync`, and idempotent read of an existing
valid file keyed by the agent UUID. Unlike v1/v2 user wallets, they do not have
a separate public operation journal. The file itself is the durable result. Do
not describe the agent lane as having the same journal format.

### MEDIUM — real Cloudflare/Neon runtime is unproven

Local Wrangler/Miniflare and disposable PostgreSQL tests do not prove Neon
serverless pooling, Neon TLS/HTTP behavior, Pages bindings, or preview/production
separation. No real Cloudflare account, DNS, secret, or Neon branch was used.
The status is **NOT RUN**, not PASS.

### Low / verified controls

- Wallet auth uses single-use nonce hashes, origin binding, EIP-191 signature
  verification, rate limits keyed by hashed client IP/address, CSRF on link and
  logout, session rotation after linking, and no Blitz call in the tested flow.
- `getClientIp` trusts only `cf-connecting-ip`; user-supplied
  `x-forwarded-for`/`x-real-ip` are not trusted.
- Proxy strips user-supplied forwarding and auth headers and never returns
  `BACKEND` or upstream error bodies as a fake success.
- `mark_ready` requires both a live worker lease and a public `user_wallets`
  row; a stale worker cannot commit and a signer success without a registry row
  cannot mark ready.
- V8 outbox stores no key material; error codes are static.
- No `TxSigner::User`, real payment, real signature, real wallet creation, or
  production migration was executed.

## Required before production

1. Approve a real Neon test branch + Pages preview; run the runbook smoke list.
2. Decide and test hash-only session cutover, including legacy row migration.
3. Wire the isolated v2 signer with a reviewed adapter and TLS/loopback
   boundary; re-run failure injection and lease fencing.
4. Add an operator runbook for `WALLET_PROVISIONING_INCOMPLETE`,
   `WALLET_IDENTITY_MISMATCH`, and recovery-journal corruption.
5. Review whether agent wallets need the same public journal format; until
   then keep the exception explicit.
