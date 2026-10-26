# Security review — local execution tree

## Controls implemented

- Wallet nonce: 32 random bytes, hashed at rest, address/purpose/origin bound,
  short TTL, single-use `UPDATE ... WHERE consumed_at IS NULL`.
- Signature: server-side EIP-191 recovery; invalid signature and replay fail
  closed.
- Login/link nonce endpoints reject a missing or cross-origin `Origin`.
  Link endpoints additionally require a session and CSRF token.
- Rate limits use `cf-connecting-ip` only. Client-supplied
  `X-Forwarded-For`/`X-Real-IP` are never used for the IP bucket. Requests
  without the Cloudflare header share the `unknown` bucket rather than
  trusting a caller value.
- Session cookies: `HttpOnly`, `SameSite=Lax`, `Secure` when production mode
  is selected, bounded `Max-Age`; session rotation after successful link.
- Session lookup: SHA-256 hash first; raw `session_id` only for rows whose
  `session_hash IS NULL`; no raw fallback for a mismatched hash row.
- Proxy: request-scoped `BACKEND`; https-only, no credentials/path/query/hash;
  forwarding/auth headers stripped; redirects manual; no backend value echoed.
- Static preview no longer imports a throwing module: missing configuration is
  a typed 503 only on backend-dependent requests.
- Signer file publication: complete temp + fsync + hard link + directory fsync.
  No `rename`; no replacement of an existing path; per-user process lock plus
  no-replace as the cross-process backstop. A durable public result is bound to
  the public address and record digest; private key bytes are zeroized.
- V8 outbox stores only user id, state, attempts, lease/fence, static error
  code, and timestamps. The claim is `FOR UPDATE SKIP LOCKED`; stale worker
  updates are filtered by `worker_id`.

## Unchanged security boundaries

- `TxSigner::User` remains absent.
- Latch/default-deny and payment policy are unchanged.
- No real signature, transaction, faucet, payment, or blockchain action was
  performed.
- No wallet file, seed, private key, `.env`, or production database was read,
  written, moved, or recreated.
- `AUTH_MODE` is opt-in. Without it, the existing backend auth/proxy lane is
  retained.

## Residual risks and unproven areas

1. **No Cloudflare/Neon runtime test.** The Worker auth tests use a Node HTTP
   harness and a test PostgreSQL adapter; Neon serverless pooling/prepared
   statement behavior is not proven.
2. **V8 is not wired.** The state machine, migration, and `PgProvisionStore`
   adapter are tested against disposable PostgreSQL, but no route, scheduler,
   login callback, or startup path enqueues or processes V8.
3. **v1 wallet lane:** the safe writer, per-user lock, idempotent re-register,
   and no-replacement check are present, but there is no independent
   `operation_id` journal for v1 and the crash window between recovery's file
   removal and registry update is not fully eliminated.
5. **Agent wallet record** still uses a direct `create_new` path; it was not
   changed because it is outside the user-lane proof.
6. **Recovery** is explicit and may remove a newly created file if registry
   update fails; this is not an automatic replacement path, but it is a
   residual operational risk.
7. **Proxy trust model:** the configured `BACKEND` is trusted server
   configuration. The proxy strips client forwarding headers, but a wrong
   backend value is a deployment mistake that fails closed only after a valid
   https origin is supplied.
8. **No hash-only session migration.** Raw session tokens remain in the
   transitional `sessions.session_id` column by design; removing them needs a
   separate migration and reader audit.

## Review verdict

The local controls above are reviewed and tested to the extent stated in the
test report. This is not a production security sign-off, not a Cloudflare/Neon
deployment proof, and not a claim that the whole application is Blitz-free.
