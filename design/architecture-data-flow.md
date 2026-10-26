# Architecture and data flow (local target)

## Authentication

```
browser wallet
  |  POST /auth/wallet/nonce {address}
  v
Pages Function (AUTH_MODE=worker)
  |  validate Origin; rate-limit by cf-connecting-ip; store nonce hash
  v
Neon `wallet_nonces` (hash, address, purpose, origin/domain, expiry)
  |
  |  EIP-191 signature over the returned message
  v
POST /auth/wallet/verify
  |  consume nonce atomically; verify signature; resolve identity
  v
Neon `auth_identities` + `sessions`
  |  session_id (transitional) + session_hash = sha256(raw token)
  |  HttpOnly; Secure in production; SameSite=Lax; CSRF hash
  v
browser agentpay_session cookie
  |
  +--> GET /api/me (Worker-owned; Neon only)
  +--> POST /auth/csrf, POST /auth/logout
  +--> wallet link: session + CSRF + link nonce + signature; rotation
```

Rust readers use the same contract: hash-first, raw `session_id` fallback only
when `session_hash IS NULL`, expiry checked, and delete/logout by the actual
row. The hash fixture is `sha256("session-token") =
c101e911469c969171040b50d70543313cf968fdef5bacc780776f8fb399ab36`.

## Wallet provisioning (not route-activated)

```
login/session (Neon) --(future explicit request)--> wallet_provision_requests
                                                        |
                                      FOR UPDATE SKIP LOCKED claim
                                                        |
                                      lease + fencing worker_id
                                                        |
                                      signer.ensure_wallet(user_id)
                                                        |
                    existing registered wallet: load only / never mint
                    missing or mismatched: wallet_missing (operator action)
                    no prior identity: one signer-local mint
                                                        |
                                      public key only -> user_wallets
```

The outbox contains no private keys, seeds, wallet-file contents, signatures,
raw signer errors, or RPC data. Provisioning is deliberately separate from
session issuance: a wallet-authenticated session is valid before a Rialo wallet
is ready.

## Public task board (Worker-owned read-only)

When `TASKS_MODE=neon`, `GET /api/tasks/open` reads `tasks_pg` directly from
Neon and returns the existing summary shape. It accepts the same session cookie
to include the viewer's own non-terminal rows. All task mutations and payout
paths remain on the backend/signer lane. This is a deliberately narrow move:
the read contract is tested, while signing/payment behavior is not moved.

## Trust boundaries

- **Cloudflare/Neon:** identity, nonce, sessions, task/agent/marketplace
  metadata. No Rialo private keys.
- **Signer:** key material, wallet files, signing, payments. Only public keys
  and static status cross the boundary.
- **Blitz:** transitional owner of routes not yet moved. Payment and Rialo
  operations remain there until a separately reviewed signer integration is
  authorized.
- **Browser:** never receives a private key, seed, wallet file, or backend
  credential.

## Deployment phases

1. Static preview can ship independently.
2. Worker auth can be enabled per environment with `AUTH_MODE=worker` while
   other routes remain proxied.
3. Hash-only session storage is deferred until every Rust reader, logout,
   GitHub OAuth, and recovery path is proven against it.
4. V8 is not wired; signer calls remain on the existing reviewed path.
