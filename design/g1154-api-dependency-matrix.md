# G1154 — API dependency matrix

Status is for the local G1154 execution tree. `Worker` means the Pages
Function handles the request without calling Blitz. `Proxy` means the request
still goes through the configured backend; that is not a migration claim.
`Tested locally` means a local unit/HTTP/disposable-PostgreSQL test exists; it
does not mean a real Cloudflare/Neon deployment was exercised.

## Worker-owned / Blitz-independent

| Route | Owner | Data source | Auth boundary | Signer/chain | Blitz needed | Test evidence |
|---|---|---|---|---|---|---|
| `POST /auth/wallet/nonce` | Pages Function (`AUTH_MODE=worker`) | Neon nonce hash | origin + rate limit + nonce | none | no | worker-auth tests; Node HTTP + disposable PG |
| `POST /auth/wallet/verify` | Pages Function | Neon identity/session | EIP-191 + single-use nonce + origin | none | no | worker-auth tests; full HTTP/PG flow with `fetch` disabled |
| `POST /auth/wallet/link/nonce` | Pages Function | Neon session/nonce | session + CSRF + origin | none | no | worker-auth tests |
| `POST /auth/wallet/link/verify` | Pages Function | Neon identity/session | session + CSRF + one-time link nonce | none | no | worker-auth tests; cross-user replay rejection |
| `POST /auth/csrf` | Pages Function | Neon session | session cookie | none | no | worker-auth tests |
| `POST /auth/logout` | Pages Function | Neon session | session cookie | none | no | worker-auth tests; HTTP/PG flow |
| `GET /api/me` | Pages Function | Neon session, public wallet, V8 status | hashed session; raw only for `session_hash IS NULL` | public address only | no | worker-auth + HTTP/PG; balance remains `unavailable` if absent, never fabricated |
| `GET /api/tasks/open` | Pages Function (`TASKS_MODE=neon`) | Neon `tasks_pg` | public board + viewer owner/worker visibility | none | no | open-tasks tests; HTTP/PG seeded board |

Wallet verification enqueues a V8 request after the session is issued. The
insert is idempotent and best-effort; an absent V8 table or an enqueue failure
does not change login success. It does not wait for wallet creation.

## V8 provisioning (no public HTTP route added)

| Operation | Owner | Store | Signer boundary | State exposed |
|---|---|---|---|---|
| enqueue after wallet auth/link | Pages Function → Neon | `wallet_provision_requests` | none | `/api/me.provisioning` |
| claim / lease / fence | opt-in Rust worker | disposable PostgreSQL | v1 strict load/mint adapter | internal outbox |
| ready / failed / wallet_missing | opt-in Rust worker | PostgreSQL | never mints on missing/corrupt | `/api/me.provisioning` |

The worker is disabled unless `AGENTPAY_WALLET_PROVISIONING=1`; it is not a
production activation. `ready` requires a live lease and a public
`user_wallets` row.

## Still backend-dependent (not migrated in G1154)

| Route group | Current owner | Why it stays a proxy / backend | Blitz down |
|---|---|---|---|
| `POST /api/tasks`, `GET /api/tasks/{id}`, `/claim`, `/submit`, `/review`, `/cancel`, payout reconcile | Rust backend | task authority, owner/worker authorization, payout/signer integration | fails closed |
| `GET/POST/PATCH/DELETE /api/agents*` | Rust backend | agent metadata, policy, credential and agent-wallet paths | fails closed |
| `GET /api/agents/{id}/balance`, agent stats/activity/leaderboard | Rust backend | Rialo RPC and backend projections | unavailable/fails closed |
| `POST /api/payment`, `POST /api/faucet`, program payment/status routes | Rust backend | Rialo signing, RPC, policy, spend limits | fails closed |
| `GET /api/health`, `GET /api/program/status` | Rust backend | RPC/program probe | fails closed |
| `GET /api/schema`, `/schema/*` | Rust backend/proxy | backend schema source | proxy typed 503 if `BACKEND` absent |
| `GET /api/public/verify`, `/api/public/agents/{id}/proofs` | Rust backend | chain RPC read-only proof data | fails closed |
| `GET/POST /auth/github*`, preview OAuth | Rust backend | OAuth client secrets and backend session exchange | fails closed |
| `POST /auth/wallet-recover` | Rust backend | explicit signer/file recovery and old-balance check | fails closed |
| `GET /auth/dev-login` | backend only if `DEV_LOGIN_USER_ID` | local development bypass; never a deployment feature | 404/fail closed |

## Route contract notes

- Worker auth keeps the cookie name `agentpay_session`, path `/`, `HttpOnly`,
  `SameSite=Lax`, and `Secure` in production options.
- `/api/me` returns the existing envelope plus `wallet_status` and
  `provisioning`; when a wallet is absent the balance is `null` with
  `balance_status="no_wallet"`, never a fake zero.
- `/api/tasks/open` returns the existing `{tasks, count}` shape; non-GET is a
  typed 405 and storage errors are typed 503.
- Proxy routes preserve path/query, strip user-controlled forwarding/auth
  headers, never expose `BACKEND`, and return a typed 503 when unconfigured.
- No frontend bundle receives a database URL, signer URL secret, GitHub secret,
  session token, nonce value, private key, or seed.

## Remaining dependency summary

Blitz/backend is still required for task mutations, agents, balances,
payments, faucet, health/program status, backend schema, public chain proofs,
GitHub OAuth, and wallet recovery. Wallet authentication, `/api/me`, the
read-only open-task board, and the V8 enqueue/worker boundary are the only
implemented Blitz-independent paths. The project is not fully Blitz-free.
