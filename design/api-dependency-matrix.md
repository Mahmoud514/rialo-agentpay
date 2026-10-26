# API dependency matrix

This is the route-level status for the local execution tree. "Worker-owned"
means the Pages Function handles the request without calling Blitz. "Proxy"
means it still goes to the configured `BACKEND`; that is not a claim that the
function is Blitz-independent.

## Worker-owned (when `AUTH_MODE=worker`)

| Route | Owner | Data store | Signer? | Tested locally | Blitz down |
|---|---|---|---|---|---|
| `POST /auth/wallet/nonce` | Pages Function | Neon nonce hash | no | unit + HTTP/PG | works |
| `POST /auth/wallet/verify` | Pages Function | Neon identity/session | no | unit + HTTP/PG | works |
| `POST /auth/wallet/link/nonce` | Pages Function | Neon session/nonce | no | unit | works for a session |
| `POST /auth/wallet/link/verify` | Pages Function | Neon session/identity | no | unit | works for a session |
| `POST /auth/csrf` | Pages Function | Neon session | no | unit | works |
| `POST /auth/logout` | Pages Function | Neon session | no | unit | works |
| `GET /api/me` | Pages Function | Neon session/wallet | public key only | unit + HTTP/PG | works; balance is `unavailable` if signer/balance is absent, never fabricated |
| `GET /api/tasks/open` | Pages Function (`TASKS_MODE=neon`) | Neon `tasks_pg` | no mint/signing | unit + HTTP/PG | works for the public/open board + viewer-visible rows; task mutation routes still fail closed |

## Backend-dependent (still transitional)

| Route group | Current owner | Needs Neon? | Needs signer? | Tested locally | Blitz down |
|---|---|---|---|---|---|
| `GET /api/health`, `/api/program/status` | Blitz/backend | backend | probe only | not through Worker | fails closed |
| `GET /api/schema` | Blitz/backend | backend | no | not through Worker | fails closed |
| `POST /api/tasks`, `GET /api/tasks/{id}`, `/claim`, `/submit`, `/review`, `/cancel`, payout routes | Blitz/backend | backend | payout path | not through Worker | fails closed |
| `GET/POST/PATCH/DELETE /api/agents*` | Blitz/backend | backend | agent wallet/payment paths | not through Worker | fails closed |
| `POST /api/payment`, `/api/faucet` | Blitz/backend | backend | yes | not through Worker | fails closed |
| `GET /api/agents/leaderboard`, `/stats`, `/activity` | Blitz/backend | backend | no direct mint | not through Worker | fails closed |
| `GET /api/public/verify`, `/api/public/agents/{id}/proofs` | Blitz/backend | backend | read-only chain | not through Worker | fails closed |
| `GET /auth/github`, `/auth/github/callback`, preview variants | Blitz/backend | backend | no | not through Worker | fails closed |
| `POST /auth/wallet-recover` | Blitz/backend | backend | explicit signer recovery | not through Worker | fails closed |
| `GET /api/dev-login` | backend only if `DEV_LOGIN_USER_ID` | backend | no | not through Worker | 404/fail closed |
| `GET /schema/*` | Blitz/backend | backend | no | proxy typed 503 if unconfigured | fails closed |

## Interpretation

- **Independent of Blitz now:** wallet nonce/login/link/csrf/logout and
  `/api/me` under `AUTH_MODE=worker`, because they do not call the proxy. The
  local HTTP/PG test disables `fetch` and still completes the flow.
- **Not independent:** tasks, agents, payments, balances, health, schema,
  public proofs, GitHub OAuth, and wallet recovery. They remain explicitly
  backend-dependent and must not be described as migrated.
- **Signer dependency:** only the paths that mint/read a Rialo wallet or sign a
  payment. The Worker auth flow carries no signer key material.
- **Cloudflare/Neon reality:** local tests use a Node HTTP harness and an
  embedded PostgreSQL adapter, plus unit tests. No request was sent to a real
  Cloudflare account or Neon branch. Neon serverless and Workers runtime
  behavior are therefore **not production-proven**.
