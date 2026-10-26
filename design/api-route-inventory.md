# Route inventory — Cloudflare/Worker readiness

> G1154 note: this file is retained as the G1153 inventory. The current,
> implementation-backed matrix is `design/g1154-api-dependency-matrix.md`;
> V8 now has an opt-in worker and login enqueue, but still no public HTTP
> provisioning route.

Status as of this execution tree. `Worker` means the Pages Function route owns
the request when its feature flag is enabled. A `proxy` route still uses the
configured backend; it is not Blitz-independent.

| Route | Current owner | Data source | Signer needed | Local test evidence | If Blitz is down |
|---|---|---|---|---|---|
| `POST /auth/wallet/nonce` | Worker | Neon nonce hash | no | Worker unit + HTTP/PG | works |
| `POST /auth/wallet/verify` | Worker | Neon identity/session | no | Worker unit + HTTP/PG | works |
| `POST /auth/wallet/link/nonce` | Worker | Neon session/nonce | no | Worker unit | works with session |
| `POST /auth/wallet/link/verify` | Worker | Neon session/identity | no | Worker unit | works with session |
| `POST /auth/csrf` | Worker | Neon session | no | Worker unit | works |
| `POST /auth/logout` | Worker | Neon session | no | Worker unit + HTTP/PG | works |
| `GET /api/me` | Worker | Neon session/wallet/provisioning | public key only | Unit + HTTP/PG | works; balance unavailable |
| `GET /api/tasks/open` | Worker when `TASKS_MODE=neon` | Neon `tasks_pg` | no | Unit + HTTP/PG | works for read-only board |
| `POST /api/tasks` | Backend | existing store | task owner/signer path | not migrated | fails closed |
| `GET /api/tasks/{id}` | Backend | existing store | no | not migrated | fails closed |
| `POST /api/tasks/{id}/claim` | Backend | existing store | no direct mint | not migrated | fails closed |
| `POST /api/tasks/{id}/submit` | Backend | existing store | no | not migrated | fails closed |
| `POST /api/tasks/{id}/review` | Backend | existing store | payout path | not migrated | fails closed |
| `POST /api/tasks/{id}/cancel` | Backend | existing store | no | not migrated | fails closed |
| `POST /api/tasks/{id}/payout/reconcile` | Backend | existing store | read-only reconciliation | not migrated | fails closed |
| `GET/POST /api/agents` | Backend | existing store | create path mints agent wallet | not migrated | fails closed |
| `GET/PATCH/DELETE /api/agents/{id}` | Backend | existing store | no | not migrated | fails closed |
| `GET /api/agents/{id}/balance` | Backend | Rialo RPC | no | not migrated | unavailable/fails closed |
| `PATCH /api/agents/{id}/status` | Backend | existing store | no | not migrated | fails closed |
| `GET/PATCH /api/agents/{id}/policy` | Backend | existing store | no | not migrated | fails closed |
| `GET/POST /api/agents/{id}/payments` | Backend | existing store/signer | yes | not migrated | fails closed |
| `GET /api/agents/{id}/stats`, `/activity` | Backend | existing store | no | not migrated | fails closed |
| `GET /api/agents/leaderboard` | Backend | existing store | no | not migrated | fails closed |
| `GET /api/agents/stats` | Backend | existing store | no | not migrated | fails closed |
| `GET/POST /api/agents/triggers/payments*` | Backend | credential lane/signer | yes | not migrated | fails closed |
| `GET /api/health` | Backend | agentpay + RPC probe | no | not migrated | fails closed |
| `GET /api/program/status` | Backend | Rialo program | no | not migrated | fails closed |
| `GET /api/schema` | Backend | static/backend schema | no | not migrated | fails closed |
| `POST /api/payment` | Backend | signer/Rialo | yes | not migrated | fails closed |
| `POST /api/faucet` | Backend | signer/Rialo | yes | not migrated | fails closed |
| `GET /api/public/verify` | Backend | Rialo RPC | no | not migrated | fails closed |
| `GET /api/public/agents/{id}/proofs` | Backend | Rialo RPC | no | not migrated | fails closed |
| `GET /auth/github`, `/auth/github/callback`, `/auth/github/preview/*` | Backend | OAuth secrets/session | no | not migrated | fails closed |
| `POST /auth/wallet-recover` | Backend | signer/recovery | explicit recovery | not migrated | fails closed |
| `GET /auth/dev-login` | Backend only if enabled | local dev identity | no | not migrated | 404/fail closed |
| `/schema/*` | Proxy/backend | backend schema | no | proxy typed 503 if no BACKEND | fails closed |
| `GET /api/wallet/provisioning` | not implemented | V8 table | no | not applicable | not activated |

## Notes

- The `GET /api/tasks/open` row is a read-only migration. Task mutations and
  payout paths remain on the backend; the route must not be described as full
  task migration.
- Balances and payments remain RPC/signer-sensitive and must not run in a
  Cloudflare Worker.
- A missing `BACKEND` only affects proxy routes; Worker-owned auth and the
  static assets continue to serve (the proxy returns a typed 503).
