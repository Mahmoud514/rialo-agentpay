# G1155 — API dependency matrix

Status legend: **W** = Worker-owned and tested locally; **N** = Neon-backed
(Worker-owned path, local PostgreSQL/Neon-shaped test); **S** = signer or chain
service; **B** = still Blitz/backend; **X** = blocked/untested; **—** = static.

## Auth and identity

| Route | Status | Evidence / reason |
|---|---|---|
| `GET /api/me` | **W/N** | Worker-owned; session + public wallet + provisioning; no Blitz; 47 node tests + HTTP/PostgreSQL test. |
| `GET /auth/wallet/message`, `POST /auth/wallet/nonce` | **W/N** | Worker auth router; nonce in Neon. |
| `POST /auth/wallet/verify` | **W/N** | Worker auth router; hashed session; provisioning enqueue. |
| `POST /auth/wallet/link` | **W/N** | Worker auth router; session + link; provisioning enqueue. |
| `GET /auth/github`, GitHub callback/session exchange | **B** | GitHub OAuth client secret and backend flow remain in Blitz; not in Worker. |
| `POST /auth/logout` | **B** | Backend session/CSRF behavior not migrated. |
| Session/CSRF/recovery endpoints | **B/X** | Recovery still uses backend/signer operator path. |

## Agents

| Route | Status | Evidence / reason |
|---|---|---|
| `GET /api/agents` | **W/N** | New Worker route; owner-scoped Neon list; no Blitz; tested with memory store and disposable PostgreSQL. |
| `GET /api/agents/{id}` | **W/N** | New Worker route; owner-scoped; foreign/missing -> 404; no Blitz. |
| `POST /api/agents`, `PATCH/DELETE /api/agents/{id}` | **B** | Validation, provisioning, signer side effects and audit remain backend. |
| `POST /api/agents/{id}/rotate-key` | **S/B** | Signer/auth-key rotation and chain policy. |
| `GET /api/agents/{id}/balance` | **S/B** | RPC/Blitz wallet balance; no fake balance in Worker. |
| `GET /api/agents/{id}/policy` | **B** | Payment policy/spend limits are backend-owned. |
| `GET /api/agents/{id}/stats`, `/activity`, `/transactions` | **B** | Backend projections. |
| `GET /api/agents/leaderboard` | **B** | Backend aggregation. |
| Agent triggers/schedules/jobs | **B** | Backend scheduler and signer authority. |

## Tasks

| Route | Status | Evidence / reason |
|---|---|---|
| `GET /api/tasks` | **W/N** | Worker-owned read-only board; owner/worker visibility in SQL; tested over HTTP/PostgreSQL. |
| `GET /api/tasks/open` | **W/N** | Worker-owned read-only; Neon; authorization contract tested. |
| `GET /api/tasks/{id}` | **W/N** | Worker-owned read-only detail from `to_jsonb(tasks_pg)`; open public, non-open authenticated; no Blitz. |
| `GET /api/tasks/{id}/files` | **B** | Attachments remain backend. |
| `POST /api/tasks`, cancel/accept/submit/approve/reject/dispute | **B** | Mutations and payment transitions require backend policy/chain. |
| Task payment/escrow/release routes | **S/B** | Rialo signing, escrow and chain confirmation. |
| Task files/attachments | **B** | Storage and validation. |

## Payments, chain and platform

| Route | Status | Reason |
|---|---|---|
| Balances, deposits, withdrawals, transfers | **S/B** | Rialo RPC + signer; no fake success. |
| Payments list/detail/intents | **S/B** | Payment policy and chain state. |
| Faucet | **S/B** | Chain transaction and limits. |
| `GET /api/health`, `/api/program`, schema endpoints | **B** | RPC/node health, program metadata, backend schema. |
| Chain proof/program inspection | **S/B** | RPC. |
| `/api/schema` and OpenAPI | **B** | Backend-owned schema. |
| Unknown non-API path | **—** | Static 404. |
| Unknown `/api/*` with no `BACKEND` | **X** | Typed `PROXY_CONFIG_ERROR` 503; not claimed as 404/independent. |

## Invariants

- No Worker route fabricates a balance, payment, signature, task state, or
  provisioning success.
- Worker reads that are not migrated return a typed dependency error or proxy;
  they do not silently return empty success.
- Agent reads are owner-scoped in SQL; a foreign UUID is indistinguishable from
  a missing one (404).
- `AUTH_MODE=worker` owns `/api/me` and agent reads. Task reads require
  `TASKS_MODE=neon`; task mutations remain proxy/backend. `AUTH_MODE=proxy`
  keeps the previous backend behavior.
- The list/detail agent and task routes are the additional Worker migrations in
  G1155. Task mutations, payments, balances, faucet, health/program, schema,
  GitHub OAuth, recovery and all Rialo signing remain backend/signer/chain
  dependent.
