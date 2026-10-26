# G1156 — API migration inventory

Legend:

- **W** Worker-owned and locally tested.
- **N** Neon/PostgreSQL-backed through the Worker.
- **B** still backend/Blitz-owned (proxy).
- **S** requires the Rialo signer, RPC, or chain; must stay behind the trusted
  backend until a safe signer boundary exists.
- **X** blocked or not implementable without an external contract.
- **—** static asset/page.

This inventory covers the Rust router, every Pages Function/proxy, the frontend
fetch calls, and the current database tables. “Tests” means existing G1156
suites, not a claim about a real Cloudflare/Neon deployment.

## Static pages and assets

| Surface | Status | Source / notes |
|---|---|---|
| `index.html`, `dashboard.html`, `wallet.html`, `agents.html`, `leaderboard.html`, `marketplace.html`, `activity.html`, `verify.html` | **—** | `frontend/src`; built by `scripts/build-static.mjs`. No backend needed to serve bytes. |
| `GET /api/schema` | **W** | Static credential schema; Worker serves the same document as `src/schema/credentials.schema.json`; no DB/signer; tests added. |
| `GET /schema/*` | **B** | Existing Pages proxy; not part of `/api/schema`. |

## Authentication and identity

| Route | Status | Source of truth / authorization / dependency | Contract / tests | Blitz? |
|---|---|---|---|---|
| `POST /auth/wallet/nonce` | **W/N** | Neon `wallet_nonces`; rate limit; address normalization; one-time nonce | Node auth tests; no Blitz | No |
| `POST /auth/wallet/verify` | **W/N** | Neon nonce consume + identity/session; EIP-191 recovery; hashed session | Node auth, HTTP/PostgreSQL | No |
| `POST /auth/wallet/link/nonce`, `/link/verify` | **W/N** | Neon nonce + identity link + session rotation | Node auth | No |
| `POST /auth/csrf`, `POST /auth/logout` | **W/N** | Hashed session + CSRF; Neon session deletion | Node auth | No |
| `GET /auth/github`, `/auth/github/callback`, preview callback | **B** | GitHub client secret, OAuth state, backend session; identity verification and CSRF not moved | No Worker migration | Yes |
| `POST /auth/wallet-recover` | **S/B** | Signer/operator recovery envelope and authorization; no app-side replacement | Explicitly blocked; no fake recovery | Yes + signer |
| `GET /auth/dev-login` | **B/X** | Local-only backend route gated by `DEV_LOGIN_USER_ID`; not production auth | Existing Rust tests | Yes/local |
| `POST /api/me` (wrong method) | **—** | GET only; proxy/backend behavior retained | not migrated | — |
| `GET /api/me` | **W/N** | Neon session, public `user_wallets`, provisioning status; no balance/RPC | Node + HTTP/PostgreSQL; logged-out 200 without DB | No |

## Agents

| Route | Status | Source / auth / dependencies | Contract / tests | Blitz? |
|---|---|---|---|---|
| `GET /api/agents` | **W/N** | Neon `agents`; session required; owner-scoped; deleted excluded | Node + HTTP/PostgreSQL; no Blitz | No |
| `GET /api/agents/{id}` | **W/N** | Neon `agents`; session + owner; foreign/missing -> 404 | Node + HTTP/PostgreSQL; no Blitz | No |
| `POST /api/agents` | **B** | Backend agent creation, isolated wallet/auth-key provisioning, metadata transaction; signer/FS; no safe Worker transaction | Existing Rust tests; not migrated | Yes |
| `PATCH /api/agents/{id}` | **B** | Backend record update + ownership/status rules | Existing Rust tests | Yes |
| `DELETE /api/agents/{id}` | **B** | Backend record deletion + wallet/credential lifecycle | Existing Rust tests | Yes |
| `GET /api/agents/{id}/balance` | **S/B** | RPC/node balance; tri-state, no fabricated zero | Existing Rust tests | Yes |
| `PATCH /api/agents/{id}/status` | **B** | Backend lifecycle state machine | Existing Rust tests | Yes |
| `GET/PATCH /api/agents/{id}/policy` | **B** | Backend policy/spend limits and signer authorization | Existing Rust tests | Yes |
| `POST /api/agents/{id}/payments` | **S/B** | Owner-initiated agent payment; signer/Latch/policy/spend; reservation | Existing Rust tests | Yes |
| `POST /api/agents/triggers/payments` | **S/B** | Credential lane; signer; Latch/default-deny/payment policy | Existing Rust tests | Yes |
| `POST /api/agents/{id}/payments/reconcile`, `/sweep`, triggers reconcile | **S/B** | Read-only chain evidence + backend intent ledger; no transfer | Existing Rust tests | Yes |
| `GET /api/agents/{id}/payments/receipts/{key}` | **S/B** | Backend receipt projection over authoritative intent/evidence | Existing Rust tests | Yes |
| `POST /api/agents/{id}/credentials/revoke` | **S/B** | Backend credential authority + audit | Existing Rust tests | Yes |
| `POST /api/agents/{id}/auth-key/rotate` | **S/B** | Backend funds-less key rotation + atomic promotion | Existing Rust tests | Yes |
| `POST /api/agents/{id}/delegation/revoke` | **B/S** | Backend delegation policy | Existing Rust tests | Yes |
| `GET /api/agents/leaderboard` | **W/N** | Neon `agents` + `payment_intents`; session + owner-scoped SQL aggregate; deterministic order; no partial board | New Node + HTTP/PostgreSQL test; no Blitz | No |
| `GET /api/agents/stats` | **B** | Backend `payment_intents` projection; owner aggregate; not yet migrated | Existing Rust tests | Yes |
| `GET /api/agents/{id}/stats` | **B** | Backend owner-scoped projection; not yet migrated | Existing Rust tests | Yes |
| `GET /api/agents/{id}/activity` | **B** | Backend paginated intent ledger; cursor/filter contract complex; not yet migrated | Existing Rust tests | Yes |
| `GET /api/agents/triggers/payments/activity` | **B/S** | Credential lane; backend ledger; not migrated | Existing Rust tests | Yes |
| `GET /api/agents/triggers/payments/stats` | **B/S** | Credential lane; privacy-filtered stats; not migrated | Existing Rust tests | Yes |

## Tasks

| Route | Status | Source / auth / dependencies | Contract / tests | Blitz? |
|---|---|---|---|---|
| `GET /api/tasks/open` | **W/N** | Neon `tasks_pg`; public open + optional viewer; limit/offset | Node + HTTP/PostgreSQL; no Blitz | No |
| `GET /api/tasks` | **W/N** | Neon `tasks_pg`; open + owner/worker visibility; newest-first | Node + HTTP/PostgreSQL; no Blitz | No |
| `GET /api/tasks/{id}` | **W/N** | Neon `to_jsonb(tasks_pg)`; open public, non-open authenticated; ownership flags | Node + HTTP/PostgreSQL; no Blitz | No |
| `POST /api/tasks` | **B** | Rust create writes task JSON + PostgreSQL + reserves reward from the agent wallet; requires agent ownership/status/payment reservation | Not migrated; precise blocker below | Yes |
| `POST /api/tasks/{id}/cancel` | **B** | Rust owner check + release reservation + FS/PG update | Not migrated; blocker below | Yes |
| `POST /api/tasks/{id}/claim` | **B** | Rust claim CAS in PostgreSQL + FS write + worker recipient + store lock | Not migrated; blocker below | Yes |
| `POST /api/tasks/{id}/submit` | **B** | Rust worker check + state transition + 12 MB submission JSON/files in FS/PG | Not migrated; blocker below | Yes |
| `POST /api/tasks/{id}/review` | **S/B** | Rust owner decision + payment/escrow settlement + signer/agent policy | Must stay signer/backend | Yes + signer |
| `POST /api/tasks/{id}/payout/reconcile`, `/tasks/payout/reconcile/sweep` | **S/B** | Read-only recovery against authoritative intent/chain; no transfer | Existing Rust tests | Yes + chain |
| Task file/attachment routes (inside submit/detail) | **B** | Backend FS storage and body limit | Existing Rust tests | Yes |

### Why task mutations are not migrated

The canonical task state is still dual-written by the Rust backend:

- `artifact/tasks/<id>.json` is the filesystem authority used by
  `read_task_for_action` / `write_json_atomic`;
- `tasks_pg` is the PostgreSQL authority used by the recovery/list paths;
- claim uses a PostgreSQL CAS **and** a subsequent filesystem write under
  `agents::store_lock`;
- cancel calls `release_reservation_inner`, which changes the agent wallet
  reservation ledger;
- submit persists submission files/notes into the task record;
- review and payout require the signer/agent-wallet payment path and
  idempotency reservation.

A Worker-only SQL mutation would either split authority (Neon row changes while
the backend FS/JSON remains stale) or bypass the reservation/payment controls.
That is not a safe migration. Until the backend has a single transactional
task store (or a reviewed task-service API), the Worker must proxy these routes.
This is a deliberate BLOCKED result, not a missing test.

## Payments, balances, chain, and platform

| Surface | Status | Source / reason |
|---|---|---|
| `POST /api/faucet` | **S/B** | Rialo RPC + faucet limits/transaction; no fake success |
| `POST /api/payment` | **S/B** | Rialo signing + transfer; private keys never in Worker |
| `GET /api/health` | **S/B** | Backend + Rialo RPC probe; no local health fabrication |
| `GET /api/program/status` | **S/B** | Venus program/RPC readiness |
| `POST /api/payment/program/*` | **S/B** | Program-mediated payment, cap/policy |
| `GET /api/public/verify` | **S/B** | Chain signature lookup; sessionless; RPC unavailable -> typed 503 |
| `GET /api/public/agents/{id}/proofs` | **S/B** | Public chain proof projection; RPC |
| `/api/schema` (Rust) | **W** in Worker; old route | Same static document; Worker route added |
| Remaining `/api/*`, `/auth/*` not listed | **B** | Proxy; no silent success |

## Migration decisions in G1156

1. Added Worker-owned `GET /api/agents/leaderboard` with owner-scoped SQL over
   `agents` + `payment_intents`, deterministic ordering, and no Blitz call.
2. Added Worker-owned `GET /api/schema` using the canonical static schema
   document; non-GET is a typed 405.
3. Preserved all existing task/agent reads and all existing proxy behavior.
4. Did **not** migrate task mutations, OAuth, recovery, balances, payments,
   faucet, health/program, public chain proofs, or signer-v2 provisioning.
5. Added boundary tests that fail if task mutations, value movement, OAuth,
   recovery, or signer ceremony secrets appear in the Worker.

## External status

Cloudflare/Neon end-to-end is **NOT RUN**. There is no authorized isolated test
project/branch or credentials in this environment. Local Postgres and Wrangler
are the only executed evidence. This file makes no claim of complete Blitz
independence.
