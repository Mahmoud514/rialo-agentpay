# Rialo AgentPay

GitHub-authenticated payments and agent payment infrastructure on Rialo.
Users log in with GitHub, receive a persistent Rialo wallet, fund it from the
faucet, and pay other addresses. On top of that, owners can register software
agents with their own wallets, spending policies, and credential-authenticated
payment APIs — with idempotency, reconciliation, and an isolated signing
boundary built in.

## Features

**User wallet**
- GitHub OAuth login and server-side sessions.
- One persistent Rialo wallet per GitHub user (mode-600 key files outside the web root).
- Balance with explicit availability status (`ok` / `unavailable` / `no_wallet` — never a fake zero).
- Faucet airdrop and direct transfers with typed error codes.

**Agents and policies**
- Agent CRUD with a strict lifecycle state machine (draft → active ⇄ paused → disabled terminal).
- Independent agent wallets: funded keypairs live in the isolated signer's own store; metadata mirrors only the public address.
- Versioned payment policies: integer-kelvin per-tx and daily limits plus recipient/action allow-lists. Unset or empty means denied.
- Payment execution behind a full gate chain: lifecycle → policy → action → recipient → amount → per-tx limit → daily headroom, with spend reservation, per-agent payment locking, and idempotency keys.
- Two authentication lanes: the owner's GitHub session, and an `X-Agent-Credential` trigger lane whose principal is resolved exclusively from an Argon2id credential store (never from a session, URL, or request body).
- Per-agent and cross-agent activity, statistics, and an owner-scoped leaderboard.
- Payment receipts: owner-scoped deterministic projections over the recorded evidence.
- Agent credential revocation and authentication-key rotation via owner-scoped HTTP endpoints; credential issuance remains an operator act (see Limitations).

**Reliability**
- Payment idempotency: replays of the same idempotency key return the stored verdict with zero RPC and zero ledger mutation.
- Reconciliation of unknown outcomes: a confirmation timeout holds funds as `unknown` and resolves through typed terminals (`reconciled_paid` / `reconciled_absent`), signature lookup, a bounded address-scan proposal lane (nothing auto-finalizes), and owner-only manual attestation. An empty scan never releases spend; terminals are immutable at the store layer.
- Graceful degradation: every chain-dependent feature reports typed infrastructure errors instead of hanging or fabricating balances.

**Optional integrations**
- Latch transport/policy lane for agent payments — fully opt-in via environment variables; a Latch denial is never converted into a native retry.
- Rialo Venus program integration (workflow-based payments) — implemented and guarded, but kill-switched off by default (see Program integration).

**API vs. frontend:** the wallet frontend (login, wallet, dashboard, agents,
activity, leaderboard) covers owner-facing flows. Agent payment execution,
credential-trigger payments, and reconciliation are API-only surfaces.

## Architecture

```
GitHub OAuth ──► HTTP server + session layer (Rust, axum)
                   │  opaque UUID cookie, in-memory session map
                   ▼
                 User wallet store          Agent store (metadata, lifecycle, policies)
                   │                              │
                   │                    Agent credentials (Argon2id) / auth keys / delegation
                   ▼                              ▼
                 Rialo integration layer  ◄── Agent payment engine
                 (one module, one RPC config)  (policy gates → spend reservation →
                   │                            transfer → intent ledger → idempotency)
                   ▼                              ▼
                 Rialo CLI (signing)  ──►  ISOLATED SIGNER (agent payments, opt-in lane)
                   │                        separate loopback process; funded agent keys
                   ▼                        never enter AgentPay
                 Rialo RPC (balance / faucet / transfer / lookups)

                 Optional Latch shim: gates + audits the settlement call
                 (transport/policy only — AgentPay stays the policy source of truth)
```

Key properties:

- **User vs. agent custody is strictly separated.** User wallets are per-user
  key files; agent funded keys live in the isolated signer's own store and only
  public addresses are mirrored into AgentPay metadata.
- **All chain calls flow through one integration module** with a single RPC
  configuration point. The server never transmits or logs key material; signing
  happens in the Rialo CLI (or, for agent payments on the isolated-signer lane,
  the separate signer process).
- **Policy enforcement is a pure check boundary** with a fixed gate order and
  deny-by-contract defaults; the daily-spend ledger, balance headroom, and
  per-agent payment locks back it at execution time.
- **A single intent ledger** powers both payment lanes (one `(agent, key)` slot
  is globally exclusive across lanes; version mismatch is a binding conflict).

## Security model and boundaries

- **Authentication and ownership:** every agent route resolves ownership
  server-side from the authenticated principal; missing and foreign agents are
  indistinguishable (`AGENT_NOT_FOUND`). The credential trigger lane never
  falls back to session or body-supplied identity.
- **Least exposure:** session cookies are opaque UUIDs (production deployments
  should set `AGENTPAY_COOKIE_SECURE=1` with TLS). Development login is
  loopback-only and fails startup if configured with a non-loopback bind
  address.
- **Deny-by-contract policies:** any unset limit or empty allow-list denies.
  A daily limit without a supplied spend figure is rejected
  (`AGENT_DAILY_ACCOUNTING_REQUIRED`) rather than bypassed.
- **Money-safe uncertainty handling:** unknown settlement outcomes are held,
  never auto-retried, refunded, or lane-switched; reconciled terminals are
  immutable; ambiguous reconciliation evidence keeps the safe over-retention.
- **Fail-closed infrastructure:** RPC/filesystem/CLI failures produce typed
  error codes, never fabricated success.
- **Latch semantics:** an explicit Latch denial is returned verbatim; a
  pre-execution lane failure falls back to exactly one native attempt; no
  fallback ever occurs after execution starts; the lane never carries key
  material.
- **No autonomous execution:** there is no scheduler, webhook, or automatic
  payment path anywhere. Agent payments are explicit, synchronous, authenticated
  API calls.

Verification evidence and threat notes live in the linked reports under
[Documentation](#documentation) (`DEPLOYMENT.md`, `MARKETPLACE.md`).

## Prerequisites and installation

Requirements:

- Rust (stable) with `cargo`.
- A Rialo CLI installation (found via `RIALO_CLI_PATH`, then `PATH`, then the
  installed release path).
- A GitHub OAuth app for authentication.

Build and run:

```bash
cargo build --features server --bin server
./target/debug/server            # loads .env from the project directory
# open http://127.0.0.1:8080
```

The default bind address is `127.0.0.1:8080` (override with `SERVER_ADDR`).

GitHub OAuth setup:

1. Create a GitHub OAuth app with a callback URL matching your deployment
   (for local development: `http://127.0.0.1:8080/auth/github/callback`).
2. Copy `.env.example` to `.env` and set `GITHUB_CLIENT_ID`,
   `GITHUB_CLIENT_SECRET`, and `GITHUB_REDIRECT_URI` (must match the callback
   URL exactly).

The frontend is plain static files in `frontend/src/` served by the same
process — no build step.

## Configuration

Copy `.env.example` to `.env`; it is loaded once at startup.

| Variable | Purpose | Status | Notes |
|---|---|---|---|
| `GITHUB_CLIENT_ID` | GitHub OAuth app client id | required | — |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app secret | required | secret — keep out of the repo |
| `GITHUB_REDIRECT_URI` | OAuth callback URL | required | must match the OAuth app exactly |
| `RIALO_RPC_URL` | The only network selection point (Rialo RPC endpoint) | recommended | defaults to the localnet node (`http://127.0.0.1:4104`); set it to a Rialo testnet endpoint for testnet use; nothing else in the codebase may hard-code a URL |
| `RIALO_CLI_PATH` | Path to the Rialo CLI | optional | falls back to `PATH` lookup |
| `SERVER_ADDR` | HTTP bind address | optional | default `127.0.0.1:8080` |
| `AGENTPAY_COOKIE_SECURE` | Add `Secure` to session cookies | optional | enable with TLS in production |
| `DEV_LOGIN_USER_ID` | Development-only login mount | optional | local testing only; never set in production — startup fails on non-loopback binds |
| `AGENTPAY_LATCH_LANE` | `"1"` arms the Latch lane for agent payments | optional | fully opt-in; unset = native path |
| `AGENTPAY_LATCH_PROXY_URL` | Latch shim address | w/ lane | loopback `http://127.0.0.1:<port>` only |
| `AGENTPAY_LATCH_ID` | Public Latch correlation id | w/ lane | never a credential |
| `AGENTPAY_ISOLATED_SIGNER_LANE` | `"1"` routes agent settlement through the isolated signer | optional | loopback-only separate process |
| `AGENTPAY_ISOLATED_SIGNER_URL` | Isolated signer endpoint | w/ lane | loopback only |
| `AGENTPAY_PROGRAM_ID` | Deployed Venus program id | optional | for the program integration |
| `AGENTPAY_PROGRAM_DIR` | Program artifact directory | optional | |
| `AGENTPAY_PROGRAM_TEST_MAX_RLO` | Kill-switch cap for program payments | optional | `0`/unset = program payments disabled |
| `AGENTPAY_STORAGE_MODE` | Storage backend (`fs` default, `postgres`) | optional | Postgres mode also needs `DATABASE_URL` and `AGENTPAY_PG_LIVE=1` for live tests |
| `DATABASE_URL` | Postgres connection string | w/ PG mode | secret — keep out of the repo |

## API reference

Authentication: user routes require a GitHub OAuth session (cookie). The
"credential" lane authenticates the agent principal exclusively from the
`X-Agent-Credential` header.

### Authentication and session

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/auth/github` | GET | – | start OAuth |
| `/auth/github/callback` | GET | – | OAuth callback (CSRF state verified) |
| `/auth/dev-login` | GET | – | development-only login (loopback only) |
| `/auth/logout` | POST | session | clear session + cookie |

### User wallet and payments

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/me` | GET | session | user, wallet address, balance + explicit `balance_status` |
| `/api/faucet` | POST | session | faucet airdrop |
| `/api/payment` | POST | session | direct transfer (validates recipient/amount, pre-checks balance, returns signature + updated balance) |

### Agent management

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/agents` | GET \| POST | session | list own agents / create draft agent + independent wallet |
| `/api/agents/{id}` | GET \| PATCH | session | read own agent / rename |
| `/api/agents/{id}/balance` | GET | session | real chain balance with explicit status |
| `/api/agents/{id}/status` | PATCH | session | lifecycle transition |

### Agent policies and payments

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/agents/{id}/policy` | GET \| PATCH | session | read / replace the payment policy (kelvin limits + allow-lists) |
| `/api/agents/{id}/payments` | POST | session | owner-initiated payment from the agent's own wallet (full gate chain; API-only) |
| `/api/agents/{id}/payments/reconcile` | POST | session (owner) | reconciliation of `unknown` outcomes (manual attestation allowed) |
| `/api/agents/{id}/payments/reconcile/sweep` | POST | session (owner) | reconcile this agent's stale pending/unknown intents through the reconciliation engine |
| `/api/agents/{id}/payments/receipts/{key}` | GET | session (owner) | deterministic payment receipt projection |
| `/api/agents/triggers/payments` | POST | credential | credential-authenticated payment (same gate chain; Intent v2 records) |
| `/api/agents/triggers/payments/reconcile` | POST | credential | credential-lane reconciliation (deterministic evidence only) |

### Credentials, keys, and delegation

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/agents/{id}/credentials/revoke` | POST | session (owner) | immediate, idempotent, fail-closed credential revocation |
| `/api/agents/{id}/auth-key/rotate` | POST | session (owner) | rotate the agent's funds-less authentication key (returns public identity only) |
| `/api/agents/{id}/delegation/revoke` | POST | session (owner) | revoke delegated authority through the parent linkage (cascades to descendants) |

### Activity and statistics

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/agents/{id}/activity` | GET | session (owner) | per-agent activity ledger (read-only projection) |
| `/api/agents/{id}/stats` | GET | session (owner) | single-agent statistics |
| `/api/agents/stats` | GET | session (owner) | cross-agent statistics |
| `/api/agents/leaderboard` | GET | session (owner) | owner-scoped confirmed-volume ranking (foreign agents filtered) |
| `/api/agents/triggers/payments/activity` | GET | credential | own agent's activity ledger |
| `/api/agents/triggers/payments/stats` | GET | credential | own agent's statistics |

### Health, verification, and schema

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/health` | GET | – | AgentPay + Rialo RPC probe |
| `/api/public/verify` | GET | – | sessionless signature verification (fail-closed on RPC loss) |
| `/api/public/agents/{id}/proofs` | GET | – | public per-agent proof listing |
| `/api/schema` | GET | – | credentials JSON schema |

### Task marketplace (tasks with funded payouts)

Session-authenticated task workflows (create, claim, submit, review, payout
reconciliation) built on the same payment engine. See `MARKETPLACE.md` and
the source under `src/` (module docs) for the design and implementation status.

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/tasks` | GET \| POST | session | list tasks (filter with `/api/tasks/open`) / create a task |
| `/api/tasks/{id}` | GET | session | read one task |
| `/api/tasks/{id}/cancel` | POST | session | cancel own task |
| `/api/tasks/{id}/claim` | POST | session | claim an open task |
| `/api/tasks/{id}/submit` | POST | session | submit completed work |
| `/api/tasks/{id}/review` | POST | session | review a submission |
| `/api/tasks/{id}/payout/reconcile` | POST | session | reconcile a task payout |
| `/api/tasks/payout/reconcile/sweep` | POST | session | sweep stale task-payout intents |

### Program integration (kill-switched)

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/program/status` | GET | – | read-only program readiness snapshot (gates, manifest alignment, on-chain status) |
| `/api/payment/program/start` | POST | session | Venus workflow start (disabled by default) |
| `/api/payment/program/execute` | POST | session | Venus workflow execute (disabled by default) |

Error envelope: every chain error uses
`{"success": false, "error": {"code": "<TYPED_CODE>", "message": "…"}}`
with stable codes (`NOT_AUTHENTICATED`, `INVALID_RECIPIENT`, `INVALID_AMOUNT`,
`RIALO_RPC_UNAVAILABLE`, `AGENT_POLICY_DENIED`, `AGENT_IDEMPOTENCY_CONFLICT`,
`LATCH_POLICY_DENIED`, and others).

## Program integration

The repository includes a Venus program workflow (`start`/`execute`) whose
integration is fully implemented but **disabled by default**: program-mediated
payments remain off until an operator explicitly sets
`AGENTPAY_PROGRAM_TEST_MAX_RLO > 0`. Before every invocation the server
validates the deployment manifest (including the verified execute-account
order) and rejects a mis-signed or buggy manifest outright; direct transfers
via `POST /api/payment` remain the standard payment path. `GET
/api/program/status` reports the three readiness gates.

## Development and testing

```bash
# build
cargo build --features server --bin server

# unit + integration tests (server feature)
cargo +nightly test --features server --bin server --locked

# signer submodule tests (requires prebuilt signer binary)
cargo build --release --locked --manifest-path tools/agentpay-signer/Cargo.toml
test -f tools/agentpay-signer/target/release/agentpay-signer
```

Notes:

- Filesystem-mode tests run without any database; Postgres-mode suites require
  `AGENTPAY_PG_LIVE=1` and `AGENTPAY_STORAGE_MODE=postgres` with a reachable
  Postgres instance (see `MARKETPLACE.md` for the harness
  details).
- The isolated signer is a standalone workspace under `tools/agentpay-signer/`
  with its own lockfile; static review and its failure-mode test results are in
  the isolated-signer harness under `tools/agentpay-signer/`.
- Live end-to-end testnet verification has been performed historically against
  the Rialo testnet; detailed evidence is maintained internally.

## Documentation

**Setup & operations:** `DEPLOYMENT.md` • `MARKETPLACE.md`


**Security & limitations:** summarized in [Security & Limitations](#security--limitations) below

**Testing & verification:** see [Tests](#tests) below


## Known limitations

- **Development login is local-only** and must never be enabled in production.
- **Program-mediated payments are kill-switched** until an operator explicitly
  raises the test cap.
- **Agent payments are API-only** — payment execution, the credential trigger
  lane, and reconciliation have no frontend surface.
- **Credential issuance is operator-managed** through the credential library;
  owners can revoke credentials and rotate auth keys over HTTP, but minting a
  new agent credential is not an HTTP operation.
- **Agent wallets have no direct faucet** — owners fund them via the user
  payment path; a zero-balance agent is `INSUFFICIENT_FUNDS`.
- **No autonomous execution** — no scheduler, webhook, or automatic payments.
- **Optional integrations need their own processes**: the isolated signer
  (loopback) and/or the Latch shim must be running and configured before the
  corresponding lane activates; without them the native paths are used.
- **Production hardening prerequisites**: TLS with `AGENTPAY_COOKIE_SECURE=1`,
  backup/restore procedures, and operator verification steps are documented in
  `DEPLOYMENT.md`.
