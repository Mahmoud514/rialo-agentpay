# G1156 — Cloudflare D1 preview application layer

## What is now Cloudflare-owned

The preview uses D1 for the wallet session plus the agent/task metadata that can
be represented without signing authority:

- `migrations/0010_d1_app.sql`: agents, tasks, task events, payment-intent
  projections.
- `functions/_lib/app/api.js`: owner-scoped agent create/rename/delete/status/
  policy/balance/stats/activity and task create/claim/submit/cancel/reject.
- `functions/_lib/app/system.js`: typed health/program status and explicit
  unavailable responses for faucet, payment, public proofs/verify.
- Read middlewares now select `createAuthStore` (D1 first), so `/api/agents`,
  `/api/agents/leaderboard`, `/api/tasks`, `/api/tasks/open`, and task detail
  load from D1 when `DB` is bound.

## Verified lifecycle

`scripts/verify-d1-app-e2e.mjs` runs against the live preview with two synthetic
EVM keys (never real wallets):

```text
PASS create agent -> 201
PASS list agents -> 200
PASS rename agent -> 200
PASS activate agent -> 200
PASS policy read/write -> 200
PASS create task -> 201
PASS claim task -> 200
PASS submit task -> 200
PASS approve blocked -> 503 PAYOUT_UNAVAILABLE
PASS reject allowed -> 200
PASS cancel task -> 200
```

The Edge UI was also used to create and activate an agent; the registry
returned the live D1 row and the lifecycle buttons changed accordingly.

## Deliberately not implemented

- `POST /api/faucet`: 503 `FAUCET_UNAVAILABLE`; needs the isolated signer.
- `POST /api/payment`: 503 `PAYMENT_UNAVAILABLE`; needs the isolated signer.
- Task approval/payout: 503 `PAYOUT_UNAVAILABLE`; never marked paid without the
  authoritative payment operation.
- `GET /api/public/verify` and agent proofs: 503; need chain RPC/proof source.
- GitHub OAuth: still a backend-owned route; no GitHub secret is placed in the
  Worker.
- Agent balances: `no_wallet` until provisioning; never fabricated.
