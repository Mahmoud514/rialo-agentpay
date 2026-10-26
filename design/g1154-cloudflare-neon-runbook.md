# G1154 — Cloudflare Pages + Neon runbook

This runbook is local-only. No Cloudflare project, DNS record, production
variable, secret, or Neon branch was created or changed in G1154.

## Build modes

| Mode | Command | Requirements | Result |
|---|---|---|---|
| static-only | `npm run build:static` | Node; no `BACKEND` | `dist/static` contains only frontend assets and `404.html` |
| Functions bundle | `npx --yes wrangler pages functions build --outdir=/tmp/g1154-functions-build` | Node/npm; no account | compiled Worker bundle |
| Functions preflight | `npm run check:functions` | provider env at deploy time | fails on missing `BACKEND` (unless static-only) or missing `DATABASE_URL` for worker auth/neon tasks |
| local Pages runtime | `npx --yes wrangler pages dev dist/static --port 8788 --ip 127.0.0.1` | local only | static `/` = 200; `/api/me` = typed 503 with no `BACKEND`; unknown path = 404 |

`FUNCTIONS_STATIC_ONLY=1` is the explicit preflight escape for a static-only
deployment. It does not create a Functions deployment.

## Environment variable names

Never commit values. Production and preview are separate provider environments.

- `BACKEND` — validated `https://` origin for proxy routes. Required for a
  Functions deployment that serves backend routes. Do not guess or replace it.
- `AUTH_MODE` — `worker` enables Worker-owned wallet auth; `proxy` is the
  rollback mode.
- `TASKS_MODE` — `neon` enables the read-only `/api/tasks/open` board; `proxy`
  leaves it on the backend.
- `DATABASE_URL` — Neon **test branch** connection string for local/staging
  validation; never a production value in a test run.
- `CF_*`/account identifiers — configured only in the provider dashboard, not
  in this repository.

The Rust worker uses its own names: `AGENTPAY_STORAGE_MODE`, `DATABASE_URL`,
and the opt-in `AGENTPAY_WALLET_PROVISIONING=1`. Do not put any of these in a
frontend bundle.

## Safe test-branch setup (requires user approval)

1. Create a dedicated Neon **test** branch/database; do not use the production
   branch.
2. Apply `migrations/0006_*`, `0007_*`, and `0008_*` in that order. The local
   disposable-PG tests prove this order and re-application; they do not prove
   a Neon branch upgrade.
3. Create a separate Cloudflare Pages preview project or preview deployment
   with its own provider variables. Do not change production DNS.
4. Set `AUTH_MODE=worker` and `TASKS_MODE=neon` only in that test environment.
5. Run the smoke script (see below) against the preview URL. Do not use real
   wallets or real funds.
6. Record `PASS`, `FAIL`, or `NOT RUN` for every check; do not infer success
   from a local Node harness.

## Smoke checklist (ready when credentials exist)

- `GET /` returns the static page with no API dependency.
- `POST /auth/wallet/nonce` returns a nonce/message; a second identical request
  remains rate-limited as designed.
- `POST /auth/wallet/verify` with a test EOA signature returns the session
  cookie and CSRF token; the nonce cannot be replayed.
- `GET /api/me` returns the same user and `provisioning` state without calling
  Blitz; a wallet-less user shows `balance_status="no_wallet"`, never `0`.
- `GET /api/tasks/open` returns `{tasks, count}` and only the expected
  owner/worker-visible rows.
- `POST /auth/logout` invalidates the session.
- A deliberately missing `BACKEND` produces a typed `PROXY_CONFIG_ERROR` 503,
  not an unhandled module exception.
- A deliberately missing `DATABASE_URL` with `AUTH_MODE=worker` produces a
  typed auth/storage failure, not a fallback to Blitz.

## Verification commands (local)

```sh
npm run build:static
npm run check:functions                    # expect failure without provider env
FUNCTIONS_STATIC_ONLY=1 npm run check:functions
npx --yes wrangler pages functions build --outdir=/tmp/g1154-functions-build
node --test tests/worker-auth/*.test.mjs tests/functions/*.test.mjs
node --test tests/integration/http-pg.test.mjs   # requires /tmp/g1154-pg-url fixture
```

Do not run `wrangler pages deploy`, `wrangler deploy`, `git push`, a migration
against production, or any command that changes DNS or secrets.
