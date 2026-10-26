# G1155 — Cloudflare Pages local runtime status

## Build

- `npm run build:static` → exit 0; output `dist/static`.
- `npx --yes wrangler pages functions build --outdir=/tmp/g1155-functions-build`
  → `Compiled Worker successfully`, exit 0.
- `FUNCTIONS_STATIC_ONLY=1 npm run check:functions` → exit 0.

These are local build checks only. No Cloudflare account, Pages project, DNS,
secret, or deployment was changed.

## Static-only runtime

Serving a copy of `dist/static` from a directory with no Functions:

| Request | Result |
|---|---|
| `GET /` | 200 |
| `GET /api/me` | 404 |
| `GET /api/tasks` | 404 |
| `GET /does-not-exist.js` | 404 |

This demonstrates the static frontend has no runtime `BACKEND` requirement.
It does **not** prove a production Pages deployment.

## Worker runtime, no database binding

`wrangler pages dev dist/static --binding AUTH_MODE=worker --binding TASKS_MODE=neon`
with no `DATABASE_URL` (so the absence path is exercised; no fake DB):

| Request | Result |
|---|---|
| `GET /` | 200 (static asset) |
| `GET /api/me` (no cookie) | 200 `logged_in:false`; no DB required |
| `GET /api/agents` (no cookie) | 401 `NOT_AUTHENTICATED` |
| `GET /api/agents/{uuid}` (no cookie) | 401 `NOT_AUTHENTICATED` |
| `GET /api/tasks` | 503 `TASK_LIST_UNAVAILABLE` typed |
| `GET /api/tasks/open` | 503 `TASK_LIST_UNAVAILABLE` typed |
| `GET /api/tasks/{id}` | 503 `TASK_DETAIL_UNAVAILABLE` typed |
| `GET /api/agents/leaderboard` | 503 `PROXY_CONFIG_ERROR` (not migrated) |
| `GET /does-not-exist.js` | 404 |

No response contained a connection string, key, or secret. The 503s are typed
dependency errors, not fabricated empty results.

## Gates

- `/api/me` and agent reads: `AUTH_MODE=worker`.
- Task reads (including `/api/tasks/open`): `TASKS_MODE=neon`; task mutations
  remain proxy/backend.
- Real Neon is not reachable through the local `@neondatabase/serverless`
  driver, so authenticated Worker reads over a real Neon branch are **NOT RUN**.
  The HTTP/PostgreSQL harness uses the same handler contracts with a local
  PostgreSQL adapter and is the executed integration evidence.
