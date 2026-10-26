# Cloudflare Pages deployment — static, Functions, and backend separation

## Three independent surfaces

1. **Static preview** — only `frontend/src` assets. No Functions directory is
   needed. `scripts/build-static.mjs` copies the assets to `dist/static` and
   writes a `404.html`; it never needs `BACKEND`, `DATABASE_URL`, or a secret.
2. **Pages Functions build** — the `functions/` tree compiled as a Worker.
   Configuration is request-scoped (`context.env`), not a module global.
3. **Backend-dependent routes** — `/api/*` except Worker-owned `/api/me`, plus
   `/schema/*` and non-worker `/auth/*`. They require a valid `BACKEND` and are
   proxied without exposing the configured value.

`AUTH_MODE=worker` is the switch for Worker-owned auth. Without it, auth and
API paths retain the transitional backend proxy. Worker auth paths do not call
the backend; `/api/me` in Worker mode reads Neon only.

`TASKS_MODE=neon` enables the read-only `GET /api/tasks/open` Worker route.
Without it, the same path retains the backend proxy. Task creation, claiming,
submission, review, cancellation, payouts, and recovery are never moved by this
flag.

## Local commands (no deployment)

```text
npm run build:static
# static-only preview with no Functions directory:
cd dist && npx wrangler@4.152.0 pages dev static --port 8790 --ip 127.0.0.1

# compile Functions only (does not deploy):
npx wrangler@4.152.0 pages functions build functions \
  --outdir /tmp/g1152-functions-build \
  --compatibility-date 2026-10-01
```

The repository-root `functions/` directory is intentionally retained. A
static-only preview must be run from a directory where `functions/` is not its
sibling (for example `dist/`); this was exercised and returned the static
`index.html` with `/api/me` as the static 404, without a module-load error.

## What is not configured

- No `wrangler.toml`, project name, account id, DNS, route, custom domain,
  secret, or deployment token is added here.
- No production Pages environment variable is changed.
- `BACKEND` remains a server-side Pages environment value. It must not appear
  in frontend assets, repository files, URLs, or logs.
- A Functions deployment with a missing/invalid `BACKEND` intentionally fails
  closed with `PROXY_CONFIG_ERROR` (HTTP 503) for backend-dependent routes.

## Build-output contract

- `dist/static/` contains only static files.
- `functions/` contains API/auth/schema routes and shared `_lib` code.
- Functions never import a frontend asset, and the frontend never imports a
  Functions module.
- `scripts/build-static.mjs` excludes backup/editor suffixes; it does not copy
  environment files or secrets.
