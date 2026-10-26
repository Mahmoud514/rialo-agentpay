# Cloudflare + Neon test-environment plan (not executed)

No Cloudflare account, Pages project, Worker, DNS record, secret, or Neon
branch was created or changed. These are the requirements for a dedicated,
non-production validation environment.

## Required resources

1. A new Cloudflare Pages project whose Git integration is **not** connected to
   this repository (manual direct upload or a separate test repository).
2. A dedicated Neon branch/database used only for this test. It must not be the
   production branch.
3. A test-only `BACKEND` service (the current transitional backend) reachable
   over HTTPS, if backend-dependent routes are in scope.
4. No production Rialo keys or wallets. The signer remains outside Cloudflare.

## Environment variables (set in the provider dashboard, never the repo)

| Name | Where | Purpose | Required |
|---|---|---|---|
| `DATABASE_URL` | Pages secret / Neon connection string | Worker auth sessions, nonces, identities | yes for Worker auth |
| `AUTH_MODE` | Pages env | `worker` enables the Worker-owned auth lane | yes for Worker auth |
| `TASKS_MODE` | Pages env | `neon` enables the read-only `/api/tasks/open` Worker route | optional |
| `BACKEND` | Pages env | HTTPS origin for routes that have not moved | only for proxy routes |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` / `GITHUB_REDIRECT_URI` | backend only | GitHub OAuth remains backend-owned | only if OAuth tested |
| `AGENTPAY_*`, Rialo RPC, signer env | backend/signer only | payments/wallet operations | never in Pages |

Do not set `DATABASE_URL`, signer keys, Rialo secrets, or OAuth secrets in
frontend assets or repository files. Do not echo environment values in build
logs.

## Commands (manual, after authorization)

```text
# Build static assets locally
npm run build:static

# Compile Functions without deploying
npx wrangler@4.152.0 pages functions build functions \
  --outdir /tmp/cloudflare-functions-build \
  --compatibility-date 2026-10-01

# Create a test project and deploy ONLY after a separate approval.
# Do not run these from this repository without the operator's approval.
# npx wrangler pages project create rialo-agentpay-auth-test --production-branch main
# npx wrangler pages deploy dist/static --project-name rialo-agentpay-auth-test
```

For a static-only preview, run from a directory without a sibling `functions/`
tree:

```text
(cd dist && npx wrangler@4.152.0 pages dev static --port 8790 --ip 127.0.0.1)
```

## Required validation checklist

- [ ] Static `/` returns 200 with no Functions and no `BACKEND`.
- [ ] Static `/api/me` returns a typed 404/static response, not a module error.
- [ ] Functions bundle compiles with `AUTH_MODE=worker` and a test `DATABASE_URL`.
- [ ] `POST /auth/wallet/nonce` → EIP-191 verify → session cookie.
- [ ] `GET /api/me` returns the session and public wallet address while Blitz is
      intentionally stopped; balance is `unavailable`, never zero.
- [ ] `GET /api/tasks/open` with `TASKS_MODE=neon` returns the same task-list
      shape while Blitz is stopped; a write route still fails closed.
- [ ] `POST /auth/logout` invalidates the session and clears the cookie.
- [ ] Legacy raw session and hash-backed session both work in the test DB.
- [ ] A backend-dependent route without `BACKEND` returns `PROXY_CONFIG_ERROR`
      (503) and does not expose the configured value.
- [ ] No secret appears in the built assets, response headers, or logs.
- [ ] The test Neon branch is deleted or detached after validation.

## Stop conditions

Stop before any project creation, deployment, DNS change, secret creation, or
production migration unless the operator explicitly authorizes that external
action. A local build is not evidence of Cloudflare/Neon integration.
