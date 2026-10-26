# G1156 — External Cloudflare/Neon verification setup

Status: **NOT RUN** in this environment. No external resource was created or
modified. The steps below are for an operator with explicit authorization to
create an isolated test project/branch.

## Required isolated resources

1. A **dedicated** Cloudflare Pages test project (not production) and a
   **dedicated** Neon branch/database (not the production branch).
2. A test GitHub OAuth app or a test callback only if OAuth is being exercised;
   do not reuse production secrets for a test.
3. A loopback signer test instance only if signer paths are being exercised;
   never expose its admin/generation secrets to Pages or Neon.

## Configuration names (values are supplied by the operator, never committed)

- `AUTH_MODE=worker`
- `TASKS_MODE=neon` (task read routes)
- `DATABASE_URL` — isolated Neon branch connection string
- `BACKEND` — only for still-proxied routes
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI` — test app
- `AGENTPAY_WALLET_PROVISIONING=1` only if the signer v1 local boundary is
  explicitly being tested; v2 remains blocked
- `FUNCTIONS_STATIC_ONLY=1` only for static-build preflight, not a worker test

Do not put any value in `wrangler.toml.example`.

## Runbook

```text
# local preflight (no external resources)
npm run build:static
FUNCTIONS_STATIC_ONLY=1 npm run check:functions
npx wrangler pages functions build --outdir=/tmp/g1156-functions-build

# against the isolated test project (operator authorization required)
# 1. apply reviewed migrations to the TEST Neon branch only
# 2. set the test environment values above
# 3. deploy the reviewed build to the TEST Pages project
# 4. verify, with logs and response bodies:
#    GET /                      -> 200 static
#    GET /api/me (logged out)   -> 200 logged_in:false
#    GET /api/schema            -> 200 canonical schema
#    GET /api/agents (no auth)  -> 401 typed
#    GET /api/tasks             -> 200/503 typed according to DB health
#    GET /api/public/verify     -> typed RPC result, never fabricated
#    unknown non-API path       -> 404
# 5. run one real wallet auth round-trip with a synthetic test wallet
# 6. stop; do not promote the test project or touch production
```

## What is still unproven after local tests

- Neon HTTP/serverless pooling and prepared-statement behavior.
- Real Pages Functions binding resolution and route precedence in production.
- Real Workers limits, cold starts, and observability.
- Real GitHub OAuth code exchange and callback behavior.
- Any signer/Latch/payment behavior; no signer v2 adapter exists.
- Production DNS, secrets, migrations, and deployment.

Local PostgreSQL and Wrangler results are not a substitute for any of the
above.
