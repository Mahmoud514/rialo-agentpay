# G1156 — Cloudflare-only wallet auth

## Scope

Wallet connect now uses **Cloudflare Pages Functions + D1**. The wallet nonce,
signature verification, session, identity, and `/api/me` paths do not call Blitz
and do not use `@neondatabase/serverless` when a D1 `DB` binding is present.

The rest of the product is not reclassified: agent/task reads still require the
Neon path, and GitHub OAuth, task mutations, payments, recovery, balances, and
Rialo signing remain on the existing backend/signer boundaries.

## Components

- `functions/_lib/auth/store.js` selects `createD1Store(env.DB)` first.
- `functions/_lib/auth/d1-store.js` implements the same store contract against D1.
- `migrations/0009_d1_auth.sql` creates the isolated auth tables:
  nonces, identities, sessions, rate limits, user wallets, and provisioning
  requests.
- `functions/auth/[[route]].ts` routes every wallet auth endpoint to the Worker
  handler regardless of `AUTH_MODE`; `AUTH_MODE=proxy` is a rollback for
  non-wallet legacy routes only.
- `functions/api/[[route]].ts` serves `/api/me` from the Worker session store
  regardless of `AUTH_MODE`.
- `scripts/verify-d1-wallet-e2e.mjs` uses a fresh synthetic EVM key (never a real
  wallet) and proves nonce -> EIP-191 signature -> session cookie -> `/api/me`.

## Preview setup used

```text
D1 database: rialo-agentpay-preview-auth
Pages project: rialo-agentpay-preview
Preview binding: DB -> rialo-agentpay-preview-auth
Preview alias: https://rialo-agentpay-preview.pages.dev
```

Apply the schema to the isolated database before deploying:

```text
wrangler d1 execute rialo-agentpay-preview-auth --remote \
  --file=migrations/0009_d1_auth.sql
```

The Pages preview project already has `AUTH_MODE=worker` and `TASKS_MODE=neon`;
the D1 binding is `DB`. No secrets or private keys are stored in D1.

## Verification

Local Wrangler + D1:

```text
node scripts/verify-d1-wallet-e2e.mjs http://127.0.0.1:8800
```

Cloudflare preview + D1:

```text
node scripts/verify-d1-wallet-e2e.mjs \
  https://rialo-agentpay-preview.pages.dev
```

Both returned HTTP 200 for nonce, verify, and `/api/me`, with
`logged_in: true` and the session login equal to the synthetic test address.
The user's real wallet was never unlocked or used in this test.

## Not done

- No production D1 binding and no production auth migration.
- No change to task mutations, balances, payments, GitHub OAuth, wallet
  recovery, or Rialo signing.
- Real MetaMask/OKX/Rabby signatures were not forced through a warning or a
  password prompt; the browser selector reached Rabby's unlock screen, which
  requires the operator's wallet password.
