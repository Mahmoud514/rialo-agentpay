# G1156 — GitHub OAuth and wallet recovery trace

Both flows remain backend-owned. No replacement identity or recovery mechanism
was invented.

## GitHub OAuth (current)

1. `GET /auth/github` creates a one-time OAuth `state`, stores it in the
   backend `AppState.oauth_states` map, and redirects to GitHub with
   `GITHUB_CLIENT_ID` and `GITHUB_REDIRECT_URI`.
2. GitHub redirects to `/auth/github/callback` with `code` and `state`.
3. The backend consumes the state (CSRF/replay protection), exchanges the code
   using `GITHUB_CLIENT_SECRET`, fetches the GitHub identity, upserts an
   `auth_identities` row, and issues the backend session cookie.
4. The preview lane uses the same credentials with a distinct redirect URI.

Dependencies: GitHub client id/secret, GitHub token/user API, backend session
store, OAuth state map, CSRF handling, and existing identity compatibility.

Why not migrated: the Worker does not have the OAuth client secret, and moving
the flow requires preserving state binding, redirect validation, code exchange,
identity verification, session rotation, and failure semantics. A partial
Worker OAuth implementation would be a new identity authority. Status: **B**.

## Wallet recovery (current)

1. The backend issues a short-lived recovery token only after the authenticated
   missing-wallet path (`issue_wallet_recovery_token`).
2. `POST /auth/wallet-recover` takes the form token, consumes it once, and
   rejects invalid/expired tokens.
3. It refuses if a wallet file now exists.
4. It requires a registered old public key in PostgreSQL.
5. It checks the old wallet's on-chain balance; any positive balance, RPC error,
   or unknown result refuses recovery.
6. It mints a new file, replaces the registry row only from the exact old public
   key, and writes the recovery journal result after the registry commit.

Why not migrated: recovery requires the backend wallet file authority, the
signer/operator key boundary, PostgreSQL registry CAS, and an on-chain balance
check. The Worker has none of those and must never mint or replace a wallet.
Status: **S/B**. The explicit recovery operation id and no-silent-replacement
rules remain in the Rust signer/wallet code.

## Tests / evidence

- Existing Rust server tests cover OAuth state handling, recovery authorization,
  missing-file refusal, balance refusal, registry replacement, and journal
  recovery.
- No G1156 Worker test claims either flow is independent.
- No secret, private key, seed, or recovery envelope was copied into the
  Worker/Neon fixtures.
