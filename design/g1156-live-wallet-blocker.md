# G1156 — Live wallet-login blocker

Observed during the actual browser attempt on **2026-10-26** (UTC):

```text
POST https://rialo-agentpay-preview.pages.dev/auth/wallet/nonce
content-type: application/json
{"address":"0x0000000000000000000000000000000000000001"}

HTTP/2 503
{"success":false,"error":{"code":"WALLET_LOGIN_UNAVAILABLE",
 "message":"Wallet login persistence is unavailable."}}
```

The same response is returned by `https://rialo-agentpay.blitz.cloud`.
`GET /api/me` returns 200 logged-out and `GET /api/health` returns 200, so this
is not a page-load failure; the backend's nonce persistence path is failing.

## Where it fails

In `src/bin/server.rs::wallet_login_nonce`, PostgreSQL storage mode calls
`pg_store::insert_oauth_state_authoritative`. A failure is intentionally
fail-closed and returns `WALLET_LOGIN_UNAVAILABLE`; the nonce is not issued.
The same code path also maps a wallet load/mint failure and a session insert
failure to the same public code.

A production diagnosis requires the backend's PostgreSQL error/logs and the
`oauth_states` table/migration state. Those were not accessed: no production
database access or deployment is authorized in this task, and inventing a
fallback would weaken login persistence/CSRF/nonce replay protection.

## Browser state

In the user's Microsoft Edge profile, the preview wallet dropdown reported:

- MetaMask: not detected;
- OKX Wallet: detected — connect;
- Rabby: detected — connect.

The wallet option opened a MetaMask connection request for
`rialo-agentpay-preview.pages.dev`; MetaMask flagged the domain as
**Malicious — flagged as unsafe**. The test stopped at that warning and did not
click “Continue at your own risk”. Independently, the live nonce request above
returns 503, so a successful wallet login would still be blocked.

## Required next step

An operator with authorized access must:

1. inspect the test/production backend PostgreSQL connectivity and
   `oauth_states` migration/table state;
2. repair the isolated test database or run the reviewed migration;
3. re-run the nonce/login E2E on a trusted domain with an unlocked test wallet;
4. only then evaluate the wallet connection.

This is an external dependency blocker, not a claim that the Worker migration
fixed production login. No secret, key, or private material was accessed.
