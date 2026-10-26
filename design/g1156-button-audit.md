# G1156 — Button / route audit (canonical preview)

URL: `https://rialo-agentpay-preview.pages.dev`

## Navigation and pages

| Control | Result |
|---|---|
| Home / Marketplace / Wallet / Dashboard / Agents / Leaderboard / Activity / Verify | HTTP 200 |
| Wallet chip / Logout | D1 session works |
| Wallet connect (OKX/Rabby) | nonce 200, verify 200, `/api/me` 200 |
| Wallet connect (MetaMask) | extension not detected in the test profile; not a server failure |

## Agents

| Action | Result |
|---|---|
| Create agent | 201, D1 row; verified in Edge |
| Rename / Activate / Pause / Disable | 200 with lifecycle guards |
| Policy read/write | 200 |
| Stats / Activity | 200 (empty activity is honest) |
| Balance | `no_wallet` until a signer provisions a wallet |
| Delete | draft only; 409 for non-draft |

## Marketplace

| Action | Result |
|---|---|
| Open board / task detail | 200 / 404 typed for unknown IDs |
| Create / cancel task | 201 / 200 |
| Claim / submit | 200 |
| Reject / request changes | 200 |
| Approve & pay | 503 `PAYOUT_UNAVAILABLE` (signer required) |

## Wallet

| Action | Result |
|---|---|
| Faucet | 503 `FAUCET_UNAVAILABLE` (signer required) |
| Direct payment | 503 `PAYMENT_UNAVAILABLE` (signer required) |
| Copy address | only after a wallet exists; no address is fabricated |
| GitHub login | 503 backend/unconfigured; no GitHub secret in Worker |

## Other

| Action | Result |
|---|---|
| Health | 200, RPC explicitly unavailable |
| Program status | 200, configured:false |
| Public verify / proofs | 503 `RPC_UNAVAILABLE` / explicit unavailable |
| Schema | 200 |

The remaining failures are not UI wiring failures. They require the isolated
signer, Rialo RPC/proofs, or GitHub OAuth credentials; the Worker must not fake
those outcomes.
