# G1156 — Isolated signer v2 blocker

Status: **BLOCKED**. No v2 adapter is implemented and no v2 success is claimed.

## Current boundary

`V8LocalSigner` in `src/bin/server.rs` calls the v1 application wallet boundary
(`strict_wallet_load_or_mint`). The isolated signer v2 user lane has a different
creation ceremony and cannot be entered with the data currently available to
the V8 worker.

## Exact signer contract

The signer route is:

`POST /user/wallet` on the loopback-only signer endpoint.

It accepts `UserWalletCreateRequest` (`tools/agentpay-signer/src/user_signer_protocol.rs`):

| Field | Meaning | Where the value must come from |
|---|---|---|
| `user_id` | decimal string subject | authenticated app user; must equal auth proof |
| `channel_nonce` | fresh per-request nonce | app request; sealed response binds it |
| `admin_ceremony_proof` | `blake3("g81-user-create-ceremony-v1" || admin_secret)` | operator-held `AGENTPAY_SIGNER_ADMIN_SECRET` |
| `intro_proof` | `blake3(INTRO_DOMAIN || generation_secret)` | operator-held `AGENTPAY_SIGNER_USER_CREATE_SECRET` |
| `auth_signature` | Ed25519 creation-intent signature by the registered user auth key | signer-side registered binding; subject signature |

The signer additionally enforces:

- `AGENTPAY_USER_WALLET_VERSION=2` (unset means structurally absent);
- the admin proof in constant time;
- the intro proof in constant time;
- `user_id == auth_signature.pubkey.user_id`;
- a durable `CreationGate` nonce burn/singleflight under the signer root;
- a registered user binding and creation-intent signature;
- signer-side user policy presence/format and identity binding;
- the v2 wallet store version and the sealed channel response.

`POST /user/wallet` is not an admin-token endpoint that can be called with a
session cookie. The admin secret is read from the signer process environment;
the generation secret never crosses the wire; the response exposes only the
public address and a recovery-envelope presence flag.

## Why the app cannot safely implement it

- Putting `AGENTPAY_SIGNER_ADMIN_SECRET` or the generation secret in the
  Worker/Neon/V8 outbox would violate the signer-isolation boundary and the
  “no private/operator secrets in Cloudflare or Neon” rule.
- A Worker cannot mint the creation-intent signature because it does not hold
  the user's registered auth private key.
- Calling the signer with a forged proof, a reused nonce, or a mismatched user
  binding would either be rejected or weaken the ceremony.
- The current V8 outbox stores only `user_id`, state, worker lease and public
  result; it has no operator ceremony material and must not acquire it.

## Safe options for a future phase

1. **Operator-provisioned users:** the operator completes `/user/wallet` out of
   band and records only the public address + binding reference; V8 then reads
   the public result. This needs an explicit provisioning registry and a
   reviewed operator workflow.
2. **Signer-issued capability:** the signer issues a short-lived, user-bound,
   single-use capability after its own ceremony; the Worker presents only that
   capability. This requires a new reviewed protocol and anti-replay design.
3. **Signer-side background provisioner:** the signer, not the Worker, owns the
   request queue and receives only user identity/authorization evidence. This
   requires moving V8 into the signer trust domain.

None of these is implemented here. Until one exists, V8 remains opt-in and
local (`AGENTPAY_WALLET_PROVISIONING=1`), using the v1 boundary.

## Contract tests

- `src/bin/pg_integration.rs::v8_isolated_signer_v2_user_wallet_adapter_is_blocked`
  is ignored with an explicit BLOCKED reason and panics if run; it is not a
  passing test.
- `tests/functions/signer-boundary.test.mjs` fails if Worker source contains
  admin/generation secret names, ceremony fields, or `/user/wallet`.
- `tests/functions/signer-boundary.test.mjs` also guards that the V8 boundary
  remains opt-in and that `TxSigner::User` is not added to the server.

Latch, default-deny, payment policy and spend limits remain untouched. No
private key, seed, recovery envelope, or operator secret is moved into
Cloudflare, Neon, logs, or a test fixture.
