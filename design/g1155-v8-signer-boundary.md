# G1155 — V8 isolated-signer boundary

## Finding

G1154's V8 worker deliberately calls the v1 application wallet boundary
(`strict_wallet_load_or_mint`). It does not call the isolated signer v2 user
lane. That is a real gap, not a deployment detail.

## What the isolated signer requires for a NEW user wallet

The signer's `POST /user/wallet` route is not a simple “create public key”
endpoint. `user_lane::handle_user_wallet_create` enforces all of the following
inside the signer process:

- `AGENTPAY_USER_WALLET_VERSION` and a generation secret in signer-only env;
- an admin ceremony proof derived from an operator-held admin secret;
- a valid intro proof derived from the generation secret;
- a registered user auth binding;
- an Ed25519 creation-intent signature over `creation_intent_message(user_id,
  nonce)`;
- a one-time channel nonce and the durable creation gate/singleflight;
- the signer-side user policy directory and version gate;
- a sealed response channel.

The application does not possess the generation secret, admin ceremony secret,
or a safely derivable creation-intent proof. The Worker/Neon/V8 outbox must not
receive any of these values: they are operator/signer credentials, not
provisioning metadata.

## Decision

Do **not** substitute an endpoint that mints a wallet with weaker ceremony.
Do **not** put the admin secret, generation secret, or private key material in
Neon, the Worker, the outbox, logs, or a V8 request. The safe state is:

- V8 worker disabled by default (`AGENTPAY_WALLET_PROVISIONING` unset);
- its local adapter remains the v1 strict load/mint boundary;
- the outbox records only public state;
- v2 integration is **BLOCKED** on a designed operator ceremony and a reviewed
  signer-side adapter.

## Required contract before enabling v2

1. A reviewed app↔signer protocol where the app can request a user wallet
   without possessing signer creation secrets.
2. Proof that the channel is loopback-only and mutually authenticated (or a
   documented equivalent), with replay/nonce/fencing semantics.
3. A test-only signer fixture that returns only a public address and
   deterministic idempotent results for the same `(user_id, auth binding,
   operation id)`.
4. Failure mapping for timeout/uncertainty, duplicate, conflicting binding,
   corrupt record, and policy-denied states.
5. A disposable-Postgres V8 test that exercises the real adapter boundary and
   proves no `ready` without the registry row.
6. Security review of secret handling and Latch/default-deny/spend-limit
   preservation.

Until all six are satisfied, claiming that V8 is connected to the isolated
signer would be false. The status is **BLOCKED**, not PASS.
