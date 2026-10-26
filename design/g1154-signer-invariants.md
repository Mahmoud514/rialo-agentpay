# G1154 — signer and wallet-file invariants

Base worktree: `/home/mahmoud/g1154-final-completion` (detached from
`32c3f4d626e446093e54655450fe8781a810d1b5`). This document describes the
implemented local invariants, not a deployment claim.

## Shared rules

1. A final wallet file is never opened with `File::create`, truncate, or
   `rename` replacement. Publication is complete-temp + `fsync` + `hard_link` +
   parent-directory `fsync`; `hard_link` fails with `EEXIST`.
2. A public-only operation journal is written before minting and completed only
   after the public file result exists. It contains only user id, operation
   hash, public address, and a digest of the public wallet file. It contains no
   private key, seed, signature, or raw signer error.
3. An existing completed journal is authoritative. A missing file, a digest
   mismatch, or an invalid journal fails closed and requires operator recovery;
   it never triggers a second mint.
4. An `InProgress` operation with no file is an incomplete operation and fails
   closed. An `InProgress` operation with a valid file is recovered by reading
   and completing the same public result.
5. Process-wide per-user serialization prevents duplicate in-process mints.
   Cross-process safety is provided by the no-replace file publication and the
   durable journal; a PostgreSQL advisory lock is coordination, never the sole
   guarantee.
6. No wallet file or seed is ever placed in PostgreSQL, the V8 outbox, logs,
   source maps, or a report.

## v1 user wallet (`src/bin/server.rs`)

- Operation id: `v1-user-wallet:<user_id>`.
- The first strict load checks the journal, then the file, then mints.
- A legacy file with no journal is imported by writing its public result to the
  journal; it is not replaced.
- A completed operation requires both the recorded public address and the
  recorded record digest to match the file.
- `load_wallet_strict` is used by the PostgreSQL-authoritative application
  paths. The legacy filesystem-only `load_or_create_wallet` path keeps its
  existing no-replace writer and per-user lock but does not read/write the
  operation journal. That path is not the PostgreSQL-authoritative money path;
  a deployment that keeps `AGENTPAY_STORAGE_MODE=filesystem` is a legacy mode
  and is not claimed to have the v1 journal guarantee.

## v1 explicit recovery (`POST /auth/wallet-recover`)

- Operation id: `v1-user-wallet-recovery:<user_id>`.
- Recovery is an explicit, token-gated operator flow. It refuses if a file is
  present, refuses if the old wallet has an on-chain balance, and refuses if
  the old registry row cannot be read.
- The recovery operation is started before minting. The public result is
  completed only after the registry row is atomically replaced from the old
  public key to the new one.
- On a registry failure, the newly created file is removed and the operation
  remains `InProgress`; a retry can start only because no file exists. It never
  overwrites a file.
- The recovery journal is checked before the normal journal, so an old
  completed journal cannot mask the explicitly recovered wallet.
- A completed recovery with a missing/mismatched file is terminal and requires
  operator action. It is never automatically replaced.

## Signer v2 / isolated signer

The g1150 `tools/agentpay-signer/src/wallet_file_safety.rs` implementation
uses the same publication and journal rules. Its operation journal is written
under the signer namespace. `user_lane.rs` journals before key generation,
classifies terminal states before burning a nonce, zeroes the seed bytes, and
requires both public address and record digest for a `Completed` replay.

The signer's own per-user single-flight plus the application-side advisory lock
are both required for the duplicate-signer window; the database lock alone is
not sufficient (the negative `db_lock_alone_*` test remains valid).

## Agent wallets (`src/bin/server/agents.rs`)

- The agent UUID is the logical operation id.
- Creation uses `OpenOptions::create_new(true)` (O_EXCL), mode `0600`, and an
  `fsync` before returning the public address.
- A repeated provision for the same agent id reads the existing valid file and
  returns the same public address. It does not replace or rewrite the file.
- A pre-existing invalid file is refused (`Exists`), never repaired or
  overwritten.
- Agent wallets do not use the user-wallet operation journal; the wallet file
  keyed by the agent id is the durable public result. This is an explicit,
  documented exception, not a claim of the same journal format.

## V8 provisioning worker

- The outbox stores only user id, state, attempt count, timestamps, lease,
  worker id, and a static error code.
- The opt-in worker is started only when `AGENTPAY_WALLET_PROVISIONING=1` and
  PostgreSQL is authoritative. It owns a separate database client and runtime.
- `ready` is written only when (a) the worker still owns the lease and (b) a
  public `user_wallets` row exists. A signer call that returns without a
  registry row is not marked ready.
- A missing/corrupt registered wallet becomes terminal `wallet_missing`; the
  worker never mints a replacement.
- The worker's signer adapter is deliberately the existing v1 strict load/mint
  boundary for local execution. Wiring the isolated v2 signer is still a
  deployment decision and is not claimed as complete.

## Gaps kept explicit

- No real Cloudflare Pages/Workers or Neon branch was contacted; only local
  Wrangler/Miniflare and disposable PostgreSQL were used.
- `TxSigner::User` remains absent; no payment or signing path was executed.
- The hash-only session cutover was not enabled; the transitional raw
  `session_id` fallback remains for rows where `session_hash IS NULL`.
- A real signer v2 deployment adapter for the V8 worker, and production
  reconciliation of a crash between recovery file creation and registry
  replacement, require external integration and operator review.
