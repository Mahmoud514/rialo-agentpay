# g1150 — wallet-file safety design (local, no wiring)

Worktree: `/home/mahmoud/g1150-wallet-file-safety`
Base: g81 `4c2e31aa255b2bae02386bcfbba3c22d6d6a91ff` plus the g81 working-tree
signer/server source copied read-only for review. No real wallet directory,
key, seed, signature, transaction, or production database was used.

## 1. Path map

### v1 app wallet (`src/bin/server.rs`)

| Path | Before | g1150 |
|---|---|---|
| `wallet_file(uid)` (`:511`) | `artifact/wallets/<uid>.json`; `create_dir_all` | same path authority |
| `load_or_create_wallet` (`:531`) | `path.exists()` TOCTOU; `File::create` truncates; no lock | per-user lock; complete temp + fsync + `hard_link`; loser reads winner |
| `load_wallet_strict` (`:460`) | file first; registry row absent after crash was never repaired; `File::create` | same identity checks; absent registry row is registered idempotently from the file; no replacement |
| `strict_wallet_load_or_mint` (`:500`) | PG strict / FS legacy | unchanged dispatch; both underlying paths are safe |
| `user_wallet_lane` (`:424`) | reads registry + pubkey-only file for signing | read-only; no writes |
| `wallet_path_for` (`:1446`) | lazily calls `load_or_create_wallet` | safe writer via the same function |

`wallet_integrity_check` remains fail-closed: a registered wallet whose file is
missing returns `WALLET_FILE_MISSING`; no mint is attempted. `registry_register_user_wallet`
is first-writer-wins and same-pubkey idempotent; a different pubkey is a hard
conflict.

### v2 isolated signer (`tools/agentpay-signer/src`)

| Path | Before | g1150 |
|---|---|---|
| `user_key_path` / `user_record_path` / `user_recovery_path` | `users/<uid>.{key,wallet,recovery}.json` | unchanged |
| `create_user_wallet` | key `create_new` direct (partial final possible); env/record temp+rename (replace); complete replay -> `AlreadyExists` | stable operation id; started/result journal; all three final writes use no-replace publisher |
| `register_user_wallet` | record temp+rename | record no-replace; existing record read/identity checked |
| `user_creation_gate` nonce/progress | temp+rename (mutable markers) | unchanged; operation journal is the wallet-result authority |
| `user_binding_registry` | binding record temp+rename | unchanged (not a wallet/key file) |
| `provision_agent_wallet` key | direct `create_new` (partial final possible) | unchanged; separate agent-wallet risk |
| `fill_reserved_key` | `truncate(true)` on an empty placeholder | unchanged; empty placeholder path only |
| `write_wallet_record` | temp+rename replace | no-replace public record |

## 2. Durable no-replace file protocol

For every final wallet artifact:

```text
create_new(temp, 0600)
  -> write_all
  -> file.sync_all
  -> hard_link(temp, final)       # link(2); EEXIST = existing file wins
  -> fsync(parent directory)
  -> unlink(temp)
```

`rename(2)` is deliberately **not** used for a final path: rename replaces the
destination and cannot prove "existing file was untouched." `hard_link` is
atomic and fails with `EEXIST`; the existing inode is never unlinked,
truncated, chmod'ed, or renamed. If the filesystem cannot hard-link, the call
fails closed rather than falling back to rename.

A crash before `hard_link` leaves only a mode-0600 temp; it is never a wallet.
A crash after `hard_link` leaves a complete final file and at most a temp; the
final is authoritative. The directory fsync makes the link durable on POSIX.
Temp cleanup is best-effort on normal error; orphan cleanup is an operator
maintenance gap (documented in the report).

## 3. Operation journal (v2)

Path: `users/ops/<uid>/started-<hash>.json` and `result-<hash>.json`, where
`hash = blake3("g1150-wallet-operation-v1" || user_id_le || operation_id)`.

- `started` is created **before any key material** and cannot be replaced.
- `result` is created **after the record is durable** and before returning.
- `result` stores only: version, user id, operation hash, public address, and
  the record file's blake3 hash. It never stores a seed, private key, key
  container, recovery draft, or auth key.
- `Completed` reads return the public address without opening the key file.
- `InProgress` without final files is terminal; no mint.
- `Incomplete` (one final file, malformed, or key/record mismatch) is terminal;
  no mint.
- A completed journal with missing/corrupt final files is evidence of a prior
  wallet: terminal, never replaced.
- A complete final pair with a missing result is recovered by writing only the
  result journal; the wallet files are untouched.

Stable operation id: `v2-user-wallet:<uid>` by default, or the explicit
`create_user_wallet_with_operation(..., operation_id)` variant. The id is not a
raw filesystem component.

## 4. Concurrency / recovery

```text
logical request
  -> CreationGate (process singleflight marker)
  -> operation started (create_new)
  -> inspect final pair (Missing only if no evidence)
  -> temp+fsync+hard_link key
  -> temp+fsync+hard_link recovery envelope
  -> temp+fsync+hard_link record
  -> result journal (create_new)
  -> gate.finish
```

- Same-user concurrent requests: one gate/operation winner; the others see
  InProgress or a completed result and never write.
- Crash after started/before key: InProgress; operator only.
- Crash after key/before record: Incomplete; no replacement.
- Crash after record/before result: complete pair; result reconstructed; no
  second wallet.
- Restart: same result/state; no key bytes read for result lookup.
- Lost PostgreSQL for v1: file is kept; next strict call reads it and registers
  the same pubkey; a different pubkey fails closed.
- Old worker: v1 registry first-writer-wins; v2 no-replace final link. Neither
  allows a stale writer to replace a winner.

## 5. Explicit gaps

- v1 has no operation-id journal; its durable public result is the wallet file
  plus the PG pubkey row. A v2-style op journal for v1 is a follow-up.
- v2 signer does not write `user_wallets`; V8 still needs an explicit mapping
  from signer record/result to PG. Not wired here.
- Agent-wallet key creation remains direct `create_new` (partial final possible)
  and `fill_reserved_key` can truncate an **empty** placeholder. Separate
  agent custody review required.
- `hard_link` requires a filesystem that supports it; unsupported filesystems
  fail closed. NFS/object-store semantics are not tested.
- No power-loss/fsync fault injection beyond the test failpoints; no real
  PostgreSQL for the v1 crash-window test.
