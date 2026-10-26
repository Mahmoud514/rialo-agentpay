# Execution plan and dependency map — g1152

> G1154 note: see `design/g1154-final-state.md` and
> `design/g1154-api-dependency-matrix.md` for the current implementation.
> This file is retained as historical planning context.

Base: `32c3f4d626e446093e54655450fe8781a810d1b5` (the commit shared by the
reviewed g1142–g1149 worktrees). New execution worktree:
`/home/mahmoud/g1152-agentpay-execution` (detached). No previous worktree is
modified.

## Preservation baseline

The following trees were inspected and left intact:

- `/home/mahmoud/rialo-agentpay` — main working tree
- `g1142-submission-review`
- `g1143-worker-auth-design`
- `g1145-blitz-session-dualread`
- `g1146-wallet-provisioning`
- `g1147-auth-integration-tests`
- `g1148-v8-signer-lock`
- `g1149-signer-idempotency-review`
- `g1150-wallet-file-safety`
- `/home/mahmoud/g81-new-wallets` (real signer source, read-only)
- `/home/mahmoud/g78-user-signer` (read-only; never modified)

The execution tree integrates reviewed pieces by copying source files only,
then rechecking them against the base. It does not use `reset`, `clean`,
`stash`, overwrite, rebase, or a merge of another worktree.

## Dependency order

```
Phase 0  baseline / preservation
   |
   +--> Phase 3  Rust dual-read session contract
   |        |
   +--> Phase 1  static preview + Functions request-scoped config
   |        |
   +--> Phase 2  Worker-owned wallet auth (uses Phase 3 session contract)
   |        |
   +--> Phase 4  signer file lifecycle (g1150)
   |        |
   +--> Phase 5  V8 outbox (requires Phase 4 signer behavior)
   |        |
   +--> Phase 7  disposable-PG migrations + tests
   |        |
   +--> Phase 6  frontend/API dependency matrix (documentation)
   |        |
   +--> Phase 8  full test matrix
   |        |
   +--> Phase 9  local delivery report / diff
```

Phase 7 is run on a disposable embedded PostgreSQL instance. The V8
`PgProvisionStore` adapter is exercised against that instance with a dedicated
runtime; the direct adapter test, concurrent-claim tests, lease/fencing tests,
and state-machine tests are green. This is still PostgreSQL-local evidence, not
a Neon deployment proof.

## Decisions

1. **Delivery base:** 32c3f4d, not the older g81 server tree, because it is the
   shared reviewer-verified base for the Worker-auth/V8 work. The signer crate
   is imported from g1150, and the v1 server wallet lane is adapted to 32c3f4d
   rather than replacing the whole server file.
2. **Static vs Functions:** static output is a standalone directory. A missing
   `BACKEND` is a request-time typed 503 and never a module-load throw, so the
   static site can be previewed without Functions. Worker-owned auth does not
   need `BACKEND` when `AUTH_MODE=worker`.
3. **Session compatibility:** hash-first lookup, raw `session_id` only when
   `session_hash IS NULL`; no hash-only storage switch in this change.
4. **Signer publication:** complete temp + fsync + hard link + directory fsync.
   `rename` is not used because it replaces silently; `hard_link` fails with
   `AlreadyExists` and the existing file is never overwritten.
5. **Provisioning:** V8 remains an outbox/state machine, not an activated route.
   Its signer call is an explicit trait; no private material is stored.
6. **Deployment:** no Cloudflare, Blitz, DNS, secret, migration, or production
   action is performed. Only local build/test commands run.
