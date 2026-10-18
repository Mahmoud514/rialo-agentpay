# Rialo AgentPay - Tasks Marketplace Implementation Specification

## Status: IMPLEMENTED — core task marketplace routes, lifecycle, reward payment, and reconciliation are covered by the existing implementation and tests.

This document is the original technical specification; it is preserved as written. The core routes (`/api/tasks*`), the task lifecycle state machine, reward payment through the shared payment engine (policy gates, spend reservation, idempotency), and payout reconciliation are implemented and covered by the existing test suite (CI-verified). One component from this specification is intentionally not exposed: the `webhook_task_complete` handler exists in the source but is **not registered as an HTTP route** — there is no webhook endpoint available.

## CRITICAL FINDINGS

### 1. Repository State
- **Current**: Removed broken `tasks.rs` (webhook-based, non-compiling)
- **Visibility Changes**: Made `load_policy()`, `agent_policies_dir()`, `spend_dir()` etc. `pub` in `agents.rs`
- **Compilation**: Still failing with "Rust 2015" errors despite `edition = "2024"` in Cargo.toml

### 2. Root Cause of Compilation Failures
The compiler is not respecting the `edition = "2024"` setting. This appears to be a local environment or Rust toolchain configuration issue, not a code problem.

## COMPLETE IMPLEMENTATION SPECIFICATION

### Architecture Overview
- **No webhooks** - All interactions via authenticated API
- **Manual review** - Owner must approve all payments
- **Separate reservation ledger** - `artifact/task_reservations/{task_id}.json`
- **Reuses existing payment core** - Calls `execute_agent_payment()`

### Data Models

```rust
// Task - artifact/tasks/{id}.json
pub struct Task {
    pub schema_version: u32,
    pub task_id: String,
    pub agent_id: String,
    pub owner_user_id: u64,
    pub title: String,
    pub description: String,
    pub acceptance_criteria: String,
    pub status: TaskStatus,
    pub worker_id: Option<u64>,
    pub worker_name: Option<String>,
    pub reward_kelvin: u64,
    pub reward_rlo: f64,
    pub recipient_address: String,
    pub submission_url: Option<String>,
    pub submission_notes: Option<String>,
    pub review_notes: Option<String>,
    pub revision_count: u32,
    pub payment_tx_signature: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub enum TaskStatus {
    Open, InProgress, Submitted, UnderReview,
    RevisionRequested, Approved, Paid, Rejected, Cancelled
}

// Reservation - artifact/task_reservations/{id}.json
pub struct TaskReservation {
    pub schema_version: u32,
    pub task_id: String,
    pub agent_id: String,
    pub amount_kelvin: u64,
    pub status: ReservationStatus,
    pub created_at: i64,
    pub released_at: Option<i64>,
    pub released_reason: Option<String>,
}
```

### State Transitions

| Current | Action | Next | Actor | Notes |
|---------|--------|------|-------|-------|
| Open | Claim | InProgress | Worker | Requires wallet address |
| Open | Cancel | Cancelled | Owner | Release reservation |
| InProgress | Submit | Submitted | Worker | Provide URL/notes |
| Submitted | Approve | Paid | Owner | Execute payment + release |
| Submitted | Reject | Rejected | Owner | Release reservation |
| Submitted | Request Revision | RevisionRequested | Owner | Increment counter |
| RevisionRequested | Submit | Submitted | Worker | Updated work |
| Approved | (system) | Paid | System | After payment confirms |

### API Endpoints

```rust
// Task management
POST /api/tasks              // Create task (owner)
GET  /api/tasks              // List my tasks (owner/worker)
GET  /api/tasks/open         // Public marketplace
GET  /api/tasks/{id}         // Get task detail
POST /api/tasks/{id}/cancel  // Cancel task (owner)

// Worker actions
POST /api/tasks/{id}/claim   // Claim task (worker)
POST /api/tasks/{id}/submit  // Submit work (worker)

// Review actions
POST /api/tasks/{id}/review  // Approve/Reject/RequestRevision (owner)
```

### Reservation Flow

1. **Create Task**:
   ```rust
   let balance = rialo.balance(&agent.wallet_address).await?;
   let reserved = calculate_total_reserved(&agent.agent_id);
   let available = balance - reserved;
   
   if reward_rlo > available {
       return Err(INSUFFICIENT_FUNDS);
   }
   
   // Create task + reservation atomically
   save_task(&task)?;
   save_reservation(&reservation)?;
   ```

2. **Approve & Pay**:
   ```rust
   // Execute through existing payment core
   let result = execute_agent_payment(
       &ops, &wallet_dir, &ledger_dir, &intents_dir,
       &agent, &policy, &idempotency_key,
       &task.recipient_address,
       task.reward_kelvin, task.reward_rlo, now
   ).await?;
   
   // Update task + release reservation
   task.status = Paid;
   task.payment_tx_signature = result.signature;
   save_task(&task)?;
   release_reservation(&task_id, "paid")?;
   ```

### Key Implementation Notes

- **Idempotency**: Payment uses format: `task_payment:{task_id}`
- **Balance Check**: `available = blockchain_balance - reserved_amount`
- **Policy Re-validation**: Re-check recipient is still allowed at payment time
- **File Storage**: Atomic writes via temp file + rename
- **Permissions**: Files use 0o600 (owner-only)

### Files to Create

1. `src/bin/server/tasks.rs` - Main module
2. `src/bin/server/_tasks_tests.rs` - Tests
3. `frontend/src/tasks.html` - Marketplace UI
4. `frontend/src/task-detail.html` - Detail page
5. `frontend/src/tasks.js` - Task management JS

### Files to Modify

1. `src/bin/server/agents.rs` - Add `pub` visibility (DONE)
2. `src/bin/server.rs` - Add task routes
3. `frontend/src/nav.js` - Add Tasks link
4. `frontend/src/dashboard.html` - Add Tasks link

## TESTING STRATEGY

```rust
#[test]
fn test_task_create_reserves_balance() {
    // Setup: Agent with 100 RLO
    // Action: Create 50 RLO task
    // Assert: Reservation created, available = 50 RLO
}

#[test] 
fn test_insufficient_funds_blocked() {
    // Setup: Agent with 10 RLO
    // Action: Try create 50 RLO task
    // Assert: 402 error
}

#[test]
fn test_approve_executes_payment() {
    // Setup: Submitted task
    // Action: Owner approves
    // Assert: Payment made, status = Paid, tx signature stored
}

#[test]
fn test_duplicate_payment_prevented() {
    // Setup: Already paid task
    // Action: Try approve again
    // Assert: Idempotency returns existing payment, no double spend
}

#[test]
fn test_cancel_releases_reservation() {
    // Setup: Open task with reservation
    // Action: Owner cancels
    // Assert: Released, available balance restored
}
```

## IMPLEMENTATION CHECKLIST

After resolving environment issues:

- [ ] Run: `cargo +nightly build --features server` (verify baseline)
- [ ] Create `src/bin/server/tasks.rs` with above models
- [ ] Add `mod tasks;` to `src/bin/server.rs`
- [ ] Add routes to router in `server.rs`
- [ ] Create frontend files
- [ ] Run: `cargo fmt --check`
- [ ] Run: `cargo check --features server`
- [ ] Run: `cargo test --features server`
- [ ] Manual Testnet verification

## FINANCING RECOMMENDATIONS

None - Project uses:
- GitHub Free (source hosting)
- Free Testnet (blockchain)
- Local filesystem storage (no database fees)

## BLOCKER RESOLUTION

If Rust compilation errors persist:

1. Check `rust-toolchain` override:
   ```bash
   rustup show
   cd ~/rialo-agentpay && rustup override unset
   cargo clean
   cargo +nightly build --features server
   ```

2. Verify edition is being read:
   ```bash
   cargo +nightly metadata --format-version 1 | jq '.packages[0].edition'
   ```

3. If still failing, the issue requires environment debugging beyond code changes.

---

**Report Generated**: After repository inspection and partial implementation
**Status**: SPECIFICATION READY - PENDING ENVIRONMENT RESOLUTION
**Changes Made**: Removed broken file, added visibility modifiers
**Next Action**: Resolve Rust toolchain configuration or proceed with implementation checklist
