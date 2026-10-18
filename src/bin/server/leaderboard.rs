//! PHASE 7 — REAL LEADERBOARD (derived read-only projection).
//!
//! # Sources (authoritative, existing — NO new database)
//!
//! The leaderboard is a PURE PROJECTION of two existing stores:
//!
//!   * `artifact/agents/<uuid>.json` — the agent metadata record (name,
//!     lifecycle status). Read via the SAME fail-closed reader the CRUD
//!     engine uses (`agents::read_agent`).
//!   * `artifact/agent_payment_intents/<uuid>/<hex-key>.json` — the
//!     idempotency/replay ledger (v1 + v2 intents), the SAME canonical
//!     source the Activity Feed projects (see activity.rs). Read through
//!     the SAME authoritative readers (`agents::read_intent` /
//!     `agents::read_intent_v2`) with the SAME version routing.
//!
//! # Hard read-only contract (same discipline as activity.rs)
//!
//! This module opens those stores for READING and nothing else. It never
//! writes, creates, renames, or locks any file; it acquires no locks of
//! its own; it never reserves or releases spend; it never transfers; it
//! never issues or revokes credentials; and it NEVER calls the chain —
//! rendering a leaderboard runs ZERO RPC.
//!
//! **Balance is EXCLUDED on purpose.** The only balance readout in this
//! codebase is a live RPC call with no persisted readout, and the
//! leaderboard rule forbids fabricating a value (a fake zero would be
//! worse than no column). Wallet-balance display is deferred to Part 2
//! with an explicit RPC/latency decision; nothing here touches the chain.
//!
//! # Auth boundary
//!
//! Owner-scoped through the ONE existing session choke point
//! (`crate::session_user`), then the same ownership filter `list_agents`
//! applies: the board contains ONLY the caller's own agents. Other
//! users' agents are silently skipped (never an error, never rendered,
//! never enumerable by path). There is NO public lane and NO new
//! authentication mechanism.
//!
//! # Metric semantics (all derived from canonical persisted states; the
//! six-state vocabulary is shared 1:1 with activity.rs)
//!
//!   * confirmed            = `confirmed` OR `reconciled_paid`. A
//!     reconciliation terminal is a PROVEN execution — the same truth the
//!     spend ledger holds (the reservation stayed consumed).
//!   * confirmed_payment_volume_kelvin = sum of amount_kelvin over
//!     exactly the confirmed records. RLO display value = kelvin / 1e9
//!     (the existing constant-based ratio the whole project uses).
//!   * failed_count         = `failed` OR `reconciled_absent` (proven
//!     NON-execution; the reservation was released; nothing paid).
//!   * pending_count        = `pending` (in flight, never settled).
//!   * unknown_count        = `unknown` (outcome unresolved; reservation
//!     held).
//!   * reconciled_count     = reconciled_paid + reconciled_absent (the
//!     proven-by-reconciliation subset, shown for transparency).
//!   * last_confirmed_at    = max(updated_at) over confirmed records —
//!     the moment the record reached its proven state — else null.
//!   * total_intent_count   = every intent slot parsed for the agent.
//!     The five buckets partition total by construction.
//!
//! # Never rendered (DTO whitelist)
//!
//! Per row ONLY: agent_id, name, status, total_intent_count,
//! confirmed_payment_count, confirmed_payment_volume_kelvin,
//! confirmed_payment_volume_rlo, last_confirmed_at, pending_count,
//! failed_count, unknown_count, reconciled_count. NO owner_user_id, NO
//! wallet_address, NO recipient, NO idempotency key (even hex), NO
//! request fingerprint, NO failure code/message, NO response blob, NO
//! reconciliation evidence, NO credential, NO keypair, NO balance, NO
//! tx signature, NO file path.
//!
//! # Fail-closed rules (identical to activity.rs)
//!
//!   * agents directory missing      -> rendered empty (no agents yet);
//!   * any other agents read error   -> Store (500; never a partial board);
//!   * an agent file that fails `read_agent` (corrupt) -> Store;
//!   * a foreign (non-owned) agent file -> SKIPPED silently (not an
//!     error — it is not this caller's board);
//!   * an intents directory missing  -> zero metrics (no ledger = no
//!     history);
//!   * an intents directory read error -> Store;
//!   * non-.json or non-canonical-hex file -> inert (never metrics);
//!   * an unknown schema_version document -> inert (same as activity);
//!   * a slot failing the authoritative reader (corrupt, identity
//!     mismatch, wrong version) -> Store. A corrupted ledger is NEVER
//!     quietly zeroed — a partial board is a dangerous board.
//!
//! # Deterministic ordering (documented, no random component)
//!
//!   1. confirmed_payment_volume_kelvin DESC
//!   2. last_confirmed_at           DESC (null sorts LAST)
//!   3. confirmed_payment_count     DESC
//!   4. agent_id                    ASC (canonical UUID string — a total
//!      order, the final stable tie-break)
//!
//! With no confirmed payments every row is (0, null, 0) and the board
//! falls back to agent_id ASC — stable and predictable.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::path::Path as FsPath;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Per-agent accumulation of whitelisted metric facts
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Metrics {
    pub total: u64,
    pub pending: u64,
    pub confirmed: u64,
    pub volume_kelvin: u64,
    pub failed: u64,
    pub unknown: u64,
    pub reconciled: u64,
    pub last_confirmed_at: Option<i64>,
}

/// A projection-neutral, fully owned totals row — the shared six-state
/// counters plus the derived confirmed-window + recipient-distinct facts
/// the stats endpoints (and any future aggregate) need. Owned by value so
/// module boundaries never share struct lifetimes.

/// Classify ONE canonical state into exactly one metric bucket. The six
/// states are exhaustive; every branch below is a pure function of the
/// state, so the buckets can never double-count.
pub(crate) fn observe(
    metrics: &mut Metrics,
    state: crate::agents::IntentState,
    kelvin: u64,
    updated_at: i64,
) {
    use crate::agents::IntentState as S;
    metrics.total += 1;
    match state {
        S::Pending => metrics.pending += 1,
        S::Confirmed => {
            metrics.confirmed += 1;
            metrics.volume_kelvin = metrics.volume_kelvin.saturating_add(kelvin);
            bump_last_confirmed(metrics, updated_at);
        }
        S::Failed => metrics.failed += 1,
        S::Unknown => metrics.unknown += 1,
        S::ReconciledPaid => {
            metrics.confirmed += 1;
            metrics.volume_kelvin = metrics.volume_kelvin.saturating_add(kelvin);
            metrics.reconciled += 1;
            bump_last_confirmed(metrics, updated_at);
        }
        S::ReconciledAbsent => {
            metrics.failed += 1;
            metrics.reconciled += 1;
        }
    }
}

fn bump_last_confirmed(metrics: &mut Metrics, updated_at: i64) {
    metrics.last_confirmed_at = Some(match metrics.last_confirmed_at {
        Some(last) => last.max(updated_at),
        None => updated_at,
    });
}

// ---------------------------------------------------------------------------
// Scan cores (read-only; directory-parameterized for tests; the production
// handler passes the canonical artifact roots)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum LeaderboardOutcome {
    /// rows already in final deterministic order
    Rendered(Vec<serde_json::Value>),
    /// typed 500 AGENT_STORE_ERROR — fail closed: never a partial board
    Store,
}

/// One file per agent; owned records only. Foreign owners are SKIPPED
/// (they are not this caller's board — the same silent filter as
/// `list_agents`); anything unreadable or corrupt that IS an agent-shaped
/// file fails closed.
fn read_owned_agents(
    dir: &FsPath,
    user_id: u64,
) -> Result<Vec<crate::agents::Agent>, LeaderboardOutcome> {
    use crate::agents::read_agent;
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(LeaderboardOutcome::Store),
    };
    let mut agents: Vec<crate::agents::Agent> = Vec::new();
    for entry in &entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue; // inert: only <uuid>.json is an agent record
        }
        match read_agent(&path) {
            Ok(agent) if agent.owner_user_id != user_id => continue, // foreign owner
            Ok(agent) => agents.push(agent),
            Err(_) => return Err(LeaderboardOutcome::Store),
        }
    }
    Ok(agents)
}

/// Scan ONE agent's intents directory into `metrics` using the exact
/// v1/v2 routing and fail-closed rules as activity.rs.
fn scan_agent_intents(
    intents_root: &FsPath,
    id: &Uuid,
    m: &mut Metrics,
) -> Result<(), LeaderboardOutcome> {
    use crate::agents::{agent_intents_dir, read_intent, read_intent_v2};
    let dir = agent_intents_dir(intents_root, id);
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(LeaderboardOutcome::Store),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in &entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort(); // deterministic listing regardless of filesystem order

    for stem in names {
        // canonical lowercase even-length hex only — same inert rule
        // as activity.rs
        if stem.is_empty()
            || stem.len() % 2 != 0
            || !stem
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            continue;
        }
        let Some(key) = hex_decode(&stem) else {
            continue;
        };
        // route v1/v2 by the document's own version tag BEFORE any typed
        // reader rejects an unknown version (foreign stays inert, corrupt
        // stays fatal)
        let bytes = match std::fs::read(dir.join(format!("{stem}.json"))) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(LeaderboardOutcome::Store),
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Err(LeaderboardOutcome::Store); // unparseable ledger file
        };
        match value.get("schema_version").and_then(|v| v.as_u64()) {
            Some(1) => {
                let intent = match read_intent(intents_root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return Err(LeaderboardOutcome::Store),
                };
                // v1 states are the canonical vocabulary directly.
                observe(m, intent.state, intent.amount_kelvin, intent.updated_at);
            }
            Some(2) => {
                let intent = match read_intent_v2(intents_root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return Err(LeaderboardOutcome::Store),
                };
                // v2 ExecState mirrors the six-state vocabulary 1:1.
                observe(
                    m,
                    v2_to_canonical(intent.exec_state),
                    intent.amount_kelvin,
                    intent.updated_at,
                );
            }
            _ => continue, // foreign/unknown document: inert, never metrics
        }
    }
    Ok(())
}

/// v2 `ExecState` -> the canonical six-state vocabulary (same order/shape).
pub(crate) fn v2_to_canonical(es: crate::agents::ExecState) -> crate::agents::IntentState {
    use crate::agents::{ExecState, IntentState as S};
    match es {
        ExecState::Pending => S::Pending,
        ExecState::Confirmed => S::Confirmed,
        ExecState::Failed => S::Failed,
        ExecState::Unknown => S::Unknown,
        ExecState::ReconciledPaid => S::ReconciledPaid,
        ExecState::ReconciledAbsent => S::ReconciledAbsent,
    }
}

fn hex_decode(input: &str) -> Option<String> {
    if input.len() % 2 != 0 {
        return None;
    }
    let bytes: Vec<u8> = (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// THE deterministic ordering (see module docs): volume DESC,
/// last_confirmed_at DESC (null last), confirmed DESC, agent_id ASC.
fn sort_rows(rows: &mut Vec<(crate::agents::Agent, Metrics)>) {
    rows.sort_by(|(a, am), (b, bm)| {
        bm.volume_kelvin
            .cmp(&am.volume_kelvin)
            .then_with(|| match (am.last_confirmed_at, bm.last_confirmed_at) {
                (Some(x), Some(y)) => y.cmp(&x),
                (Some(_), None) => std::cmp::Ordering::Less, // b (null) last
                (None, Some(_)) => std::cmp::Ordering::Greater, // b (Some) first
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| bm.confirmed.cmp(&am.confirmed))
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });
}

/// Build the full projection (HTTP-free) so tests can drive it directly
/// with temp dir trees. `user_id` is the authenticated caller.
pub(crate) fn render_leaderboard_in(
    agents_dir_path: &FsPath,
    intents_root: &FsPath,
    user_id: u64,
) -> LeaderboardOutcome {
    use crate::agents::parse_agent_id;

    let agents = match read_owned_agents(agents_dir_path, user_id) {
        Ok(agents) => agents,
        Err(outcome) => return outcome,
    };

    let mut rows: Vec<(crate::agents::Agent, Metrics)> = Vec::with_capacity(agents.len());
    for agent in agents {
        let Some(id) = parse_agent_id(&agent.agent_id) else {
            // an owned record whose id is not canonical is corruption:
            // fail closed, never a partial board.
            return LeaderboardOutcome::Store;
        };
        let mut m = Metrics::default();
        if let Err(outcome) = scan_agent_intents(intents_root, &id, &mut m) {
            return outcome;
        }
        rows.push((agent, m));
    }
    sort_rows(&mut rows);

    LeaderboardOutcome::Rendered(
        rows.iter()
            .map(|(agent, m)| {
                serde_json::json!({
                    "agent_id": agent.agent_id,
                    "name": agent.name,
                    "status": agent_status_name(agent.status),
                    "total_intent_count": m.total,
                    "confirmed_payment_count": m.confirmed,
                    "confirmed_payment_volume_kelvin": m.volume_kelvin,
                    "confirmed_payment_volume_rlo": m.volume_kelvin as f64 / 1_000_000_000.0,
                    "last_confirmed_at": m.last_confirmed_at,
                    "pending_count": m.pending,
                    "failed_count": m.failed,
                    "unknown_count": m.unknown,
                    "reconciled_count": m.reconciled,
                })
            })
            .collect(),
    )
}

/// Map the lifecycle enum to its canonical lowercase public name (the same
/// strings `serde(rename_all="lowercase")` already emits across the API).
fn agent_status_name(status: crate::agents::AgentStatus) -> &'static str {
    use crate::agents::AgentStatus as S;
    match status {
        S::Draft => "draft",
        S::Active => "active",
        S::Paused => "paused",
        S::Disabled => "disabled",
        S::Deleted => "deleted",
    }
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

/// GET /api/agents/leaderboard — owner-scoped read-only projection.
///
/// AUTH: existing session only (`crate::session_user`) + ownership
/// filter. NO public lane. PERFORMANCE: synchronous file scan on the
/// blocking pool; ZERO chain/RPC calls (no balance — see module doc).
pub async fn agent_leaderboard(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = crate::session_user(&state, &headers) else {
        return crate::api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    let (agents_dir_path, intents_root) =
        (crate::agents::agents_dir(), crate::agents::intents_root());
    let user_id = user.id;
    let result = tokio::task::spawn_blocking(move || {
        render_leaderboard_in(&agents_dir_path, &intents_root, user_id)
    })
    .await;
    match result {
        Ok(LeaderboardOutcome::Rendered(rows)) => (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "success": true,
                "agents": rows,
                "total": rows.len(),
                "order": "confirmed_payment_volume_kelvin DESC, last_confirmed_at DESC, confirmed_payment_count DESC, agent_id ASC"
            })),
        )
            .into_response(),
        Ok(LeaderboardOutcome::Store) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Leaderboard could not be read completely; a partial board is never shown",
        ),
        Err(join_err) => crate::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RIALO_ERROR",
            &format!("leaderboard worker failed: {join_err}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the pure projection directly against temp dir trees (same
// discipline as activity.rs's tests — no server, no network, no chain).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::AgentStatus;
    use std::path::PathBuf;
    use std::{fs, sync::atomic::AtomicU64};

    static CTR: AtomicU64 = AtomicU64::new(0);
    fn temp_root() -> PathBuf {
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("agentpay-leaderboard-{}-{n}", std::process::id()));
        fs::create_dir_all(root.join("agents")).unwrap();
        fs::create_dir_all(root.join("agent_payment_intents")).unwrap();
        root
    }
    use std::sync::atomic::Ordering;

    #[derive(Clone)]
    struct Tree {
        root: PathBuf,
    }
    impl Tree {
        // NOTE: accessors return owned PathBufs (never &refs to temporaries).
        fn agents(&self) -> PathBuf {
            self.root.join("agents")
        }
        fn intents(&self) -> PathBuf {
            self.root.join("agent_payment_intents")
        }
        fn write_agent(&self, id: &str, name: &str, owner: u64, status: AgentStatus) {
            // write the SAME shape read_agent requires (canonical record)
            let json = serde_json::json!({
                "schema_version": 1,
                "agent_id": id,
                "owner_user_id": owner,
                "name": name,
                "status": status,
                "wallet_address": null,
                "created_at": 1_700_000_000,
                "updated_at": 1_700_000_000,
            });
            fs::write(
                self.root.join("agents").join(format!("{id}.json")),
                serde_json::to_vec(&json).unwrap(),
            )
            .unwrap();
        }
        fn write_v1(&self, id: &str, key: &str, state: &str, amount: u64, updated: i64) {
            let json = serde_json::json!({
                "schema_version": 1,
                "agent_id": id,
                "idempotency_key": key,
                "request_fingerprint": "00",
                "recipient": "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw",
                "amount_kelvin": amount,
                "state": state,
                "response": null,
                "created_at": 1_700_000_000,
                "updated_at": updated,
            });
            let dir = self.root.join("agent_payment_intents").join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join(format!("{}.json", hex::of(key))),
                serde_json::to_vec(&json).unwrap(),
            )
            .unwrap();
        }
        fn write_v2(&self, id: &str, key: &str, state: &str, amount: u64, updated: i64) {
            let json = serde_json::json!({
                "schema_version": 2,
                "intent_id": "11111111-2222-4333-8444-555555555599",
                "agent_id": id,
                "principal_kind": "agent",
                "recipient": "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw",
                "amount_kelvin": amount,
                "idempotency_key": key,
                "request_fingerprint": "00",
                "authz": { "policy_fingerprint": "00", "authorized_at": 1_700_000_000 },
                "exec_state": state,
                "tx_signature": null,
                "failure": null,
                "response": null,
                "reconciliation": null,
                "created_at": 1_700_000_000,
                "updated_at": updated,
            });
            let dir = self.root.join("agent_payment_intents").join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join(format!("{}.json", hex::of(key))),
                serde_json::to_vec(&json).unwrap(),
            )
            .unwrap();
        }
    }
    mod hex {
        pub fn of(key: &str) -> String {
            const TABLE: &[u8; 16] = b"0123456789abcdef";
            let mut out = String::with_capacity(key.len() * 2);
            for b in key.as_bytes() {
                out.push(TABLE[(b >> 4) as usize] as char);
                out.push(TABLE[(b & 0x0f) as usize] as char);
            }
            out
        }
    }

    const OWN: &str = "11111111-1111-4111-8111-111111111111";
    const OWN2: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";
    const USER: u64 = 1001;
    const OTHER_USER: u64 = 9999;

    fn render(t: &Tree, user: u64) -> LeaderboardOutcome {
        render_leaderboard_in(&t.agents(), &t.intents(), user)
    }
    fn rows_of(t: &Tree, user: u64) -> Vec<serde_json::Value> {
        match render(t, user) {
            LeaderboardOutcome::Rendered(rows) => rows,
            LeaderboardOutcome::Store => panic!("store error"),
        }
    }

    #[test]
    fn empty_agents_dir_renders_empty_board() {
        let t = Tree { root: temp_root() };
        let rows = rows_of(&t, USER);
        assert!(rows.is_empty());
    }

    #[test]
    fn owner_scoping_excludes_foreign_agents_and_is_not_an_error() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "Mine", USER, AgentStatus::Active);
        t.write_agent(OTHER, "Theirs", OTHER_USER, AgentStatus::Active);
        let rows = rows_of(&t, USER);
        assert_eq!(rows.len(), 1, "only the caller's own agent");
        assert_eq!(rows[0]["agent_id"], OWN);
        // and the OTHER user sees THEIR board
        let rows_other = rows_of(&t, OTHER_USER);
        assert_eq!(rows_other.len(), 1);
        assert_eq!(rows_other[0]["agent_id"], OTHER);
    }

    #[test]
    fn confirmed_bucket_counts_confirmed_and_reconciled_paid_and_sums_volume() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_v1(OWN, "k-c1", "confirmed", 1_000_000_000, 100);
        t.write_v1(OWN, "k-rp", "reconciled_paid", 2_000_000_000, 200);
        t.write_v1(OWN, "k-rn", "reconciled_absent", 5_000_000_000, 300);
        t.write_v1(OWN, "k-f", "failed", 999, 400);
        t.write_v1(OWN, "k-u", "unknown", 998, 500);
        t.write_v1(OWN, "k-p", "pending", 997, 600);
        let rows = rows_of(&t, USER);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r["total_intent_count"], 6);
        assert_eq!(
            r["confirmed_payment_count"], 2,
            "confirmed + reconciled_paid"
        );
        assert_eq!(r["confirmed_payment_volume_kelvin"], 3_000_000_000u64);
        assert_eq!(r["confirmed_payment_volume_rlo"], 3.0);
        assert_eq!(r["last_confirmed_at"], 200, "max updated_at over confirmed");
        assert_eq!(r["reconciled_count"], 2, "paid + absent");
        assert_eq!(r["failed_count"], 2, "failed + reconciled_absent");
        assert_eq!(r["unknown_count"], 1);
        assert_eq!(r["pending_count"], 1);
        // partition check
        assert_eq!(
            r["confirmed_payment_count"].as_u64().unwrap()
                + r["failed_count"].as_u64().unwrap()
                + r["unknown_count"].as_u64().unwrap()
                + r["pending_count"].as_u64().unwrap(),
            r["total_intent_count"].as_u64().unwrap()
        );
    }

    #[test]
    fn v2_slots_fold_with_the_same_semantics() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_v2(OWN, "v2-c", "confirmed", 4_000_000_000, 111);
        t.write_v2(OWN, "v2-pa", "reconciled_paid", 1_000_000_000, 222);
        t.write_v2(OWN, "v2-f", "failed", 777, 333);
        let rows = rows_of(&t, USER);
        let r = &rows[0];
        assert_eq!(r["total_intent_count"], 3);
        assert_eq!(r["confirmed_payment_count"], 2);
        assert_eq!(r["confirmed_payment_volume_kelvin"], 5_000_000_000u64);
        assert_eq!(r["failed_count"], 1);
        assert_eq!(r["reconciled_count"], 1);
        assert_eq!(r["last_confirmed_at"], 222);
    }

    #[test]
    fn volume_order_with_null_last_confirmed_then_agent_id() {
        let t = Tree { root: temp_root() };
        // B has a confirmed payment (5 RLO), A has none.
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_agent(OWN2, "B", USER, AgentStatus::Active);
        t.write_v1(OWN2, "k-b", "confirmed", 5_000_000_000, 100);
        let rows = rows_of(&t, USER);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["agent_id"], OWN2, "higher volume first");
        assert_eq!(rows[1]["agent_id"], OWN, "no volume sorts last");
        assert!(rows[1]["last_confirmed_at"].is_null());
    }

    #[test]
    fn equal_volume_ties_break_by_last_confirmed_then_agent_id_asc() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_agent(OWN2, "B", USER, AgentStatus::Active);
        // both 2 RLO confirmed; B confirmed LATER (higher updated_at)
        t.write_v1(OWN, "k-a", "confirmed", 2_000_000_000, 100);
        t.write_v1(OWN2, "k-b", "confirmed", 2_000_000_000, 900);
        let rows = rows_of(&t, USER);
        assert_eq!(rows[0]["agent_id"], OWN2, "later last_confirmed_at first");

        // now make them equal in time too -> agent_id ASC
        let t2 = Tree { root: temp_root() };
        t2.write_agent(OWN, "A", USER, AgentStatus::Active);
        t2.write_agent(OWN2, "B", USER, AgentStatus::Active);
        t2.write_v1(OWN, "k-a", "confirmed", 2_000_000_000, 500);
        t2.write_v1(OWN2, "k-b", "confirmed", 2_000_000_000, 500);
        let rows2 = rows_of(&t2, USER);
        assert_eq!(rows2[0]["agent_id"], OWN, "id ASC is the final tie-break");
        assert_eq!(rows2[1]["agent_id"], OWN2);
    }

    #[test]
    fn same_volume_and_time_different_confirmed_counts_order_by_confirmed_desc() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_agent(OWN2, "B", USER, AgentStatus::Active);
        // A: 1 confirmed @200 (2 RLO); B: 2 confirmed @100+200 (1+1 RLO)
        // volumes equal (2 == 2)? No — volumes differ; craft equal volumes:
        t.write_v1(OWN, "k-a1", "confirmed", 2_000_000_000, 200);
        t.write_v1(OWN2, "k-b1", "confirmed", 1_000_000_000, 200);
        t.write_v1(OWN2, "k-b2", "confirmed", 1_000_000_000, 200);
        let rows = rows_of(&t, USER);
        // volumes both 2 RLO; last_confirmed both 200; confirmed A=1 B=2
        assert_eq!(rows[0]["agent_id"], OWN2, "more confirmed payments first");
        assert_eq!(rows[1]["agent_id"], OWN);
    }

    #[test]
    fn identity_mismatched_slot_fails_closed() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        // a slot whose record claims ANOTHER agent's identity: the
        // authoritative reader rejects (identity mismatch) -> Store
        let json = serde_json::json!({
            "schema_version": 1,
            "agent_id": OTHER,
            "idempotency_key": "k-fk",
            "request_fingerprint": "00",
            "recipient": "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw",
            "amount_kelvin": 1,
            "state": "confirmed",
            "response": null,
            "created_at": 1,
            "updated_at": 1,
        });
        let dir = t.root.join("agent_payment_intents").join(OWN);
        fs::create_dir_all(&dir).unwrap();
        let hex: String = "k-fk"
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fs::write(
            dir.join(format!("{hex}.json")),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();
        assert!(
            matches!(render(&t, USER), LeaderboardOutcome::Store),
            "an identity-mismatched slot is corruption, not a row"
        );
    }

    #[test]
    fn corrupt_intent_file_fails_closed() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        let dir = t.root.join("agent_payment_intents").join(OWN);
        fs::create_dir_all(&dir).unwrap();
        let hex: String = "k-bad"
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fs::write(dir.join(format!("{hex}.json")), b"not json").unwrap();
        assert!(
            matches!(render(&t, USER), LeaderboardOutcome::Store),
            "a corrupted ledger is never quietly zeroed"
        );
    }

    #[test]
    fn reconciled_terminals_are_never_corrupted_or_recounted() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        // a record already at a reconciled terminal with full evidence
        t.write_v1(OWN, "k-ok", "reconciled_paid", 1_000_000_000, 42);
        // the projection only READS the state; evidence internals are
        // written in a REAL record only by the reconciler, but even if a
        // record carried them they must never be RENDERED:
        let rows = rows_of(&t, USER);
        let blob = serde_json::to_string(&rows).unwrap();
        assert!(
            !blob.contains("reconciliation")
                && !blob.contains("evidence")
                && !blob.contains("method"),
            "reconciliation internals never rendered"
        );
        assert_eq!(rows[0]["reconciled_count"], 1);
    }

    #[test]
    fn non_hex_and_non_json_files_are_inert_not_errors() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_v1(OWN, "k-p", "pending", 500, 10);
        let dir = t.root.join("agent_payment_intents").join(OWN);
        fs::write(dir.join("README.txt"), b"inert note").unwrap();
        fs::write(dir.join("UPPER.json"), b"{}").unwrap(); // not lowercase hex
        fs::write(
            dir.join(format!("{}9999.json", hex::of("k-zz"))),
            b"{\"schema_version\": 99}",
        )
        .unwrap(); // hex-named but unknown version -> inert
        // all inert: only k-p is counted
        let rows = rows_of(&t, USER);
        assert_eq!(rows[0]["total_intent_count"], 1);
    }

    #[test]
    fn missing_agent_intents_dir_is_zero_metrics_not_an_error() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        let rows = rows_of(&t, USER);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_intent_count"], 0);
        assert_eq!(rows[0]["confirmed_payment_count"], 0);
        assert!(rows[0]["last_confirmed_at"].is_null());
    }

    #[test]
    fn no_private_fields_are_rendered() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        t.write_v1(OWN, "k-x", "confirmed", 1_000_000_000, 10);
        let rows = rows_of(&t, USER);
        let blob = serde_json::to_string(&rows).unwrap();
        for secret in [
            "owner_user_id",
            "wallet_address",
            "wallet",
            "recipient",
            "idempotency_key",
            "request_fingerprint",
            "response",
            "policy_fingerprint",
            "token",
            "keypair",
            "balance",
            "path",
            "tx_signature",
        ] {
            assert!(!blob.contains(secret), "must never render: {secret}");
        }
        for key in [
            "agent_id",
            "name",
            "status",
            "total_intent_count",
            "confirmed_payment_count",
            "confirmed_payment_volume_kelvin",
            "confirmed_payment_volume_rlo",
            "last_confirmed_at",
            "pending_count",
            "failed_count",
            "unknown_count",
            "reconciled_count",
        ] {
            assert!(
                rows[0].as_object().unwrap().contains_key(key),
                "whitelisted key missing: {key}"
            );
        }
    }

    #[test]
    fn corrupt_owned_agent_file_fails_closed() {
        let t = Tree { root: temp_root() };
        t.write_agent(OWN, "A", USER, AgentStatus::Active);
        fs::write(
            t.root.join("agents").join(format!("{OWN2}.json")),
            b"{not an agent",
        )
        .unwrap();
        assert!(
            matches!(render(&t, USER), LeaderboardOutcome::Store),
            "a corrupt agent record is never dropped silently"
        );
    }

    // ---- structural proof: the production section is read-only and
    //      money/credential/lifecycle/RPC-free ------------------------------
    // Scans only the section before #[cfg(test)] (the fixtures below
    // legitimately contain the forbidden literals) with comment lines
    // stripped so prose about the boundaries never trips the token scan.
    #[test]
    fn structural_leaderboard_module_is_read_only_and_money_free() {
        let src = include_str!("leaderboard.rs");
        let production = src.split("#[cfg(test)]").next().unwrap();
        let stripped: String = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("///") || t.starts_with("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        // no artifact writes, money motion, spend reservation, intent
        // mutation, credential/policy/lifecycle ops, keypair access, or
        // chain/RPC reads — the leaderboard must be able to do NONE of it.
        for forbidden in [
            "fs::write",
            "File::create",
            "create_dir",
            "rename(",
            "remove_",
            "set_permissions",
            "OpenOptions",
            "store_lock",
            "payment_lock",
            "reserve_spend",
            "release_spend",
            "claim_intent",
            "update_intent",
            "reconcile_intent",
            "ops.transfer",
            ".transfer(",
            "ops.balance",
            ".balance(",
            "airdrop",
            "faucet",
            "issue_credential",
            "revoke_credential",
            "rotate_credential",
            "set_status",
            "update_policy",
            "keypair",
            "wallet_path_for",
            "load_or_create_wallet",
            "agent_wallets",
            "wallets",
            "PHC",
            "argon",
            "reqwest",
            "RialoConfig",
            "rpc_read",
            "transaction_lookup",
            "signatures_for_address",
            "offset",
            "balance",
        ] {
            assert!(
                !stripped.contains(forbidden),
                "leaderboard production code references forbidden token: {forbidden}"
            );
        }
        // the authoritative fail-closed readers, the owner session choke
        // point, and the typed envelope codes are the only touch points.
        for required in [
            "read_agent(",
            "read_intent(",
            "read_intent_v2(",
            "parse_agent_id(",
            "session_user(",
            "agents_dir()",
            "intents_root()",
            "agent_intents_dir(",
            "NOT_AUTHENTICATED",
            "AGENT_STORE_ERROR",
        ] {
            assert!(
                stripped.contains(required),
                "leaderboard production code must use {required}"
            );
        }
    }
}
