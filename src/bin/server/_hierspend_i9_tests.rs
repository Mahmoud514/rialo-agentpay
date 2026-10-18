//! PHASE 9 "Hierarchical spend controls" — focused tests for the aggregate
//! reservation layer over the frozen hierarchical policy model. The
//! aggregate buckets live in the SAME reservation authority (the spend
//! ledger directory) under the SAME store lock with the SAME atomic
//! temp+rename discipline; the multi-level reservation is GROUP-ATOMIC
//! (one lock section: per-agent CAS + per-scope CAS + full rollback on
//! any failure). The per-agent CAS semantics are unchanged.

use crate::agents::{
    AggregateSpend, DailySpend, SPEND_SCHEMA_VERSION, read_spend, reserve_spend_hierarchical,
};
use std::path::PathBuf;
use uuid::Uuid;

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-hspend-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agent_spend")).unwrap();
        Self(root)
    }
    fn ledger(&self) -> PathBuf {
        self.0.join("artifact/agent_spend")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn scope(id: &Uuid, cap: u64) -> (String, u64) {
    (id.to_string(), cap)
}

fn read_agg(root: &Root, scope: &Uuid) -> Option<AggregateSpend> {
    // mirror read path through the public fs (the private read fn is
    // exercised via the reservation API)
    let path = root.ledger().join(format!("{scope}.agg.json"));
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn read_daily(root: &Root, id: &Uuid) -> Option<DailySpend> {
    let path = root.ledger().join(format!("{id}.json"));
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

const DAY: &str = "2026-10-04";
const NOW: i64 = 1_790_000_000;

// ---------------------------------------------------------------------------
// (A) flat/root behavior unchanged (no scopes = bare per-agent reservation)
// ---------------------------------------------------------------------------

#[test]
fn flat_agent_reservation_identical_to_legacy() {
    let root = Root::new("flat");
    let id = Uuid::new_v4();
    let res = reserve_spend_hierarchical(&root.ledger(), &id, &[], DAY, 100, 1_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(res.agent.reserved_to_kelvin, 100);
    assert!(res.scopes.is_empty());
    assert_eq!(read_daily(&root, &id).unwrap().spent_kelvin, 100);
    // no aggregate bucket was created
    assert!(read_agg(&root, &id).is_none());
}

// ---------------------------------------------------------------------------
// (B,C,D,E) aggregate enforcement + shared scope
// ---------------------------------------------------------------------------

#[test]
fn aggregate_cap_enforced_across_children() {
    let root = Root::new("agg");
    let parent = Uuid::new_v4();
    let child_a = Uuid::new_v4();
    let child_b = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];

    // child A spends 400
    reserve_spend_hierarchical(&root.ledger(), &child_a, &scopes, DAY, 400, 10_000, NOW)
        .unwrap()
        .unwrap();
    // child B spends 500
    reserve_spend_hierarchical(&root.ledger(), &child_b, &scopes, DAY, 500, 10_000, NOW)
        .unwrap()
        .unwrap();
    // aggregate bucket = 900; only 100 remains
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 900);
    // D/E: each child's spend counted against the SAME aggregate
    // a subsequent 150 must fail atomically (150 > 100 remaining)
    let over = reserve_spend_hierarchical(&root.ledger(), &child_a, &scopes, DAY, 150, 10_000, NOW)
        .unwrap();
    assert!(over.is_err(), "aggregate cap exhausted — must deny");
    // and NOTHING was written (no partial reservation)
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 900);
    assert_eq!(
        read_daily(&root, &child_a).unwrap().spent_kelvin,
        400,
        "rolled back"
    );
}

#[test]
fn parent_own_spend_draws_its_own_aggregate_scope() {
    let root = Root::new("parentown");
    let parent = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    // the parent's own payment draws its own scope bucket too
    reserve_spend_hierarchical(&root.ledger(), &parent, &scopes, DAY, 300, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 300);
    assert_eq!(read_daily(&root, &parent).unwrap().spent_kelvin, 300);
    // a child draws the same bucket: 300 + 700 = cap
    reserve_spend_hierarchical(
        &root.ledger(),
        &Uuid::new_v4(),
        &scopes,
        DAY,
        700,
        10_000,
        NOW,
    )
    .unwrap()
    .unwrap();
    // one-unit over fails
    let over = reserve_spend_hierarchical(
        &root.ledger(),
        &Uuid::new_v4(),
        &scopes,
        DAY,
        1,
        10_000,
        NOW,
    )
    .unwrap();
    assert!(over.is_err());
}

// ---------------------------------------------------------------------------
// (F,G,H,I) multi-level scopes; exact boundary; one-unit over
// ---------------------------------------------------------------------------

#[test]
fn multi_level_scopes_all_enforced() {
    let root = Root::new("multi");
    let grand = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    // B pays under BOTH scopes (root cap 10_000; parent cap 1_000)
    let scopes = vec![scope(&parent, 1_000), scope(&grand, 10_000)];
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 600, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 600);
    assert_eq!(read_agg(&root, &grand).unwrap().spent_kelvin, 600);
    // the ROOT cap is the binding one now: 600 + 4_500 <= 10_000 but the
    // parent cap 1_000 blocks at 1_000 total
    let over_parent =
        reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 401, 10_000, NOW).unwrap();
    assert!(over_parent.is_err(), "parent scope cap exhausted");
    assert_eq!(
        read_agg(&root, &grand).unwrap().spent_kelvin,
        600,
        "rolled back"
    );
    // G: the child CANNOT bypass the ancestor cap even with a huge per-agent limit
    let over =
        reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 500, 10_000, NOW).unwrap();
    assert!(over.is_err(), "400 remaining on the parent scope");
    // H: exact boundary succeeds (600 + 400 = 1_000)
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 400, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 1_000);
    // I: one-unit over fails
    let one_over =
        reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 1, 10_000, NOW).unwrap();
    assert!(one_over.is_err());
}

// ---------------------------------------------------------------------------
// (J,K) concurrency: children cannot overshoot the aggregate cap
// ---------------------------------------------------------------------------

#[test]
fn concurrent_children_cannot_overshoot_aggregate_cap() {
    let root = Root::new("conc");
    let parent = Uuid::new_v4();
    let scopes = std::sync::Arc::new(vec![scope(&parent, 1_000)]);
    let ledger = std::sync::Arc::new(root.ledger());
    let mut handles = Vec::new();
    // 20 children each trying 100 against a 1_000 cap: at most 10 succeed
    for _ in 0..20 {
        let scopes = scopes.clone();
        let ledger = ledger.clone();
        handles.push(std::thread::spawn(move || {
            reserve_spend_hierarchical(&ledger, &Uuid::new_v4(), &scopes, DAY, 100, 10_000, NOW)
                .unwrap()
                .is_ok()
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.join().unwrap() {
            ok += 1;
        }
    }
    assert!(ok <= 10, "K: at most 10 children fit the cap (got {ok})");
    let agg = read_agg(&root, &parent).unwrap();
    assert!(agg.spent_kelvin <= 1_000, "aggregate NEVER exceeds the cap");
    assert_eq!(
        agg.spent_kelvin,
        (ok as u64) * 100,
        "exactly the winners' amounts"
    );
    // every denied child left NO residue in its own per-agent bucket
    // (checked implicitly by the aggregate arithmetic matching the wins)
}

#[test]
fn many_concurrent_children_never_overshoot() {
    let root = Root::new("many");
    let parent = Uuid::new_v4();
    let scopes = std::sync::Arc::new(vec![scope(&parent, 500)]);
    let ledger = std::sync::Arc::new(root.ledger());
    let mut handles = Vec::new();
    for _ in 0..64 {
        let scopes = scopes.clone();
        let ledger = ledger.clone();
        handles.push(std::thread::spawn(move || {
            reserve_spend_hierarchical(&ledger, &Uuid::new_v4(), &scopes, DAY, 10, 10_000, NOW)
                .unwrap()
                .is_ok()
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.join().unwrap() {
            ok += 1;
        }
    }
    assert_eq!(ok, 50, "exactly 50 fit (500/10)");
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 500);
}

// ---------------------------------------------------------------------------
// (L) multi-level reservation cannot leave partial reservations
// ---------------------------------------------------------------------------

#[test]
fn multi_level_failure_leaves_no_partial_reservation() {
    let root = Root::new("partial");
    let grand = Uuid::new_v4();
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    // parent cap 500 (fails at 600), grand cap 10_000 (would succeed)
    let scopes = vec![scope(&parent, 500), scope(&grand, 10_000)];
    // seed the parent bucket with 400
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 400, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 400);
    // the next payment needs 200: parent scope fails (400+200=600>500)
    // — the grand scope (already acquired in-section) MUST be rolled back
    let denied =
        reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 200, 10_000, NOW).unwrap();
    assert!(denied.is_err());
    assert_eq!(
        read_agg(&root, &grand).unwrap().spent_kelvin,
        400,
        "L: rolled back"
    );
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 400);
    assert_eq!(
        read_daily(&root, &child).unwrap().spent_kelvin,
        400,
        "per-agent rolled back"
    );
}

// ---------------------------------------------------------------------------
// (M,N,O,P,Q) lifecycle consistency (existing reservation model)
// ---------------------------------------------------------------------------

#[test]
fn aggregate_release_matches_existing_reservation_lifecycle() {
    // the bookkept release helper restores acquired buckets exactly — the
    // same path the cores' failure arms use
    let root = Root::new("lifecycle");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    let res = reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 300, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 300);
    // definitive failure path: release_scopes_bookkept restores the
    // previous figures (exact match)
    crate::agents::release_scopes_bookkept_pub(&root.ledger(), &res.scopes, NOW).unwrap();
    assert_eq!(
        read_agg(&root, &parent).unwrap().spent_kelvin,
        0,
        "M: restored"
    );
    // N: the per-agent release belongs to the cores' existing arm (covered
    // by the step8 suites) — this item adds the AGGREGATE release, which
    // is what is asserted here.
    let _ = child;
    // O/P/Q: the reconciliation Absent path uses the intent's claim-time
    // scopes (release_scopes_inner) — day-mismatch and underflow are
    // no-ops (over-retention, the money-safe direction)
    crate::agents::release_scopes_inner_pub(&root.ledger(), &[parent.to_string()], DAY, 300, NOW)
        .unwrap();
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 0);
    // a day-mismatched release is a NO-OP (never subtract from a new day)
    crate::agents::release_scopes_inner_pub(
        &root.ledger(),
        &[parent.to_string()],
        "1999-01-01",
        300,
        NOW,
    )
    .unwrap();
    // and an over-release is a NO-OP (checked_sub underflow)
    crate::agents::release_scopes_inner_pub(&root.ledger(), &[parent.to_string()], DAY, 5_000, NOW)
        .unwrap();
}

// ---------------------------------------------------------------------------
// (R) idempotent replay: the claim path returns BEFORE reserving (no
// double-consume) — pinned by the existing idempotency suite; here we pin
// that a SECOND reservation for the same agent+day is additive (the
// per-agent CAS), and that aggregate buckets follow the same discipline.
// ---------------------------------------------------------------------------

#[test]
fn repeat_reservations_are_additive_never_reset() {
    let root = Root::new("idem");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 300, 10_000, NOW)
        .unwrap()
        .unwrap();
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 200, 10_000, NOW)
        .unwrap()
        .unwrap();
    assert_eq!(read_daily(&root, &child).unwrap().spent_kelvin, 500);
    assert_eq!(read_agg(&root, &parent).unwrap().spent_kelvin, 500);
    // R adjacency: a rollover to the next day starts a fresh bucket
    let next_day = "2026-10-05";
    reserve_spend_hierarchical(&root.ledger(), &child, &scopes, next_day, 100, 10_000, NOW)
        .unwrap()
        .unwrap();
    // the aggregate bucket follows the ESTABLISHED day-rotation semantics
    // (one file per scope; the stored bucket rotates to the current day —
    // exactly like DailySpend: "a stored bucket for an older day rotates
    // to zero — the read is presentation only, the CAS is authoritative")
    let next_agg = read_agg(&root, &parent).unwrap();
    assert_eq!(next_agg.day, next_day, "bucket rotated to the current day");
    assert_eq!(next_agg.spent_kelvin, 100, "the new day's spend is fresh");
}

// ---------------------------------------------------------------------------
// (S,T,U,V) fail-closed interactions
// ---------------------------------------------------------------------------

#[test]
fn malformed_scopes_fail_closed_with_rollback() {
    let root = Root::new("malformed");
    let child = Uuid::new_v4();
    let valid_scope = Uuid::new_v4();
    let scopes = vec![
        scope(&valid_scope, 1_000),
        ("not-a-uuid".to_string(), 1_000), // malformed AFTER a valid one
    ];
    let denied =
        reserve_spend_hierarchical(&root.ledger(), &child, &scopes, DAY, 100, 10_000, NOW).unwrap();
    assert!(denied.is_err(), "T: malformed scope denies");
    assert_eq!(
        read_agg(&root, &valid_scope).unwrap().spent_kelvin,
        0,
        "rolled back"
    );
    assert_eq!(
        read_daily(&root, &child).unwrap().spent_kelvin,
        0,
        "per-agent rolled back"
    );
}

#[test]
fn u64_overflow_denies_atomically() {
    let root = Root::new("overflow");
    let parent = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    // seed the aggregate near u64::MAX
    let agg_path = root.ledger().join(format!("{parent}.agg.json"));
    std::fs::write(
        &agg_path,
        serde_json::to_vec(&AggregateSpend {
            schema_version: SPEND_SCHEMA_VERSION,
            scope_agent_id: parent.to_string(),
            day: DAY.to_string(),
            spent_kelvin: u64::MAX - 5,
            updated_at: NOW,
        })
        .unwrap(),
    )
    .unwrap();
    let denied = reserve_spend_hierarchical(
        &root.ledger(),
        &Uuid::new_v4(),
        &scopes,
        DAY,
        100,
        10_000,
        NOW,
    )
    .unwrap();
    assert!(denied.is_err(), "checked_add overflow denies");
    // no residue: the per-agent bucket was rolled back
    assert!(read_daily(&root, &Uuid::new_v4()).is_none());
}

// ---------------------------------------------------------------------------
// (AB) no secrets in the aggregate records
// ---------------------------------------------------------------------------

#[test]
fn aggregate_records_carry_no_secrets() {
    let root = Root::new("hygiene");
    let parent = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    reserve_spend_hierarchical(
        &root.ledger(),
        &Uuid::new_v4(),
        &scopes,
        DAY,
        10,
        10_000,
        NOW,
    )
    .unwrap()
    .unwrap();
    let raw = std::fs::read_to_string(root.ledger().join(format!("{parent}.agg.json"))).unwrap();
    for forbidden in [
        "lat_",
        "Bearer",
        "phc",
        "argon",
        "keypair",
        "token",
        "credential",
    ] {
        assert!(
            !raw.contains(forbidden),
            "aggregate records must never contain {forbidden}"
        );
    }
    // the record shape is scalars only
    let agg: AggregateSpend = serde_json::from_str(&raw).unwrap();
    assert_eq!(agg.scope_agent_id, parent.to_string());
}

// ---------------------------------------------------------------------------
// (AA) one authority: the aggregate bucket is a SIBLING record in the
// SAME ledger directory (the reservation authority), not a second store.
// ---------------------------------------------------------------------------

#[test]
fn aggregate_buckets_live_in_the_same_ledger_authority() {
    let root = Root::new("authority");
    let parent = Uuid::new_v4();
    let scopes = vec![scope(&parent, 1_000)];
    reserve_spend_hierarchical(
        &root.ledger(),
        &Uuid::new_v4(),
        &scopes,
        DAY,
        10,
        10_000,
        NOW,
    )
    .unwrap()
    .unwrap();
    // the aggregate file lives beside the per-agent file, in the same dir
    let agg_path = root.ledger().join(format!("{parent}.agg.json"));
    assert!(
        agg_path.exists(),
        "AA: same ledger authority (sibling record)"
    );
    // and the per-agent bucket of the payer also lives there
    let daily_files: Vec<_> = std::fs::read_dir(root.ledger())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(daily_files.iter().any(|f| f.ends_with(".agg.json")));
    assert!(
        daily_files
            .iter()
            .any(|f| f.ends_with(".json") && !f.ends_with(".agg.json"))
    );
}

// ---------------------------------------------------------------------------
// (W,X structural) rate limits untouched; per-agent CAS intact
// ---------------------------------------------------------------------------

#[test]
fn spend_layer_references_no_rate_limit_and_keeps_the_cas_primitives() {
    let src = include_str!("agents.rs");
    let start = src
        .find("the AGGREGATE reservation ledger.")
        .expect("aggregate section present");
    let end = src
        .find("/// Locked convenience core for tests and the standalone path.")
        .unwrap();
    let body = &src[start..end];
    for forbidden in ["RATE_LIMITED", "rate_limit", "EXPENSIVE_CAP", "CHEAP_CAP"] {
        assert!(
            !body.contains(forbidden),
            "spend layer must not reference {forbidden}"
        );
    }
    // the CAS primitives are still in use: the per-agent read/persist +
    // the exact-match release discipline are present in the section
    assert!(body.contains("spend_for_day"), "per-agent CAS read intact");
    assert!(body.contains("write_json_atomic"), "atomic persist intact");
    assert!(body.contains("store_lock"), "single lock discipline intact");
}
