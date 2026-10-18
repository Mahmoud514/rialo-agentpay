//! PHASE 9 "Crash recovery" (TM-AV-02) — focused tests for the
//! stale-intent sweep. All stores are fresh std::env::temp_dir() subtrees
//! entered via the established CWD-lock pattern; the real artifact/ tree
//! is never opened. The sweep is pure and bounded: it reuses the existing
//! reconciliation engine only, never transfers, and is idempotent.
//!
//! NOTE on record versions: the reconciliation engine's facts reader
//! (IntentFacts::of) is frozen production code — V1 intent records never
//! carried a persisted tx signature, so the known-signature lane only
//! exists for schema-2 (V2) records. V1 stale intents therefore recover
//! exclusively through the read-only scan lane, whose findings stay
//! PROPOSALS (never silently committed) — exactly the engine's own
//! over-retention-safe rule.

use crate::agents::{
    AGENT_PENDING_STALE_AFTER_SECONDS, Agent, AgentStatus, IntentState, PaymentOps,
    ReconcilePrincipal, ReconcileRequest, RialoError, SweepReport, TxLookup, stale_intent_keys,
    sweep_agent_intents,
};
use crate::rialo::RialoConfig;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const OWNER_ID: u64 = 50506084;
const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const AGENT_WALLET: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

// ---------------------------------------------------------------------------
// fixture: one temp root per test, chdir'd under the shared CWD lock
// ---------------------------------------------------------------------------

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    // Share the ESTABLISHED process-wide CWD lock (the same one the stats
    // shards use) so chdir windows never overlap across shards — the
    // documented parallel-flake class otherwise. PHASE 9 UNIFICATION: the
    // shared static is now a std::sync::Mutex so the sync tasks battery's
    // isolated_cwd() serializes on the SAME lock object.
    &crate::stats::tests24::tests24::CWD_LOCK
}

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-sweep-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agent_payment_intents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_spend")).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.clone()
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn agent_record(id: &Uuid) -> Agent {
    Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: OWNER_ID,
        name: "sweep-agent".to_string(),
        status: AgentStatus::Active,
        wallet_address: Some(AGENT_WALLET.to_string()),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
        auth_public_key: None,
    }
}

fn hex_key(key: &str) -> String {
    key.bytes().map(|b| format!("{b:02x}")).collect()
}

fn v1_intent(id: &Uuid, key: &str, state: &str, updated_at: i64) -> String {
    format!(
        r#"{{"schema_version":1,"agent_id":"{id}","idempotency_key":"{key}","request_fingerprint":"fp-{key}","recipient":"{RECIPIENT}","amount_kelvin":1000000,"state":"{state}","response":null,"failure":null,"reconciliation":null,"created_at":1700000000,"updated_at":{updated_at}}}"#
    )
}

fn v2_intent(
    id: &Uuid,
    key: &str,
    state: &str,
    updated_at: i64,
    signature: Option<&str>,
) -> String {
    let sig_json = match signature {
        Some(sig) => format!("\"{sig}\""),
        None => "null".to_string(),
    };
    format!(
        r#"{{"schema_version":2,"intent_id":"int-{key}","agent_id":"{id}","principal_kind":"agent","recipient":"{RECIPIENT}","amount_kelvin":1000000,"idempotency_key":"{key}","request_fingerprint":"fp-{key}","authz":{{"policy_fingerprint":"pfp","authorized_at":1700000000}},"exec_state":"{state}","tx_signature":{sig_json},"failure":null,"response":null,"signer":null,"reconciliation":null,"created_at":1700000000,"updated_at":{updated_at}}}"#
    )
}

fn write_intent(root: &Root, id: &Uuid, key: &str, body: &str) {
    let dir = root
        .path()
        .join("artifact/agent_payment_intents")
        .join(id.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.json", hex_key(key))), body).unwrap();
}

fn read_intent(root: &Root, id: &Uuid, key: &str) -> String {
    std::fs::read_to_string(
        root.path()
            .join("artifact/agent_payment_intents")
            .join(id.to_string())
            .join(format!("{}.json", hex_key(key))),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// the read-only mock ops (only read_tx + signatures_for_address are used)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockReads {
    lookups: Mutex<Vec<(String, TxLookup)>>,
    scans: Mutex<Vec<(String, Vec<crate::agents::SignatureInfoRecord>)>>,
}

impl MockReads {
    fn set_lookup(&self, sig: &str, lookup: TxLookup) {
        self.lookups.lock().unwrap().push((sig.to_string(), lookup));
    }
    fn set_scan(&self, wallet: &str, entries: Vec<crate::agents::SignatureInfoRecord>) {
        self.scans
            .lock()
            .unwrap()
            .push((wallet.to_string(), entries));
    }
}

impl PaymentOps for MockReads {
    fn balance(&self, _address: &str) -> Result<f64, RialoError> {
        Err(RialoError {
            code: "RIALO_RPC_UNAVAILABLE",
            detail: "not used".to_string(),
            tx_signature: None,
        })
    }
    fn transfer(
        &self,
        _keypair_path: &std::path::Path,
        _to: &str,
        _amount_rlo: &str,
    ) -> Result<String, RialoError> {
        panic!("THE SWEEP MUST NEVER TRANSFER");
    }
    fn read_tx(&self, signature: &str) -> TxLookup {
        self.lookups
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(s, _)| s == signature)
            .map(|(_, l)| l.clone())
            .unwrap_or(TxLookup::NotFound)
    }
    fn signatures_for_address(
        &self,
        address: &str,
        _before: Option<&str>,
        _limit: u64,
    ) -> Result<Vec<crate::agents::SignatureInfoRecord>, RialoError> {
        Ok(self
            .scans
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(a, _)| a == address)
            .map(|(_, v)| v.clone())
            .unwrap_or_default())
    }
}

fn mock() -> Arc<MockReads> {
    Arc::new(MockReads::default())
}

fn sig_record(sig: &str) -> crate::agents::SignatureInfoRecord {
    crate::agents::SignatureInfoRecord {
        signature: sig.to_string(),
        block_height: Some(100),
        block_time: Some(1_700_000_050),
        err: None,
    }
}

fn found_tx(sig: &str) -> TxLookup {
    TxLookup::Found(crate::rialo::TxRecord {
        signature: Some(sig.to_string()),
        executed: true,
        err: None,
        slot: Some(101),
        block_height: Some(101),
        block_time: Some(1_700_000_060),
        fee: Some(5000),
        payer: Some(AGENT_WALLET.to_string()),
        transfer_recipient: Some(RECIPIENT.to_string()),
        transfer_amount_kelvin: Some(1_000_000),
        complete: true,
    })
}

// ---------------------------------------------------------------------------
// (1) enumeration: stale selection and untouched fresh/terminal records
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stale_pending_and_unknown_selected_fresh_and_terminal_untouched() {
    let root = Root::new("enum");
    let id = Uuid::new_v4();
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let fresh_at = now - 10;
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "stale-pending",
            &v1_intent(&id, "stale-pending", "pending", stale_at),
        );
        write_intent(
            &root,
            &id,
            "stale-unknown",
            &v1_intent(&id, "stale-unknown", "unknown", stale_at),
        );
        write_intent(
            &root,
            &id,
            "fresh-unknown",
            &v1_intent(&id, "fresh-unknown", "unknown", fresh_at),
        );
        write_intent(
            &root,
            &id,
            "terminal",
            &v1_intent(&id, "terminal", "reconciled_paid", stale_at),
        );
        write_intent(
            &root,
            &id,
            "confirmed",
            &v1_intent(&id, "confirmed", "confirmed", stale_at),
        );
        write_intent(
            &root,
            &id,
            "failed",
            &v1_intent(&id, "failed", "failed", stale_at),
        );

        let keys = stale_intent_keys(
            &crate::agents::intents_root(),
            &id,
            now,
            AGENT_PENDING_STALE_AFTER_SECONDS,
        )
        .unwrap();
        let keys: Vec<&str> = keys.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["stale-pending", "stale-unknown"],
            "exactly the stale Pending/Unknown set"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// (2) V2 known-signature recovery: stale Unknown/Pending reconcile through
// the EXISTING engine (the only lane that can commit, evidence-based)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sweep_reconciles_stale_unknown_with_signature_and_touches_nothing_else() {
    let root = Root::new("recon");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIG1", found_tx("SIG1"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "k1",
            &v2_intent(&id, "k1", "unknown", stale_at, Some("SIG1")),
        );
        write_intent(
            &root,
            &id,
            "fresh",
            &v2_intent(&id, "fresh", "unknown", now - 10, Some("SIG2")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.examined, 1);
        assert_eq!(report.stale, 1);
        assert_eq!(report.reconciled, 1);
        assert_eq!(report.entries[0].pre_state, "unknown");
        assert_eq!(report.entries[0].outcome, "reconciled");
        // the intent record flipped to a Reconciled terminal through the
        // existing engine (evidence-based, one commit)
        let stored = read_intent(&root, &id, "k1");
        assert!(stored.contains("\"reconciled_paid\""), "{stored}");
        assert!(stored.contains("\"tx_lookup\""));
        // fresh record untouched
        let fresh = read_intent(&root, &id, "fresh");
        assert!(
            fresh.contains("\"unknown\""),
            "fresh record must stay Unknown"
        );
    })
    .await;
}

#[tokio::test]
async fn stale_pending_is_normalized_to_unknown_then_reconciled() {
    let root = Root::new("pending");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGP", found_tx("SIGP"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kp",
            &v2_intent(&id, "kp", "pending", stale_at, Some("SIGP")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.stale, 1);
        assert_eq!(report.entries[0].pre_state, "pending");
        assert_eq!(
            report.reconciled, 1,
            "crash-recovered Pending resolves via the engine"
        );
        let stored = read_intent(&root, &id, "kp");
        assert!(stored.contains("\"reconciled_paid\""), "{stored}");
    })
    .await;
}

#[tokio::test]
async fn insufficient_evidence_stays_unknown_and_is_reported() {
    let root = Root::new("noev");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    // signature known but node answers transiently: NO terminal decision
    ops.set_lookup(
        "SIGU",
        TxLookup::Unavailable(RialoError {
            code: "RIALO_RPC_UNAVAILABLE",
            detail: "down".to_string(),
            tx_signature: None,
        }),
    );
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "ku",
            &v2_intent(&id, "ku", "unknown", stale_at, Some("SIGU")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.unresolved, 1);
        assert_eq!(report.reconciled, 0);
        assert_eq!(
            report.entries[0].code.as_deref(),
            Some("RIALO_RPC_UNAVAILABLE")
        );
        let stored = read_intent(&root, &id, "ku");
        assert!(
            stored.contains("\"unknown\""),
            "transient evidence NEVER flips the state: {stored}"
        );
        assert!(!stored.contains("reconciled"));
    })
    .await;
}

#[tokio::test]
async fn evidence_mismatch_never_commits() {
    let root = Root::new("mm");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    // wrong recipient in the found tx: mismatched evidence is never Paid
    ops.set_lookup(
        "SIGM",
        TxLookup::Found(crate::rialo::TxRecord {
            signature: Some("SIGM".to_string()),
            executed: true,
            err: None,
            slot: Some(101),
            block_height: Some(101),
            block_time: Some(1_700_000_060),
            fee: Some(5000),
            payer: Some(AGENT_WALLET.to_string()),
            transfer_recipient: Some("SomeOtherRecipient111111111111111111111111111".to_string()),
            transfer_amount_kelvin: Some(1_000_000),
            complete: true,
        }),
    );
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "km",
            &v2_intent(&id, "km", "unknown", stale_at, Some("SIGM")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.unresolved, 1);
        assert_eq!(
            report.entries[0].code.as_deref(),
            Some("AGENT_RECONCILIATION_EVIDENCE_MISMATCH")
        );
        let stored = read_intent(&root, &id, "km");
        assert!(stored.contains("\"unknown\""));
    })
    .await;
}

// ---------------------------------------------------------------------------
// (3) exactly-once: engine replay is zero-RPC zero-mutation; concurrent
// sweeps cannot double-commit (single locked commit section)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repeated_sweep_is_idempotent_replay_no_second_release() {
    let root = Root::new("idem");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGR", found_tx("SIGR"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kr",
            &v2_intent(&id, "kr", "unknown", stale_at, Some("SIGR")),
        );
        let first =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(first.reconciled, 1);
        let stored_after_first = read_intent(&root, &id, "kr");
        // second sweep: the record is terminal now, so the sweep's
        // enumeration (stale Pending/Unknown only) examines NOTHING —
        // the hold is gone, no second release is even attempted
        let second =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(second.examined, 0, "terminal records are never re-swept");
        assert_eq!(second.reconciled, 0);
        assert_eq!(second.entries.len(), 0);
        assert_eq!(
            stored_after_first,
            read_intent(&root, &id, "kr"),
            "the second sweep mutates nothing"
        );
        // and the ENGINE itself replays the stored terminal with zero RPC
        // and zero mutation (idempotent repeated reconciliation)
        let principal = ReconcilePrincipal::agent(&id);
        let replay = crate::agents::reconcile_production(
            ops.as_ref(),
            &agent,
            &ReconcileRequest {
                idempotency_key: "kr".to_string(),
                manual_outcome: None,
                attestation: None,
                allow_scan: false,
                allow_auto: false,
            },
            &principal,
            now,
        );
        assert!(matches!(
            replay,
            crate::agents::ReconcileVerdict::Reconciled { .. }
        ));
        assert_eq!(
            stored_after_first,
            read_intent(&root, &id, "kr"),
            "engine replay mutates nothing"
        );
    })
    .await;
}

#[tokio::test]
async fn concurrent_sweeps_cannot_double_commit() {
    let root = Root::new("conc");
    let id = Uuid::new_v4();
    let agent = Arc::new(agent_record(&id));
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGC", found_tx("SIGC"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kc",
            &v2_intent(&id, "kc", "unknown", stale_at, Some("SIGC")),
        );
        // 8 concurrent sweeps over the same stale Unknown
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ops = ops.clone();
            let agent = agent.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now)
                    .unwrap()
            }));
        }
        let mut reconciled = 0u64;
        for h in handles {
            let r = h.await.unwrap();
            reconciled += r.reconciled;
        }
        // every sweep SEES a reconciled terminal (commit or replay), but
        // the record is committed exactly once — the reconciliation block
        // appears exactly once in the stored JSON.
        assert!(reconciled >= 1, "at least one sweep commits or replays");
        let stored = read_intent(&root, &id, "kc");
        assert_eq!(
            stored.matches("\"reconciled_paid\"").count(),
            1,
            "exactly one terminal state in the record"
        );
        assert_eq!(
            stored.matches("\"reconciliation\"").count(),
            1,
            "one reconciliation block"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// (4) V1 coverage: no persisted signature exists on V1 records, so the
// sweep's scan findings stay PROPOSALS (never committed) and absent
// history stays Unknown — over-retention, never a silent release
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v1_stale_unknown_scan_proposal_stays_unknown() {
    let root = Root::new("v1scan");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    // exactly ONE matching successful transfer in the wallet's history
    ops.set_scan(AGENT_WALLET, vec![sig_record("SIGSCAN")]);
    ops.set_lookup("SIGSCAN", found_tx("SIGSCAN"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kv1",
            &v1_intent(&id, "kv1", "unknown", stale_at),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(
            report.proposals, 1,
            "a V1 scan match is a PROPOSAL, never a commit"
        );
        assert_eq!(report.reconciled, 0);
        let stored = read_intent(&root, &id, "kv1");
        assert!(
            stored.contains("\"unknown\""),
            "the V1 intent stays Unknown: {stored}"
        );
        assert!(!stored.contains("reconciled"));
    })
    .await;
}

#[tokio::test]
async fn v1_stale_unknown_no_history_stays_unknown() {
    let root = Root::new("v1none");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock(); // empty history: NO_MATCH
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kv1n",
            &v1_intent(&id, "kv1n", "unknown", stale_at),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.unresolved, 1);
        assert_eq!(
            report.entries[0].code.as_deref(),
            Some("AGENT_RECONCILIATION_NO_MATCH")
        );
        let stored = read_intent(&root, &id, "kv1n");
        assert!(
            stored.contains("\"unknown\""),
            "absence of scan candidates NEVER releases: {stored}"
        );
    })
    .await;
}

#[tokio::test]
async fn v1_stale_pending_is_normalized_but_never_auto_resolved() {
    let root = Root::new("v1pend");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kv1p",
            &v1_intent(&id, "kv1p", "pending", stale_at),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.entries[0].pre_state, "pending");
        // the engine normalized Pending -> Unknown (reconciliation-eligible)
        // but the scan found no evidence, so the outcome is unresolved and
        // the record stays Unknown — never silently Failed, never released
        assert_eq!(report.reconciled, 0);
        assert_eq!(report.unresolved, 1);
        let stored = read_intent(&root, &id, "kv1p");
        assert!(
            stored.contains("\"unknown\""),
            "normalized, not Failed: {stored}"
        );
        assert!(
            stored.contains("AGENT_PAYMENT_STALE_PENDING"),
            "normalization is recorded"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------
// (5) V2 (credential-lane) coverage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v2_stale_unknown_reconciles_the_same_way() {
    let root = Root::new("v2");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGV2", found_tx("SIGV2"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kv2",
            &v2_intent(&id, "kv2", "unknown", stale_at, Some("SIGV2")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.reconciled, 1);
        let stored = read_intent(&root, &id, "kv2");
        assert!(stored.contains("\"reconciled_paid\""), "{stored}");
    })
    .await;
}

#[tokio::test]
async fn v2_stale_pending_is_normalized_and_recovered() {
    let root = Root::new("v2p");
    let id = Uuid::new_v4();
    let agent = agent_record(&id);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGV2P", found_tx("SIGV2P"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &id,
            "kv2p",
            &v2_intent(&id, "kv2p", "pending", stale_at, Some("SIGV2P")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent, now).unwrap();
        assert_eq!(report.entries[0].pre_state, "pending");
        assert_eq!(report.reconciled, 1, "v2 crash-recovered Pending resolves");
    })
    .await;
}

// ---------------------------------------------------------------------------
// (6) multi-agent isolation + lane consistency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sweeps_are_per_agent_and_isolated() {
    let root = Root::new("multi");
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let agent_a = agent_record(&a);
    let now = 1_700_010_000;
    let stale_at = now - AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let ops = mock();
    ops.set_lookup("SIGA", found_tx("SIGA"));
    with_cwd(&root.path(), async {
        write_intent(
            &root,
            &a,
            "ka",
            &v2_intent(&a, "ka", "unknown", stale_at, Some("SIGA")),
        );
        write_intent(
            &root,
            &b,
            "kb",
            &v2_intent(&b, "kb", "unknown", stale_at, Some("SIGB")),
        );
        let report =
            sweep_agent_intents(ops.as_ref(), &crate::agents::intents_root(), &agent_a, now)
                .unwrap();
        assert_eq!(
            report.examined, 1,
            "agent A's sweep sees only agent A's intents"
        );
        assert_eq!(report.reconciled, 1);
        // agent B's intent untouched by A's sweep
        let stored_b = read_intent(&root, &b, "kb");
        assert!(stored_b.contains("\"unknown\""));
    })
    .await;
}

#[tokio::test]
async fn sweep_core_never_transfers_never_falls_back() {
    // Structural: the sweep module code contains no transfer call and no
    // lane/fallback machinery — money can only move through the frozen
    // cores. The mock's `transfer` panics if ever called; this test also
    // pins the source text.
    let src = include_str!("agents.rs");
    let sweep = src
        .split("pub(crate) fn sweep_agent_intents")
        .nth(1)
        .expect("sweep core present")
        .split("// PHASE 6 STEP 4 — RECONCILIATION HTTP HANDLERS")
        .next()
        .unwrap();
    for forbidden in [
        "ops.transfer",
        "native.transfer",
        "gateway.submit",
        "ExecutionLane",
        "production_payment_ops",
        "reserve_spend",
        "claim_intent",
    ] {
        assert!(
            !sweep.contains(forbidden),
            "sweep core references {forbidden}"
        );
    }
    assert!(
        sweep.contains("reconcile_production"),
        "the engine is THE only authority"
    );
}

#[tokio::test]
async fn stale_intent_keys_handles_missing_dir_and_corrupt_files() {
    let root = Root::new("robust");
    let id = Uuid::new_v4();
    let now = 1_700_010_000;
    with_cwd(&root.path(), async {
        // missing dir -> empty
        let keys = stale_intent_keys(
            &crate::agents::intents_root(),
            &id,
            now,
            AGENT_PENDING_STALE_AFTER_SECONDS,
        )
        .unwrap();
        assert!(keys.is_empty());
        // corrupt json -> skipped, not an error
        let dir = root
            .path()
            .join("artifact/agent_payment_intents")
            .join(id.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("garbage.json"), "not json at all").unwrap();
        let keys = stale_intent_keys(
            &crate::agents::intents_root(),
            &id,
            now,
            AGENT_PENDING_STALE_AFTER_SECONDS,
        )
        .unwrap();
        assert!(keys.is_empty());
    })
    .await;
}

// ---------------------------------------------------------------------------
// chdir helper (same discipline as the stats shards)
// ---------------------------------------------------------------------------

async fn with_cwd<R: std::future::Future>(root: &std::path::Path, f: R) -> R::Output {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(root).unwrap();
    let result = f.await;
    let _ = std::env::set_current_dir(&original);
    result
}

// keep the unused-import lint quiet for the report/serialize types
#[allow(unused)]
fn _report_shape(r: &SweepReport) -> String {
    format!("{r:?}")
}
#[allow(unused)]
fn _state_shape(s: IntentState) -> &'static str {
    match s {
        IntentState::Pending => "pending",
        IntentState::Confirmed => "confirmed",
        IntentState::Failed => "failed",
        IntentState::Unknown => "unknown",
        IntentState::ReconciledPaid => "reconciled_paid",
        IntentState::ReconciledAbsent => "reconciled_absent",
    }
}
#[allow(unused)]
fn _config_shape(c: &RialoConfig) -> bool {
    // the production ops surface exists; the sweep uses whatever ops the
    // caller passes (RialoConfig in production, mock in tests)
    let _ = c;
    true
}
#[allow(unused)]
fn _principal_shape(p: &ReconcilePrincipal) -> bool {
    !p.resolver().is_empty()
}
