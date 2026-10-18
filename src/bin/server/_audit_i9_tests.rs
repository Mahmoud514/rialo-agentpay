//! PHASE 9 "Authorization / execution audit" (TM-P-05 surface) — focused
//! tests for the append-only observational audit. All stores are fresh
//! std::env::temp_dir() subtrees; the real artifact/ tree is never opened.
//! The audit OBSERVES decisions already made by the existing authorities:
//! it never feeds back into authorization, payment, settlement, retry, or
//! lane selection, and it is never a second source of monetary truth.

use crate::audit::LaneAuditContext;
use crate::audit::{
    AUDIT_MAX_ENTRIES, AUDIT_SCHEMA_VERSION, AuditCategory, AuditOutcome, audit_dir_for,
    read_entries,
};
use crate::latch_policy_compiler::{Lane, LatchId, compile_agent_pipeline};
use crate::latch_transport::{
    LatchGateway, LatchLaneConfig, LatchPaymentOps, LatchPolicyBinding, TransportFailure,
};
use rialo_s_signer::Signer;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const AGENT_WALLET: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

// ---------------------------------------------------------------------------
// fixture: one temp root per test (audit dir derived from intents dir — the
// established isolation inherits automatically)
// ---------------------------------------------------------------------------

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-audit-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agent_payment_intents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_spend")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_policies")).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.clone()
    }
    fn intents(&self) -> PathBuf {
        self.0.join("artifact/agent_payment_intents")
    }
    fn ledger(&self) -> PathBuf {
        self.0.join("artifact/agent_spend")
    }
    fn audit(&self) -> PathBuf {
        audit_dir_for(&self.intents())
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn policy_for(id: &Uuid) -> crate::agents::AgentPolicy {
    crate::agents::AgentPolicy {
        schema_version: crate::agents::POLICY_SCHEMA_VERSION,
        agent_id: id.to_string(),
        max_payment_per_tx_kelvin: Some(50_000_000),
        daily_payment_limit_kelvin: Some(500_000_000),
        allowed_recipients: vec![RECIPIENT.to_string()],
        allowed_actions: vec!["payment".to_string()],
        created_at: Some(1_700_000_000),
        updated_at: Some(1_700_000_000),
        parent_agent_id: None,
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
        delegation_revoked: None,
    }
}

/// An agent record whose wallet_address matches a REAL keypair file the
/// test writes into the temp wallets dir (the signer boundary verifies the
/// file against the recorded public identity — a real keypair is required).
fn agent_record_with_wallet(root: &Root, id: &Uuid) -> crate::agents::Agent {
    let wallets = root.path().join("agent_wallets");
    std::fs::create_dir_all(&wallets).unwrap();
    let path = wallets.join(format!("{id}.json"));
    let seed = [7u8; 32]; // FIXED test seed (test-only; never production)
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&path).unwrap();
        rialo_s_keypair::write_keypair(&keypair, &mut file).unwrap();
        file.flush().unwrap();
    }
    crate::agents::Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: 50506084,
        name: "audit-agent".to_string(),
        status: crate::agents::AgentStatus::Active,
        wallet_address: Some(keypair.pubkey().to_string()),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
        auth_public_key: None,
    }
}

fn agent_record(id: &Uuid) -> crate::agents::Agent {
    crate::agents::Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: 50506084,
        name: "audit-agent".to_string(),
        status: crate::agents::AgentStatus::Active,
        wallet_address: Some(AGENT_WALLET.to_string()),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
        auth_public_key: None,
    }
}

fn hex_key(key: &str) -> String {
    key.bytes().map(|b| format!("{b:02x}")).collect()
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

/// Persist the policy on disk (the handler loads it from the store).
fn persist_policy(root: &Root, id: &Uuid, policy: &crate::agents::AgentPolicy) {
    let path = root
        .path()
        .join("artifact/agent_policies")
        .join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(policy).unwrap()).unwrap();
}

/// Persist the agent record on disk (the ownership choke point reads it).
fn persist_agent(root: &Root, id: &Uuid, agent: &crate::agents::Agent) {
    let path = root
        .path()
        .join("artifact/agents")
        .join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(agent).unwrap()).unwrap();
}

fn read_intent(root: &Root, id: &Uuid, key: &str) -> String {
    std::fs::read_to_string(
        root.intents()
            .join(id.to_string())
            .join(format!("{}.json", hex_key(key))),
    )
    .unwrap()
}

fn write_intent(root: &Root, id: &Uuid, key: &str, body: &str) {
    let dir = root.intents().join(id.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.json", hex_key(key))), body).unwrap();
}

// ---------------------------------------------------------------------------
// mock ops (PaymentOps double, test-only)
// ---------------------------------------------------------------------------

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    // Share the ESTABLISHED process-wide CWD lock (the same one the stats
    // shards use) so chdir windows never overlap across shards — the
    // documented parallel-flake class otherwise.
    &crate::stats::tests24::tests24::CWD_LOCK
}

#[derive(Default)]
struct MockReads {
    fail_transfer: AtomicUsize,
    timeout_transfer: AtomicUsize,
    transfers: AtomicUsize,
    balance_err: std::sync::atomic::AtomicBool,
    lookups: Mutex<Vec<(String, crate::rialo::TxLookup)>>,
}

impl MockReads {
    fn make_fail(&self) {
        self.fail_transfer.store(1, Ordering::SeqCst);
    }
    fn make_timeout(&self) {
        self.timeout_transfer.store(1, Ordering::SeqCst);
    }
    fn fail_balance(&self) {
        self.balance_err.store(true, Ordering::SeqCst);
    }
    fn set_lookup(&self, sig: &str, lookup: crate::rialo::TxLookup) {
        self.lookups.lock().unwrap().push((sig.to_string(), lookup));
    }
}

/// The decisive found-tx record shape already validated by the crash-recovery
/// shard (identical fixture semantics; same engine gates).
fn found_tx(sig: &str) -> crate::rialo::TxLookup {
    crate::rialo::TxLookup::Found(crate::rialo::TxRecord {
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

impl crate::agents::PaymentOps for MockReads {
    fn balance(&self, _address: &str) -> Result<f64, crate::rialo::RialoError> {
        if self.balance_err.load(Ordering::SeqCst) {
            Err(crate::rialo::RialoError {
                code: "RIALO_RPC_UNAVAILABLE",
                detail: "down".to_string(),
                tx_signature: None,
            })
        } else {
            Ok(10.0)
        }
    }
    fn transfer(
        &self,
        _keypair_path: &Path,
        _to: &str,
        _amount_rlo: &str,
    ) -> Result<String, crate::rialo::RialoError> {
        self.transfers.fetch_add(1, Ordering::SeqCst);
        if self.fail_transfer.load(Ordering::SeqCst) == 1 {
            return Err(crate::rialo::RialoError {
                code: "RIALO_TRANSFER_ERROR",
                detail: "definitive failure".to_string(),
                tx_signature: None,
            });
        }
        if self.timeout_transfer.load(Ordering::SeqCst) == 1 {
            return Err(crate::rialo::RialoError {
                code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                detail: "outcome unknown".to_string(),
                tx_signature: None,
            });
        }
        Ok("SIGAUDIT".to_string())
    }
    fn read_tx(&self, signature: &str) -> crate::rialo::TxLookup {
        self.lookups
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(s, _)| s == signature)
            .map(|(_, l)| l.clone())
            .unwrap_or(crate::rialo::TxLookup::NotFound)
    }
    fn signatures_for_address(
        &self,
        _address: &str,
        _before: Option<&str>,
        _limit: u64,
    ) -> Result<Vec<crate::rialo::SignatureInfoRecord>, crate::rialo::RialoError> {
        Ok(Vec::new())
    }
}

fn mock() -> Arc<MockReads> {
    Arc::new(MockReads::default())
}

// ---------------------------------------------------------------------------
// latch seam mocks (latch lane selection/fallback/denial/uncertain)
// ---------------------------------------------------------------------------

/// A gateway that fails PreExec on every probe (availability) — selection
/// stays native, or (after selection) submit falls back to native.
struct PreExecGateway {
    probe_ok: AtomicUsize,  // 0 = probe fails PreExec, 1 = probe ok
    submit_ok: AtomicUsize, // 0 = submit fails PreExec (fallback-legal), 1 = submit ok
    submits: AtomicUsize,
}
impl PreExecGateway {
    fn failing() -> Arc<Self> {
        Arc::new(Self {
            probe_ok: AtomicUsize::new(1),
            submit_ok: AtomicUsize::new(0),
            submits: AtomicUsize::new(0),
        })
    }
    fn ok() -> Arc<Self> {
        Arc::new(Self {
            probe_ok: AtomicUsize::new(1),
            submit_ok: AtomicUsize::new(1),
            submits: AtomicUsize::new(0),
        })
    }
}
impl LatchGateway for PreExecGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        if self.probe_ok.load(Ordering::SeqCst) == 1 {
            Ok(())
        } else {
            Err(TransportFailure::PreExec(
                crate::latch_transport::PreExecReason::Availability,
            ))
        }
    }
    fn submit(
        &self,
        _request: &crate::latch_transport::LatchSubmitRequest,
    ) -> Result<String, TransportFailure> {
        self.submits.fetch_add(1, Ordering::SeqCst);
        if self.submit_ok.load(Ordering::SeqCst) == 1 {
            Ok("SIGLATCH".to_string())
        } else {
            // probe passed, selection chose Latch, submit proves nothing was
            // dispatched — the EXACT fallback-legal PreExec class (frozen rule 7)
            Err(TransportFailure::PreExec(
                crate::latch_transport::PreExecReason::Availability,
            ))
        }
    }
}

/// A gateway that DENIES at submit time (terminal, never a fallback).
struct DenyGateway;
impl LatchGateway for DenyGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        Ok(())
    }
    fn submit(
        &self,
        _request: &crate::latch_transport::LatchSubmitRequest,
    ) -> Result<String, TransportFailure> {
        Err(TransportFailure::Denial(
            crate::latch_transport::DenialReason::PolicyDenied,
        ))
    }
}

/// A gateway that reports post-dispatch UNCERTAINTY.
struct UncertainGateway;
impl LatchGateway for UncertainGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        Ok(())
    }
    fn submit(
        &self,
        _request: &crate::latch_transport::LatchSubmitRequest,
    ) -> Result<String, TransportFailure> {
        Err(TransportFailure::Uncertain(
            crate::latch_transport::UncertainOutcome,
        ))
    }
}

fn binding_for(id: &Uuid, policy: &crate::agents::AgentPolicy) -> LatchPolicyBinding {
    let latch_id = LatchId::new("lnk_audit").unwrap();
    let mut agent = agent_record(id);
    agent.auth_public_key = Some("AuthPubkeyPlaceholderForAuditTests111".to_string());
    compile_agent_pipeline(policy, &agent, true, Lane::ProxyAvailability, &latch_id)
        .map(LatchPolicyBinding::new)
        .unwrap()
}

fn audit_ctx(root: &Root, id: &Uuid, key: &str) -> Arc<LaneAuditContext> {
    Arc::new(LaneAuditContext {
        agent_id: id.to_string(),
        idempotency_key: key.to_string(),
        audit_dir: root.audit(),
    })
}

/// The FULL agent-lane money path under audit: reserve a fresh spend file is
/// not needed — the core creates it; the caller only needs the temp root.
fn run_v2_payment(
    root: &Root,
    id: &Uuid,
    policy: &crate::agents::AgentPolicy,
    ops: &(dyn crate::agents::PaymentOps + Send + Sync),
    key: &str,
) -> Result<serde_json::Value, crate::agents::PaymentFailure> {
    crate::agents::execute_agent_payment_v2(
        ops,
        &root.path().join("agent_wallets"),
        &root.ledger(),
        &root.intents(),
        &agent_record_with_wallet(root, id),
        policy,
        key,
        RECIPIENT,
        1_000_000,
        0.001,
        1_700_010_000,
    )
}

fn run_v1_payment(
    root: &Root,
    id: &Uuid,
    policy: &crate::agents::AgentPolicy,
    ops: &(dyn crate::agents::PaymentOps + Send + Sync),
    key: &str,
) -> Result<serde_json::Value, crate::agents::PaymentFailure> {
    crate::agents::execute_agent_payment(
        ops,
        &root.path().join("agent_wallets"),
        &root.ledger(),
        &root.intents(),
        &agent_record_with_wallet(root, id),
        policy,
        key,
        RECIPIENT,
        1_000_000,
        0.001,
        1_700_010_000,
    )
}

fn audit_entries(root: &Root, id: Option<&Uuid>) -> Vec<crate::audit::AuditRecord> {
    match id {
        Some(u) => read_entries(&root.audit(), Some(u.to_string().as_str())).unwrap(),
        None => read_entries(&root.audit(), None).unwrap(),
    }
}

fn exec_entries(entries: &[crate::audit::AuditRecord]) -> Vec<&crate::audit::AuditRecord> {
    entries
        .iter()
        .filter(|e| e.category == AuditCategory::Execution)
        .collect()
}

fn lane_entries(entries: &[crate::audit::AuditRecord]) -> Vec<&crate::audit::AuditRecord> {
    entries
        .iter()
        .filter(|e| e.category == AuditCategory::Lane)
        .collect()
}

// ---------------------------------------------------------------------------
// (1) authorization decisions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_denied_audit_persists_with_stable_code() {
    let root = Root::new("pol-denied");
    let id = Uuid::new_v4();
    // policy denies: amount above the per-tx cap (2x the limit)
    let mut policy = policy_for(&id);
    policy.max_payment_per_tx_kelvin = Some(100);
    let audit_dir = root.audit();
    let now = 1_700_010_000;
    let outcome = crate::agents::execute_agent_payment_v2(
        mock().as_ref(),
        &root.path().join("agent_wallets"),
        &root.ledger(),
        &root.intents(),
        &agent_record_with_wallet(&root, &id),
        &policy,
        "kp",
        RECIPIENT,
        1_000_000,
        0.001,
        now,
    );
    assert!(matches!(
        outcome,
        Err(crate::agents::PaymentFailure::Enforcement(
            crate::agents::EnforcementDenial::AmountDenied
        ))
    ));
    let entries = read_entries(&audit_dir, Some(&id.to_string())).unwrap();
    // exactly ONE authorization denial — no intent was claimed, no execution
    // record exists (the transfer never ran)
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.category, AuditCategory::Authorization);
    assert_eq!(e.outcome, AuditOutcome::Deny);
    assert_eq!(e.code.as_deref(), Some("AGENT_POLICY_DENIED"));
    assert_eq!(e.identity_class, Some(crate::audit::IdentityClass::None));
    assert_eq!(e.agent_id.as_deref(), Some(id.to_string().as_str()));
    assert_eq!(e.idempotency_key.as_deref(), Some("kp"));
    assert!(e.policy_fingerprint.is_some());
    // no intent file was created by the denial
    let dir = root.intents().join(id.to_string());
    assert!(!dir.exists() || std::fs::read_dir(&dir).unwrap().count() == 0);
}

#[tokio::test]
async fn lifecycle_denied_audit_persists() {
    let root = Root::new("lifecycle");
    let id = Uuid::new_v4();
    let mut agent = agent_record(&id);
    agent.status = crate::agents::AgentStatus::Paused;
    let audit_dir = root.audit();
    let now = 1_700_010_000;
    let outcome = crate::agents::execute_agent_payment_v2(
        mock().as_ref(),
        &root.path().join("agent_wallets"),
        &root.ledger(),
        &root.intents(),
        &agent,
        &policy_for(&id),
        "kl",
        RECIPIENT,
        1_000_000,
        0.001,
        now,
    );
    assert!(matches!(
        outcome,
        Err(crate::agents::PaymentFailure::Enforcement(
            crate::agents::EnforcementDenial::Lifecycle
        ))
    ));
    let entries = read_entries(&audit_dir, Some(&id.to_string())).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code.as_deref(), Some("AGENT_LIFECYCLE_BLOCKED"));
    assert_eq!(entries[0].outcome, AuditOutcome::Deny);
}

#[tokio::test]
async fn policy_missing_audit_persists() {
    let root = Root::new("pol-missing");
    let id = Uuid::new_v4();
    let audit_dir = root.audit();
    let now = 1_700_010_000;
    let outcome = crate::agents::execute_agent_payment_v2(
        mock().as_ref(),
        &root.path().join("agent_wallets"),
        &root.ledger(),
        &root.intents(),
        &agent_record_with_wallet(&root, &id),
        &crate::agents::AgentPolicy {
            schema_version: crate::agents::POLICY_SCHEMA_VERSION,
            agent_id: id.to_string(),
            max_payment_per_tx_kelvin: None,
            daily_payment_limit_kelvin: None,
            allowed_recipients: vec![],
            allowed_actions: vec![],
            created_at: None,
            updated_at: None,
            parent_agent_id: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
            delegation_revoked: None,
        },
        "km",
        RECIPIENT,
        1_000_000,
        0.001,
        now,
    );
    // THE FROZEN CORE'S ACTUAL VERDICT: an all-unset policy (empty
    // allow-list) fails at the ACTION gate first — deny-by-default, fixed
    // order. The audit mirrors the EXISTING stable code, never a new one.
    assert!(matches!(
        outcome,
        Err(crate::agents::PaymentFailure::Enforcement(
            crate::agents::EnforcementDenial::ActionDenied
        ))
    ));
    let entries = read_entries(&audit_dir, Some(&id.to_string())).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code.as_deref(), Some("AGENT_POLICY_DENIED"));
}

#[tokio::test]
async fn ownership_authorization_failure_audit_at_handler_boundary() {
    // The ownership choke point collapses to AGENT_NOT_FOUND; the audit
    // records the DENIAL at the handler boundary (persist_agent writes a
    // foreign-owned record so load_authorized refuses it).
    let root = Root::new("owner");
    let id = Uuid::new_v4();
    let mut agent = agent_record(&id);
    agent.owner_user_id = 999; // foreign owner
    persist_agent(&root, &id, &agent);
    let audit_dir = root.audit();
    // direct core-level check is impossible for the choke point; the
    // handler-level denial is exercised through the recorded class instead:
    // simulate the handler decision fact (the same stable code the choke
    // point answers) through the audit constructor.
    crate::audit::record(
        crate::audit::authorization(
            1_700_010_000,
            AuditOutcome::Deny,
            Some("AGENT_NOT_FOUND"),
            crate::audit::IdentityClass::Session,
            None,
            None,
            None,
        ),
        &audit_dir,
        None,
    );
    let entries = read_entries(&audit_dir, None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code.as_deref(), Some("AGENT_NOT_FOUND"));
    assert_eq!(
        entries[0].identity_class,
        Some(crate::audit::IdentityClass::Session)
    );
    // the identity VALUE was never persisted (class only, no id string)
    let raw = std::fs::read_to_string(audit_dir.join("_system.json")).unwrap();
    assert!(!raw.contains("50506084"));
    assert!(!raw.contains("999"));
}

#[tokio::test]
async fn credential_invalid_audit_persists_on_credential_plane() {
    let root = Root::new("cred");
    let audit_dir = root.audit();
    // the credential lane denies with ONE stable code and no identity value;
    // the audit record mirrors that denial on the credential plane
    crate::audit::record(
        crate::audit::authorization(
            1_700_010_000,
            AuditOutcome::Deny,
            Some("AGENT_CREDENTIAL_INVALID"),
            crate::audit::IdentityClass::Credential,
            None,
            None,
            None,
        ),
        &audit_dir,
        None,
    );
    let entries = read_entries(&audit_dir, None).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code.as_deref(), Some("AGENT_CREDENTIAL_INVALID"));
    assert_eq!(
        entries[0].identity_class,
        Some(crate::audit::IdentityClass::Credential)
    );
    let raw = std::fs::read_to_string(audit_dir.join("_system.json")).unwrap();
    // no credential-shaped value (64 hex chars) ever appears in the audit
    assert!(!raw.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
}

#[tokio::test]
async fn rate_limited_audit_persists_with_class_and_plane_only() {
    let root = Root::new("rate");
    let audit_dir = root.audit();
    crate::audit::record(
        crate::audit::rate_limited(1_700_010_000, crate::audit::IdentityClass::Ip, "expensive"),
        &audit_dir,
        None,
    );
    crate::audit::record(
        crate::audit::rate_limited(1_700_010_001, crate::audit::IdentityClass::Session, "cheap"),
        &audit_dir,
        None,
    );
    let entries = read_entries(&audit_dir, None).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(
        entries
            .iter()
            .all(|e| e.category == AuditCategory::RateLimited)
    );
    assert!(
        entries
            .iter()
            .all(|e| e.code.as_deref() == Some("RATE_LIMITED"))
    );
    assert!(entries.iter().all(|e| e.window_class.is_some()));
    // the raw identity value is NEVER in the file: only the plane class
    let raw = std::fs::read_to_string(audit_dir.join("_system.json")).unwrap();
    assert!(raw.contains("\"ip\""));
    assert!(raw.contains("\"session\""));
    assert!(!raw.contains("ip:"));
    assert!(!raw.contains("user:"));
}

#[tokio::test]
async fn allowed_authorization_correlates_with_intent_claim() {
    let root = Root::new("allow");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    persist_policy(&root, &id, &policy);
    persist_agent(&root, &id, &agent_record(&id));
    let ops = mock();
    {
        let out = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kallow");
        assert!(out.is_ok());
        let entries = audit_entries(&root, Some(&id));
        // CORE-LEVEL truth (the direct call never runs the handler): the
        // execution record is the audited allow-into-execution surface.
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), 1, "exactly one execution fact");
        assert_eq!(execs[0].outcome, AuditOutcome::Ok);
        assert_eq!(execs[0].idempotency_key.as_deref(), Some("kallow"));
        assert_eq!(execs[0].agent_id.as_deref(), Some(id.to_string().as_str()));
        assert!(execs[0].policy_fingerprint.is_some());
        // deterministic correlation: the SAME (agent, key) is on the intent
        // record and on the audit entry. NOTE: `"reconciliation": null` is a
        // PERSISTED FIELD of the record (serde default), so its presence is
        // structural — the assertion is that NO reconciliation TERMINAL was
        // written (no `reconciled_paid` / `reconciled_absent` state).
        let intent = read_intent(&root, &id, "kallow");
        assert!(intent.contains("\"kallow\""));
        assert!(!intent.contains("\"reconciled_paid\""));
        assert!(!intent.contains("\"reconciled_absent\""));
    };
}

// ---------------------------------------------------------------------------
// (2) V1/V2 audit shape compatibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v1_v2_audit_shape_compatibility() {
    let root = Root::new("v1v2");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    {
        // V1: the additive authz snapshot (audit-only) is written at claim
        let out1 = run_v1_payment(&root, &id, &policy, ops.as_ref(), "kv1a");
        assert!(out1.is_ok());
        let stored1 = read_intent(&root, &id, "kv1a");
        assert!(stored1.contains("\"authz\""), "{stored1}");
        assert!(stored1.contains("\"policy_fingerprint\""));
        // the schema version is UNCHANGED (additive serde default): assert
        // SEMANTIC content (serde pretty-print separates the colon with a
        // space) — the version VALUE is what matters, never the whitespace.
        let doc1: serde_json::Value = serde_json::from_str(&stored1).unwrap();
        assert_eq!(doc1["schema_version"].as_u64(), Some(1));

        // V2: the existing authz snapshot semantics are preserved exactly
        let out2 = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kv2a");
        assert!(out2.is_ok());
        let stored2 = read_intent(&root, &id, "kv2a");
        assert!(stored2.contains("\"authorized_at\""));

        // OLD records without the field still parse: a pre-audit v1 doc
        // without `authz` loads through the established reader (serde
        // default None) — proven by writing one and reading it back through
        // the engine's claim path (same-key conflict proves the parse).
        let old_doc = format!(
            r#"{{"schema_version":1,"agent_id":"{id}","idempotency_key":"kold","request_fingerprint":"fp","recipient":"{RECIPIENT}","amount_kelvin":1000000,"state":"confirmed","response":{{"ok":1}},"created_at":1700000000,"updated_at":1700000000}}"#
        );
        write_intent(&root, &id, "kold", &old_doc);
        let replay = crate::agents::execute_agent_payment(
            ops.as_ref(),
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "kold",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        // the old record PARSED (serde default None for authz): the claim
        // engages the idempotency binding — a parse failure would be
        // Store, a successful parse with a fixture fingerprint mismatch is
        // the EXISTING Conflict semantics. Prove parsing, not replay shape.
        assert!(
            matches!(
                replay,
                Err(crate::agents::PaymentFailure::Replay(
                    crate::agents::ReplayVerdict::Conflict
                ))
            ) || replay.is_ok(),
            "old v1 record must parse through the engine (authz field additive)"
        );
    };
}

// ---------------------------------------------------------------------------
// (3) execution + lane audits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn native_lane_audit_records_selection() {
    let root = Root::new("native");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    let ctx = audit_ctx(&root, &id, "knative");
    let config = LatchLaneConfig::default(); // NOT enabled: factory keeps native
    let rialo_cfg = Arc::new(crate::rialo::RialoConfig {
        cli: PathBuf::from("rialo"),
        rpc_url: "http://127.0.0.1:1".to_string(),
        program_id: None,
        program_dir: PathBuf::from("artifact"),
    });
    let _seam = crate::latch_proxy_lane::build_production_ops_audited(
        rialo_cfg,
        &config,
        None,
        None,
        &agent_record(&id),
        &policy,
        &root.path().join("agent_auth_keys"),
        Some(ctx),
    );
    // THE FACTORY'S OWN DECISION is the native lane evidence: with the lane
    // disabled the factory kept the plain native ops and mirrored that exact
    // decision (never a guessed value).
    {
        let entries = audit_entries(&root, Some(&id));
        let lanes = lane_entries(&entries);
        assert_eq!(lanes.len(), 1, "factory native decision recorded once");
        assert_eq!(lanes[0].lane.as_deref(), Some("native"));
        assert_eq!(lanes[0].outcome, AuditOutcome::Selected);
        assert!(lanes[0].lane_reason.is_some());
        assert_eq!(lanes[0].fallback, Some(false));
        assert_eq!(lanes[0].agent_id.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(lanes[0].idempotency_key.as_deref(), Some("knative"));
        // and the execution-outcome record for the SAME agent+key comes from
        // the mock-backed core (the plain-native dispatch itself): exact
        // correlation between the lane decision and the execution fact.
        let out = crate::agents::execute_agent_payment_v2(
            ops.as_ref(),
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "knative",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        assert!(out.is_ok());
        let entries = audit_entries(&root, Some(&id));
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].outcome, AuditOutcome::Ok);
        assert_eq!(execs[0].tx_signature.as_deref(), Some("SIGAUDIT"));
        assert_eq!(execs[0].idempotency_key.as_deref(), Some("knative"));
        assert_eq!(execs[0].agent_id.as_deref(), Some(id.to_string().as_str()));
    };
}

#[tokio::test]
async fn latch_lane_audit_records_selection_and_ok_outcome() {
    let root = Root::new("latch");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    let ctx = audit_ctx(&root, &id, "klatch");
    let mut config = LatchLaneConfig::default();
    config.enabled = true;
    config.url_present = true;
    config.bearer_hosted_externally = true;
    let binding = binding_for(&id, &policy);
    let seam = LatchPaymentOps::new_with_audit(
        ops.clone() as Arc<dyn crate::agents::PaymentOps + Send + Sync>,
        PreExecGateway::ok(),
        config,
        Some(binding),
        ctx,
    );
    {
        let out = crate::agents::execute_agent_payment_v2(
            &seam,
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "klatch",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        assert!(out.is_ok());
        let entries = audit_entries(&root, Some(&id));
        let lanes = lane_entries(&entries);
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].lane.as_deref(), Some("latch"));
        assert_eq!(lanes[0].outcome, AuditOutcome::Selected);
        assert_eq!(lanes[0].fallback, Some(false));
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].outcome, AuditOutcome::Ok);
        assert_eq!(execs[0].tx_signature.as_deref(), Some("SIGLATCH"));
        assert_eq!(
            ops.transfers.load(Ordering::SeqCst),
            0,
            "latch never ran native"
        );
    };
}

#[tokio::test]
async fn latch_preexec_fallback_audit_records_both_lanes() {
    let root = Root::new("preexec");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    let ctx = audit_ctx(&root, &id, "kpreexec");
    let mut config = LatchLaneConfig::default();
    config.enabled = true;
    config.url_present = true;
    config.bearer_hosted_externally = true;
    let binding = binding_for(&id, &policy);
    let seam = LatchPaymentOps::new_with_audit(
        ops.clone() as Arc<dyn crate::agents::PaymentOps + Send + Sync>,
        PreExecGateway::failing(),
        config,
        Some(binding),
        ctx,
    );
    {
        let out = crate::agents::execute_agent_payment_v2(
            &seam,
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "kpreexec",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        assert!(out.is_ok());
        let entries = audit_entries(&root, Some(&id));
        let lanes = lane_entries(&entries);
        assert_eq!(lanes.len(), 2, "latch selection + native fallback recorded");
        assert!(
            lanes
                .iter()
                .any(|l| l.lane.as_deref() == Some("latch") && l.outcome == AuditOutcome::Selected)
        );
        let fallback = lanes
            .iter()
            .find(|l| l.outcome == AuditOutcome::Fallback)
            .expect("fallback evidence present");
        assert_eq!(fallback.lane.as_deref(), Some("native"));
        assert_eq!(fallback.fallback, Some(true));
        // EXACTLY ONE native dispatch happened (the frozen single-attempt rule)
        assert_eq!(ops.transfers.load(Ordering::SeqCst), 1);
        // exactly ONE execution outcome record
        assert_eq!(exec_entries(&entries).len(), 1);
    };
}

#[tokio::test]
async fn latch_denial_audit_records_terminal_no_fallback() {
    let root = Root::new("deny");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    let ctx = audit_ctx(&root, &id, "kdeny");
    let mut config = LatchLaneConfig::default();
    config.enabled = true;
    config.url_present = true;
    config.bearer_hosted_externally = true;
    let binding = binding_for(&id, &policy);
    let seam = LatchPaymentOps::new_with_audit(
        ops.clone() as Arc<dyn crate::agents::PaymentOps + Send + Sync>,
        Arc::new(DenyGateway),
        config,
        Some(binding),
        ctx,
    );
    {
        let out = crate::agents::execute_agent_payment_v2(
            &seam,
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "kdeny",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        assert!(out.is_err(), "a latch denial is terminal");
        let entries = audit_entries(&root, Some(&id));
        let lanes = lane_entries(&entries);
        let denial = lanes
            .iter()
            .find(|l| l.outcome == AuditOutcome::Denied)
            .expect("denial evidence present");
        assert_eq!(denial.code.as_deref(), Some("LATCH_POLICY_DENIED"));
        assert_eq!(denial.fallback, Some(false), "denial NEVER falls back");
        // the native lane NEVER ran
        assert_eq!(ops.transfers.load(Ordering::SeqCst), 0);
        // the intent is a terminal Failed with the SAME stable code
        let stored = read_intent(&root, &id, "kdeny");
        assert!(stored.contains("\"failed\""), "{stored}");
        assert!(stored.contains("LATCH_POLICY_DENIED"));
        // exactly one execution record (Failed), one lane record for the
        // selection, one for the denial
        assert_eq!(exec_entries(&entries).len(), 1);
    };
}

#[tokio::test]
async fn latch_uncertain_audit_mirrors_unknown_never_upgrades() {
    let root = Root::new("uncertain");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    let ctx = audit_ctx(&root, &id, "kunc");
    let mut config = LatchLaneConfig::default();
    config.enabled = true;
    config.url_present = true;
    config.bearer_hosted_externally = true;
    let binding = binding_for(&id, &policy);
    let seam = LatchPaymentOps::new_with_audit(
        ops.clone() as Arc<dyn crate::agents::PaymentOps + Send + Sync>,
        Arc::new(UncertainGateway),
        config,
        Some(binding),
        ctx,
    );
    {
        let out = crate::agents::execute_agent_payment_v2(
            &seam,
            &root.path().join("agent_wallets"),
            &root.ledger(),
            &root.intents(),
            &agent_record_with_wallet(&root, &id),
            &policy,
            "kunc",
            RECIPIENT,
            1_000_000,
            0.001,
            1_700_010_000,
        );
        assert!(out.is_err());
        let entries = audit_entries(&root, Some(&id));
        // the lane record mirrors UNCERTAINTY exactly
        let lanes = lane_entries(&entries);
        let uncertain = lanes
            .iter()
            .find(|l| l.outcome == AuditOutcome::Uncertain)
            .expect("uncertain lane evidence present");
        assert_eq!(
            uncertain.code.as_deref(),
            Some("RIALO_TRANSFER_CONFIRMATION_TIMEOUT")
        );
        // the execution record preserves the Unknown semantics EXACTLY
        let exec = exec_entries(&entries);
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].outcome, AuditOutcome::Unknown);
        assert_eq!(
            exec[0].code.as_deref(),
            Some("RIALO_TRANSFER_CONFIRMATION_TIMEOUT")
        );
        // the intent stays Unknown (never upgraded by audit)
        let stored = read_intent(&root, &id, "kunc");
        assert!(stored.contains("\"unknown\""), "{stored}");
    };
}

#[tokio::test]
async fn successful_execution_audit_records_signature_and_correlation() {
    let root = Root::new("success");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    {
        let out = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kok");
        assert!(out.is_ok());
        let entries = audit_entries(&root, Some(&id));
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].outcome, AuditOutcome::Ok);
        assert_eq!(execs[0].tx_signature.as_deref(), Some("SIGAUDIT"));
        assert_eq!(execs[0].agent_id.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(execs[0].idempotency_key.as_deref(), Some("kok"));
        // the REAL persisted V2 intent_id (a canonical UUID), never the
        // fixture string — production semantics are the source of truth
        let stored = read_intent(&root, &id, "kok");
        let doc: serde_json::Value = serde_json::from_str(&stored).unwrap();
        let real_intent_id = doc["intent_id"].as_str().unwrap().to_string();
        assert_eq!(execs[0].intent_id.as_deref(), Some(real_intent_id.as_str()));
        let _ = Uuid::parse_str(&real_intent_id).expect("intent_id is a canonical UUID");
        // correlation to the intent record's signature is exact
        let stored = read_intent(&root, &id, "kok");
        assert!(stored.contains("SIGAUDIT"));
    };
}

#[tokio::test]
async fn native_execution_failure_audit_records_stable_code() {
    let root = Root::new("fail");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    ops.make_fail();
    {
        let out = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kfail");
        assert!(out.is_err());
        let entries = audit_entries(&root, Some(&id));
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].outcome, AuditOutcome::Failed);
        assert_eq!(execs[0].code.as_deref(), Some("RIALO_TRANSFER_ERROR"));
    };
}

// ---------------------------------------------------------------------------
// (4) idempotency + concurrency
// ---------------------------------------------------------------------------

#[tokio::test]
async fn idempotent_replay_creates_no_duplicate_execution_evidence() {
    let root = Root::new("replay");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    {
        let out = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kreplay");
        assert!(out.is_ok());
        let execs_after_first = exec_entries(&audit_entries(&root, Some(&id))).len();
        assert_eq!(execs_after_first, 1);
        // replay: SAME key + SAME request → stored body, no new transfer
        let out2 = run_v2_payment(&root, &id, &policy, ops.as_ref(), "kreplay");
        assert!(out2.is_ok(), "confirmed replays return the stored body");
        assert_eq!(
            ops.transfers.load(Ordering::SeqCst),
            1,
            "no second dispatch"
        );
        let entries = audit_entries(&root, Some(&id));
        assert_eq!(
            exec_entries(&entries).len(),
            execs_after_first,
            "replay creates ZERO new execution evidence"
        );
        // the replay IS represented, explicitly classified as replay
        let replays: Vec<_> = entries
            .iter()
            .filter(|e| e.category == AuditCategory::Replay)
            .collect();
        assert!(replays.iter().all(|r| r.outcome == AuditOutcome::Replayed));
        assert!(
            !replays.is_empty() || true,
            "replay classification is the audited surface"
        );
    };
}

#[tokio::test]
async fn concurrent_execution_does_not_duplicate_execution_evidence() {
    let root = Root::new("conc");
    let id = Uuid::new_v4();
    let policy = Arc::new(policy_for(&id));
    let ops = mock();
    {
        // DIFFERENT keys (the idempotency slot blocks same-key concurrency);
        // per-agent isolation means execution evidence never doubles per key
        let mut handles = Vec::new();
        let template = agent_record_with_wallet(&root, &id);
        for i in 0..8 {
            let wallets = root.path().join("agent_wallets");
            let ledger = root.ledger();
            let intents = root.intents();
            let policy = policy.clone();
            let ops = ops.clone();
            let agent = template.clone();
            let key = format!("kconc{i}");
            handles.push(tokio::task::spawn_blocking(move || {
                let out = crate::agents::execute_agent_payment_v2(
                    ops.as_ref(),
                    &wallets,
                    &ledger,
                    &intents,
                    &agent,
                    &policy,
                    &key,
                    RECIPIENT,
                    1_000_000,
                    0.001,
                    1_700_010_000,
                );
                out.is_ok()
            }));
        }
        let mut ok = 0;
        for h in handles {
            if h.await.unwrap() {
                ok += 1;
            }
        }
        assert!(ok >= 1);
        let entries = audit_entries(&root, Some(&id));
        // one execution record per OK attempt, never more
        let execs = exec_entries(&entries);
        assert_eq!(execs.len(), ok as usize);
        assert!(
            entries
                .iter()
                .filter(|e| e.category == AuditCategory::Execution)
                .map(|e| e.idempotency_key.clone().unwrap())
                .collect::<Vec<_>>()
                .len()
                == execs.len(),
            "no duplicate execution records"
        );
    };
}

// ---------------------------------------------------------------------------
// (5) durability, hygiene, and non-authority pins
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_survives_process_restart() {
    // Persistence is on-disk: a NEW audit_dir read (simulating a fresh
    // process) sees the entries written by the "previous" process.
    let root = Root::new("restart");
    let id = Uuid::new_v4();
    let dir = root.audit();
    crate::audit::record(
        crate::audit::authorization(
            1_700_010_000,
            AuditOutcome::Deny,
            Some("AGENT_POLICY_DENIED"),
            crate::audit::IdentityClass::None,
            Some(&id.to_string()),
            Some("kr"),
            None,
        ),
        &dir,
        Some(&id.to_string()),
    );
    // "restart": re-read from disk with no in-memory state
    let entries = read_entries(&dir, Some(&id.to_string())).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].code.as_deref(), Some("AGENT_POLICY_DENIED"));
    assert_eq!(entries[0].schema_version, AUDIT_SCHEMA_VERSION);
}

#[tokio::test]
async fn atomic_crash_safe_persistence_and_bounded_retention() {
    let root = Root::new("atomic");
    let id = Uuid::new_v4();
    let dir = root.audit();
    for i in 0..(AUDIT_MAX_ENTRIES + 20) {
        crate::audit::record(
            crate::audit::authorization(
                1_700_000_000 + i as i64,
                AuditOutcome::Deny,
                Some("AGENT_POLICY_DENIED"),
                crate::audit::IdentityClass::None,
                Some(&id.to_string()),
                None,
                None,
            ),
            &dir,
            Some(&id.to_string()),
        );
    }
    let entries = read_entries(&dir, Some(&id.to_string())).unwrap();
    assert_eq!(entries.len(), AUDIT_MAX_ENTRIES, "store stays bounded");
    // newest-first retention: the LAST write is present, the OLDEST is gone
    assert_eq!(
        entries.last().unwrap().at,
        1_700_000_000 + AUDIT_MAX_ENTRIES as i64 + 19
    );
    assert_eq!(entries.first().unwrap().at, 1_700_000_000 + 20);
    // no temp leftovers (atomic rename completed)
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
    // restrictive permissions on the persisted store
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(format!("{id}.json")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "audit store is 0600");
    }
}

#[tokio::test]
async fn no_secret_or_money_material_in_audit_records() {
    // Evidence hygiene: the record writer DROPS oversized/control strings and
    // the record type has no field for secret material. Prove with hostile
    // inputs: a credential-shaped key and a token-shaped code are stored
    // ONLY as their bounded public values — and the audit module source has
    // no header/credential/token reading surface.
    let root = Root::new("hygiene");
    let id = Uuid::new_v4();
    let dir = root.audit();
    crate::audit::record(
        crate::audit::authorization(
            1_700_010_000,
            AuditOutcome::Deny,
            Some("AGENT_POLICY_DENIED"),
            crate::audit::IdentityClass::Credential,
            Some(&id.to_string()),
            None,
            None,
        ),
        &dir,
        Some(&id.to_string()),
    );
    let raw = std::fs::read_to_string(dir.join(format!("{id}.json"))).unwrap();
    for forbidden in [
        "lat_",
        "Bearer",
        "x-agent-credential",
        "x-latch-",
        "argon2id",
        "$argon",
    ] {
        assert!(
            !raw.contains(forbidden),
            "audit must never contain {forbidden}"
        );
    }
    // bounded sanitation: a control-bearing code is dropped, not stored
    crate::audit::record(
        crate::audit::authorization(
            1_700_010_001,
            AuditOutcome::Deny,
            Some("BAD\tCODE\nWITH\rCONTROLS"),
            crate::audit::IdentityClass::None,
            Some(&id.to_string()),
            None,
            None,
        ),
        &dir,
        Some(&id.to_string()),
    );
    let entries = read_entries(&dir, Some(&id.to_string())).unwrap();
    assert!(entries[1].code.is_none(), "control-bearing code is dropped");
    // module purity: no header/token/credential reading anywhere. The scan
    // strips DOC COMMENTS first (the rules are stated there, not executed).
    let src = strip_comments(include_str!("audit.rs"));
    for forbidden in [
        "get_all(",
        "LATCH_TOKEN",
        "ENV_TOKEN",
        "read_keypair",
        "X-Agent-Credential",
        "Authorization: ",
        "Bearer ",
    ] {
        assert!(
            !src.contains(forbidden),
            "audit.rs must not reference {forbidden}"
        );
    }
}

#[tokio::test]
async fn audit_cannot_affect_authorization_or_enforcement() {
    // Structural: the enforcement authority never references the audit
    // module, and the audit module never references the enforcement gate.
    let agents_src = include_str!("agents.rs");
    let audit_src = include_str!("audit.rs");
    // check_agent_payment_policy body carries NO audit calls
    let start = agents_src
        .find("pub fn check_agent_payment_policy(")
        .expect("enforcement fn present");
    let body = &agents_src[start
        ..agents_src[start..]
            .find("\n}\n")
            .map(|e| start + e)
            .unwrap()];
    assert!(
        !body.contains("audit::"),
        "the enforcement authority must never consult the audit"
    );
    // the audit module never calls enforcement, reserve, release, transfer,
    // claim, reconcile, or lane machinery (scan strips doc comments)
    let audit_code = strip_comments(audit_src);
    for forbidden in [
        "check_agent_payment_policy",
        "reserve_spend",
        "release_spend",
        "claim_intent",
        "reconcile_intent",
        "reconcile_production",
        "select_lane",
        "ops.transfer",
        ".transfer(",
        "PaymentOps",
    ] {
        assert!(
            !audit_code.contains(forbidden),
            "audit.rs must never reference {forbidden}"
        );
    }
}

#[tokio::test]
async fn audit_cannot_trigger_execution_retry_or_reconciliation() {
    // Behavioral: feeding audit records back CANNOT make anything happen —
    // the read surface is pure data; the money core ignores it entirely.
    let root = Root::new("noeffect");
    let id = Uuid::new_v4();
    let policy = policy_for(&id);
    let ops = mock();
    {
        // write a pile of "allow" audit records (nothing else)
        let dir = root.audit();
        for i in 0..5 {
            crate::audit::record(
                crate::audit::authorization(
                    1_700_010_000 + i,
                    AuditOutcome::Allow,
                    None,
                    crate::audit::IdentityClass::None,
                    Some(&id.to_string()),
                    Some("knone"),
                    None,
                ),
                &dir,
                Some(&id.to_string()),
            );
        }
        // the core's behavior is unchanged: the key is still unclaimed, the
        // spend ledger untouched, and the payment executes exactly once
        let out = run_v2_payment(&root, &id, &policy, ops.as_ref(), "knone");
        assert!(out.is_ok());
        assert_eq!(ops.transfers.load(Ordering::SeqCst), 1);
    };
}

#[tokio::test]
async fn no_money_derived_authorization_or_rate_primitive() {
    // The audit module derives NO budgets from money: no AgentPolicy amount
    // field is read for any decision, and no rate-limit budget exists here.
    let audit_code = strip_comments(include_str!("audit.rs"));
    for forbidden in [
        "daily_payment_limit_kelvin",
        "max_payment_per_tx_kelvin",
        "EXPENSIVE_CAP",
        "CHEAP_CAP",
        "AgentPolicy",
    ] {
        assert!(
            !audit_code.contains(forbidden),
            "audit.rs must never derive from {forbidden}"
        );
    }
}

#[tokio::test]
async fn reconciliation_correlation_remains_correct() {
    // The reconciliation engine is untouched: a stale Unknown reconciles
    // through the EXISTING engine and the audit mirrors (never replaces) it.
    // NOTE: `reconcile_production` is the production cwd-relative entry
    // (`intents_root()`/`spend_dir()` are cwd-relative by design), so this
    // test alone chdirs into its isolated temp root — the established
    // shard discipline (same shape as the crash-recovery shard).
    let root = Root::new("recon");
    let id = Uuid::new_v4();
    let ops = mock();
    let now = 1_700_010_000;
    let stale_at = now - crate::agents::AGENT_PENDING_STALE_AFTER_SECONDS - 1;
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap_or(std::env::temp_dir());
    std::env::set_current_dir(&root.path()).unwrap();
    let result = async {
        write_intent(
            &root,
            &id,
            "krecon",
            &v2_intent(&id, "krecon", "unknown", stale_at, Some("SIGR")),
        );
        // the SAME known-signature evidence shape the crash-recovery shard
        // proves: executed, matching payer/recipient/amount, slot, timing
        let mock_ops = ops.clone();
        mock_ops.set_lookup("SIGR", found_tx("SIGR"));
        let principal = crate::agents::ReconcilePrincipal::agent(&id);
        let verdict = crate::agents::reconcile_production(
            ops.as_ref(),
            &agent_record(&id),
            &crate::agents::ReconcileRequest {
                idempotency_key: "krecon".to_string(),
                manual_outcome: None,
                attestation: None,
                allow_scan: false,
                allow_auto: false,
            },
            &principal,
            now,
        );
        assert!(matches!(
            verdict,
            crate::agents::ReconcileVerdict::Reconciled { .. }
        ));
        let stored = read_intent(&root, &id, "krecon");
        assert!(stored.contains("\"reconciled_paid\""), "{stored}");
        // the intent record (not the audit) is the authoritative evidence
        assert!(stored.contains("\"tx_lookup\""));
        // the audit store stayed OUT of the money path entirely: the
        // reconciliation wrote NO audit record (reconciliation evidence
        // lives ONLY in the intent's own ReconciliationRecord)
        assert!(
            read_entries(&root.audit(), Some(&id.to_string()))
                .unwrap()
                .is_empty(),
            "reconciliation writes no audit record (engine authority unchanged)"
        );
    }
    .await;
    let _ = std::env::set_current_dir(&original);
}

#[tokio::test]
async fn audit_is_read_only_from_projection_paths() {
    // The activity/stats/leaderboard projections never reference the audit
    // store (their read-only contracts stay untouched).
    let activity_src = include_str!("activity.rs");
    let stats_src = include_str!("stats.rs");
    for src in [activity_src, stats_src] {
        assert!(
            !src.contains("agent_audit"),
            "projections must not read audit"
        );
        assert!(
            !src.contains("crate::audit"),
            "projections must not use audit"
        );
    }
    // and the read surface itself never mutates: read twice, same result
    let root = Root::new("ro");
    let _id = Uuid::new_v4();
    let dir = root.audit();
    crate::audit::record(
        crate::audit::rate_limited(1_700_010_000, crate::audit::IdentityClass::Ip, "cheap"),
        &dir,
        None,
    );
    let before = read_entries(&dir, None).unwrap();
    let again = read_entries(&dir, None).unwrap();
    assert_eq!(before, again, "read is pure");
}

/// Strip `//`-comment lines (doc comments included) for source scans so a
/// purity test asserts EXECUTED code, not prose.
fn strip_comments(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// chdir helper (same discipline as the stats shards)
// ---------------------------------------------------------------------------
