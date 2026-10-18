//! PHASE 9 I-4 — focused tests for the Latch transport seam.
//!
//! Every gate the frozen I-4 rules demand is tested at the trait boundary
//! AND (for the settlement-safety trio) end-to-end through the real
//! `execute_agent_payment` core with temp-dir stores only. No network, no
//! real artifact/ paths, no user-wallet touch (sentinel pattern), keypair
//! files are test-only seeds whose bytes are never read back or printed.

use super::*;
use crate::agents::{
    AGENT_SCHEMA_VERSION, Agent, AgentPolicy, AgentStatus, IntentState, POLICY_SCHEMA_VERSION,
    PaymentFailure, PaymentOps, execute_agent_payment, read_intent,
};
use crate::latch_policy_compiler::{CompiledPipeline, Lane, LatchId, compile_agent_pipeline};
use crate::rialo::{RialoError, SignatureInfoRecord, TxLookup};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const AUTH_PUBKEY: &str = "TestAuthPubkey111111111111111111111111111111";
const USER_ID: u64 = 50506086;
const NOW: i64 = 1_760_000_000;
const PAY_TX: u64 = 5_000_000_000;
const PAY_DAY: u64 = 20_000_000_000;

// ---------------------------------------------------------------- doubles

/// Recording stand-in for the native boundary (the real `RialoConfig`).
struct RecordingNative {
    transfers: Mutex<Vec<(String, String, String)>>,
    reads: Mutex<usize>,
}

impl RecordingNative {
    fn new() -> Self {
        Self {
            transfers: Mutex::new(Vec::new()),
            reads: Mutex::new(0),
        }
    }
    fn transfers(&self) -> Vec<(String, String, String)> {
        self.transfers.lock().unwrap().clone()
    }
}

impl PaymentOps for RecordingNative {
    fn balance(&self, _address: &str) -> Result<f64, RialoError> {
        *self.reads.lock().unwrap() += 1;
        Ok(10.0)
    }
    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError> {
        self.transfers.lock().unwrap().push((
            keypair_path.display().to_string(),
            to.into(),
            amount_rlo.into(),
        ));
        Ok("5NativeSignature1111111111111111111111111111111111111".into())
    }
    fn read_tx(&self, _signature: &str) -> TxLookup {
        *self.reads.lock().unwrap() += 1;
        TxLookup::NotFound
    }
    fn signatures_for_address(
        &self,
        _address: &str,
        _until: Option<&str>,
        _limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
        *self.reads.lock().unwrap() += 1;
        Ok(vec![])
    }
}

/// Scripted Latch gateway double. The ONLY way any test gets a non-
/// production gateway verdict — production code paths only ever see
/// `UnconfiguredLatchGateway`.
struct ScriptedGateway {
    probe_result: Result<(), TransportFailure>,
    submits: Mutex<VecDeque<Result<String, TransportFailure>>>,
    submit_calls: Mutex<usize>,
    probe_calls: Mutex<usize>,
    seen: Mutex<Vec<LatchSubmitRequest>>,
}

impl ScriptedGateway {
    fn new(
        probe_result: Result<(), TransportFailure>,
        submits: Vec<Result<String, TransportFailure>>,
    ) -> Self {
        Self {
            probe_result,
            submits: Mutex::new(submits.into()),
            submit_calls: Mutex::new(0),
            probe_calls: Mutex::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }
    fn probes(&self) -> usize {
        *self.probe_calls.lock().unwrap()
    }
    fn submits(&self) -> usize {
        *self.submit_calls.lock().unwrap()
    }
    fn requests(&self) -> Vec<LatchSubmitRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl LatchGateway for ScriptedGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        *self.probe_calls.lock().unwrap() += 1;
        self.probe_result.clone()
    }
    fn submit(&self, request: &LatchSubmitRequest) -> Result<String, TransportFailure> {
        *self.submit_calls.lock().unwrap() += 1;
        self.seen.lock().unwrap().push(request.clone());
        self.submits
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(TransportFailure::PreExec(PreExecReason::Availability)))
    }
}

fn full_config() -> LatchLaneConfig {
    LatchLaneConfig {
        enabled: true,
        url_present: true,
        token_present: true,
        bearer_hosted_externally: false,
    }
}

/// Compile a real C-2 pipeline for a synthetic active agent (pure,
/// in-memory — the same fixture class `_c2compiler_tests` uses).
fn compiled_pipeline(agent_id: &str) -> CompiledPipeline {
    let agent = Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: agent_id.into(),
        owner_user_id: 7,
        name: "I4".into(),
        status: AgentStatus::Active,
        wallet_address: Some("TestWalletPubkey2222222222222222222222222222222222222222".into()),
        auth_public_key: Some(AUTH_PUBKEY.into()),
        created_at: 1,
        updated_at: 2,
    };
    let policy = AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: agent_id.into(),
        max_payment_per_tx_kelvin: Some(PAY_TX),
        daily_payment_limit_kelvin: Some(PAY_DAY),
        allowed_recipients: vec![RECIPIENT.into()],
        allowed_actions: vec!["payment".into()],
        created_at: Some(1),
        updated_at: Some(2),
        parent_agent_id: None,
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
        delegation_revoked: None,
    };
    let pipeline = compile_agent_pipeline(
        &policy,
        &agent,
        true,
        Lane::ProxyAvailability,
        &LatchId::new("lnk-i4-test").unwrap(),
    )
    .expect("fixture compiles");
    pipeline
}

fn compiled_binding(agent_id: &str) -> LatchPolicyBinding {
    LatchPolicyBinding::new(compiled_pipeline(agent_id))
}

// ---------------------------------------------------------------- 1+3..7:
// native preservation and the three legal pre-execution fallback classes

#[test]
fn disabled_lane_keeps_native_unchanged_and_never_touches_the_gateway() {
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(Ok(()), vec![Ok("unused".into())]));
    let ops = LatchPaymentOps::new(native.clone(), gw.clone(), LatchLaneConfig::default(), None);
    let ok = ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0");
    assert!(ok.is_ok());
    assert_eq!(native.transfers().len(), 1);
    assert_eq!(gw.probes(), 0);
    assert_eq!(gw.submits(), 0);
}

#[test]
fn pre_exec_failures_all_fall_back_to_exactly_one_native_dispatch() {
    // Availability / Configuration / Capability — and ONLY these — may
    // fall back (frozen rule 7). Selection runs before any submit.
    for reason in [
        PreExecReason::Availability,
        PreExecReason::Configuration,
        PreExecReason::Capability,
    ] {
        let native = Arc::new(RecordingNative::new());
        let gw = Arc::new(ScriptedGateway::new(
            Err(TransportFailure::PreExec(reason)),
            vec![],
        ));
        let ops = LatchPaymentOps::new(
            native.clone(),
            gw.clone(),
            full_config(),
            Some(compiled_binding(&Uuid::new_v4().to_string())),
        );
        assert!(
            ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
                .is_ok()
        );
        assert_eq!(
            native.transfers().len(),
            1,
            "native ran once for {reason:?}"
        );
        assert_eq!(gw.submits(), 0, "no latch submit for {reason:?}");
        assert_eq!(gw.probes(), 1);
    }
}

#[test]
fn missing_env_config_never_probes_and_stays_native() {
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(Ok(()), vec![Ok("sig".into())]));
    let cfg = LatchLaneConfig {
        enabled: true,
        url_present: false,
        token_present: true,
        bearer_hosted_externally: false,
    };
    let ops = LatchPaymentOps::new(native.clone(), gw.clone(), cfg, None);
    assert!(
        ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    assert_eq!(gw.probes(), 0, "configuration gate precedes the probe");
    assert_eq!(gw.submits(), 0);
    assert_eq!(native.transfers().len(), 1);
}

#[test]
fn production_default_gateway_fails_closed_pre_exec() {
    let gw = UnconfiguredLatchGateway;
    let probe = gw.probe();
    assert_eq!(
        probe,
        Err(TransportFailure::PreExec(PreExecReason::Configuration))
    );
    let req = LatchSubmitRequest {
        agent_id: "a".into(),
        recipient: RECIPIENT.into(),
        amount_rlo: "1.0".into(),
        policy_ir_json: "{}".into(),
        signer_reference: PathBuf::from("x.json"),
    };
    assert_eq!(
        gw.submit(&req),
        Err(TransportFailure::PreExec(PreExecReason::Configuration))
    );
}

// ---------------------------------------------------------- 6..9: denials

#[test]
fn every_denial_class_never_falls_back_and_keeps_its_stable_code() {
    let cases = [
        (DenialReason::PolicyDenied, CODE_LATCH_POLICY_DENIED),
        (DenialReason::SecurityDenied, CODE_LATCH_SECURITY_DENIED),
        (DenialReason::AuthRejected, CODE_LATCH_AUTH_REJECTED),
    ];
    for (reason, code) in cases {
        let native = Arc::new(RecordingNative::new());
        let gw = Arc::new(ScriptedGateway::new(
            Ok(()),
            vec![Err(TransportFailure::Denial(reason))],
        ));
        let binding = compiled_binding(&Uuid::new_v4().to_string());
        let ops = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
        let err = ops
            .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
            .expect_err("denied");
        assert_eq!(err.code, code, "stable code for {reason:?}");
        assert_eq!(native.transfers().len(), 0, "NEVER fall back on {reason:?}");
        assert_eq!(gw.submits(), 1);
    }
}

#[test]
fn pre_exec_refusal_at_submit_time_is_still_fallback_legal() {
    // Probe passed, selection chose Latch, but submit proved pre-dispatch
    // refusal: nothing moved, so one native dispatch is still allowed.
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Err(TransportFailure::PreExec(PreExecReason::Availability))],
    ));
    let binding = compiled_binding(&Uuid::new_v4().to_string());
    let ops = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
    assert!(
        ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    assert_eq!(gw.submits(), 1);
    assert_eq!(native.transfers().len(), 1);
}

// ---------------------------------------------------------------- 2/11:
// latch lane selection shape

#[test]
fn latch_lane_is_selected_only_with_config_probe_and_matching_binding() {
    let binding_agent = Uuid::new_v4().to_string();
    let binding = Some(compiled_binding(&binding_agent));
    let gw = ScriptedGateway::new(Ok(()), vec![Ok("5LatchSignature".into())]);

    let selected = select_lane(&full_config(), &gw, binding.as_ref(), &binding_agent);
    assert_eq!(selected.lane, ExecutionLane::Latch);

    // missing binding -> native (Capability-class, pre-exec)
    let no_binding = select_lane(&full_config(), &gw, None, &binding_agent);
    assert_eq!(no_binding.lane, ExecutionLane::Native);

    // agent mismatch -> native (the binding is never guessed into place)
    let wrong = select_lane(
        &full_config(),
        &gw,
        binding.as_ref(),
        &Uuid::new_v4().to_string(),
    );
    assert_eq!(wrong.lane, ExecutionLane::Native);

    // flag off -> native without probing
    let off = select_lane(
        &LatchLaneConfig::default(),
        &gw,
        binding.as_ref(),
        &binding_agent,
    );
    assert_eq!(off.lane, ExecutionLane::Native);
    assert_eq!(gw.probes(), 1, "only the success case probed");
}

#[test]
fn latch_submit_path_returns_the_gateway_signature() {
    let agent_id = Uuid::new_v4().to_string();
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Ok("5LatchSignature".into())],
    ));
    let binding = compiled_binding(&agent_id);
    let ops = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
    let sig = ops
        .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
        .expect("latch settlement accepted");
    assert_eq!(sig, "5LatchSignature");
    assert_eq!(native.transfers().len(), 0, "latch ran; native never did");
    assert_eq!(gw.submits(), 1);
}

// ------------------------------------------------------------- 13: G-2 IR

#[test]
fn compiled_pipeline_passes_through_unmutated_and_deterministic() {
    let agent_id = Uuid::new_v4().to_string();
    let binding = compiled_binding(&agent_id);
    let before = binding.pipeline_json();
    let again = binding.pipeline_json();
    assert_eq!(before, again, "to_json is deterministic bytes");

    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Ok("s".into()), Ok("s".into())],
    ));
    let native = Arc::new(RecordingNative::new());
    // A fresh seam per intent (guard discipline): two intents, same binding.
    for _ in 0..2 {
        let ops = LatchPaymentOps::new(
            native.clone(),
            gw.clone(),
            full_config(),
            Some(compiled_binding(&agent_id)),
        );
        assert!(
            ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
                .is_ok()
        );
    }
    let reqs = gw.requests();
    assert_eq!(reqs.len(), 2);
    for req in &reqs {
        assert_eq!(req.agent_id, agent_id);
        assert_eq!(req.policy_ir_json, before, "IR bytes verbatim, unmuted");
        assert!(req.carries_ir(&compiled_pipeline(&agent_id)));
    }
    assert_eq!(
        binding.pipeline_json(),
        before,
        "binding still identical after transport"
    );
    assert_eq!(native.transfers().len(), 0);
}

// ------------------------------------------------------ 10/11: one attempt

#[test]
fn uncertain_outcome_rides_the_core_timeout_code_and_retries_refuse() {
    let agent_id = Uuid::new_v4().to_string();
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Err(TransportFailure::Uncertain(UncertainOutcome))],
    ));
    let ops = LatchPaymentOps::new(
        native.clone(),
        gw.clone(),
        full_config(),
        Some(compiled_binding(&agent_id)),
    );
    let err = ops
        .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
        .expect_err("uncertain");
    assert_eq!(err.code, CODE_TRANSFER_CONFIRMATION_TIMEOUT);
    // A second attempt on the same intent instance is refused outright —
    // no second dispatch on ANY lane (frozen rules 6/8/10).
    let err2 = ops
        .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
        .expect_err("guard");
    assert_eq!(err2.code, CODE_TRANSFER_CONFIRMATION_TIMEOUT);
    assert_eq!(native.transfers().len(), 0);
    assert_eq!(gw.submits(), 1);
    assert_eq!(
        CODE_TRANSFER_CONFIRMATION_TIMEOUT,
        "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
    );
}

#[test]
fn the_guard_spends_after_any_dispatch_on_either_lane() {
    // After a SUCCESSFUL latch settlement: second call refused, no new
    // submit, no native.
    let gw = Arc::new(ScriptedGateway::new(Ok(()), vec![Ok("s1".into())]));
    let native = Arc::new(RecordingNative::new());
    let ops = LatchPaymentOps::new(
        native.clone(),
        gw.clone(),
        full_config(),
        Some(compiled_binding(&Uuid::new_v4().to_string())),
    );
    assert!(
        ops.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    let err = ops
        .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
        .expect_err("one attempt");
    assert_eq!(err.code, CODE_TRANSFER_CONFIRMATION_TIMEOUT);
    assert_eq!(gw.submits(), 1);
    assert_eq!(native.transfers().len(), 0);

    // After a native FALLBACK dispatch: guard spent, second call refused,
    // native ran exactly once overall.
    let gw2 = Arc::new(ScriptedGateway::new(
        Err(TransportFailure::PreExec(PreExecReason::Availability)),
        vec![],
    ));
    let native2 = Arc::new(RecordingNative::new());
    let ops2 = LatchPaymentOps::new(native2.clone(), gw2, full_config(), None);
    assert!(
        ops2.transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    let err2 = ops2
        .transfer(&FsPath::new("x.json"), RECIPIENT, "1.0")
        .expect_err("one attempt");
    assert_eq!(err2.code, CODE_TRANSFER_CONFIRMATION_TIMEOUT);
    assert_eq!(native2.transfers().len(), 1);
}

// ------------------------------------------------------- 15 (reads) etc.

#[test]
fn read_only_plane_always_delegates_and_never_touches_the_gateway() {
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(Ok(()), vec![]));
    let ops = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), None);
    assert_eq!(ops.balance("addr").unwrap(), 10.0);
    assert!(matches!(ops.read_tx("s"), TxLookup::NotFound));
    assert!(ops.signatures_for_address("a", None, 1).unwrap().is_empty());
    assert_eq!(gw.probes(), 0);
    assert_eq!(gw.submits(), 0);
}

#[test]
fn config_and_requests_carry_no_credential_shapes() {
    // The config type is booleans + static names: no value fields exist
    // at all, so no token/URL value can be stored, cloned, or Debug
    // -printed into logs.
    let cfg = LatchLaneConfig {
        enabled: true,
        url_present: true,
        token_present: true,
        bearer_hosted_externally: false,
    };
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("lat"));
    assert!(!dbg.contains("Bearer"));
    // Env NAME constants only:
    assert!(!LatchLaneConfig::ENV_TOKEN.contains("lat_"));
    let req = LatchSubmitRequest {
        agent_id: "a".into(),
        recipient: RECIPIENT.into(),
        amount_rlo: "1.0".into(),
        policy_ir_json: "{}".into(),
        signer_reference: PathBuf::from("x.json"),
    };
    let req_dbg = format!("{req:?}");
    assert!(!req_dbg.contains("keypair"));
    // I-5 amendment (D-PROXY transport wiring): the envelope gained the
    // signer_reference PATH field — a file reference, never key material.
    // Credential shapes stay banned; the reference itself is exact.
    assert!(!req_dbg.contains("lat_"));
    assert!(!req_dbg.contains("Bearer"));
    assert!(!req_dbg.contains("Authorization"));
    assert_eq!(req.signer_reference, PathBuf::from("x.json"));
}

// ------------------------------------------------- 1/10/11 at CORE level

struct CoreFixture {
    root: PathBuf,
    wallets: PathBuf,
    ledger: PathBuf,
    intents: PathBuf,
    uuid: Uuid,
    agent: Agent,
    policy: AgentPolicy,
}

impl CoreFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-i4-{}", Uuid::new_v4()));
        let agents = root.join("agents");
        let wallets = root.join("agent_wallets");
        let user_wallets = root.join("wallets");
        let ledger = root.join("agent_spend");
        let intents = root.join("agent_payment_intents");
        fs::create_dir_all(&agents).unwrap();
        fs::create_dir_all(&user_wallets).unwrap();
        // Sentinel proves the user-wallet plane is untouched.
        fs::write(
            user_wallets.join(format!("{USER_ID}.json")),
            b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE",
        )
        .unwrap();
        fs::create_dir_all(&wallets).unwrap();
        let uuid = Uuid::new_v4();
        let mut seed = [0u8; 32];
        assert!(getrandom::getrandom(&mut seed).is_ok());
        let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
        let path = wallets.join(format!("{uuid}.json"));
        let mut file = fs::File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        rialo_s_keypair::write_keypair(&keypair, &mut file).unwrap();
        drop(file);
        use rialo_s_signer::Signer;
        let address = keypair.pubkey().to_string();
        let agent = Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: uuid.to_string(),
            owner_user_id: 7,
            name: "I4Core".into(),
            status: AgentStatus::Active,
            wallet_address: Some(address),
            auth_public_key: Some(AUTH_PUBKEY.into()),
            created_at: 0,
            updated_at: 0,
        };
        let policy = AgentPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            agent_id: uuid.to_string(),
            max_payment_per_tx_kelvin: Some(PAY_TX),
            daily_payment_limit_kelvin: Some(PAY_DAY),
            allowed_recipients: vec![RECIPIENT.into()],
            allowed_actions: vec!["payment".into()],
            created_at: Some(0),
            updated_at: Some(0),
            parent_agent_id: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
            delegation_revoked: None,
        };
        Self {
            root,
            wallets,
            ledger,
            intents,
            uuid,
            agent,
            policy,
        }
    }

    fn pay(&self, ops: &dyn PaymentOps, key: &str) -> Result<serde_json::Value, PaymentFailure> {
        execute_agent_payment(
            ops,
            &self.wallets,
            &self.ledger,
            &self.intents,
            &self.agent,
            &self.policy,
            key,
            RECIPIENT,
            1_000_000_000,
            1.0,
            NOW,
        )
    }

    fn intent_state(&self, key: &str) -> IntentState {
        read_intent(&self.intents, &self.uuid, key)
            .expect("io")
            .expect("intent exists")
            .state
    }
}

impl Drop for CoreFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

#[test]
fn core_native_lane_behavior_is_preserved_through_the_seam() {
    // Latch disabled: the seam must be indistinguishable from calling the
    // wrapped ops directly — real commit path, exactly one dispatch.
    let f = CoreFixture::new();
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(Ok(()), vec![Ok("never".into())]));
    let seam = LatchPaymentOps::new(native.clone(), gw.clone(), LatchLaneConfig::default(), None);
    let body = f.pay(&seam, "i4-native").expect("pays");
    assert_eq!(body["success"], serde_json::json!(true));
    assert_eq!(f.intent_state("i4-native"), IntentState::Confirmed);
    assert_eq!(native.transfers().len(), 1);
    assert_eq!(gw.probes(), 0);
    assert_eq!(gw.submits(), 0);
}

#[test]
fn core_uncertain_latch_settlement_holds_unknown_and_never_second_attempts() {
    let f = CoreFixture::new();
    let binding = compiled_binding(&f.uuid.to_string());
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Err(TransportFailure::Uncertain(UncertainOutcome))],
    ));
    let seam = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
    let err = f
        .pay(&seam, "i4-uncertain")
        .expect_err("uncertain settlement");
    assert!(matches!(err, PaymentFailure::Transfer(_)));
    // The core's established unknown-hold exit ran: intent Unknown,
    // reservation held (never refunded by this path), no native dispatch.
    assert_eq!(f.intent_state("i4-uncertain"), IntentState::Unknown);
    assert_eq!(native.transfers().len(), 0);
    assert_eq!(gw.submits(), 1);
    // Replay of the SAME intent key is gated (no second settlement
    // attempt, no lane switch): Unreconciled replay refusal.
    let again = f.pay(&seam, "i4-uncertain");
    assert!(again.is_err());
    assert_eq!(native.transfers().len(), 0);
    assert_eq!(gw.submits(), 1);
    assert_eq!(f.intent_state("i4-uncertain"), IntentState::Unknown);
}

#[test]
fn core_policy_denial_from_latch_fails_intent_and_never_runs_native() {
    let f = CoreFixture::new();
    let binding = compiled_binding(&f.uuid.to_string());
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Ok(()),
        vec![Err(TransportFailure::Denial(DenialReason::PolicyDenied))],
    ));
    let seam = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
    let err = f
        .pay(&seam, "i4-denied")
        .expect_err("denied settles as failure");
    match err {
        PaymentFailure::Transfer(e) => assert_eq!(e.code, CODE_LATCH_POLICY_DENIED),
        other => panic!("expected Transfer, got {other:?}"),
    }
    // Definitive non-dispatch failure: the core's refund+Failed path is
    // correct here (nothing moved); the key is burned. NO native transfer,
    // NO lane switch, intent Failed with the stable code recorded.
    assert_eq!(native.transfers().len(), 0);
    assert_eq!(gw.submits(), 1);
    let intent = read_intent(&f.intents, &f.uuid, "i4-denied")
        .unwrap()
        .expect("intent exists");
    assert_eq!(intent.state, IntentState::Failed);
    let recorded = intent.response.expect("recorded error");
    assert_eq!(recorded["code"], CODE_LATCH_POLICY_DENIED);
}

#[test]
fn core_availability_fallback_pays_via_native_exactly_once() {
    // The full frozen matrix end-to-end: latch unavailable pre-exec ->
    // native settles -> Confirmed, one dispatch, zero latch submits.
    let f = CoreFixture::new();
    let binding = compiled_binding(&f.uuid.to_string());
    let native = Arc::new(RecordingNative::new());
    let gw = Arc::new(ScriptedGateway::new(
        Err(TransportFailure::PreExec(PreExecReason::Availability)),
        vec![],
    ));
    let seam = LatchPaymentOps::new(native.clone(), gw.clone(), full_config(), Some(binding));
    f.pay(&seam, "i4-fallback").expect("native pays");
    assert_eq!(native.transfers().len(), 1);
    assert_eq!(gw.submits(), 0);
    assert_eq!(f.intent_state("i4-fallback"), IntentState::Confirmed);
}

// ------------------------------------------------------------- purity

#[test]
fn transport_module_stays_pure_networkless_and_secretless() {
    let src = include_str!("latch_transport.rs");
    let production = src.split("#[cfg(test)]").next().expect("test boundary");
    let kept: Vec<&str> = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let code = kept.join("\n");
    // vacuity guard: the scan actually sees the seam
    assert!(code.contains("impl PaymentOps for LatchPaymentOps"));
    for banned in [
        "reqwest",
        "std::net",
        "TcpStream",
        "http",
        "ureq",
        "lat_",
        "Bearer",
        "Authorization",
        "argon",
        "read_keypair",
        "write_keypair",
        "from_seed",
        "keypair_reference",
        "agent_wallets",
        "privy",
        "Privy",
        "fs::",
        "std::fs",
        "File::",
        "remove_dir",
        "compile_agent_pipeline",
        "rialo_canonical",
        "sh -c",
        "Command",
    ] {
        assert!(
            !code.contains(banned),
            "transport code must not reference {banned:?}"
        );
    }
    // The trait's keypair parameter is a NATIVE pass-through: it may
    // appear in the signature, in the native delegation calls, and —
    // since I-5 — in exactly one envelope binding (signer_reference, a
    // path never a key). NOWHERE ELSE.
    assert_eq!(
        code.matches("keypair_path").count(),
        4,
        "exactly: fn signature + the two native delegation call sites + the I-5 envelope binding"
    );
    // The frozen cores never reference the seam (isolation, I-2 precedent).
    assert!(
        !include_str!("agents.rs").contains("latch_transport"),
        "agents.rs must stay transport-agnostic"
    );
}
