//! PHASE 9 I-5 — focused tests for the armed D-PROXY transport lane.
//!
//! Coverage per the I-5 spec (B-list): proxy selected when configured and
//! capable; native when the shim is unavailable BEFORE execution; policy /
//! auth / validation-class denials NEVER falling back; uncertain outcomes
//! riding the single hold channel; exactly one execution attempt; the
//! read-only plane staying native; the loopback parse contract; and the
//! production factory's env-free decision core exercised through a
//! recording fake CLI that PROVES the settlement hop dialed the shim URL.
//! No external network: the "shim" is a local listener serving /healthz;
//! the lane executor is the real `RialoConfig` pointed at a temp script.

use super::*;
use crate::agents::{
    AGENT_SCHEMA_VERSION, Agent, AgentPolicy, AgentStatus, IntentState, POLICY_SCHEMA_VERSION,
    PaymentOps, execute_agent_payment, read_intent,
};
use crate::rialo::{SignatureInfoRecord, TxLookup};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const NOW: i64 = 1_760_000_000;
const PAY_TX: u64 = 5_000_000_000;
const PAY_DAY: u64 = 20_000_000_000;
const LANE_SIG: &str = "5I5LaneSignatureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HOLD_CODE: &str = "RIALO_TRANSFER_CONFIRMATION_TIMEOUT";

// ---------------------------------------------------------------- doubles

/// Recording PaymentOps with a scripted outcome queue (one per transfer).
struct ScriptedOps {
    transfers: Mutex<Vec<(String, String, String)>>,
    outcomes: Mutex<VecDeque<Result<String, RialoError>>>,
    reads: Mutex<usize>,
    balance_rlo: f64,
}

impl ScriptedOps {
    fn success() -> Self {
        Self::scripted(vec![Ok(LANE_SIG.into())])
    }
    fn scripted(outcomes: Vec<Result<String, RialoError>>) -> Self {
        Self {
            transfers: Mutex::new(Vec::new()),
            outcomes: Mutex::new(outcomes.into()),
            reads: Mutex::new(0),
            balance_rlo: 10.0,
        }
    }
    fn transfers(&self) -> Vec<(String, String, String)> {
        self.transfers.lock().unwrap().clone()
    }
    fn reads(&self) -> usize {
        *self.reads.lock().unwrap()
    }
}

impl PaymentOps for ScriptedOps {
    fn balance(&self, _address: &str) -> Result<f64, RialoError> {
        *self.reads.lock().unwrap() += 1;
        Ok(self.balance_rlo)
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
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(RialoError {
                code: "RIALO_TRANSFER_ERROR",
                detail: "script exhausted".into(),
                tx_signature: None,
            }))
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

fn rialo_err(code: &'static str, detail: &str) -> RialoError {
    RialoError {
        code,
        detail: detail.to_string(),
        tx_signature: None,
    }
}

/// Local test double for the D-TRANSPORT shim: answers the health probe
/// and counts TCP accepts. It never forwards anywhere — its only job is
/// making the pre-execution reachability decision observable.
struct TestShim {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

impl TestShim {
    fn healthy() -> Self {
        Self::with_status("200 OK")
    }
    fn with_status(status_line: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        std::thread::spawn(move || {
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 256];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 {status_line}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                        )
                        .as_bytes(),
                    );
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self { addr, accepts }
    }
    /// A bind-and-drop address: guaranteed connection-refused.
    fn dead() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
    fn wait_accepts(&self, n: usize) {
        for _ in 0..200 {
            if self.accepts() >= n {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("expected >= {n} probe accepts, saw {}", self.accepts());
    }
}

fn proxy_config() -> LatchLaneConfig {
    LatchLaneConfig {
        enabled: true,
        url_present: true,
        token_present: false,
        bearer_hosted_externally: true,
    }
}

fn dial_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

// ---------------------------------------------------------------- fixtures

struct VaultFixture {
    root: PathBuf,
    auth_dir: PathBuf,
    wallets_dir: PathBuf,
    uuid: Uuid,
    wallet_address: String,
    auth_public_key: String,
}

impl VaultFixture {
    /// Mints one wallet keypair and one funds-less auth keypair into TEMP
    /// dirs only (never real artifact/ paths) and records their pubkeys.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-i5-{}", Uuid::new_v4()));
        let auth_dir = root.join("agent_auth_keys");
        let wallets_dir = root.join("agent_wallets");
        fs::create_dir_all(&auth_dir).unwrap();
        fs::create_dir_all(&wallets_dir).unwrap();
        let uuid = Uuid::new_v4();
        let mint = |seed_byte: u8| {
            let mut seed = [seed_byte; 32];
            assert!(getrandom::getrandom(&mut seed).is_ok());
            rialo_s_keypair::keypair_from_seed(&seed).unwrap()
        };
        use rialo_s_signer::Signer;
        let wallet = mint(7);
        let auth = mint(9);
        let write_to = |path: PathBuf, kp: &rialo_s_keypair::Keypair| {
            let mut file = fs::File::options()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            rialo_s_keypair::write_keypair(kp, &mut file).unwrap();
        };
        write_to(wallets_dir.join(format!("{uuid}.json")), &wallet);
        write_to(
            crate::agent_auth_keys::auth_key_path(&auth_dir, &uuid),
            &auth,
        );
        Self {
            root,
            auth_dir,
            wallets_dir,
            uuid,
            wallet_address: wallet.pubkey().to_string(),
            auth_public_key: auth.pubkey().to_string(),
        }
    }

    fn agent(&self) -> Agent {
        Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: self.uuid.to_string(),
            owner_user_id: 7,
            name: "I5".into(),
            status: AgentStatus::Active,
            wallet_address: Some(self.wallet_address.clone()),
            auth_public_key: Some(self.auth_public_key.clone()),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn policy(&self) -> AgentPolicy {
        AgentPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            agent_id: self.uuid.to_string(),
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
        }
    }
}

impl Drop for VaultFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).ok();
    }
}

/// RialoConfig whose CLI is a temp script: it logs the `--url` it was
/// handed (line per execution) and answers with a success envelope.
struct FakeCli {
    config: Arc<RialoConfig>,
    calls: PathBuf,
}

impl FakeCli {
    fn new(rpc_url: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("agentpay-i5-cli-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let calls = dir.join("calls.log");
        let script = dir.join("rialo");
        // Plain concatenation: the success payload carries braces and
        // quotes and must NOT pass through format! escaping at all.
        let payload = "{\"signature\":\"5FakeCliSignatureAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"status\":{\"slot\":42,\"executed\":true,\"err\":null}}";
        let content = "#!/bin/sh\nurl=''\nprev=''\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"--url\" ]; then url=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nprintf 'call %s\\n' \"$url\" >> '".to_string()
            + &calls.display().to_string()
            + "'\nprintf '%s\\n' '"
            + payload
            + "'\n";
        fs::write(&script, content).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let config = Arc::new(RialoConfig {
            cli: script,
            rpc_url: rpc_url.to_string(),
            program_id: None,
            program_dir: dir.clone(),
        });
        Self { config, calls }
    }
    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.calls)
            .unwrap_or_default()
            .lines()
            .map(|l| l.to_string())
            .collect()
    }
    fn cleanup(&self) {
        if let Some(dir) = self.calls.parent() {
            fs::remove_dir_all(dir).ok();
        }
    }
}

// ---------------------------------------------------------------- A: parse contract

#[test]
fn parse_proxy_url_accepts_only_loopback_shim_bases() {
    let ok = [
        ("http://127.0.0.1:4107", "http://127.0.0.1:4107"),
        ("http://localhost:4107", "http://127.0.0.1:4107"),
        ("http://127.5.6.7:1", "http://127.5.6.7:1"),
        ("http://[::1]:4107", "http://[::1]:4107"),
    ];
    for (raw, url) in ok {
        let (got_url, addr) = parse_proxy_url(raw).unwrap_or_else(|| panic!("accept {raw}"));
        assert_eq!(got_url, url);
        assert!(addr.ip().is_loopback(), "{raw} must dial loopback");
    }
    for bad in [
        "",
        "127.0.0.1:4107",
        "https://127.0.0.1:4107",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:70000",
        "http://evil.example:4107",
        "http://93.184.216.34:4107",
        "http://10.0.0.5:4107",
        "http://[::1]",
        "http://127.0.0.1:4107/",
        "http://127.0.0.1:4107/proxy",
        "http://user@127.0.0.1:4107",
        "http://127.0.0.1:4107?x=1",
        "http://127.0.0.1:4107#f",
        "http://127.0.0.1: 4107",
    ] {
        assert!(
            parse_proxy_url(bad).is_none(),
            "must refuse {bad:?} (configuration refusal => native)"
        );
    }
}

// ---------------------------------------------------------------- A: fallback taxonomy

#[test]
fn classify_lane_error_matrix_is_structurally_pinned() {
    use TransportFailure::*;
    let cases: Vec<(RialoError, TransportFailure, &str)> = vec![
        (
            rialo_err("RIALO_CLI_UNAVAILABLE", "failed to run rialo CLI at …"),
            PreExec(PreExecReason::Availability),
            "executor binary dead = provably pre-dispatch",
        ),
        (
            rialo_err("RIALO_WALLET_ERROR", "failed to load keypair"),
            PreExec(PreExecReason::Availability),
            "signing never started = provably pre-dispatch",
        ),
        (
            rialo_err(
                "RIALO_ERROR",
                "shim replied 502 {\"class\":\"pre-forward\"}",
            ),
            PreExec(PreExecReason::Availability),
            "shim's own zero-upstream-connection proof",
        ),
        (
            rialo_err("RIALO_RPC_UNAVAILABLE", "network error: connection refused"),
            PreExec(PreExecReason::Availability),
            "no connection ever established",
        ),
        (
            rialo_err("RIALO_RPC_UNAVAILABLE", "timed out waiting for response"),
            Uncertain(UncertainOutcome),
            "RPC_UNAVAILABLE alone is NOT proof of non-dispatch",
        ),
        (
            rialo_err("RIALO_TRANSFER_CONFIRMATION_TIMEOUT", "timed out"),
            Uncertain(UncertainOutcome),
            "the single established uncertainty channel",
        ),
        (
            rialo_err(
                "RIALO_ERROR",
                "shim replied 504 {\"class\":\"post-dispatch\"}",
            ),
            Uncertain(UncertainOutcome),
            "written-but-unproven stays unknown",
        ),
        (
            rialo_err("RIALO_ERROR", "outcome unknown"),
            Uncertain(UncertainOutcome),
            "explicit unknown marker",
        ),
        (
            rialo_err(
                "RIALO_ERROR",
                "denied {\"error\":\"Request denied by policy\",\"deniedBy\":\"method_1\"}",
            ),
            Denial(DenialReason::PolicyDenied),
            "explicit latch policy refusal NEVER falls back",
        ),
        (
            rialo_err("RIALO_ERROR", "Too Many Requests — rate limited"),
            Denial(DenialReason::PolicyDenied),
            "lane rate refusal is definitive, never a rerun",
        ),
        (
            rialo_err("RIALO_ERROR", "Latch said: invalid token"),
            Denial(DenialReason::AuthRejected),
            "credential failure NEVER falls back",
        ),
        (
            rialo_err("RIALO_ERROR", "HTTP 401 unauthorized"),
            Denial(DenialReason::AuthRejected),
            "auth rejection NEVER falls back",
        ),
        (
            rialo_err(
                "RIALO_CLOCK_SKEW",
                "TimestampInFuture after bounded retries",
            ),
            Uncertain(UncertainOutcome),
            "no trustworthy pre-dispatch proof -> conservative hold",
        ),
        (
            rialo_err("RIALO_TRANSFER_ERROR", "transfer failed"),
            Uncertain(UncertainOutcome),
            "generic failure on an armed lane holds, never refunds",
        ),
    ];
    for (err, expected, note) in cases {
        assert_eq!(classify_lane_error(&err), expected, "{note}");
    }
}

// ---------------------------------------------------------------- probe honesty

#[test]
fn probe_reflects_shim_health_and_never_settles() {
    let shim = TestShim::healthy();
    let lane = Arc::new(ScriptedOps::success());
    let gw = ProxyShimGateway {
        lane: lane.clone(),
        addr: shim.addr,
    };
    assert_eq!(gw.probe(), Ok(()), "healthy shim unlocks the lane");
    assert_eq!(
        gw.submit(&LatchSubmitRequest {
            agent_id: "a".into(),
            recipient: RECIPIENT.into(),
            amount_rlo: "1.0".into(),
            policy_ir_json: "{}".into(),
            signer_reference: PathBuf::from("x.json"),
        }),
        Ok(LANE_SIG.into())
    );
    assert_eq!(
        shim.accepts(),
        1,
        "probe hit the shim once; submit itself never re-probes"
    );
    assert_eq!(lane.transfers().len(), 1, "submit delegated exactly once");

    let dead = gw_probe_dead();
    assert_eq!(
        dead.probe(),
        Err(TransportFailure::PreExec(PreExecReason::Availability)),
        "shim down is the availability class (fallback-eligible)"
    );
    let sick = TestShim::with_status("503 Service Unavailable");
    let sick_gw = ProxyShimGateway {
        lane: Arc::new(ScriptedOps::success()),
        addr: sick.addr,
    };
    assert_eq!(
        sick_gw.probe(),
        Err(TransportFailure::PreExec(PreExecReason::Availability)),
        "a shim that is not healthy cannot carry settlement"
    );
}

fn gw_probe_dead() -> ProxyShimGateway {
    ProxyShimGateway {
        lane: Arc::new(ScriptedOps::success()),
        addr: TestShim::dead(),
    }
}

#[test]
fn submit_request_fields_reach_the_lane_verbatim() {
    let shim = TestShim::healthy();
    let lane = Arc::new(ScriptedOps::success());
    let gw = ProxyShimGateway {
        lane: lane.clone(),
        addr: shim.addr,
    };
    let req = LatchSubmitRequest {
        agent_id: "agent-1".into(),
        recipient: RECIPIENT.into(),
        amount_rlo: "2.5".into(),
        policy_ir_json: "{\"filters\":[]}".into(),
        signer_reference: PathBuf::from("/tmp/wherever/kepair.json"),
    };
    assert_eq!(gw.submit(&req), Ok(LANE_SIG.into()));
    assert_eq!(
        lane.transfers(),
        vec![(
            "/tmp/wherever/kepair.json".to_string(),
            RECIPIENT.to_string(),
            "2.5".to_string()
        )],
        "path reference + recipient + amount pass through unchanged"
    );
}

// ---------------------------------------------------------------- seam matrix (armed)

fn armed_seam(
    native: Arc<ScriptedOps>,
    lane: Arc<ScriptedOps>,
    shim_addr: SocketAddr,
    binding: bool,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let binding = if binding {
        Some(LatchPolicyBinding::new(
            crate::latch_policy_compiler::compile_agent_pipeline(
                &synthetic_policy(),
                &synthetic_agent("a"),
                true,
                Lane::ProxyAvailability,
                &LatchId::new("lnk-i5-test").unwrap(),
            )
            .expect("fixture compiles"),
        ))
    } else {
        None
    };
    assemble_lane(
        native,
        lane,
        proxy_config(),
        shim_addr,
        binding.map(|b| {
            // rebind the agent id to "a" — the seam checks equality.
            b
        }),
    )
}

fn synthetic_agent(id: &str) -> Agent {
    Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: id.into(),
        owner_user_id: 7,
        name: "I5".into(),
        status: AgentStatus::Active,
        wallet_address: Some("TestWalletPubkey2222222222222222222222222222222222222222".into()),
        auth_public_key: Some("TestAuthPubkey111111111111111111111111111111".into()),
        created_at: 0,
        updated_at: 0,
    }
}

fn synthetic_policy() -> AgentPolicy {
    AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: "a".into(),
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
    }
}

#[test]
fn armed_lane_settles_on_latch_only_and_once() {
    let shim = TestShim::healthy();
    let native = Arc::new(ScriptedOps::scripted(vec![]));
    let lane = Arc::new(ScriptedOps::success());
    let ops = armed_seam(native.clone(), lane.clone(), shim.addr, true);
    let sig = ops
        .transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
        .expect("latch settlement");
    assert_eq!(sig, LANE_SIG);
    assert_eq!(lane.transfers().len(), 1);
    assert_eq!(native.transfers().len(), 0, "native must not run");
    // Second call on the SAME intent: refused through the hold channel,
    // no new dispatch on any lane (one intent = one settlement attempt).
    let err = ops
        .transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
        .expect_err("guard");
    assert_eq!(err.code, HOLD_CODE);
    assert_eq!(lane.transfers().len(), 1);
    assert_eq!(native.transfers().len(), 0);
}

#[test]
fn denials_and_uncertainty_on_the_armed_lane_never_fall_back() {
    let cases: Vec<(RialoError, &str, &str)> = vec![
        (
            rialo_err(
                "RIALO_ERROR",
                "denied: Request denied by policy deniedBy endpoint_0",
            ),
            "LATCH_POLICY_DENIED",
            "policy denial",
        ),
        (
            rialo_err("RIALO_ERROR", "invalid token"),
            "LATCH_AUTH_REJECTED",
            "auth rejection",
        ),
        (
            rialo_err("RIALO_TRANSFER_CONFIRMATION_TIMEOUT", "timed out"),
            HOLD_CODE,
            "confirmation timeout",
        ),
        (
            rialo_err("RIALO_ERROR", "shim 504 {\"class\":\"post-dispatch\"}"),
            HOLD_CODE,
            "outcome unknown",
        ),
        (
            rialo_err("RIALO_TRANSFER_ERROR", "relayed failure, no marker"),
            HOLD_CODE,
            "unprovable -> conservative hold",
        ),
    ];
    for (err, code, note) in cases {
        let shim = TestShim::healthy();
        let native = Arc::new(ScriptedOps::scripted(vec![]));
        let lane = Arc::new(ScriptedOps::scripted(vec![Err(err.clone())]));
        let ops = armed_seam(native.clone(), lane.clone(), shim.addr, true);
        let got = ops
            .transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
            .expect_err(note);
        assert_eq!(got.code, code, "{note}");
        assert_eq!(native.transfers().len(), 0, "{note} must NOT fall back");
        assert_eq!(lane.transfers().len(), 1, "{note}: one lane attempt");
    }
}

#[test]
fn unavailable_shim_pre_execution_falls_back_to_native_exactly_once() {
    // Rule 6: only pre-dispatch availability failures may route native.
    let native = Arc::new(ScriptedOps::success());
    let lane = Arc::new(ScriptedOps::scripted(vec![Err(rialo_err(
        "RIALO_RPC_UNAVAILABLE",
        "network error: connection refused",
    ))]));
    let ops = armed_seam(native.clone(), lane.clone(), TestShim::healthy().addr, true);
    assert!(
        ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    assert_eq!(lane.transfers().len(), 1, "lane attempted once");
    assert_eq!(native.transfers().len(), 1, "native ran exactly once after");
    let err = ops
        .transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
        .expect_err("guard");
    assert_eq!(err.code, HOLD_CODE);
    assert_eq!(
        native.transfers().len(),
        1,
        "still exactly one settlement attempt"
    );
}

#[test]
fn dead_shim_never_reaches_the_lane_and_settles_native_once() {
    let native = Arc::new(ScriptedOps::success());
    let lane = Arc::new(ScriptedOps::success());
    let ops = armed_seam(native.clone(), lane.clone(), TestShim::dead(), true);
    assert!(
        ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    assert_eq!(lane.transfers().len(), 0, "probe failed before any submit");
    assert_eq!(native.transfers().len(), 1);
}

#[test]
fn read_only_plane_stays_native_with_the_lane_armed() {
    let shim = TestShim::healthy();
    let native = Arc::new(ScriptedOps::success());
    let lane = Arc::new(ScriptedOps::success());
    let ops = armed_seam(native.clone(), lane.clone(), shim.addr, true);
    assert_eq!(ops.balance("addr").unwrap(), 10.0);
    assert!(matches!(ops.read_tx("s"), TxLookup::NotFound));
    assert!(ops.signatures_for_address("a", None, 1).unwrap().is_empty());
    assert_eq!(native.reads(), 3, "all reads delegated natively");
    assert_eq!(lane.transfers().len(), 0);
    assert_eq!(shim.accepts(), 0, "reads never even probe the lane");
}

// ---------------------------------------------------------------- binding fail-closed

#[test]
fn proxy_binding_is_fail_closed_on_every_identity_gap() {
    let f = VaultFixture::new();
    let lid = LatchId::new("lnk-i5-test").unwrap();

    // Positive: vault-linked active agent with an encodable policy.
    assert!(proxy_binding(&f.agent(), &f.policy(), &f.auth_dir, &lid).is_some());

    // Pre-I-1 record (no auth pubkey) -> no binding, no vault read attempt.
    let mut legacy = f.agent();
    legacy.auth_public_key = None;
    assert!(proxy_binding(&legacy, &f.policy(), &f.auth_dir, &lid).is_none());

    // Record/vault mismatch -> no binding (never a fallback key).
    let mut tampered = f.agent();
    tampered.auth_public_key = Some("SomeoneElsesPubkeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
    assert!(proxy_binding(&tampered, &f.policy(), &f.auth_dir, &lid).is_none());

    // Vault file missing -> none.
    let empty_dir = f.root.join("no_vault_here");
    assert!(proxy_binding(&f.agent(), &f.policy(), &empty_dir, &lid).is_none());

    // Non-canonical agent id -> none (choke-point rule reused).
    let mut shouty = f.agent();
    shouty.agent_id = shouty.agent_id.to_uppercase();
    let mut p = f.policy();
    p.agent_id = shouty.agent_id.clone();
    assert!(proxy_binding(&shouty, &p, &f.auth_dir, &lid).is_none());

    // Deny-only policy -> the compiler refuses -> no binding.
    let mut deny_only = f.policy();
    deny_only.allowed_recipients = vec![];
    assert!(proxy_binding(&f.agent(), &deny_only, &f.auth_dir, &lid).is_none());

    // Inactive agent -> compiler refuses.
    let mut paused = f.agent();
    paused.status = AgentStatus::Paused;
    assert!(proxy_binding(&paused, &f.policy(), &f.auth_dir, &lid).is_none());
}

// ---------------------------------------------------------------- factory

#[test]
fn factory_keeps_plain_native_ops_for_every_incomplete_configuration() {
    let f = VaultFixture::new();
    let cli = FakeCli::new("http://127.0.0.1:9"); // never dialed on native
    let native = cli.config.clone();

    // flag off -> plain native (dials the ORIGINAL rpc_url, never the shim)
    let off = LatchLaneConfig::default();
    let ops = build_production_ops(
        native.clone(),
        &off,
        Some("http://127.0.0.1:4107"),
        Some("lnk-i5-test"),
        &f.agent(),
        &f.policy(),
        &f.auth_dir,
    );
    assert!(
        ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    let calls = cli.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].contains("127.0.0.1:9"),
        "disabled lane dials the configured RPC, not any proxy: {calls:?}"
    );

    // enabled but unparsable/evil proxy URL -> plain native
    for raw in [
        "http://evil.example:4107",
        "https://127.0.0.1:4107",
        "nonsense",
    ] {
        let ops = build_production_ops(
            native.clone(),
            &proxy_config(),
            Some(raw),
            Some("lnk-i5-test"),
            &f.agent(),
            &f.policy(),
            &f.auth_dir,
        );
        assert!(
            ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
                .is_ok()
        );
    }

    // enabled + good URL but missing/invalid latch id -> plain native
    for raw_id in [None, Some("has spaces"), Some("")] {
        let ops = build_production_ops(
            native.clone(),
            &proxy_config(),
            Some("http://127.0.0.1:4107"),
            raw_id,
            &f.agent(),
            &f.policy(),
            &f.auth_dir,
        );
        assert!(
            ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
                .is_ok()
        );
    }
    cli.cleanup();
}

#[test]
fn factory_arms_the_lane_and_the_cli_dials_the_shim_only() {
    // The decisive end-to-end wiring proof at factory level: a complete,
    // capable configuration routes the settlement executor to the loopback
    // shim URL — never the original RPC, never a direct upstream dial.
    let shim = TestShim::healthy();
    let f = VaultFixture::new();
    let cli = FakeCli::new(&format!("http://127.0.0.1:{}", 4104)); // "direct" URL
    let native = cli.config.clone();
    let ops = build_production_ops(
        native.clone(),
        &proxy_config(),
        Some(&dial_url(shim.addr)),
        Some("lnk_8711f88dddfa4429"),
        &f.agent(),
        &f.policy(),
        &f.auth_dir,
    );
    let sig = ops
        .transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
        .expect("lane settlement");
    assert!(sig.starts_with("5FakeCliSignature"));
    shim.wait_accepts(1); // the health probe ran: the lane was real
    let calls = cli.calls();
    assert_eq!(calls.len(), 1, "exactly one executor run for one intent");
    assert!(
        calls[0].contains(&format!("127.0.0.1:{}", shim.addr.port())),
        "the settlement hop dialed THE SHIM: {calls:?}"
    );
    assert!(
        !calls[0].contains("4104"),
        "the proxy lane never dialed the direct RPC URL: {calls:?}"
    );

    // Binding absent (pre-I-1 agent): wrapped but native-selected, and —
    // structurally pinned by the seam — native selection skips the probe.
    let mut legacy = f.agent();
    legacy.auth_public_key = None;
    let ops = build_production_ops(
        native.clone(),
        &proxy_config(),
        Some(&dial_url(shim.addr)),
        Some("lnk_8711f88dddfa4429"),
        &legacy,
        &f.policy(),
        &f.auth_dir,
    );
    let before = shim.accepts();
    assert!(
        ops.transfer(&FsPath::new("k.json"), RECIPIENT, "1.0")
            .is_ok()
    );
    assert_eq!(shim.accepts(), before, "no binding = no probe = native");
    let calls = cli.calls();
    assert_eq!(calls.len(), 2);
    assert!(
        calls[1].contains("4104"),
        "bindingless intent used the native lane: {calls:?}"
    );
    cli.cleanup();
}

#[test]
fn proxy_env_presence_is_names_only_and_off_by_default() {
    // In a process without the operator env vars (the cargo test binary —
    // this is exactly the production default posture), the proxy lane is
    // off, and the presence model never demands a server-side token.
    let cfg = LatchLaneConfig::from_proxy_env();
    assert!(!cfg.enabled, "AGENTPAY_LATCH_LANE unset => native");
    assert!(!cfg.token_present, "the server never needs the token env");
    assert!(cfg.bearer_hosted_externally, "bearer lives with the shim");
    assert!(!cfg.config_ok());
    // Legacy enclave-era presence path is unchanged for its own lane.
    let legacy = LatchLaneConfig::from_env();
    assert!(!legacy.bearer_hosted_externally);
    assert!(!legacy.config_ok());
}

// ---------------------------------------------------------------- CORE level

#[test]
fn core_settlement_through_the_armed_lane_confirms_once_with_the_latch_path() {
    // Full frozen core, real seams, real (temp-store) signer resolution,
    // recording shim, fake CLI executor. The transfer the core performs
    // must run on the SHIM-BOUND executor exactly once and commit.
    let shim = TestShim::healthy();
    let f = VaultFixture::new();
    let cli = FakeCli::new(&dial_url(shim.addr));
    let native = Arc::new(ScriptedOps::success());
    let binding = Some(LatchPolicyBinding::new(
        crate::latch_policy_compiler::compile_agent_pipeline(
            &f.policy(),
            &f.agent(),
            true,
            Lane::ProxyAvailability,
            &LatchId::new("lnk_8711f88dddfa4429").unwrap(),
        )
        .expect("fixture compiles"),
    ));
    let ops = assemble_lane(
        native.clone(),
        cli.config.clone(),
        proxy_config(),
        shim.addr,
        binding,
    );

    let ledger = f.root.join("agent_spend");
    let intents = f.root.join("agent_payment_intents");
    fs::create_dir_all(&ledger).unwrap();
    let body = execute_agent_payment(
        ops.as_ref(),
        &f.wallets_dir,
        &ledger,
        &intents,
        &f.agent(),
        &f.policy(),
        "i5-core",
        RECIPIENT,
        1_000_000_000,
        1.0,
        NOW,
    )
    .expect("core pays through the lane");
    assert_eq!(body["success"], serde_json::json!(true));
    assert!(
        body["payment"]["signature"]
            .as_str()
            .unwrap()
            .starts_with("5FakeCliSignature")
    );
    let intent = read_intent(&intents, &f.uuid, "i5-core")
        .expect("io")
        .expect("intent exists");
    assert_eq!(intent.state, IntentState::Confirmed);
    assert_eq!(
        intent
            .signer
            .as_ref()
            .and_then(|s| s.address.clone())
            .expect("signer linkage"),
        f.wallet_address
    );
    assert_eq!(native.transfers().len(), 0, "native lane never executed");
    assert_eq!(native.reads(), 1, "the balance read stayed native");
    shim.wait_accepts(1);
    let calls = cli.calls();
    assert_eq!(calls.len(), 1, "exactly one settlement attempt");
    assert!(
        calls[0].contains(&format!("127.0.0.1:{}", shim.addr.port())),
        "core settlement dialed the shim: {calls:?}"
    );

    // Replay of the same intent key: the recorded Confirmed replays; no
    // third dispatch anywhere.
    let replay = execute_agent_payment(
        ops.as_ref(),
        &f.wallets_dir,
        &ledger,
        &intents,
        &f.agent(),
        &f.policy(),
        "i5-core",
        RECIPIENT,
        1_000_000_000,
        1.0,
        NOW,
    )
    .expect("confirmed replay");
    assert_eq!(replay["payment"]["signature"], body["payment"]["signature"]);
    assert_eq!(cli.calls().len(), 1, "replay moved no money again");

    // The signer keypair REFERENCE (path only) reached the lane executor;
    // the envelope carried it verbatim into the CLI argv (call log proves
    // the script ran; the seam's request field is asserted above).
    cli.cleanup();
}

// ---------------------------------------------------------------- A: structure

#[test]
fn proxy_lane_module_is_secretless_single_shot_and_loopback_only() {
    let src = include_str!("latch_proxy_lane.rs");
    let production = src.split("#[cfg(test)]").next().expect("test boundary");
    let code: Vec<&str> = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let joined = code.join("\n");
    // vacuity guard: the scan actually sees the gateway
    assert!(joined.contains("impl LatchGateway for ProxyShimGateway"));
    for banned in [
        "lat_",
        "ltk_",
        "Bearer",
        "Authorization",
        "LATCH_TOKEN",
        "reqwest",
        "ureq",
        "std::fs",
        "fs::",
        "File::",
        "read_keypair",
        "write_keypair",
        "from_seed",
        "privy",
        "Privy",
        "retry_with",
        "backoff",
        "for attempt",
        "Command",
        "keypair_reference",
        "agent_wallets",
        ".post(",
    ] {
        assert!(
            !joined.contains(banned),
            "proxy lane code must not reference {banned:?}"
        );
    }
    // The no-retry proof: EXACTLY ONE `.transfer(` dispatch site — a retry
    // or lane-switch would require a second one (same grammar as the shim).
    assert_eq!(
        joined.matches(".transfer(").count(),
        1,
        "submit owns the single lane dispatch"
    );
    // No env VALUE ever stored: the only env reads are the factory glue's
    // two config vars; the token env name is never mentioned in code.
    // (PHASE 9 audit: the audited factory is a SECOND call surface of the
    // SAME two names — the count scales with factories, the NAME SET does
    // not; pinned via the exact-name scan below.)
    assert_eq!(
        joined.matches("std::env::var").count(),
        4,
        "AGENTPAY_LATCH_PROXY_URL + AGENTPAY_LATCH_ID (both factory surfaces)"
    );
    assert!(
        !joined.contains("LATCH_TOKEN"),
        "token env name never in code"
    );
    // The module never names the token env constant it is forbidden to use.
    assert!(!joined.contains("ENV_TOKEN"));
    // agents.rs keeps its I-4 isolation pin even after the wiring:
    assert!(
        !include_str!("agents.rs").contains("latch_transport"),
        "agents.rs must stay transport-agnostic"
    );
}

#[test]
fn money_cores_still_own_exactly_one_transfer_call_each() {
    // I-5 wiring touches the HANDLERS only. The frozen cores keep their
    // single `ops.transfer(` site — re-pinned here at the new phase edge.
    let src = include_str!("agents.rs");
    for core_marker in [
        "pub fn execute_agent_payment(",
        "pub fn execute_agent_payment_v2(",
    ] {
        let start = src.find(core_marker).expect("core exists");
        let body = &src[start..];
        let end = find_fn_end(body);
        let core = &body[..end];
        assert_eq!(
            core.matches("ops.transfer(").count(),
            1,
            "{core_marker} must contain exactly one transfer dispatch"
        );
    }
    // And exactly two handler sites arm the lane — no third path. (PHASE 9
    // STEP 7: the money handlers arm the lane through the ISOLATED-SIGNER
    // precedence wrapper, which delegates to THIS audited factory when the
    // signer gate is off — the SAME wiring decision (two handler sites,
    // audited factory), reached through one precedence layer. The plain
    // factory stays for the I-5 contract and its own tests.)
    let armed = src
        .matches("crate::isolated_signer_lane::production_isolated_signer_ops_audited(")
        .count();
    assert_eq!(
        armed, 2,
        "owner + trigger handlers only (through the STEP 7 precedence wrapper)"
    );
    // the latch factory is invoked from EXACTLY ONE place in the HANDLER
    // FILE: nowhere (the wrapper in isolated_signer_lane.rs owns the
    // delegation point — pinned there)
    let lane_src = include_str!("isolated_signer_lane.rs");
    let delegated = lane_src
        .matches("super::latch_proxy_lane::production_payment_ops_audited(")
        .count();
    assert_eq!(
        delegated, 1,
        "the wrapper delegates to the latch factory at exactly one site"
    );
    let handler_delegated = src
        .matches("crate::latch_proxy_lane::production_payment_ops_audited(")
        .count();
    assert_eq!(
        handler_delegated, 0,
        "handlers no longer call the latch factory directly"
    );
    let plain_armed = src
        .matches("crate::latch_proxy_lane::production_payment_ops(")
        .count();
    assert_eq!(plain_armed, 0, "no un-audited handler wiring remains");
}

/// Test-local brace matcher: finds the end of a top-level `fn` body given
/// a slice that starts at the signature (strings are approximated — the
/// cores contain no brace-heavy string literals on the path, and the i4
/// `fn_body` helper is private to its own shard).
fn find_fn_end(body: &str) -> usize {
    let mut depth = 0usize;
    let mut started = false;
    for (i, ch) in body.char_indices() {
        match ch {
            '{' => {
                depth += 1;
                started = true;
            }
            '}' => {
                depth -= 1;
                if started && depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    body.len()
}
