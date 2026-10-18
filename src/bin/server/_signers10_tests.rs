//! PHASE 8 Item 10 — focused tests for the rialo_tx_signers boundary.
//! All stores are fresh std::env::temp_dir() subtrees; the real
//! artifact/ tree is never opened. Keypair files here are test-only
//! seeds; their bytes are never read back, printed, or asserted on —
//! only public addresses and path/naming behavior.

use super::*;
use crate::agents::{
    AGENT_SCHEMA_VERSION, Agent, AgentPolicy, AgentStatus, POLICY_SCHEMA_VERSION, PaymentFailure,
    PaymentOps, execute_agent_payment, execute_agent_payment_v2, read_intent, read_intent_v2,
};
use crate::rialo::{RialoError, SignatureInfoRecord, TxLookup};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const USER_ID: u64 = 50506084;
const NOW: i64 = 1_760_000_000;
const PAY_TX: u64 = 5_000_000_000; // 5 RLO
const PAY_DAY: u64 = 20_000_000_000; // 20 RLO

struct Fixture {
    root: PathBuf,
    agents: PathBuf,
    wallets: PathBuf,
    user_wallets: PathBuf,
    ledger: PathBuf,
    intents: PathBuf,
    uuid: Uuid,
    address: String,
    agent: Agent,
    policy: AgentPolicy,
}

/// Mint a REAL keypair file (test dirs only) so public-address
/// verification exercises the genuine container format.
fn mint_wallet(dir: &PathBuf, id: &Uuid) -> String {
    fs::create_dir_all(dir).unwrap();
    let mut seed = [0u8; 32];
    assert!(getrandom::getrandom(&mut seed).is_ok());
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
    let path = dir.join(format!("{id}.json"));
    let mut file = fs::File::options()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    rialo_s_keypair::write_keypair(&keypair, &mut file).unwrap();
    drop(file);
    use rialo_s_signer::Signer;
    keypair.pubkey().to_string()
}

fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!("agentpay-signers10-{}", Uuid::new_v4()));
    let agents = root.join("agents");
    let wallets = root.join("agent_wallets");
    let user_wallets = root.join("wallets");
    let ledger = root.join("agent_spend");
    let intents = root.join("agent_payment_intents");
    fs::create_dir_all(&agents).unwrap();
    fs::create_dir_all(&user_wallets).unwrap();
    let sentinel = user_wallets.join(format!("{USER_ID}.json"));
    fs::write(&sentinel, b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE").unwrap();

    let uuid = Uuid::new_v4();
    let address = mint_wallet(&wallets, &uuid);
    let agent = Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: uuid.to_string(),
        owner_user_id: 7,
        name: "Pay".into(),
        status: AgentStatus::Active,
        wallet_address: Some(address.clone()),
        auth_public_key: None,
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
    Fixture {
        root,
        agents,
        wallets,
        user_wallets,
        ledger,
        intents,
        uuid,
        address,
        agent,
        policy,
    }
}

impl Fixture {
    fn cleanup(&self) {
        fs::remove_dir_all(&self.root).ok();
    }
    fn user_wallet_untouched(&self) {
        let sentinel = self.user_wallets.join(format!("{USER_ID}.json"));
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE",
            "user wallet bytes changed"
        );
        assert_eq!(fs::read_dir(&self.user_wallets).unwrap().count(), 1);
    }
}

struct FakeOps {
    calls: Mutex<Vec<(String, String, String)>>,
}
impl FakeOps {
    fn new() -> Self {
        FakeOps {
            calls: Mutex::new(Vec::new()),
        }
    }
    fn transfers(&self) -> Vec<(String, String, String)> {
        self.calls.lock().unwrap().clone()
    }
}
impl PaymentOps for FakeOps {
    fn balance(&self, _address: &str) -> Result<f64, RialoError> {
        Ok(10.0)
    }
    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError> {
        self.calls.lock().unwrap().push((
            keypair_path.display().to_string(),
            to.into(),
            amount_rlo.into(),
        ));
        Ok("5FakeSignature111111111111111111111111111111111111111".into())
    }
    fn read_tx(&self, _signature: &str) -> TxLookup {
        TxLookup::NotFound
    }
    fn signatures_for_address(
        &self,
        _address: &str,
        _until: Option<&str>,
        _limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
        Ok(vec![])
    }
}

fn pay(f: &Fixture, ops: &FakeOps, key: &str) -> Result<serde_json::Value, PaymentFailure> {
    execute_agent_payment(
        ops,
        &f.wallets,
        &f.ledger,
        &f.intents,
        &f.agent,
        &f.policy,
        key,
        RECIPIENT,
        1_000_000_000,
        1.0,
        NOW,
    )
}

fn pay_v2(f: &Fixture, ops: &FakeOps, key: &str) -> Result<serde_json::Value, PaymentFailure> {
    execute_agent_payment_v2(
        ops,
        &f.wallets,
        &f.ledger,
        &f.intents,
        &f.agent,
        &f.policy,
        key,
        RECIPIENT,
        1_000_000_000,
        1.0,
        NOW,
    )
}

// ---------------------------------------------------------------- identity

#[test]
fn identity_is_canonical_and_rejects_every_noncanonical_form() {
    let id = Uuid::new_v4();
    let ok = TxSigner::for_agent_record(&id.to_string(), "Addr123").unwrap();
    assert_eq!(
        ok,
        TxSigner::Agent {
            agent_id: id,
            address: "Addr123".into()
        }
    );

    for bad_id in [
        id.to_string().to_uppercase(),
        format!("{{{id}}}"),
        format!("urn:uuid:{id}"),
        id.to_string().replace('-', ""),
        "6fa459ea-ee8a-3ca4-894e-db77e160355e".into(), // v1, not v4
        "not-a-uuid".into(),
        "../../etc/passwd".into(),
    ] {
        assert_eq!(
            TxSigner::for_agent_record(&bad_id, "Addr123"),
            Err(SignerError::InvalidReference),
            "accepted non-canonical id: {bad_id}"
        );
    }
    for bad_addr in ["", "   ", "\t\n"] {
        assert_eq!(
            TxSigner::for_agent_record(&id.to_string(), bad_addr),
            Err(SignerError::InvalidReference)
        );
    }
}

#[test]
fn signer_kinds_never_conflate_with_agent_credential_or_user_identity() {
    let id = Uuid::new_v4();
    let agent = TxSigner::for_agent_record(&id.to_string(), "Addr123").unwrap();
    let user = TxSigner::for_user(USER_ID);
    assert_ne!(agent, user);
    assert_eq!(agent.kind(), "agent_wallet");
    assert_eq!(user.kind(), "user_wallet");
    assert_eq!(agent.public_address(), Some("Addr123"));
    assert_eq!(user.public_address(), None);

    let dir = std::env::temp_dir().join(format!("agentpay-signers10-naming-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    // The two kinds reference DIFFERENT filenames; neither creates files.
    let a_ref = agent.keypair_reference(&dir);
    let u_ref = user.keypair_reference(&dir);
    assert!(a_ref.ends_with(format!("{id}.json")));
    assert!(u_ref.ends_with(format!("{USER_ID}.json")));
    assert!(
        !a_ref.exists() && !u_ref.exists(),
        "reference is a pure join"
    );
    fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------- linkage

#[test]
fn confirmed_v1_intent_records_the_signer_that_produced_the_signature() {
    let f = fixture();
    let ops = FakeOps::new();
    pay(&f, &ops, "k-link").unwrap();

    let calls = ops.transfers();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        f.wallets
            .join(format!("{}.json", f.uuid))
            .display()
            .to_string(),
        "transfer must be signed by exactly the signer's keypair reference"
    );

    let intent = read_intent(&f.intents, &f.uuid, "k-link").unwrap().unwrap();
    let signer = intent.signer.expect("confirmed intent carries its signer");
    assert_eq!(signer.kind, "agent_wallet");
    assert_eq!(signer.address.as_deref(), Some(f.address.as_str()));
    assert_eq!(intent.agent_id, f.uuid.to_string());
    let body = intent
        .response
        .expect("confirmed response carries the signature");
    assert_eq!(
        body["payment"]["signature"].as_str().unwrap(),
        "5FakeSignature111111111111111111111111111111111111111"
    );
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn confirmed_v2_intent_records_the_signer_alongside_tx_signature() {
    let f = fixture();
    let ops = FakeOps::new();
    pay_v2(&f, &ops, "k-link2").unwrap();
    assert_eq!(ops.transfers().len(), 1);

    let intent = read_intent_v2(&f.intents, &f.uuid, "k-link2")
        .unwrap()
        .unwrap();
    let signer = intent
        .signer
        .expect("confirmed v2 intent carries its signer");
    assert_eq!(signer.kind, "agent_wallet");
    assert_eq!(signer.address.as_deref(), Some(f.address.as_str()));
    assert!(intent.tx_signature.is_some());
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn signer_record_schema_is_minimal_and_secret_free() {
    let f = fixture();
    let ops = FakeOps::new();
    pay(&f, &ops, "k-schema").unwrap();
    let raw = fs::read_dir(&f.intents)
        .unwrap()
        .filter_map(|e| e.ok())
        .flat_map(|e| fs::read_dir(e.path()).ok())
        .flatten()
        .filter_map(|e| e.ok())
        .flat_map(|e| fs::read_to_string(e.path()).ok())
        .find(|s| s.contains("k-schema"))
        .expect("intent file on disk");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let mut keys: Vec<&String> = v["signer"].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["address", "kind"],
        "signer record fields drifted"
    );
    assert!(!raw.contains("PRIVATE") && v["signer"]["address"] != serde_json::Value::Null);
    f.cleanup();
}

// ---------------------------------------------------------- failure modes

#[test]
fn missing_signer_file_aborts_before_transfer_without_fallback() {
    let f = fixture();
    fs::remove_file(f.wallets.join(format!("{}.json", f.uuid))).unwrap();
    let ops = FakeOps::new();
    let err = pay(&f, &ops, "k-missing").expect_err("must fail");
    assert!(matches!(err, PaymentFailure::WalletStore));
    assert!(
        ops.transfers().is_empty(),
        "no transfer may run without its signer"
    );
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn invalid_reference_aborts_before_transfer() {
    let mut f = fixture();
    f.agent.wallet_address = Some("  ".into()); // corrupt public identity
    let ops = FakeOps::new();
    let err = pay(&f, &ops, "k-invalid").expect_err("must fail");
    assert!(matches!(err, PaymentFailure::WalletStore));
    assert!(ops.transfers().is_empty());
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn signer_mismatch_aborts_and_never_signs_with_the_foreign_key() {
    let f = fixture();
    // Replace the agent's wallet file with a DIFFERENT minted keypair:
    // the recorded address and the file no longer belong together.
    let other = Uuid::new_v4();
    let other_addr = mint_wallet(&f.root.join("foreign").join("agent_wallets"), &other);
    let target = f.wallets.join(format!("{}.json", f.uuid));
    fs::remove_file(&target).unwrap();
    fs::rename(
        f.root
            .join("foreign")
            .join("agent_wallets")
            .join(format!("{other}.json")),
        &target,
    )
    .unwrap();

    // boundary-level verdict
    let signer = TxSigner::for_agent_record(&f.agent.agent_id, &f.address).unwrap();
    assert_eq!(
        verify_agent_public_address(&signer, &f.wallets),
        Err(SignerError::Mismatch)
    );
    assert_ne!(other_addr, f.address, "fixture sanity");

    // core-level verdict: the money core must refuse, not sign with it
    let ops = FakeOps::new();
    let err = pay(&f, &ops, "k-mismatch").expect_err("must fail");
    assert!(matches!(err, PaymentFailure::WalletStore));
    assert!(ops.transfers().is_empty(), "mismatch must never fall back");
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn unparseable_keypair_container_is_unavailable_not_bypassed() {
    let f = fixture();
    fs::write(f.wallets.join(format!("{}.json", f.uuid)), b"not-a-keypair").unwrap();
    let signer = TxSigner::for_agent_record(&f.agent.agent_id, &f.address).unwrap();
    assert_eq!(
        verify_agent_public_address(&signer, &f.wallets),
        Err(SignerError::Unavailable)
    );
    let ops = FakeOps::new();
    assert!(pay(&f, &ops, "k-garbage").is_err());
    assert!(ops.transfers().is_empty());
    f.cleanup();
}

// ------------------------------------------------------------ boundary law

#[test]
fn authorization_gates_run_before_the_signer_boundary() {
    let f = fixture();
    let ops = FakeOps::new();
    // recipient not on the allow-list: policy denial, signer never consulted
    let err = execute_agent_payment(
        &ops,
        &f.wallets,
        &f.ledger,
        &f.intents,
        &f.agent,
        &f.policy,
        "k-order",
        "OtherRecipientAddress0000000000000000000000",
        1_000_000_000,
        1.0,
        NOW,
    )
    .expect_err("policy must deny");
    assert!(matches!(err, PaymentFailure::Enforcement(_)), "got {err:?}");
    assert!(ops.transfers().is_empty());
    f.cleanup();
}

#[test]
fn agent_core_cannot_be_pointed_at_the_user_store() {
    let f = fixture();
    // Even naming the user wallets dir, the agent signer resolves by its
    // UUID filename only — the user sentinel is a different name and the
    // boundary reports NotFound rather than touching it.
    let signer = TxSigner::for_agent_record(&f.agent.agent_id, &f.address).unwrap();
    assert_eq!(
        verify_agent_public_address(&signer, &f.user_wallets),
        Err(SignerError::NotFound)
    );
    // A user signer asked to pass the AGENT verification is refused outright.
    assert_eq!(
        verify_agent_public_address(&TxSigner::for_user(USER_ID), &f.user_wallets),
        Err(SignerError::Mismatch)
    );
    f.user_wallet_untouched();
    f.cleanup();
}

#[test]
fn module_source_carries_no_private_key_machinery() {
    // The boundary reads public identity only. It must never mint, write,
    // or seed keypairs (that is provisioning's frozen job), and must never
    // name artifact paths.
    let src = include_str!("rialo_tx_signers.rs");
    for forbidden in [
        "write_keypair",
        "keypair_from_seed",
        "getrandom",
        "seed",
        "\"artifact\"",
        "artifact/",
        "wallets\\\"",
        "mnemonic",
        "secret",
    ] {
        // strip the doc-comment lines first: prose may name the concepts
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains(forbidden),
            "signer code references {forbidden}"
        );
    }
    // I-6 boundary: verification reads the PUBLIC half only through the
    // strict pubkey-only reader. read_keypair (which materializes the
    // full Keypair incl. the secret) is forbidden in this module.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains(".sign("),
        "server-side signing is forbidden here"
    );
    assert!(
        !code.contains("read_keypair"),
        "verification must never materialize the private half (I-6)"
    );
    assert!(
        !code.contains("SigningKey"),
        "no signing key may be constructed in the verification path (I-6)"
    );
    assert!(
        code.contains("read_pubkey_address_only"),
        "verification must use the strict pubkey-only reader (I-6)"
    );
}
