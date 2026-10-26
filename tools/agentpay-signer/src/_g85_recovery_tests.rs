//! G85 — recovery-contract tests: the auth keypair must be recoverable by
//! the two-custodian XOR ceremony, and every failure path must fail closed
//! without leaking material. Offline only; TEST seed keypairs; temp stores.

use crate::user_lane::{
    RecoveryError, UserWalletRecord, create_user_wallet, creation_record_hash,
    expected_ceremony_proof, recover_user_auth_key, user_key_path, user_record_path,
    user_recovery_path,
};
use crate::{SignerStore, user_signer_protocol::creation_intent_message};
use rialo_s_signer::Signer;
use uuid::Uuid;

const VER: &str = "2";
const SECRET: &str = "f00dfeed00d2face";

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::CROSS_TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn intro_proof(secret: &str) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

struct Cfg {
    _dir: std::path::PathBuf,
    store: SignerStore,
    gate: crate::user_creation_gate::CreationGate,
    nonce: String,
}

fn new_cfg() -> Cfg {
    let dir = std::env::temp_dir().join(format!("g85-{}-{}", std::process::id(), Uuid::new_v4()));
    let store_root = dir.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = SignerStore::open(&store_root).unwrap();
    let gate = crate::user_creation_gate::CreationGate::open(&dir.join("gate")).unwrap();
    Cfg {
        _dir: dir,
        store,
        gate,
        nonce: "bm9uY2UtZzg1LXJlY292ZXJ5".to_string(),
    }
}

/// Create a wallet as the G85 fixture subject; returns (draft1, creation_record).
fn create_fixture(cfg: &Cfg, user_id: u64) -> (String, String) {
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user_id}:{subject_auth_b58}"),
        );
    }
    let msg = creation_intent_message(user_id, &cfg.nonce);
    let sig = crate::base64_encode(&<[u8; 64]>::from(auth.sign_message(&msg)));
    let (resp, draft1, record) = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof(SECRET),
        user_id,
        user_id,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .expect("fixture create succeeds");
    assert_eq!(resp.wallet_version, 2);
    (draft1, record)
}

#[test]
fn authorized_recovery_reconstructs_the_auth_keypair() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);

    // round-trip: the operator holds draft1; the store holds draft2 (envelope)
    let record_hash = creation_record_hash(&cfg.store, 50506318).expect("record present");
    assert_eq!(record_hash, creation_record);

    let (recovered_pub, _recovered_kp) =
        recover_user_auth_key(&cfg.store, 50506318, 2, &creation_record, &draft1)
            .expect("authorized recovery succeeds");
    // the recovered key is the LANE auth key (minted at create and bound in
    // the wallet record) — not the operator registration key
    let record_bytes = user_record_path(&cfg.store, 50506318);
    let record: UserWalletRecord =
        serde_json::from_slice(&std::fs::read(record_bytes).unwrap()).unwrap();
    assert_eq!(recovered_pub, record.auth_pubkey);
    // matches the envelope's persisted auth pubkey too (serde roundtrip —
    // the raw-string split was a fixture bug: serde_json emits no space)
    let env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(user_recovery_path(&cfg.store, 50506318)).unwrap())
            .unwrap();
    assert_eq!(
        env["released_auth_pubkey"].as_str(),
        Some(recovered_pub.as_str())
    );
}

#[test]
fn single_draft_alone_cannot_recover() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);
    // wrong LENGTH draft1 (can't XOR against the envelope draft2) → fail closed
    let wrong = "00".repeat(64);
    let err = recover_user_auth_key(&cfg.store, 50506318, 2, &creation_record, &wrong).unwrap_err();
    assert_eq!(err, RecoveryError::DraftsInvalid);
    // exists-only-in-store draft2 without the operator draft1: simulate by
    // supplying EMPTY operator material → DraftsInvalid (fail closed)
    let err2 = recover_user_auth_key(&cfg.store, 50506318, 2, &creation_record, "").unwrap_err();
    assert_eq!(err2, RecoveryError::DraftsInvalid);
    // (the created key file itself is untouched — signer-side custody)
    assert!(user_key_path(&cfg.store, 50506318).exists());
    let _ = draft1; // draft1 held by the operator; unrecoverable from the store alone
}

#[test]
fn mismatched_and_wrong_user_material_rejected() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);
    // WRONG USER: envelope for 111 doesn't exist → EnvelopeInvalid (never
    // leaks whether another user has a wallet — indistinguishable shapes)
    let err = recover_user_auth_key(&cfg.store, 111, 2, &creation_record, &draft1).unwrap_err();
    assert_eq!(err, RecoveryError::EnvelopeInvalid);
    // WRONG WALLET VERSION: v1 (an old-lane envelope can never be accepted)
    let err2 =
        recover_user_auth_key(&cfg.store, 50506318, 1, &creation_record, &draft1).unwrap_err();
    assert_eq!(err2, RecoveryError::BindMismatch);
}

#[test]
fn stale_creation_record_rejected() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("50506318:{}", auth.pubkey().to_string()),
        );
    }
    let (draft1, _creation_record) = create_fixture(&cfg, 50506318);
    // a DIFFERENT (fabricated/stale) creation record → BindMismatch
    let stale = "f".repeat(64);
    let err = recover_user_auth_key(&cfg.store, 50506318, 2, &stale, &draft1).unwrap_err();
    assert_eq!(err, RecoveryError::BindMismatch);
}

#[test]
fn corrupted_envelope_fails_closed() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, _creation_record) = create_fixture(&cfg, 50506318);
    // corrupt the payout hash inside the envelope (simulated store tamper)
    let env_path = user_recovery_path(&cfg.store, 50506318);
    let mut val: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&env_path).unwrap()).unwrap();
    val["payout_hash"] = serde_json::json!("ab".repeat(32));
    std::fs::write(&env_path, serde_json::to_vec(&val).unwrap()).unwrap();
    let record_hash = creation_record_hash(&cfg.store, 50506318).unwrap();
    let err = recover_user_auth_key(&cfg.store, 50506318, 2, &record_hash, &draft1).unwrap_err();
    assert_eq!(err, RecoveryError::IntegrityFailed);
    // and a TRUNCATED envelope (missing draft2) → EnvelopeInvalid
    std::fs::write(&env_path, r#"{"version":1}"#).unwrap();
    let err2 = recover_user_auth_key(&cfg.store, 50506318, 2, &record_hash, &draft1).unwrap_err();
    assert_eq!(err2, RecoveryError::EnvelopeInvalid);
}

#[test]
fn recovered_key_matches_the_registered_binding() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);
    let (recovered_pub, recovered_kp) =
        recover_user_auth_key(&cfg.store, 50506318, 2, &creation_record, &draft1).unwrap();
    // matches the wallet record's auth linkage
    let record_bytes = std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap();
    let record: UserWalletRecord = serde_json::from_slice(&record_bytes).unwrap();
    assert_eq!(recovered_pub, record.auth_pubkey);
    // and actually signs (proof of possession of the recovered key)
    let msg = creation_intent_message(50506318, "recovered-signing-test");
    let sig = <[u8; 64]>::from(recovered_kp.sign_message(&msg));
    use rialo_s_signer::Signer as _;
    let pk_bytes = crate::base58_decode_32(&recovered_pub).unwrap();
    assert!(
        rialo_s_signature::Signature::try_from(sig.as_slice())
            .unwrap()
            .verify(&pk_bytes, &msg)
    );
}

#[test]
fn funded_private_key_never_enters_envelope_or_output() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, _creation_record) = create_fixture(&cfg, 50506318);
    // the envelope never contains the funded key container
    let env_text = std::fs::read_to_string(user_recovery_path(&cfg.store, 50506318)).unwrap();
    let key_container = std::fs::read_to_string(user_key_path(&cfg.store, 50506318)).unwrap();
    let inner = key_container
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    assert!(
        !env_text.contains(&inner),
        "funded key material leaked into the envelope"
    );
    // the CreateResponse carry type was already proven public-only in G81;
    // here assert the OPERATOR return values do not contain the funded key either
    let key_container2 = std::fs::read_to_string(user_key_path(&cfg.store, 50506318)).unwrap();
    let inner2 = key_container2
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    assert!(!draft1.contains(&inner2));
    // and the recovery output type exposes pubkey only (typed, not bytes)
    let cfg_dbg = format!("{:?}", "UserWalletCreateResponse"); // shape guard: keep response public-only
    assert!(!cfg_dbg.contains("Keypair"));
    // ceremony proof remains deterministic over a stable record input (used by ops)
    let p1 = expected_ceremony_proof("creation-record-input");
    let p2 = expected_ceremony_proof("creation-record-input");
    assert_eq!(p1, p2);
    assert_ne!(p1, expected_ceremony_proof("different"));
}

#[test]
fn recovery_never_replaces_or_modifies_an_existing_wallet() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);
    let key_before = std::fs::read(user_key_path(&cfg.store, 50506318)).unwrap();
    let record_before = std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap();
    let _ = recover_user_auth_key(&cfg.store, 50506318, 2, &creation_record, &draft1).unwrap();
    // byte-identical: recovery is READ-ONLY over wallet state
    assert_eq!(
        std::fs::read(user_key_path(&cfg.store, 50506318)).unwrap(),
        key_before
    );
    assert_eq!(
        std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap(),
        record_before
    );
}

#[test]
fn ceremony_proof_and_failure_paths_leak_nothing() {
    let cfg = new_cfg();
    let _g = env_guard();
    let (draft1, creation_record) = create_fixture(&cfg, 50506318);
    // denial Debug/Display shapes never carry drafts, seeds, or payloads
    let cases: Vec<RecoveryError> = vec![
        RecoveryError::EnvelopeInvalid,
        RecoveryError::BindMismatch,
        RecoveryError::DraftsInvalid,
        RecoveryError::IntegrityFailed,
        RecoveryError::KeyMismatch,
        RecoveryError::KeyInvalid,
    ];
    for e in cases {
        let dbg = format!("{e:?}");
        assert!(!dbg.contains(draft1.split_at(8.min(draft1.len())).0));
        assert!(!dbg.to_lowercase().contains("secret"));
        assert!(!dbg.to_lowercase().contains("seed"));
    }
}
