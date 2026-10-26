//! G81 offline tests: NEW-user wallet provisioning in the isolated signer
//! user namespace. Synthetic keys ONLY (test stores, seeded/random temp);
//! no network, no RPC, no real funds, no broadcasts. Covers: create +
//! retry idempotency, identity binding, v2 gating, no-mint exclusion of
//! existing wallets, record/key/recovery writing, and the protocol shape.

use crate::user_lane::USER_WALLET_VERSION_V2;
use crate::user_lane::{
    UserDenial, create_user_wallet, expected_ceremony_proof, user_key_path, user_record_path,
    user_recovery_path, user_status, verify_intro_secret,
};
use crate::{SignerStore, user_lane};

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::CROSS_TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
use uuid::Uuid;

struct Cfg {
    _dir: std::path::PathBuf,
    store: SignerStore,
    gate: crate::user_creation_gate::CreationGate,
    version: String,
    secret: String,
    intro_proof: String,
    nonce: String,
}

fn new_cfg() -> Cfg {
    let dir = std::env::temp_dir().join(format!("g81-{}-{}", std::process::id(), Uuid::new_v4()));
    let store_root = dir.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = SignerStore::open(&store_root).unwrap();
    let gate = crate::user_creation_gate::CreationGate::open(&dir.join("gate")).unwrap();
    let secret = "deadbeef".repeat(8); // 64 hex chars (test fixture only)
    let intro_proof = crate::user_lane::INTRO_SECRET_DOMAIN.to_string();
    // the correct proof: blake3(INTRO_DOMAIN || secret) — computed via the
    // exported verifier for honesty; tests use a helper from the module
    let proof = {
        // reproduce the expected proof: hash(INTRO_SECRET_DOMAIN || secret)
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
        h.update(secret.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let _ = intro_proof;
    Cfg {
        _dir: dir,
        store,
        gate,
        version: USER_WALLET_VERSION_V2.to_string(),
        secret,
        intro_proof: proof,
        nonce: "bm9uY2UtZzgx".to_string(),
    }
}

/// TEST-ONLY: the subject auth key used by the G81 create tests (seeded;
/// registered via AGENTPAY_SIGNER_PROVISION_USERS by each test).
fn test_auth_keypair() -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap()
}

fn auth_pubkey_of_test() -> String {
    use rialo_s_signer::Signer;
    test_auth_keypair().pubkey().to_string()
}

fn test_sig_for(user_id: u64, nonce: &str) -> String {
    use rialo_s_signer::Signer;
    let msg = crate::user_signer_protocol::creation_intent_message(user_id, nonce);
    crate::base64_encode(&<[u8; 64]>::from(test_auth_keypair().sign_message(&msg)))
}

#[test]
fn create_provisions_wallet_and_returns_public_data_only() {
    let cfg = new_cfg();
    let _g = env_guard();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("50506318:{}", auth_pubkey_of_test()),
        );
    }
    let (resp, draft1, creation_record) = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .expect("first create succeeds");
    assert_eq!(resp.user_id, "50506318");
    assert_eq!(resp.wallet_version, 2);
    assert!(resp.recovery_envelope_stored);
    assert!(!resp.public_address.is_empty());
    assert_ne!(resp.public_address, "0");
    // public address decodes to a valid 32-byte pubkey
    assert_eq!(
        crate::base58_decode_32(&resp.public_address).unwrap().len(),
        32
    );
    // the operator gets draft1 + the creation record (recovery ceremony)
    assert!(!draft1.is_empty());
    assert!(!creation_record.is_empty());
    // the FUDENT key file exists in the signer namespace, 0600
    let key_path = user_key_path(&cfg.store, 50506318);
    assert!(key_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // the record binds identity → address
    let rec_bytes = std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap();
    let rec: crate::user_lane::UserWalletRecord = serde_json::from_slice(&rec_bytes).unwrap();
    assert_eq!(rec.public_address, resp.public_address);
    // the recovery envelope exists (write-once, 0600)
    assert!(user_recovery_path(&cfg.store, 50506318).exists());
    // the response type is PUBLIC-DATA-ONLY by construction: serialize and
    // confirm no "priv"/"secret"/"key material" field can appear
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("priv"));
    assert!(!json.contains("secret"));
    assert!(!json.contains("seed"));
}

#[test]
fn create_is_idempotent_same_identity_never_second_wallet() {
    // THE martian contract: a repeated create for the same user+identity
    // returns the SAME wallet — the first create stands (delta=first).
    let cfg = new_cfg();
    let _g = env_guard();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("50506318:{}", auth_pubkey_of_test()),
        );
    }
    let first = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .expect("first create");
    // retry → AlreadyExists (the first wallet is THE wallet; recovery is
    // operator-run, never an auto-mint of a replacement)
    let second = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_100,
        &cfg.nonce,
    );
    assert_eq!(second.unwrap_err(), UserDenial::AlreadyExists);
    // the first wallet is UNCHANGED (address + record intact)
    let rec_bytes = std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap();
    let rec: crate::user_lane::UserWalletRecord = serde_json::from_slice(&rec_bytes).unwrap();
    assert_eq!(rec.public_address, first.0.public_address);
}

#[test]
fn create_refuses_mismatched_identity() {
    let cfg = new_cfg();
    let _g = env_guard();
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        50506318, // the session user
        999,      // the DECLARED subject — mismatch
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::IdentityMismatch);
}

#[test]
fn create_requires_v2_marker_and_secret_proof() {
    let cfg = new_cfg();
    let _g = env_guard();
    // version unset / wrong → structurally absent (deny; SigningNotEnabled)
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        "1",
        &cfg.secret,
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::SigningNotEnabled);
    // v2 but empty generation secret → deny
    let err2 = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        "",
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err2, UserDenial::SigningNotEnabled);
    // wrong proof → AuthInvalid
    let err3 = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        "00",
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err3, UserDenial::AuthInvalid);
}

#[test]
fn intro_secret_verify_is_constant_and_correct() {
    let secret = "cafebabe".repeat(8);
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
    h.update(secret.as_bytes());
    let good = h.finalize().to_hex().to_string();
    assert!(verify_intro_secret(&secret, &good));
    assert!(!verify_intro_secret(&secret, "00"));
    // length-mismatch constant-time path
    assert!(!verify_intro_secret(&secret, ""));
}

#[test]
fn ceremony_proof_is_deterministic_and_bound() {
    let p1 = expected_ceremony_proof("creation-record-1");
    let p2 = expected_ceremony_proof("creation-record-1");
    let p3 = expected_ceremony_proof("creation-record-2");
    assert_eq!(p1, p2, "same record → same ceremony proof");
    assert_ne!(p1, p3, "different record → different proof");
}

#[test]
fn existing_v1_style_record_blocks_create() {
    // an EXISTING registered user (import ceremony) is EXCLUDED from the
    // new-create path: the operator-owned record must never be rewritten
    let cfg = new_cfg();
    let _g = env_guard();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("50506318:{}", auth_pubkey_of_test()),
        );
    }
    // simulate the import ceremony state (record + key) WITHOUT minting
    let ns = cfg.store.root().join("users");
    std::fs::create_dir_all(&ns).unwrap();
    std::fs::write(
        ns.join("50506318.wallet.json"),
        serde_json::to_vec(&crate::user_lane::UserWalletRecord {
            user_id: 50506318,
            public_address: "From1111111111111111111111111111111111111111".into(),
            auth_pubkey: "Auth1111111111111111111111111111111111111111".into(),
        })
        .unwrap(),
    )
    .unwrap();
    // the KEY container also exists (a fully-imported v1 wallet)
    std::fs::write(
        ns.join("50506318.key.json"),
        serde_json::to_vec(&vec![7u8; 64]).unwrap(),
    )
    .unwrap();
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        50506318,
        50506318,
        &test_sig_for(50506318, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::AlreadyExists);
}

#[test]
fn created_wallet_visible_in_status_and_independent_of_v1() {
    // a created (v2) wallet is Fully distinguishable from the imported
    // v1 world: the status endpoint reflects the signer-side state only.
    let cfg = new_cfg();
    let _g = env_guard();
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("424242:{}", auth_pubkey_of_test()),
        );
    }
    let (resp, _d1, _record) = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        &cfg.version,
        &cfg.secret,
        &cfg.intro_proof,
        424242,
        424242,
        &test_sig_for(424242, &cfg.nonce),
        1_700_000_000,
        &cfg.nonce,
    )
    .expect("create user 424242");
    let st = user_status(&cfg.store, &cfg._dir.join("policies"), 424242);
    assert!(st.registered);
    assert_eq!(
        st.public_address.as_deref(),
        Some(resp.public_address.as_str())
    );
    assert_eq!(st.key_container_state, "linked");
    // a DIFFERENT user has no wallet at all (no cross-contamination)
    let st_other = user_status(&cfg.store, &cfg._dir.join("policies"), 777);
    assert!(!st_other.registered);
}
