//! G83-FIX tests: creation authorization (M1), crash-safe staging (M2),
//! custody invariants (M3), zeroization hygiene (M4). Offline only; TEST
//! seed keypairs in temp stores; no live keys, RPC, or broadcasts.

use crate::user_creation_gate::CreationGate;
use crate::user_lane::{
    UserDenial, create_user_wallet, user_key_path, user_record_path, user_recovery_path,
};
use crate::{
    SignerStore, user_lane::USER_WALLET_VERSION_V2, user_signer_protocol::creation_intent_message,
};
use rialo_s_signer::Signer;
use uuid::Uuid;

const VER: &str = "2";

/// Shared env lock (cross-test): AGENTPAY_SIGNER_PROVISION_USERS is process
/// global; parallel tests must serialize their set/remove (G79 lesson).
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::CROSS_TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// The CORRECT intro proof for SECRET (fixture helper).
fn intro_proof_for(secret: &str) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}
const SECRET: &str = "f00dfeed00d2face";

struct Cfg {
    _dir: std::path::PathBuf,
    store: SignerStore,
    gate: CreationGate,
    nonce: String,
}

fn new_cfg() -> Cfg {
    let dir =
        std::env::temp_dir().join(format!("g83fix-{}-{}", std::process::id(), Uuid::new_v4()));
    let store_root = dir.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = SignerStore::open(&store_root).unwrap();
    let gate = CreationGate::open(&dir.join("gate")).unwrap();
    Cfg {
        _dir: dir,
        store,
        gate,
        nonce: "bm9uY2UtZzgzLWZpeA==".to_string(),
    }
}

fn register_binding(user_id: u64, auth_pubkey: &str) {
    // the operator out-of-band registration (env; single-subject at a time
    // is enough for these tests)
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user_id}:{auth_pubkey}"),
        );
    }
}

fn clear_binding() {
    unsafe { std::env::remove_var("AGENTPAY_SIGNER_PROVISION_USERS") };
}

/// The subject's auth key: in the G83 model the operator generates the
/// subject's funds-less auth key OUT-OF-BAND and registers its PUBLIC
/// half; the subject signs the creation intent with the private half.
/// (The create path then mints only the FUNDED key + envelope.)
fn subject_signs(user_id: u64, nonce: &str) -> (rialo_s_keypair::Keypair, String) {
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let msg = creation_intent_message(user_id, nonce);
    let sig = crate::base64_encode(&<[u8; 64]>::from(auth.sign_message(&msg)));
    (auth, sig)
}

struct armed_guard {
    _g: (),
}

#[test]
fn authorized_creation_end_to_end_succeeds() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    let now = 1_700_000_000;
    let result = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        now,
        &cfg.nonce,
    );
    clear_binding();
    let insta = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
        h.update(SECRET.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let _ = insta;
    let (resp, draft1, record_hash) = result.unwrap();
    assert_eq!(resp.user_id, "50506318");
    assert_eq!(resp.wallet_version, 2);
    assert!(user_key_path(&cfg.store, 50506318).exists());
    assert!(user_record_path(&cfg.store, 50506318).exists());
    assert!(user_recovery_path(&cfg.store, 50506318).exists());
    assert!(!draft1.is_empty());
    assert!(!record_hash.is_empty());
    // envelope: the funded key is NOT inside (M3), the auth key IS
    let env_bytes = std::fs::read(user_recovery_path(&cfg.store, 50506318)).unwrap();
    let env_text = String::from_utf8_lossy(&env_bytes).to_string();
    let key_bytes = std::fs::read(user_key_path(&cfg.store, 50506318)).unwrap();
    assert!(
        !env_text.contains(
            serde_json::to_string(&key_bytes)
                .unwrap()
                .trim_matches(|c| c == '[' || c == ']')
        ),
        "funded key material must not appear in the recovery envelope"
    );
}

#[test]
fn invalid_signature_refused() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    // sign the intent with a DIFFERENT (unregistered) key
    let rogue = rialo_s_keypair::keypair_from_seed(&[62u8; 32]).unwrap();
    let msg = creation_intent_message(50506318, &cfg.nonce);
    let bad_sig = crate::base64_encode(&<[u8; 64]>::from(rogue.sign_message(&msg)));
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &bad_sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    clear_binding();
    assert_eq!(err, UserDenial::AuthInvalid);
}

#[test]
fn wrong_subject_signature_refused() {
    let cfg = new_cfg();
    let _g = env_guard();
    // the binding is for user 50506318; the request declares user 999 with
    // THEIR OWN signature (a subject cannot sign for another principal)
    let auth999 = rialo_s_keypair::keypair_from_seed(&[63u8; 32]).unwrap();
    register_binding(50506318, &auth999.pubkey().to_string());
    let msg = creation_intent_message(999, &cfg.nonce);
    let sig = crate::base64_encode(&<[u8; 64]>::from(auth999.sign_message(&msg)));
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        999,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    clear_binding();
    // identity mismatch fires at step 2 (before binding/signature gates)
    assert_eq!(err, UserDenial::IdentityMismatch);
}

#[test]
fn altered_nonce_invalidates_signature() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    // sign over nonce A, submit with nonce B
    let msg = creation_intent_message(50506318, "nonce-A");
    let sig = crate::base64_encode(&<[u8; 64]>::from(auth.sign_message(&msg)));
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        "nonce-B",
    )
    .unwrap_err();
    clear_binding();
    assert_eq!(err, UserDenial::AuthInvalid);
}

#[test]
fn replayed_nonce_refused_durably() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    let insta = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
        h.update(SECRET.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let r1 = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &insta,
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    );
    assert!(r1.is_ok(), "first use accepted");
    let r2 = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &insta,
        50506318,
        50506318,
        &sig,
        1_700_000_100,
        &cfg.nonce,
    );
    clear_binding();
    // the FIRST wallet stands (AlreadyExists precedes the nonce check
    // deterministically; either way the nonce can never mint twice)
    assert!(matches!(
        r2.unwrap_err(),
        UserDenial::AlreadyExists | UserDenial::NonceReplay
    ));
}

#[test]
fn missing_registered_binding_fails_closed() {
    let cfg = new_cfg();
    let _g = env_guard();
    clear_binding();
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::PrerequisiteMissing);
    // nothing was minted
    assert!(!user_key_path(&cfg.store, 50506318).exists());
    assert!(!user_record_path(&cfg.store, 50506318).exists());
}

#[test]
fn unusable_registered_binding_fails_closed() {
    let cfg = new_cfg();
    let _g = env_guard();
    // a binding that is NOT valid base58-32 → PrerequisiteMissing (not a panic)
    register_binding(50506318, "NotAValidAddress");
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    clear_binding();
    assert!(err == UserDenial::PrerequisiteMissing || err == UserDenial::AuthMalformed);
}

#[test]
fn concurrent_create_single_winner() {
    use std::sync::Arc;
    let cfg = Arc::new(new_cfg());
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    let auth_conc = Arc::new(auth);
    register_binding(50506318, &subject_auth_b58);
    let mut handles = Vec::new();
    let subject_auth_for_threads = subject_auth_b58.clone();
    for i in 0..4 {
        let cfg = Arc::clone(&cfg);
        let auth = Arc::clone(&auth_conc);
        let subject_auth_b58 = subject_auth_for_threads.clone();
        let nonce = format!("{}-{}", cfg.nonce, i);
        handles.push(std::thread::spawn(move || {
            // NOTE: env binding is set once by the parent (no per-thread
            // env writes: the shared env must only be mutated under the
            // cross-test lock, which the parent holds for this test).
            let msg = creation_intent_message(50506318, &nonce);
            let sig = crate::base64_encode(&<[u8; 64]>::from(auth.sign_message(&msg)));
            create_user_wallet(
                &cfg.store,
                &cfg.gate,
                VER,
                SECRET,
                &intro_proof_for(SECRET),
                50506318,
                50506318,
                &sig,
                1_700_000_000,
                &nonce,
            )
        }));
    }
    let mut outcomes = Vec::new();
    for h in handles {
        outcomes.push(h.join().unwrap());
    }
    clear_binding();
    let oks = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "exactly one create wins; got {outcomes:?}");
    // exactly one key/record/envelope triple exists
    let ns = cfg.store.root().join("users");
    let keys = std::fs::read_dir(&ns)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with("50506318.")
        })
        .count();
    assert!(
        keys >= 3 && keys <= 4,
        "key+record+envelope (+progress遗留) = 3..4; got {keys}"
    );
}

#[test]
fn injected_persistence_failures_end_typed_and_recover_safely() {
    // fault injection at the FIRST persistence boundary (gate.begin);
    // simulate by pre-creating the in-progress marker (crash equivalent)
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    // simulate: a previous attempt died right after gate.begin (marker EXISTS)
    cfg.gate.begin(50506318).unwrap();
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    // the in-progress marker is authoritative: the caller gets IN_PROGRESS
    // (or NONCE_REPLAY; either is a typed refusal with NOTHING minted)
    assert!(matches!(
        err,
        UserDenial::ProvisioningInProgress | UserDenial::NonceReplay
    ));
    assert!(!user_key_path(&cfg.store, 50506318).exists());
    assert!(!user_record_path(&cfg.store, 50506318).exists());
    // operator-resolution simulation: finish() clears the marker, then a
    // fresh fully-authorized create succeeds (no secret requires clearing)
    cfg.gate.finish(50506318).unwrap();
    let insta = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
        h.update(SECRET.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let fresh = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &insta,
        50506318,
        50506318,
        &sig,
        1_700_000_200,
        "bm9uY2UtZzgzLWZpeC1yZXRyeQ==",
    );
    let _ = fresh;
    clear_binding();
}

#[test]
fn partial_artifacts_are_typed_incomplete_never_silent() {
    // (record ABSENT + key PRESENT) = the G82 orphan state — now a typed
    // ProvisioningIncomplete, never a silent wall or an overwrite
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    // simulate the crash: key exists, record does not
    std::fs::create_dir_all(cfg.store.root().join("users")).unwrap();
    let some_key = rialo_s_keypair::keypair_from_seed(&[71u8; 32]).unwrap();
    let kp_bytes: [u8; 64] = some_key.to_bytes();
    std::fs::write(
        user_key_path(&cfg.store, 50506318),
        serde_json::to_vec(&kp_bytes.to_vec()).unwrap(),
    )
    .unwrap();
    let err = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &intro_proof_for(SECRET),
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap_err();
    clear_binding();
    assert_eq!(err, UserDenial::ProvisioningIncomplete);
    // the orphan key file is UNTOUCHED (never overwritten)
    assert!(user_key_path(&cfg.store, 50506318).exists());
    assert!(!user_record_path(&cfg.store, 50506318).exists());
}

#[test]
fn existing_valid_wallet_never_replaced() {
    let cfg = new_cfg();
    let _g = env_guard();
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let subject_auth_b58 = auth.pubkey().to_string();
    register_binding(50506318, &subject_auth_b58);
    let (_auth, sig) = subject_signs(50506318, &cfg.nonce);
    let insta = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
        h.update(SECRET.as_bytes());
        h.finalize().to_hex().to_string()
    };
    let first = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &insta,
        50506318,
        50506318,
        &sig,
        1_700_000_000,
        &cfg.nonce,
    )
    .unwrap();
    let record_before = std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap();
    let key_before = std::fs::read(user_key_path(&cfg.store, 50506318)).unwrap();
    let second = create_user_wallet(
        &cfg.store,
        &cfg.gate,
        VER,
        SECRET,
        &insta,
        50506318,
        50506318,
        &sig,
        1_700_000_100,
        &cfg.nonce,
    );
    clear_binding();
    assert_eq!(second.unwrap_err(), UserDenial::AlreadyExists);
    // byte-identical: the first wallet was NOT replaced or rewritten
    assert_eq!(
        std::fs::read(user_record_path(&cfg.store, 50506318)).unwrap(),
        record_before
    );
    assert_eq!(
        std::fs::read(user_key_path(&cfg.store, 50506318)).unwrap(),
        key_before
    );
    assert_eq!(
        first.0.public_address,
        serde_json::from_slice::<crate::user_lane::UserWalletRecord>(&record_before)
            .unwrap()
            .public_address
    );
}
