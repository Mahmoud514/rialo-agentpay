//! G79 offline test shard for the user signer lane. Runtime-free (no HTTP,
//! no RPC): exercises the signer-side user-namespace chain end to end with
//! TEST-ONLY synthetic keypairs (never real funds, never moved anywhere).
//! The env arm/remove pairs below run under `--test-threads=1` semantics via
//! the crate's own env-lock convention; CI runs this crate serially.

use crate::rialo_canonical::{CanonicalTransferSpec, build_canonical_message};
use crate::user_lane::{
    UserDenial, register_user_wallet, sign_user_transaction, user_key_path, user_record_path,
    user_status,
};
use crate::user_signer_protocol::{
    UserAuthEnvelope, UserAuthRef, UserSemanticTransaction, UserSignRequest, UserSignResponse,
};
use crate::{SignerStore, base58_decode_32, base64_decode, base64_encode};
use rialo_s_signer::Signer;
use uuid::Uuid;

const ARM_ENV: &str = "AGENTPAY_SIGNER_SIGNING_ENABLED";

/// THE crate-wide env lock (shared with the lib's STEP-6 battery): a
/// private lock here let two batteries toggle the same env var concurrently
/// and corrupt each other. Every env toggle in this shard holds it.
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::CROSS_TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Fixture {
    _dir: std::path::PathBuf,
    store: SignerStore,
    policy_dir: std::path::PathBuf,
    user_id: u64,
    payer_b58: String,
    recipient_b58: String,
    /// a VALID base58 address that is NOT the registered payer and NOT in
    /// the allow-list (for payer/recipient mismatch tests)
    stranger_b58: String,
    auth_keypair: rialo_s_keypair::Keypair,
    auth_pubkey_b58: String,
}

fn fixture() -> Fixture {
    let dir =
        std::env::temp_dir().join(format!("g79lane-{}-{}", std::process::id(), Uuid::new_v4()));
    let store_root = dir.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = SignerStore::open(&store_root).unwrap();
    // TEST-ONLY synthetic keys (deterministic seeds; never real material)
    let auth = rialo_s_keypair::keypair_from_seed(&[9u8; 32]).unwrap();
    let auth_pubkey_b58 = auth.pubkey().to_string();
    let user_key = rialo_s_keypair::keypair_from_seed(&[7u8; 32]).unwrap();
    let payer_b58 = user_key.pubkey().to_string();
    let recipient_key = rialo_s_keypair::keypair_from_seed(&[21u8; 32]).unwrap();
    let recipient_b58 = recipient_key.pubkey().to_string();
    let stranger_key = rialo_s_keypair::keypair_from_seed(&[41u8; 32]).unwrap();
    let stranger_b58 = stranger_key.pubkey().to_string();
    // place the FUNDED key container (the operator-ceremony equivalent)
    let key_path = user_key_path(&store, 50506318);
    let kp_bytes: [u8; 64] = user_key.to_bytes();
    std::fs::write(&key_path, serde_json::to_vec(&kp_bytes.to_vec()).unwrap()).unwrap();
    // the operator policy for the user (bound to the auth linkage)
    let policy_dir = dir.join("policies");
    std::fs::create_dir_all(&policy_dir).unwrap();
    let policy = crate::user_policy::UserPolicyRecord {
        user_id: 50506318,
        auth_pubkey: auth_pubkey_b58.clone(),
        max_per_tx_kelvin: 100_000,
        recipients: vec![
            payer_b58.clone(),
            recipient_b58.clone(),
            "Other1111111111111111111111111111111111111111".to_string(),
        ],
    };
    std::fs::write(
        policy_dir.join("50506318.policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    // the public registration (the ceremony's verified step)
    register_user_wallet(&store, 50506318, &payer_b58, &auth_pubkey_b58).unwrap();
    Fixture {
        _dir: dir,
        store,
        policy_dir,
        user_id: 50506318,
        payer_b58,
        recipient_b58,
        stranger_b58,
        auth_keypair: auth,
        auth_pubkey_b58,
    }
}

fn request_bytes(f: &Fixture, now_ms: i64, recipient: &str, amount: u64) -> Vec<u8> {
    let from = base58_decode_32(&f.payer_b58).unwrap();
    let to = base58_decode_32(recipient).unwrap();
    let canonical = build_canonical_message(&CanonicalTransferSpec {
        from: &from,
        to: &to,
        amount_kelvin: amount,
        valid_from_ms: now_ms,
        config_hash_prefix: 42,
        occ: false,
    });
    let auth_sig = base64_encode(&<[u8; 64]>::from(f.auth_keypair.sign_message(&canonical)));
    let req = UserSignRequest {
        user_id: f.user_id.to_string(),
        transaction: UserSemanticTransaction {
            fee_payer: f.payer_b58.clone(),
            recipient: recipient.to_string(),
            amount_kelvin: amount,
            valid_from_ms: now_ms,
            config_hash_prefix: "42".to_string(),
            occ: false,
        },
        auth_signature: UserAuthEnvelope {
            pubkey: UserAuthRef {
                user_id: f.user_id.to_string(),
                base58: f.auth_pubkey_b58.clone(),
            },
            signature: auth_sig,
        },
        channel_nonce: "bm9uY2U=".to_string(),
    };
    serde_json::to_vec(&req).unwrap()
}

/// A minimal H-1 verifier shaped like the server lane's
/// `verify_channel_response` — proves the seal structure is consumable by
/// the app side (pin + nonce + blake3(canonical body) binding).
fn verify_seal_with_channel_pk(
    store: &SignerStore,
    sealed_body: &str,
    nonce: &str,
) -> Result<(), ()> {
    let pinned = crate::channel_public_key(store).map_err(|_| ())?;
    let v: serde_json::Value = serde_json::from_str(sealed_body).map_err(|_| ())?;
    let sig_b64 = v
        .get("signer_sig")
        .and_then(|x| x.as_str())
        .ok_or(())?
        .to_string();
    let mut clean = v.clone();
    if let Some(o) = clean.as_object_mut() {
        o.remove("signer_sig");
    }
    let clean_str = serde_json::to_string(&clean).map_err(|_| ())?;
    let pk = base58_decode_32(&pinned).ok_or(())?;
    let sig = base64_decode(sig_b64.trim()).ok_or(())?;
    let mut msg = blake3::hash(clean_str.as_bytes()).as_bytes().to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    let s = rialo_s_signature::Signature::try_from(sig.as_slice()).map_err(|_| ())?;
    if s.verify(&pk, &msg) { Ok(()) } else { Err(()) }
}

#[test]
fn deny_when_not_armed() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::remove_var(ARM_ENV) };
    let body = request_bytes(&f, 1_700_000_000_000, &f.recipient_b58, 500);
    let err = sign_user_transaction(&f.store, &f.policy_dir, &body, 1_700_000_000_000).unwrap_err();
    assert_eq!(err.parts().1, "USER_SIGNING_NOT_ENABLED");
}

#[test]
fn signs_selfverifies_and_seals() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    let now_ms = 1_700_000_000_000;
    let body = request_bytes(&f, now_ms, &f.recipient_b58, 500);
    let resp: UserSignResponse =
        sign_user_transaction(&f.store, &f.policy_dir, &body, now_ms).unwrap();
    assert_eq!(resp.user_id, "50506318");
    assert_eq!(resp.required_signatures, 1);
    // the returned signature verifies against the PAYER address
    let msg = base64_decode(&resp.canonical_message_b64).unwrap();
    let sig = base64_decode(&resp.signature_b64).unwrap();
    let payer = base58_decode_32(&f.payer_b58).unwrap();
    assert!(
        rialo_s_signature::Signature::try_from(sig.as_slice())
            .unwrap()
            .verify(&payer, &msg)
    );
    // THE SEAL — the sealed body verifies under the pinned channel key +
    // nonce (the H-1 shape the app adapter consumes).
    let plain = serde_json::to_string(&resp).unwrap();
    let sealed = crate::seal_channel_response(&f.store, &plain, Some("bm9uY2U="));
    assert!(sealed.contains("signer_sig"));
    verify_seal_with_channel_pk(&f.store, &sealed, "bm9uY2U=").expect("seal verifies");
    unsafe { std::env::remove_var(ARM_ENV) };
}

#[test]
fn cross_user_auth_identity_rejected() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    let now_ms = 1_700_000_000_000;
    let base = request_bytes(&f, now_ms, &f.recipient_b58, 500);
    // attacker declares a DIFFERENT (unregistered) user
    let mut body: serde_json::Value = serde_json::from_slice(&base).unwrap();
    body["user_id"] = serde_json::json!("999");
    body["auth_signature"]["pubkey"]["user_id"] = serde_json::json!("999");
    let err = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::UnknownWallet);
    // inconsistent identity pair (user A body, user B declared) → AuthInvalid
    let mut body2: serde_json::Value = serde_json::from_slice(&base).unwrap();
    body2["auth_signature"]["pubkey"]["user_id"] = serde_json::json!("999");
    let err2 = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body2.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(err2, UserDenial::AuthInvalid);
    unsafe { std::env::remove_var(ARM_ENV) };
}

#[test]
fn payer_mismatch_rejected() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    let now_ms = 1_700_000_000_000;
    let mut body: serde_json::Value =
        serde_json::from_slice(&request_bytes(&f, now_ms, &f.recipient_b58, 500)).unwrap();
    body["transaction"]["fee_payer"] = serde_json::json!(f.stranger_b58.clone());
    let err = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::PayerMismatch);
    unsafe { std::env::remove_var(ARM_ENV) };
}

#[test]
fn policy_classes_reject() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    let now_ms = 1_700_000_000_000;
    // over cap
    let over = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &request_bytes(&f, now_ms, &f.recipient_b58, 200_000),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(over, UserDenial::PolicyDenied);
    // non-allowlisted recipient
    let other = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &request_bytes(&f, now_ms, &f.stranger_b58, 1),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(other, UserDenial::PolicyDenied);
    unsafe { std::env::remove_var(ARM_ENV) };
}

#[test]
fn policy_missing_for_registered_user_rejects() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    // a second registered user with NO policy file → PolicyMissing
    let user2_key = rialo_s_keypair::keypair_from_seed(&[11u8; 32]).unwrap();
    let user2_addr = user2_key.pubkey().to_string();
    let user2_auth = rialo_s_keypair::keypair_from_seed(&[12u8; 32]).unwrap();
    let user2_auth_b58 = user2_auth.pubkey().to_string();
    let key_path = user_key_path(&f.store, 111);
    let kp_bytes: [u8; 64] = user2_key.to_bytes();
    std::fs::write(&key_path, serde_json::to_vec(&kp_bytes.to_vec()).unwrap()).unwrap();
    register_user_wallet(&f.store, 111, &user2_addr, &user2_auth_b58).unwrap();
    let from = base58_decode_32(&user2_addr).unwrap();
    let to = base58_decode_32(&f.recipient_b58).unwrap();
    let canonical = build_canonical_message(&CanonicalTransferSpec {
        from: &from,
        to: &to,
        amount_kelvin: 500,
        valid_from_ms: 1_700_000_000_000,
        config_hash_prefix: 42,
        occ: false,
    });
    let auth_sig = base64_encode(&<[u8; 64]>::from(user2_auth.sign_message(&canonical)));
    let req = UserSignRequest {
        user_id: "111".to_string(),
        transaction: UserSemanticTransaction {
            fee_payer: user2_addr,
            recipient: f.recipient_b58.clone(),
            amount_kelvin: 500,
            valid_from_ms: 1_700_000_000_000,
            config_hash_prefix: "42".to_string(),
            occ: false,
        },
        auth_signature: UserAuthEnvelope {
            pubkey: UserAuthRef {
                user_id: "111".to_string(),
                base58: user2_auth_b58,
            },
            signature: auth_sig,
        },
        channel_nonce: "bm9uY2U=".to_string(),
    };
    let err = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &serde_json::to_vec(&req).unwrap(),
        1_700_000_000_000,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::PolicyMissing);
    unsafe { std::env::remove_var(ARM_ENV) };
}

#[test]
fn status_reports_classes_not_secrets() {
    let f = fixture();
    let st = user_status(&f.store, &f.policy_dir, f.user_id);
    assert!(st.registered);
    assert_eq!(st.policy_state, "ok");
    assert_eq!(st.key_container_state, "linked");
    assert!(st.public_address.is_some());
    let unknown = user_status(&f.store, &f.policy_dir, 424242);
    assert!(!unknown.registered);
    assert_eq!(unknown.policy_state, "unknown");
    assert_eq!(unknown.key_container_state, "not_imported");
}

#[test]
fn ceremony_refuses_unimported_and_mismatched_keys() {
    let f = fixture();
    let err = register_user_wallet(&f.store, 777, &f.payer_b58, &f.auth_pubkey_b58).unwrap_err();
    assert_eq!(err, UserDenial::KeyNotImported);
    let other_key = rialo_s_keypair::keypair_from_seed(&[13u8; 32]).unwrap();
    let other_addr = other_key.pubkey().to_string();
    let key_path = user_key_path(&f.store, 888);
    let kp_bytes: [u8; 64] = other_key.to_bytes();
    std::fs::write(&key_path, serde_json::to_vec(&kp_bytes.to_vec()).unwrap()).unwrap();
    let err2 = register_user_wallet(&f.store, 888, &f.payer_b58, &f.auth_pubkey_b58).unwrap_err();
    assert_ne!(other_addr, f.payer_b58);
    assert_eq!(err2, UserDenial::CeremonyAddressMismatch);
}

#[test]
fn conflicting_registration_rejected() {
    let f = fixture();
    let err = register_user_wallet(
        &f.store,
        f.user_id,
        &f.payer_b58,
        "DifferentAuth111111111111111111111111111111",
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::ConflictingRegistration);
}

#[test]
fn corrupt_record_is_distinct_from_missing() {
    let f = fixture();
    let record_path = user_record_path(&f.store, f.user_id);
    let bytes = std::fs::read(&record_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["public_address"] = serde_json::json!("Corrupt111111111111111111111111111111111111111");
    std::fs::write(&record_path, serde_json::to_vec(&v).unwrap()).unwrap();
    let st = user_status(&f.store, &f.policy_dir, f.user_id);
    assert!(st.record_corrupt, "corrupt ≠ missing (G76 discipline)");
    assert!(!st.registered);
}

#[test]
fn malformed_request_shapes_rejected() {
    let f = fixture();
    let _g = env_guard();
    unsafe { std::env::set_var(ARM_ENV, "1") };
    let now_ms = 1_700_000_000_000;
    let base = request_bytes(&f, now_ms, &f.recipient_b58, 500);
    // unknown field (deny_unknown_fields on the typed contract)
    let mut body: serde_json::Value = serde_json::from_slice(&base).unwrap();
    body["surprise"] = serde_json::json!(1);
    let err = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(err, UserDenial::BadRequest);
    // blank nonce
    let mut body2: serde_json::Value = serde_json::from_slice(&base).unwrap();
    body2["channel_nonce"] = serde_json::json!("   ");
    let err2 = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body2.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert_eq!(err2, UserDenial::BadRequest);
    // wrong auth key (valid base58, NOT the registered linkage) — ALSO fails
    // the signature check; the typed result must be an auth-class denial
    let rogue = rialo_s_keypair::keypair_from_seed(&[31u8; 32]).unwrap();
    let mut body3: serde_json::Value = serde_json::from_slice(&base).unwrap();
    body3["auth_signature"]["pubkey"]["base58"] = serde_json::json!(rogue.pubkey().to_string());
    let err3 = sign_user_transaction(
        &f.store,
        &f.policy_dir,
        &body3.to_string().into_bytes(),
        now_ms,
    )
    .unwrap_err();
    assert!(err3 == UserDenial::AuthInvalid || err3 == UserDenial::AuthMalformed);
    unsafe { std::env::remove_var(ARM_ENV) };
}
