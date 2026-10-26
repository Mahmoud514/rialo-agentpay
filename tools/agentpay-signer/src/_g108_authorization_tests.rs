//! G108 — deterministic security tests for the D1/D8 primitives.
//!
//! All keys are synthetic seeds; no production key or secret is present.
//! These tests exercise the interfaces only. They do not claim that a real
//! identity provider, durable replay store, operator trust store, or audit
//! sink is connected.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use base64::Engine as _;
use rialo_s_signer::Signer;

use crate::user_authorization::*;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn kp(seed: u8) -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn pub_b64(k: &rialo_s_keypair::Keypair) -> String {
    b64(k.pubkey().as_ref())
}

fn fingerprint(k: &rialo_s_keypair::Keypair) -> String {
    auth_key_fingerprint(k.pubkey().as_ref()).unwrap()
}

fn sign_auth(
    k: &rialo_s_keypair::Keypair,
    operator_id: &str,
    payload: &AuthorizationPayload,
) -> OperatorSignature {
    let bytes = payload.canonical_bytes().unwrap();
    OperatorSignature {
        operator_id: operator_id.to_string(),
        signature_b64: b64(k.sign_message(&bytes).as_ref()),
    }
}

#[allow(clippy::too_many_arguments)]
fn auth_payload(
    ids: &[&str],
    threshold: u8,
    operation: LifecycleOperation,
    user_id: u64,
    generation: u64,
    current_fp: &str,
    new_fp: &str,
    issued_at: u64,
    expires_at: u64,
) -> AuthorizationPayload {
    let mut operator_ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
    operator_ids.sort();
    AuthorizationPayload {
        version: PROTOCOL_VERSION,
        policy_version: POLICY_VERSION_ONE,
        request_id: "req-1".to_string(),
        nonce: "nonce-1".to_string(),
        operation,
        user_id,
        generation,
        current_key_fingerprint: current_fp.to_string(),
        new_key_fingerprint: new_fp.to_string(),
        issued_at,
        expires_at,
        threshold,
        operator_ids,
    }
}

struct Trust(HashMap<String, OperatorRecord>);

impl Trust {
    fn new(records: Vec<OperatorRecord>) -> Self {
        Self(
            records
                .into_iter()
                .map(|r| (r.operator_id.clone(), r))
                .collect(),
        )
    }
}

impl OperatorTrustStore for Trust {
    fn lookup(&self, operator_id: &str) -> Result<Option<OperatorRecord>, TrustStoreError> {
        Ok(self.0.get(operator_id).cloned())
    }
}

#[derive(Default)]
struct Replay {
    requests: Mutex<HashSet<String>>,
    nonces: Mutex<HashSet<String>>,
}

impl ReplayStore for Replay {
    fn consume(
        &self,
        scope: ReplayScope,
        request_id: &str,
        nonce: &str,
        _now: u64,
        _expires_at: u64,
    ) -> Result<(), ReplayError> {
        let mut requests = self.requests.lock().unwrap();
        let mut nonces = self.nonces.lock().unwrap();
        let req_key = format!(
            "{}:{}:{}",
            scope.user_id,
            scope.operation.as_str(),
            request_id
        );
        let nonce_key = format!("{}:{}:{}", scope.user_id, scope.operation.as_str(), nonce);
        if requests.contains(&req_key) || nonces.contains(&nonce_key) {
            return Err(ReplayError::Replay);
        }
        requests.insert(req_key);
        nonces.insert(nonce_key);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum IdMode {
    Ok,
    Unavailable,
    Invalid,
    Mismatch,
}

struct Ids {
    user_id: u64,
    provider: String,
    subject: String,
    mode: IdMode,
}

impl Ids {
    fn good(user_id: u64) -> Self {
        Self {
            user_id,
            provider: "test-idp".to_string(),
            subject: "user-subject".to_string(),
            mode: IdMode::Ok,
        }
    }
}

impl IdentityProvider for Ids {
    fn verify(
        &self,
        assertion: &IdentityAssertion,
        expected_user_id: u64,
        _now: u64,
    ) -> Result<VerifiedIdentity, IdentityError> {
        match self.mode {
            IdMode::Unavailable => return Err(IdentityError::Unavailable),
            IdMode::Invalid => return Err(IdentityError::Invalid),
            IdMode::Mismatch => {
                return Ok(VerifiedIdentity {
                    user_id: self.user_id.saturating_add(1),
                    provider: self.provider.clone(),
                    subject: self.subject.clone(),
                });
            }
            IdMode::Ok => {}
        }
        if assertion.provider != self.provider {
            return Err(IdentityError::Invalid);
        }
        if expected_user_id != self.user_id {
            return Err(IdentityError::Mismatch);
        }
        Ok(VerifiedIdentity {
            user_id: self.user_id,
            provider: self.provider.clone(),
            subject: self.subject.clone(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn enrollment_at(
    k: &rialo_s_keypair::Keypair,
    user_id: u64,
    provider: &str,
    subject: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> EnrollmentRequest {
    let mut req = EnrollmentRequest {
        version: PROTOCOL_VERSION,
        user_id,
        auth_pubkey_b64: pub_b64(k),
        key_fingerprint: fingerprint(k),
        request_id: "req-e1".to_string(),
        nonce: nonce.to_string(),
        issued_at,
        expires_at,
        identity: IdentityAssertion {
            provider: provider.to_string(),
            subject: subject.to_string(),
            evidence_b64: b64(b"test-evidence"),
            issued_at,
            expires_at,
            nonce: nonce.to_string(),
        },
        possession_signature_b64: String::new(),
    };
    let bytes = req.possession_bytes().unwrap();
    req.possession_signature_b64 = b64(k.sign_message(&bytes).as_ref());
    req
}

fn enrollment(k: &rialo_s_keypair::Keypair, user_id: u64) -> EnrollmentRequest {
    enrollment_at(
        k,
        user_id,
        "test-idp",
        "user-subject",
        "enroll-1",
        1_000,
        1_300,
    )
}

// --- D8 positive paths ------------------------------------------------------

#[test]
fn g108_one_of_one_authorization_verifies() {
    let old = kp(11);
    let new = kp(12);
    let payload = auth_payload(
        &["op-1"],
        THRESHOLD_ONE,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = sign_auth(&old, "op-1", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&old))]),
        Replay::default(),
    );
    let out = verifier.verify(&payload, &[sig], 1_001).unwrap();
    assert_eq!(out.approved_by, vec!["op-1"]);
    assert_eq!(out.request_id, "req-1");
}

#[test]
fn g108_two_person_requires_two_distinct_keys() {
    let op1 = kp(21);
    let op2 = kp(22);
    let new = kp(23);
    let payload = auth_payload(
        &["op-1", "op-2"],
        THRESHOLD_TWO,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op1),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig1 = sign_auth(&op1, "op-1", &payload);
    let sig2 = sign_auth(&op2, "op-2", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![
            OperatorRecord::operator("op-1", pub_b64(&op1)),
            OperatorRecord::operator("op-2", pub_b64(&op2)),
        ]),
        Replay::default(),
    );
    let out = verifier
        .verify(&payload, &[sig1.clone(), sig2], 1_001)
        .unwrap();
    assert_eq!(out.approved_by, vec!["op-1", "op-2"]);

    let duplicate = verifier.verify(&payload, &[sig1.clone(), sig1], 1_001);
    assert_eq!(duplicate, Err(AuthzError::DuplicateOperator));
}

#[test]
fn g108_two_person_rejects_shared_operator_key() {
    let shared = kp(31);
    let new = kp(32);
    let payload = auth_payload(
        &["op-1", "op-2"],
        THRESHOLD_TWO,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&shared),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig1 = sign_auth(&shared, "op-1", &payload);
    let sig2 = sign_auth(&shared, "op-2", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![
            OperatorRecord::operator("op-1", pub_b64(&shared)),
            OperatorRecord::operator("op-2", pub_b64(&shared)),
        ]),
        Replay::default(),
    );
    assert_eq!(
        verifier.verify(&payload, &[sig1, sig2], 1_001),
        Err(AuthzError::DuplicateOperator)
    );
}

// --- D8 negative paths ------------------------------------------------------

#[test]
fn g108_rejects_expired_not_yet_valid_and_overlong_authorizations() {
    let op = kp(41);
    let new = kp(42);
    let payload = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = sign_auth(&op, "op-1", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&op))]),
        Replay::default(),
    );
    assert_eq!(
        verifier.verify(&payload, &[sig], 1_200),
        Err(AuthzError::Expired)
    );

    let mut future = payload.clone();
    future.issued_at = 1_100;
    future.expires_at = 1_300;
    let sig = sign_auth(&op, "op-1", &future);
    assert_eq!(
        verifier.verify(&future, &[sig], 1_000),
        Err(AuthzError::NotYetValid)
    );

    let mut long = payload.clone();
    long.expires_at = 1_601;
    assert_eq!(long.canonical_bytes(), Err(AuthzError::PolicyMismatch));
}

#[test]
fn g108_rejects_unknown_revoked_and_invalid_signatures() {
    let op = kp(51);
    let other = kp(52);
    let new = kp(53);
    let payload = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );

    let unknown_trust = AuthorizationVerifier::new(Trust::new(vec![]), Replay::default());
    assert_eq!(
        unknown_trust.verify(&payload, &[sign_auth(&op, "op-1", &payload)], 1_001),
        Err(AuthzError::UnknownOperator)
    );

    let revoked = AuthorizationVerifier::new(
        Trust::new(vec![
            OperatorRecord::operator("op-1", pub_b64(&op)).revoked(),
        ]),
        Replay::default(),
    );
    assert_eq!(
        revoked.verify(&payload, &[sign_auth(&op, "op-1", &payload)], 1_001),
        Err(AuthzError::RevokedOperator)
    );

    let good = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&op))]),
        Replay::default(),
    );
    let mut bad = sign_auth(&op, "op-1", &payload);
    bad.signature_b64 = b64(&[0u8; 64]);
    assert_eq!(
        good.verify(&payload, &[bad], 1_001),
        Err(AuthzError::InvalidSignature)
    );

    let wrong_signer = sign_auth(&other, "op-1", &payload);
    assert_eq!(
        good.verify(&payload, &[wrong_signer], 1_001),
        Err(AuthzError::InvalidSignature)
    );

    let mut tampered = payload.clone();
    tampered.user_id = 43;
    let original_sig = sign_auth(&op, "op-1", &payload);
    assert_eq!(
        good.verify(&tampered, &[original_sig], 1_001),
        Err(AuthzError::InvalidSignature)
    );
}

#[test]
fn g108_rejects_replayed_request_id_and_nonce() {
    let op = kp(61);
    let new = kp(62);
    let payload = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = sign_auth(&op, "op-1", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&op))]),
        Replay::default(),
    );
    verifier.verify(&payload, &[sig.clone()], 1_001).unwrap();
    assert_eq!(
        verifier.verify(&payload, &[sig], 1_001),
        Err(AuthzError::Replay)
    );

    let mut same_request = payload.clone();
    same_request.nonce = "nonce-2".to_string();
    let sig = sign_auth(&op, "op-1", &same_request);
    assert_eq!(
        verifier.verify(&same_request, &[sig], 1_001),
        Err(AuthzError::Replay)
    );

    let mut same_nonce = payload.clone();
    same_nonce.request_id = "req-2".to_string();
    let sig = sign_auth(&op, "op-1", &same_nonce);
    assert_eq!(
        verifier.verify(&same_nonce, &[sig], 1_001),
        Err(AuthzError::Replay)
    );
}

#[test]
fn g108_default_deny_stores_fail_closed() {
    let op = kp(71);
    let new = kp(72);
    let payload = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = sign_auth(&op, "op-1", &payload);

    let empty_trust = AuthorizationVerifier::new(DenyAllTrustStore, Replay::default());
    assert_eq!(
        empty_trust.verify(&payload, &[sig.clone()], 1_001),
        Err(AuthzError::StoreUnavailable)
    );

    let deny_replay = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&op))]),
        DenyAllReplayStore,
    );
    assert_eq!(
        deny_replay.verify(&payload, &[sig], 1_001),
        Err(AuthzError::StoreUnavailable)
    );
}

#[test]
fn g108_rejects_policy_and_operation_shape_mismatches() {
    let op = kp(81);
    let fp = fingerprint(&op);
    let base = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fp,
        1_000,
        1_200,
    );
    assert!(base.canonical_bytes().is_ok());

    let mut bad_threshold = base.clone();
    bad_threshold.threshold = 3;
    assert_eq!(
        bad_threshold.canonical_bytes(),
        Err(AuthzError::PolicyMismatch)
    );

    let mut two_with_one = base.clone();
    two_with_one.threshold = 2;
    assert_eq!(
        two_with_one.canonical_bytes(),
        Err(AuthzError::InsufficientApprovals)
    );

    let mut enroll_gen2 = base.clone();
    enroll_gen2.generation = 2;
    assert_eq!(enroll_gen2.canonical_bytes(), Err(AuthzError::Malformed));

    let mut rotate_same = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fp,
        &fp,
        1_000,
        1_200,
    );
    assert_eq!(rotate_same.canonical_bytes(), Err(AuthzError::Malformed));

    rotate_same.operation = LifecycleOperation::Revoke;
    rotate_same.current_key_fingerprint = fp.clone();
    rotate_same.new_key_fingerprint = "0".repeat(64);
    assert_eq!(rotate_same.canonical_bytes(), Err(AuthzError::Malformed));

    let mut unsorted = auth_payload(
        &["op-2", "op-1"],
        1,
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fp,
        1_000,
        1_200,
    );
    unsorted.operator_ids = vec!["op-2".to_string(), "op-1".to_string()];
    assert_eq!(
        unsorted.canonical_bytes(),
        Err(AuthzError::DuplicateOperator)
    );
}

#[test]
fn g108_canonical_bytes_are_deterministic_and_tamper_sensitive() {
    let op = kp(91);
    let fp = fingerprint(&op);
    let a = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fp,
        1_000,
        1_200,
    );
    let b = a.clone();
    assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());

    let mut changed_user = a.clone();
    changed_user.user_id = 43;
    assert_ne!(
        a.canonical_bytes().unwrap(),
        changed_user.canonical_bytes().unwrap()
    );

    let mut changed_op = a.clone();
    changed_op.operation = LifecycleOperation::Revoke;
    changed_op.current_key_fingerprint = fp.clone();
    changed_op.new_key_fingerprint = String::new();
    assert_ne!(
        a.canonical_bytes().unwrap(),
        changed_op.canonical_bytes().unwrap()
    );
}

// --- D1 enrollment ----------------------------------------------------------

#[test]
fn g108_enrollment_binds_identity_and_possession() {
    let auth = kp(101);
    let req = enrollment(&auth, 42);
    let verifier = EnrollmentVerifier::new(Ids::good(42), Replay::default());
    let out = verifier.verify(&req, 1_001).unwrap();
    assert_eq!(out.user_id, 42);
    assert_eq!(out.auth_pubkey_b64, req.auth_pubkey_b64);
    assert_eq!(out.key_fingerprint, req.key_fingerprint);
    assert_eq!(out.identity_provider, "test-idp");
    assert_eq!(out.identity_subject, "user-subject");
    assert_eq!(out.generation, 1);
}

#[test]
fn g108_enrollment_rejects_bad_proof_replay_and_identity_mismatch() {
    let auth = kp(111);
    let req = enrollment(&auth, 42);

    let mut bad = req.clone();
    bad.possession_signature_b64 = b64(&[0u8; 64]);
    let verifier = EnrollmentVerifier::new(Ids::good(42), Replay::default());
    assert_eq!(
        verifier.verify(&bad, 1_001),
        Err(EnrollmentError::InvalidPossessionProof)
    );

    let verifier = EnrollmentVerifier::new(Ids::good(42), Replay::default());
    verifier.verify(&req, 1_001).unwrap();
    assert_eq!(verifier.verify(&req, 1_001), Err(EnrollmentError::Replay));

    let mismatch = EnrollmentVerifier::new(
        Ids {
            mode: IdMode::Mismatch,
            ..Ids::good(42)
        },
        Replay::default(),
    );
    assert_eq!(
        mismatch.verify(&req, 1_001),
        Err(EnrollmentError::IdentityMismatch)
    );
}

#[test]
fn g108_enrollment_rejects_unavailable_provider_and_expired_request() {
    let auth = kp(121);
    let req = enrollment(&auth, 42);

    let unavailable = EnrollmentVerifier::new(
        Ids {
            mode: IdMode::Unavailable,
            ..Ids::good(42)
        },
        Replay::default(),
    );
    assert_eq!(
        unavailable.verify(&req, 1_001),
        Err(EnrollmentError::IdentityUnavailable)
    );

    let deny = EnrollmentVerifier::new(DenyAllIdentityProvider, Replay::default());
    assert_eq!(
        deny.verify(&req, 1_001),
        Err(EnrollmentError::IdentityUnavailable)
    );

    let expired = enrollment_at(&auth, 42, "test-idp", "user-subject", "e2", 900, 1_000);
    let verifier = EnrollmentVerifier::new(Ids::good(42), Replay::default());
    assert_eq!(
        verifier.verify(&expired, 1_001),
        Err(EnrollmentError::Expired)
    );
}

#[test]
fn g108_enrollment_rejects_wrong_key_fingerprint_and_malformed_key() {
    let auth = kp(131);
    let req = enrollment(&auth, 42);

    let mut wrong_fp = req.clone();
    wrong_fp.key_fingerprint = "0".repeat(64);
    let verifier = EnrollmentVerifier::new(Ids::good(42), Replay::default());
    assert_eq!(
        verifier.verify(&wrong_fp, 1_001),
        Err(EnrollmentError::KeyMismatch)
    );

    let mut bad_key = req.clone();
    bad_key.auth_pubkey_b64 = "!!!".to_string();
    assert_eq!(
        verifier.verify(&bad_key, 1_001),
        Err(EnrollmentError::Malformed)
    );

    let mut bad_nonce = req.clone();
    bad_nonce.identity.nonce = "other".to_string();
    assert_eq!(
        verifier.verify(&bad_nonce, 1_001),
        Err(EnrollmentError::Malformed)
    );
}

// --- D10 audit boundary -----------------------------------------------------

#[test]
fn g108_deny_all_audit_sink_fails_closed() {
    let sink = DenyAllAuditSink;
    let event = AuditEvent {
        kind: "enrollment_verified",
        outcome: "allowed",
        policy_version: 1,
        request_id: "req-1".to_string(),
        user_id: 42,
        generation: 1,
        operation: "enroll",
        approved_by: vec!["op-1".to_string()],
        operator_key_fingerprints: vec!["0".repeat(64)],
        at: 1_001,
    };
    assert_eq!(sink.record(&event), Err(AuditError::Unavailable));
    assert!(!event.approved_by.iter().any(|s| s.contains("signature")));
}

// --- G109: replay scope and operator operation scope -----------------------

#[test]
fn g109_replay_scope_is_user_and_operation_scoped() {
    let op = kp(141);
    let new = kp(142);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![OperatorRecord::operator("op-1", pub_b64(&op))]),
        Replay::default(),
    );

    let p42 = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let s42 = sign_auth(&op, "op-1", &p42);
    verifier.verify(&p42, &[s42], 1_001).unwrap();

    // Same request/nonce, different user: separate scope, allowed.
    let mut p43 = p42.clone();
    p43.user_id = 43;
    let s43 = sign_auth(&op, "op-1", &p43);
    verifier.verify(&p43, &[s43], 1_001).unwrap();

    // Same user, different operation: separate scope, allowed.
    let p_enroll = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let s_enroll = sign_auth(&op, "op-1", &p_enroll);
    verifier.verify(&p_enroll, &[s_enroll], 1_001).unwrap();

    // Same user + same operation: replay.
    let s42_again = sign_auth(&op, "op-1", &p42);
    assert_eq!(
        verifier.verify(&p42, &[s42_again], 1_001),
        Err(AuthzError::Replay)
    );
}

#[test]
fn g109_operator_operation_scope_is_enforced() {
    let op = kp(151);
    let new = kp(152);
    let payload = auth_payload(
        &["op-1"],
        1,
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = sign_auth(&op, "op-1", &payload);
    let verifier = AuthorizationVerifier::new(
        Trust::new(vec![
            OperatorRecord::operator("op-1", pub_b64(&op))
                .with_operations(vec![LifecycleOperation::Enroll]),
        ]),
        Replay::default(),
    );
    assert_eq!(
        verifier.verify(&payload, &[sig], 1_001),
        Err(AuthzError::UnauthorizedOperation)
    );
}
