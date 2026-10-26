//! G111 — end-to-end synthetic lifecycle coordinator tests.
//!
//! These tests exercise the coordinator, durable replay, audit, and binding
//! registry together. They use synthetic keys only and do not claim a real
//! identity provider or operator trust root.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;

use base64::Engine as _;
use rialo_s_signer::Signer;

use crate::user_authorization::{
    AuthorizationPayload, DenyAllAuditSink, EnrollmentRequest, IdentityAssertion, IdentityError,
    IdentityProvider, LifecycleOperation, OperatorRecord, OperatorSignature, OperatorTrustStore,
    TrustStoreError, VerifiedIdentity, auth_key_fingerprint,
};
use crate::user_authorization_store::{FileAuditSink, FileReplayStore};
use crate::user_binding_registry::{BindingStatus, RegistryError, UserBindingRegistry};
use crate::user_lifecycle_coordinator::{LifecycleCoordinator, LifecycleError};

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("g111-{tag}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone, Copy)]
enum IdMode {
    Ok,
    Unavailable,
}

struct Ids {
    user_id: u64,
    mode: IdMode,
}

impl IdentityProvider for Ids {
    fn verify(
        &self,
        _assertion: &IdentityAssertion,
        expected_user_id: u64,
        _now: u64,
    ) -> Result<VerifiedIdentity, IdentityError> {
        if matches!(self.mode, IdMode::Unavailable) {
            return Err(IdentityError::Unavailable);
        }
        if expected_user_id != self.user_id {
            return Err(IdentityError::Mismatch);
        }
        Ok(VerifiedIdentity {
            user_id: self.user_id,
            provider: "test-idp".to_string(),
            subject: "subject".to_string(),
        })
    }
}

struct Trust(HashMap<String, OperatorRecord>);

impl Trust {
    fn with(records: Vec<OperatorRecord>) -> Self {
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

fn kp(seed: u8) -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn fingerprint(k: &rialo_s_keypair::Keypair) -> String {
    auth_key_fingerprint(k.pubkey().as_ref()).unwrap()
}

fn proof(
    key: &rialo_s_keypair::Keypair,
    user_id: u64,
    operation: LifecycleOperation,
    request_id: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> EnrollmentRequest {
    let mut req = EnrollmentRequest {
        version: 1,
        user_id,
        auth_pubkey_b64: b64(key.pubkey().as_ref()),
        key_fingerprint: fingerprint(key),
        request_id: request_id.to_string(),
        nonce: nonce.to_string(),
        issued_at,
        expires_at,
        identity: IdentityAssertion {
            provider: "test-idp".to_string(),
            subject: "subject".to_string(),
            evidence_b64: b64(b"evidence"),
            issued_at,
            expires_at,
            nonce: nonce.to_string(),
        },
        possession_signature_b64: String::new(),
    };
    let bytes = req.possession_bytes_for(operation).unwrap();
    req.possession_signature_b64 = b64(key.sign_message(&bytes).as_ref());
    req
}

#[allow(clippy::too_many_arguments)]
fn payload(
    operation: LifecycleOperation,
    user_id: u64,
    generation: u64,
    current: &str,
    new: &str,
    request_id: &str,
    nonce: &str,
    issued_at: u64,
    expires_at: u64,
) -> AuthorizationPayload {
    AuthorizationPayload {
        version: 1,
        policy_version: 1,
        request_id: request_id.to_string(),
        nonce: nonce.to_string(),
        operation,
        user_id,
        generation,
        current_key_fingerprint: current.to_string(),
        new_key_fingerprint: new.to_string(),
        issued_at,
        expires_at,
        threshold: 1,
        operator_ids: vec!["op-1".to_string()],
    }
}

fn signed(k: &rialo_s_keypair::Keypair, p: &AuthorizationPayload) -> OperatorSignature {
    OperatorSignature {
        operator_id: "op-1".to_string(),
        signature_b64: b64(k.sign_message(&p.canonical_bytes().unwrap()).as_ref()),
    }
}

fn trust_for(op: &rialo_s_keypair::Keypair) -> Trust {
    Trust::with(vec![OperatorRecord::operator(
        "op-1",
        b64(op.pubkey().as_ref()),
    )])
}

fn good_coordinator(
    temp: &Temp,
    user_id: u64,
    op: &rialo_s_keypair::Keypair,
) -> LifecycleCoordinator<Ids, Trust, FileReplayStore, FileAuditSink> {
    LifecycleCoordinator::new(
        Ids {
            user_id,
            mode: IdMode::Ok,
        },
        trust_for(op),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        UserBindingRegistry::open(&temp.path).unwrap(),
    )
}

fn audit_count(temp: &Temp) -> usize {
    fs::read_dir(temp.path.join("audit"))
        .map(|d| d.count())
        .unwrap_or(0)
}

#[test]
fn g111_enroll_rotation_revocation_end_to_end() {
    let temp = Temp::new("e2e");
    let old = kp(1);
    let new = kp(2);
    let op = kp(3);
    let coord = good_coordinator(&temp, 42, &op);

    let p1 = proof(
        &old,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a1 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&old),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    let b = coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001).unwrap();
    assert_eq!(b.generation, 1);
    assert_eq!(b.status, BindingStatus::Active);
    assert!(coord.signing_allowed(42, &fingerprint(&old)).unwrap());
    assert_eq!(audit_count(&temp), 1);

    let p2 = proof(
        &new,
        42,
        LifecycleOperation::Rotate,
        "proof-2",
        "pn-2",
        1_100,
        1_400,
    );
    let a2 = payload(
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        "auth-2",
        "an-2",
        1_100,
        1_300,
    );
    let b = coord
        .rotate(&p2, &a2, &[signed(&op, &a2)], 1, 1_101)
        .unwrap();
    assert_eq!(b.generation, 2);
    assert!(!coord.signing_allowed(42, &fingerprint(&old)).unwrap());
    assert!(coord.signing_allowed(42, &fingerprint(&new)).unwrap());

    let a3 = payload(
        LifecycleOperation::Revoke,
        42,
        2,
        &fingerprint(&new),
        "",
        "auth-3",
        "an-3",
        1_200,
        1_400,
    );
    let b = coord.revoke(&a3, &[signed(&op, &a3)], 1_201).unwrap();
    assert_eq!(b.status, BindingStatus::Revoked);
    assert_eq!(b.revoked_at, Some(1_201));
    assert!(!coord.signing_allowed(42, &fingerprint(&new)).unwrap());

    // Restart persistence.
    let reopened = UserBindingRegistry::open(&temp.path).unwrap();
    let persisted = reopened.get(42).unwrap().unwrap();
    assert_eq!(persisted.status, BindingStatus::Revoked);
    assert_eq!(persisted.generation, 2);
}

#[test]
fn g111_identity_failure_denies_before_any_state() {
    let temp = Temp::new("id-fail");
    let key = kp(11);
    let op = kp(12);
    let coord = LifecycleCoordinator::new(
        Ids {
            user_id: 42,
            mode: IdMode::Unavailable,
        },
        trust_for(&op),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        UserBindingRegistry::open(&temp.path).unwrap(),
    );
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Enrollment(
            crate::user_authorization::EnrollmentError::IdentityUnavailable
        ))
    );
    assert!(coord.status(42).unwrap().is_none());
    assert_eq!(audit_count(&temp), 0);
}

#[test]
fn g111_invalid_operator_denies_without_binding() {
    let temp = Temp::new("op-fail");
    let key = kp(21);
    let op = kp(22);
    let coord = LifecycleCoordinator::new(
        Ids {
            user_id: 42,
            mode: IdMode::Ok,
        },
        Trust::with(vec![]),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        UserBindingRegistry::open(&temp.path).unwrap(),
    );
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::UnknownOperator
            )
        ))
    );
    assert!(coord.status(42).unwrap().is_none());
    assert_eq!(audit_count(&temp), 0);
}

#[test]
fn g111_audit_failure_prevents_mutation_and_burns_proof() {
    let temp = Temp::new("audit-fail");
    let key = kp(31);
    let op = kp(32);
    let coord = LifecycleCoordinator::new(
        Ids {
            user_id: 42,
            mode: IdMode::Ok,
        },
        trust_for(&op),
        FileReplayStore::open(&temp.path).unwrap(),
        DenyAllAuditSink,
        UserBindingRegistry::open(&temp.path).unwrap(),
    );
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::AuditUnavailable
        ))
    );
    assert!(coord.status(42).unwrap().is_none());
    // D1 replay was consumed before D8; a retry with the same proof is denied.
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Enrollment(
            crate::user_authorization::EnrollmentError::Replay
        ))
    );
}

#[test]
fn g111_replayed_proof_and_stale_generation_are_rejected() {
    let temp = Temp::new("replay-stale");
    let old = kp(41);
    let new = kp(42);
    let other = kp(43);
    let op = kp(44);
    let coord = good_coordinator(&temp, 42, &op);
    let p1 = proof(
        &old,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a1 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&old),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001).unwrap();

    assert_eq!(
        coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001),
        Err(LifecycleError::Enrollment(
            crate::user_authorization::EnrollmentError::Replay
        ))
    );

    let p2 = proof(
        &new,
        42,
        LifecycleOperation::Rotate,
        "proof-2",
        "pn-2",
        1_100,
        1_400,
    );
    let a2 = payload(
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        "auth-2",
        "an-2",
        1_100,
        1_300,
    );
    coord
        .rotate(&p2, &a2, &[signed(&op, &a2)], 1, 1_101)
        .unwrap();

    // Stale generation is rejected before D1 replay is consumed.
    let p3 = proof(
        &other,
        42,
        LifecycleOperation::Rotate,
        "proof-3",
        "pn-3",
        1_200,
        1_500,
    );
    let a3 = payload(
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&old),
        &fingerprint(&other),
        "auth-3",
        "an-3",
        1_200,
        1_400,
    );
    assert_eq!(
        coord.rotate(&p3, &a3, &[signed(&op, &a3)], 1, 1_201),
        Err(LifecycleError::Registry(RegistryError::GenerationMismatch))
    );
    assert_eq!(coord.status(42).unwrap().unwrap().generation, 2);
}

#[test]
fn g111_wrong_shape_is_rejected_before_replay_consumption() {
    let temp = Temp::new("shape");
    let key = kp(51);
    let op = kp(52);
    let coord = good_coordinator(&temp, 42, &op);
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let wrong_user = payload(
        LifecycleOperation::Enroll,
        43,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    assert_eq!(
        coord.enroll(&p, &wrong_user, &[signed(&op, &wrong_user)], 1_001),
        Err(LifecycleError::RequestMismatch)
    );
    // The proof was not consumed by a shape-only rejection.
    let right = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord
        .enroll(&p, &right, &[signed(&op, &right)], 1_001)
        .unwrap();

    // Same proof/auth id is rejected before replay too.
    let temp2 = Temp::new("shape-ids");
    let coord2 = good_coordinator(&temp2, 42, &op);
    let p2 = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "same",
        "pn-2",
        1_000,
        1_300,
    );
    let a2 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "same",
        "an-2",
        1_000,
        1_200,
    );
    assert_eq!(
        coord2.enroll(&p2, &a2, &[signed(&op, &a2)], 1_001),
        Err(LifecycleError::RequestMismatch)
    );
    assert!(coord2.status(42).unwrap().is_none());
}

#[test]
fn g111_corrupt_binding_fails_closed() {
    let temp = Temp::new("corrupt");
    let key = kp(61);
    let op = kp(62);
    let coord = good_coordinator(&temp, 42, &op);
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord.enroll(&p, &a, &[signed(&op, &a)], 1_001).unwrap();
    fs::write(temp.path.join("bindings/42.json"), b"corrupt").unwrap();
    assert_eq!(
        coord.status(42),
        Err(LifecycleError::Registry(RegistryError::Corrupt))
    );
    assert_eq!(
        coord.signing_allowed(42, &fingerprint(&key)),
        Err(LifecycleError::Registry(RegistryError::Corrupt))
    );
}

#[test]
fn g111_concurrent_conflicting_rotations_have_one_winner() {
    let temp = Temp::new("concurrent");
    let old = kp(71);
    let a_new = kp(72);
    let b_new = kp(73);
    let op = kp(74);
    let coord = Arc::new(good_coordinator(&temp, 42, &op));
    let p1 = proof(
        &old,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a1 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&old),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (i, new_key) in [a_new, b_new].into_iter().enumerate() {
        let coord = Arc::clone(&coord);
        let barrier = Arc::clone(&barrier);
        let op = op.insecure_clone();
        let current = fingerprint(&old);
        let target = fingerprint(&new_key);
        let new_b64 = b64(new_key.pubkey().as_ref());
        handles.push(thread::spawn(move || {
            let p = proof(
                &rialo_s_keypair::keypair_from_seed(&[1u8; 32]).unwrap(),
                42,
                LifecycleOperation::Rotate,
                &format!("proof-r{i}"),
                &format!("pn-r{i}"),
                1_100,
                1_400,
            );
            // The proof must be signed by the new key, not the old one.
            let mut p = p;
            p.auth_pubkey_b64 = new_b64;
            p.key_fingerprint = target.clone();
            let bytes = p.possession_bytes_for(LifecycleOperation::Rotate).unwrap();
            p.possession_signature_b64 = b64(new_key.sign_message(&bytes).as_ref());
            let a = payload(
                LifecycleOperation::Rotate,
                42,
                2,
                &current,
                &target,
                &format!("auth-r{i}"),
                &format!("an-r{i}"),
                1_100,
                1_300,
            );
            barrier.wait();
            coord.rotate(&p, &a, &[signed(&op, &a)], 1, 1_101)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(LifecycleError::Registry(RegistryError::GenerationMismatch)))
            .count(),
        1
    );
    let binding = coord.status(42).unwrap().unwrap();
    assert_eq!(binding.generation, 2);
    assert_eq!(audit_count(&temp), 3);
}

#[test]
fn g111_revoked_binding_blocks_rotation_and_signing() {
    let temp = Temp::new("revoked");
    let old = kp(81);
    let new = kp(82);
    let op = kp(83);
    let coord = good_coordinator(&temp, 42, &op);
    let p1 = proof(
        &old,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a1 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&old),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001).unwrap();
    let a2 = payload(
        LifecycleOperation::Revoke,
        42,
        1,
        &fingerprint(&old),
        "",
        "auth-2",
        "an-2",
        1_100,
        1_300,
    );
    coord.revoke(&a2, &[signed(&op, &a2)], 1_101).unwrap();
    assert!(!coord.signing_allowed(42, &fingerprint(&old)).unwrap());

    let p3 = proof(
        &new,
        42,
        LifecycleOperation::Rotate,
        "proof-3",
        "pn-3",
        1_200,
        1_500,
    );
    let a3 = payload(
        LifecycleOperation::Rotate,
        42,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        "auth-3",
        "an-3",
        1_200,
        1_400,
    );
    assert_eq!(
        coord.rotate(&p3, &a3, &[signed(&op, &a3)], 1, 1_201),
        Err(LifecycleError::Registry(RegistryError::Revoked))
    );
    assert_eq!(
        coord.revoke(&a2, &[signed(&op, &a2)], 1_201),
        Err(LifecycleError::Registry(RegistryError::AlreadyRevoked))
    );
}

#[test]
fn g111_duplicate_enrollment_returns_error_without_changing_state() {
    let temp = Temp::new("duplicate");
    let key = kp(91);
    let op = kp(92);
    let coord = good_coordinator(&temp, 42, &op);
    let p1 = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-1",
        "pn-1",
        1_000,
        1_300,
    );
    let a1 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-1",
        "an-1",
        1_000,
        1_200,
    );
    coord.enroll(&p1, &a1, &[signed(&op, &a1)], 1_001).unwrap();
    let p2 = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-2",
        "pn-2",
        1_100,
        1_400,
    );
    let a2 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-2",
        "an-2",
        1_100,
        1_300,
    );
    assert_eq!(
        coord.enroll(&p2, &a2, &[signed(&op, &a2)], 1_101),
        Err(LifecycleError::Registry(RegistryError::AlreadyExists))
    );
    assert_eq!(coord.status(42).unwrap().unwrap().generation, 1);
    assert_eq!(audit_count(&temp), 2);
}

#[test]
fn g111_expired_and_revoked_approvals_deny() {
    let temp = Temp::new("expired");
    let key = kp(101);
    let op = kp(102);
    let coord = good_coordinator(&temp, 42, &op);
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-e",
        "pn-e",
        900,
        1_300,
    );
    let mut a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-e",
        "an-e",
        900,
        1_000,
    );
    a.expires_at = 1_000;
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::Expired
            )
        ))
    );
    assert!(coord.status(42).unwrap().is_none());

    let temp2 = Temp::new("revoked-op");
    let coord2 = LifecycleCoordinator::new(
        Ids {
            user_id: 42,
            mode: IdMode::Ok,
        },
        Trust::with(vec![
            OperatorRecord::operator("op-1", b64(op.pubkey().as_ref())).revoked(),
        ]),
        FileReplayStore::open(&temp2.path).unwrap(),
        FileAuditSink::open(&temp2.path).unwrap(),
        UserBindingRegistry::open(&temp2.path).unwrap(),
    );
    let p2 = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-r",
        "pn-r",
        1_000,
        1_300,
    );
    let a2 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-r",
        "an-r",
        1_000,
        1_200,
    );
    assert_eq!(
        coord2.enroll(&p2, &a2, &[signed(&op, &a2)], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::RevokedOperator
            )
        ))
    );
    assert!(coord2.status(42).unwrap().is_none());
}

#[test]
fn g111_insufficient_and_invalid_signatures_deny() {
    let temp = Temp::new("insufficient");
    let key = kp(111);
    let op1 = kp(112);
    let op2 = kp(113);
    let coord = LifecycleCoordinator::new(
        Ids {
            user_id: 42,
            mode: IdMode::Ok,
        },
        Trust::with(vec![
            OperatorRecord::operator("op-1", b64(op1.pubkey().as_ref())),
            OperatorRecord::operator("op-2", b64(op2.pubkey().as_ref())),
        ]),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        UserBindingRegistry::open(&temp.path).unwrap(),
    );
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-i",
        "pn-i",
        1_000,
        1_300,
    );
    let mut a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-i",
        "an-i",
        1_000,
        1_200,
    );
    a.threshold = 2;
    a.operator_ids = vec!["op-1".to_string(), "op-2".to_string()];
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op1, &a)], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::InsufficientApprovals
            )
        ))
    );

    let temp2 = Temp::new("bad-sig");
    let coord2 = good_coordinator(&temp2, 42, &op1);
    let p2 = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-b",
        "pn-b",
        1_000,
        1_300,
    );
    let a2 = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-b",
        "an-b",
        1_000,
        1_200,
    );
    let mut bad = signed(&op1, &a2);
    bad.signature_b64 = b64(&[0u8; 64]);
    assert_eq!(
        coord2.enroll(&p2, &a2, &[bad], 1_001),
        Err(LifecycleError::Authorization(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::InvalidSignature
            )
        ))
    );
    assert!(coord2.status(42).unwrap().is_none());
}

#[test]
fn g112_coordinator_enrollment_rejects_existing_legacy_wallet() {
    let temp = Temp::new("legacy");
    fs::create_dir_all(temp.path.join("users")).unwrap();
    fs::write(temp.path.join("users/42.wallet.json"), b"{}").unwrap();
    let key = kp(121);
    let op = kp(122);
    let coord = good_coordinator(&temp, 42, &op);
    let p = proof(
        &key,
        42,
        LifecycleOperation::Enroll,
        "proof-l",
        "pn-l",
        1_000,
        1_300,
    );
    let a = payload(
        LifecycleOperation::Enroll,
        42,
        1,
        "",
        &fingerprint(&key),
        "auth-l",
        "an-l",
        1_000,
        1_200,
    );
    assert_eq!(
        coord.enroll(&p, &a, &[signed(&op, &a)], 1_001),
        Err(LifecycleError::Registry(RegistryError::AlreadyExists))
    );
    assert!(coord.status(42).unwrap().is_none());
}
