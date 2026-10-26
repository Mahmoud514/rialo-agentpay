//! G109 — durable replay and audit adapter tests.
//!
//! These tests use only synthetic ids, temporary directories and redacted
//! events. They do not claim production provisioning or a wired lifecycle.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;

use base64::Engine as _;
use rialo_s_signer::Signer;

use crate::user_authorization::{
    AuditEvent, AuditSink, AuthorizationPayload, AuthzError, DenyAllAuditSink,
    LifecycleAuthorizationError, LifecycleAuthorizer, LifecycleOperation, OperatorRecord,
    OperatorSignature, OperatorTrustStore, ReplayError, ReplayScope, ReplayStore, TrustStoreError,
};
use crate::user_authorization_store::{FileAuditSink, FileReplayStore};
use crate::user_binding_registry::{BindingStatus, MutationContext, UserBindingRegistry};

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("g109-{tag}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn scope(user_id: u64, operation: LifecycleOperation) -> ReplayScope {
    ReplayScope { user_id, operation }
}

fn event(at: u64) -> AuditEvent {
    AuditEvent {
        kind: "authorization_verified",
        outcome: "allowed",
        policy_version: 1,
        request_id: "req-1".to_string(),
        user_id: 42,
        generation: 2,
        operation: "rotate",
        approved_by: vec!["op-1".to_string()],
        operator_key_fingerprints: vec!["a".repeat(64)],
        at,
    }
}

#[test]
fn g109_file_replay_is_durable_across_reopen() {
    let temp = Temp::new("reopen");
    let store = FileReplayStore::open(&temp.path).unwrap();
    let s = scope(42, LifecycleOperation::Rotate);
    store.consume(s, "req-1", "nonce-1", 100, 200).unwrap();
    drop(store);

    let reopened = FileReplayStore::open(&temp.path).unwrap();
    assert_eq!(
        reopened.consume(s, "req-1", "nonce-1", 100, 200),
        Err(ReplayError::Replay)
    );
}

#[test]
fn g109_file_replay_concurrent_consume_has_one_winner() {
    let temp = Temp::new("concurrent");
    let store = Arc::new(FileReplayStore::open(&temp.path).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let s = scope(42, LifecycleOperation::Rotate);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            store.consume(s, "req-1", "nonce-1", 100, 200).is_ok()
        }));
    }
    let winners = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(winners, 1, "exactly one concurrent consumer wins");
}

#[test]
fn g109_file_replay_expired_records_are_rejected_until_purged() {
    let temp = Temp::new("expiry");
    let store = FileReplayStore::open(&temp.path).unwrap();
    let s = scope(42, LifecycleOperation::Rotate);
    store.consume(s, "req-1", "nonce-1", 50, 100).unwrap();
    assert_eq!(
        store.consume(s, "req-1", "nonce-1", 101, 200),
        Err(ReplayError::Replay),
        "expiry alone must not reactivate a consumed id"
    );
    assert_eq!(store.purge_expired(101).unwrap(), 2);
    store.consume(s, "req-1", "nonce-1", 101, 200).unwrap();
    assert_eq!(
        store.consume(s, "req-1", "nonce-1", 101, 200),
        Err(ReplayError::Replay)
    );
}

#[test]
fn g109_file_replay_purges_only_expired_records() {
    let temp = Temp::new("purge");
    let store = FileReplayStore::open(&temp.path).unwrap();
    store
        .consume(scope(1, LifecycleOperation::Enroll), "r1", "n1", 50, 100)
        .unwrap();
    store
        .consume(scope(1, LifecycleOperation::Rotate), "r2", "n2", 50, 200)
        .unwrap();
    assert_eq!(store.purge_expired(150).unwrap(), 2);
    assert_eq!(store.purge_expired(250).unwrap(), 2);
}

#[test]
fn g109_file_replay_scope_is_user_and_operation_scoped() {
    let temp = Temp::new("scope");
    let store = FileReplayStore::open(&temp.path).unwrap();
    let user1_rotate = scope(1, LifecycleOperation::Rotate);
    store
        .consume(user1_rotate, "req-1", "nonce-1", 100, 200)
        .unwrap();
    store
        .consume(
            scope(2, LifecycleOperation::Rotate),
            "req-1",
            "nonce-1",
            100,
            200,
        )
        .unwrap();
    store
        .consume(
            scope(1, LifecycleOperation::Revoke),
            "req-1",
            "nonce-1",
            100,
            200,
        )
        .unwrap();
    assert_eq!(
        store.consume(user1_rotate, "req-1", "nonce-1", 100, 200),
        Err(ReplayError::Replay)
    );
}

#[test]
fn g109_file_replay_storage_failure_fails_closed() {
    let temp = Temp::new("replay-fail");
    let store = FileReplayStore::open(&temp.path).unwrap();
    fs::remove_dir_all(temp.path.join("replay")).unwrap();
    fs::write(temp.path.join("replay"), b"not a directory").unwrap();
    assert_eq!(
        store.consume(
            scope(1, LifecycleOperation::Rotate),
            "req-1",
            "nonce-1",
            100,
            200
        ),
        Err(ReplayError::Unavailable)
    );
}

#[cfg(unix)]
#[test]
fn g109_file_replay_creates_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new("modes");
    let store = FileReplayStore::open(&temp.path).unwrap();
    store
        .consume(
            scope(1, LifecycleOperation::Rotate),
            "req-1",
            "nonce-1",
            100,
            200,
        )
        .unwrap();
    let dir_mode = fs::metadata(temp.path.join("replay"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    for entry in fs::read_dir(temp.path.join("replay")).unwrap().flatten() {
        let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "replay record must be 0600");
    }
}

#[test]
fn g109_file_audit_persists_redacted_event() {
    let temp = Temp::new("audit");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();

    let files: Vec<_> = fs::read_dir(temp.path.join("audit"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(files.len(), 1);
    let text = fs::read_to_string(files[0].path()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["kind"], "authorization_verified");
    assert_eq!(value["outcome"], "allowed");
    assert_eq!(value["policy_version"], 1);
    assert_eq!(value["request_id"], "req-1");
    assert_eq!(value["user_id"], 42);
    assert_eq!(value["operation"], "rotate");
    for forbidden in [
        "PRIVATE KEY",
        "BEGIN OPENSSH",
        "signature",
        "evidence",
        "nonce",
        "secret",
        "password",
    ] {
        assert!(
            !text
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()),
            "audit leaked forbidden marker: {forbidden}"
        );
    }
}

#[test]
fn g109_file_audit_identical_event_is_idempotent() {
    let temp = Temp::new("audit-idem");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();
    sink.record(&event(100)).unwrap();
    assert_eq!(
        fs::read_dir(temp.path.join("audit")).unwrap().count(),
        1,
        "identical event must not create a duplicate file"
    );
    sink.record(&event(101)).unwrap();
    assert_eq!(
        fs::read_dir(temp.path.join("audit")).unwrap().count(),
        2,
        "distinct event gets a distinct file"
    );
}

#[test]
fn g109_file_audit_corrupt_existing_event_fails_closed() {
    let temp = Temp::new("audit-corrupt");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();
    let path = fs::read_dir(temp.path.join("audit"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    fs::write(&path, b"corrupt").unwrap();
    assert!(
        sink.record(&event(100)).is_err(),
        "a mismatched existing audit file must not be reported as success"
    );
}

#[test]
fn g109_file_audit_storage_failure_fails_closed() {
    let temp = Temp::new("audit-fail");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    fs::remove_dir_all(temp.path.join("audit")).unwrap();
    fs::write(temp.path.join("audit"), b"not a directory").unwrap();
    assert!(sink.record(&event(100)).is_err());
}

#[cfg(unix)]
#[test]
fn g109_file_audit_creates_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new("audit-modes");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();
    let dir_mode = fs::metadata(temp.path.join("audit"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    for entry in fs::read_dir(temp.path.join("audit")).unwrap().flatten() {
        let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit event must be 0600");
    }
}

// --- G109 lifecycle authorization integration (still not wired) ------------

struct Trust(HashMap<String, OperatorRecord>);

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
    crate::user_authorization::auth_key_fingerprint(k.pubkey().as_ref()).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn payload(
    user_id: u64,
    operation: LifecycleOperation,
    generation: u64,
    current: &str,
    new: &str,
    issued_at: u64,
    expires_at: u64,
) -> AuthorizationPayload {
    AuthorizationPayload {
        version: 1,
        policy_version: 1,
        request_id: "req-1".to_string(),
        nonce: "nonce-1".to_string(),
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

#[test]
fn g109_lifecycle_authorizer_persists_audit_and_rejects_replay() {
    let temp = Temp::new("authz");
    let op = kp(201);
    let new = kp(202);
    let p = payload(
        42,
        LifecycleOperation::Rotate,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = signed(&op, &p);
    let mut records = HashMap::new();
    records.insert(
        "op-1".to_string(),
        OperatorRecord::operator("op-1", b64(op.pubkey().as_ref())),
    );
    let authorizer = LifecycleAuthorizer::new(
        Trust(records),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
    );
    authorizer.authorize(&p, &[sig.clone()], 1_001).unwrap();
    assert_eq!(fs::read_dir(temp.path.join("audit")).unwrap().count(), 1);
    assert_eq!(
        authorizer.authorize(&p, &[sig], 1_001),
        Err(LifecycleAuthorizationError::Authorization(
            AuthzError::Replay
        ))
    );
}

#[test]
fn g109_lifecycle_authorizer_fails_closed_when_audit_is_unavailable() {
    let temp = Temp::new("authz-audit");
    let op = kp(211);
    let new = kp(212);
    let p = payload(
        42,
        LifecycleOperation::Rotate,
        2,
        &fingerprint(&op),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = signed(&op, &p);
    let mut records = HashMap::new();
    records.insert(
        "op-1".to_string(),
        OperatorRecord::operator("op-1", b64(op.pubkey().as_ref())),
    );
    let authorizer = LifecycleAuthorizer::new(
        Trust(records),
        FileReplayStore::open(&temp.path).unwrap(),
        DenyAllAuditSink,
    );
    assert_eq!(
        authorizer.authorize(&p, &[sig.clone()], 1_001),
        Err(LifecycleAuthorizationError::AuditUnavailable)
    );
    // Replay was consumed before the failed audit; the request is burned.
    assert_eq!(
        authorizer.authorize(&p, &[sig], 1_001),
        Err(LifecycleAuthorizationError::Authorization(
            AuthzError::Replay
        ))
    );
}

// --- G110: authorized mutation of durable binding state (test-only) --------

#[test]
fn g110_authorized_rotation_updates_durable_registry() {
    let temp = Temp::new("g110-rotate");
    let old = kp(221);
    let new = kp(222);
    let op = kp(223);
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let ids = vec!["op-1".to_string()];
    let op_fps = vec![fingerprint(&op)];
    let enroll_ctx = MutationContext {
        request_id: "enroll-1",
        operator_ids: &ids,
        operator_key_fingerprints: &op_fps,
        at: 1_000,
    };
    reg.enroll(42, &b64(old.pubkey().as_ref()), &enroll_ctx)
        .unwrap();

    let p = payload(
        42,
        LifecycleOperation::Rotate,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = signed(&op, &p);
    let mut records = HashMap::new();
    records.insert(
        "op-1".to_string(),
        OperatorRecord::operator("op-1", b64(op.pubkey().as_ref())),
    );
    let authorizer = LifecycleAuthorizer::new(
        Trust(records),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
    );
    authorizer.authorize(&p, &[sig], 1_001).unwrap();

    let rotate_ctx = MutationContext {
        request_id: "rotate-1",
        operator_ids: &ids,
        operator_key_fingerprints: &op_fps,
        at: 1_001,
    };
    let updated = reg
        .rotate(42, 1, &b64(new.pubkey().as_ref()), &rotate_ctx)
        .unwrap();
    assert_eq!(updated.generation, 2);
    assert_eq!(updated.status, BindingStatus::Active);
    assert!(!reg.signing_allowed(42, &fingerprint(&old)).unwrap());
    assert!(reg.signing_allowed(42, &fingerprint(&new)).unwrap());
    assert_eq!(fs::read_dir(temp.path.join("audit")).unwrap().count(), 1);
}

#[test]
fn g110_audit_failure_prevents_registry_mutation() {
    let temp = Temp::new("g110-audit-fail");
    let old = kp(231);
    let new = kp(232);
    let op = kp(233);
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let ids = vec!["op-1".to_string()];
    let op_fps = vec![fingerprint(&op)];
    let ctx = MutationContext {
        request_id: "enroll-1",
        operator_ids: &ids,
        operator_key_fingerprints: &op_fps,
        at: 1_000,
    };
    reg.enroll(43, &b64(old.pubkey().as_ref()), &ctx).unwrap();
    let p = payload(
        43,
        LifecycleOperation::Rotate,
        2,
        &fingerprint(&old),
        &fingerprint(&new),
        1_000,
        1_200,
    );
    let sig = signed(&op, &p);
    let mut records = HashMap::new();
    records.insert(
        "op-1".to_string(),
        OperatorRecord::operator("op-1", b64(op.pubkey().as_ref())),
    );
    let authorizer = LifecycleAuthorizer::new(
        Trust(records),
        FileReplayStore::open(&temp.path).unwrap(),
        DenyAllAuditSink,
    );
    assert_eq!(
        authorizer.authorize(&p, &[sig], 1_001),
        Err(LifecycleAuthorizationError::AuditUnavailable)
    );
    assert_eq!(reg.get(43).unwrap().unwrap().generation, 1);
    assert!(reg.signing_allowed(43, &fingerprint(&old)).unwrap());
}

// --- G112 adversarial audit-file checks ------------------------------------

#[cfg(unix)]
#[test]
fn g112_audit_existing_event_with_wrong_mode_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new("audit-mode-bad");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();
    let path = fs::read_dir(temp.path.join("audit"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        sink.record(&event(100)).is_err(),
        "a world-readable audit file must not be accepted as idempotent"
    );
}

#[cfg(unix)]
#[test]
fn g112_audit_symlinked_existing_event_is_rejected() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new("audit-symlink");
    let sink = FileAuditSink::open(&temp.path).unwrap();
    sink.record(&event(100)).unwrap();
    let path = fs::read_dir(temp.path.join("audit"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    let body = fs::read(&path).unwrap();
    let target = temp.path.join("target.json");
    fs::write(&target, &body).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();
    assert!(
        sink.record(&event(100)).is_err(),
        "a symlinked audit event must not be accepted"
    );
}
