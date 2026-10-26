//! G110 — durable user binding/revocation registry tests.
//!
//! Synthetic keys, temporary directories and public metadata only. No real
//! identity, operator key, wallet or funds are involved.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;

use base64::Engine as _;
use rialo_s_signer::Signer;

use crate::user_authorization::auth_key_fingerprint;
use crate::user_binding_registry::{
    BindingStatus, MutationContext, RegistryError, UserBindingRegistry,
};

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("g110-{tag}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn kp(seed: u8) -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(&[seed; 32]).unwrap()
}

fn pub_b64(k: &rialo_s_keypair::Keypair) -> String {
    base64::engine::general_purpose::STANDARD.encode(k.pubkey().as_ref())
}

fn fingerprint(k: &rialo_s_keypair::Keypair) -> String {
    auth_key_fingerprint(k.pubkey().as_ref()).unwrap()
}

fn ops() -> (Vec<String>, Vec<String>) {
    (vec!["op-1".to_string()], vec!["a".repeat(64)])
}

fn context_at<'a>(
    request_id: &'a str,
    ids: &'a [String],
    fps: &'a [String],
    at: u64,
) -> MutationContext<'a> {
    MutationContext {
        request_id,
        operator_ids: ids,
        operator_key_fingerprints: fps,
        at,
    }
}

fn context<'a>(request_id: &'a str, ids: &'a [String], fps: &'a [String]) -> MutationContext<'a> {
    context_at(request_id, ids, fps, 1_000)
}

#[test]
fn g110_enroll_persists_across_restart() {
    let temp = Temp::new("enroll");
    let key = kp(1);
    let (ids, fps) = ops();
    let binding = {
        let reg = UserBindingRegistry::open(&temp.path).unwrap();
        let b = reg
            .enroll(42, &pub_b64(&key), &context("req-1", &ids, &fps))
            .unwrap();
        assert_eq!(b.generation, 1);
        assert_eq!(b.status, BindingStatus::Active);
        b
    };
    let reopened = UserBindingRegistry::open(&temp.path).unwrap();
    assert_eq!(reopened.get(42).unwrap().unwrap(), binding);
    assert!(reopened.signing_allowed(42, &fingerprint(&key)).unwrap());
    assert!(!reopened.signing_allowed(42, &"0".repeat(64)).unwrap());
}

#[test]
fn g110_duplicate_enroll_is_rejected_even_after_revoke() {
    let temp = Temp::new("duplicate");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(2);
    let (ids, fps) = ops();
    reg.enroll(7, &pub_b64(&key), &context("req-1", &ids, &fps))
        .unwrap();
    assert_eq!(
        reg.enroll(7, &pub_b64(&key), &context("req-2", &ids, &fps)),
        Err(RegistryError::AlreadyExists)
    );
    reg.revoke(7, 1, &context("req-3", &ids, &fps)).unwrap();
    assert_eq!(
        reg.enroll(7, &pub_b64(&kp(3)), &context("req-4", &ids, &fps)),
        Err(RegistryError::AlreadyExists)
    );
}

#[test]
fn g110_rotate_changes_generation_and_invalidates_old_key() {
    let temp = Temp::new("rotate");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let old = kp(11);
    let new = kp(12);
    let (ids, fps) = ops();
    reg.enroll(9, &pub_b64(&old), &context("req-1", &ids, &fps))
        .unwrap();
    let b = reg
        .rotate(
            9,
            1,
            &pub_b64(&new),
            &context_at("req-2", &ids, &fps, 1_100),
        )
        .unwrap();
    assert_eq!(b.generation, 2);
    assert_eq!(b.key_fingerprint, fingerprint(&new));
    assert!(!reg.signing_allowed(9, &fingerprint(&old)).unwrap());
    assert!(reg.signing_allowed(9, &fingerprint(&new)).unwrap());
    assert_eq!(
        reg.rotate(
            9,
            1,
            &pub_b64(&old),
            &context_at("req-3", &ids, &fps, 1_200)
        ),
        Err(RegistryError::GenerationMismatch)
    );
    assert_eq!(
        reg.rotate(
            9,
            2,
            &pub_b64(&new),
            &context_at("req-4", &ids, &fps, 1_300)
        ),
        Err(RegistryError::SameKey)
    );
}

#[test]
fn g110_revoke_is_terminal_and_blocks_rotation_and_signing() {
    let temp = Temp::new("revoke");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(21);
    let next = kp(22);
    let (ids, fps) = ops();
    reg.enroll(5, &pub_b64(&key), &context("req-1", &ids, &fps))
        .unwrap();
    assert_eq!(
        reg.revoke(5, 99, &context_at("req-1b", &ids, &fps, 1_050)),
        Err(RegistryError::GenerationMismatch)
    );
    let revoked = reg
        .revoke(5, 1, &context_at("req-2", &ids, &fps, 1_100))
        .unwrap();
    assert_eq!(revoked.status, BindingStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(1_100));
    assert!(!reg.signing_allowed(5, &fingerprint(&key)).unwrap());
    assert_eq!(
        reg.revoke(5, 1, &context_at("req-3", &ids, &fps, 1_200)),
        Err(RegistryError::AlreadyRevoked)
    );
    assert_eq!(
        reg.rotate(
            5,
            1,
            &pub_b64(&next),
            &context_at("req-4", &ids, &fps, 1_300)
        ),
        Err(RegistryError::Revoked)
    );
    assert_eq!(
        reg.rotate(
            5,
            2,
            &pub_b64(&next),
            &context_at("req-5", &ids, &fps, 1_400)
        ),
        Err(RegistryError::Revoked)
    );
}

#[test]
fn g110_rotation_and_revocation_survive_restart() {
    let temp = Temp::new("restart");
    let old = kp(31);
    let new = kp(32);
    let (ids, fps) = ops();
    {
        let reg = UserBindingRegistry::open(&temp.path).unwrap();
        reg.enroll(3, &pub_b64(&old), &context("req-1", &ids, &fps))
            .unwrap();
        reg.rotate(
            3,
            1,
            &pub_b64(&new),
            &context_at("req-2", &ids, &fps, 1_100),
        )
        .unwrap();
    }
    {
        let reg = UserBindingRegistry::open(&temp.path).unwrap();
        let b = reg.get(3).unwrap().unwrap();
        assert_eq!(b.generation, 2);
        assert_eq!(b.key_fingerprint, fingerprint(&new));
        reg.revoke(3, 2, &context_at("req-3", &ids, &fps, 1_200))
            .unwrap();
    }
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let b = reg.get(3).unwrap().unwrap();
    assert_eq!(b.status, BindingStatus::Revoked);
    assert_eq!(b.generation, 2);
    assert!(!reg.signing_allowed(3, &fingerprint(&new)).unwrap());
}

#[test]
fn g110_concurrent_enroll_has_exactly_one_winner() {
    let temp = Temp::new("concurrent-enroll");
    let reg = Arc::new(UserBindingRegistry::open(&temp.path).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let key = pub_b64(&kp(41));
    let (ids, fps) = ops();
    let mut handles = Vec::new();
    for i in 0..8 {
        let reg = Arc::clone(&reg);
        let barrier = Arc::clone(&barrier);
        let key = key.clone();
        let ids = ids.clone();
        let fps = fps.clone();
        handles.push(thread::spawn(move || {
            let req = format!("req-{i}");
            barrier.wait();
            reg.enroll(44, &key, &context(&req, &ids, &fps))
                .map(|b| b.generation)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(RegistryError::AlreadyExists))
            .count(),
        7
    );
}

#[test]
fn g110_concurrent_rotate_has_exactly_one_winner() {
    let temp = Temp::new("concurrent-rotate");
    let reg = Arc::new(UserBindingRegistry::open(&temp.path).unwrap());
    let old = kp(51);
    let new = kp(52);
    let (ids, fps) = ops();
    reg.enroll(55, &pub_b64(&old), &context("req-1", &ids, &fps))
        .unwrap();
    let barrier = Arc::new(Barrier::new(6));
    let new_b64 = pub_b64(&new);
    let mut handles = Vec::new();
    for i in 0..6 {
        let reg = Arc::clone(&reg);
        let barrier = Arc::clone(&barrier);
        let new_b64 = new_b64.clone();
        let ids = ids.clone();
        let fps = fps.clone();
        handles.push(thread::spawn(move || {
            let req = format!("req-r{i}");
            barrier.wait();
            reg.rotate(55, 1, &new_b64, &context(&req, &ids, &fps))
                .map(|b| b.generation)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(RegistryError::GenerationMismatch))
            .count(),
        5
    );
    assert_eq!(reg.get(55).unwrap().unwrap().generation, 2);
}

#[test]
fn g110_corrupt_record_fails_closed_without_overwrite() {
    let temp = Temp::new("corrupt");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(61);
    let (ids, fps) = ops();
    reg.enroll(66, &pub_b64(&key), &context("req-1", &ids, &fps))
        .unwrap();
    let path = temp.path.join("bindings/66.json");
    fs::write(&path, b"not-json").unwrap();
    assert_eq!(reg.get(66), Err(RegistryError::Corrupt));
    assert_eq!(
        reg.rotate(66, 1, &pub_b64(&kp(62)), &context("req-2", &ids, &fps)),
        Err(RegistryError::Corrupt)
    );
    assert_eq!(fs::read(&path).unwrap(), b"not-json".to_vec());
}

#[test]
fn g110_duplicate_operator_metadata_is_corrupt() {
    let temp = Temp::new("corrupt-ops");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(63);
    let (ids, fps) = ops();
    reg.enroll(67, &pub_b64(&key), &context("req-1", &ids, &fps))
        .unwrap();
    let path = temp.path.join("bindings/67.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["last_operator_ids"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("op-1"));
    value["last_operator_key_fingerprints"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("a".repeat(64)));
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(reg.get(67), Err(RegistryError::Corrupt));
}

#[test]
fn g110_storage_failure_fails_closed() {
    let temp = Temp::new("storage");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    fs::remove_dir_all(temp.path.join("bindings")).unwrap();
    fs::write(temp.path.join("bindings"), b"not a directory").unwrap();
    let (ids, fps) = ops();
    assert_eq!(
        reg.enroll(77, &pub_b64(&kp(71)), &context("req-1", &ids, &fps)),
        Err(RegistryError::Unavailable)
    );
    assert_eq!(reg.get(77), Err(RegistryError::Unavailable));
}

#[cfg(unix)]
#[test]
fn g110_symlinked_record_is_rejected() {
    use std::os::unix::fs::symlink;
    let temp = Temp::new("symlink");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let real = temp.path.join("real.json");
    fs::write(&real, b"{}").unwrap();
    symlink(&real, temp.path.join("bindings/88.json")).unwrap();
    assert_eq!(reg.get(88), Err(RegistryError::Corrupt));
}

#[cfg(unix)]
#[test]
fn g110_binding_files_and_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let temp = Temp::new("modes");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(81);
    let (ids, fps) = ops();
    reg.enroll(99, &pub_b64(&key), &context("req-1", &ids, &fps))
        .unwrap();
    let dir_mode = fs::metadata(temp.path.join("bindings"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    let file_mode = fs::metadata(temp.path.join("bindings/99.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(file_mode, 0o600);
    let leftovers: Vec<_> = fs::read_dir(temp.path.join("bindings"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp file may remain after success"
    );
}

#[test]
fn g110_malformed_inputs_are_rejected() {
    let temp = Temp::new("malformed");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(91);
    let (ids, fps) = ops();
    assert_eq!(
        reg.enroll(0, &pub_b64(&key), &context("req-1", &ids, &fps)),
        Err(RegistryError::Malformed)
    );
    assert_eq!(
        reg.enroll(1, "!!!", &context("req-1", &ids, &fps)),
        Err(RegistryError::Malformed)
    );
    assert_eq!(
        reg.enroll(1, &pub_b64(&key), &context("", &ids, &fps)),
        Err(RegistryError::Malformed)
    );
    let empty: Vec<String> = vec![];
    assert_eq!(
        reg.enroll(1, &pub_b64(&key), &context("req-1", &empty, &fps)),
        Err(RegistryError::Malformed)
    );
    let ids2 = vec!["op-1".to_string(), "op-2".to_string()];
    let fps2 = vec!["a".repeat(64), "a".repeat(64)];
    assert_eq!(
        reg.enroll(1, &pub_b64(&key), &context("req-1", &ids2, &fps2)),
        Err(RegistryError::Malformed),
        "duplicate operator key fingerprints are not distinct approvals"
    );
}

#[test]
fn g110_cross_user_isolation_and_audit_metadata() {
    let temp = Temp::new("isolation");
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let a = kp(101);
    let b = kp(102);
    let ids = vec!["op-1".to_string(), "op-2".to_string()];
    let fps = vec!["a".repeat(64), "b".repeat(64)];
    let ctx = context("req-a", &ids, &fps);
    reg.enroll(1, &pub_b64(&a), &ctx).unwrap();
    reg.enroll(2, &pub_b64(&b), &ctx).unwrap();
    assert_eq!(reg.get(1).unwrap().unwrap().auth_pubkey_b64, pub_b64(&a));
    assert_eq!(reg.get(2).unwrap().unwrap().auth_pubkey_b64, pub_b64(&b));
    assert_eq!(reg.get(1).unwrap().unwrap().last_request_id, "req-a");
    assert_eq!(reg.get(1).unwrap().unwrap().last_operator_ids, ids);
    assert_eq!(
        reg.get(1).unwrap().unwrap().last_operator_key_fingerprints,
        fps
    );
    assert_eq!(
        reg.get(3).unwrap(),
        None,
        "unknown user is not implicitly bound"
    );
    assert_eq!(
        reg.signing_allowed(3, &fingerprint(&a)),
        Err(RegistryError::NotFound)
    );
}

// --- G112 adversarial regressions -----------------------------------------

#[test]
fn g112_two_registry_instances_share_one_process_lock() {
    let temp = Temp::new("shared-lock");
    let old = kp(201);
    let a = kp(202);
    let b = kp(203);
    let (ids, fps) = ops();
    let r1 = UserBindingRegistry::open(&temp.path).unwrap();
    let r2 = UserBindingRegistry::open(&temp.path).unwrap();
    r1.enroll(300, &pub_b64(&old), &context("req-1", &ids, &fps))
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let a_b64 = pub_b64(&a);
    let b_b64 = pub_b64(&b);
    let t1 = {
        let barrier = Arc::clone(&barrier);
        let ids = ids.clone();
        let fps = fps.clone();
        thread::spawn(move || {
            barrier.wait();
            r1.rotate(300, 1, &a_b64, &context("req-a", &ids, &fps))
        })
    };
    let t2 = {
        let barrier = Arc::clone(&barrier);
        let ids = ids.clone();
        let fps = fps.clone();
        thread::spawn(move || {
            barrier.wait();
            r2.rotate(300, 1, &b_b64, &context("req-b", &ids, &fps))
        })
    };
    let ra = t1.join().unwrap();
    let rb = t2.join().unwrap();
    assert_eq!(
        [ra.is_ok(), rb.is_ok()].iter().filter(|ok| **ok).count(),
        1,
        "exactly one registry instance may rotate"
    );
    assert!(
        [ra, rb]
            .iter()
            .any(|r| *r == Err(RegistryError::GenerationMismatch)),
        "loser must observe the committed generation"
    );
}

#[test]
fn g112_enrollment_rejects_existing_legacy_wallet() {
    let temp = Temp::new("legacy-wallet");
    fs::create_dir_all(temp.path.join("users")).unwrap();
    fs::write(
        temp.path.join("users/300.wallet.json"),
        br#"{"user_id":"300","address":"SYNTH300"}"#,
    )
    .unwrap();
    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let key = kp(211);
    let (ids, fps) = ops();
    assert_eq!(
        reg.enroll(300, &pub_b64(&key), &context("req-1", &ids, &fps)),
        Err(RegistryError::AlreadyExists)
    );
    assert_eq!(reg.get(300).unwrap(), None);
}
