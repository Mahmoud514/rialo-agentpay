//! g1150 tests: wallet-file durability and operation idempotency.
//!
//! All keys are synthetic and live under a per-test temp directory. No real
//! wallet, signer store, RPC, signature, or transaction is touched.

use crate::user_lane::{
    UserDenial, create_user_wallet, user_key_path, user_record_path, user_wallet_operation_result,
};
use crate::wallet_file_safety::{
    begin_operation, complete_operation, inspect_wallet_files, read_operation, set_test_failpoint,
    set_test_failpoint_for, write_new_file_no_replace, OperationState, SafetyError, WalletFiles,
};
use crate::{SignerStore, user_lane};
use rialo_s_signer::Signer;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use uuid::Uuid;

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::CROSS_TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn tmp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("g1150-{tag}-{}-{}", std::process::id(), Uuid::new_v4()))
}

fn write_keypair(path: &Path, seed: u8) {
    use rialo_s_signer::Signer;
    let kp = rialo_s_keypair::keypair_from_seed(&[seed; 32]).unwrap();
    let mut file = std::fs::File::create(path).unwrap();
    rialo_s_keypair::write_keypair(&kp, &mut file).unwrap();
    let _ = kp.pubkey();
}

fn test_auth() -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap()
}

fn auth_pubkey() -> String {
    use rialo_s_signer::Signer;
    test_auth().pubkey().to_string()
}

fn sig_for(user: u64, nonce: &str) -> String {
    use rialo_s_signer::Signer;
    let msg = crate::user_signer_protocol::creation_intent_message(user, nonce);
    crate::base64_encode(&<[u8; 64]>::from(test_auth().sign_message(&msg)))
}

fn proof(secret: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes());
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

struct Fixture {
    dir: PathBuf,
    store: SignerStore,
    gate: crate::user_creation_gate::CreationGate,
    secret: String,
    proof: String,
    user: u64,
}

fn fixture(tag: &str, user: u64) -> Fixture {
    let dir = tmp_dir(tag);
    let store_root = dir.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = SignerStore::open(&store_root).unwrap();
    let gate = crate::user_creation_gate::CreationGate::open(&dir.join("gate")).unwrap();
    let secret = "deadbeef".repeat(8);
    let proof = proof(&secret);
    Fixture {
        dir,
        store,
        gate,
        secret,
        proof,
        user,
    }
}

fn bind(user: u64) {
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user}:{}", auth_pubkey()),
        );
    }
}

fn create(f: &Fixture, nonce: &str, operation_id: Option<&str>) -> Result<String, UserDenial> {
    let sig = sig_for(f.user, nonce);
    let result = match operation_id {
        Some(op) => user_lane::create_user_wallet_with_operation(
            &f.store,
            &f.gate,
            crate::user_lane::USER_WALLET_VERSION_V2,
            &f.secret,
            &f.proof,
            f.user,
            f.user,
            &sig,
            1_700_000_000,
            nonce,
            op,
        ),
        None => create_user_wallet(
            &f.store,
            &f.gate,
            crate::user_lane::USER_WALLET_VERSION_V2,
            &f.secret,
            &f.proof,
            f.user,
            f.user,
            &sig,
            1_700_000_000,
            nonce,
        ),
    };
    result.map(|(resp, _, _)| resp.public_address)
}

#[test]
fn writer_never_replaces_existing_inode_and_leaves_no_temp() {
    let dir = tmp_dir("writer");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wallet.json");
    std::fs::write(&path, b"old-wallet-bytes").unwrap();
    let err = write_new_file_no_replace(&path, b"new-wallet-bytes", 0o600).unwrap_err();
    assert_eq!(err, SafetyError::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"old-wallet-bytes");
    let entries = std::fs::read_dir(&dir).unwrap().count();
    assert_eq!(entries, 1, "temp must be removed");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn concurrent_writers_only_one_final_file() {
    let dir = tmp_dir("race");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wallet.json");
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for i in 0..8u8 {
        let p = path.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            write_new_file_no_replace(&p, &[i; 32], 0o600).is_ok()
        }));
    }
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(successes, 1);
    assert_eq!(std::fs::read(&path).unwrap().len(), 32);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "only the final file may remain"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn operation_journal_is_durable_public_only_and_idempotent() {
    let dir = tmp_dir("op");
    std::fs::create_dir_all(&dir).unwrap();
    let user = 7;
    let op = "v2-user-wallet:7";
    assert_eq!(
        begin_operation(&dir, user, op).unwrap(),
        OperationState::InProgress
    );
    assert_eq!(
        read_operation(&dir, user, op).unwrap(),
        OperationState::InProgress
    );
    let address = rialo_s_keypair::keypair_from_seed(&[3u8; 32])
        .unwrap()
        .pubkey()
        .to_string();
    let hash = "a".repeat(64);
    complete_operation(&dir, user, op, &address, &hash).unwrap();
    match read_operation(&dir, user, op).unwrap() {
        OperationState::Completed {
            public_address,
            record_sha256,
        } => {
            assert_eq!(public_address, address);
            assert_eq!(record_sha256, hash);
        }
        other => panic!("unexpected state: {other:?}"),
    }
    // Same public result is idempotent; conflicting result is refused.
    complete_operation(&dir, user, op, &address, &hash).unwrap();
    assert_eq!(
        complete_operation(&dir, user, op, &address, &"b".repeat(64)).unwrap_err(),
        SafetyError::Conflict
    );
    // The journal contains public metadata only.
    let text = std::fs::read_dir(dir.join("users/ops/7"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect::<String>();
    assert!(!text.contains("seed"));
    assert!(!text.contains("private"));
    assert!(!text.contains("draft"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn operation_begin_is_single_flight_under_concurrency() {
    let dir = tmp_dir("oprace");
    std::fs::create_dir_all(&dir).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let d = dir.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            begin_operation(&d, 9, "op-9").unwrap()
        }));
    }
    let states: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(states.iter().all(|s| matches!(s, OperationState::InProgress)));
    assert_eq!(
        std::fs::read_dir(dir.join("users/ops/9")).unwrap().count(),
        1,
        "exactly one started journal"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn create_writes_one_wallet_and_replay_never_changes_bytes() {
    let f = fixture("create", 50506318);
    let _g = env_guard();
    bind(f.user);
    let first = create(&f, "bm9uY2UtZzgx", None).expect("first create");
    let key_before = std::fs::read(user_key_path(&f.store, f.user)).unwrap();
    let rec_before = std::fs::read(user_record_path(&f.store, f.user)).unwrap();
    let second = create(&f, "bm9uY2Utc2Vjb25k", None);
    assert_eq!(second.unwrap_err(), UserDenial::AlreadyExists);
    assert_eq!(
        std::fs::read(user_key_path(&f.store, f.user)).unwrap(),
        key_before
    );
    assert_eq!(
        std::fs::read(user_record_path(&f.store, f.user)).unwrap(),
        rec_before
    );
    assert_eq!(
        user_wallet_operation_result(
            &f.store,
            f.user,
            &format!("v2-user-wallet:{}", f.user)
        )
        .unwrap(),
        Some(first)
    );
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn crash_after_key_before_record_never_mints_a_second_wallet() {
    let f = fixture("partial-key", 50506319);
    let _g = env_guard();
    bind(f.user);
    let key_path = user_key_path(&f.store, f.user);
    std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
    write_keypair(&key_path, 9);
    let before = std::fs::read(&key_path).unwrap();
    let err = create(&f, "bm9uY2UtcGFydGlhbA", None).unwrap_err();
    assert_eq!(err, UserDenial::ProvisioningIncomplete);
    assert!(!user_record_path(&f.store, f.user).exists());
    assert_eq!(std::fs::read(&key_path).unwrap(), before);
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn completed_journal_without_files_never_replaces() {
    let f = fixture("result-only", 50506320);
    let _g = env_guard();
    bind(f.user);
    let address = create(&f, "bm9uY2UtcmVzdWx0", None).expect("create");
    let key_path = user_key_path(&f.store, f.user);
    let record_path = user_record_path(&f.store, f.user);
    let key = std::fs::read(&key_path).unwrap();
    std::fs::remove_file(&key_path).unwrap();
    std::fs::remove_file(&record_path).unwrap();
    let err = create(&f, "bm9uY2UtcmVzdWx0Mg", None).unwrap_err();
    assert_eq!(err, UserDenial::ProvisioningIncomplete);
    assert!(!key_path.exists());
    // The durable result still records the prior public identity only.
    assert_eq!(
        user_wallet_operation_result(
            &f.store,
            f.user,
            &format!("v2-user-wallet:{}", f.user)
        )
        .unwrap(),
        Some(address)
    );
    // No private key was copied into the journal.
    let journal = std::fs::read_to_string(
        f.store
            .root()
            .join(format!("users/ops/{}/", f.user))
            .join(std::fs::read_dir(f.store.root().join(format!("users/ops/{}/", f.user))).unwrap().next().unwrap().unwrap().file_name()),
    )
    .unwrap();
    let key_text = String::from_utf8_lossy(&key).to_string();
    assert!(!journal.contains(&key_text));
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn crash_after_record_before_result_reconstructs_public_result() {
    let f = fixture("record-only", 50506321);
    let _g = env_guard();
    bind(f.user);
    let address = create(&f, "bm9uY2UtcmVjb3Jk", None).expect("create");
    let op_dir = f.store.root().join(format!("users/ops/{}/", f.user));
    let result = std::fs::read_dir(&op_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("result-"))
        .expect("result journal");
    std::fs::remove_file(&result).unwrap();
    let key_before = std::fs::read(user_key_path(&f.store, f.user)).unwrap();
    let rec_before = std::fs::read(user_record_path(&f.store, f.user)).unwrap();
    let replay = create(&f, "bm9uY2UtcmVjb3JkMg", None).unwrap_err();
    assert_eq!(replay, UserDenial::AlreadyExists);
    assert_eq!(
        std::fs::read(user_key_path(&f.store, f.user)).unwrap(),
        key_before
    );
    assert_eq!(
        std::fs::read(user_record_path(&f.store, f.user)).unwrap(),
        rec_before
    );
    assert_eq!(
        user_wallet_operation_result(
            &f.store,
            f.user,
            &format!("v2-user-wallet:{}", f.user)
        )
        .unwrap(),
        Some(address)
    );
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn inspect_reports_incomplete_without_creating_files() {
    let f = fixture("inspect", 50506322);
    assert_eq!(
        inspect_wallet_files(
            &user_key_path(&f.store, f.user),
            &user_record_path(&f.store, f.user),
            f.user
        )
        .unwrap(),
        WalletFiles::Missing
    );
    assert!(!user_key_path(&f.store, f.user).exists());
    assert!(!user_record_path(&f.store, f.user).exists());
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn key_publish_failpoint_then_retry_never_mints() {
    let f = fixture("fail-create-key", 50506325);
    let _g = env_guard();
    bind(f.user);
    set_test_failpoint_for(&user_key_path(&f.store, f.user), 1);
    let err = create(&f, "bm9uY2UtZmFpbDE", None).unwrap_err();
    set_test_failpoint(0);
    assert_eq!(err, UserDenial::StoreUnavailable);
    assert!(!user_key_path(&f.store, f.user).exists());
    assert!(!user_record_path(&f.store, f.user).exists());
    // The started journal remains; a retry is IN_PROGRESS, not a second mint.
    let retry = create(&f, "bm9uY2UtZmFpbDEy", None).unwrap_err();
    assert_eq!(retry, UserDenial::ProvisioningInProgress);
    assert!(!user_key_path(&f.store, f.user).exists());
    assert!(!user_record_path(&f.store, f.user).exists());
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn key_link_failpoint_leaves_one_complete_key_and_no_record() {
    let f = fixture("fail-create-link", 50506326);
    let _g = env_guard();
    bind(f.user);
    set_test_failpoint_for(&user_key_path(&f.store, f.user), 2);
    let err = create(&f, "bm9uY2UtZmFpbDI", None).unwrap_err();
    set_test_failpoint(0);
    assert_eq!(err, UserDenial::StoreUnavailable);
    let key = user_key_path(&f.store, f.user);
    assert!(key.exists());
    let key_before = std::fs::read(&key).unwrap();
    assert!(!user_record_path(&f.store, f.user).exists());
    // A retry classifies the partial pair as terminal; it never overwrites.
    let retry = create(&f, "bm9uY2UtZmFpbDIy", None).unwrap_err();
    assert_eq!(retry, UserDenial::ProvisioningIncomplete);
    assert_eq!(std::fs::read(&key).unwrap(), key_before);
    assert!(!user_record_path(&f.store, f.user).exists());
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn writer_failpoint_after_temp_write_publishes_nothing() {
    let dir = tmp_dir("fail-temp");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wallet.json");
    set_test_failpoint(1);
    assert_eq!(
        write_new_file_no_replace(&path, b"partial", 0o600).unwrap_err(),
        SafetyError::Unavailable
    );
    set_test_failpoint(0);
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn writer_failpoint_after_link_leaves_complete_final_untouched() {
    let dir = tmp_dir("fail-link");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wallet.json");
    set_test_failpoint(2);
    assert_eq!(
        write_new_file_no_replace(&path, b"complete-before-return-error", 0o600).unwrap_err(),
        SafetyError::Unavailable
    );
    set_test_failpoint(0);
    assert_eq!(std::fs::read(&path).unwrap(), b"complete-before-return-error");
    assert_eq!(
        write_new_file_no_replace(&path, b"must-not-replace", 0o600).unwrap_err(),
        SafetyError::AlreadyExists
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"complete-before-return-error");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn replay_after_reopened_store_does_not_rewrite_wallet() {
    let f = fixture("restart", 50506324);
    let _g = env_guard();
    bind(f.user);
    let first = create(&f, "bm9uY2UtcmVzdGFydA", None).expect("first create");
    let key_before = std::fs::read(user_key_path(&f.store, f.user)).unwrap();
    let rec_before = std::fs::read(user_record_path(&f.store, f.user)).unwrap();
    drop(f.gate);
    let store2 = SignerStore::open(f.store.root()).unwrap();
    let gate2 = crate::user_creation_gate::CreationGate::open(&f.dir.join("gate")).unwrap();
    let sig = sig_for(f.user, "bm9uY2UtcmVzdGFydDI");
    let replay = create_user_wallet(
        &store2,
        &gate2,
        crate::user_lane::USER_WALLET_VERSION_V2,
        &f.secret,
        &f.proof,
        f.user,
        f.user,
        &sig,
        1_700_000_100,
        "bm9uY2UtcmVzdGFydDI",
    );
    assert_eq!(replay.unwrap_err(), UserDenial::AlreadyExists);
    assert_eq!(
        std::fs::read(user_key_path(&store2, f.user)).unwrap(),
        key_before
    );
    assert_eq!(
        std::fs::read(user_record_path(&store2, f.user)).unwrap(),
        rec_before
    );
    assert_eq!(
        user_wallet_operation_result(&store2, f.user, &format!("v2-user-wallet:{}", f.user))
            .unwrap(),
        Some(first)
    );
    std::fs::remove_dir_all(&f.dir).ok();
}

#[test]
fn concurrent_create_for_same_user_has_one_wallet() {
    let f = fixture("create-race", 50506323);
    let _g = env_guard();
    bind(f.user);
    let barrier = Arc::new(Barrier::new(6));
    let root = f.store.root().to_path_buf();
    let gate_dir = f.dir.join("gate");
    let secret = f.secret.clone();
    let proof = f.proof.clone();
    let user = f.user;
    let mut handles = Vec::new();
    for i in 0..6 {
        let root = root.clone();
        let gate_dir = gate_dir.clone();
        let secret = secret.clone();
        let proof = proof.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            let store = SignerStore::open(&root).unwrap();
            let gate = crate::user_creation_gate::CreationGate::open(&gate_dir).unwrap();
            let nonce = format!("race-{i}");
            let sig = sig_for(user, &nonce);
            b.wait();
            create_user_wallet(
                &store,
                &gate,
                crate::user_lane::USER_WALLET_VERSION_V2,
                &secret,
                &proof,
                user,
                user,
                &sig,
                1_700_000_000,
                &nonce,
            )
            .is_ok()
        }));
    }
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert_eq!(successes, 1, "exactly one create may win");
    assert!(user_key_path(&f.store, f.user).exists());
    assert!(user_record_path(&f.store, f.user).exists());
    assert_eq!(
        std::fs::read_dir(f.store.root().join(format!("users/ops/{}/", f.user)))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("result-")
            })
            .count(),
        1
    );
    std::fs::remove_dir_all(&f.dir).ok();
}
