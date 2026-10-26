//! G113 — legacy wallet migration dry-run and failure-injection tests.
//! Synthetic wallet metadata only; key/recovery files are dummy bytes and are
//! never read by the migration scanner.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use rialo_s_signer::Signer;

use crate::SignerStore;
use crate::legacy_wallet_migration::{
    LegacyWalletMigration, LegacyWalletScanner, MigrationError, MigrationMode, MigrationOutcome,
    MigrationPlan, MigrationStatus,
};
use crate::user_authorization::{
    AuthorizationPayload, DenyAllAuditSink, LifecycleOperation, OperatorRecord, OperatorSignature,
    OperatorTrustStore, TrustStoreError,
};
use crate::user_authorization_store::{FileAuditSink, FileReplayStore};
use crate::user_binding_registry::{BindingStatus, RegistryError, UserBindingRegistry, WriteStage};

struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("g113-{tag}-{}", uuid::Uuid::new_v4()));
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

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn set_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

struct Legacy {
    wallet: Vec<u8>,
    key: Vec<u8>,
    recovery: Vec<u8>,
}

fn write_legacy(
    store: &SignerStore,
    user_id: u64,
    wallet_key: &rialo_s_keypair::Keypair,
    auth_key: &rialo_s_keypair::Keypair,
) -> Legacy {
    let users = store.root().join("users");
    fs::create_dir_all(&users).unwrap();
    let wallet = serde_json::to_vec(&serde_json::json!({
        "user_id": user_id,
        "public_address": wallet_key.pubkey().to_string(),
        "auth_pubkey": auth_key.pubkey().to_string(),
    }))
    .unwrap();
    let key = b"[]".to_vec();
    let recovery = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "wallet_version": 2,
        "user_id": user_id.to_string(),
        "canonical_creation_record": "a".repeat(64),
        "payout_hash": "b".repeat(64),
        "release_draft2_hex": "00",
        "released_auth_pubkey": auth_key.pubkey().to_string(),
        "wallet_address": wallet_key.pubkey().to_string(),
    }))
    .unwrap();
    for (name, body) in [
        (format!("{user_id}.wallet.json"), &wallet),
        (format!("{user_id}.key.json"), &key),
        (format!("{user_id}.recovery.json"), &recovery),
    ] {
        let path = users.join(name);
        fs::write(&path, body).unwrap();
        set_0600(&path);
    }
    Legacy {
        wallet,
        key,
        recovery,
    }
}

struct Trust(std::collections::HashMap<String, OperatorRecord>);

impl Trust {
    fn for_operator(op: &rialo_s_keypair::Keypair) -> Self {
        let record = OperatorRecord::operator("op-1", b64(op.pubkey().as_ref()))
            .with_operations(vec![LifecycleOperation::Migrate]);
        Self([("op-1".to_string(), record)].into_iter().collect())
    }
}

impl OperatorTrustStore for Trust {
    fn lookup(&self, operator_id: &str) -> Result<Option<OperatorRecord>, TrustStoreError> {
        Ok(self.0.get(operator_id).cloned())
    }
}

fn payload(
    plan: &MigrationPlan,
    entry: &crate::legacy_wallet_migration::MigrationPlanEntry,
    nonce: &str,
) -> AuthorizationPayload {
    AuthorizationPayload {
        version: 1,
        policy_version: 1,
        request_id: format!("migrate-{nonce}"),
        nonce: nonce.to_string(),
        operation: LifecycleOperation::Migrate,
        user_id: entry.user_id,
        generation: 1,
        current_key_fingerprint: String::new(),
        new_key_fingerprint: entry.auth_key_fingerprint.clone(),
        issued_at: 1_000,
        expires_at: 1_200,
        threshold: 1,
        operator_ids: vec!["op-1".to_string()],
    }
}

fn signed(op: &rialo_s_keypair::Keypair, payload: &AuthorizationPayload) -> OperatorSignature {
    OperatorSignature {
        operator_id: "op-1".to_string(),
        signature_b64: b64(op
            .sign_message(&payload.canonical_bytes().unwrap())
            .as_ref()),
    }
}

fn apply_migration(
    temp: &Temp,
    store: &SignerStore,
    op: &rialo_s_keypair::Keypair,
    mode: MigrationMode,
) -> LegacyWalletMigration<Trust, FileReplayStore, FileAuditSink> {
    LegacyWalletMigration::with_mode(
        store.clone(),
        UserBindingRegistry::open(&temp.path).unwrap(),
        Trust::for_operator(op),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        mode,
    )
}

#[test]
fn g113_dry_run_is_read_only_and_classifies_legacy_wallet() {
    let temp = Temp::new("dry");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(1);
    let auth_key = kp(2);
    let legacy = write_legacy(&store, 42, &wallet_key, &auth_key);
    assert!(!temp.path.join("bindings").exists());

    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.scanned, 1);
    assert_eq!(report.count(MigrationStatus::Migratable), 1);
    assert!(
        !temp.path.join("bindings").exists(),
        "dry-run created bindings"
    );
    assert_eq!(
        fs::read(store.root().join("users/42.wallet.json")).unwrap(),
        legacy.wallet
    );
    let candidate = &report.candidates[0];
    assert_eq!(candidate.user_id, 42);
    assert_eq!(candidate.auth_key_fingerprint.len(), 64);
    assert_eq!(candidate.wallet_address_fingerprint.len(), 64);
    assert!(!candidate.auth_pubkey_b64.is_empty());
}

#[test]
fn g113_apply_migrates_without_touching_legacy_files_and_is_idempotent() {
    let temp = Temp::new("apply");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(11);
    let auth_key = kp(12);
    let op = kp(13);
    let before = write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");
    let sig = signed(&op, &auth);

    let migration = apply_migration(&temp, &store, &op, MigrationMode::Apply);
    let outcome = migration
        .apply(&plan, &entry, &auth, &[sig.clone()], 1_001)
        .unwrap();
    let binding = match outcome {
        MigrationOutcome::Migrated(b) => b,
        MigrationOutcome::AlreadyMigrated(_) => panic!("expected migration"),
    };
    assert_eq!(binding.generation, 1);
    assert_eq!(binding.status, BindingStatus::Active);
    assert!(binding.migration.is_some());
    assert_eq!(binding.migration.unwrap().plan_hash, plan.plan_hash);
    assert_eq!(
        fs::read(store.root().join("users/42.wallet.json")).unwrap(),
        before.wallet
    );
    assert_eq!(
        fs::read(store.root().join("users/42.key.json")).unwrap(),
        before.key
    );
    assert_eq!(
        fs::read(store.root().join("users/42.recovery.json")).unwrap(),
        before.recovery
    );
    assert_eq!(fs::read_dir(temp.path.join("audit")).unwrap().count(), 1);

    // Rerun is idempotent; no second binding mutation is required.
    let again = migration
        .apply(&plan, &entry, &auth, &[sig], 1_001)
        .unwrap();
    assert!(matches!(again, MigrationOutcome::AlreadyMigrated(_)));
    let read = UserBindingRegistry::open_read_only(&temp.path).unwrap();
    assert_eq!(read.get(42).unwrap().unwrap().generation, 1);
}

#[test]
fn g113_default_mode_is_read_only() {
    let temp = Temp::new("readonly");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(21);
    let auth_key = kp(22);
    let op = kp(23);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");
    let sig = signed(&op, &auth);
    let migration = LegacyWalletMigration::new(
        store.clone(),
        UserBindingRegistry::open(&temp.path).unwrap(),
        Trust::for_operator(&op),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
    );
    assert_eq!(
        migration.apply(&plan, &entry, &auth, &[sig], 1_001),
        Err(MigrationError::Disabled)
    );
    assert!(
        UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .is_none()
    );
}

#[test]
fn g113_corrupt_unsafe_and_conflicting_candidates_are_rejected() {
    let temp = Temp::new("reject");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(31);
    let auth_key = kp(32);
    let legacy = write_legacy(&store, 42, &wallet_key, &auth_key);

    // Unsafe mode.
    let wallet_path = store.root().join("users/42.wallet.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wallet_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Unsafe);
    set_0600(&wallet_path);

    // Corrupt wallet.
    fs::write(&wallet_path, b"not-json").unwrap();
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Corrupt);

    // Missing recovery.
    write_legacy(&store, 42, &wallet_key, &auth_key);
    fs::remove_file(store.root().join("users/42.recovery.json")).unwrap();
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Unsupported);

    // Extra/unknown wallet fields are unsupported.
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&wallet_path).unwrap()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    fs::write(&wallet_path, serde_json::to_vec(&value).unwrap()).unwrap();
    set_0600(&wallet_path);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Corrupt);

    // Unexpected wallet file type (directory) is unsafe.
    fs::remove_file(&wallet_path).unwrap();
    fs::create_dir(&wallet_path).unwrap();
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Unsafe);
    fs::remove_dir(&wallet_path).unwrap();
    fs::write(&wallet_path, &legacy.wallet).unwrap();
    set_0600(&wallet_path);

    // Conflicting normal binding.
    let temp2 = Temp::new("conflict");
    let store2 = SignerStore::open(&temp2.path).unwrap();
    let reg = UserBindingRegistry::open(&temp2.path).unwrap();
    let ids = vec!["op-1".to_string()];
    let fps = vec!["a".repeat(64)];
    let ctx = crate::user_binding_registry::MutationContext {
        request_id: "bind-1",
        operator_ids: &ids,
        operator_key_fingerprints: &fps,
        at: 1_000,
    };
    reg.enroll(43, &b64(auth_key.pubkey().as_ref()), &ctx)
        .unwrap();
    write_legacy(&store2, 43, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store2.clone()).scan().unwrap();
    assert_eq!(report.candidates[0].status, MigrationStatus::Conflict);
}

#[test]
fn g113_audit_failure_prevents_migration() {
    let temp = Temp::new("audit-fail");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(41);
    let auth_key = kp(42);
    let op = kp(43);
    let before = write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");
    let migration = LegacyWalletMigration::with_mode(
        store.clone(),
        UserBindingRegistry::open(&temp.path).unwrap(),
        Trust::for_operator(&op),
        FileReplayStore::open(&temp.path).unwrap(),
        DenyAllAuditSink,
        MigrationMode::Apply,
    );
    assert_eq!(
        migration.apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001),
        Err(MigrationError::Approval(
            crate::user_authorization::LifecycleAuthorizationError::AuditUnavailable
        ))
    );
    assert!(
        UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read(store.root().join("users/42.wallet.json")).unwrap(),
        before.wallet
    );
}

#[test]
fn g113_write_failure_before_rename_leaves_no_binding() {
    for stage in [
        WriteStage::BeforeTemp,
        WriteStage::DuringTemp,
        WriteStage::BeforeRename,
    ] {
        let temp = Temp::new("write-fail");
        let store = SignerStore::open(&temp.path).unwrap();
        let wallet_key = kp(51);
        let auth_key = kp(52);
        let op = kp(53);
        let before = write_legacy(&store, 42, &wallet_key, &auth_key);
        let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
        let plan = MigrationPlan::from_report(&report).unwrap();
        let entry = plan.entries[0].clone();
        let auth = payload(&plan, &entry, "mn-1");
        let registry = UserBindingRegistry::open(&temp.path).unwrap();
        registry.set_write_failure(stage);
        let migration = LegacyWalletMigration::with_mode(
            store.clone(),
            registry,
            Trust::for_operator(&op),
            FileReplayStore::open(&temp.path).unwrap(),
            FileAuditSink::open(&temp.path).unwrap(),
            MigrationMode::Apply,
        );
        assert_eq!(
            migration.apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001),
            Err(MigrationError::Registry(RegistryError::Unavailable))
        );
        assert!(
            UserBindingRegistry::open_read_only(&temp.path)
                .unwrap()
                .get(42)
                .unwrap()
                .is_none(),
            "stage {stage:?} must not leave a binding"
        );
        assert_eq!(
            fs::read(store.root().join("users/42.wallet.json")).unwrap(),
            before.wallet
        );
        assert_eq!(
            fs::read(store.root().join("users/42.key.json")).unwrap(),
            before.key
        );
        assert_eq!(
            fs::read(store.root().join("users/42.recovery.json")).unwrap(),
            before.recovery
        );
    }
}

#[test]
fn g113_write_failure_after_rename_is_ambiguous_and_recoverable() {
    for stage in [WriteStage::AfterRename, WriteStage::DirSync] {
        let temp = Temp::new("post-rename");
        let store = SignerStore::open(&temp.path).unwrap();
        let wallet_key = kp(61);
        let auth_key = kp(62);
        let op = kp(63);
        let before = write_legacy(&store, 42, &wallet_key, &auth_key);
        let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
        let plan = MigrationPlan::from_report(&report).unwrap();
        let entry = plan.entries[0].clone();
        let auth = payload(&plan, &entry, "mn-1");
        let registry = UserBindingRegistry::open(&temp.path).unwrap();
        registry.set_write_failure(stage);
        let migration = LegacyWalletMigration::with_mode(
            store.clone(),
            registry,
            Trust::for_operator(&op),
            FileReplayStore::open(&temp.path).unwrap(),
            FileAuditSink::open(&temp.path).unwrap(),
            MigrationMode::Apply,
        );
        assert_eq!(
            migration.apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001),
            Err(MigrationError::Registry(RegistryError::Unavailable))
        );
        let binding = UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .unwrap();
        assert_eq!(binding.generation, 1);
        assert!(binding.migration.is_some());
        assert_eq!(
            fs::read(store.root().join("users/42.wallet.json")).unwrap(),
            before.wallet
        );
        assert_eq!(
            fs::read(store.root().join("users/42.key.json")).unwrap(),
            before.key
        );
        assert_eq!(
            fs::read(store.root().join("users/42.recovery.json")).unwrap(),
            before.recovery
        );

        // Rerun observes AlreadyMigrated; the legacy file remains untouched.
        let migration2 = apply_migration(&temp, &store, &op, MigrationMode::Apply);
        let outcome = migration2
            .apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001)
            .unwrap();
        assert!(matches!(outcome, MigrationOutcome::AlreadyMigrated(_)));
        assert_eq!(
            fs::read(store.root().join("users/42.wallet.json")).unwrap(),
            before.wallet
        );
    }
}

#[test]
fn g113_unsafe_or_missing_wallet_files_are_rejected() {
    let temp = Temp::new("unsafe");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(71);
    let auth_key = kp(72);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let wallet_path = store.root().join("users/42.wallet.json");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = store.root().join("users/target.json");
        fs::copy(&wallet_path, &target).unwrap();
        fs::remove_file(&wallet_path).unwrap();
        symlink(&target, &wallet_path).unwrap();
        let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
        assert_eq!(report.candidates[0].status, MigrationStatus::Unsafe);
    }
    let _ = wallet_path;
}

#[test]
fn g113_restart_after_interrupted_migration_preserves_binding() {
    let temp = Temp::new("restart");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(81);
    let auth_key = kp(82);
    let op = kp(83);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");
    {
        let migration = apply_migration(&temp, &store, &op, MigrationMode::Apply);
        migration
            .apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001)
            .unwrap();
    }
    let reopened = UserBindingRegistry::open_read_only(&temp.path).unwrap();
    let binding = reopened.get(42).unwrap().unwrap();
    assert_eq!(binding.generation, 1);
    assert!(binding.migration.is_some());
}

#[test]
fn g113_approval_mismatch_expired_and_unauthorized_are_rejected() {
    let temp = Temp::new("approval-neg");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(91);
    let auth_key = kp(92);
    let op = kp(93);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();

    let mut mismatch = payload(&plan, &entry, "mn-1");
    mismatch.user_id = 43;
    let migration = apply_migration(&temp, &store, &op, MigrationMode::Apply);
    assert_eq!(
        migration.apply(&plan, &entry, &mismatch, &[signed(&op, &mismatch)], 1_001),
        Err(MigrationError::ApprovalMismatch)
    );

    let mut expired = payload(&plan, &entry, "mn-2");
    expired.issued_at = 900;
    expired.expires_at = 1_000;
    assert_eq!(
        migration.apply(&plan, &entry, &expired, &[signed(&op, &expired)], 1_001),
        Err(MigrationError::Approval(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::Expired
            )
        ))
    );
    assert!(
        UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .is_none()
    );

    let mut wrong_scope = OperatorRecord::operator("op-1", b64(op.pubkey().as_ref()))
        .with_operations(vec![LifecycleOperation::Enroll]);
    wrong_scope.active = true;
    let migration2 = LegacyWalletMigration::with_mode(
        store.clone(),
        UserBindingRegistry::open(&temp.path).unwrap(),
        Trust([("op-1".to_string(), wrong_scope)].into_iter().collect()),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        MigrationMode::Apply,
    );
    let valid = payload(&plan, &entry, "mn-3");
    assert_eq!(
        migration2.apply(&plan, &entry, &valid, &[signed(&op, &valid)], 1_001),
        Err(MigrationError::Approval(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::UnauthorizedOperation
            )
        ))
    );
}

#[test]
fn g113_retry_after_pre_rename_failure_needs_fresh_authorization() {
    let temp = Temp::new("retry");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(101);
    let auth_key = kp(102);
    let op = kp(103);
    let before = write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let first = payload(&plan, &entry, "mn-1");
    let registry = UserBindingRegistry::open(&temp.path).unwrap();
    registry.set_write_failure(WriteStage::BeforeRename);
    let migration = LegacyWalletMigration::with_mode(
        store.clone(),
        registry,
        Trust::for_operator(&op),
        FileReplayStore::open(&temp.path).unwrap(),
        FileAuditSink::open(&temp.path).unwrap(),
        MigrationMode::Apply,
    );
    assert_eq!(
        migration.apply(&plan, &entry, &first, &[signed(&op, &first)], 1_001),
        Err(MigrationError::Registry(RegistryError::Unavailable))
    );
    assert!(
        UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .is_none()
    );
    // The D8 authorization was consumed; retrying it is a replay.
    assert_eq!(
        migration.apply(&plan, &entry, &first, &[signed(&op, &first)], 1_001),
        Err(MigrationError::Approval(
            crate::user_authorization::LifecycleAuthorizationError::Authorization(
                crate::user_authorization::AuthzError::Replay
            )
        ))
    );
    // A fresh authorization (new nonce) can complete the same plan.
    let second = payload(&plan, &entry, "mn-2");
    let migration2 = apply_migration(&temp, &store, &op, MigrationMode::Apply);
    let outcome = migration2
        .apply(&plan, &entry, &second, &[signed(&op, &second)], 1_002)
        .unwrap();
    assert!(matches!(outcome, MigrationOutcome::Migrated(_)));
    assert_eq!(
        fs::read(store.root().join("users/42.wallet.json")).unwrap(),
        before.wallet
    );
}

#[test]
fn g113_plan_entry_must_match_rescanned_wallet() {
    let temp = Temp::new("rescan");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(111);
    let auth_key = kp(112);
    let replacement = kp(113);
    let op = kp(114);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");

    // Change both public wallet and recovery auth fields after planning.
    let users = store.root().join("users");
    let wallet = serde_json::json!({
        "user_id": 42,
        "public_address": wallet_key.pubkey().to_string(),
        "auth_pubkey": replacement.pubkey().to_string(),
    });
    fs::write(
        users.join("42.wallet.json"),
        serde_json::to_vec(&wallet).unwrap(),
    )
    .unwrap();
    set_0600(&users.join("42.wallet.json"));
    let recovery = serde_json::json!({
        "version": 1,
        "wallet_version": 2,
        "user_id": "42",
        "canonical_creation_record": "a".repeat(64),
        "payout_hash": "b".repeat(64),
        "release_draft2_hex": "00",
        "released_auth_pubkey": replacement.pubkey().to_string(),
        "wallet_address": wallet_key.pubkey().to_string(),
    });
    fs::write(
        users.join("42.recovery.json"),
        serde_json::to_vec(&recovery).unwrap(),
    )
    .unwrap();
    set_0600(&users.join("42.recovery.json"));

    let migration = apply_migration(&temp, &store, &op, MigrationMode::Apply);
    assert_eq!(
        migration.apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001),
        Err(MigrationError::PlanInvalid)
    );
    assert!(
        UserBindingRegistry::open_read_only(&temp.path)
            .unwrap()
            .get(42)
            .unwrap()
            .is_none()
    );
}

#[test]
fn g113_already_migrated_survives_post_migration_rotation() {
    let temp = Temp::new("rotated");
    let store = SignerStore::open(&temp.path).unwrap();
    let wallet_key = kp(121);
    let auth_key = kp(122);
    let op = kp(123);
    let next = kp(124);
    write_legacy(&store, 42, &wallet_key, &auth_key);
    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    let plan = MigrationPlan::from_report(&report).unwrap();
    let entry = plan.entries[0].clone();
    let auth = payload(&plan, &entry, "mn-1");
    let migration = apply_migration(&temp, &store, &op, MigrationMode::Apply);
    migration
        .apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_001)
        .unwrap();

    let reg = UserBindingRegistry::open(&temp.path).unwrap();
    let ids = vec!["op-1".to_string()];
    let fps = vec!["a".repeat(64)];
    let ctx = crate::user_binding_registry::MutationContext {
        request_id: "post-migration-rotate",
        operator_ids: &ids,
        operator_key_fingerprints: &fps,
        at: 1_100,
    };
    reg.rotate(42, 1, &b64(next.pubkey().as_ref()), &ctx)
        .unwrap();

    let report = LegacyWalletScanner::new(store.clone()).scan().unwrap();
    assert_eq!(
        report.candidates[0].status,
        MigrationStatus::AlreadyMigrated
    );
    let again = apply_migration(&temp, &store, &op, MigrationMode::Apply)
        .apply(&plan, &entry, &auth, &[signed(&op, &auth)], 1_200)
        .unwrap();
    assert!(matches!(again, MigrationOutcome::AlreadyMigrated(_)));
}
