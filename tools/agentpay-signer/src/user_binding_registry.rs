//! G110 — durable user-to-authentication-key binding and revocation registry.
//!
//! This is the authoritative durable state for one active authentication key
//! per user. It is **not wired** into any route or signer mutation. A future
//! lifecycle operation must call `LifecycleAuthorizer` (D8 + replay + audit)
//! and this registry as one approved operation.
//!
//! Storage model: one JSON record per user under `<root>/bindings`, directory
//! 0700, file 0600. Writes use create-new temp + fsync + atomic rename +
//! directory fsync. Process concurrency is serialized by a mutex; cross-process
//! safety relies on the signer's existing one-process-per-store `flock`
//! discipline. The record itself carries the redacted mutation audit metadata
//! (request id, operator ids and public-key fingerprints), so state and its
//! audit metadata commit atomically in the same file.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::user_authorization::{auth_key_fingerprint, decode_auth_pubkey};

const RECORD_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Active,
    Revoked,
}

/// Durable binding record. Public keys and public fingerprints only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserBinding {
    pub version: u8,
    pub user_id: u64,
    pub auth_pubkey_b64: String,
    pub key_fingerprint: String,
    pub generation: u64,
    pub status: BindingStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_request_id: String,
    pub last_operator_ids: Vec<String>,
    pub last_operator_key_fingerprints: Vec<String>,
    pub revoked_at: Option<u64>,
    /// Present only for a record created by the legacy-wallet migration.
    #[serde(default)]
    pub migration: Option<MigrationMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationMetadata {
    pub plan_hash: String,
    pub wallet_address_fingerprint: String,
    pub migrated_at: u64,
}

/// Redacted metadata accompanying every binding mutation.
#[derive(Debug, Clone, Copy)]
pub struct MutationContext<'a> {
    pub request_id: &'a str,
    pub operator_ids: &'a [String],
    pub operator_key_fingerprints: &'a [String],
    pub at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    Unavailable,
    Corrupt,
    AlreadyExists,
    NotFound,
    Revoked,
    AlreadyRevoked,
    GenerationMismatch,
    KeyMismatch,
    SameKey,
    Malformed,
    LegacyWalletMissing,
}

static PROCESS_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

fn shared_process_lock(dir: &Path) -> Result<Arc<Mutex<()>>, RegistryError> {
    // Canonicalize so two relative/absolute opens of the same directory share
    // one lock within this process. Cross-process locking still relies on the
    // signer's one-process-per-store flock.
    let key = fs::canonicalize(dir).map_err(|_| RegistryError::Unavailable)?;
    let map = PROCESS_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().map_err(|_| RegistryError::Unavailable)?;
    Ok(map
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

pub struct UserBindingRegistry {
    dir: PathBuf,
    wallet_dir: PathBuf,
    lock: Arc<Mutex<()>>,
    #[cfg(test)]
    failure: Arc<Mutex<Option<WriteStage>>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteStage {
    BeforeTemp,
    DuringTemp,
    BeforeRename,
    AfterRename,
    DirSync,
}

impl UserBindingRegistry {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let root = root.as_ref();
        let dir = root.join("bindings");
        ensure_private_dir(&dir).map_err(|_| RegistryError::Unavailable)?;
        let lock = shared_process_lock(&dir)?;
        Ok(Self {
            dir,
            wallet_dir: root.join("users"),
            lock,
            #[cfg(test)]
            failure: Arc::new(Mutex::new(None)),
        })
    }

    /// Read-only view used by migration dry-runs. Creates no directory.
    pub fn open_read_only(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let root = root.as_ref();
        let dir = root.join("bindings");
        match fs::symlink_metadata(&dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(RegistryError::Corrupt);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o077 != 0 {
                        return Err(RegistryError::Corrupt);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RegistryError::Unavailable),
        }
        Ok(Self {
            dir,
            wallet_dir: root.join("users"),
            lock: Arc::new(Mutex::new(())),
            #[cfg(test)]
            failure: Arc::new(Mutex::new(None)),
        })
    }

    pub fn get(&self, user_id: u64) -> Result<Option<UserBinding>, RegistryError> {
        if user_id == 0 {
            return Err(RegistryError::Malformed);
        }
        let _guard = self.lock.lock().map_err(|_| RegistryError::Unavailable)?;
        self.read(user_id)
    }

    pub fn enroll(
        &self,
        user_id: u64,
        auth_pubkey_b64: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        validate_user(user_id)?;
        validate_context(ctx)?;
        let fingerprint = fingerprint_of(auth_pubkey_b64)?;
        let _guard = self.lock.lock().map_err(|_| RegistryError::Unavailable)?;
        if self.read(user_id)?.is_some() {
            return Err(RegistryError::AlreadyExists);
        }
        // Do not let a new registry enrollment silently replace a pre-existing
        // user wallet that has no binding record (legacy/provisioned wallet).
        // Migration is an explicit operator operation, not enrollment.
        match fs::symlink_metadata(self.wallet_path(user_id)) {
            Ok(_) => return Err(RegistryError::AlreadyExists),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RegistryError::Unavailable),
        }
        let binding = UserBinding {
            version: RECORD_VERSION,
            user_id,
            auth_pubkey_b64: auth_pubkey_b64.to_string(),
            key_fingerprint: fingerprint,
            generation: 1,
            status: BindingStatus::Active,
            created_at: ctx.at,
            updated_at: ctx.at,
            last_request_id: ctx.request_id.to_string(),
            last_operator_ids: ctx.operator_ids.to_vec(),
            last_operator_key_fingerprints: ctx.operator_key_fingerprints.to_vec(),
            revoked_at: None,
            migration: None,
        };
        self.write(&binding)?;
        Ok(binding)
    }

    /// Operator-authorized migration of a legacy wallet. This bypasses the
    /// enrollment guard for an existing `users/<id>.wallet.json`, but only the
    /// explicit migration workflow may call it; it never modifies the legacy
    /// files and never overwrites an existing binding.
    pub(crate) fn migrate_legacy(
        &self,
        user_id: u64,
        auth_pubkey_b64: &str,
        plan_hash: &str,
        wallet_address_fingerprint: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        validate_user(user_id)?;
        validate_context(ctx)?;
        if !valid_fingerprint(plan_hash) || !valid_fingerprint(wallet_address_fingerprint) {
            return Err(RegistryError::Malformed);
        }
        let fingerprint = fingerprint_of(auth_pubkey_b64)?;
        let _guard = self.lock.lock().map_err(|_| RegistryError::Unavailable)?;
        if self.read(user_id)?.is_some() {
            return Err(RegistryError::AlreadyExists);
        }
        match fs::symlink_metadata(self.wallet_path(user_id)) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.file_type().is_file() => {}
            Ok(_) => return Err(RegistryError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RegistryError::LegacyWalletMissing);
            }
            Err(_) => return Err(RegistryError::Unavailable),
        }
        let binding = UserBinding {
            version: RECORD_VERSION,
            user_id,
            auth_pubkey_b64: auth_pubkey_b64.to_string(),
            key_fingerprint: fingerprint,
            generation: 1,
            status: BindingStatus::Active,
            created_at: ctx.at,
            updated_at: ctx.at,
            last_request_id: ctx.request_id.to_string(),
            last_operator_ids: ctx.operator_ids.to_vec(),
            last_operator_key_fingerprints: ctx.operator_key_fingerprints.to_vec(),
            revoked_at: None,
            migration: Some(MigrationMetadata {
                plan_hash: plan_hash.to_string(),
                wallet_address_fingerprint: wallet_address_fingerprint.to_string(),
                migrated_at: ctx.at,
            }),
        };
        self.write(&binding)?;
        Ok(binding)
    }

    pub fn rotate(
        &self,
        user_id: u64,
        expected_generation: u64,
        new_auth_pubkey_b64: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        self.rotate_inner(user_id, expected_generation, None, new_auth_pubkey_b64, ctx)
    }

    /// Rotation that also requires the caller's expected current fingerprint.
    pub fn rotate_checked(
        &self,
        user_id: u64,
        expected_generation: u64,
        expected_current_fingerprint: &str,
        new_auth_pubkey_b64: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        self.rotate_inner(
            user_id,
            expected_generation,
            Some(expected_current_fingerprint),
            new_auth_pubkey_b64,
            ctx,
        )
    }

    fn rotate_inner(
        &self,
        user_id: u64,
        expected_generation: u64,
        expected_current_fingerprint: Option<&str>,
        new_auth_pubkey_b64: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        validate_user(user_id)?;
        validate_context(ctx)?;
        if let Some(fp) = expected_current_fingerprint {
            if !valid_fingerprint(fp) {
                return Err(RegistryError::Malformed);
            }
        }
        let new_fingerprint = fingerprint_of(new_auth_pubkey_b64)?;
        let _guard = self.lock.lock().map_err(|_| RegistryError::Unavailable)?;
        let mut binding = self.read(user_id)?.ok_or(RegistryError::NotFound)?;
        if binding.status == BindingStatus::Revoked {
            return Err(RegistryError::Revoked);
        }
        if binding.generation != expected_generation {
            return Err(RegistryError::GenerationMismatch);
        }
        if let Some(fp) = expected_current_fingerprint {
            if binding.key_fingerprint != fp {
                return Err(RegistryError::KeyMismatch);
            }
        }
        if binding.key_fingerprint == new_fingerprint {
            return Err(RegistryError::SameKey);
        }
        binding.auth_pubkey_b64 = new_auth_pubkey_b64.to_string();
        binding.key_fingerprint = new_fingerprint;
        binding.generation = binding
            .generation
            .checked_add(1)
            .ok_or(RegistryError::Malformed)?;
        binding.updated_at = ctx.at;
        binding.last_request_id = ctx.request_id.to_string();
        binding.last_operator_ids = ctx.operator_ids.to_vec();
        binding.last_operator_key_fingerprints = ctx.operator_key_fingerprints.to_vec();
        self.write(&binding)?;
        Ok(binding)
    }

    pub fn revoke(
        &self,
        user_id: u64,
        expected_generation: u64,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        self.revoke_inner(user_id, expected_generation, None, ctx)
    }

    /// Revocation that also requires the caller's expected current fingerprint.
    pub fn revoke_checked(
        &self,
        user_id: u64,
        expected_generation: u64,
        expected_current_fingerprint: &str,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        self.revoke_inner(
            user_id,
            expected_generation,
            Some(expected_current_fingerprint),
            ctx,
        )
    }

    fn revoke_inner(
        &self,
        user_id: u64,
        expected_generation: u64,
        expected_current_fingerprint: Option<&str>,
        ctx: &MutationContext<'_>,
    ) -> Result<UserBinding, RegistryError> {
        validate_user(user_id)?;
        validate_context(ctx)?;
        if let Some(fp) = expected_current_fingerprint {
            if !valid_fingerprint(fp) {
                return Err(RegistryError::Malformed);
            }
        }
        let _guard = self.lock.lock().map_err(|_| RegistryError::Unavailable)?;
        let mut binding = self.read(user_id)?.ok_or(RegistryError::NotFound)?;
        if binding.status == BindingStatus::Revoked {
            return Err(RegistryError::AlreadyRevoked);
        }
        if binding.generation != expected_generation {
            return Err(RegistryError::GenerationMismatch);
        }
        if let Some(fp) = expected_current_fingerprint {
            if binding.key_fingerprint != fp {
                return Err(RegistryError::KeyMismatch);
            }
        }
        binding.status = BindingStatus::Revoked;
        binding.updated_at = ctx.at;
        binding.revoked_at = Some(ctx.at);
        binding.last_request_id = ctx.request_id.to_string();
        binding.last_operator_ids = ctx.operator_ids.to_vec();
        binding.last_operator_key_fingerprints = ctx.operator_key_fingerprints.to_vec();
        self.write(&binding)?;
        Ok(binding)
    }

    /// Signing is allowed only for an active binding whose current fingerprint
    /// matches the presented authentication key.
    pub fn signing_allowed(
        &self,
        user_id: u64,
        key_fingerprint: &str,
    ) -> Result<bool, RegistryError> {
        if user_id == 0 || !valid_fingerprint(key_fingerprint) {
            return Err(RegistryError::Malformed);
        }
        let binding = self.get(user_id)?.ok_or(RegistryError::NotFound)?;
        Ok(binding.status == BindingStatus::Active && binding.key_fingerprint == key_fingerprint)
    }

    #[cfg(test)]
    pub(crate) fn set_write_failure(&self, stage: WriteStage) {
        if let Ok(mut slot) = self.failure.lock() {
            *slot = Some(stage);
        }
    }

    fn path(&self, user_id: u64) -> PathBuf {
        self.dir.join(format!("{user_id}.json"))
    }

    fn wallet_path(&self, user_id: u64) -> PathBuf {
        self.wallet_dir.join(format!("{user_id}.wallet.json"))
    }

    fn read(&self, user_id: u64) -> Result<Option<UserBinding>, RegistryError> {
        let path = self.path(user_id);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RegistryError::Unavailable),
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(RegistryError::Corrupt);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o777 != 0o600 {
                return Err(RegistryError::Corrupt);
            }
        }
        let body = fs::read(&path).map_err(|_| RegistryError::Unavailable)?;
        let binding: UserBinding =
            serde_json::from_slice(&body).map_err(|_| RegistryError::Corrupt)?;
        validate_record(&binding)?;
        if binding.user_id != user_id {
            return Err(RegistryError::Corrupt);
        }
        Ok(Some(binding))
    }

    fn write(&self, binding: &UserBinding) -> Result<(), RegistryError> {
        validate_record(binding)?;
        #[cfg(test)]
        let injected = self.failure.lock().ok().and_then(|mut f| f.take());
        #[cfg(test)]
        if matches!(injected, Some(WriteStage::BeforeTemp)) {
            return Err(RegistryError::Unavailable);
        }
        let tmp = self
            .dir
            .join(format!(".{}.tmp-{}", binding.user_id, uuid::Uuid::new_v4()));
        let body = serde_json::to_vec(binding).map_err(|_| RegistryError::Unavailable)?;
        let mut file = secure_create(&tmp).map_err(|_| RegistryError::Unavailable)?;
        if harden_0600(&file, &tmp).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Unavailable);
        }
        #[cfg(test)]
        if matches!(injected, Some(WriteStage::DuringTemp)) {
            let half = body.len() / 2;
            let _ = file.write_all(&body[..half]);
            let _ = file.sync_all();
            drop(file);
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Unavailable);
        }
        if file.write_all(&body).is_err() || file.sync_all().is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Unavailable);
        }
        #[cfg(test)]
        if matches!(injected, Some(WriteStage::BeforeRename)) {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Unavailable);
        }
        if fs::rename(&tmp, self.path(binding.user_id)).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Unavailable);
        }
        #[cfg(test)]
        if matches!(injected, Some(WriteStage::AfterRename)) {
            return Err(RegistryError::Unavailable);
        }
        if sync_dir(&self.dir).is_err() {
            return Err(RegistryError::Unavailable);
        }
        #[cfg(test)]
        if matches!(injected, Some(WriteStage::DirSync)) {
            return Err(RegistryError::Unavailable);
        }
        Ok(())
    }
}

fn validate_user(user_id: u64) -> Result<(), RegistryError> {
    if user_id == 0 {
        return Err(RegistryError::Malformed);
    }
    Ok(())
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control())
}

fn valid_fingerprint(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_context(ctx: &MutationContext<'_>) -> Result<(), RegistryError> {
    if ctx.at == 0 || !valid_id(ctx.request_id) || ctx.operator_ids.is_empty() {
        return Err(RegistryError::Malformed);
    }
    if ctx.operator_ids.len() > 8 || ctx.operator_ids.len() != ctx.operator_key_fingerprints.len() {
        return Err(RegistryError::Malformed);
    }
    let mut seen = HashSet::new();
    for id in ctx.operator_ids {
        if !valid_id(id) || !seen.insert(id.as_str()) {
            return Err(RegistryError::Malformed);
        }
    }
    for fp in ctx.operator_key_fingerprints {
        if !valid_fingerprint(fp) {
            return Err(RegistryError::Malformed);
        }
    }
    let mut seen_fps = HashSet::new();
    for fp in ctx.operator_key_fingerprints {
        if !seen_fps.insert(fp.as_str()) {
            return Err(RegistryError::Malformed);
        }
    }
    Ok(())
}

fn validate_record(binding: &UserBinding) -> Result<(), RegistryError> {
    if binding.version != RECORD_VERSION
        || binding.user_id == 0
        || binding.generation == 0
        || !valid_id(&binding.last_request_id)
        || binding.last_operator_ids.is_empty()
        || binding.last_operator_ids.len() > 8
        || binding.last_operator_ids.len() != binding.last_operator_key_fingerprints.len()
    {
        return Err(RegistryError::Corrupt);
    }
    let mut seen_operators = HashSet::new();
    for id in &binding.last_operator_ids {
        if !valid_id(id) || !seen_operators.insert(id.as_str()) {
            return Err(RegistryError::Corrupt);
        }
    }
    let pubkey =
        decode_auth_pubkey(&binding.auth_pubkey_b64).map_err(|_| RegistryError::Corrupt)?;
    let fp = auth_key_fingerprint(&pubkey).map_err(|_| RegistryError::Corrupt)?;
    if fp != binding.key_fingerprint || !valid_fingerprint(&binding.key_fingerprint) {
        return Err(RegistryError::Corrupt);
    }
    for fp in &binding.last_operator_key_fingerprints {
        if !valid_fingerprint(fp) {
            return Err(RegistryError::Corrupt);
        }
    }
    let mut seen_fps = HashSet::new();
    for fp in &binding.last_operator_key_fingerprints {
        if !seen_fps.insert(fp.as_str()) {
            return Err(RegistryError::Corrupt);
        }
    }
    if binding.created_at == 0
        || binding.updated_at < binding.created_at
        || binding.revoked_at.is_some_and(|at| at < binding.created_at)
    {
        return Err(RegistryError::Corrupt);
    }
    if let Some(migration) = &binding.migration {
        if !valid_fingerprint(&migration.plan_hash)
            || !valid_fingerprint(&migration.wallet_address_fingerprint)
            || migration.migrated_at < binding.created_at
        {
            return Err(RegistryError::Corrupt);
        }
    }
    match binding.status {
        BindingStatus::Active if binding.revoked_at.is_some() => Err(RegistryError::Corrupt),
        BindingStatus::Revoked if binding.revoked_at.is_none() => Err(RegistryError::Corrupt),
        _ => Ok(()),
    }
}

fn fingerprint_of(pubkey_b64: &str) -> Result<String, RegistryError> {
    let pubkey = decode_auth_pubkey(pubkey_b64).map_err(|_| RegistryError::Malformed)?;
    auth_key_fingerprint(&pubkey).map_err(|_| RegistryError::Malformed)
}

fn secure_create(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn harden_0600(file: &File, path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "binding record mode is not 0600",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "bindings path is not a private directory",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            let meta = fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "created bindings path is not a private directory",
                ));
            }
        }
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
