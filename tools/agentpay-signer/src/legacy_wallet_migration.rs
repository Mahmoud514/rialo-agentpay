//! G113 — operator-mediated migration of legacy user wallets into the durable
//! `UserBindingRegistry`.
//!
//! Legacy format (read-only):
//!   * `users/<id>.wallet.json` — public record `{user_id, public_address,
//!     auth_pubkey}` (no private key);
//!   * `users/<id>.key.json` — private funded-key container; migration checks
//!     existence/mode only and NEVER reads it;
//!   * `users/<id>.recovery.json` — contains a secret XOR draft; migration
//!     parses only the public correspondence fields and never reports or logs
//!     the draft.
//!
//! Migration is operator-attested: the legacy record has no user-signed
//! possession proof for the current auth key. The apply path therefore requires
//! a D8 `Migrate` authorization whose request id is the plan hash; it does not
//! fabricate a user identity or claim fresh possession. Dry-run is read-only.
//! No production route calls this module.

use std::fs;
use std::path::Path;

use base64::Engine as _;
use serde::Deserialize;

use crate::SignerStore;
use crate::user_authorization::{
    AuditSink, AuthorizationPayload, LifecycleAuthorizationError, LifecycleAuthorizer,
    LifecycleOperation, OperatorSignature, OperatorTrustStore, ReplayStore, auth_key_fingerprint,
};
use crate::user_binding_registry::{
    BindingStatus, MutationContext, RegistryError, UserBinding, UserBindingRegistry,
    UserBindingRegistry as Registry,
};
use crate::user_lane::{user_key_path, user_record_path, user_recovery_path};

const MAX_LEGACY_BYTES: u64 = 16 * 1024;
const PLAN_DOMAIN: &[u8] = b"AGENTPAY-LEGACY-MIGRATION-PLAN-v1\x00";
const ADDRESS_DOMAIN: &[u8] = b"AGENTPAY-LEGACY-WALLET-ADDRESS-v1\x00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    Migratable,
    AlreadyMigrated,
    Conflict,
    Corrupt,
    Unsupported,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationMode {
    ReadOnly,
    Apply,
}

/// Redacted candidate. `auth_pubkey_b64` is public key material used only to
/// build a plan; it is not emitted by the report summary.
pub struct MigrationCandidate {
    pub user_id: u64,
    pub wallet_address_fingerprint: String,
    pub auth_key_fingerprint: String,
    pub status: MigrationStatus,
    pub reason: &'static str,
    pub(crate) auth_pubkey_b64: String,
}

pub struct MigrationReport {
    pub scanned: usize,
    pub candidates: Vec<MigrationCandidate>,
}

impl MigrationReport {
    pub fn count(&self, status: MigrationStatus) -> usize {
        self.candidates
            .iter()
            .filter(|c| c.status == status)
            .count()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MigrationPlanEntry {
    pub user_id: u64,
    pub auth_pubkey_b64: String,
    pub auth_key_fingerprint: String,
    pub wallet_address_fingerprint: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub plan_hash: String,
    pub entries: Vec<MigrationPlanEntry>,
}

impl MigrationPlan {
    pub fn from_report(report: &MigrationReport) -> Result<Self, MigrationError> {
        let mut entries: Vec<_> = report
            .candidates
            .iter()
            .filter(|c| c.status == MigrationStatus::Migratable)
            .map(|c| MigrationPlanEntry {
                user_id: c.user_id,
                auth_pubkey_b64: c.auth_pubkey_b64.clone(),
                auth_key_fingerprint: c.auth_key_fingerprint.clone(),
                wallet_address_fingerprint: c.wallet_address_fingerprint.clone(),
            })
            .collect();
        entries.sort_by_key(|e| e.user_id);
        for pair in entries.windows(2) {
            if pair[0].user_id == pair[1].user_id {
                return Err(MigrationError::PlanInvalid);
            }
        }
        let plan_hash = hash_plan(&entries)?;
        Ok(Self { plan_hash, entries })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    StoreUnavailable,
    Registry(RegistryError),
    Disabled,
    PlanInvalid,
    ApprovalMismatch,
    Approval(LifecycleAuthorizationError),
    NotMigratable(MigrationStatus),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    Migrated(UserBinding),
    AlreadyMigrated(UserBinding),
}

pub struct LegacyWalletScanner {
    store: SignerStore,
}

impl LegacyWalletScanner {
    pub fn new(store: SignerStore) -> Self {
        Self { store }
    }

    pub fn scan(&self) -> Result<MigrationReport, MigrationError> {
        let users = self.store.root().join("users");
        if let Ok(meta) = fs::symlink_metadata(&users) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(MigrationError::StoreUnavailable);
            }
        }
        let entries = match fs::read_dir(&users) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(MigrationReport {
                    scanned: 0,
                    candidates: Vec::new(),
                });
            }
            Err(_) => return Err(MigrationError::StoreUnavailable),
        };
        let mut candidates = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| MigrationError::StoreUnavailable)?;
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(prefix) = name.strip_suffix(".wallet.json") else {
                continue;
            };
            let Ok(user_id) = prefix.parse::<u64>() else {
                continue;
            };
            candidates.push(self.scan_user(user_id)?);
        }
        candidates.sort_by_key(|c| c.user_id);
        Ok(MigrationReport {
            scanned: candidates.len(),
            candidates,
        })
    }

    pub(crate) fn scan_user(&self, user_id: u64) -> Result<MigrationCandidate, MigrationError> {
        let registry = UserBindingRegistry::open_read_only(self.store.root())
            .map_err(MigrationError::Registry)?;
        let mut candidate = MigrationCandidate {
            user_id,
            wallet_address_fingerprint: String::new(),
            auth_key_fingerprint: String::new(),
            status: MigrationStatus::Corrupt,
            reason: "wallet_corrupt",
            auth_pubkey_b64: String::new(),
        };

        let wallet_path = user_record_path(&self.store, user_id);
        if let Err(status) = safe_regular_file(&wallet_path) {
            candidate.status = status;
            candidate.reason = "wallet_file_unsafe";
            return Ok(candidate);
        }
        let wallet_bytes = read_limited(&wallet_path)?;
        let wallet: LegacyWalletFile = match serde_json::from_slice(&wallet_bytes) {
            Ok(wallet) => wallet,
            Err(_) => return Ok(candidate),
        };
        if wallet.user_id != user_id {
            candidate.reason = "wallet_user_mismatch";
            return Ok(candidate);
        }
        let Some(address_bytes) = crate::base58_decode_32(&wallet.public_address) else {
            return Ok(candidate);
        };
        let Some(auth_bytes) = crate::base58_decode_32(&wallet.auth_pubkey) else {
            return Ok(candidate);
        };
        candidate.wallet_address_fingerprint = address_fingerprint(&address_bytes);
        candidate.auth_key_fingerprint =
            auth_key_fingerprint(&auth_bytes).map_err(|_| MigrationError::StoreUnavailable)?;
        candidate.auth_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(auth_bytes);

        if let Err(status) = safe_regular_file(&user_key_path(&self.store, user_id)) {
            candidate.status = status;
            candidate.reason = "key_container_unsafe";
            return Ok(candidate);
        }
        let recovery_path = user_recovery_path(&self.store, user_id);
        if let Err(status) = safe_regular_file(&recovery_path) {
            candidate.status = status;
            candidate.reason = "recovery_file_unsafe";
            return Ok(candidate);
        }
        let recovery_bytes = read_limited(&recovery_path)?;
        let recovery: LegacyRecoveryPublic = match serde_json::from_slice(&recovery_bytes) {
            Ok(recovery) => recovery,
            Err(_) => {
                candidate.status = MigrationStatus::Unsupported;
                candidate.reason = "recovery_unsupported";
                return Ok(candidate);
            }
        };
        if recovery.version != 1
            || recovery.wallet_version != 2
            || recovery.user_id != user_id.to_string()
            || recovery.canonical_creation_record.len() != 64
            || recovery.payout_hash.len() != 64
            || recovery.release_draft2_hex.is_empty()
            || recovery.release_draft2_hex.len() % 2 != 0
            || !recovery
                .release_draft2_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            candidate.status = MigrationStatus::Unsupported;
            candidate.reason = "recovery_unsupported";
            return Ok(candidate);
        }
        if recovery.released_auth_pubkey != wallet.auth_pubkey
            || recovery.wallet_address != wallet.public_address
        {
            candidate.status = MigrationStatus::Conflict;
            candidate.reason = "recovery_mismatch";
            return Ok(candidate);
        }

        match registry.get(user_id) {
            Err(RegistryError::Corrupt) => {
                candidate.status = MigrationStatus::Conflict;
                candidate.reason = "binding_corrupt";
            }
            Err(RegistryError::Unavailable) => {
                return Err(MigrationError::Registry(RegistryError::Unavailable));
            }
            Err(_) => return Err(MigrationError::StoreUnavailable),
            Ok(Some(binding)) => {
                if binding.status == BindingStatus::Revoked {
                    candidate.status = MigrationStatus::Conflict;
                    candidate.reason = "binding_revoked";
                } else if binding.migration.is_some() {
                    // Migration metadata is durable evidence that this user
                    // was already migrated, even if the auth key has since
                    // rotated. Never re-run or overwrite it.
                    candidate.status = MigrationStatus::AlreadyMigrated;
                    candidate.reason = "already_migrated";
                } else if binding.key_fingerprint == candidate.auth_key_fingerprint {
                    candidate.status = MigrationStatus::Conflict;
                    candidate.reason = "binding_exists";
                } else {
                    candidate.status = MigrationStatus::Conflict;
                    candidate.reason = "binding_key_conflict";
                }
            }
            Ok(None) => {
                candidate.status = MigrationStatus::Migratable;
                candidate.reason = "ok";
            }
        }
        Ok(candidate)
    }
}

pub struct LegacyWalletMigration<S, R, A> {
    store: SignerStore,
    registry: UserBindingRegistry,
    trust: S,
    replay: R,
    audit: A,
    mode: MigrationMode,
}

impl<S, R, A> LegacyWalletMigration<S, R, A>
where
    S: OperatorTrustStore,
    R: ReplayStore,
    A: AuditSink,
{
    /// Default construction is read-only; apply requires an explicit
    /// `with_mode(..., MigrationMode::Apply)`.
    pub fn new(
        store: SignerStore,
        registry: UserBindingRegistry,
        trust: S,
        replay: R,
        audit: A,
    ) -> Self {
        Self::with_mode(
            store,
            registry,
            trust,
            replay,
            audit,
            MigrationMode::ReadOnly,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_mode(
        store: SignerStore,
        registry: UserBindingRegistry,
        trust: S,
        replay: R,
        audit: A,
        mode: MigrationMode,
    ) -> Self {
        Self {
            store,
            registry,
            trust,
            replay,
            audit,
            mode,
        }
    }

    pub fn scan(&self) -> Result<MigrationReport, MigrationError> {
        LegacyWalletScanner::new(self.store.clone()).scan()
    }

    /// Apply one plan entry. The plan hash is the D8 request id; the operator
    /// authorization must use `Migrate`, generation 1, empty current
    /// fingerprint, and the entry's auth fingerprint. The legacy wallet is
    /// only read/validated, never modified.
    pub fn apply(
        &self,
        plan: &MigrationPlan,
        entry: &MigrationPlanEntry,
        authorization: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        now: u64,
    ) -> Result<MigrationOutcome, MigrationError> {
        if self.mode != MigrationMode::Apply {
            return Err(MigrationError::Disabled);
        }
        if hash_plan(&plan.entries)? != plan.plan_hash || !plan.entries.iter().any(|e| e == entry) {
            return Err(MigrationError::PlanInvalid);
        }
        if authorization.operation != LifecycleOperation::Migrate
            || authorization.user_id != entry.user_id
            || authorization.generation != 1
            || !authorization.current_key_fingerprint.is_empty()
            || authorization.new_key_fingerprint != entry.auth_key_fingerprint
            || now == 0
        {
            return Err(MigrationError::ApprovalMismatch);
        }

        let candidate = LegacyWalletScanner::new(self.store.clone()).scan_user(entry.user_id)?;
        match candidate.status {
            MigrationStatus::AlreadyMigrated => {
                let binding = self
                    .registry
                    .get(entry.user_id)
                    .map_err(MigrationError::Registry)?
                    .ok_or(MigrationError::Registry(RegistryError::NotFound))?;
                return Ok(MigrationOutcome::AlreadyMigrated(binding));
            }
            MigrationStatus::Migratable => {}
            other => return Err(MigrationError::NotMigratable(other)),
        }
        if candidate.auth_key_fingerprint != entry.auth_key_fingerprint
            || candidate.wallet_address_fingerprint != entry.wallet_address_fingerprint
            || candidate.auth_pubkey_b64 != entry.auth_pubkey_b64
        {
            return Err(MigrationError::PlanInvalid);
        }

        let outcome = LifecycleAuthorizer::new(&self.trust, &self.replay, &self.audit)
            .authorize(authorization, signatures, now)
            .map_err(MigrationError::Approval)?;
        let ctx = MutationContext {
            request_id: &authorization.request_id,
            operator_ids: &outcome.approved_by,
            operator_key_fingerprints: &outcome.approved_key_fingerprints,
            at: now,
        };
        let binding = self
            .registry
            .migrate_legacy(
                entry.user_id,
                &entry.auth_pubkey_b64,
                &plan.plan_hash,
                &entry.wallet_address_fingerprint,
                &ctx,
            )
            .map_err(MigrationError::Registry)?;
        Ok(MigrationOutcome::Migrated(binding))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyWalletFile {
    user_id: u64,
    public_address: String,
    auth_pubkey: String,
}

#[derive(Deserialize)]
struct LegacyRecoveryPublic {
    version: u8,
    wallet_version: u8,
    user_id: String,
    #[serde(default)]
    canonical_creation_record: String,
    #[serde(default)]
    payout_hash: String,
    #[serde(default)]
    release_draft2_hex: String,
    released_auth_pubkey: String,
    wallet_address: String,
}

fn safe_regular_file(path: &Path) -> Result<(), MigrationStatus> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MigrationStatus::Unsupported
        } else {
            MigrationStatus::Unsafe
        }
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(MigrationStatus::Unsafe);
    }
    if meta.len() == 0 || meta.len() > MAX_LEGACY_BYTES {
        return Err(MigrationStatus::Unsupported);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(MigrationStatus::Unsafe);
        }
    }
    Ok(())
}

fn read_limited(path: &Path) -> Result<Vec<u8>, MigrationError> {
    let meta = fs::metadata(path).map_err(|_| MigrationError::StoreUnavailable)?;
    if meta.len() > MAX_LEGACY_BYTES {
        return Err(MigrationError::StoreUnavailable);
    }
    fs::read(path).map_err(|_| MigrationError::StoreUnavailable)
}

fn address_fingerprint(address: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(ADDRESS_DOMAIN);
    h.update(address);
    h.finalize().to_hex().to_string()
}

fn hash_plan(entries: &[MigrationPlanEntry]) -> Result<String, MigrationError> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|e| e.user_id);
    if sorted.windows(2).any(|p| p[0].user_id == p[1].user_id) {
        return Err(MigrationError::PlanInvalid);
    }
    let mut h = blake3::Hasher::new();
    h.update(PLAN_DOMAIN);
    h.update(&1u16.to_be_bytes());
    h.update(&(sorted.len() as u32).to_be_bytes());
    for entry in &sorted {
        if entry.auth_key_fingerprint.len() != 64 || entry.wallet_address_fingerprint.len() != 64 {
            return Err(MigrationError::PlanInvalid);
        }
        h.update(&entry.user_id.to_be_bytes());
        h.update(entry.auth_key_fingerprint.as_bytes());
        h.update(entry.wallet_address_fingerprint.as_bytes());
    }
    Ok(h.finalize().to_hex().to_string())
}
