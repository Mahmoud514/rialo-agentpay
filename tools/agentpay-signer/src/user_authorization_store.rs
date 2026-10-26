//! G109 — durable, filesystem-backed replay and audit adapters.
//!
//! These adapters are **not wired** into the signer lifecycle. They are built
//! on the signer store's local-filesystem trust model:
//!
//! * one signer process per store (kernel `flock` at startup);
//! * private directories (0700) and files (0600);
//! * symlink-refusing creation;
//! * `create_new` for atomic uniqueness;
//! * `sync_all` before acknowledging a record.
//!
//! Replay records contain no raw request id or nonce: the filename is a
//! domain-separated blake3 hash and the body stores only expiry metadata.
//! Audit records are redacted JSON event files. Identical events are
//! idempotent; distinct events produce distinct files. There is no deletion
//! or deduplication beyond the identical-event filename check.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::user_authorization::{
    AuditError, AuditEvent, AuditSink, ReplayError, ReplayScope, ReplayStore,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const REPLAY_DOMAIN: &[u8] = b"AGENTPAY-REPLAY-RECORD-v1\x00";
const AUDIT_DOMAIN: &[u8] = b"AGENTPAY-AUDIT-EVENT-v1\x00";
const MAX_AUDIT_EVENT_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct ReplayRecord {
    version: u8,
    expires_at: u64,
    consumed_at: u64,
}

/// Durable filesystem replay store. Process-local coordination is not relied
/// on: uniqueness is enforced by `create_new` on the local filesystem.
#[derive(Clone)]
pub struct FileReplayStore {
    dir: PathBuf,
}

impl FileReplayStore {
    /// Open (or create) `<root>/replay` with 0700 permissions.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ReplayError> {
        let dir = root.as_ref().join("replay");
        ensure_private_dir(&dir).map_err(|_| ReplayError::Unavailable)?;
        Ok(Self { dir })
    }

    fn record_path(&self, scope: ReplayScope, kind: &str, value: &str) -> PathBuf {
        let mut h = blake3::Hasher::new();
        h.update(REPLAY_DOMAIN);
        h.update(&scope.user_id.to_be_bytes());
        h.update(scope.operation.as_str().as_bytes());
        h.update(kind.as_bytes());
        h.update(value.as_bytes());
        self.dir.join(format!("{}.json", h.finalize().to_hex()))
    }

    /// Remove replay records whose expiry is at or before `now`.
    /// Corrupt/unreadable records are left in place (fail closed).
    pub fn purge_expired(&self, now: u64) -> Result<usize, ReplayError> {
        let entries = fs::read_dir(&self.dir).map_err(|_| ReplayError::Unavailable)?;
        let mut removed = 0;
        for entry in entries {
            let entry = entry.map_err(|_| ReplayError::Unavailable)?;
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match read_record(&path) {
                Ok(record) if now >= record.expires_at => {
                    fs::remove_file(&path).map_err(|_| ReplayError::Unavailable)?;
                    removed += 1;
                }
                _ => {}
            }
        }
        Ok(removed)
    }
}

impl ReplayStore for FileReplayStore {
    fn consume(
        &self,
        scope: ReplayScope,
        request_id: &str,
        nonce: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), ReplayError> {
        if expires_at <= now {
            // The verifier rejects expired requests before this point; fail
            // closed rather than creating an already-expired record.
            return Err(ReplayError::Unavailable);
        }
        let request_path = self.record_path(scope, "request", request_id);
        let nonce_path = self.record_path(scope, "nonce", nonce);
        let record = ReplayRecord {
            version: 1,
            expires_at,
            consumed_at: now,
        };

        if !create_record(&request_path, &record)? {
            // Request ids are never silently reactivated on expiry. An
            // operator must run `purge_expired` under the retention policy.
            return Err(ReplayError::Replay);
        }

        if !create_record(&nonce_path, &record)? {
            // The request record remains burned: a failed attempt must not
            // silently free the request id for a different nonce.
            return Err(ReplayError::Replay);
        }
        Ok(())
    }
}

fn create_record(path: &Path, record: &ReplayRecord) -> Result<bool, ReplayError> {
    let mut file = match secure_create(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(_) => return Err(ReplayError::Unavailable),
    };
    if harden_0600(&file, path).is_err() {
        let _ = fs::remove_file(path);
        return Err(ReplayError::Unavailable);
    }
    let body = serde_json::to_vec(record).map_err(|_| ReplayError::Unavailable)?;
    if file.write_all(&body).is_err() || file.sync_all().is_err() {
        let _ = fs::remove_file(path);
        return Err(ReplayError::Unavailable);
    }
    if sync_parent(path).is_err() {
        let _ = fs::remove_file(path);
        return Err(ReplayError::Unavailable);
    }
    Ok(true)
}

fn read_record(path: &Path) -> Result<ReplayRecord, ()> {
    let body = fs::read(path).map_err(|_| ())?;
    let record: ReplayRecord = serde_json::from_slice(&body).map_err(|_| ())?;
    if record.version != 1 {
        return Err(());
    }
    Ok(record)
}

/// Durable, redacted audit sink. Each event is a separate 0600 file named by
/// a blake3 hash of its canonical JSON; identical events are idempotent.
pub struct FileAuditSink {
    dir: PathBuf,
}

impl FileAuditSink {
    /// Open (or create) `<root>/audit` with 0700 permissions.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AuditError> {
        let dir = root.as_ref().join("audit");
        ensure_private_dir(&dir).map_err(|_| AuditError::Unavailable)?;
        Ok(Self { dir })
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let body = serde_json::to_vec(event).map_err(|_| AuditError::Unavailable)?;
        if body.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(AuditError::Unavailable);
        }
        let mut h = blake3::Hasher::new();
        h.update(AUDIT_DOMAIN);
        h.update(&body);
        let path = self.dir.join(format!("{}.json", h.finalize().to_hex()));

        let mut file = match secure_create(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Idempotent only for a regular 0600 file with byte-identical
                // content. Symlinks, unexpected types, wrong modes or corrupt
                // content are audit failures.
                let meta = fs::symlink_metadata(&path).map_err(|_| AuditError::Unavailable)?;
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    return Err(AuditError::Unavailable);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if meta.permissions().mode() & 0o777 != 0o600 {
                        return Err(AuditError::Unavailable);
                    }
                }
                return match fs::read(&path) {
                    Ok(existing) if existing == body => Ok(()),
                    _ => Err(AuditError::Unavailable),
                };
            }
            Err(_) => return Err(AuditError::Unavailable),
        };
        if harden_0600(&file, &path).is_err() {
            let _ = fs::remove_file(&path);
            return Err(AuditError::Unavailable);
        }
        if file.write_all(&body).is_err() || file.sync_all().is_err() {
            let _ = fs::remove_file(&path);
            return Err(AuditError::Unavailable);
        }
        if sync_parent(&path).is_err() {
            let _ = fs::remove_file(&path);
            return Err(AuditError::Unavailable);
        }
        Ok(())
    }
}

fn secure_create(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
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
                "record mode is not 0600",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "record has no parent")
    })?;
    File::open(parent)?.sync_all()
}

fn ensure_private_dir(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "replay/audit path is not a private directory",
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            // Re-check after creation to close the simplest symlink race.
            let meta = fs::symlink_metadata(path)?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "created path is not a private directory",
                ));
            }
        }
        Err(e) => return Err(e),
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
