//! wallet_file_safety — v1 app wallet-file writer.
//!
//! The app's legacy wallet path is not the signer namespace, but it has the
//! same two requirements: never replace an existing final file and never
//! publish partial bytes. This module is intentionally independent of the
//! signer crate (the server binary cannot import the isolated signer).
//!
//! It provides a per-user in-process lock plus a complete-temp + fsync +
//! hard_link publisher. `hard_link` fails with EEXIST instead of replacing;
//! final files are never written with `File::create`/rename.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyError {
    AlreadyExists,
    Unavailable,
}

static USER_LOCKS: OnceLock<Mutex<HashMap<u64, &'static Mutex<()>>>> = OnceLock::new();

/// Serialize all app-side operations for one user. The lock is process-wide;
/// cross-process safety comes from the no-replace final writer.
pub fn lock_user(user_id: u64) -> std::sync::MutexGuard<'static, ()> {
    let map = USER_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
    let entry = guard
        .entry(user_id)
        .or_insert_with(|| Box::leak(Box::new(Mutex::new(()))));
    // The leaked mutex is intentionally process-lifetime (one per user id).
    let mutex: &'static Mutex<()> = *entry;
    drop(guard);
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn sync_dir(dir: &Path) -> Result<(), SafetyError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .map_err(|_| SafetyError::Unavailable)?
            .sync_all()
            .map_err(|_| SafetyError::Unavailable)?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn random_suffix() -> Result<String, SafetyError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| SafetyError::Unavailable)?;
    let mut out = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

/// Publish complete bytes at `path` without ever replacing an existing file.
pub fn write_new_file_no_replace(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), SafetyError> {
    let parent = path.parent().ok_or(SafetyError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| SafetyError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(SafetyError::AlreadyExists);
    }
    let tmp = parent.join(format!(
        ".agentpay-wallet-tmp-{}-{}",
        std::process::id(),
        random_suffix()?
    ));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut file = opts.open(&tmp).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            SafetyError::AlreadyExists
        } else {
            SafetyError::Unavailable
        }
    })?;
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|_| SafetyError::Unavailable)?;
        }
        file.write_all(bytes)
            .map_err(|_| SafetyError::Unavailable)?;
        file.sync_all().map_err(|_| SafetyError::Unavailable)?;
        drop(file);
        match fs::hard_link(&tmp, path) {
            Ok(()) => {
                sync_dir(parent)?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(SafetyError::AlreadyExists)
            }
            Err(_) => Err(SafetyError::Unavailable),
        }
    })();
    let _ = fs::remove_file(&tmp);
    result
}

// ---------------------------------------------------------------------------
// v1 operation journal (public-only)
//
// This is the missing v1 counterpart to the signer's g1150 journal. It stores
// only (user id, operation hash, public address, record digest); no key
// material. `started` is written before a mint, and `result` is written only
// after the public result is durable. A result is never replaced.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletOperationState {
    Absent,
    InProgress,
    Completed {
        public_address: String,
        record_sha256: String,
    },
    Corrupt,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartedOp {
    version: u8,
    user_id: String,
    operation_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResultOp {
    version: u8,
    user_id: String,
    operation_hash: String,
    public_address: String,
    record_sha256: String,
}

const OP_VERSION: u8 = 1;
const OP_DOMAIN: &str = "g1154-v1-wallet-operation-v1";

fn op_hash(user_id: u64, operation_id: &str) -> Option<String> {
    if operation_id.is_empty() || operation_id.len() > 256 {
        return None;
    }
    let mut h = blake3::Hasher::new();
    h.update(OP_DOMAIN.as_bytes());
    h.update(&user_id.to_le_bytes());
    h.update(operation_id.as_bytes());
    Some(h.finalize().to_hex().to_string())
}

fn op_dir(root: &Path, user_id: u64) -> PathBuf {
    root.join("wallet_ops").join(user_id.to_string())
}

fn started_path(root: &Path, user_id: u64, op: &str) -> Option<PathBuf> {
    Some(op_dir(root, user_id).join(format!("started-{}.json", op_hash(user_id, op)?)))
}

fn result_path(root: &Path, user_id: u64, op: &str) -> Option<PathBuf> {
    Some(op_dir(root, user_id).join(format!("result-{}.json", op_hash(user_id, op)?)))
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Public, deterministic digest of the wallet bytes. It is not a key; it is
/// used only to bind a journal result to the exact record that was published.
pub fn record_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn read_operation(root: &Path, user_id: u64, operation_id: &str) -> WalletOperationState {
    let Some(result_path) = result_path(root, user_id, operation_id) else {
        return WalletOperationState::Corrupt;
    };
    match fs::symlink_metadata(&result_path) {
        Ok(meta) if meta.file_type().is_symlink() => return WalletOperationState::Corrupt,
        Ok(_) => {
            let Some(result) = read_json_file::<ResultOp>(&result_path) else {
                return WalletOperationState::Corrupt;
            };
            if result.version != OP_VERSION
                || result.user_id != user_id.to_string()
                || op_hash(user_id, operation_id).as_deref() != Some(result.operation_hash.as_str())
                || result.public_address.is_empty()
                || result.record_sha256.is_empty()
            {
                return WalletOperationState::Corrupt;
            }
            return WalletOperationState::Completed {
                public_address: result.public_address,
                record_sha256: result.record_sha256,
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return WalletOperationState::Corrupt,
    }
    let Some(started_path) = started_path(root, user_id, operation_id) else {
        return WalletOperationState::Corrupt;
    };
    match fs::symlink_metadata(&started_path) {
        Ok(meta) if meta.file_type().is_symlink() => WalletOperationState::Corrupt,
        Ok(_) => match read_json_file::<StartedOp>(&started_path) {
            Some(started)
                if started.version == OP_VERSION
                    && started.user_id == user_id.to_string()
                    && op_hash(user_id, operation_id).as_deref()
                        == Some(started.operation_hash.as_str()) =>
            {
                WalletOperationState::InProgress
            }
            _ => WalletOperationState::Corrupt,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => WalletOperationState::Absent,
        Err(_) => WalletOperationState::Corrupt,
    }
}

/// Write the started marker before any key generation. Idempotent: an existing
/// completed result is returned as-is; an existing started marker is
/// InProgress; a new marker is created without replacement.
pub fn begin_operation(
    root: &Path,
    user_id: u64,
    operation_id: &str,
) -> Result<WalletOperationState, SafetyError> {
    match read_operation(root, user_id, operation_id) {
        WalletOperationState::Completed {
            public_address,
            record_sha256,
        } => {
            return Ok(WalletOperationState::Completed {
                public_address,
                record_sha256,
            })
        }
        WalletOperationState::InProgress => return Ok(WalletOperationState::InProgress),
        WalletOperationState::Corrupt => return Err(SafetyError::Unavailable),
        WalletOperationState::Absent => {}
    }
    let path = started_path(root, user_id, operation_id).ok_or(SafetyError::AlreadyExists)?;
    let started = StartedOp {
        version: OP_VERSION,
        user_id: user_id.to_string(),
        operation_hash: op_hash(user_id, operation_id).ok_or(SafetyError::AlreadyExists)?,
    };
    let bytes = serde_json::to_vec(&started).map_err(|_| SafetyError::Unavailable)?;
    match write_new_file_no_replace(&path, &bytes, 0o600) {
        Ok(()) => Ok(WalletOperationState::InProgress),
        Err(SafetyError::AlreadyExists) => Ok(read_operation(root, user_id, operation_id)),
        Err(e) => Err(e),
    }
}

/// Publish the public result once. A second completion with the exact same
/// public address/digest is idempotent; any disagreement is Conflict.
pub fn complete_operation(
    root: &Path,
    user_id: u64,
    operation_id: &str,
    public_address: &str,
    record_sha256: &str,
) -> Result<(), SafetyError> {
    if public_address.is_empty() || record_sha256.is_empty() {
        return Err(SafetyError::Unavailable);
    }
    let path = result_path(root, user_id, operation_id).ok_or(SafetyError::AlreadyExists)?;
    let result = ResultOp {
        version: OP_VERSION,
        user_id: user_id.to_string(),
        operation_hash: op_hash(user_id, operation_id).ok_or(SafetyError::AlreadyExists)?,
        public_address: public_address.to_string(),
        record_sha256: record_sha256.to_string(),
    };
    let bytes = serde_json::to_vec(&result).map_err(|_| SafetyError::Unavailable)?;
    match write_new_file_no_replace(&path, &bytes, 0o600) {
        Ok(()) => Ok(()),
        Err(SafetyError::AlreadyExists) => match read_operation(root, user_id, operation_id) {
            WalletOperationState::Completed {
                public_address: existing_address,
                record_sha256: existing_digest,
            } if existing_address == public_address && existing_digest == record_sha256 => Ok(()),
            WalletOperationState::Completed { .. } => Err(SafetyError::Unavailable),
            _ => Err(SafetyError::Unavailable),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn writer_refuses_to_replace_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!(
            "g1150-v1-writer-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        fs::write(&path, b"old").unwrap();
        assert_eq!(
            write_new_file_no_replace(&path, b"new", 0o600).unwrap_err(),
            SafetyError::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_writers_publish_one_file() {
        let dir = std::env::temp_dir().join(format!(
            "g1150-v1-race-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.json");
        let barrier = Arc::new(Barrier::new(8));
        let mut hs = Vec::new();
        for i in 0..8u8 {
            let p = path.clone();
            let b = barrier.clone();
            hs.push(thread::spawn(move || {
                b.wait();
                write_new_file_no_replace(&p, &[i; 16], 0o600).is_ok()
            }));
        }
        assert_eq!(
            hs.into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count(),
            1
        );
        assert_eq!(fs::read(&path).unwrap().len(), 16);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn operation_journal_is_public_only_idempotent_and_survives_restart() {
        let root = std::env::temp_dir().join(format!(
            "g1154-v1-journal-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        assert_eq!(read_operation(&root, 7, "op-a"), WalletOperationState::Absent);
        assert_eq!(
            begin_operation(&root, 7, "op-a").unwrap(),
            WalletOperationState::InProgress
        );
        assert_eq!(
            begin_operation(&root, 7, "op-a").unwrap(),
            WalletOperationState::InProgress
        );
        complete_operation(&root, 7, "op-a", "pub-a", "digest-a").unwrap();
        assert_eq!(
            read_operation(&root, 7, "op-a"),
            WalletOperationState::Completed {
                public_address: "pub-a".into(),
                record_sha256: "digest-a".into(),
            }
        );
        complete_operation(&root, 7, "op-a", "pub-a", "digest-a").unwrap();
        assert!(complete_operation(&root, 7, "op-a", "pub-b", "digest-a").is_err());
        assert_eq!(
            read_operation(&root, 7, "op-a"),
            WalletOperationState::Completed {
                public_address: "pub-a".into(),
                record_sha256: "digest-a".into(),
            }
        );
        let all = fs::read_dir(root.join("wallet_ops").join("7"))
            .unwrap()
            .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
            .collect::<String>();
        assert!(!all.contains("private"));
        assert!(!all.contains("secret"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_journal_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "g1154-v1-journal-corrupt-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        begin_operation(&root, 8, "op").unwrap();
        let path = started_path(&root, 8, "op").unwrap();
        fs::write(&path, b"not-json").unwrap();
        assert_eq!(read_operation(&root, 8, "op"), WalletOperationState::Corrupt);
        assert!(begin_operation(&root, 8, "op").is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn journal_rejects_empty_or_oversized_operation_ids() {
        let root = std::env::temp_dir().join(format!(
            "g1154-v1-journal-id-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        assert!(begin_operation(&root, 9, "").is_err());
        assert!(begin_operation(&root, 9, &"x".repeat(257)).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn journal_is_scoped_by_user_and_operation() {
        let root = std::env::temp_dir().join(format!(
            "g1154-v1-journal-scope-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        complete_operation(&root, 7, "op-a", "pub-a", "digest-a").unwrap();
        // The same operation id under a different user is not visible.
        assert_eq!(read_operation(&root, 8, "op-a"), WalletOperationState::Absent);
        // A different operation id for the same user is independent.
        assert_eq!(read_operation(&root, 7, "op-b"), WalletOperationState::Absent);
        complete_operation(&root, 7, "op-b", "pub-b", "digest-b").unwrap();
        assert_eq!(
            read_operation(&root, 7, "op-a"),
            WalletOperationState::Completed {
                public_address: "pub-a".into(),
                record_sha256: "digest-a".into(),
            }
        );
        fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn journal_symlink_is_corrupt_and_never_followed() {
        let root = std::env::temp_dir().join(format!(
            "g1154-v1-journal-link-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        begin_operation(&root, 10, "op").unwrap();
        let path = started_path(&root, 10, "op").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
        assert_eq!(read_operation(&root, 10, "op"), WalletOperationState::Corrupt);
        assert!(begin_operation(&root, 10, "op").is_err());
        fs::remove_dir_all(&root).ok();
    }
}
