//! wallet_file_safety — g1150 local hardening for signer wallet files.
//!
//! Scope: user-wallet persistence inside the isolated signer. The module is
//! deliberately small and dependency-free (besides the crates already used
//! by the signer): it provides a no-overwrite durable file writer, a durable
//! operation journal, and a strict classifier for existing wallet files.
//!
//! INVARIANTS
//!   * final wallet files are created with a complete temp file + fsync +
//!     hard_link(temp, final); `link(2)` fails with EEXIST, so a final file
//!     is NEVER replaced. `rename(2)` is not used for final files.
//!   * the operation journal stores PUBLIC metadata only (user id, operation
//!     hash, public address, record hash); no seed, private key, recovery
//!     draft, or key-container bytes.
//!   * a completed operation is readable without opening the key container.
//!   * partial/corrupt final files are terminal and classified; they are
//!     never repaired or replaced automatically.
//!   * a `started` journal without a `result` is in-progress; callers must
//!     not mint based only on a vanished process.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
thread_local! {
    static TEST_FAILPOINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static TEST_FAILPOINT_PATH: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub fn set_test_failpoint(value: u8) {
    TEST_FAILPOINT.with(|f| f.set(value));
    TEST_FAILPOINT_PATH.with(|p| *p.borrow_mut() = None);
}

#[cfg(test)]
pub fn set_test_failpoint_for(path: &Path, value: u8) {
    TEST_FAILPOINT.with(|f| f.set(value));
    TEST_FAILPOINT_PATH.with(|p| *p.borrow_mut() = Some(path.to_path_buf()));
}

#[cfg(test)]
fn test_failpoint(path: &Path) -> u8 {
    let path_matches = TEST_FAILPOINT_PATH.with(|p| match p.borrow().as_ref() {
        None => true,
        Some(target) => target == path,
    });
    if path_matches {
        TEST_FAILPOINT.with(|f| f.get())
    } else {
        0
    }
}

#[cfg(not(test))]
fn test_failpoint(_path: &Path) -> u8 {
    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyError {
    /// A final path already exists. Callers must classify/read, never replace.
    AlreadyExists,
    /// I/O or fsync failure. The caller cannot assert success.
    Unavailable,
    /// Existing bytes are malformed or fail identity binding.
    Corrupt,
    /// Two public results disagree for the same operation.
    Conflict,
    /// Empty/oversized operation id.
    BadOperation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationState {
    Absent,
    InProgress,
    Completed { public_address: String, record_sha256: String },
    /// Journal exists but cannot be trusted. Never mint from this state.
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletFiles {
    Missing,
    Complete { public_address: String, record_sha256: String },
    /// One side is missing, empty, malformed, or key/record identities differ.
    Incomplete,
}

#[derive(Debug, Serialize, Deserialize)]
struct StartedJournal {
    version: u8,
    user_id: String,
    operation_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResultJournal {
    version: u8,
    user_id: String,
    operation_hash: String,
    public_address: String,
    record_sha256: String,
}

#[derive(Debug, Deserialize)]
struct RecordView {
    user_id: u64,
    public_address: String,
    auth_pubkey: String,
}

const OPERATION_VERSION: u8 = 1;
const OPERATION_HASH_DOMAIN: &str = "g1150-wallet-operation-v1";

fn operation_hash(user_id: u64, operation_id: &str) -> Result<String, SafetyError> {
    if operation_id.is_empty() || operation_id.len() > 256 {
        return Err(SafetyError::BadOperation);
    }
    let mut h = blake3::Hasher::new();
    h.update(OPERATION_HASH_DOMAIN.as_bytes());
    h.update(&user_id.to_le_bytes());
    h.update(operation_id.as_bytes());
    Ok(h.finalize().to_hex().to_string())
}

fn op_dir(root: &Path, user_id: u64) -> PathBuf {
    root.join("users").join("ops").join(user_id.to_string())
}

fn started_path(root: &Path, user_id: u64, operation_id: &str) -> Result<PathBuf, SafetyError> {
    Ok(op_dir(root, user_id).join(format!(
        "started-{}.json",
        operation_hash(user_id, operation_id)?
    )))
}

fn result_path(root: &Path, user_id: u64, operation_id: &str) -> Result<PathBuf, SafetyError> {
    Ok(op_dir(root, user_id).join(format!(
        "result-{}.json",
        operation_hash(user_id, operation_id)?
    )))
}

/// Reject symlinked directories at the exact path we are about to use.
fn ensure_real_dir(dir: &Path) -> Result<(), SafetyError> {
    fs::create_dir_all(dir).map_err(|_| SafetyError::Unavailable)?;
    let meta = fs::symlink_metadata(dir).map_err(|_| SafetyError::Unavailable)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(SafetyError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = meta.permissions();
        if perms.mode() & 0o777 != 0o700 {
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms).map_err(|_| SafetyError::Unavailable)?;
        }
    }
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

fn sync_dir(dir: &Path) -> Result<(), SafetyError> {
    #[cfg(unix)]
    {
        let f = File::open(dir).map_err(|_| SafetyError::Unavailable)?;
        f.sync_all().map_err(|_| SafetyError::Unavailable)?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Create `path` with complete bytes and NO replacement of an existing file.
///
/// The content is written to a unique `create_new` temp in the same directory,
/// permissions are set before content (0600), the file is fsynced, then
/// `hard_link(temp, path)` publishes it atomically. Unlike `rename`, link
/// returns EEXIST when the destination exists; the existing inode is never
/// touched. The directory is fsynced after the link. The temp is removed on
/// both success and failure; a crash may leave a temp, which is never treated
/// as a wallet.
pub fn write_new_file_no_replace(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), SafetyError> {
    let parent = path.parent().ok_or(SafetyError::Unavailable)?;
    ensure_real_dir(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(SafetyError::AlreadyExists);
    }
    let tmp = parent.join(format!(".g1150-tmp-{}-{}", std::process::id(), random_suffix()?));
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
        if test_failpoint(path) == 1 {
            return Err(SafetyError::Unavailable);
        }
        match fs::hard_link(&tmp, path) {
            Ok(()) => {
                sync_dir(parent)?;
                if test_failpoint(path) == 2 {
                    return Err(SafetyError::Unavailable);
                }
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

pub fn read_operation(
    root: &Path,
    user_id: u64,
    operation_id: &str,
) -> Result<OperationState, SafetyError> {
    let result = result_path(root, user_id, operation_id)?;
    if fs::symlink_metadata(&result).is_ok() {
        let bytes = fs::read(&result).map_err(|_| SafetyError::Unavailable)?;
        let parsed: ResultJournal = serde_json::from_slice(&bytes).map_err(|_| SafetyError::Corrupt)?;
        let expected = operation_hash(user_id, operation_id)?;
        if parsed.version != OPERATION_VERSION
            || parsed.user_id != user_id.to_string()
            || parsed.operation_hash != expected
            || crate::base58_decode_32(&parsed.public_address).is_none()
            || parsed.record_sha256.len() != 64
        {
            return Err(SafetyError::Corrupt);
        }
        return Ok(OperationState::Completed {
            public_address: parsed.public_address,
            record_sha256: parsed.record_sha256,
        });
    }
    let started = started_path(root, user_id, operation_id)?;
    if fs::symlink_metadata(&started).is_ok() {
        let bytes = fs::read(&started).map_err(|_| SafetyError::Unavailable)?;
        let parsed: StartedJournal = serde_json::from_slice(&bytes).map_err(|_| SafetyError::Corrupt)?;
        let expected = operation_hash(user_id, operation_id)?;
        if parsed.version != OPERATION_VERSION
            || parsed.user_id != user_id.to_string()
            || parsed.operation_hash != expected
        {
            return Err(SafetyError::Corrupt);
        }
        return Ok(OperationState::InProgress);
    }
    Ok(OperationState::Absent)
}

/// Durably record the logical operation before any key material is written.
/// If a result already exists it wins (completed). If a started marker already
/// exists without a result, this returns InProgress; it never mints.
pub fn begin_operation(
    root: &Path,
    user_id: u64,
    operation_id: &str,
) -> Result<OperationState, SafetyError> {
    match read_operation(root, user_id, operation_id)? {
        OperationState::Completed { .. } => return read_operation(root, user_id, operation_id),
        OperationState::InProgress => return Ok(OperationState::InProgress),
        OperationState::Corrupt => return Err(SafetyError::Corrupt),
        OperationState::Absent => {}
    }
    ensure_real_dir(&op_dir(root, user_id))?;
    let started = started_path(root, user_id, operation_id)?;
    let body = serde_json::to_vec(&StartedJournal {
        version: OPERATION_VERSION,
        user_id: user_id.to_string(),
        operation_hash: operation_hash(user_id, operation_id)?,
    })
    .map_err(|_| SafetyError::Unavailable)?;
    match write_new_file_no_replace(&started, &body, 0o600) {
        Ok(()) => Ok(OperationState::InProgress),
        Err(SafetyError::AlreadyExists) => {
            // A concurrent caller published first; read its state, never mint.
            match read_operation(root, user_id, operation_id)? {
                OperationState::Completed { .. } => read_operation(root, user_id, operation_id),
                OperationState::InProgress => Ok(OperationState::InProgress),
                OperationState::Corrupt => Err(SafetyError::Corrupt),
                OperationState::Absent => Err(SafetyError::Unavailable),
            }
        }
        Err(e) => Err(e),
    }
}

/// Publish the durable public result. Only public identity + a record hash are
/// stored. Existing identical results are idempotent; differing results fail
/// closed and are never overwritten.
pub fn complete_operation(
    root: &Path,
    user_id: u64,
    operation_id: &str,
    public_address: &str,
    record_sha256: &str,
) -> Result<(), SafetyError> {
    if crate::base58_decode_32(public_address).is_none()
        || record_sha256.len() != 64
        || !record_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(SafetyError::Corrupt);
    }
    ensure_real_dir(&op_dir(root, user_id))?;
    let result = result_path(root, user_id, operation_id)?;
    let body = serde_json::to_vec(&ResultJournal {
        version: OPERATION_VERSION,
        user_id: user_id.to_string(),
        operation_hash: operation_hash(user_id, operation_id)?,
        public_address: public_address.to_string(),
        record_sha256: record_sha256.to_string(),
    })
    .map_err(|_| SafetyError::Unavailable)?;
    match write_new_file_no_replace(&result, &body, 0o600) {
        Ok(()) => Ok(()),
        Err(SafetyError::AlreadyExists) => match read_operation(root, user_id, operation_id)? {
            OperationState::Completed {
                public_address: existing,
                record_sha256: existing_hash,
            } if existing == public_address && existing_hash == record_sha256 => Ok(()),
            OperationState::Completed { .. } => Err(SafetyError::Conflict),
            _ => Err(SafetyError::Conflict),
        },
        Err(e) => Err(e),
    }
}

fn read_record(path: &Path, user_id: u64) -> Result<(String, String), SafetyError> {
    let bytes = fs::read(path).map_err(|_| SafetyError::Unavailable)?;
    let rec: RecordView = serde_json::from_slice(&bytes).map_err(|_| SafetyError::Corrupt)?;
    if rec.user_id != user_id
        || crate::base58_decode_32(&rec.public_address).is_none()
        || crate::base58_decode_32(&rec.auth_pubkey).is_none()
    {
        return Err(SafetyError::Corrupt);
    }
    let digest = blake3::hash(&bytes).to_hex().to_string();
    Ok((rec.public_address, digest))
}

/// Strictly classify the two final user-wallet files. A complete wallet
/// requires a parseable public record AND a parseable key container whose
/// derived address equals the record. Any asymmetry is Incomplete (terminal),
/// never a reason to mint a replacement.
pub fn inspect_wallet_files(
    key_path: &Path,
    record_path: &Path,
    user_id: u64,
) -> Result<WalletFiles, SafetyError> {
    let key_meta = fs::symlink_metadata(key_path).ok();
    let rec_meta = fs::symlink_metadata(record_path).ok();
    match (key_meta, rec_meta) {
        (None, None) => return Ok(WalletFiles::Missing),
        (Some(_), None) | (None, Some(_)) => return Ok(WalletFiles::Incomplete),
        (Some(km), Some(rm)) => {
            if km.file_type().is_symlink() || rm.file_type().is_symlink() {
                return Ok(WalletFiles::Incomplete);
            }
        }
    }
    let record = match read_record(record_path, user_id) {
        Ok(v) => v,
        Err(SafetyError::Corrupt) => return Ok(WalletFiles::Incomplete),
        Err(e) => return Err(e),
    };
    let mut key_file = File::open(key_path).map_err(|_| SafetyError::Unavailable)?;
    let keypair = match rialo_s_keypair::read_keypair(&mut key_file) {
        Ok(k) => k,
        Err(_) => return Ok(WalletFiles::Incomplete),
    };
    use rialo_s_signer::Signer;
    if keypair.pubkey().to_string() != record.0 {
        return Ok(WalletFiles::Incomplete);
    }
    Ok(WalletFiles::Complete {
        public_address: record.0,
        record_sha256: record.1,
    })
}

/// Read the durable result without opening any key container. Returns None
/// only for a genuinely absent operation; InProgress/Corrupt are errors.
pub fn completed_result(
    root: &Path,
    user_id: u64,
    operation_id: &str,
) -> Result<Option<String>, SafetyError> {
    match read_operation(root, user_id, operation_id)? {
        OperationState::Completed { public_address, .. } => Ok(Some(public_address)),
        OperationState::Absent => Ok(None),
        OperationState::InProgress => Err(SafetyError::Unavailable),
        OperationState::Corrupt => Err(SafetyError::Corrupt),
    }
}

/// Test-only helper: read bytes only; never materialize a keypair.
pub fn read_public_bytes(path: &Path) -> Result<Vec<u8>, SafetyError> {
    let mut f = File::open(path).map_err(|_| SafetyError::Unavailable)?;
    let mut out = Vec::new();
    f.read_to_end(&mut out).map_err(|_| SafetyError::Unavailable)?;
    Ok(out)
}
