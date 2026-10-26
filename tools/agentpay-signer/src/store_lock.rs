//! store_lock — single-signer-process-per-store ownership.
//!
//! G91 (F2) — the AUTHORITY is a kernel advisory lock (`flock(2)`,
//! LOCK_EX|LOCK_NB) held on an open descriptor of the STORE ROOT DIRECTORY
//! for the whole process lifetime:
//!   * it cannot be forged by deleting/replacing `signer_instance.lock`
//!     (the lock lives on the directory inode, not on the marker file);
//!   * it is released by the kernel on process death — no PID-liveness
//!     heuristics, no stale-file takeover races, no PID-reuse ambiguity;
//!   * a second signer on the same store fails EWOULDBLOCK ⇒ Busy ⇒ the
//!     startup aborts (fail closed, exit 2).
//!
//! `<store>/signer_instance.lock` is retained as a DIAGNOSTIC MARKER only
//! (`{pid, started_at_unix}`). Its content is never trusted for ownership.
//!
//! G91 (F1) — creating/refreshing the marker enforces mode 0600 and FAILS
//! CLOSED if the mode cannot be set AND verified (the marker is removed
//! before the error is returned; the store is never served under a lock
//! file with unverified permissions).
//!
//! G91 (F3) — every path component is symlink-validated BEFORE any
//! filesystem write, and re-validated after directory creation. Residual
//! TOCTOU: a component can in principle be swapped between validation and
//! use; the mitigating boundary is that the store root is 0700
//! (owner-only) and its parent is operator-controlled. No openat2/
//! O_NOFOLLOW based walk is used (no extra dependencies); this is
//! documented as a residual platform limitation.
//!
//! G93-B — non-Unix platforms are REFUSED at startup: `acquire` returns an
//! error unconditionally (the weaker marker-only ownership is never used).
//! The supported platform is Unix; the deployment target is Linux.

use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLockError {
    /// another (living) signer process owns this store
    Busy,
    /// the lock file / store root could not be established (fail closed)
    Unavailable,
}

pub struct StoreLock {
    // Debug is NOT derived: the handle's fields are process-owned state.
    /// G91 (F2): the flocked store-root DIRECTORY descriptor — the
    /// ownership authority; held for the process lifetime.
    #[cfg(unix)]
    _dir: std::fs::File,
    /// the diagnostic marker file (0600, best-effort content) — NOT the
    /// ownership authority.
    _file: std::fs::File,
    path: PathBuf,
}

/// G89 (M1) — the running effective uid read from /proc (zero-dependency
/// discipline; `None` when /proc is unavailable ⇒ callers FAIL CLOSED).
#[cfg(unix)]
pub(crate) fn euid_from_proc() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // "Uid:\treal\teffective\tsaved\tfs" — the EFFECTIVE uid is 2nd
            let mut it = rest.split_whitespace();
            let _real = it.next()?;
            return it.next()?.parse::<u32>().ok();
        }
    }
    None
}

/// G91 (F2) — the single libc symbol this crate needs, declared directly
/// (no new dependency): kernel advisory locking on a file descriptor.
#[cfg(unix)]
mod flock_abi {
    use std::os::raw::c_int;
    unsafe extern "C" {
        pub fn flock(fd: c_int, operation: c_int) -> c_int;
    }
    pub const LOCK_EX: c_int = 2;
    pub const LOCK_NB: c_int = 4;
}

/// G91 (F3) — reject a symlink in any EXISTING component of `root`; missing
/// suffix components are skipped (the caller creates them, then re-validates
/// with [`reject_symlink_components`]). Runs BEFORE any write.
pub(crate) fn reject_existing_symlink_components(root: &Path) -> Result<(), StoreLockError> {
    let mut acc = PathBuf::new();
    for comp in root.components() {
        acc.push(comp.as_os_str());
        match std::fs::symlink_metadata(&acc) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(StoreLockError::Unavailable),
            Ok(_) => {}
            Err(_) => break, // remainder does not exist yet
        }
    }
    Ok(())
}

/// G91 (F3) — full-path validation AFTER creation: every component must
/// exist and none may be a symlink (catches a component swapped in during
/// the creation window, within the documented TOCTOU limits).
pub(crate) fn reject_symlink_components(root: &Path) -> Result<(), StoreLockError> {
    let mut acc = PathBuf::new();
    for comp in root.components() {
        acc.push(comp.as_os_str());
        match std::fs::symlink_metadata(&acc) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(StoreLockError::Unavailable),
            Ok(_) => {}
            Err(_) => return Err(StoreLockError::Unavailable),
        }
    }
    Ok(())
}

/// G95-A — Linux filesystem boundary for the store.
///
/// Detection strategy: parse `/proc/self/mountinfo` (text, architecture
/// independent — no hand-rolled `statfs` struct ABI) and take the LONGEST
/// mount point containing the canonical store path. Policy:
///   * POSITIVELY identified network filesystem (nfs/nfs4/cifs/smbfs/smb3)
///     ⇒ hard refusal (`Unavailable`);
///   * ANY other type (ext4/xfs/tmpfs/overlay/… and unknown types) ⇒
///     allowed — an allow-list would reject legitimate local filesystems,
///     and "unknown" is therefore explicitly permitted, not silently
///     treated as local-and-supported;
///   * mount table unreadable / path not covered by any mount / canonical
///     path unavailable ⇒ fail closed (`Unavailable`).
///
/// Linux-only: other Unix targets keep the operational requirement
/// (documented) because their mount tables differ; the deployment target
/// is Linux.
#[cfg(target_os = "linux")]
mod fs_boundary {
    use super::StoreLockError;
    use std::path::Path;

    /// Positively unsupported (network) filesystem types.
    pub(super) const NETWORK_FS: &[&str] = &["nfs", "nfs4", "cifs", "smbfs", "smb3"];

    pub(super) fn filesystem_allowed(fstype: &str) -> bool {
        !NETWORK_FS.contains(&fstype)
    }

    /// Mountinfo escapes: \040 space, \011 tab, \012 newline, \134 '\'.
    ///
    /// G97-A — byte-preserving and UTF-8-validated: escapes are decoded into
    /// bytes, then the WHOLE field must be valid UTF-8. Malformed input
    /// (truncated/non-octal escape, invalid UTF-8) returns None and the
    /// caller SKIPS that line — no panic, and no mount is selected from a
    /// malformed line.
    fn unescape(field: &[u8]) -> Option<String> {
        let mut out = Vec::with_capacity(field.len());
        let mut i = 0;
        while i < field.len() {
            if field[i] == b'\\' {
                if i + 3 >= field.len() {
                    return None; // truncated escape
                }
                let mut v: u16 = 0;
                for &d in &field[i + 1..i + 4] {
                    if !(b'0'..=b'7').contains(&d) {
                        return None; // non-octal escape
                    }
                    v = v * 8 + u16::from(d - b'0');
                }
                out.push(v as u8);
                i += 4;
            } else {
                out.push(field[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }

    fn ws_fields(line: &[u8]) -> impl Iterator<Item = &[u8]> {
        line.split(|b| b.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
    }

    /// Pure: longest-prefix mount lookup over raw mountinfo bytes.
    /// A matching line whose mount point cannot be decoded is skipped; a
    /// path with no decodable covering mount returns None (fail closed).
    pub(super) fn fstype_for_path(mountinfo: &[u8], path: &Path) -> Option<String> {
        let path = path.to_str()?;
        let mut best: Option<(usize, String)> = None;
        for line in mountinfo.split(|&b| b == b'\n') {
            let Some(pos) = line.windows(3).position(|w| w == b" - ") else {
                continue;
            };
            let (left, right) = (&line[..pos], &line[pos + 3..]);
            let Some(mp_raw) = ws_fields(left).nth(4) else {
                continue;
            };
            let Some(mp) = unescape(mp_raw) else { continue };
            // component-aware containment; "/" contains every absolute path
            let sep_ok = mp == "/"
                || path == mp
                || (path.starts_with(&mp) && path.as_bytes().get(mp.len()) == Some(&b'/'));
            if !sep_ok {
                continue;
            }
            let Some(fs_raw) = ws_fields(right).next() else {
                continue;
            };
            let Ok(fstype) = std::str::from_utf8(fs_raw) else {
                continue;
            };
            if best
                .as_ref()
                .map(|(len, _)| mp.len() > *len)
                .unwrap_or(true)
            {
                best = Some((mp.len(), fstype.to_string()));
            }
        }
        best.map(|(_, fs)| fs)
    }

    /// Enforced boundary: refuse positively identified network filesystems
    /// and any store whose filesystem cannot be established.
    pub(super) fn ensure_supported_filesystem(root: &Path) -> Result<(), StoreLockError> {
        // raw bytes: a non-UTF-8 mount table must not abort the whole check
        // for an unrelated line — undecodable lines are skipped and only an
        // uncovered store path fails closed.
        let table =
            std::fs::read("/proc/self/mountinfo").map_err(|_| StoreLockError::Unavailable)?;
        let canonical = std::fs::canonicalize(root).map_err(|_| StoreLockError::Unavailable)?;
        match fstype_for_path(&table, &canonical) {
            Some(fs) if filesystem_allowed(&fs) => Ok(()),
            _ => Err(StoreLockError::Unavailable),
        }
    }
}

/// G91 (F1) — enforce AND verify 0600 on the marker; ANY failure is a
/// hard error (the caller removes the marker and aborts the startup).
#[cfg(unix)]
fn set_lock_mode_0600(f: &std::fs::File, path: &Path) -> Result<(), StoreLockError> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| StoreLockError::Unavailable)?;
    let meta = std::fs::symlink_metadata(path).map_err(|_| StoreLockError::Unavailable)?;
    if meta.file_type().is_symlink() || (meta.permissions().mode() & 0o777) != 0o600 {
        return Err(StoreLockError::Unavailable);
    }
    Ok(())
}

impl StoreLock {
    /// Acquire exclusive ownership of `store_root` for this process.
    /// The returned handle must be held for the process lifetime.
    ///
    /// G91: 1) validate existing components (no symlinks) BEFORE any write;
    /// 2) create the root; 3) re-validate the full path; 4) take the kernel
    /// directory lock (the ownership authority); 5) refresh the 0600 marker
    /// (diagnostics) with fail-closed permission verification.
    ///
    /// G93-A: the permission step is injected so tests can deterministically
    /// exercise the failure path without production hooks or env bypasses.
    #[cfg(unix)]
    pub fn acquire(store_root: &Path) -> Result<Self, StoreLockError> {
        Self::acquire_with(store_root, set_lock_mode_0600)
    }

    /// G93-B — unsupported platforms are refused outright: the weaker
    /// marker-only ownership is NEVER used. The supported deployment target
    /// is Unix (flock(2) on the store-root directory).
    #[cfg(not(unix))]
    pub fn acquire(_store_root: &Path) -> Result<Self, StoreLockError> {
        Err(StoreLockError::Unavailable)
    }

    #[cfg(unix)]
    fn acquire_with<M>(store_root: &Path, set_mode: M) -> Result<Self, StoreLockError>
    where
        M: FnOnce(&std::fs::File, &Path) -> Result<(), StoreLockError>,
    {
        reject_existing_symlink_components(store_root)?;
        std::fs::create_dir_all(store_root).map_err(|_| StoreLockError::Unavailable)?;
        reject_symlink_components(store_root)?;
        // G95-A — fail closed on positively identified network filesystems
        // (Linux); the store must live on a supported local filesystem.
        #[cfg(target_os = "linux")]
        fs_boundary::ensure_supported_filesystem(store_root)?;

        {
            use std::os::unix::io::AsRawFd;
            let dir = std::fs::File::open(store_root).map_err(|_| StoreLockError::Unavailable)?;
            let rc = unsafe {
                flock_abi::flock(dir.as_raw_fd(), flock_abi::LOCK_EX | flock_abi::LOCK_NB)
            };
            if rc != 0 {
                return Err(match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock => StoreLockError::Busy,
                    _ => StoreLockError::Unavailable,
                });
            }
            // We own the store from here (kernel-enforced). The marker is
            // diagnostic only; never follow a symlink at its path.
            let path = store_root.join("signer_instance.lock");
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    return Err(StoreLockError::Busy);
                }
            }
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .map_err(|_| StoreLockError::Unavailable)?;
            let pid = std::process::id();
            let body = format!(
                "{{\"pid\":{pid},\"started_at_unix\":{}}}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            );
            f.write_all(body.as_bytes())
                .map_err(|_| StoreLockError::Unavailable)?;
            f.sync_all().map_err(|_| StoreLockError::Unavailable)?;
            // G91 (F1): permission enforcement is fail-closed — any failure
            // to set AND verify 0600 removes the marker and aborts. The
            // cleanup runs under the directory flock, so it can only ever
            // remove the marker this acquisition just created/truncated.
            if let Err(e) = set_mode(&f, &path) {
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
            return Ok(Self {
                _dir: dir,
                _file: f,
                path,
            });
        }
    }

    /// The lock file path (for diagnostics; never logged with contents).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for StoreLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug prints the path only — never the handle internals or contents
        f.debug_struct("StoreLock")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod g87_lock_tests {
    use super::*;
    use uuid::Uuid;

    fn temp_store(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "g87lock-{tag}-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn acquire_is_exclusive_within_the_process() {
        let dir = temp_store("excl");
        let l1 = StoreLock::acquire(&dir).expect("first acquire wins");
        let err = StoreLock::acquire(&dir).unwrap_err();
        assert_eq!(err, StoreLockError::Busy, "second acquire must fail closed");
        drop(l1);
        // G91: ownership is the kernel directory lock; dropping the handle
        // releases it, so a fresh acquire wins again.
        let l2 = StoreLock::acquire(&dir).expect("released after drop");
        drop(l2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_lock_from_dead_pid_is_taken_over() {
        let dir = temp_store("stale");
        // fabricate a marker whose pid cannot be alive (negative ⇒ dead)
        std::fs::write(dir.join("signer_instance.lock"), r#"{"pid":-1}"#).unwrap();
        let l = StoreLock::acquire(&dir).expect("stale marker is reclaimed");
        let body = std::fs::read_to_string(l.path()).unwrap();
        assert!(body.contains("\"pid\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// G91 — a garbage marker with NO live kernel-lock holder is not proof
    /// of an owner (marker content is diagnostic only); it is reclaimed.
    #[test]
    fn unparsable_marker_without_owner_is_reclaimed() {
        let dir = temp_store("junk-free");
        std::fs::write(dir.join("signer_instance.lock"), "not json at all").unwrap();
        let l = StoreLock::acquire(&dir).expect("no holder ⇒ reclaim");
        let body = std::fs::read_to_string(l.path()).unwrap();
        assert!(body.contains("\"started_at_unix\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// G91 — the fail-closed property is preserved where it matters: a
    /// garbage marker while a LIVE owner holds the store ⇒ Busy.
    #[test]
    fn unparsable_marker_with_live_owner_is_busy() {
        let dir = temp_store("junk-live");
        let l = StoreLock::acquire(&dir).expect("first");
        std::fs::write(dir.join("signer_instance.lock"), "not json at all").unwrap();
        assert_eq!(StoreLock::acquire(&dir).unwrap_err(), StoreLockError::Busy);
        drop(l);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- G91 (F1): fail-closed marker permissions ------------------------

    #[cfg(unix)]
    #[test]
    fn f1_lock_marker_is_0600_after_acquire() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_store("f1-mode");
        let l = StoreLock::acquire(&dir).expect("acquire");
        let meta = std::fs::symlink_metadata(l.path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Deterministic exercise of the VERIFY leg: the chmod succeeds on the
    /// real inode, but the marker path is a symlink ⇒ refused (fail closed).
    #[cfg(unix)]
    #[test]
    fn f1_mode_verification_rejects_symlinked_marker_path() {
        let dir = temp_store("f1-link");
        let outside = temp_store("f1-outside");
        let real = outside.join("real.lock");
        std::fs::write(&real, b"x").unwrap();
        let link = dir.join("marker-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let f = std::fs::File::open(&real).unwrap();
        assert_eq!(
            set_lock_mode_0600(&f, &link).unwrap_err(),
            StoreLockError::Unavailable
        );
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    // --- G91 (F2): marker deletion/replacement cannot release ownership --

    #[test]
    fn f2_deleting_the_marker_does_not_release_ownership() {
        let dir = temp_store("f2-del");
        let l1 = StoreLock::acquire(&dir).expect("first");
        std::fs::remove_file(l1.path()).unwrap();
        assert_eq!(
            StoreLock::acquire(&dir).unwrap_err(),
            StoreLockError::Busy,
            "directory flock must still exclude a second signer"
        );
        drop(l1);
        let l2 = StoreLock::acquire(&dir).expect("released only after handle death");
        drop(l2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn f2_replacing_the_marker_does_not_grant_second_owner() {
        let dir = temp_store("f2-repl");
        let l1 = StoreLock::acquire(&dir).expect("first");
        std::fs::remove_file(l1.path()).unwrap();
        std::fs::write(
            dir.join("signer_instance.lock"),
            format!(r#"{{"pid":{}}}"#, std::process::id()),
        )
        .unwrap();
        assert_eq!(StoreLock::acquire(&dir).unwrap_err(), StoreLockError::Busy);
        drop(l1);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- G91 (F3): no writes through unvalidated paths -------------------

    #[cfg(unix)]
    #[test]
    fn f3_symlinked_parent_is_rejected_before_any_creation() {
        let real = temp_store("f3-real");
        let holder = temp_store("f3-holder");
        let alias = holder.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let target = alias.join("child-store");
        assert_eq!(
            StoreLock::acquire(&target).unwrap_err(),
            StoreLockError::Unavailable
        );
        assert!(
            !real.join("child-store").exists(),
            "no directory may be created through a symlinked component"
        );
        std::fs::remove_dir_all(&real).ok();
        std::fs::remove_dir_all(&holder).ok();
    }

    // --- G89 (M1): symlink / permission hardening -----------------------

    /// A symlinked lock file is NEVER ridden nor removed-and-replaced: the
    /// acquire fails BUSY (fail closed) and the symlink target is untouched.
    #[cfg(unix)]
    #[test]
    fn symlinked_lock_file_is_refused_not_ridden() {
        let dir = temp_store("lock-link");
        let outside = temp_store("outside-victim");
        let victim = outside.join("victim.lock");
        std::fs::write(&victim, b"attacker planted").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("signer_instance.lock")).unwrap();
        let err = StoreLock::acquire(&dir).unwrap_err();
        assert_eq!(
            err,
            StoreLockError::Busy,
            "symlinked lock ⇒ Busy (fail closed)"
        );
        // the victim file was NOT removed (no symlink-following takeover)
        assert!(victim.exists(), "symlink target must survive the refusal");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    // --- G93-A: injected permission-setter failure ------------------------

    /// The injected setter fails exactly like a chmod(2) rejection: the
    /// acquisition must abort, remove its own marker, and leave no ownership
    /// behind (the store stays acquirable).
    #[test]
    fn g93_injected_mode_failure_fails_closed_and_cleans_its_marker() {
        let dir = temp_store("g93-mode-fail");
        let err =
            StoreLock::acquire_with(&dir, |_, _| Err(StoreLockError::Unavailable)).unwrap_err();
        assert_eq!(err, StoreLockError::Unavailable);
        assert!(
            !dir.join("signer_instance.lock").exists(),
            "the failed acquisition removes its own marker"
        );
        let l = StoreLock::acquire(&dir).expect("no ownership leaked: store still acquirable");
        drop(l);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The failure cleanup must never touch a marker owned by ANOTHER live
    /// signer: a competing acquisition is rejected at the directory flock
    /// before any write/cleanup runs.
    #[test]
    fn g93_injected_failure_never_touches_a_live_owners_marker() {
        let dir = temp_store("g93-other-owner");
        let owner = StoreLock::acquire(&dir).expect("owner");
        let marker = dir.join("signer_instance.lock");
        let before = std::fs::read_to_string(&marker).unwrap();
        let err =
            StoreLock::acquire_with(&dir, |_, _| Err(StoreLockError::Unavailable)).unwrap_err();
        assert_eq!(err, StoreLockError::Busy, "flock precedes any marker work");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            before,
            "the live owner's marker is untouched"
        );
        drop(owner);
        std::fs::remove_dir_all(&dir).ok();
    }

    // --- G93-B: unsupported platform refusal ------------------------------

    /// Runs only on non-Unix targets: startup must be refused outright (no
    /// marker-only fallback). Not executed on this Linux host — stated as
    /// platform-untested in the report.
    // --- G95-A: Linux filesystem boundary --------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn g95_network_filesystems_are_refused() {
        for fs in ["nfs", "nfs4", "cifs", "smbfs", "smb3"] {
            assert!(!fs_boundary::filesystem_allowed(fs), "{fs} must be refused");
        }
        for fs in ["ext4", "xfs", "btrfs", "tmpfs", "overlay", "f2fs"] {
            assert!(fs_boundary::filesystem_allowed(fs), "{fs} must be allowed");
        }
        // unknown types are explicitly allowed (documented policy: only
        // POSITIVELY identified network filesystems are refused)
        assert!(fs_boundary::filesystem_allowed("zfs"));
        assert!(fs_boundary::filesystem_allowed("9p"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g95_mountinfo_uses_the_longest_matching_mount() {
        let table = "36 25 0:32 / / rw - ext4 /dev/sda1 rw\n\
                     40 36 0:40 / /tmp rw - tmpfs tmpfs rw\n\
                     50 40 0:50 / /tmp/store rw - nfs4 srv:/x rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/tmp/store/users/1"))
                .as_deref(),
            Some("nfs4")
        );
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/tmp/other")).as_deref(),
            Some("tmpfs")
        );
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/var/lib/x")).as_deref(),
            Some("ext4")
        );
        // "/tmpfoo" must NOT match the "/tmp" mount (separator check)
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/tmpfoo")).as_deref(),
            Some("ext4")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g95_escaped_mount_points_are_unescaped() {
        let table = "1 0 0:1 / / rw - ext4 /dev/sda1 rw\n\
                     2 1 0:2 / /mnt/my\\040disk rw - cifs //srv/share rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/my disk/store"))
                .as_deref(),
            Some("cifs")
        );
    }

    // --- G97-A: UTF-8-safe / malformed-input unescaping ------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn g97_non_ascii_mount_point_is_matched_exactly() {
        // raw (unescaped) UTF-8 mount point: byte-preserving decode must
        // compare equal to the canonical path — no Latin-1 mangling
        let table = "7 1 0:7 / /mnt/ديسك rw - ext4 /dev/sdb1 rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/ديسك/store")).as_deref(),
            Some("ext4")
        );
        // a different non-ASCII path must NOT match that mount
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/مجلد")),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g97_escaped_backslash_and_whitespace_decode_correctly() {
        // mount point bytes: /mnt/a\b c   encoded as /mnt/a\134b\040c
        let table = "8 1 0:8 / /mnt/a\\134b\\040c rw - xfs /dev/sdc1 rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/a\\b c/x")).as_deref(),
            Some("xfs")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g97_malformed_escape_is_skipped_not_selected() {
        // malformed (\999) matching line + a valid root line: the malformed
        // mount must be skipped; the root still covers the path correctly
        let table = "9 1 0:9 / / rw - ext4 /dev/sda1 rw\n\
                     10 9 0:10 / /mnt/bad\\999 rw - nfs4 srv:/x rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/bad/store")).as_deref(),
            Some("ext4")
        );
        // only the malformed line: no decodable covering mount ⇒ None
        let only_bad = "10 9 0:10 / /mnt/bad\\999 rw - nfs4 srv:/x rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(only_bad.as_bytes(), Path::new("/mnt/bad/store")),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g97_truncated_escape_fails_closed() {
        let table = "11 9 0:11 / /mnt/t\\04 rw - ext4 /dev/sdd1 rw\n";
        assert_eq!(
            fs_boundary::fstype_for_path(table.as_bytes(), Path::new("/mnt/t")),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g97_invalid_utf8_mount_line_is_skipped() {
        // a matching mount line with invalid UTF-8 bytes (0xFF) is skipped;
        // the valid root line still covers the path
        let mut table: Vec<u8> =
            b"12 1 0:12 / / rw - ext4 /dev/sda1 rw\n13 12 0:13 / /mnt/".to_vec();
        table.push(0xFF);
        table.extend_from_slice(b" rw - cifs //srv/x rw\n");
        let path = Path::new("/mnt/\u{FFFD}/store");
        assert_eq!(
            fs_boundary::fstype_for_path(&table, path).as_deref(),
            Some("ext4")
        );
        // without the root line nothing decodable covers the path ⇒ None
        let mut only: Vec<u8> = b"13 12 0:13 / /mnt/".to_vec();
        only.push(0xFF);
        only.extend_from_slice(b" rw - cifs //srv/x rw\n");
        assert_eq!(fs_boundary::fstype_for_path(&only, path), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn g95_current_store_filesystem_is_accepted() {
        let dir = temp_store("g95-fs-ok");
        assert!(fs_boundary::ensure_supported_filesystem(&dir).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(not(unix))]
    #[test]
    fn g93_non_unix_platform_is_refused() {
        let dir = temp_store("g93-nonunix");
        assert_eq!(
            StoreLock::acquire(&dir).unwrap_err(),
            StoreLockError::Unavailable
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
