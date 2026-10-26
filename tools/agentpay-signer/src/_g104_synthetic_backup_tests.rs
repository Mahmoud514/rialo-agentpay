//! G104 — synthetic backup/restore MECHANICS (TEST-ONLY).
//!
//! Scope: manifest construction, integrity verification (missing/extra/
//! tampered files), stale-epoch rejection, and restore into a fresh directory.
//! NOT implemented here (and still blocked on ADR-001 approval):
//! encryption, backup-key custody, real signer-store integration, funded-key
//! recovery, and operator authorization. Synthetic files only; no real keys.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MANIFEST_NAME: &str = "manifest.json";

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct ManifestFile {
    path: String,
    size: u64,
    blake3: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct Manifest {
    schema: String,
    manifest_version: u32,
    store_epoch: u64,
    files: Vec<ManifestFile>,
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "g104-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn write_file(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, body).unwrap();
    set_mode(&p, 0o600);
}

/// Synthetic store: fake keys/records only (never real key material).
fn synthetic_store(root: &Path, users: &[u64]) {
    for u in users {
        write_file(
            root,
            &format!("users/{u}.wallet.json"),
            &format!(r#"{{"user_id":"{u}","wallet_version":2,"address":"SYNTH{u}"}}"#),
        );
        write_file(
            root,
            &format!("users/{u}.key.json"),
            &format!(r#"{{"v":1,"user_id":"{u}","fake_key":"SYNTHETIC-{u}"}}"#),
        );
        write_file(
            root,
            &format!("users/{u}.recovery.json"),
            &format!(
                r#"{{"version":1,"wallet_version":2,"user_id":"{u}","wallet_address":"SYNTH{u}"}}"#
            ),
        );
    }
    write_file(root, "creation_gate/nonce-aa11.json", r#"{"nonce":"aa11"}"#);
    write_file(
        root,
        "signer_identity.key.json",
        r#"{"fake_channel":"SYNTHETIC"}"#,
    );
}

fn rel_path(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap()
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn collect(root: &Path) -> BTreeMap<String, (u64, String)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let rel = rel_path(root, &p);
                if rel == MANIFEST_NAME {
                    continue;
                }
                let body = std::fs::read(&p).unwrap();
                out.insert(
                    rel,
                    (body.len() as u64, blake3::hash(&body).to_hex().to_string()),
                );
            }
        }
    }
    out
}

fn build_manifest(root: &Path, epoch: u64) -> Manifest {
    let files = collect(root)
        .into_iter()
        .map(|(path, (size, blake3))| ManifestFile { path, size, blake3 })
        .collect();
    Manifest {
        schema: "agentpay-store-manifest-v1".to_string(),
        manifest_version: 1,
        store_epoch: epoch,
        files,
    }
}

fn verify_manifest(root: &Path, m: &Manifest) -> Result<(), String> {
    if m.schema != "agentpay-store-manifest-v1" || m.manifest_version != 1 {
        return Err("manifest schema/version".into());
    }
    let actual = collect(root);
    let expected: BTreeMap<String, (u64, String)> = m
        .files
        .iter()
        .map(|f| (f.path.clone(), (f.size, f.blake3.clone())))
        .collect();
    if expected.len() != m.files.len() {
        return Err("duplicate manifest entries".into());
    }
    let missing: Vec<_> = expected
        .keys()
        .filter(|k| !actual.contains_key(*k))
        .collect();
    if !missing.is_empty() {
        return Err(format!("missing files: {missing:?}"));
    }
    let extra: Vec<_> = actual
        .keys()
        .filter(|k| !expected.contains_key(*k))
        .collect();
    if !extra.is_empty() {
        return Err(format!("unexpected files: {extra:?}"));
    }
    for (path, (size, hash)) in &expected {
        let (a_size, a_hash) = actual.get(path).unwrap();
        if a_size != size || a_hash != hash {
            return Err(format!("tampered file: {path}"));
        }
    }
    Ok(())
}

fn try_copy_tree(src: &Path, dst: &Path, fail_after: &mut Option<usize>) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    set_mode(dst, 0o700);
    for e in std::fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
        if let Some(n) = fail_after.as_mut() {
            if *n == 0 {
                return Err("injected copy failure".into());
            }
            *n -= 1;
        }
        let from = e.path();
        let to = dst.join(e.file_name());
        if e.file_type().map_err(|e| e.to_string())?.is_dir() {
            try_copy_tree(&from, &to, fail_after)?;
        } else {
            std::fs::copy(&from, &to).map_err(|e| e.to_string())?;
            set_mode(&to, 0o600);
        }
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) {
    let mut none = None;
    try_copy_tree(src, dst, &mut none).unwrap();
}

/// Snapshot: copy the store and write its manifest into the archive root.
fn snapshot(src: &Path, archive: &Path, epoch: u64) -> Manifest {
    copy_tree(src, archive);
    let m = build_manifest(src, epoch);
    std::fs::write(
        archive.join(MANIFEST_NAME),
        serde_json::to_vec_pretty(&m).unwrap(),
    )
    .unwrap();
    m
}

fn load_manifest(archive: &Path) -> Result<Manifest, String> {
    let bytes = std::fs::read(archive.join(MANIFEST_NAME)).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn restore_verified(archive: &Path, dst: &Path, current_epoch: u64) -> Result<(), String> {
    let m = load_manifest(archive)?;
    restore(archive, dst, &m, current_epoch)
}

/// Replace an existing destination only after full verification; restores the
/// previous state if the swap fails. (Tenant-level simulation, not a claim of
/// platform-atomic directory replacement.)
fn restore_replace(archive: &Path, dst: &Path, current_epoch: u64) -> Result<(), String> {
    restore_replace_inner(archive, dst, current_epoch, None)
}

fn restore_replace_inner(
    archive: &Path,
    dst: &Path,
    current_epoch: u64,
    fail_after: Option<usize>,
) -> Result<(), String> {
    let m = load_manifest(archive)?;
    if m.store_epoch < current_epoch {
        return Err("stale epoch".into());
    }
    verify_manifest(archive, &m)?;
    let tmp = dst.with_file_name(format!(".restore-tmp-{}", uuid::Uuid::new_v4()));
    let mut fail = fail_after;
    if let Err(e) = try_copy_tree(archive, &tmp, &mut fail) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    verify_manifest(&tmp, &m)?;
    let bak = dst.with_file_name(format!(".restore-bak-{}", uuid::Uuid::new_v4()));
    let existed = dst.exists();
    if existed {
        std::fs::rename(dst, &bak).map_err(|e| e.to_string())?;
    }
    match std::fs::rename(&tmp, dst) {
        Ok(()) => {
            if existed {
                let _ = std::fs::remove_dir_all(&bak);
            }
            Ok(())
        }
        Err(e) => {
            if existed {
                let _ = std::fs::rename(&bak, dst);
            }
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e.to_string())
        }
    }
}

/// Synthetic binding/envelope consistency: wallet record, key container, and
/// recovery envelope must agree on user_id + address (test fixture only).
fn verify_binding_integrity(root: &Path, users: &[u64]) -> Result<(), String> {
    for u in users {
        let read = |name: &str| -> Result<serde_json::Value, String> {
            let p = root.join(format!("users/{u}.{name}.json"));
            let b = std::fs::read(&p).map_err(|e| format!("{p:?}: {e}"))?;
            serde_json::from_slice(&b).map_err(|e| format!("{p:?}: {e}"))
        };
        let w = read("wallet")?;
        let k = read("key")?;
        let r = read("recovery")?;
        let uid = u.to_string();
        let addr = format!("SYNTH{u}");
        if w.get("user_id").and_then(|v| v.as_str()) != Some(uid.as_str())
            || w.get("address").and_then(|v| v.as_str()) != Some(addr.as_str())
        {
            return Err(format!("wallet record mismatch for {u}"));
        }
        if k.get("user_id").and_then(|v| v.as_str()) != Some(uid.as_str()) {
            return Err(format!("key container mismatch for {u}"));
        }
        if r.get("user_id").and_then(|v| v.as_str()) != Some(uid.as_str())
            || r.get("wallet_address").and_then(|v| v.as_str()) != Some(addr.as_str())
        {
            return Err(format!("recovery envelope mismatch for {u}"));
        }
    }
    Ok(())
}

/// Restore into a FRESH directory; refuses stale epochs and existing targets.
fn restore(archive: &Path, dst: &Path, m: &Manifest, current_epoch: u64) -> Result<(), String> {
    if m.store_epoch < current_epoch {
        return Err("stale epoch".into());
    }
    verify_manifest(archive, m)?;
    if dst.exists() {
        return Err("destination exists".into());
    }
    let tmp = dst.with_file_name(format!(".restore-tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        copy_tree(archive, &tmp);
        verify_manifest(&tmp, m)?;
        std::fs::rename(&tmp, dst).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    result
}

#[test]
fn g104_synthetic_backup_roundtrip() {
    let src = Tmp::new("src");
    synthetic_store(src.path(), &[11, 22, 33]);
    let m = build_manifest(src.path(), 7);
    assert_eq!(m.files.len(), 3 * 3 + 2);
    verify_manifest(src.path(), &m).unwrap();

    let archive = Tmp::new("archive");
    copy_tree(src.path(), archive.path());
    verify_manifest(archive.path(), &m).unwrap();

    let parent = Tmp::new("restore");
    let dst = parent.path().join("store");
    restore(archive.path(), &dst, &m, 7).unwrap();
    verify_manifest(&dst, &m).unwrap();
    assert_eq!(collect(src.path()), collect(&dst));
}

#[test]
fn g104_missing_extra_and_tampered_files_are_rejected() {
    let src = Tmp::new("src2");
    synthetic_store(src.path(), &[7]);
    let m = build_manifest(src.path(), 1);

    let missing = Tmp::new("missing");
    copy_tree(src.path(), missing.path());
    std::fs::remove_file(missing.path().join("users/7.key.json")).unwrap();
    assert!(verify_manifest(missing.path(), &m).is_err());

    let extra = Tmp::new("extra");
    copy_tree(src.path(), extra.path());
    std::fs::write(extra.path().join("users/evil.json"), b"x").unwrap();
    assert!(verify_manifest(extra.path(), &m).is_err());

    let tampered = Tmp::new("tampered");
    copy_tree(src.path(), tampered.path());
    std::fs::write(tampered.path().join("users/7.wallet.json"), b"changed").unwrap();
    assert!(verify_manifest(tampered.path(), &m).is_err());
}

#[test]
fn g104_stale_epoch_and_duplicate_restore_are_rejected() {
    let src = Tmp::new("src3");
    synthetic_store(src.path(), &[9]);
    let m = build_manifest(src.path(), 2);

    let parent = Tmp::new("restore3");
    let dst = parent.path().join("store");
    assert!(restore(src.path(), &dst, &m, 3).is_err(), "stale epoch");
    restore(src.path(), &dst, &m, 2).unwrap();
    let before = collect(&dst);
    assert!(
        restore(src.path(), &dst, &m, 2).is_err(),
        "duplicate restore"
    );
    assert_eq!(
        collect(&dst),
        before,
        "failed restore must not mutate destination"
    );
}

#[test]
fn g104_failed_restore_leaves_no_partial_destination() {
    let src = Tmp::new("src4");
    synthetic_store(src.path(), &[5]);
    let m = build_manifest(src.path(), 1);
    let archive = Tmp::new("archive4");
    copy_tree(src.path(), archive.path());
    // corrupt the archive AFTER manifest creation
    std::fs::write(archive.path().join("users/5.key.json"), b"corrupt").unwrap();

    let parent = Tmp::new("restore4");
    let dst = parent.path().join("store");
    assert!(restore(archive.path(), &dst, &m, 1).is_err());
    assert!(!dst.exists(), "no partial destination");
    // temp directory must be cleaned up
    let leftovers: Vec<_> = std::fs::read_dir(parent.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".restore-tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temp restore dir cleaned");
}

// --- Payment-signing interface: SCHEMA-ONLY boundary tests -----------------
// These validate the typed wire contract; they do NOT sign, route, or call a
// live signer.

#[test]
fn g104_user_sign_request_schema_is_strict() {
    use crate::user_signer_protocol::UserSignRequest;
    let valid = r#"{
        "user_id":"42",
        "transaction":{
            "fee_payer":"PAYER","recipient":"RECIPIENT","amount_kelvin":1000,
            "valid_from_ms":1700000000000,"config_hash_prefix":"123","occ":false
        },
        "auth_signature":{"pubkey":{"user_id":"42","base58":"AUTH"},"signature":"SIG"},
        "channel_nonce":"n1"
    }"#;
    assert!(serde_json::from_str::<UserSignRequest>(valid).is_ok());

    let extra = valid.replace(
        r#""channel_nonce":"n1""#,
        r#""channel_nonce":"n1","extra":1"#,
    );
    assert!(
        serde_json::from_str::<UserSignRequest>(&extra).is_err(),
        "unknown field"
    );

    let mut v: serde_json::Value = serde_json::from_str(valid).unwrap();
    v.as_object_mut().unwrap().remove("channel_nonce");
    let missing = v.to_string();
    assert!(
        serde_json::from_str::<UserSignRequest>(&missing).is_err(),
        "missing nonce"
    );

    let bad_amount = valid.replace(r#""amount_kelvin":1000"#, r#""amount_kelvin":-1"#);
    assert!(
        serde_json::from_str::<UserSignRequest>(&bad_amount).is_err(),
        "negative amount"
    );
}

#[test]
fn g104_user_sign_response_and_denial_shapes_roundtrip() {
    use crate::user_signer_protocol::{UserSignDenial, UserSignResponse};
    let resp = UserSignResponse {
        user_id: "42".into(),
        canonical_hash: "h".into(),
        canonical_message_b64: "bQ==".into(),
        signature_b64: "c2ln".into(),
        required_signatures: 1,
    };
    let text = serde_json::to_string(&resp).unwrap();
    assert_eq!(
        serde_json::from_str::<UserSignResponse>(&text).unwrap(),
        resp
    );
    let extra = text.replace(
        r#""required_signatures":1"#,
        r#""required_signatures":1,"extra":1"#,
    );
    assert!(serde_json::from_str::<UserSignResponse>(&extra).is_err());

    let denial = UserSignDenial {
        error: "DENIED".into(),
        code: "USER_POLICY_DENIED".into(),
    };
    let dtext = serde_json::to_string(&denial).unwrap();
    assert_eq!(
        serde_json::from_str::<UserSignDenial>(&dtext).unwrap(),
        denial
    );
}

// --- G105: snapshot manifest, atomic replacement, binding integrity ---------

#[test]
fn g105_snapshot_manifest_roundtrip_and_restore() {
    let src = Tmp::new("g105src");
    synthetic_store(src.path(), &[1, 2]);
    let archive = Tmp::new("g105arc");
    let m = snapshot(src.path(), archive.path(), 5);
    assert!(archive.path().join(MANIFEST_NAME).exists());
    assert_eq!(load_manifest(archive.path()).unwrap(), m);

    let parent = Tmp::new("g105dst");
    let dst = parent.path().join("store");
    restore_verified(archive.path(), &dst, 5).unwrap();
    verify_manifest(&dst, &m).unwrap();
    assert_eq!(collect(src.path()), collect(&dst));
}

#[test]
fn g105_replace_swaps_only_after_verification() {
    let src = Tmp::new("g105src2");
    synthetic_store(src.path(), &[3]);
    let archive = Tmp::new("g105arc2");
    let m = snapshot(src.path(), archive.path(), 2);

    let parent = Tmp::new("g105dst2");
    let dst = parent.path().join("store");
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("old-state.txt"), b"old").unwrap();

    restore_replace(archive.path(), &dst, 2).unwrap();
    assert!(!dst.join("old-state.txt").exists(), "old state replaced");
    verify_manifest(&dst, &m).unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(parent.path())
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with(".restore-bak-") || n.starts_with(".restore-tmp-")
        })
        .collect();
    assert!(leftovers.is_empty(), "no swap/temp leftovers");
}

#[test]
fn g105_failed_replace_keeps_previous_state() {
    let src = Tmp::new("g105src3");
    synthetic_store(src.path(), &[4]);
    let archive = Tmp::new("g105arc3");
    snapshot(src.path(), archive.path(), 2);
    // corrupt AFTER snapshot + manifest
    std::fs::write(archive.path().join("users/4.key.json"), b"corrupt").unwrap();

    let parent = Tmp::new("g105dst3");
    let dst = parent.path().join("store");
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("old-state.txt"), b"keep-me").unwrap();

    assert!(restore_replace(archive.path(), &dst, 2).is_err());
    assert!(
        dst.join("old-state.txt").exists(),
        "previous state preserved"
    );
    assert_eq!(
        std::fs::read(dst.join("old-state.txt")).unwrap(),
        b"keep-me"
    );
}

#[test]
fn g105_stale_snapshot_cannot_replace_current_state() {
    let src = Tmp::new("g105src4");
    synthetic_store(src.path(), &[6]);
    let archive = Tmp::new("g105arc4");
    snapshot(src.path(), archive.path(), 1);

    let parent = Tmp::new("g105dst4");
    let dst = parent.path().join("store");
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("current.txt"), b"current").unwrap();

    assert!(
        restore_replace(archive.path(), &dst, 2).is_err(),
        "stale epoch"
    );
    assert!(dst.join("current.txt").exists(), "current state preserved");
}

#[test]
fn g105_partial_copy_failure_is_never_promoted() {
    let src = Tmp::new("g105src5");
    synthetic_store(src.path(), &[7, 8]);
    let parent = Tmp::new("g105dst5");
    let tmp = parent.path().join(".restore-tmp-test");
    let dst = parent.path().join("store");
    let mut fail_after = Some(2usize);
    assert!(try_copy_tree(src.path(), &tmp, &mut fail_after).is_err());
    assert!(tmp.exists(), "partial temp exists while failed");
    assert!(!dst.exists(), "failed copy is never promoted");
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn g105_binding_and_envelope_integrity() {
    let src = Tmp::new("g105bind");
    synthetic_store(src.path(), &[11, 22]);
    assert!(verify_binding_integrity(src.path(), &[11, 22]).is_ok());

    std::fs::write(
        src.path().join("users/11.recovery.json"),
        r#"{"version":1,"wallet_version":2,"user_id":"11","wallet_address":"WRONG"}"#,
    )
    .unwrap();
    assert!(
        verify_binding_integrity(src.path(), &[11, 22]).is_err(),
        "envelope mismatch"
    );

    // cross-user key container substitution must be rejected
    let other = std::fs::read(src.path().join("users/22.key.json")).unwrap();
    std::fs::write(src.path().join("users/11.key.json"), other).unwrap();
    assert!(
        verify_binding_integrity(src.path(), &[11, 22]).is_err(),
        "cross-user key"
    );
}

// --- G106: manifest version, interrupted swap, orphan cleanup --------------

/// Test-only crash-recovery helper: remove leftover restore temp/backup dirs.
fn cleanup_orphan_temps(parent: &Path) -> usize {
    let mut removed = 0;
    if let Ok(entries) = std::fs::read_dir(parent) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if (n.starts_with(".restore-tmp-") || n.starts_with(".restore-bak-"))
                && std::fs::remove_dir_all(e.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

#[test]
fn g106_manifest_version_is_rejected() {
    let src = Tmp::new("g106ver");
    synthetic_store(src.path(), &[1]);
    let mut m = build_manifest(src.path(), 1);
    assert!(verify_manifest(src.path(), &m).is_ok());
    m.manifest_version = 99;
    assert!(verify_manifest(src.path(), &m).is_err());
}

#[test]
fn g106_interrupted_replace_keeps_previous_state() {
    let src = Tmp::new("g106src");
    synthetic_store(src.path(), &[2]);
    let archive = Tmp::new("g106arc");
    snapshot(src.path(), archive.path(), 2);

    let parent = Tmp::new("g106dst");
    let dst = parent.path().join("store");
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(dst.join("old-state.txt"), b"keep").unwrap();

    assert!(
        restore_replace_inner(archive.path(), &dst, 2, Some(2)).is_err(),
        "injected copy failure"
    );
    assert!(dst.join("old-state.txt").exists(), "previous state kept");
    let leftovers: Vec<_> = std::fs::read_dir(parent.path())
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.starts_with(".restore-tmp-") || n.starts_with(".restore-bak-")
        })
        .collect();
    assert!(leftovers.is_empty(), "temp cleaned on interrupted copy");
}

#[test]
fn g106_orphan_temp_cleanup_only_touches_restore_artifacts() {
    let parent = Tmp::new("g106orph");
    std::fs::create_dir_all(parent.path().join(".restore-tmp-a")).unwrap();
    std::fs::create_dir_all(parent.path().join(".restore-bak-b")).unwrap();
    std::fs::create_dir_all(parent.path().join("live-store")).unwrap();
    assert_eq!(cleanup_orphan_temps(parent.path()), 2);
    assert!(
        parent.path().join("live-store").exists(),
        "live store untouched"
    );
}

// --- G107: malformed metadata, duplicate entries, modes, fixture hygiene ----

#[test]
fn g107_truncated_or_corrupt_manifest_is_rejected() {
    let src = Tmp::new("g107msrc");
    synthetic_store(src.path(), &[1]);
    let archive = Tmp::new("g107marc");
    snapshot(src.path(), archive.path(), 1);

    std::fs::write(archive.path().join(MANIFEST_NAME), b"{\"schema\":").unwrap();
    assert!(load_manifest(archive.path()).is_err(), "truncated JSON");

    std::fs::write(archive.path().join(MANIFEST_NAME), b"not-json").unwrap();
    assert!(load_manifest(archive.path()).is_err(), "corrupt JSON");
}

#[test]
fn g107_wrong_schema_and_duplicate_manifest_entries_are_rejected() {
    let src = Tmp::new("g107ssrc");
    synthetic_store(src.path(), &[1]);
    let mut m = build_manifest(src.path(), 1);
    assert!(verify_manifest(src.path(), &m).is_ok());

    let mut wrong = m.clone();
    wrong.schema = "agentpay-store-manifest-v0".into();
    assert!(verify_manifest(src.path(), &wrong).is_err(), "wrong schema");

    m.files.push(m.files[0].clone());
    assert!(verify_manifest(src.path(), &m).is_err(), "duplicate entry");
}

#[cfg(unix)]
#[test]
fn g107_restore_preserves_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let src = Tmp::new("g107psrc");
    synthetic_store(src.path(), &[1, 2]);
    let archive = Tmp::new("g107parc");
    snapshot(src.path(), archive.path(), 1);
    let parent = Tmp::new("g107pdst");
    let dst = parent.path().join("store");
    restore_verified(archive.path(), &dst, 1).unwrap();

    for (rel, _) in collect(&dst) {
        let p = dst.join(rel);
        let mode = p.metadata().unwrap().permissions().mode() & 0o777;
        if p.is_file() {
            assert_eq!(mode, 0o600, "file {} must stay 0600", p.display());
        }
    }
    let users = dst.join("users");
    assert_eq!(
        users.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn g107_fixtures_contain_no_secret_material() {
    let src = Tmp::new("g107sec");
    synthetic_store(src.path(), &[1, 2]);
    let mut all = Vec::new();
    for (rel, _) in collect(src.path()) {
        all.extend_from_slice(rel.as_bytes());
        all.extend_from_slice(&std::fs::read(src.path().join(&rel)).unwrap());
    }
    let text = String::from_utf8_lossy(&all).to_ascii_uppercase();
    for marker in [
        "PRIVATE KEY",
        "BEGIN OPENSSH",
        "MNEMONIC",
        "PASSWORD",
        "SEED PHRASE",
    ] {
        assert!(!text.contains(marker), "fixture leaked marker: {marker}");
    }
    assert!(text.contains("SYNTHETIC"), "fixtures are labeled synthetic");
}
