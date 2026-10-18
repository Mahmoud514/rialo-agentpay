// PHASE 5 — AGENT CREDENTIALS (autonomous-principal credential store).
//
// Scope of this module (and ONLY this module):
//   * issue / rotate / revoke / authenticate of a per-Agent credential,
//     stored as an Argon2id PHC hash on disk, keyed by the canonical Agent
//     UUID at `artifact/agent_credentials/<uuid>.json`.
//   * The credential secret is 32 fresh getrandom bytes, rendered to the
//     caller ONE TIME as lowercase hex. It is never persisted, never
//     logged, never derivable from the record.
//
// Deliberate non-scope:
//   * NO HTTP routes and no handler changes — this module is not wired to
//     any endpoint yet; issuing, rotating, revoking, or authenticating
//     happens through the functions below only.
//   * NO contact with the user store, any key material, or chain state.
//     There are zero external process invocations and zero address or
//     amount concepts here.
//
// Security properties:
//   * Disk is the authority. There is no in-memory credential map and no
//     cache — a process restart changes nothing about what authenticates.
//   * Fail closed: malformed JSON, wrong schema, non-canonical / mismatched
//     ids, malformed Argon2 PHC strings, revoked records, and unreadable
//     files ALL deny. Parse failures never become partial acceptance.
//   * Anti-enumeration: every authentication failure collapses to the same
//     `AuthenticationFailed` value; the API never says whether an agent or
//     credential exists, and the record contents are never echoed.
//   * revoke keeps the record and stamps revoked_at; rotation replaces the
//     record atomically (temp + rename) WITHOUT ever first deleting the
//     existing file, so a crash mid-rotation cannot destroy the live
//     credential state.
//   * Ownership of an Agent is enforced by the existing API choke point;
//     this module only accepts canonical v4 UUIDs and requires the matching
//     Agent metadata record to exist (fail closed) before issuing.

#![allow(dead_code)] // the credential API is not yet consumed by routes

use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Record format version. A record whose `schema_version` is anything else
/// is corrupt and denied — never migrated, never assumed.
pub const CREDENTIAL_SCHEMA_VERSION: u32 = 1;

/// Bytes of randomness per issued credential (rendered as 64 hex chars).
pub const CREDENTIAL_BYTES: usize = 32;

/// Bytes of fresh randomness for the Argon2 salt (embedded in the PHC).
pub const SALT_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Persisted credential record. Fields are public-safety by construction:
/// only the PHC hash (which embeds algorithm, params, salt, and digest —
/// all one-way), the agent id, and timestamps. The plaintext credential is
/// NEVER represented in this type.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub schema_version: u32,
    pub agent_id: String,
    /// full Argon2id PHC string:
    /// `$argon2id$v=19$m=...,t=...,p=...$<salt-b64>$<hash-b64>`
    pub phc: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// set once by revoke; the record is retained for audit. Revoked
    /// credentials never authenticate and never rotate.
    pub revoked_at: Option<i64>,
    /// PHASE 9 "Key rotation / lifecycle" — the POLICY-NEUTRAL expiry
    /// mechanism. `None` = no expiry configured (the current policy state:
    /// no TTL value has been decided by the project — the mechanism exists,
    /// the VALUE is a recorded decision blocker). When `Some(ts)`, the
    /// credential stops authenticating at/after that unix timestamp —
    /// fail-closed, checked at authentication time (not at load time, so
    /// rotate/revoke of an expired record stays possible).
    #[serde(default)]
    pub expires_at: Option<i64>,
}

/// Outcome vocabulary. Fieldless — no internal detail can ever travel with
/// a denial, which is also what makes authentication failures
/// indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialError {
    /// the agent id is not canonical, or the agent record does not exist /
    /// is unreadable / is not schema v1
    InvalidAgent,
    /// issue onto an existing live record, or rotate/revoke a missing,
    /// corrupt, or already-revoked record — collapsed into ONE stable
    /// category so lifecycle calls cannot enumerate record state either
    RecordUnavailable,
    /// persistence failed (directory, temp file, write, or rename)
    Storage,
    /// THE authentication denial: no agent matched this credential, or the
    /// presented credential is malformed. Identical in every case.
    AuthenticationFailed,
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Canonical lowercase UUIDv4 only (same rules as the agent store): no
/// braces, urn form, uppercase, missing hyphens, or non-v4 versions. An
/// unvalidated string can never reach path construction.
fn parse_canonical_agent_id(raw: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(raw).ok()?;
    if id.get_version() != Some(uuid::Version::Random) {
        return None;
    }
    if raw != id.to_string() {
        return None;
    }
    Some(id)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Strict lowercase-or-uppercase hex; rejects odd length and any other
/// character. Never used on persisted secret material (nothing secret is
/// persisted).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

fn fill_random(buf: &mut [u8]) -> bool {
    getrandom::getrandom(buf).is_ok()
}

fn credential_path(dir: &Path, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// temp file in the SAME directory (unique name) + fs::rename = atomic
/// replace. Mode 0600 is set on the temp file BEFORE content lands, so the
/// secret-shaped (though hash-only) record is never momentarily readable by
/// others, and readers never observe a partial document. On any failure the
/// temp file this call created is removed — only ever this exact path.
fn write_record_atomic(path: &Path, record: &CredentialRecord) -> Result<(), CredentialError> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| CredentialError::Storage)?;
    let tmp = path.with_file_name(format!(".tmp-{}", Uuid::new_v4()));

    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(&bytes)?;
        file.flush()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(_) => {
            // remove ONLY the unique temp path this function just created;
            // the final path was never touched, so a failed replacement can
            // never destroy the previously live record.
            let _ = fs::remove_file(&tmp);
            Err(CredentialError::Storage)
        }
    }
}

/// Reads and fully validates a record: JSON shape, schema v1, canonical
/// agent id, id/path agreement, and Argon2id PHC parseability. Anything
/// less is corruption → None (fail closed).
fn load_record(dir: &Path, id: &Uuid) -> Option<CredentialRecord> {
    let bytes = fs::read(credential_path(dir, id)).ok()?;
    let record: CredentialRecord = serde_json::from_slice(&bytes).ok()?;
    if record.schema_version != CREDENTIAL_SCHEMA_VERSION {
        return None;
    }
    if parse_canonical_agent_id(&record.agent_id)? != *id {
        return None; // planted/mismatched record — deny
    }
    let parsed = argon2::password_hash::PasswordHash::new(&record.phc).ok()?;
    if parsed.algorithm.as_str() != "argon2id" {
        return None; // not argon2id — never accept foreign hashes
    }
    Some(record)
}

fn agent_record_exists(agents_dir: &Path, id: &Uuid) -> bool {
    // minimal, read-only existence gate against the agent store's shape:
    // schema v1 and self-consistent id. Ownership is enforced by the API
    // choke point; this module never opens any other store.
    #[derive(Deserialize)]
    struct AgentStub {
        schema_version: u32,
        agent_id: String,
    }
    match fs::read(agents_dir.join(format!("{id}.json"))) {
        Ok(bytes) => match serde_json::from_slice::<AgentStub>(&bytes) {
            Ok(stub) => {
                stub.schema_version == 1
                    && parse_canonical_agent_id(&stub.agent_id).as_ref() == Some(id)
            }
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn ensure_dir(dir: &Path) -> Result<(), CredentialError> {
    fs::create_dir_all(dir).map_err(|_| CredentialError::Storage)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// The ONE Argon2 configuration used by this module: Argon2id v0x13 with
/// library-safe default parameters. No SHA-256, no fast hashes, no
/// hand-rolled KDF — hashing and verification are pure argon2-c rates.
fn argon2id() -> argon2::Argon2<'static> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
}

/// Hash a fresh credential with a fresh random salt; returns
/// (phc-string-to-store, one-time credential hex). The credential bytes are
/// dropped after this call — only the PHC is ever persisted.
fn mint_credential() -> Result<(String, String), CredentialError> {
    use argon2::PasswordHasher;
    use argon2::password_hash::{Salt, SaltString};
    let mut secret = [0u8; CREDENTIAL_BYTES];
    if !fill_random(&mut secret) {
        return Err(CredentialError::Storage);
    }
    let mut salt = [0u8; SALT_BYTES];
    if !fill_random(&mut salt) {
        return Err(CredentialError::Storage);
    }
    // PHC carries the salt B64-encoded: encode the fresh random bytes and
    // validate them through the password-hash Salt type.
    let salt_string = SaltString::encode_b64(&salt).map_err(|_| CredentialError::Storage)?;
    let argon2 = argon2id();
    let phc = argon2
        .hash_password(
            &secret,
            Salt::from_b64(salt_string.as_str()).map_err(|_| CredentialError::Storage)?,
        )
        .map_err(|_| CredentialError::Storage)?
        .to_string();
    Ok((phc, hex_encode(&secret)))
}

fn verify_against_phc(secret: &[u8], phc: &str) -> bool {
    use argon2::PasswordVerifier;
    match argon2::password_hash::PasswordHash::new(phc) {
        Ok(parsed) => argon2id().verify_password(secret, &parsed).is_ok(),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Directory-parameterized core (tests run against temp stores ONLY; the
// production wrappers below are the only code that names artifact/)
// ---------------------------------------------------------------------------

pub(crate) fn issue_in(
    agents_dir: &Path,
    creds_dir: &Path,
    agent_id: &str,
    now: i64,
) -> Result<String, CredentialError> {
    let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
    if !agent_record_exists(agents_dir, &id) {
        return Err(CredentialError::InvalidAgent);
    }
    if load_record(creds_dir, &id).is_some() || credential_path(creds_dir, &id).exists() {
        // a live OR a corrupt record for this agent blocks re-issue;
        // rotate/revoke are the explicit paths. Revoked records stay
        // revoked: no silent re-issue over them.
        return Err(CredentialError::RecordUnavailable);
    }
    let (phc, credential) = mint_credential()?;
    ensure_dir(creds_dir)?;
    let record = CredentialRecord {
        schema_version: CREDENTIAL_SCHEMA_VERSION,
        agent_id: id.to_string(),
        phc,
        created_at: now,
        updated_at: now,
        revoked_at: None,
        expires_at: None,
    };
    write_record_atomic(&credential_path(creds_dir, &id), &record)?;
    Ok(credential) // returned once; never stored anywhere in this process
}

pub(crate) fn rotate_in(
    agents_dir: &Path,
    creds_dir: &Path,
    agent_id: &str,
    now: i64,
) -> Result<String, CredentialError> {
    let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
    if !agent_record_exists(agents_dir, &id) {
        return Err(CredentialError::InvalidAgent);
    }
    let existing = load_record(creds_dir, &id).ok_or(CredentialError::RecordUnavailable)?;
    if existing.revoked_at.is_some() {
        return Err(CredentialError::RecordUnavailable);
    }
    let (phc, credential) = mint_credential()?;
    // atomic replacement: the previous record remains fully intact until
    // the rename; there is NO delete-first window.
    let replacement = CredentialRecord {
        schema_version: CREDENTIAL_SCHEMA_VERSION,
        agent_id: id.to_string(),
        phc,
        created_at: existing.created_at, // issue-time preserved for audit
        updated_at: now,
        revoked_at: None,
        expires_at: None,
    };
    write_record_atomic(&credential_path(creds_dir, &id), &replacement)?;
    Ok(credential)
}

pub(crate) fn revoke_in(
    agents_dir: &Path,
    creds_dir: &Path,
    agent_id: &str,
    now: i64,
) -> Result<(), CredentialError> {
    let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
    if !agent_record_exists(agents_dir, &id) {
        return Err(CredentialError::InvalidAgent);
    }
    let mut existing = load_record(creds_dir, &id).ok_or(CredentialError::RecordUnavailable)?;
    if existing.revoked_at.is_some() {
        return Ok(()); // already revoked: idempotent, record preserved
    }
    existing.revoked_at = Some(now);
    existing.updated_at = now;
    // the record is RETAINED — revoke writes revoked_at onto the same
    // path atomically; nothing is deleted.
    write_record_atomic(&credential_path(creds_dir, &id), &existing)
}

/// Authentication from DISK ONLY. Every failure mode — malformed input,
/// unknown credential, corrupt record, revoked record, foreign hash tag —
/// yields the identical `AuthenticationFailed`. Successful authentication
/// returns the canonical agent id. There is no process-memory state
/// consulted or required.
pub(crate) fn authenticate_in(creds_dir: &Path, credential: &str) -> Result<Uuid, CredentialError> {
    let secret = hex_decode(credential).ok_or(CredentialError::AuthenticationFailed)?;
    if secret.len() != CREDENTIAL_BYTES {
        return Err(CredentialError::AuthenticationFailed);
    }
    let entries: Vec<fs::DirEntry> = match fs::read_dir(creds_dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(_) => return Err(CredentialError::AuthenticationFailed), // no store = no match
    };
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(id) = parse_canonical_agent_id(name) else {
            continue; // non-agent-shaped filenames are ignored, never errors
        };
        // The revoked flag lives on the validated record; load_record enforces
        // schema/id/PHC integrity. A revoked record is simply not an
        // authenticatable one — indistinguishable from any other denial.
        let Some(record) = load_record(creds_dir, &id) else {
            continue;
        };
        if record.revoked_at.is_some() {
            continue;
        }
        // PHASE 9 TTL mechanism (policy-neutral): an expired credential can
        // never authenticate — fail-closed, indistinguishable from any
        // other denial (no state enumeration). `None` = no expiry, the
        // current policy state (no TTL value decided yet).
        if let Some(expires_at) = record.expires_at {
            if now_unix() >= expires_at {
                continue;
            }
        }
        if verify_against_phc(&secret, &record.phc) {
            return Ok(id);
        }
    }
    Err(CredentialError::AuthenticationFailed)
}

// ---------------------------------------------------------------------------
// Public API — the four calls the next integration step will use.
// Thin wrappers binding the production stores:
//   artifact/agents (read-only existence gate)
//   artifact/agent_credentials/<canonical-agent-uuid>.json
//
// GATE 2 STEP 1 — storage-mode dispatch: when pg_is_authoritative() the
// credential authority IS PostgreSQL (the FS paths are NEVER touched — no
// dual-write, the established single-authority rule). Filesystem mode is
// byte-identical legacy behavior. In PG mode the agent-existence gate reads
// the authoritative `agents` table instead of the FS metadata record (the
// same shape check: schema v1 + self-consistent id, which is what the
// importer wrote). Every DB error fails closed with the module's own
// stable error vocabulary — never a silent FS fallback.
// ---------------------------------------------------------------------------

pub fn production_agents_dir() -> PathBuf {
    Path::new("artifact").join("agents")
}

pub fn production_credentials_dir() -> PathBuf {
    Path::new("artifact").join("agent_credentials")
}

/// The agent-existence gate in PG mode: reads the authoritative `agents`
/// table (same minimal shape check the FS stub performs — schema v1 and a
/// self-consistent canonical id). A DB error is fail-closed (invalid).
fn pg_agent_record_exists(id: Uuid) -> bool {
    // Sync dispatch from the caller's spawn_blocking context (the same
    // established pattern the payment cores use). Fail closed: any error
    // (mode mismatch, DB failure) reads as "not a valid agent".
    matches!(
        crate::pg_store::pg_run(crate::pg_store::pg_agent_record_exists_dispatch(id)),
        Ok(Ok(true))
    )
}

/// Issue the credential for an existing Agent. The credential hex is
/// returned exactly once and never persisted or logged. Re-issue onto an
/// existing record is refused (use rotate).
pub fn issue_credential(agent_id: &str) -> Result<String, CredentialError> {
    if crate::pg_store::pg_is_authoritative() {
        let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
        if !pg_agent_record_exists(id) {
            return Err(CredentialError::InvalidAgent);
        }
        let (phc, credential) = mint_credential()?;
        match crate::pg_store::pg_run(crate::pg_store::credential_issue_dispatch(
            id,
            phc,
            now_unix(),
        )) {
            Ok(Ok(true)) => Ok(credential),
            Ok(Ok(false)) => Err(CredentialError::RecordUnavailable),
            _ => Err(CredentialError::Storage),
        }
    } else {
        issue_in(
            &production_agents_dir(),
            &production_credentials_dir(),
            agent_id,
            now_unix(),
        )
    }
}

/// Atomically replace the live credential. The old credential stops
/// authenticating at the rename (FS) / commit (PG); there is never a
/// delete-first window. Revoked credentials cannot be rotated.
pub fn rotate_credential(agent_id: &str) -> Result<String, CredentialError> {
    if crate::pg_store::pg_is_authoritative() {
        let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
        if !pg_agent_record_exists(id) {
            return Err(CredentialError::InvalidAgent);
        }
        let (phc, credential) = mint_credential()?;
        match crate::pg_store::pg_run(crate::pg_store::credential_rotate_dispatch(
            id,
            phc,
            now_unix(),
        )) {
            Ok(Ok(true)) => Ok(credential),
            Ok(Ok(false)) => Err(CredentialError::RecordUnavailable),
            _ => Err(CredentialError::Storage),
        }
    } else {
        rotate_in(
            &production_agents_dir(),
            &production_credentials_dir(),
            agent_id,
            now_unix(),
        )
    }
}

/// Revoke: the record is PRESERVED with revoked_at stamped; authentication
/// then denies it forever and rotation is closed. Idempotent in both modes.
pub fn revoke_credential(agent_id: &str) -> Result<(), CredentialError> {
    if crate::pg_store::pg_is_authoritative() {
        let id = parse_canonical_agent_id(agent_id).ok_or(CredentialError::InvalidAgent)?;
        if !pg_agent_record_exists(id) {
            return Err(CredentialError::InvalidAgent);
        }
        match crate::pg_store::pg_run(crate::pg_store::credential_revoke_dispatch(id, now_unix())) {
            Ok(Ok(true)) => Ok(()), // freshly stamped OR already revoked (idempotent)
            Ok(Ok(false)) => Err(CredentialError::RecordUnavailable),
            _ => Err(CredentialError::Storage),
        }
    } else {
        revoke_in(
            &production_agents_dir(),
            &production_credentials_dir(),
            agent_id,
            now_unix(),
        )
    }
}

/// Authenticate a presented credential against the AUTHORITATIVE store.
/// Returns the canonical agent id on success; one stable denial otherwise.
/// PG mode scans the authoritative rows and verifies the PHC with the SAME
/// pure argon2 verification; every failure is the identical
/// `AuthenticationFailed` — the store kind is never observable.
pub fn authenticate_agent_credential(credential: &str) -> Result<Uuid, CredentialError> {
    if crate::pg_store::pg_is_authoritative() {
        let secret = match hex_decode(credential) {
            Some(s) if s.len() == CREDENTIAL_BYTES => s,
            _ => return Err(CredentialError::AuthenticationFailed),
        };
        let now = now_unix();
        let candidates =
            match crate::pg_store::pg_run(crate::pg_store::credential_authenticate_dispatch()) {
                Ok(Ok(rows)) => rows,
                // a DB failure is fail-closed: the same denial as any other —
                // never a silent FS fallback (an ambiguous authority is never
                // acceptable on an identity plane).
                _ => return Err(CredentialError::AuthenticationFailed),
            };
        for (id, phc) in candidates {
            if verify_against_phc(&secret, &phc) {
                return Ok(id);
            }
        }
        Err(CredentialError::AuthenticationFailed)
    } else {
        authenticate_in(&production_credentials_dir(), credential)
    }
}

// ---------------------------------------------------------------------------
// TEST-ONLY seams (never called from production): the pg_store tests need the
// module's OWN minting/verification primitives so the PG path is exercised
// against the exact same Argon2id PHC the FS path produces.
// ---------------------------------------------------------------------------

/// (test-only) mint a credential exactly as issue does; returns
/// (phc, one-time hex).
#[cfg(test)]
pub fn pg_test_mint_credential_for_tests() -> Result<(String, String), CredentialError> {
    mint_credential()
}

/// (test-only) verify a secret against a PHC with the module's pure verifier.
#[cfg(test)]
pub fn pg_test_verify_for_tests(secret: &[u8], phc: &str) -> bool {
    verify_against_phc(secret, phc)
}

// ---------------------------------------------------------------------------
// Tests — every case runs against a fresh temp dir under
// std::env::temp_dir(). The production artifact/ tree is NEVER opened by
// any test, so no real credential is ever created, and nothing here ever
// touches any store outside the temp tree.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod credential_tests {
    use super::*;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("agentpay-creds-{}", Uuid::new_v4()))
    }

    fn write_agent(agents_dir: &Path, id: &Uuid) {
        fs::create_dir_all(agents_dir).unwrap();
        // minimal agent record matching the real store shape; the module
        // only ever checks schema + id self-consistency.
        fs::write(
            agents_dir.join(format!("{id}.json")),
            serde_json::json!({
                "schema_version": 1,
                "agent_id": id.to_string(),
                "owner_user_id": 7,
                "name": "CredTest",
                "status": "draft",
                "created_at": 0,
                "updated_at": 0,
            })
            .to_string(),
        )
        .unwrap();
    }

    struct Fix {
        root: PathBuf,
        agents: PathBuf,
        creds: PathBuf,
        id: Uuid,
    }

    fn fixture() -> Fix {
        let root = temp_root();
        let agents = root.join("agents");
        let creds = root.join("agent_credentials");
        let id = Uuid::new_v4();
        write_agent(&agents, &id);
        Fix {
            root,
            agents,
            creds,
            id,
        }
    }

    impl Fix {
        fn cleanup(&self) {
            // restore writability if a test chmod-ed the store, then remove
            // ONLY this fixture's own unique temp subtree (no recursive
            // deletion of anything else).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.creds, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_dir_all(&self.root);
        }
        fn record_raw(&self) -> String {
            fs::read_to_string(credential_path(&self.creds, &self.id)).unwrap()
        }
        fn tmp_leftovers(&self) -> Vec<String> {
            fs::read_dir(&self.creds)
                .map(|it| {
                    it.flatten()
                        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    impl Drop for Fix {
        fn drop(&mut self) {
            // panic-safe fixture teardown: if an assert fails mid-test the
            // temp tree still goes away — never leaks fixtures into /tmp.
            // ONLY ever this fixture's own unique root directory.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.creds, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    const NOW: i64 = 1_790_649_600; // 2026-09-29 ~04:00 UTC

    // (1) issue + authenticate round trip, and the record is a real
    // argon2id PHC — never a fast hash
    #[test]
    fn issue_then_authenticates_with_argon2id_phc() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        assert_eq!(credential.len(), 64);
        assert!(hex_decode(&credential).is_some());

        let authed = authenticate_in(&f.creds, &credential).unwrap();
        assert_eq!(authed, f.id);

        let record: CredentialRecord = serde_json::from_str(&f.record_raw()).unwrap();
        assert!(
            record.phc.starts_with("$argon2id$v=19$"),
            "PHC must be argon2id v0x13"
        );
        assert_eq!(record.schema_version, CREDENTIAL_SCHEMA_VERSION);
        assert_eq!(record.created_at, NOW);
        assert_eq!(record.revoked_at, None);
        f.cleanup();
    }

    // (2) wrong credential rejected — with the SAME stable error as an
    // unknown one (no enumeration)
    #[test]
    fn wrong_credential_is_stably_denied() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        let wrong = {
            let mut b = hex_decode(&credential).unwrap();
            b[0] ^= 0x01;
            hex_encode(&b)
        };
        let err_wrong = authenticate_in(&f.creds, &wrong).unwrap_err();
        let err_unknown =
            authenticate_in(&f.creds, &hex_encode(&[9u8; CREDENTIAL_BYTES])).unwrap_err();
        let err_nonexistent_store = authenticate_in(&f.root.join("nothing"), "00").unwrap_err();
        assert_eq!(err_wrong, CredentialError::AuthenticationFailed);
        assert_eq!(err_wrong, err_unknown);
        assert_eq!(err_wrong, err_nonexistent_store);
        assert_eq!(err_wrong, err_nonexistent_store);
        f.cleanup();
    }

    // (3) revoke: record PRESERVED with revoked_at; authentication denies
    #[test]
    fn revoke_preserves_record_and_denies_auth() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        revoke_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 5).unwrap();

        assert!(credential_path(&f.creds, &f.id).exists(), "record kept");
        let record: CredentialRecord = serde_json::from_str(&f.record_raw()).unwrap();
        assert_eq!(record.revoked_at, Some(NOW + 5));
        assert_eq!(record.created_at, NOW);
        // the original phc is untouched by revoke
        assert!(record.phc.starts_with("$argon2id$"));

        assert_eq!(
            authenticate_in(&f.creds, &credential).unwrap_err(),
            CredentialError::AuthenticationFailed
        );
        // revoked cannot rotate, and cannot re-issue
        assert_eq!(
            rotate_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 6).unwrap_err(),
            CredentialError::RecordUnavailable
        );
        assert_eq!(
            issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 6).unwrap_err(),
            CredentialError::RecordUnavailable
        );
        // revoke is idempotent and preserves the FIRST revoked_at
        revoke_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 9).unwrap();
        let record2: CredentialRecord = serde_json::from_str(&f.record_raw()).unwrap();
        assert_eq!(record2.revoked_at, Some(NOW + 5));
        f.cleanup();
    }

    // (4) rotate: old denied, new accepted, single record, created_at kept
    #[test]
    fn rotate_replaces_atomically_and_invalidates_old() {
        let f = fixture();
        let old = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        let new = rotate_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 7).unwrap();
        assert_ne!(old, new);
        assert_eq!(
            authenticate_in(&f.creds, &old).unwrap_err(),
            CredentialError::AuthenticationFailed
        );
        assert_eq!(authenticate_in(&f.creds, &new).unwrap(), f.id);

        let record: CredentialRecord = serde_json::from_str(&f.record_raw()).unwrap();
        assert_eq!(record.created_at, NOW, "issue time preserved");
        assert_eq!(record.updated_at, NOW + 7);
        assert_eq!(record.revoked_at, None);

        let files: Vec<_> = fs::read_dir(&f.creds)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        assert_eq!(files.len(), 1, "rotate replaces, never adds");
        f.cleanup();
    }

    // (5) restart simulation: the DISK is the authority. authenticate_in
    // reads only files; nothing process-local exists to lose.
    #[test]
    fn restart_simulation_disk_is_authority() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        // "new process": a fresh call chain with zero carried state
        let fresh_auth = authenticate_in(&f.creds, &credential);
        assert_eq!(fresh_auth.unwrap(), f.id);
        // and the record alone is sufficient to re-verify
        let record: CredentialRecord = serde_json::from_str(&f.record_raw()).unwrap();
        assert!(verify_against_phc(
            &hex_decode(&credential).unwrap(),
            &record.phc
        ));
        f.cleanup();
    }

    // (6) fail-closed table: malformed JSON, wrong schema, malformed PHC,
    // mismatched id, foreign hash algorithm — every one denies, and the
    // auth denial is always the SAME value
    #[test]
    fn fail_closed_on_every_corrupt_record_shape() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        let path = credential_path(&f.creds, &f.id);

        let corruptions: Vec<String> = vec![
            "{ this is not json".into(),
            serde_json::json!({"no": "fields"}).to_string(),
            serde_json::json!({
                "schema_version": 99,
                "agent_id": f.id.to_string(),
                "phc": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$abcdef",
                "created_at": NOW, "updated_at": NOW, "revoked_at": null
            })
            .to_string(),
            serde_json::json!({
                "schema_version": CREDENTIAL_SCHEMA_VERSION,
                "agent_id": f.id.to_string(),
                "phc": "sha256-not-a-phc-string",
                "created_at": NOW, "updated_at": NOW, "revoked_at": null
            })
            .to_string(),
            serde_json::json!({
                "schema_version": CREDENTIAL_SCHEMA_VERSION,
                "agent_id": f.id.to_string(),
                "phc": "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$YWJjZGVm",
                "created_at": NOW, "updated_at": NOW, "revoked_at": null
            })
            .to_string(), // argon2i, not argon2id
            serde_json::json!({
                "schema_version": CREDENTIAL_SCHEMA_VERSION,
                "agent_id": Uuid::new_v4().to_string(),
                "phc": "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$abcdef",
                "created_at": NOW, "updated_at": NOW, "revoked_at": null
            })
            .to_string(), // planted foreign agent_id inside the record
        ];
        for corrupt in corruptions {
            fs::write(&path, corrupt).unwrap();
            assert_eq!(
                authenticate_in(&f.creds, &credential).unwrap_err(),
                CredentialError::AuthenticationFailed,
                "corrupt record must deny auth identically"
            );
            assert!(load_record(&f.creds, &f.id).is_none(), "must not load");
            assert_eq!(
                rotate_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap_err(),
                CredentialError::RecordUnavailable
            );
            assert_eq!(
                revoke_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap_err(),
                CredentialError::RecordUnavailable
            );
        }
        f.cleanup();
    }

    // (7) the plaintext credential NEVER appears in the persisted record
    #[test]
    fn plaintext_never_persisted() {
        let f = fixture();
        let credential = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        let raw = f.record_raw();
        assert!(!raw.contains(&credential), "plaintext leaked to disk");
        assert!(!raw.contains(&credential.to_uppercase()));
        let decoded = hex_decode(&credential).unwrap();
        for field in [
            &decoded[0..8],
            &decoded[8..16],
            &decoded[16..24],
            &decoded[24..32],
        ] {
            assert!(
                !raw.contains(&hex_encode(field)),
                "credential fragment leaked"
            );
        }
        // and nothing secret is reachable from the record struct's Debug
        let record: CredentialRecord = serde_json::from_str(&raw).unwrap();
        let dbg = format!("{record:?}");
        assert!(!dbg.contains(&credential));
        f.cleanup();
    }

    // (8) permissions: record 0600, store dir 0700
    #[test]
    fn persisted_modes_are_owner_only() {
        let f = fixture();
        issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = fs::metadata(credential_path(&f.creds, &f.id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let dir_mode = fs::metadata(&f.creds).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600, "record must be owner rw only");
            assert_eq!(dir_mode, 0o700, "credential dir must be owner-only");
        }
        f.cleanup();
    }

    // (9) atomic persistence leaves no temp debris — including on the
    // failure path (unwritable store)
    #[test]
    fn atomic_write_leaves_no_temp_files() {
        let f = fixture();
        issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        rotate_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 1).unwrap();
        revoke_in(&f.agents, &f.creds, &f.id.to_string(), NOW + 2).unwrap();
        assert!(f.tmp_leftovers().is_empty(), "no .tmp after success");

        // deterministic failure path that needs no filesystem-quirk
        // assumptions: the destination exists as a DIRECTORY, so the atomic
        // rename fails (EISDIR) AFTER the temp file was created — the
        // writer must clean up its own temp and report Storage
        let rogue = credential_path(&f.creds, &Uuid::new_v4());
        fs::create_dir(&rogue).unwrap();
        let record = CredentialRecord {
            schema_version: CREDENTIAL_SCHEMA_VERSION,
            agent_id: f.id.to_string(),
            phc: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$ZGVhZGJlZWY".into(),
            created_at: NOW,
            updated_at: NOW,
            revoked_at: None,
            expires_at: None,
        };
        let err = write_record_atomic(&rogue, &record).unwrap_err();
        assert_eq!(err, CredentialError::Storage);
        assert!(
            f.tmp_leftovers().is_empty(),
            "failed rename must clean up its temp file"
        );
        assert!(
            fs::metadata(&rogue).map(|m| m.is_dir()).unwrap_or(false),
            "the failed replacement must not have overwritten the path"
        );
        f.cleanup();
    }

    // (10) nonexistent / malformed / foreign-ish agents are refused before
    // any credential state is created
    #[test]
    fn issue_requires_a_real_canonical_agent() {
        let f = fixture();
        // agent id that has no record
        let ghost = Uuid::new_v4();
        assert_eq!(
            issue_in(&f.agents, &f.creds, &ghost.to_string(), NOW).unwrap_err(),
            CredentialError::InvalidAgent
        );
        assert!(!f.creds.join(format!("{ghost}.json")).exists());

        // non-canonical spellings never reach path construction
        let bad_ids: Vec<String> = vec![
            "not-an-uuid".into(),
            "".into(),
            format!("{{{}}}", f.id.to_string().to_uppercase()),
            f.id.to_string().to_uppercase(),
            "../evil".into(),
        ];
        for bad in bad_ids {
            assert_eq!(
                issue_in(&f.agents, &f.creds, &bad, NOW).unwrap_err(),
                CredentialError::InvalidAgent,
                "accepted malformed id: {bad:?}"
            );
        }

        // agent record with mismatched self-id = corrupt = deny
        let corrupt_root = temp_root();
        let corrupt_agents = corrupt_root.join("agents");
        fs::create_dir_all(&corrupt_agents).unwrap();
        let other = Uuid::new_v4();
        fs::write(
            corrupt_agents.join(format!("{other}.json")),
            format!(
                "{{\"schema_version\":1,\"agent_id\":\"{}\"}}",
                Uuid::new_v4()
            ),
        )
        .unwrap();
        assert!(!agent_record_exists(&corrupt_agents, &other));
        let _ = fs::remove_dir_all(&corrupt_root);
        f.cleanup();
    }

    // (11) different agents authenticate independently; a credential for A
    // NEVER maps to B
    #[test]
    fn credentials_are_per_agent() {
        let f = fixture();
        let id_b = Uuid::new_v4();
        write_agent(&f.agents, &id_b);
        let cred_a = issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        let cred_b = issue_in(&f.agents, &f.creds, &id_b.to_string(), NOW).unwrap();
        assert_eq!(authenticate_in(&f.creds, &cred_a).unwrap(), f.id);
        assert_eq!(authenticate_in(&f.creds, &cred_b).unwrap(), id_b);
        f.cleanup();
    }

    // (12) structural purity: this module contains no access to the user
    // store, any key material, chain state, or endpoints — by source
    // inspection
    #[test]
    fn source_purity_by_inspection() {
        let src = include_str!("./agent_credentials.rs");
        // scan the PRODUCTION section only (before #[cfg(test)]) — the test
        // module legitimately contains the forbidden literals as fixtures;
        // then strip comments so prose cannot false-flag
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("test section anchor");
        let code: String = {
            let mut out = String::with_capacity(production.len());
            for line in production.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                out.push_str(line);
                out.push('\n');
            }
            out
        };
        for forbidden in [
            "wallet",
            "Wallet",
            "keypair",
            "Keypair",
            "rialo",
            "Rialo",
            "transfer",
            "faucet",
            "airdrop",
            "axum",
            "HeaderMap",
            "session",
            "argon2::argon2_data_hash",
            "sha2",
            "Sha256",
            "pbkdf2",
            "scrypt",
            "bcrypt",
            "md5",
            "HashMap<Uuid, Credential>",
            "chrono",
            "std::process",
            "Command",
            "reqwest",
        ] {
            assert!(
                !code.contains(forbidden),
                "credential module references forbidden token: {forbidden}"
            );
        }
        // the hashing path is argon2id only
        assert!(code.contains("Algorithm::Argon2id"));
        assert!(code.contains("Version::V0x13"));
    }

    // (13) issue into a fresh dir creates the store with safe modes
    #[test]
    fn store_is_created_lazily_and_privately() {
        let f = fixture();
        assert!(!f.creds.exists());
        issue_in(&f.agents, &f.creds, &f.id.to_string(), NOW).unwrap();
        assert!(f.creds.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&f.creds).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        f.cleanup();
    }
}
