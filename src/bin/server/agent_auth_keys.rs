//! agent_auth_keys — PHASE 9 I-1 (capability C-1): the funds-less
//! per-agent AUTHENTICATION keypair vault.
//!
//! What this module IS (I-0 §5.2 scope, verbatim): the durable store
//! asset for a second, strictly identity-only ed25519 keypair per agent.
//! The key carries NO funds and has NO funding path — it is not a
//! wallet, never a `rialo_tx_signers` money signer, and never appears
//! in any payment or transfer path. Its only job is to be the
//! funds-less, revocable identity handle that later Latch lanes enroll
//! in the `rialo_tx_signers` filter (Item 2 D8; storage location
//! ratified as app-side vault by I-0 Q6).
//!
//! Established patterns reused EXACTLY (Phase 5 STEP 3 / durable-store
//! rules): getrandom 32-byte seed → `keypair_from_seed` → `create_new`
//! (O_EXCL: an existing path is refused, never overwritten) → owner-only
//! mode hardened BEFORE content lands → `write_keypair` → only the
//! PUBLIC address ever leaves this module. Directory parameters are
//! always caller-supplied: this module never names `artifact/...` and
//! never hard-codes a store path (same structural contract as
//! `rialo_tx_signers`).
//!
//! What this module is NOT (later items, deliberately absent): no
//! transaction signing and no exposure of any signing operation (I-2+);
//! no Latch transport, no network calls, no routes (I-4); no Privy (the
//! deferred §3 lane); no rotation or revocation machinery (D12 — revoke
//! is a later lifecycle/operator act; this vault only mints and
//! verifies); no backfill of pre-I-1 agent records (their
//! `auth_public_key` stays absent/`None` until an explicitly scoped
//! later act); no key material in return values, Debug output, or logs
//! — by construction there is no code path here that could emit one.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path as FsPath, PathBuf};
use uuid::Uuid;

/// Failures while minting a NEW auth keypair. Fieldless, like every
/// established error enum here: no io detail, no path, no key-adjacent
/// context can ever surface through Debug/Display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyProvisionError {
    /// The target path already exists — refused, never overwritten.
    /// Nothing on disk was touched.
    Exists,
    /// Seed/keypair/file failure — anything this call created was
    /// cleaned up (only its own just-created path).
    Store,
}

/// Deterministic failures of the public-read/verify side. An error here
/// is terminal for the operation; there is no fallback key anywhere.
///
/// Read/verify is consumed by tests today and by the later enrollment /
/// verification steps (I-2/I-3+); same `#[allow(dead_code)]` precedent
/// as `TxSigner::User` in rialo_tx_signers.rs (canonical named surface
/// comes first, callers arrive with the lanes that need them).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyError {
    /// The caller's recorded public identity was blank/unusable.
    /// Nothing was touched on disk.
    InvalidReference,
    /// The auth keypair file does not exist in the supplied directory.
    NotFound,
    /// The file exists but is not openable, or its keypair container
    /// cannot be parsed by the established reader.
    Unavailable,
    /// The keypair at the reference does not belong to the recorded
    /// public identity. The operation MUST abort — switching keys or
    /// accepting the unverified key would be a fallback.
    Mismatch,
}

/// `<dir>/<canonical-uuid>.json` — the filename is ALWAYS the
/// server-minted agent UUID (typed `Uuid`, so no client string can
/// shape a path; same construction as `agent_wallet_path`).
pub fn auth_key_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// Collapse non-io failure shapes into one internal error so no detail
/// leaks (mirrors agents.rs `io_other`).
fn io_other(err: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{err:?}"))
}

/// Mint a NEW funds-less authentication keypair for this agent id only.
/// Strictly create-new (`O_EXCL`): an existing path is refused with
/// `Exists` and left byte-identical. On any failure the only file ever
/// removed is the one this call just created. Returns ONLY the public
/// address; the private half never leaves the file.
pub fn provision_agent_auth_key(dir: &FsPath, id: &Uuid) -> Result<String, AuthKeyProvisionError> {
    let path = auth_key_path(dir, id);
    let now = crate::pg_store::pg_now_unix_for_auth_keys();

    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        return Err(AuthKeyProvisionError::Store);
    }

    let Ok(keypair) = rialo_s_keypair::keypair_from_seed(&seed) else {
        return Err(AuthKeyProvisionError::Store);
    };

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(ref err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AuthKeyProvisionError::Exists);
        }
        Err(_) => return Err(AuthKeyProvisionError::Store),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Hardening BEFORE content lands (established wallet pattern).
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    let written = rialo_s_keypair::write_keypair(&keypair, &mut file)
        .map_err(io_other)
        .and_then(|_| file.flush().map_err(io_other));

    drop(file);

    if written.is_err() {
        // We created this exact path under O_EXCL, so removing it can
        // only ever delete our own half-written file.
        let _ = fs::remove_file(&path);
        return Err(AuthKeyProvisionError::Store);
    }

    // Only the PUBLIC address is ever returned.
    if crate::pg_store::pg_is_authoritative() {
        // PG IS the authority for the PUBLIC identity: commit the row. The
        // private half stays in the local file (never enters PG). An
        // existing row is a refusal (the O_EXCL semantics); a DB error is
        // fail-closed Store (the file this call created is removed).
        match crate::pg_store::pg_run(crate::pg_store::auth_key_provision_dispatch(
            *id,
            auth_pubkey(&keypair),
            now,
        )) {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                let _ = fs::remove_file(&path);
                return Err(AuthKeyProvisionError::Exists);
            }
            _ => {
                let _ = fs::remove_file(&path);
                return Err(AuthKeyProvisionError::Store);
            }
        }
    }
    Ok(auth_pubkey(&keypair))
}

/// Read the vault file and return ONLY its public address (PHASE 9
/// I-6): the read goes through the shared strict pubkey-only reader
/// [`super::rialo_tx_signers::read_pubkey_address_only`], so the vault
/// file's PRIVATE half is never materialized here — no `SigningKey`,
/// no `Keypair` is constructed just to expose a public identity.
/// Nothing is ever logged or persisted by this function.
#[allow(dead_code)] // see AuthKeyError's note (non-test builds)
pub fn read_auth_public_key(dir: &FsPath, id: &Uuid) -> Result<String, AuthKeyError> {
    if crate::pg_store::pg_is_authoritative() {
        // PG IS the authority for the PUBLIC identity. NotFound maps to the
        // same typed error; any DB error is fail-closed Unavailable (never
        // a silent FS fallback).
        return match crate::pg_store::pg_run(crate::pg_store::auth_key_read_dispatch(*id)) {
            Ok(Ok(Some(pk))) => Ok(pk),
            Ok(Ok(None)) => Err(AuthKeyError::NotFound),
            _ => Err(AuthKeyError::Unavailable),
        };
    }
    let path = auth_key_path(dir, id);
    let mut file = match fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(AuthKeyError::NotFound),
        Err(_) => return Err(AuthKeyError::Unavailable),
    };
    super::rialo_tx_signers::read_pubkey_address_only(&mut file)
        .map_err(|_| AuthKeyError::Unavailable)
}

/// PHASE 9 isolated-signer lane (STEP 7): load the FULL funds-less auth
/// keypair so the app — acting as the agent's runtime — can mint the
/// off-chain approval signature the signer verifies. The key is FUNDS-LESS
/// (identity only): loading it materializes NO funded key material and
/// grants NO spend authority. This is the documented two-key model (the
/// auth key proves who is asking; the signer holds the funded key).
/// The read is strict: only the canonical 64-byte container parses.
#[allow(dead_code)] // consumed by the isolated-signer lane (non-test builds)
pub fn read_auth_keypair_full(
    dir: &FsPath,
    id: &Uuid,
) -> Result<rialo_s_keypair::Keypair, AuthKeyError> {
    let path = auth_key_path(dir, id);
    let bytes = fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AuthKeyError::NotFound
        } else {
            AuthKeyError::Unavailable
        }
    })?;
    let arr: Vec<u8> = serde_json::from_slice(&bytes).map_err(|_| AuthKeyError::Unavailable)?;
    if arr.len() != 64 {
        return Err(AuthKeyError::Unavailable);
    }
    rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|_| AuthKeyError::Unavailable)
}

/// Hard, deterministic record↔vault verification: the auth public key
/// persisted on the agent record MUST be provably the public half of
/// the vault file for the same canonical agent id. Outcomes are
/// explicit; a `Mismatch` aborts and mutates nothing.
#[allow(dead_code)] // see AuthKeyError's note (non-test builds)
pub fn verify_auth_public_address(
    dir: &FsPath,
    id: &Uuid,
    expected: &str,
) -> Result<(), AuthKeyError> {
    if expected.trim().is_empty() {
        return Err(AuthKeyError::InvalidReference);
    }
    match read_auth_public_key(dir, id) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(_) => Err(AuthKeyError::Mismatch),
        Err(e) => Err(e),
    }
}

/// `rialo_s_signer::Signer::pubkey()` surfaced through a tiny free
/// function so the trait import stays local to this vault (mirrors the
/// established pattern in rialo_tx_signers.rs). Used ONLY by the
/// minting path (`provision_agent_auth_key`), where constructing the
/// full keypair is required by creation itself; the read/verify path
/// uses the shared pubkey-only reader instead (PHASE 9 I-6).
fn auth_pubkey(keypair: &rialo_s_keypair::Keypair) -> String {
    use rialo_s_signer::Signer;
    keypair.pubkey().to_string()
}

/// Failures while ROTATING an auth keypair. Fieldless: no path, no key
/// material, no io detail can ever surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKeyRotateError {
    /// the sidecar could not be minted/validated (io/seed/parse) — only
    /// the just-created sidecar was ever touched; the canonical key and
    /// the agent record are untouched
    Store,
}

/// The unique sidecar filename for one rotation attempt:
/// `<canonical-uuid>.rotate-<hex>.json`. Never the canonical path (a
/// partially-written sidecar can NEVER become authoritative — promotion
/// happens only by a single atomic rename AFTER the record switched).
fn rotation_sidecar_path(dir: &FsPath, id: &Uuid, generation: &str) -> PathBuf {
    dir.join(format!("{id}.rotate-{generation}.json"))
}

/// PHASE 9 "Key rotation / lifecycle" — mint + VALIDATE a genuinely new
/// funds-less authentication keypair for this agent WITHOUT touching the
/// authoritative current key. Step 1-2 of the mandated ordering:
///
///   new key creation -> new key validation
///   -> authoritative record switch (caller)
///   -> old key becomes non-authoritative (promotion, caller)
///
/// The sidecar is created with EXCLUSIVE creation semantics (O_EXCL),
/// hardened to 0600 BEFORE any content lands, fully written and flushed,
/// and validated through the strict pubkey-only reader (no private half
/// is ever materialized to validate — the freshly minted public address
/// is compared against the file's own public identity). Any failure
/// removes ONLY the sidecar this call created; the canonical key file and
/// the agent record are byte-identical to before (nothing half-rotated).
/// Returns the NEW public address (public half only) and the generation token
/// token for the promotion step.
pub fn mint_rotated_auth_key(
    dir: &FsPath,
    id: &Uuid,
) -> Result<(String, String), AuthKeyRotateError> {
    use rialo_s_signer::Signer;

    let generation = Uuid::new_v4().simple().to_string();
    let path = rotation_sidecar_path(dir, id, &generation);

    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        return Err(AuthKeyRotateError::Store);
    }
    let Ok(keypair) = rialo_s_keypair::keypair_from_seed(&seed) else {
        return Err(AuthKeyRotateError::Store);
    };
    let new_pubkey = auth_pubkey(&keypair);

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => {
            // unique-suffix collision is astronomically improbable, but a
            // refusal is the correct outcome either way (never overwrite)
            return Err(AuthKeyRotateError::Store);
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    let written = rialo_s_keypair::write_keypair(&keypair, &mut file)
        .map_err(|_| AuthKeyRotateError::Store)
        .and_then(|_| file.flush().map_err(|_| AuthKeyRotateError::Store));
    drop(file);
    if written.is_err() {
        // only OUR OWN just-created sidecar may ever be removed
        let _ = fs::remove_file(&path);
        return Err(AuthKeyRotateError::Store);
    }

    // VALIDATE through the established pubkey-only reader: the sidecar's
    // own public identity must equal the freshly minted public address.
    // A keypair file that cannot be parsed, or whose public identity
    // differs, is NEVER allowed near the authoritative record.
    match read_auth_public_key_at(dir, &path) {
        Ok(actual) if actual == new_pubkey => Ok((new_pubkey, generation)),
        _ => {
            let _ = fs::remove_file(&path);
            Err(AuthKeyRotateError::Store)
        }
    }
}

/// The pubkey-only read at an ARBITRARY path (the strict shared reader —
/// no private half is ever materialized). Used ONLY by the rotation
/// mint/validate step; the canonical read path stays
/// `read_auth_public_key`.
fn read_auth_public_key_at(dir: &FsPath, path: &FsPath) -> Result<String, AuthKeyError> {
    let _ = dir;
    let mut file = fs::File::open(path).map_err(|_| AuthKeyError::NotFound)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| AuthKeyError::Unavailable)?;
    super::rialo_tx_signers::read_pubkey_address_only(&mut std::io::Cursor::new(&bytes))
        .map_err(|_| AuthKeyError::Unavailable)
}

/// PHASE 9 rotation step 4: promote the validated sidecar to the
/// authoritative canonical path by ONE atomic rename. After this single
/// operation the OLD key file no longer exists at the canonical path —
/// it can never be authoritative again (no ambiguity, no in-place
/// overwrite: a rename is an atomic replacement, and the old content is
/// gone with it). The caller MUST have switched the authoritative record
/// BEFORE calling this (the mandated ordering), so a crash between the
/// record switch and this rename leaves a fail-closed state (record=new
/// pubkey, canonical file=old key => every verification answers Mismatch
/// until a retry completes the rotation) — never an ambiguous TWO-key
/// acceptance.
pub fn promote_rotated_auth_key(
    dir: &FsPath,
    id: &Uuid,
    generation: &str,
) -> Result<(), std::io::Error> {
    let sidecar = rotation_sidecar_path(dir, id, generation);
    let canonical = auth_key_path(dir, id);
    fs::rename(&sidecar, &canonical)
}

/// Remove a rotation sidecar (cleanup after a failed record switch — only
/// the caller's own sidecar path is ever removed).
pub fn discard_rotated_auth_key(dir: &FsPath, id: &Uuid, generation: &str) {
    let _ = fs::remove_file(rotation_sidecar_path(dir, id, generation));
}

/// (import-only seam, production-reachable) Extract ONLY the public
/// address from a vault container read as raw bytes. Accepts the strict
/// pubkey-only canonical form or the full 64-byte keypair JSON array (the
/// on-disk format `write_keypair` produces); the private half is NEVER
/// returned, logged, or persisted. Used by the PG legacy importer, which
/// must not materialize private key material into any authoritative
/// store. Returns `Err` on any non-canonical shape (fail closed).
pub fn pubkey_from_container_for_import(bytes: &[u8]) -> Result<String, String> {
    // Try the strict pubkey-only reader first (canonical public form).
    if let Ok(pubkey) =
        super::rialo_tx_signers::read_pubkey_address_only(&mut std::io::Cursor::new(bytes))
    {
        return Ok(pubkey);
    }
    // Fall back to the on-disk keypair container (write_keypair format):
    // decode locally and return ONLY the public half.
    let arr: Vec<u8> = serde_json::from_slice(bytes).map_err(|e| format!("parse: {e}"))?;
    if arr.len() != 64 {
        return Err(format!("bad container length {}", arr.len()));
    }
    let keypair = rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|e| format!("parse: {e}"))?;
    use rialo_s_signer::Signer;
    Ok(keypair.pubkey().to_string())
}

/// Test-only helper: mint a fresh keypair and return (public_key, private_bytes).
/// Used by PG store tests to provision auth keys without coupling to the
/// filesystem vault. The private half is returned ONLY so tests can verify
/// public-key derivation matches; it must NOT be stored in PG.
#[cfg(test)]
pub fn pg_test_provision_keypair_for_tests() -> (String, Vec<u8>) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("system RNG");
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).expect("valid seed");
    use rialo_s_signer::Signer;
    let pubkey = keypair.pubkey().to_string();
    let priv_bytes = keypair.to_bytes().to_vec();
    (pubkey, priv_bytes)
}

#[cfg(test)]
#[path = "_authkeys_i1_tests.rs"]
mod authkeys_tests;
