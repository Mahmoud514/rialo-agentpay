//! user_creation_gate — G83-FIX M1/M2: operator registration binding +
//! durable nonce replay protection + durable singleflight for the create
//! path. All state is PERSISTED first (temp+rename under a lock), then
//! reflected in the in-memory index — the same discipline as user_intents.
//!
//! M1 PREREQUISITE MODEL (no self-authentication invented):
//!   The operator registers the binding OUT-OF-BAND during onboarding
//!   (the agent-lane admin-registration precedent):
//!     `AGENTPAY_SIGNER_PROVISION_USERS` = comma-separated
//!     `user_id:auth_pubkey` — the ONLY authoritative source the signer may
//!     consult for a pre-create auth binding. With no binding registered
//!     for a subject, create fails closed (PREREQUISITE_MISSING) and the
//!     operator supplies it. The binding's auth_pubkey is then what the
//!     Ed25519 creation-intent signature is verified AGAINST — a
//!     caller-supplied public key is never trusted as identity proof.

use blake3::Hasher;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use uuid::Uuid;

pub const NONCE_SEEN_DOMAIN: &str = "g81-user-nonce-seen-v1";

fn nonce_id(user_id: u64, nonce: &str) -> String {
    let mut h = Hasher::new();
    h.update(NONCE_SEEN_DOMAIN.as_bytes());
    h.update(&user_id.to_le_bytes());
    h.update(nonce.as_bytes());
    h.finalize().to_hex().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// the subject has NO operator-registered auth binding (fail-closed)
    NoBinding,
    PersistFailed,
}

/// The operator-supplied allowance list (process env, read per call —
/// same shape as the signer's agent allow-list; no argv, no file).
pub fn registered_user_binding(user_id: u64) -> Option<String> {
    let raw = std::env::var("AGENTPAY_SIGNER_PROVISION_USERS").ok()?;
    for pair in raw.split(',') {
        let pair = pair.trim();
        if let Some((id, pk)) = pair.split_once(':') {
            if let Ok(parsed) = id.trim().parse::<u64>() {
                if parsed == user_id {
                    let pk = pk.trim().to_string();
                    if !pk.is_empty() {
                        return Some(pk);
                    }
                }
            }
        }
    }
    None
}

/// DURABLE nonce + singleflight store for the create path. Every accepted
/// state transition is persisted BEFORE it is visible in memory.
pub struct CreationGate {
    dir: PathBuf,
    seen: Mutex<HashSet<String>>,   // nonce_id hex values
    in_flight: Mutex<HashSet<u64>>, // user_ids with a durable in-progress marker
}

impl CreationGate {
    pub fn open(dir: &Path) -> Result<Self, GateError> {
        std::fs::create_dir_all(dir).map_err(|_| GateError::PersistFailed)?;
        let mut seen = HashSet::new();
        // rehydrate durable nonces (crash-safe: a replay AFTER a crash is
        // still a replay)
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix("nonce-") {
                    if let Some(stripped) = rest.strip_suffix(".json") {
                        seen.insert(stripped.to_string());
                    }
                }
            }
        }
        let mut in_flight = HashSet::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix("progress-") {
                    if let Some(stripped) = rest.strip_suffix(".json") {
                        if let Ok(id) = stripped.parse::<u64>() {
                            in_flight.insert(id);
                        }
                    }
                }
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            seen: Mutex::new(seen),
            in_flight: Mutex::new(in_flight),
        })
    }

    fn persist_file(&self, name: &str, body: &str) -> Result<(), GateError> {
        let path = self.dir.join(name);
        let tmp = self.dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, body).map_err(|_| GateError::PersistFailed)?;
        std::fs::rename(&tmp, &path).map_err(|_| GateError::PersistFailed)?;
        Ok(())
    }

    /// M1: atomic check-and-burn of the creation nonce. An unknown nonce
    /// is consumed (persisted) and accepted; a repeat is NONCE_REPLAY.
    /// The nonce is consumed EVEN IF signing later fails (creation intents
    /// are single-use, like the agent chain's one-shot authority).
    pub fn consume_nonce(&self, user_id: u64, nonce: &str) -> Result<(), GateError> {
        let id = nonce_id(user_id, nonce);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&id) {
            return Err(GateError::PersistFailed); // caller maps to NONCE_REPLAY
        }
        // durable FIRST, then in-memory (a crash between = the nonce is
        // burned on disk but memory lost — rehydrate treats it as seen;
        // conservative: a retry after that crash is refused, never reused)
        self.persist_file(&format!("nonce-{id}.json"), &format!("{{\"burned\":true}}"))?;
        seen.insert(id);
        Ok(())
    }

    /// M2: durable singleflight — only ONE create per user may pass this
    /// point process-wide; the marker survives crashes and is rehydrated.
    pub fn begin(&self, user_id: u64) -> Result<(), GateError> {
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        if in_flight.contains(&user_id) {
            return Err(GateError::PersistFailed); // caller maps to IN_PROGRESS
        }
        self.persist_file(
            &format!("progress-{user_id}.json"),
            &format!("{{\"user_id\":{user_id}}}"),
        )?;
        in_flight.insert(user_id);
        Ok(())
    }

    /// Terminal success (record exists) or terminal refusal — clears the
    /// in-progress marker durably so a LATER, fresh, fully-authorized
    /// create attempt is possible.
    pub fn finish(&self, user_id: u64) -> Result<(), GateError> {
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join(format!("progress-{user_id}.json"));
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(GateError::PersistFailed),
        }
        in_flight.remove(&user_id);
        Ok(())
    }
}

#[cfg(test)]
mod g83_gate_tests {
    use super::*;

    #[test]
    fn nonce_is_single_use_per_user() {
        let dir =
            std::env::temp_dir().join(format!("g83gate-{}-{}", std::process::id(), Uuid::new_v4()));
        let gate = CreationGate::open(&dir).unwrap();
        gate.consume_nonce(1, "n1").unwrap();
        assert!(gate.consume_nonce(1, "n1").is_err());
        // same nonce, DIFFERENT user = different nonce_id = accepted
        gate.consume_nonce(2, "n1").unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nonce_survives_restart() {
        let dir =
            std::env::temp_dir().join(format!("g83gate-{}-{}", std::process::id(), Uuid::new_v4()));
        {
            let gate = CreationGate::open(&dir).unwrap();
            gate.consume_nonce(1, "once").unwrap();
        }
        let gate = CreationGate::open(&dir).unwrap();
        assert!(
            gate.consume_nonce(1, "once").is_err(),
            "replay after restart refused"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn singleflight_blocks_second_begin_and_rehydrates() {
        let dir =
            std::env::temp_dir().join(format!("g83gate-{}-{}", std::process::id(), Uuid::new_v4()));
        let gate = CreationGate::open(&dir).unwrap();
        gate.begin(7).unwrap();
        assert!(gate.begin(7).is_err());
        // rehydrate from disk
        let gate2 = CreationGate::open(&dir).unwrap();
        assert!(gate2.begin(7).is_err(), "in-flight marker survives restart");
        gate2.finish(7).unwrap();
        // terminal state clears the marker (fresh attempt possible)
        assert!(gate2.begin(7).is_ok());
        gate2.finish(7).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binding_lookup_fail_closed() {
        // no env → no binding (fail-closed)
        unsafe { std::env::remove_var("AGENTPAY_SIGNER_PROVISION_USERS") };
        assert!(registered_user_binding(42).is_none());
        unsafe {
            std::env::set_var(
                "AGENTPAY_SIGNER_PROVISION_USERS",
                "42:Auth1111111111111111111111111111111111111111, 43:Pk211111111111111111111111111111111111111111",
            );
        }
        assert_eq!(
            registered_user_binding(42).as_deref(),
            Some("Auth1111111111111111111111111111111111111111")
        );
        assert!(registered_user_binding(44).is_none());
        unsafe { std::env::remove_var("AGENTPAY_SIGNER_PROVISION_USERS") };
    }
}

#[allow(unused_imports)]
use uuid::Uuid as _UuidForGateTests;
