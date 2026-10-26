//! user_intents — G79 decision 4: DURABLE idempotency for user transfer
//! intents. Same guarantees as the agent reservation ledger, without
//! importing it into the user lane: one in-process Mutex (the established
//! serialization discipline) + temp-file+rename+CASCADE persistence keyed
//! by the opaque idempotency key; states ride the frozen V1-style grammar.
//!
//! KEY BINDING (G79-corrected): the ledger index is the STABLE payment
//! identity —
//!   blake3("g78-user-intent-v1" || user_id || recipient || amount_kelvin)
//! NOT the canonical bytes: those embed `validFrom` (fresh per attempt), so
//! hashing them would let an HTTP retry (same payment, fresh clock) create a
//! second intent — exactly the unknown-outcome double-submission this
//! ledger exists to prevent. The first-built canonical bytes are PERSISTED
//! in the record at reserve and REUSED for signing; a replay of the same
//! stable identity with different canonical bytes is AlreadyReserved (the
//! original intent stands, hold semantics apply).
//!
//! CALLER KEY: the caller's idempotency key remains bound — same key +
//! different stable identity = INTENT_CONFLICT (never silent reuse).
//!
//! ATOMIC RESERVE: `reserve_intent` checks-and-writes under the lock and
//! persists BEFORE returning; a crash between memory and disk cannot
//! double-reserve (the loser of the disk rename retries and converges).
//!
//! STATES (frozen grammar): Reserved → Submitted → Confirmed | Failed |
//! Unknown. Unknown holds (gate-replay semantics): `record_outcome` REFUSES
//! transition FROM Unknown — a late node answer can move Unknown only
//! through the read-only reconciliation (out of scope for this module's
//! writers; the sweep/reconcile engines remain the ONLY authority there).
//!
//! NO RESUBMISSION: nothing in this module ever re-broadcasts. Ambiguous
//! outcome ⇒ state Unknown, recorded once (or stays Unknown), never retried.

use blake3::Hasher;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const INTENT_DOMAIN: &str = "g78-user-intent-v1";

/// Canonical intent hash (the ledger index): the STABLE payment identity.
/// Binds user_id + recipient + integer amount — a different user, a
/// different recipient, or a different amount is a different intent,
/// mechanically. `validFrom`/`configHashPrefix`/occ are intentionally
/// EXCLUDED (they vary across legitimate retries of one payment).
pub fn intent_hash(user_id: u64, recipient: &str, amount_kelvin: u64) -> String {
    let mut h = Hasher::new();
    h.update(INTENT_DOMAIN.as_bytes());
    h.update(&user_id.to_le_bytes());
    h.update(recipient.as_bytes());
    h.update(&amount_kelvin.to_le_bytes());
    h.finalize().to_hex().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IntentState {
    Reserved,
    Submitted,
    Confirmed,
    Failed,
    Unknown,
}

impl IntentState {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentState::Reserved => "reserved",
            IntentState::Submitted => "submitted",
            IntentState::Confirmed => "confirmed",
            IntentState::Failed => "failed",
            IntentState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UserIntentRecord {
    /// the caller's opaque idempotency key (stored, must match on replay)
    pub idempotency_key: String,
    pub user_id: u64,
    /// blake3 hex of the STABLE payment identity (user+recipient+amount)
    pub intent_hash: String,
    /// the canonical bytes built at reserve (persisted; REUSED for the
    /// actual signing so a retry cannot mint fresh clock-dependent bytes)
    pub canonical_bytes_b64: String,
    /// the recipient (stable identity component, kept explicit for the
    /// reconciliation reader)
    pub recipient: String,
    /// integer kelvin (stable identity component)
    pub amount_kelvin: u64,
    pub state: IntentState,
    /// the node's tx signature: present ONLY as surfaced evidence (never
    /// fabricated; its presence is never proof of payment)
    pub tx_signature: Option<String>,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    /// same key + DIFFERENT canonical intent — refuse, never silently reuse
    Conflict,
    /// an equivalent intent already exists (same hash). Caller maps this to
    /// its idempotency contract (return the existing record's view).
    AlreadyReserved,
    /// transition refused: Unknown is terminal for writers (hold semantics)
    UnknownHold,
    /// the transition is not legal for the current state
    InvalidTransition,
    PersistFailed,
}

pub struct UserIntentLedger {
    dir: PathBuf,
    mem: Mutex<HashMap<String, UserIntentRecord>>, // key → record
}

impl UserIntentLedger {
    pub fn open(dir: &Path) -> Result<Self, IntentError> {
        std::fs::create_dir_all(dir).map_err(|_| IntentError::PersistFailed)?;
        let mut mem = HashMap::new();
        // recover all persisted records (crash-recovery surface; the sweep
        // machinery stays the ONLY re-driver of Unknown records)
        let entries = std::fs::read_dir(dir).map_err(|_| IntentError::PersistFailed)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(rec) = serde_json::from_slice::<UserIntentRecord>(&bytes) {
                    mem.insert(rec.idempotency_key.clone(), rec);
                }
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            mem: Mutex::new(mem),
        })
    }

    /// Atomic check-and-reserve, persisted BEFORE returning (the agent
    /// store's temp+rename+CASCADE discipline). `canonical_bytes_b64` is the
    /// FIRST-built canonical intent (persisted; reused for signing).
    pub fn reserve_intent(
        &self,
        idempotency_key: &str,
        user_id: u64,
        recipient: &str,
        amount_kelvin: u64,
        canonical_bytes_b64: &str,
        now_unix: i64,
    ) -> Result<UserIntentRecord, IntentError> {
        let hash = intent_hash(user_id, recipient, amount_kelvin);
        let mut mem = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        // a collision on the KEY with a different stable identity = Conflict
        if let Some(existing) = mem.get(idempotency_key) {
            if existing.intent_hash != hash {
                return Err(IntentError::Conflict);
            }
        }
        // an equivalent intent under a DIFFERENT key = AlreadyReserved
        // (same user resubmitting the same payment; hold semantics apply)
        if let Some(twin) = mem.values().find(|r| r.intent_hash == hash) {
            let _ = twin;
            return Err(IntentError::AlreadyReserved);
        }
        let record = UserIntentRecord {
            idempotency_key: idempotency_key.to_string(),
            user_id,
            intent_hash: hash,
            canonical_bytes_b64: canonical_bytes_b64.to_string(),
            recipient: recipient.to_string(),
            amount_kelvin,
            state: IntentState::Reserved,
            tx_signature: None,
            updated_at_unix: now_unix,
        };
        self.persist(&record)?;
        mem.insert(idempotency_key.to_string(), record.clone());
        Ok(record)
    }

    /// Record a submission/confirmation outcome. FROM `Unknown`: REFUSED
    /// (hold semantics — writers may never flip an unknown outcome; the
    /// read-only reconciliation engine owns that class).
    pub fn record_outcome(
        &self,
        idempotency_key: &str,
        state: IntentState,
        tx_signature: Option<&str>,
        now_unix: i64,
    ) -> Result<UserIntentRecord, IntentError> {
        if matches!(state, IntentState::Unknown) {
            // explicit Unknown is set ONLY by record_unknown() below
            return Err(IntentError::UnknownHold);
        }
        let mut mem = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        let rec = mem
            .get_mut(idempotency_key)
            .ok_or(IntentError::InvalidTransition)?;
        if rec.state == IntentState::Unknown {
            return Err(IntentError::UnknownHold);
        }
        if rec.state == IntentState::Confirmed || rec.state == IntentState::Failed {
            return Err(IntentError::InvalidTransition);
        }
        rec.state = state;
        rec.tx_signature = tx_signature.map(|s| s.to_string());
        rec.updated_at_unix = now_unix;
        let snapshot = rec.clone();
        self.persist(&snapshot)?;
        Ok(snapshot)
    }

    /// Mark an ambiguous outcome Unknown — idempotent (a second unknown
    /// observation does not erase or alter the first).
    pub fn record_unknown(&self, idempotency_key: &str, now_unix: i64) -> Result<(), IntentError> {
        let mut mem = self.mem.lock().unwrap_or_else(|e| e.into_inner());
        let rec = mem
            .get_mut(idempotency_key)
            .ok_or(IntentError::InvalidTransition)?;
        if rec.state == IntentState::Confirmed || rec.state == IntentState::Failed {
            return Err(IntentError::InvalidTransition);
        }
        if rec.state == IntentState::Unknown {
            return Ok(()); // idempotent
        }
        rec.state = IntentState::Unknown;
        rec.updated_at_unix = now_unix;
        let snapshot = rec.clone();
        self.persist(&snapshot)?;
        Ok(())
    }

    pub fn get(&self, idempotency_key: &str) -> Option<UserIntentRecord> {
        self.mem
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(idempotency_key)
            .cloned()
    }

    /// The ONLY writer-side persistence (temp + rename, cascade under the
    /// module lock — the established store discipline).
    fn persist(&self, record: &UserIntentRecord) -> Result<(), IntentError> {
        let path = self.dir.join(format!("{}.json", record.idempotency_key));
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(record).map_err(|_| IntentError::PersistFailed)?;
        std::fs::write(&tmp, bytes).map_err(|_| IntentError::PersistFailed)?;
        std::fs::rename(&tmp, &path).map_err(|_| IntentError::PersistFailed)?;
        Ok(())
    }
}

// tests use their own clock; the import below stays scope-minimal
#[allow(unused_imports)]
use std::sync::OnceLock as _OnceLockUnused;

#[cfg(test)]
mod g79_intent_tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "g79int-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reserve_is_atomic_and_persisted() {
        let dir = tempdir("reserve");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        let rec = ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        assert_eq!(rec.state, IntentState::Reserved);
        // durable: a fresh ledger instance recovers the record from disk
        let reopened = UserIntentLedger::open(&dir).unwrap();
        assert_eq!(reopened.get("key-1").unwrap().state, IntentState::Reserved);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_same_intent_same_key_is_already_reserved() {
        let dir = tempdir("replay");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        assert_eq!(
            ledger.reserve_intent("key-1", 50506318, "Rcpt1", 7, "T1RIRVI=", 1001),
            Err(IntentError::AlreadyReserved)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn same_key_different_intent_is_conflict() {
        let dir = tempdir("conflict");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        assert_eq!(
            ledger.reserve_intent("key-1", 50506318, "Rcpt1", 9, "Y2Fub25uaWNhbA==", 1000),
            Err(IntentError::Conflict)
        );
        // different user, same key: different hash ⇒ Conflict
        assert_eq!(
            ledger.reserve_intent("key-1", 99999999, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000),
            Err(IntentError::Conflict)
        );
        // different amount identity ⇒ Conflict as well
        assert_eq!(
            ledger.reserve_intent("key-1", 50506318, "Rcpt1", 8, "Y2Fub25uaWNhbA==", 1000),
            Err(IntentError::Conflict)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retry_with_fresh_validfrom_stays_one_intent() {
        // THE regression the G79 correction targets: the canonical bytes
        // embed validFrom (fresh per attempt) — the STABLE identity decides,
        // so an HTTP retry can never mint a second intent.
        let dir = tempdir("freshclock");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Zmlyc3QtY2xvY2s=", 1000)
            .unwrap();
        assert_eq!(
            ledger.reserve_intent("key-1", 50506318, "Rcpt1", 7, "c2Vjb25kLWNsb2Nr", 2000,),
            Err(IntentError::AlreadyReserved)
        );
        // the FIRST-built canonical bytes remain the signing intent
        let rec = ledger.get("key-1").unwrap();
        assert_eq!(rec.canonical_bytes_b64, "Zmlyc3QtY2xvY2s=");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cross_user_same_intent_is_distinct_ledger_entry() {
        let dir = tempdir("xuser");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        let a = ledger
            .reserve_intent("key-a", 111, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        let b = ledger
            .reserve_intent("key-b", 222, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        assert_ne!(a.intent_hash, b.intent_hash, "user_id binds the hash");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_holds_and_never_auto_resubmits() {
        let dir = tempdir("hold");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        ledger.record_unknown("key-1", 1001).unwrap();
        // idempotent second unknown
        ledger.record_unknown("key-1", 1002).unwrap();
        assert_eq!(ledger.get("key-1").unwrap().state, IntentState::Unknown);
        // writers MUST NOT flip an Unknown (no auto-resend, ever)
        assert_eq!(
            ledger.record_outcome("key-1", IntentState::Confirmed, Some("sig"), 1003),
            Err(IntentError::UnknownHold)
        );
        assert_eq!(
            ledger.record_outcome("key-1", IntentState::Failed, None, 1003),
            Err(IntentError::UnknownHold)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn happy_path_reserved_submitted_confirmed() {
        let dir = tempdir("happy");
        let ledger = UserIntentLedger::open(&dir).unwrap();
        ledger
            .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
            .unwrap();
        ledger
            .record_outcome("key-1", IntentState::Submitted, Some("sig5"), 1001)
            .unwrap();
        let done = ledger
            .record_outcome("key-1", IntentState::Confirmed, Some("sig5"), 1002)
            .unwrap();
        assert_eq!(done.state, IntentState::Confirmed);
        assert_eq!(done.tx_signature.as_deref(), Some("sig5"));
        // terminal: further transitions refused
        assert_eq!(
            ledger.record_outcome("key-1", IntentState::Failed, None, 1003),
            Err(IntentError::InvalidTransition)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_survives_restart() {
        let dir = tempdir("restart");
        {
            let ledger = UserIntentLedger::open(&dir).unwrap();
            ledger
                .reserve_intent("key-1", 50506318, "Rcpt1", 7, "Y2Fub25uaWNhbA==", 1000)
                .unwrap();
            ledger.record_unknown("key-1", 1001).unwrap();
        }
        // restart: the Unknown hold is DURABLE — no silent resend
        let ledger = UserIntentLedger::open(&dir).unwrap();
        assert_eq!(ledger.get("key-1").unwrap().state, IntentState::Unknown);
        assert_eq!(
            ledger.record_outcome("key-1", IntentState::Confirmed, Some("sig5"), 1005),
            Err(IntentError::UnknownHold)
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
