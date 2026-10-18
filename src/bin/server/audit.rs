//! audit — PHASE 9 "Authorization / execution audit" (app-side half).
//!
//! WHAT THIS IS (and the only thing it is): an APPEND-ONLY, OBSERVATIONAL
//! evidence projection of authorization and execution decisions that the
//! EXISTING authorities already made. It creates NO second authorization
//! authority and NO second execution/settlement authority:
//!
//! * `check_agent_payment_policy` remains THE enforcement authority; the
//!   audit never re-checks, never gates, and is never consulted by any
//!   decision path.
//! * The intent records (`artifact/agent_payment_intents/...`) and the
//!   spend ledger (`artifact/agent_spend/...`) remain THE authoritative
//!   money facts. An audit entry mirrors decisions; it can never create,
//!   release, reserve, reconcile, retry, transfer, or flip anything.
//! * Every writer here is BEST-EFFORT: an audit I/O failure is swallowed
//!   exactly like the existing `let _ = mark_intent_failed(...)` pattern —
//!   money-state semantics are untouched by audit availability.
//!
//! STORAGE SHAPE (bounded, validated, crash-safe):
//! * Agent-scoped store: `artifact/agent_audit/<agent-uuid>.json` — one
//!   bounded, newest-trimmed entry list per agent (cap AUDIT_MAX_ENTRIES),
//!   written ATOMICALLY (temp file + chmod 0600 BEFORE rename + fs::rename,
//!   the exact established `write_json_atomic` discipline) under ONE
//!   process-global audit lock. Crash mid-write leaves the previous file
//!   intact (rename is atomic); a crash after rename loses nothing.
//! * Agent-less store: `artifact/agent_audit/_system.json` — same shape,
//!   for decisions that carry no agent context (rate-limit denials,
//!   authentication failures before an agent identity is resolved).
//! * The audit root is DERIVED from the intents root the callers already
//!   pass (`intents_dir.parent()/agent_audit`), so every production caller
//!   and every temp-dir test inherits the established store isolation with
//!   ZERO new path plumbing and zero repo-tree pollution in tests.
//! * NOT a source of monetary truth: nothing reads audit entries to make a
//!   decision; the only read surface is `read_entries` for projections and
//!   tests. The activity/stats/leaderboard projections do not reference
//!   this module (pinned by structural tests).
//!
//! EVIDENCE HYGIENE (hard rules, pinned by tests):
//! * NO credential, token, PHC hash, private-key/keypair material, or
//!   secret-bearing header value can exist in any record: the record type
//!   has NO field that could carry them, and every writer takes only the
//!   whitelisted public facts below.
//! * Identity is persisted as a CLASS ONLY (`session` / `credential` /
//!   `ip` / `none`) — never a raw GitHub id, IP address, agent name, or
//!   header value.
//! * No money-derived authorization/rate primitive: the module contains no
//!   `AgentPolicy` field access for decisions and no budget derivation; a
//!   policy fingerprint is recorded ONLY as the opaque audit snapshot the
//!   engine already computes (V2 `AuthzBinding` semantics).
//! * `x-latch-*` headers are never read anywhere in this module; the only
//!   Latch correlation persisted is the PUBLIC topology/latch id the
//!   operator already configured (`AGENTPAY_LATCH_ID`, public metadata),
//!   and it is never treated as authorization evidence.
//!
//! CORRELATION MODEL (deterministic, existing keys only):
//! * agent uuid + idempotency key (+ V2 intent_id when the record is v2)
//!   correlate authorization and execution records exactly;
//! * lane evidence records carry the same (agent, key) pair the execution
//!   outcome record carries — one dispatch attempt produces exactly one
//!   lane record and exactly one execution record (the seam's one-shot
//!   guard + the per-agent payment lock make a second attempt impossible
//!   in-process; single-process deployment assumption GA-11 unchanged);
//! * reconciliation correlation stays EXACTLY as shipped: the existing
//!   `ReconciliationRecord` inside the intent record is the authority; the
//!   audit only mirrors its existence, never its verdict.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

/// Audit store file format. Bumped only with a documented amendment (the
/// established schema-version rule).
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// Bounded per-file entry cap. Oldest entries are trimmed newest-first
/// retention: the file always keeps the MOST RECENT AUDIT_MAX_ENTRIES
/// entries, so the store is bounded regardless of traffic.
pub const AUDIT_MAX_ENTRIES: usize = 256;

/// The decision categories. A CLOSED enum: unknown shapes fail to parse
/// (fail-closed deserialization), so no unclassified fact can masquerade
/// as audit evidence.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    /// An authorization decision (allow INTO claim, or a pre-claim denial).
    Authorization,
    /// An execution attempt outcome (the single `ops.transfer` dispatch of
    /// one intent, or a pre-dispatch abort after claim+reserve).
    Execution,
    /// The lane/transport decision evidence (Native vs Latch selection,
    /// PreExec fallback, Latch denial, Latch uncertainty).
    Lane,
    /// An idempotent REPLAY observation — explicitly NOT execution
    /// evidence; replays never create new execution/lane facts.
    Replay,
    /// A rate-limit denial observed by the (unpersisted) meter — the meter
    /// stays the enforcement authority; this is the minimal safe export.
    RateLimited,
}

/// The decision outcome vocabulary. `unknown` preserves the established
/// Unknown semantics EXACTLY: an audit entry can never upgrade an Unknown
/// settlement into a terminal, and never downgrades one either.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allow,
    Deny,
    Ok,
    Failed,
    Unknown,
    Aborted,
    Replayed,
    Selected,
    Fallback,
    Denied,
    Uncertain,
}

/// The identity plane, as a CLASS ONLY. No raw identity value is ever
/// persisted (see module hygiene rules).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClass {
    /// GitHub-session principal (owner lane).
    Session,
    /// X-Agent-Credential principal (trigger lane).
    Credential,
    /// Client-peer plane (rate limiter / unauthenticated surfaces).
    Ip,
    /// No identity plane applies.
    None,
}

/// ONE bounded audit fact. Every field is a public, non-secret fact; the
/// shape is closed (`deny_unknown_fields`) so a malformed/foreign file is
/// rejected at parse time rather than silently accepted.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub schema_version: u32,
    /// Unix seconds (the established `now_unix` clock).
    pub at: i64,
    pub category: AuditCategory,
    pub outcome: AuditOutcome,
    /// The stable error/decision code already defined by the existing
    /// authorities (e.g. `AGENT_POLICY_DENIED`, `RATE_LIMITED`,
    /// `LATCH_POLICY_DENIED`, `RIALO_TRANSFER_CONFIRMATION_TIMEOUT`), or
    /// None for plain allow/ok facts.
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub identity_class: Option<IdentityClass>,
    /// Canonical agent uuid (validated at every writer), when the decision
    /// is agent-scoped.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// The client's idempotency key, when the decision is intent-scoped.
    /// NOT a secret (the intent record already stores it in cleartext);
    /// it is THE deterministic correlation key.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// V2 intent correlation id when the record is bound to a v2 intent.
    #[serde(default)]
    pub intent_id: Option<String>,
    /// `native` | `latch` — which execution lane was involved. Recorded
    /// only where the lane decision is already AgentPay-owned evidence.
    #[serde(default)]
    pub lane: Option<String>,
    /// The lane-selection reason string (a static label from the seam —
    /// carries no detail values by construction).
    #[serde(default)]
    pub lane_reason: Option<String>,
    /// True when the Latch lane was selected and the native lane then
    /// performed the single dispatch (PreExec fallback evidence).
    #[serde(default)]
    pub fallback: Option<bool>,
    /// The transaction signature when the execution PROVED success.
    #[serde(default)]
    pub tx_signature: Option<String>,
    /// The opaque policy fingerprint snapshot the engine already computes
    /// (audit-only; never a re-check input).
    #[serde(default)]
    pub policy_fingerprint: Option<String>,
    /// Rate-limit class label for `rate_limited` records
    /// (`expensive` | `cheap`).
    #[serde(default)]
    pub window_class: Option<String>,
}

/// PHASE 9 audit: the correlation context the seam/factory need to mirror
/// their OWN existing decision values. Public, non-secret facts only (the
/// caller already holds all of them at the wiring site). Lives in the audit
/// module — NOT in the transport — so the money handlers stay
/// transport-agnostic (the frozen I-4 isolation pin).
#[derive(Debug, Clone)]
pub struct LaneAuditContext {
    pub agent_id: String,
    pub idempotency_key: String,
    pub audit_dir: PathBuf,
}

/// The audit root derived from the intents root every caller already has.
/// Production: `artifact/agent_payment_intents` -> `artifact/agent_audit`.
/// Temp-dir tests inherit isolation by construction (no repo pollution).
pub(crate) fn audit_dir_for(intents_dir: &FsPath) -> PathBuf {
    intents_dir
        .parent()
        .unwrap_or(FsPath::new("artifact"))
        .join("agent_audit")
}

fn audit_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// The per-agent (or `_system`) store file path. The id must be the
/// VALIDATED canonical uuid or the `_system` literal — nothing else ever
/// reaches a path (the established no-client-path rule).
fn audit_path(dir: &FsPath, agent_id: Option<&str>) -> PathBuf {
    match agent_id {
        Some(id) => dir.join(format!("{id}.json")),
        None => dir.join("_system.json"),
    }
}

#[derive(Serialize, Deserialize, Default)]
struct AuditFile {
    schema_version: u32,
    #[serde(default)]
    entries: Vec<AuditRecord>,
}

/// THE one writer. Append-only + bounded + atomic:
///   read (if any) -> push -> trim to cap -> temp+rename write.
/// Best-effort: every failure (lock poisoned, unreadable file, serialize
/// error, rename failure) is swallowed — the caller's decision path is
/// NEVER affected by audit availability (rule 4 of the item scope).
pub(crate) fn record(entry: AuditRecord, audit_dir: &FsPath, agent_id: Option<&str>) {
    let _guard = audit_lock().lock().unwrap_or_else(|e| e.into_inner());
    let _ = write_entry(entry, audit_dir, agent_id);
}

fn write_entry(
    entry: AuditRecord,
    audit_dir: &FsPath,
    agent_id: Option<&str>,
) -> Result<(), std::io::Error> {
    fs::create_dir_all(audit_dir)?;
    let path = audit_path(audit_dir, agent_id);
    let mut file = match fs::read(&path) {
        Ok(bytes) => {
            let parsed: AuditFile = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("audit parse: {e}")))?;
            if parsed.schema_version != AUDIT_SCHEMA_VERSION {
                return Err(std::io::Error::other("unsupported audit schema_version"));
            }
            parsed
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => AuditFile {
            schema_version: AUDIT_SCHEMA_VERSION,
            entries: Vec::new(),
        },
        Err(err) => return Err(err),
    };
    file.entries.push(entry);
    if file.entries.len() > AUDIT_MAX_ENTRIES {
        // Newest-first retention: drop the OLDEST entries beyond the cap.
        let overflow = file.entries.len() - AUDIT_MAX_ENTRIES;
        file.entries.drain(0..overflow);
    }
    write_audit_atomic(&path, &file)
}

/// The established atomic-write discipline, local to this module (the
/// agents.rs helper is private and the audit store must not grow coupling):
/// temp file in the SAME directory, 0600 BEFORE rename, fs::rename replace.
fn write_audit_atomic(path: &FsPath, value: &impl Serialize) -> Result<(), std::io::Error> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| std::io::Error::other(format!("audit serialize: {e}")))?;
    let tmp = path.with_file_name(format!(".tmp-{}", Uuid::new_v4()));
    let mut file = fs::File::create(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    file.write_all(&bytes)?;
    file.flush()?;
    drop(file);
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

/// The read surface for projections/tests. Read-ONLY: no lock, no write,
/// no mutation; a missing file is an empty history, a corrupt file is a
/// typed error (fail-closed, never silently mis-parsed).
#[allow(dead_code)] // consumed by the focused audit tests and future projections
pub(crate) fn read_entries(
    audit_dir: &FsPath,
    agent_id: Option<&str>,
) -> Result<Vec<AuditRecord>, std::io::Error> {
    let path = audit_path(audit_dir, agent_id);
    match fs::read(&path) {
        Ok(bytes) => {
            let parsed: AuditFile = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("audit parse: {e}")))?;
            if parsed.schema_version != AUDIT_SCHEMA_VERSION {
                return Err(std::io::Error::other("unsupported audit schema_version"));
            }
            Ok(parsed.entries)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

// ---------------------------------------------------------------------------
// Typed constructors — the ONLY ways an audit record may come into being.
// Every constructor validates/bounds its inputs and accepts ONLY public,
// non-secret facts.
// ---------------------------------------------------------------------------

/// One authorization decision. `code` is the stable existing code (None for
/// the allowed transition). `policy_fingerprint` is recorded only when the
/// persisted policy was successfully loaded (the snapshot the engine uses).
pub(crate) fn authorization(
    at: i64,
    outcome: AuditOutcome,
    code: Option<&str>,
    identity_class: IdentityClass,
    agent_id: Option<&str>,
    idempotency_key: Option<&str>,
    policy_fingerprint: Option<&str>,
) -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        at,
        category: AuditCategory::Authorization,
        outcome,
        code: bounded(code),
        identity_class: Some(identity_class),
        agent_id: bounded(agent_id),
        idempotency_key: bounded(idempotency_key),
        intent_id: None,
        lane: None,
        lane_reason: None,
        fallback: None,
        tx_signature: None,
        policy_fingerprint: bounded(policy_fingerprint),
        window_class: None,
    }
}

/// One execution-attempt outcome, written ONLY by the cores' single
/// `ops.transfer` dispatch boundary (or its pre-dispatch abort helper).
pub(crate) fn execution(
    at: i64,
    outcome: AuditOutcome,
    code: Option<&str>,
    agent_id: &str,
    idempotency_key: &str,
    tx_signature: Option<&str>,
    policy_fingerprint: Option<&str>,
    intent_id: Option<&str>,
) -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        at,
        category: AuditCategory::Execution,
        outcome,
        code: bounded(code),
        identity_class: None,
        agent_id: bounded(Some(agent_id)),
        idempotency_key: bounded(Some(idempotency_key)),
        intent_id: bounded(intent_id),
        lane: None,
        lane_reason: None,
        fallback: None,
        tx_signature: bounded(tx_signature),
        policy_fingerprint: bounded(policy_fingerprint),
        window_class: None,
    }
}

/// One lane/transport decision fact, written ONLY by the seam's observer at
/// the existing AgentPay-owned decision points (selection, PreExec fallback
/// after selection, Latch denial, Latch uncertainty).
pub(crate) fn lane(
    at: i64,
    outcome: AuditOutcome,
    code: Option<&str>,
    agent_id: &str,
    idempotency_key: &str,
    lane: Option<&str>,
    lane_reason: &str,
    fallback: bool,
) -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        at,
        category: AuditCategory::Lane,
        outcome,
        code: bounded(code),
        identity_class: None,
        agent_id: bounded(Some(agent_id)),
        idempotency_key: bounded(Some(idempotency_key)),
        intent_id: None,
        lane: bounded(lane),
        lane_reason: bounded(Some(lane_reason)),
        fallback: Some(fallback),
        tx_signature: None,
        policy_fingerprint: None,
        window_class: None,
    }
}

/// One idempotent-REPLAY observation. Explicitly classified as replay —
/// NEVER execution evidence, never a second lane fact.
pub(crate) fn replay(at: i64, code: &str, agent_id: &str, idempotency_key: &str) -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        at,
        category: AuditCategory::Replay,
        outcome: AuditOutcome::Replayed,
        code: bounded(Some(code)),
        identity_class: None,
        agent_id: bounded(Some(agent_id)),
        idempotency_key: bounded(Some(idempotency_key)),
        intent_id: None,
        lane: None,
        lane_reason: None,
        fallback: None,
        tx_signature: None,
        policy_fingerprint: None,
        window_class: None,
    }
}

/// One rate-limit denial fact. The meter stays the enforcement authority;
/// this is the minimal safe export (identity CLASS only, no amount, no
/// headers, no credentials, no raw identity value).
pub(crate) fn rate_limited(
    at: i64,
    identity_class: IdentityClass,
    window_class: &str,
) -> AuditRecord {
    AuditRecord {
        schema_version: AUDIT_SCHEMA_VERSION,
        at,
        category: AuditCategory::RateLimited,
        outcome: AuditOutcome::Deny,
        code: Some("RATE_LIMITED".to_string()),
        identity_class: Some(identity_class),
        agent_id: None,
        idempotency_key: None,
        intent_id: None,
        lane: None,
        lane_reason: None,
        fallback: None,
        tx_signature: None,
        policy_fingerprint: None,
        window_class: bounded(Some(window_class)),
    }
}

/// Field bound: every string field is bounded and control-character-free
/// (the established sanitize discipline). Oversized or control-bearing
/// values are DROPPED (None) — an audit entry never carries unbounded data.
fn bounded(raw: Option<&str>) -> Option<String> {
    raw.filter(|s| !s.is_empty())
        .filter(|s| s.len() <= 256)
        .filter(|s| !s.chars().any(char::is_control))
        .map(|s| s.to_string())
}

/// The per-agent audit directory (validated canonical uuid only — the same
/// gate every other store path uses).
#[allow(dead_code)] // the validated per-agent audit path (test/pinned)
pub(crate) fn agent_audit_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

#[cfg(test)]
#[path = "_audit_i9_tests.rs"]
mod audit_tests;
