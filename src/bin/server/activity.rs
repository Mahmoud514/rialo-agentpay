//! PHASE 6 STEP 6 — TRANSACTION / ACTIVITY TRACKING (derived read model).
//!
//! Activity is a PURE PROJECTION of the existing idempotency/replay ledger
//! `artifact/agent_payment_intents/<agent-uuid>/<hex-key>.json`. There is
//! NO activity database, NO activity files, NO second source of truth:
//! every activity fact already lives in the intent record, and the
//! (agent, key) file IS the activity identity. One intent file renders
//! exactly ONE activity item across its whole lifecycle — pending,
//! confirmed, failed, unknown, reconciled_paid, reconciled_absent — and a
//! reconciliation mutation NEVER creates a second item: the terminal flips
//! in place inside the same file, `updated_at` is data, not an event, and
//! the cursor is created_at-anchored so a reconciled record cannot re-enter
//! a window it already left.
//!
//! HARD READ-ONLY CONTRACT (product requirement): this module opens the
//! intents ledger for READING and nothing else. It never writes, creates,
//! renames, or locks any file; never reserves or releases spend; never
//! transfers; never reads balances; never touches the faucet; never issues
//! or revokes credentials; never calls the chain — activity rendering runs
//! ZERO RPC. The Step-4 read-only verifier lane in rialo.rs stays the only
//! consumer of chain reads (Phase 7 will add a separate verifier endpoint
//! there, not here). The authoritative record readers reused below
//! (`crate::agents::read_intent` / `read_intent_v2`) are the same
//! fail-closed validators the engines use; their internal store_lock is
//! microseconds of file I/O and belongs to the readers, not to this
//! module — activity acquires no locks of its own.
//!
//! DTO WHITELIST: items are built field-by-field from typed record fields
//! plus two strictly whitelisted digs for v1 (`response.payment.signature`,
//! `response.code` + `response.http_status`). The raw `response` blob is
//! NEVER rendered. There is no code path here that serializes a path,
//! keypair, credential, PHC hash, policy fingerprint, session token, or
//! any store internal.
//!
//! ORDERING + PAGINATION: fixed deterministic order — created_at DESC,
//! tie-break (agent_id, key_hex) ASC. No sort parameters exist. The cursor
//! is a versioned opaque base64url token over {v,c,a,k} with STRICT
//! validation: unknown version, malformed shape, traversal-shaped values,
//! and any cursor bound to a DIFFERENT agent are rejected. There is NO
//! offset pagination anywhere in this module.

use axum::{
    Json,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Pagination constants (approved defaults)
// ---------------------------------------------------------------------------

pub const ACTIVITY_DEFAULT_PAGE_SIZE: usize = 20;
pub const ACTIVITY_MAX_PAGE_SIZE: usize = 100;
pub(crate) const CURSOR_VERSION: u64 = 1;
pub(crate) const MAX_CURSOR_TOKEN_LEN: usize = 512;
const MAX_SIGNATURE_FILTER_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Raw query carrier (parsed strictly BY THIS MODULE, never by an
// extractor that would answer axum's plain-text 400 — the typed-envelope
// rule: every failure lands on the project envelope)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RawQuery(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for RawQuery {
    type Rejection = std::convert::Infallible;
    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // take the RAW (still percent-encoded) query string; this module
        // owns the validation so every failure lands on the project
        // envelope instead of an extractor's plain-text 400
        let raw = parts.uri.query().map(|q| q.to_string());
        std::future::ready(Ok(RawQuery(raw)))
    }
}

// ---------------------------------------------------------------------------
// Query model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStateFilter {
    Pending,
    Confirmed,
    Failed,
    Unknown,
    ReconciledPaid,
    ReconciledAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActivityPrincipalFilter {
    Owner,
    Agent,
}

/// Validated query. Built ONLY through `parse_activity_query`; any value
/// that is not one of the whitelisted parameters, or repeats one, or fails
/// its grammar, is a typed `ACTIVITY_REQUEST_INVALID` 400.
#[derive(Debug, Clone)]
pub struct ActivityQuery {
    pub state: Option<ActivityStateFilter>,
    pub principal: Option<ActivityPrincipalFilter>,
    pub recipient: Option<String>,
    pub signature: Option<String>,
    pub amount_kelvin: Option<u64>,
    pub created_at_gte: Option<i64>,
    pub created_at_lt: Option<i64>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
}

impl Default for ActivityQuery {
    fn default() -> Self {
        Self {
            state: None,
            principal: None,
            recipient: None,
            signature: None,
            amount_kelvin: None,
            created_at_gte: None,
            created_at_lt: None,
            limit: ACTIVITY_DEFAULT_PAGE_SIZE,
            cursor: None,
        }
    }
}

/// Percent-decode (RFC 3986 minimal) — kept local; the server feature's
/// dependency surface stays exactly the manifest it is today.
pub(crate) fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = *bytes.get(i + 1)?;
                let lo = *bytes.get(i + 2)?;
                let v = (hex_val(hi)? << 4) | hex_val(lo)?;
                out.push(v);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_state_filter(s: &str) -> Option<ActivityStateFilter> {
    serde_json::from_value::<ActivityStateFilter>(serde_json::Value::String(s.to_string())).ok()
}

fn parse_principal_filter(s: &str) -> Option<ActivityPrincipalFilter> {
    serde_json::from_value::<ActivityPrincipalFilter>(serde_json::Value::String(s.to_string())).ok()
}

/// Parse + validate a raw query string. Splitting happens on the ENCODED
/// form (& / =), values are percent-decoded afterwards, so a literal
/// `%26` can never smuggle a second parameter.
pub(crate) fn parse_activity_query(raw: &str) -> Result<ActivityQuery, String> {
    let mut q = ActivityQuery::default();
    let mut seen: Vec<&'static str> = Vec::new();
    if raw.is_empty() {
        return Ok(q);
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err("empty parameter".to_string());
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => return Err("parameters must be key=value".to_string()),
        };
        let key = percent_decode(k).ok_or("undecodable parameter name")?;
        let value = percent_decode(v).ok_or("undecodable parameter value")?;
        let slot: &'static str = match key.as_str() {
            "state" => "state",
            "principal" => "principal",
            "recipient" => "recipient",
            "signature" => "signature",
            "amount_kelvin" => "amount_kelvin",
            "created_at_gte" => "created_at_gte",
            "created_at_lt" => "created_at_lt",
            "limit" => "limit",
            "cursor" => "cursor",
            _ => return Err(format!("unknown parameter: {key}")),
        };
        if seen.contains(&slot) {
            return Err(format!("duplicate parameter: {key}"));
        }
        seen.push(slot);
        match slot {
            "state" => {
                q.state = Some(
                    parse_state_filter(&value)
                        .ok_or("state must be one of the six canonical states")?,
                );
            }
            "principal" => {
                q.principal =
                    Some(parse_principal_filter(&value).ok_or("principal must be owner or agent")?);
            }
            "recipient" => {
                // the ONE address validator — an invalid recipient is a
                // typed rejection, never an implicit empty page
                if !crate::valid_rialo_address(&value) {
                    return Err("recipient is not a valid Rialo address".to_string());
                }
                q.recipient = Some(value);
            }
            "signature" => {
                if value.is_empty() || value.len() > MAX_SIGNATURE_FILTER_LEN {
                    return Err("signature filter must be a bounded non-empty string".to_string());
                }
                q.signature = Some(value);
            }
            "amount_kelvin" => {
                q.amount_kelvin = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "amount_kelvin must be an unsigned integer".to_string())?,
                );
            }
            "created_at_gte" => {
                q.created_at_gte = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| "created_at_gte must be an integer unix time".to_string())?,
                );
            }
            "created_at_lt" => {
                q.created_at_lt = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| "created_at_lt must be an integer unix time".to_string())?,
                );
            }
            "limit" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| "limit must be an integer".to_string())?;
                if n == 0 || n > ACTIVITY_MAX_PAGE_SIZE as u64 {
                    return Err(format!(
                        "limit must be between 1 and {ACTIVITY_MAX_PAGE_SIZE}"
                    ));
                }
                q.limit = n as usize;
            }
            "cursor" => {
                if value.len() > MAX_CURSOR_TOKEN_LEN {
                    return Err("cursor is too long".to_string());
                }
                q.cursor = Some(
                    decode_cursor(&value).ok_or("cursor is malformed or has an unknown version")?,
                );
            }
            _ => unreachable!(),
        }
    }
    Ok(q)
}

// ---------------------------------------------------------------------------
// Cursor — versioned opaque token {v,c,a,k} over base64url (no padding)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub v: u64,
    pub c: i64,
    pub a: String,
    pub k: String,
}

impl Cursor {
    /// Opaque base64url (no padding) encoding of the 4-field cursor.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        b64url_encode(&json)
    }
}

pub(crate) fn is_canonical_hex_lower(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// STRICT cursor decode: base64url charset only, JSON object only, exact
/// 4-field shape, canonical agent UUID, canonical lowercase EVEN-length
/// hex key, version == 1, and no traversal-shaped values. A cursor is an
/// opaque continuation, not a filter — anything else is malformed.
pub(crate) fn decode_cursor(token: &str) -> Option<Cursor> {
    if token.is_empty() || token.len() > MAX_CURSOR_TOKEN_LEN {
        return None;
    }
    let json = b64url_decode(token)?;
    let value: serde_json::Value = serde_json::from_slice(&json).ok()?;
    let obj = value.as_object()?;
    if obj.len() != 4 {
        return None;
    }
    let v = obj.get("v")?.as_u64()?;
    if v != CURSOR_VERSION {
        return None;
    }
    let c = obj.get("c")?.as_i64()?;
    let a = obj.get("a")?.as_str()?;
    let k = obj.get("k")?.as_str()?;
    if a.contains('/') || a.contains('\\') || a.contains('.') || a.contains(':') {
        return None;
    }
    if !is_canonical_hex_lower(k) || k.len() % 2 != 0 {
        return None;
    }
    let uuid = crate::agents::parse_agent_id(a)?;
    if uuid.to_string() != a {
        return None;
    }
    Some(Cursor {
        v,
        c,
        a: a.to_string(),
        k: k.to_string(),
    })
}

// base64url (RFC 4648, no padding) — local, minimal, dependency-free.
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.contains('=') {
        return None; // padded tokens are not this grammar
    }
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out: Vec<u8> = Vec::with_capacity(input.len() * 3 / 4 + 1);
    for ch in input.bytes() {
        let val = B64_ALPHABET.iter().position(|&a| a == ch)? as u32;
        acc = (acc << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // a dangling partial group is only valid if its leftover bits are zero
    if bits > 0 {
        if acc & ((1u32 << bits) - 1) != 0 || input.len() % 4 == 1 {
            return None;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Projection: intent slot -> whitelisted activity item
// ---------------------------------------------------------------------------

pub(crate) enum Slot {
    V1(crate::agents::PaymentIntent),
    V2(crate::agents::PaymentIntentV2),
}

pub(crate) fn state_name_v1(state: crate::agents::IntentState) -> &'static str {
    match state {
        crate::agents::IntentState::Pending => "pending",
        crate::agents::IntentState::Confirmed => "confirmed",
        crate::agents::IntentState::Failed => "failed",
        crate::agents::IntentState::Unknown => "unknown",
        crate::agents::IntentState::ReconciledPaid => "reconciled_paid",
        crate::agents::IntentState::ReconciledAbsent => "reconciled_absent",
    }
}

pub(crate) fn state_name_v2(state: crate::agents::ExecState) -> &'static str {
    match state {
        crate::agents::ExecState::Pending => "pending",
        crate::agents::ExecState::Confirmed => "confirmed",
        crate::agents::ExecState::Failed => "failed",
        crate::agents::ExecState::Unknown => "unknown",
        crate::agents::ExecState::ReconciledPaid => "reconciled_paid",
        crate::agents::ExecState::ReconciledAbsent => "reconciled_absent",
    }
}

fn principal_name(kind: crate::agents::PrincipalKind) -> &'static str {
    match kind {
        crate::agents::PrincipalKind::Owner => "owner",
        crate::agents::PrincipalKind::Agent => "agent",
    }
}

/// The ONE whitelisted dig for a v1 confirmed signature: a NON-EMPTY
/// string at `response.payment.signature`, exactly the grammar the replay
/// path already trusts. Anything else yields None — the raw blob is never
/// rendered and never repurposed.
pub(crate) fn v1_signature_from_response(response: &Option<serde_json::Value>) -> Option<String> {
    let sig = response
        .as_ref()?
        .get("payment")?
        .get("signature")?
        .as_str()?;
    (!sig.is_empty() && sig.len() <= MAX_SIGNATURE_FILTER_LEN).then(|| sig.to_string())
}

/// The whitelisted v1 failure view: `response.code` + `response.http_status`
/// only (the recorded error grammar already validated on the replay path).
/// The human message is NOT part of the whitelist and never renders.
fn v1_failure_from_response(response: &Option<serde_json::Value>) -> Option<serde_json::Value> {
    let resp = response.as_ref()?;
    let code = resp.get("code")?.as_str()?;
    let status = resp.get("http_status")?.as_u64()?;
    if code.is_empty() || code.len() > 64 || status > 599 {
        return None;
    }
    Some(serde_json::json!({ "code": code, "http_status": status }))
}

fn reconciliation_value(record: &Option<crate::agents::ReconciliationRecord>) -> serde_json::Value {
    // reuse the established renderer verbatim; null when absent
    match record {
        Some(record) => crate::agents::reconciliation_json(record)["reconciliation"].clone(),
        None => serde_json::Value::Null,
    }
}

/// Render one slot into the whitelisted activity item JSON. The field set
/// is the approved DTO whitelist — nothing else has a path to the output.
/// `amount_rlo` is the single DISPLAY derivation from the canonical
/// integer kelvin (it is never stored, compared, or accepted).
fn item_json(key_hex: &str, slot: &Slot) -> serde_json::Value {
    match slot {
        Slot::V1(i) => serde_json::json!({
            "schema_version": i.schema_version,
            "intent_id": null,
            "agent_id": i.agent_id,
            "principal_kind": "owner", // v1 slots are owner-principal by construction
            "recipient": i.recipient,
            "amount_kelvin": i.amount_kelvin,
            "amount_rlo": i.amount_kelvin as f64 / 1_000_000_000.0,
            "state": state_name_v1(i.state),
            "tx_signature": v1_signature_from_response(&i.response),
            "failure": v1_failure_from_response(&i.response),
            "reconciliation": reconciliation_value(&i.reconciliation),
            "created_at": i.created_at,
            "updated_at": i.updated_at,
            "idempotency_slot": key_hex,
        }),
        Slot::V2(i) => {
            let failure = i
                .failure
                .as_ref()
                .map(|f| serde_json::json!({ "code": f.code, "http_status": f.http_status }));
            serde_json::json!({
                "schema_version": i.schema_version,
                "intent_id": i.intent_id,
                "agent_id": i.agent_id,
                "principal_kind": principal_name(i.principal_kind),
                "recipient": i.recipient,
                "amount_kelvin": i.amount_kelvin,
                "amount_rlo": i.amount_kelvin as f64 / 1_000_000_000.0,
                "state": state_name_v2(i.exec_state),
                "tx_signature": i.tx_signature,
                "failure": failure,
                "reconciliation": reconciliation_value(&i.reconciliation),
                "created_at": i.created_at,
                "updated_at": i.updated_at,
                "idempotency_slot": key_hex,
                "authz_bound": true, // v2 records always carry the authz binding
            })
        }
    }
}

struct SortFacts {
    created_at: i64,
    principal: &'static str,
    signature: Option<String>,
    state: &'static str,
    recipient: String,
    amount_kelvin: u64,
}

pub(crate) fn slot_facts(slot: &Slot) -> SortFacts {
    match slot {
        Slot::V1(i) => SortFacts {
            created_at: i.created_at,
            principal: "owner",
            signature: v1_signature_from_response(&i.response),
            state: state_name_v1(i.state),
            recipient: i.recipient.clone(),
            amount_kelvin: i.amount_kelvin,
        },
        Slot::V2(i) => SortFacts {
            created_at: i.created_at,
            principal: principal_name(i.principal_kind),
            signature: i.tx_signature.clone(),
            state: state_name_v2(i.exec_state),
            recipient: i.recipient.clone(),
            amount_kelvin: i.amount_kelvin,
        },
    }
}

/// The created-at timestamp either slot kind carries (the scan sort
/// key). Single accessor so activity and proof ordering can never
/// diverge.
pub(crate) fn slot_created_at(slot: &Slot) -> i64 {
    match slot {
        Slot::V1(i) => i.created_at,
        Slot::V2(i) => i.created_at,
    }
}

fn matches_filters(q: &ActivityQuery, facts: &SortFacts) -> bool {
    if let Some(f) = &q.state {
        let s = match f {
            ActivityStateFilter::Pending => "pending",
            ActivityStateFilter::Confirmed => "confirmed",
            ActivityStateFilter::Failed => "failed",
            ActivityStateFilter::Unknown => "unknown",
            ActivityStateFilter::ReconciledPaid => "reconciled_paid",
            ActivityStateFilter::ReconciledAbsent => "reconciled_absent",
        };
        if facts.state != s {
            return false;
        }
    }
    if let Some(f) = &q.principal {
        let p = match f {
            ActivityPrincipalFilter::Owner => "owner",
            ActivityPrincipalFilter::Agent => "agent",
        };
        if facts.principal != p {
            return false;
        }
    }
    if let Some(r) = &q.recipient {
        if &facts.recipient != r {
            return false;
        }
    }
    if let Some(sig) = &q.signature {
        match &facts.signature {
            Some(s) if s == sig => {}
            _ => return false,
        }
    }
    if let Some(amt) = q.amount_kelvin {
        if facts.amount_kelvin != amt {
            return false;
        }
    }
    if let Some(gte) = q.created_at_gte {
        if facts.created_at < gte {
            return false;
        }
    }
    if let Some(lt) = q.created_at_lt {
        if facts.created_at >= lt {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The scan core (fs::read only; temp-dir testable; production handlers
// pass crate::agents::intents_root())
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ActivityOutcome {
    /// items + next_cursor (null when exhausted) — always 200
    Rendered(Vec<serde_json::Value>, Option<String>),
    /// typed 400 ACTIVITY_REQUEST_INVALID
    Rejected(String),
    /// typed 500 AGENT_STORE_ERROR — fail closed: never a partial page
    Store,
}

struct ScannedSlot {
    key_hex: String,
    facts: SortFacts,
    slot: Slot,
}

/// Enumerate the agent's OWN intents directory, deterministically. Rules
/// (each fail-closed or inert — never a partial truth):
///   * missing directory        -> empty activity (no ledger = no history);
///   * any other read_dir error -> Store;
///   * non-`.json` names        -> inert (extra files never become activity,
///                                 the same rule every store here applies);
///   * non-canonical hex stems  -> inert;
///   * schema_version not 1|2   -> inert (foreign documents are NOT
///                                 activity and NOT corruption — mirroring
///                                 the credential-store skip rule);
///   * a v1/v2 record that FAILS its authoritative reader (corrupt JSON,
///     identity mismatch, key/filename divergence) -> Store: a page never
///     silently drops a real ledger entry, and a partial history is a
///     dangerous history.
pub(crate) fn render_activity_in(
    root: &std::path::Path,
    id: &Uuid,
    q: &ActivityQuery,
) -> ActivityOutcome {
    let dir = crate::agents::agent_intents_dir(root, id);
    let entries: Vec<fs::DirEntry> = match fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return ActivityOutcome::Store,
    };
    let mut names: Vec<String> = Vec::new();
    for entry in &entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort(); // deterministic listing regardless of filesystem order

    let mut scanned: Vec<ScannedSlot> = Vec::new();
    for stem in names {
        if !is_canonical_hex_lower(&stem) || stem.len() % 2 != 0 {
            continue; // not a slot shape this store can ever mint
        }
        let Some(key) = hex_decode(&stem) else {
            continue;
        };
        // route v1/v2 by the document's own version tag BEFORE any typed
        // reader rejects an unknown version (foreign stays inert, corrupt
        // stays fatal)
        let bytes = match fs::read(dir.join(format!("{stem}.json"))) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return ActivityOutcome::Store,
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return ActivityOutcome::Store; // unparseable ledger file
        };
        match value.get("schema_version").and_then(|v| v.as_u64()) {
            Some(1) => {
                let intent = match crate::agents::read_intent(root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return ActivityOutcome::Store,
                };
                let slot = Slot::V1(intent);
                scanned.push(ScannedSlot {
                    key_hex: stem,
                    facts: slot_facts(&slot),
                    slot,
                });
            }
            Some(2) => {
                let intent = match crate::agents::read_intent_v2(root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return ActivityOutcome::Store,
                };
                let slot = Slot::V2(intent);
                scanned.push(ScannedSlot {
                    key_hex: stem,
                    facts: slot_facts(&slot),
                    slot,
                });
            }
            _ => continue, // foreign/unknown document: inert, never activity
        }
    }

    finalize_activity(scanned, id, q)
}

/// Apply the fixed ordering, filters, cursor, page bound, and DTO mapping to
/// an already-scanned slot set. Shared by the filesystem and PG projections
/// so their pagination/filter semantics cannot drift.
fn finalize_activity(
    mut scanned: Vec<ScannedSlot>,
    id: &Uuid,
    q: &ActivityQuery,
) -> ActivityOutcome {
    // fixed deterministic order: created_at DESC, tie-break key_hex ASC
    scanned.sort_by(|a, b| {
        b.facts
            .created_at
            .cmp(&a.facts.created_at)
            .then_with(|| a.key_hex.cmp(&b.key_hex))
    });

    let mut selected: Vec<&ScannedSlot> = scanned
        .iter()
        .filter(|s| matches_filters(q, &s.facts))
        .collect();
    if let Some(c) = &q.cursor {
        if c.a != id.to_string() {
            return ActivityOutcome::Rejected("cursor is bound to a different agent".to_string());
        }
        // strictly AFTER the tuple in this order
        selected.retain(|s| {
            s.facts.created_at < c.c
                || (s.facts.created_at == c.c && s.key_hex.as_str() > c.k.as_str())
        });
    }

    let page: Vec<serde_json::Value> = selected
        .iter()
        .take(q.limit)
        .map(|s| item_json(&s.key_hex, &s.slot))
        .collect();
    let next_cursor = if selected.len() > q.limit && page.len() == q.limit {
        let last = selected.get(q.limit - 1).expect("full page");
        Some(
            Cursor {
                v: CURSOR_VERSION,
                c: last.facts.created_at,
                a: id.to_string(),
                k: last.key_hex.clone(),
            }
            .encode(),
        )
    } else {
        None
    };
    ActivityOutcome::Rendered(page, next_cursor)
}

/// PG-authoritative activity projection. Production's authoritative ledger
/// is `payment_intents`; the filesystem directory is empty there. Build the
/// same `ScannedSlot` set from the DB docs, then use the shared finalizer.
async fn render_activity_pg(id: &Uuid, q: &ActivityQuery) -> ActivityOutcome {
    let client = crate::pg_store::global_client().await;
    let rows = match client
        .query(
            "SELECT idempotency_key, doc FROM payment_intents WHERE agent_id = $1",
            &[id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return ActivityOutcome::Store,
    };
    let mut scanned: Vec<ScannedSlot> = Vec::new();
    for row in rows {
        let key: String = row.get(0);
        let doc: serde_json::Value = row.get(1);
        let key_hex = crate::agents::hex_encode(key.as_bytes());
        match doc.get("schema_version").and_then(|v| v.as_u64()) {
            Some(1) => {
                let Ok(intent) = serde_json::from_value::<crate::agents::PaymentIntent>(doc) else {
                    return ActivityOutcome::Store;
                };
                if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                    return ActivityOutcome::Store;
                }
                let slot = Slot::V1(intent);
                scanned.push(ScannedSlot {
                    key_hex,
                    facts: slot_facts(&slot),
                    slot,
                });
            }
            Some(2) => {
                let Ok(intent) = serde_json::from_value::<crate::agents::PaymentIntentV2>(doc)
                else {
                    return ActivityOutcome::Store;
                };
                if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                    return ActivityOutcome::Store;
                }
                let slot = Slot::V2(intent);
                scanned.push(ScannedSlot {
                    key_hex,
                    facts: slot_facts(&slot),
                    slot,
                });
            }
            _ => continue, // foreign/unknown document: inert, never activity
        }
    }
    finalize_activity(scanned, id, q)
}

pub(crate) fn hex_decode(input: &str) -> Option<String> {
    if input.len() % 2 != 0 {
        return None;
    }
    let bytes: Vec<u8> = (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    String::from_utf8(bytes).ok()
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

fn request_invalid(reason: &str) -> Response {
    crate::api_error(StatusCode::BAD_REQUEST, "ACTIVITY_REQUEST_INVALID", reason)
}

fn store_error() -> Response {
    crate::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "AGENT_STORE_ERROR",
        "Activity could not be read completely; a partial history is never shown",
    )
}

fn activity_http(outcome: ActivityOutcome, agent_id: &str, q: &ActivityQuery) -> Response {
    match outcome {
        ActivityOutcome::Rendered(items, next_cursor) => Json(serde_json::json!({
            "success": true,
            "agent_id": agent_id,
            "page_size": q.limit,
            "items": items,
            "next_cursor": next_cursor,
        }))
        .into_response(),
        ActivityOutcome::Rejected(reason) => request_invalid(&reason),
        ActivityOutcome::Store => store_error(),
    }
}

/// GET /api/agents/{id}/activity — owner lane. Authorization order is the
/// established one: session -> ownership choke point (missing/foreign/
/// corrupt collapse to ONE indistinguishable AGENT_NOT_FOUND) -> query
/// validation -> read-only projection.
pub async fn agent_activity(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    raw: RawQuery,
) -> Response {
    let Some(user) = crate::session_user(&state, &headers) else {
        return crate::api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    let agent = match crate::agents::load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = crate::agents::parse_agent_id(&agent.agent_id) else {
        // an owned record whose id is not canonical is corruption:
        // collapse into the same indistinguishable AGENT_NOT_FOUND
        return crate::api_error(StatusCode::NOT_FOUND, "AGENT_NOT_FOUND", "Agent not found");
    };
    let q = match parse_activity_query(&raw.0.unwrap_or_default()) {
        Ok(q) => q,
        Err(reason) => return request_invalid(&reason),
    };
    let outcome = if crate::pg_store::pg_is_authoritative() {
        // Production authority is PostgreSQL; the filesystem ledger is
        // empty there. A DB/runtime error is fail-closed, never a partial
        // or empty page.
        match crate::pg_store::pg_run(render_activity_pg(&uuid, &q)) {
            Ok(outcome) => outcome,
            Err(_) => ActivityOutcome::Store,
        }
    } else {
        let root = crate::agents::intents_root();
        render_activity_in(&root, &uuid, &q)
    };
    activity_http(outcome, &agent.agent_id, &q)
}

/// GET /api/agents/triggers/payments/activity — credential lane. The
/// agent principal comes EXCLUSIVELY from X-Agent-Credential (exactly one
/// value, 64 lowercase hex, Argon2-verified against the disk store);
/// EVERY credential-layer failure collapses to ONE stable 401
/// AGENT_CREDENTIAL_INVALID — never from URL/body/query/session. Lifecycle
/// is deliberately NOT a gate (the Step-4 precedent: a deactivated agent's
/// history still belongs to it). Only the resolved agent's OWN intents
/// directory is ever opened.
pub async fn agent_trigger_activity(headers: HeaderMap, raw: RawQuery) -> Response {
    fn credential_invalid() -> Response {
        crate::api_error(
            StatusCode::UNAUTHORIZED,
            "AGENT_CREDENTIAL_INVALID",
            "A valid X-Agent-Credential header is required to resolve the agent principal",
        )
    }
    let mut cred_values = headers.get_all("x-agent-credential").iter();
    let credential = match (cred_values.next(), cred_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|c| crate::agents::valid_credential_shape(c))
            .map(|c| c.to_string()),
        _ => None,
    };
    let Some(credential) = credential else {
        return credential_invalid();
    };
    // the expensive Argon2 verify stays off the async executor, exactly as
    // the trigger payment/reconcile handlers do; the plaintext is dropped
    // at the end of resolution and never logged or echoed
    let resolution = {
        let credential = credential.clone();
        tokio::task::spawn_blocking(move || {
            let uuid = crate::agent_credentials::authenticate_agent_credential(&credential)
                .map_err(|_| ())?;
            drop(credential);
            // the principal owns an agent record; the record is NOT
            // re-read for display — only its canonical existence gates the
            // lane (same choke as the reconcile credential handler)
            let agents = crate::agents::agents_dir();
            crate::agents::read_agent(&crate::agents::agent_path(&agents, &uuid))
                .map_err(|_| ())?;
            Ok::<_, ()>(uuid)
        })
        .await
    };
    let Ok(Ok(uuid)) = resolution else {
        return credential_invalid();
    };
    let q = match parse_activity_query(&raw.0.unwrap_or_default()) {
        Ok(q) => q,
        Err(reason) => return request_invalid(&reason),
    };
    let root = crate::agents::intents_root();
    let outcome = render_activity_in(&root, &uuid, &q);
    activity_http(outcome, &uuid.to_string(), &q)
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    const AGENT_ID: &str = "11111111-1111-4111-8111-111111111111";
    const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
    const OTHER_RECIPIENT: &str = "9XkVj5p8Qh3tWn2rLm6dFb1sYc4gHe0aJu7Ki8mNoPqr";
    const SIG: &str =
        "3aoVja3ms9ypcDqk3ZEozjydJDP3RSYigRdz7rdmFGAtJcRpo4GUud6u2YuTdndXCbvZAn736gF2H8w5NmfdYGRk";

    struct Fix {
        root: PathBuf,
    }
    impl Drop for Fix {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).ok();
        }
    }

    fn fix() -> Fix {
        let root = std::env::temp_dir().join(format!("agentpay-step6-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join(AGENT_ID)).unwrap();
        Fix { root }
    }

    fn hex_of(s: &str) -> String {
        s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn write_slot(f: &Fix, name: &str, intent: serde_json::Value) {
        let path = f.root.join(AGENT_ID).join(format!("{name}.json"));
        fs::write(&path, serde_json::to_vec(&intent).unwrap()).unwrap();
    }

    fn v1(
        f: &Fix,
        key: &str,
        state: &str,
        created: i64,
        amount: u64,
        recipient: &str,
        extra: serde_json::Value,
    ) {
        let mut intent = serde_json::json!({
            "schema_version": 1,
            "agent_id": AGENT_ID,
            "idempotency_key": key,
            "request_fingerprint": format!("{:016x}", key.len()),
            "recipient": recipient,
            "amount_kelvin": amount,
            "state": state,
            "response": null,
            "created_at": created,
            "updated_at": created,
        });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                intent[k] = v.clone();
            }
        }
        write_slot(f, &hex_of(key), intent);
    }

    fn v2(
        f: &Fix,
        key: &str,
        exec_state: &str,
        principal: &str,
        created: i64,
        amount: u64,
        extra: serde_json::Value,
    ) {
        let mut intent = serde_json::json!({
            "schema_version": 2,
            "intent_id": Uuid::new_v4().to_string(),
            "agent_id": AGENT_ID,
            "principal_kind": principal,
            "recipient": RECIPIENT,
            "amount_kelvin": amount,
            "idempotency_key": key,
            "request_fingerprint": format!("{:016x}", key.len() + 1),
            "authz": { "policy_fingerprint": "aabbccddeeff0011", "authorized_at": created },
            "exec_state": exec_state,
            "tx_signature": null,
            "failure": null,
            "response": null,
            "reconciliation": null,
            "created_at": created,
            "updated_at": created,
        });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                intent[k] = v.clone();
            }
        }
        write_slot(f, &hex_of(key), intent);
    }

    fn query(s: &str) -> ActivityQuery {
        parse_activity_query(s).unwrap_or_else(|e| panic!("query {s:?}: {e}"))
    }

    fn id() -> Uuid {
        Uuid::parse_str(AGENT_ID).unwrap()
    }

    fn rendered(f: &Fix, q: &ActivityQuery) -> (Vec<serde_json::Value>, Option<String>) {
        match render_activity_in(&f.root, &id(), q) {
            ActivityOutcome::Rendered(items, cursor) => (items, cursor),
            ActivityOutcome::Rejected(r) => panic!("unexpected reject: {r}"),
            ActivityOutcome::Store => panic!("unexpected store error"),
        }
    }

    // ---- (1) v1 fixtures for every state --------------------------------
    #[test]
    fn step6_v1_all_states_render_one_item_each() {
        let f = fix();
        let states = [
            "pending",
            "confirmed",
            "failed",
            "unknown",
            "reconciled_paid",
            "reconciled_absent",
        ];
        for (n, st) in states.iter().enumerate() {
            v1(
                &f,
                &format!("k1-{st}"),
                st,
                1_790_000_000 + n as i64,
                1_000_000,
                RECIPIENT,
                serde_json::json!({}),
            );
        }
        let (items, cursor) = rendered(&f, &query(""));
        assert_eq!(items.len(), 6, "one item per slot");
        assert!(cursor.is_none());
        let mut names: Vec<&str> = items.iter().map(|i| i["state"].as_str().unwrap()).collect();
        names.sort();
        let mut expected: Vec<&str> = states.to_vec();
        expected.sort();
        assert_eq!(names, expected);
        for item in &items {
            assert_eq!(item["schema_version"], 1);
            assert_eq!(item["principal_kind"], "owner");
            assert!(item["intent_id"].is_null());
            assert!(
                item["authz_bound"].is_null(),
                "v1 items carry no v2-only field"
            );
        }
    }

    // ---- (2) v2 fixtures for every state --------------------------------
    #[test]
    fn step6_v2_all_states_render_one_item_each() {
        let f = fix();
        let states = [
            "pending",
            "confirmed",
            "failed",
            "unknown",
            "reconciled_paid",
            "reconciled_absent",
        ];
        for (n, st) in states.iter().enumerate() {
            v2(
                &f,
                &format!("k2-{st}"),
                st,
                "agent",
                1_790_000_000 + n as i64,
                2_000_000,
                serde_json::json!({}),
            );
        }
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items.len(), 6);
        for item in &items {
            assert_eq!(item["schema_version"], 2);
            assert_eq!(item["principal_kind"], "agent");
            assert!(item["intent_id"].is_string());
            assert_eq!(item["authz_bound"], true);
        }
    }

    // ---- (3) v1 signature extraction (whitelisted dig only) --------------
    #[test]
    fn step6_v1_signature_comes_only_from_the_whitelisted_dig() {
        let f = fix();
        v1(
            &f,
            "k-ok",
            "confirmed",
            1,
            1_000,
            RECIPIENT,
            serde_json::json!({
                "response": {
                    "success": true,
                    "agent_id": AGENT_ID,
                    "payment": {"to": RECIPIENT, "amount_rlo": 0.001, "amount_kelvin": 1_000,
                                 "signature": SIG, "balance_before_rlo": "2 RLO", "balance_after_rlo": null},
                    "secret_note": "must never render"
                }
            }),
        );
        v1(
            &f,
            "k-bad-dig",
            "confirmed",
            2,
            1_000,
            RECIPIENT,
            serde_json::json!({"response": {"payment": {"signature": 123}}}),
        );
        let (items, _) = rendered(&f, &query(""));
        let ok = items
            .iter()
            .find(|i| i["idempotency_slot"] == hex_of("k-ok"))
            .expect("slot");
        assert_eq!(ok["tx_signature"], SIG);
        let blob = serde_json::to_string(ok).unwrap();
        assert!(
            !blob.contains("secret_note"),
            "raw response blob must never render"
        );
        assert!(
            !blob.contains("balance_before"),
            "raw response blob must never render"
        );
        assert!(
            !blob.contains("request_fingerprint"),
            "fingerprint must never render"
        );
        let bad = items
            .iter()
            .find(|i| i["idempotency_slot"] == hex_of("k-bad-dig"))
            .unwrap();
        assert!(
            bad["tx_signature"].is_null(),
            "a non-string dig is not a signature"
        );
    }

    // ---- (4) v2 top-level signature --------------------------------------
    #[test]
    fn step6_v2_uses_top_level_signature_and_signature_filter() {
        let f = fix();
        v2(
            &f,
            "k-sig",
            "unknown",
            "agent",
            1,
            1_000,
            serde_json::json!({"tx_signature": SIG}),
        );
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items[0]["tx_signature"], SIG);
        let (only, _) = rendered(&f, &query(&format!("signature={SIG}")));
        assert_eq!(only.len(), 1);
        let (none, _) = rendered(&f, &query("signature=NopeNopeNope"));
        assert!(none.is_empty(), "signature filter is exact-match");
    }

    // ---- (5) failure mapping ----------------------------------------------
    #[test]
    fn step6_failure_views_map_v1_and_v2() {
        let f = fix();
        v1(
            &f,
            "k-f1",
            "failed",
            1,
            1_000,
            RECIPIENT,
            serde_json::json!({"response": {"http_status": 403, "code": "AGENT_POLICY_DENIED", "message": "human text never rendered here"}}),
        );
        v2(
            &f,
            "k-f2",
            "failed",
            "agent",
            2,
            1_000,
            serde_json::json!({"failure": {"code": "RIALO_RPC_UNAVAILABLE", "http_status": 502}}),
        );
        let (items, _) = rendered(&f, &query("state=failed"));
        assert_eq!(items.len(), 2);
        let v1f = items.iter().find(|i| i["schema_version"] == 1).unwrap();
        assert_eq!(v1f["failure"]["code"], "AGENT_POLICY_DENIED");
        assert_eq!(v1f["failure"]["http_status"], 403);
        let blob = serde_json::to_string(v1f).unwrap();
        assert!(
            !blob.contains("human text"),
            "failure.message is NOT whitelisted"
        );
        let v2f = items.iter().find(|i| i["schema_version"] == 2).unwrap();
        assert_eq!(v2f["failure"]["code"], "RIALO_RPC_UNAVAILABLE");
        v1(&f, "k-p", "pending", 3, 1, RECIPIENT, serde_json::json!({}));
        let (items, _) = rendered(&f, &query("state=pending"));
        assert!(
            items[0]["failure"].is_null(),
            "no failure -> null, never a guess"
        );
    }

    // ---- (6)+(21) reconciliation: one item, evidence passthrough ---------
    #[test]
    fn step6_reconciliation_is_one_item_with_evidence() {
        let f = fix();
        let record = serde_json::json!({
            "method": "tx_lookup",
            "outcome": "paid",
            "tx_signature": SIG,
            "resolved_at": 1_790_000_500,
            "resolver": "owner:tester",
            "evidence": {"block_height": 900, "slot": 777, "block_time": 1_790_000_400i64,
                          "fee": 5000, "meta_err": null, "tx_summary": "tx lookup: executed=true err=null"}
        });
        v1(
            &f,
            "k-r",
            "reconciled_paid",
            1,
            1_000_000,
            RECIPIENT,
            serde_json::json!({"reconciliation": record}),
        );
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(
            items.len(),
            1,
            "reconciliation NEVER creates a second activity row"
        );
        let item = &items[0];
        assert_eq!(item["state"], "reconciled_paid");
        assert_eq!(item["reconciliation"]["outcome"], "paid");
        assert_eq!(item["reconciliation"]["method"], "tx_lookup");
        assert_eq!(item["reconciliation"]["evidence"]["slot"], 777);
        assert_eq!(item["reconciliation"]["tx_signature"], SIG);
        // the identity is still the slot itself
        assert_eq!(item["idempotency_slot"], hex_of("k-r"));

        // an absent terminal likewise stays one item
        let g = fix();
        let absent = serde_json::json!({
            "method": "tx_lookup", "outcome": "absent", "tx_signature": SIG,
            "resolved_at": 2, "resolver": "owner:tester", "evidence": null
        });
        v2(
            &g,
            "k-a",
            "reconciled_absent",
            "agent",
            1,
            1,
            serde_json::json!({"reconciliation": absent}),
        );
        let (items, _) = rendered(&g, &query(""));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["reconciliation"]["outcome"], "absent");
    }

    // ---- (7)+(8) mixed directory, deterministic ordering -----------------
    #[test]
    fn step6_mixed_directory_orders_deterministically() {
        let f = fix();
        v1(
            &f,
            "aaa",
            "confirmed",
            1_790_000_000,
            1,
            RECIPIENT,
            serde_json::json!({}),
        );
        v2(
            &f,
            "bbb",
            "pending",
            "agent",
            1_790_000_001,
            1,
            serde_json::json!({}),
        );
        v1(
            &f,
            "ccc",
            "failed",
            1_790_000_000,
            1,
            RECIPIENT,
            serde_json::json!({}),
        );
        let (items, _) = rendered(&f, &query(""));
        // created_at DESC; ties by key_hex ASC: aaa < ccc
        let slots: Vec<&str> = items
            .iter()
            .map(|i| i["idempotency_slot"].as_str().unwrap())
            .collect();
        assert_eq!(slots[0], hex_of("bbb"));
        assert_eq!(slots[1], hex_of("aaa"));
        assert_eq!(slots[2], hex_of("ccc"));
        // pure projection: byte-identical repeats
        let (again, _) = rendered(&f, &query(""));
        assert_eq!(items, again);
    }

    // ---- (9)+(10)+(11) cursor round-trip, tie-break paging, exhaustion ---
    #[test]
    fn step6_cursor_round_trip_tie_break_and_exhaustion() {
        let f = fix();
        for i in 0..5 {
            v2(
                &f,
                &format!("tie-{i}"),
                "pending",
                "agent",
                1_790_000_000,
                1,
                serde_json::json!({}),
            );
        }
        let (items, cur) = rendered(&f, &query("limit=2"));
        assert_eq!(items.len(), 2);
        let cur = cur.expect("more pages exist");
        let (items2, cur2) = rendered(&f, &query(&format!("limit=2&cursor={cur}")));
        assert_eq!(items2.len(), 2);
        assert_ne!(items2[0]["idempotency_slot"], items[0]["idempotency_slot"]);
        let (items3, cur3) = rendered(&f, &query(&format!("limit=2&cursor={}", cur2.unwrap())));
        assert_eq!(items3.len(), 1);
        assert!(cur3.is_none(), "exhausted pages end with null cursor");
        // the whole walk visits every slot exactly once
        let mut seen: Vec<&str> = items
            .iter()
            .chain(items2.iter())
            .chain(items3.iter())
            .map(|i| i["idempotency_slot"].as_str().unwrap())
            .collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 5);
        // encode/decode is a lossless round-trip
        let c = Cursor {
            v: 1,
            c: 123,
            a: AGENT_ID.to_string(),
            k: "6162".to_string(),
        };
        assert_eq!(decode_cursor(&c.encode()).as_ref(), Some(&c));
    }

    // ---- (12) cursor rejections -------------------------------------------
    #[test]
    fn step6_malformed_unknown_version_and_traversal_cursors_rejected() {
        assert!(decode_cursor("").is_none());
        assert!(decode_cursor("!!!not-base64!!!").is_none());
        assert!(decode_cursor(&b64url_encode(b"not json at all")).is_none());
        let unknown_version = serde_json::json!({"v": 2, "c": 1, "a": AGENT_ID, "k": "6162"});
        assert!(
            decode_cursor(&b64url_encode(
                &serde_json::to_vec(&unknown_version).unwrap()
            ))
            .is_none()
        );
        let extra_field =
            serde_json::json!({"v": 1, "c": 1, "a": AGENT_ID, "k": "6162", "offset": 5});
        assert!(
            decode_cursor(&b64url_encode(&serde_json::to_vec(&extra_field).unwrap())).is_none()
        );
        let traversal = serde_json::json!({"v": 1, "c": 1, "a": "../wallets/1", "k": "6162"});
        assert!(decode_cursor(&b64url_encode(&serde_json::to_vec(&traversal).unwrap())).is_none());
        let uppercase_hex = serde_json::json!({"v": 1, "c": 1, "a": AGENT_ID, "k": "A1"});
        assert!(
            decode_cursor(&b64url_encode(&serde_json::to_vec(&uppercase_hex).unwrap())).is_none()
        );
        let odd_hex = serde_json::json!({"v": 1, "c": 1, "a": AGENT_ID, "k": "61a"});
        assert!(decode_cursor(&b64url_encode(&serde_json::to_vec(&odd_hex).unwrap())).is_none());
        // a cursor bound to a DIFFERENT agent is a typed rejection
        let f = fix();
        v2(&f, "x", "pending", "agent", 1, 1, serde_json::json!({}));
        let foreign = Cursor {
            v: 1,
            c: 9,
            a: Uuid::new_v4().to_string(),
            k: "78".to_string(),
        };
        match render_activity_in(
            &f.root,
            &id(),
            &query(&format!("cursor={}", foreign.encode())),
        ) {
            ActivityOutcome::Rejected(r) => assert!(r.contains("different agent"), "{r}"),
            other => panic!("expected rejection, got {other:?}"),
        }
        // query grammar rejections
        assert!(parse_activity_query("cursor=%21%21").is_err());
        assert!(parse_activity_query("cursor=zzzz_not_valid_base64_url_alphabet!!!").is_err());
    }

    // ---- (13) page size default/max ----------------------------------------
    #[test]
    fn step6_default_and_max_page_sizes() {
        assert_eq!(query("").limit, ACTIVITY_DEFAULT_PAGE_SIZE);
        assert_eq!(query("limit=100").limit, ACTIVITY_MAX_PAGE_SIZE);
        for bad in [
            "limit=0",
            "limit=101",
            "limit=-1",
            "limit=abc",
            "limit=20&limit=30",
        ] {
            assert!(parse_activity_query(bad).is_err(), "must reject: {bad}");
        }
        let f = fix();
        for i in 0..25 {
            v2(
                &f,
                &format!("many-{i:02}"),
                "pending",
                "agent",
                1_790_000_000 - i,
                1,
                serde_json::json!({}),
            );
        }
        let (items, cur) = rendered(&f, &query("limit=20"));
        assert_eq!(items.len(), 20);
        assert!(cur.is_some());
        let (rest, cur2) = rendered(&f, &query(&format!("limit=20&cursor={}", cur.unwrap())));
        assert_eq!(rest.len(), 5);
        assert!(cur2.is_none());
    }

    // ---- (14) owner authentication gate at the handler --------------------
    #[tokio::test]
    async fn step6_owner_lane_requires_session() {
        let (state, _sid) = test_state(9001);
        let resp = agent_activity(
            State(state),
            HeaderMap::new(),
            Path(AGENT_ID.to_string()),
            RawQuery(None),
        )
        .await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "NOT_AUTHENTICATED");
    }

    // ---- (15) foreign/missing/malformed collapse to one verdict ----------
    #[tokio::test]
    async fn step6_owner_lane_collapse_is_indistinguishable() {
        let (state, sid) = test_state(9001);
        let ghost = Uuid::new_v4().to_string();
        for bad in ["../etc/passwd", "not-a-uuid", ghost.as_str(), ""] {
            let resp = agent_activity(
                State(state.clone()),
                cookie(&sid),
                Path(bad.to_string()),
                RawQuery(None),
            )
            .await;
            let (status, json) = envelope(resp).await;
            assert_eq!(status, 404, "id {bad:?}");
            assert_eq!(json["error"]["code"], "AGENT_NOT_FOUND", "id {bad:?}");
        }
        // auth gates run BEFORE query validation: a bad query on an
        // unauthorized agent is still the same indistinguishable 404
        let resp = agent_activity(
            State(state),
            cookie(&sid),
            Path(ghost),
            RawQuery(Some("sort_by=amount".to_string())),
        )
        .await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(json["error"]["code"], "AGENT_NOT_FOUND");
    }

    // ---- typed 400 on unknown filter parameter (after ownership) ---------
    #[test]
    fn step6_unknown_parameters_are_typed_rejections() {
        assert!(parse_activity_query("made_up_param=1").is_err());
        assert!(parse_activity_query("state=bogus").is_err());
        assert!(parse_activity_query("principal=robot").is_err());
        assert!(parse_activity_query("recipient=short").is_err());
        assert!(parse_activity_query("created_at_gte=not-a-time").is_err());
        assert!(parse_activity_query("no_equals_sign").is_err());
        assert!(parse_activity_query("&limit=2").is_err());
    }

    // ---- (16) credential auth behavior at the handler --------------------
    #[tokio::test]
    async fn step6_credential_lane_stable_401() {
        let mut headers = HeaderMap::new();
        // absent header
        let resp = agent_trigger_activity(headers.clone(), RawQuery(None)).await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "AGENT_CREDENTIAL_INVALID");
        // wrong shape
        headers.insert(
            "x-agent-credential",
            axum::http::HeaderValue::from_str("short").unwrap(),
        );
        let resp = agent_trigger_activity(headers.clone(), RawQuery(None)).await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "AGENT_CREDENTIAL_INVALID");
        // two values
        headers.insert(
            "x-agent-credential",
            axum::http::HeaderValue::from_str(&"0".repeat(64)).unwrap(),
        );
        headers.append(
            "x-agent-credential",
            axum::http::HeaderValue::from_str(&"1".repeat(64)).unwrap(),
        );
        let resp = agent_trigger_activity(headers, RawQuery(None)).await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "AGENT_CREDENTIAL_INVALID");
    }

    // ---- (17) credential resolves one agent; only its own dir is read ----
    #[test]
    fn step6_only_the_resolved_agents_own_directory_is_read() {
        let f = fix();
        v2(&f, "mine", "pending", "agent", 1, 1, serde_json::json!({}));
        // a foreign principal's directory does not exist: empty page, no
        // error, no enumeration signal
        let foreign = Uuid::new_v4();
        match render_activity_in(&f.root, &foreign, &query("")) {
            ActivityOutcome::Rendered(items, cursor) => {
                assert!(items.is_empty());
                assert!(cursor.is_none());
            }
            other => panic!("{other:?}"),
        }
        // the resolved agent still sees exactly its own slot
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["agent_id"], AGENT_ID);
    }

    // ---- (18) corrupt ledger file fails the whole page closed -------------
    #[test]
    fn step6_corrupt_ledger_file_is_store_error_not_silent_drop() {
        let f = fix();
        v2(&f, "good", "pending", "agent", 1, 1, serde_json::json!({}));
        write_slot(&f, &hex_of("bad"), serde_json::json!({"schema_version": 2})); // truncated record
        match render_activity_in(&f.root, &id(), &query("")) {
            ActivityOutcome::Store => {}
            other => panic!("expected Store, got {other:?}"),
        }
        // unparseable JSON too
        fs::write(
            f.root
                .join(AGENT_ID)
                .join(format!("{}.json", hex_of("raw"))),
            b"{ not json",
        )
        .unwrap();
        assert!(matches!(
            render_activity_in(&f.root, &id(), &query("")),
            ActivityOutcome::Store
        ));
    }

    // ---- (19) unknown schema/non-hex/non-json names are inert -------------
    #[test]
    fn step6_unknown_schema_non_hex_and_non_json_names_are_inert() {
        let f = fix();
        v2(&f, "real", "pending", "agent", 1, 1, serde_json::json!({}));
        write_slot(
            &f,
            &hex_of("ghost"),
            serde_json::json!({"schema_version": 99, "agent_id": AGENT_ID}),
        );
        write_slot(&f, "zzz", serde_json::json!({"schema_version": 2})); // non-hex stem
        fs::write(f.root.join(AGENT_ID).join("README.txt"), b"x").unwrap(); // not .json
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items.len(), 1, "only the real ledger entry is activity");
        assert_eq!(items[0]["idempotency_slot"], hex_of("real"));
    }

    // ---- (20) one slot = one item; replay is not an event -----------------
    #[test]
    fn step6_one_file_one_item_replays_never_duplicate() {
        let f = fix();
        v1(
            &f,
            "dup",
            "confirmed",
            1,
            1_000,
            RECIPIENT,
            serde_json::json!({
                "response": {"payment": {"signature": SIG}}
            }),
        );
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items.len(), 1);
        let (filtered, _) = rendered(&f, &query("state=confirmed"));
        assert_eq!(filtered.len(), 1);
        // key/filename divergence is corruption, not a second slot
        let g = fix();
        let path = g
            .root
            .join(AGENT_ID)
            .join(format!("{}.json", hex_of("liar")));
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1, "agent_id": AGENT_ID, "idempotency_key": "truth",
                "request_fingerprint": "0000000000000000", "recipient": RECIPIENT,
                "amount_kelvin": 1, "state": "pending", "response": null,
                "created_at": 1, "updated_at": 1
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            render_activity_in(&g.root, &id(), &query("")),
            ActivityOutcome::Store
        ));
    }

    // ---- (22)+(23) read-only invariance + zero temp files -----------------
    #[test]
    fn step6_rendering_never_mutates_the_ledger_and_leaves_no_debris() {
        let f = fix();
        v1(
            &f,
            "a",
            "confirmed",
            1,
            1,
            RECIPIENT,
            serde_json::json!({"response": {"payment": {"signature": SIG}}}),
        );
        v2(
            &f,
            "b",
            "unknown",
            "agent",
            2,
            2,
            serde_json::json!({"tx_signature": SIG}),
        );
        fs::write(f.root.join(AGENT_ID).join("extra.txt"), b"untracked").unwrap();
        let before = snapshot(&f.root.join(AGENT_ID));
        for _ in 0..3 {
            let _ = render_activity_in(&f.root, &id(), &query("limit=1&state=confirmed"));
            let _ = render_activity_in(&f.root, &id(), &query(""));
        }
        let after = snapshot(&f.root.join(AGENT_ID));
        assert_eq!(
            before, after,
            "bytes+mtime identical across GET-equivalents"
        );
        let debris: Vec<_> = fs::read_dir(&f.root.join(AGENT_ID))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp"))
            .collect();
        assert!(debris.is_empty(), "zero temp files");
    }

    fn snapshot(dir: &std::path::Path) -> Vec<(String, u64, std::time::SystemTime)> {
        use std::hash::{Hash, Hasher};
        let mut out = Vec::new();
        // a missing ledger directory is a legitimately empty store, not a
        // test error — snapshot simply comes back empty
        let entries = match fs::read_dir(dir) {
            Ok(iter) => iter.flatten().collect::<Vec<_>>(),
            Err(_) => return out,
        };
        for entry in entries {
            let meta = entry.metadata().unwrap();
            let bytes = fs::read(entry.path()).unwrap_or_default();
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut hasher);
            out.push((
                entry.file_name().to_string_lossy().to_string(),
                hasher.finish(),
                meta.modified().unwrap(),
            ));
        }
        out.sort();
        out
    }

    // ---- (24) structural purity of the production section -----------------
    #[test]
    fn step6_structural_activity_module_is_read_only_and_money_free() {
        let src = include_str!("activity.rs");
        let production = src.split("#[cfg(test)]").next().unwrap();
        // strip doc/line comments so prose about the boundaries never
        // trips the token scan (established pattern)
        let stripped: String = production
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("///") || t.starts_with("//!"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in [
            "fs::write",
            "File::create",
            "create_dir",
            "rename(",
            "remove_",
            "set_permissions",
            "store_lock",
            "reserve_spend",
            "release_spend",
            "ops.transfer",
            ".transfer(",
            "ops.balance",
            ".balance(",
            "airdrop",
            "faucet",
            "claim_intent",
            "update_intent",
            "reconcile_intent",
            "issue_credential",
            "revoke",
            "rotate",
            "payment_lock",
            "keypair",
            "wallet_path_for",
            "load_or_create_wallet",
            "agent_wallets",
            "PHC",
            "argon",
            "reqwest",
            "transaction_lookup",
            "signatures_for_address",
            "rpc_read",
            "offset",
        ] {
            assert!(
                !stripped.contains(forbidden),
                "activity production code references forbidden token: {forbidden}"
            );
        }
        // the authoritative fail-closed readers and the typed envelope codes
        for required in [
            "read_intent(",
            "read_intent_v2(",
            "AGENT_CREDENTIAL_INVALID",
            "ACTIVITY_REQUEST_INVALID",
            "AGENT_NOT_FOUND",
            "NOT_AUTHENTICATED",
            "AGENT_STORE_ERROR",
        ] {
            assert!(
                stripped.contains(required),
                "activity production code must use {required}"
            );
        }
    }

    // ---- filters matrix ----------------------------------------------------
    #[test]
    fn step6_filter_matrix() {
        let f = fix();
        v1(
            &f,
            "a",
            "confirmed",
            10,
            1_000,
            RECIPIENT,
            serde_json::json!({"response": {"payment": {"signature": SIG}}}),
        );
        v2(
            &f,
            "b",
            "pending",
            "agent",
            20,
            2_000,
            serde_json::json!({}),
        );
        v1(
            &f,
            "c",
            "failed",
            30,
            1_000,
            OTHER_RECIPIENT,
            serde_json::json!({"response": {"http_status": 422, "code": "AGENT_PAYMENT_REQUEST_INVALID"}}),
        );
        let (items, _) = rendered(&f, &query("state=confirmed"));
        assert_eq!(items.len(), 1);
        let (items, _) = rendered(&f, &query("principal=agent"));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["idempotency_slot"], hex_of("b"));
        let (items, _) = rendered(&f, &query(&format!("recipient={RECIPIENT}")));
        assert_eq!(items.len(), 2);
        let (items, _) = rendered(
            &f,
            &query(&format!("recipient={OTHER_RECIPIENT}&state=failed")),
        );
        assert_eq!(items.len(), 1);
        let (items, _) = rendered(&f, &query("created_at_gte=20&created_at_lt=30"));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["idempotency_slot"], hex_of("b"));
        let (items, _) = rendered(&f, &query("amount_kelvin=1000"));
        assert_eq!(items.len(), 2);
    }

    // ---- DTO whitelist sweep ------------------------------------------------
    #[test]
    fn step6_dto_never_carries_secrets_or_store_internals() {
        let f = fix();
        v1(
            &f,
            "s1",
            "confirmed",
            1,
            1_000,
            RECIPIENT,
            serde_json::json!({
                "response": {"payment": {"signature": SIG}, "http_status": 200, "code": "X",
                             "agent_wallet": "/abs/path/keypair.json", "phc": "$argon2id$fake$hash"}
            }),
        );
        v2(
            &f,
            "s2",
            "confirmed",
            "agent",
            2,
            1_000,
            serde_json::json!({
                "tx_signature": SIG,
                "authz": {"policy_fingerprint": "deadbeefdeadbeef", "authorized_at": 2},
                "response": {"payment": {"signature": SIG}}
            }),
        );
        let (items, _) = rendered(&f, &query(""));
        let blob = serde_json::to_string(&items).unwrap();
        for forbidden in [
            "keypair",
            "argon",
            "deadbeefdeadbeef",
            "/abs/path",
            "policy_fingerprint",
            "artifact",
        ] {
            assert!(
                !blob.contains(forbidden),
                "secret-shaped token leaked: {forbidden}"
            );
        }
        for item in &items {
            for k in item.as_object().unwrap().keys() {
                assert!(
                    [
                        "schema_version",
                        "intent_id",
                        "agent_id",
                        "principal_kind",
                        "recipient",
                        "amount_kelvin",
                        "amount_rlo",
                        "state",
                        "tx_signature",
                        "failure",
                        "reconciliation",
                        "created_at",
                        "updated_at",
                        "idempotency_slot",
                        "authz_bound",
                    ]
                    .contains(&k.as_str()),
                    "non-whitelisted DTO field: {k}"
                );
            }
        }
    }

    // ---- money representation invariants -----------------------------------
    #[test]
    fn step6_amount_rlo_is_derived_from_the_canonical_kelvin() {
        let f = fix();
        v2(
            &f,
            "m",
            "confirmed",
            "agent",
            1,
            1_000_000,
            serde_json::json!({}),
        );
        let (items, _) = rendered(&f, &query(""));
        assert_eq!(items[0]["amount_kelvin"], 1_000_000);
        assert_eq!(items[0]["amount_rlo"], 0.001);
        assert_eq!(
            crate::agents::rlo_balance_to_kelvin(items[0]["amount_rlo"].as_f64().unwrap()),
            Some(1_000_000),
            "the single converter must agree with the derived display"
        );
    }

    // ---- percent-decoding is bounded to the encoded grammar ------------------
    #[test]
    fn step6_percent_encoded_values_decode_without_smuggling() {
        // the split happens on the ENCODED form: %26 decodes INSIDE the
        // value and can never spawn a second parameter — and a decoded
        // value containing '&' matches no real signature (empty page)
        let q = parse_activity_query("signature=a%26state%3Dpending").expect("single param");
        assert_eq!(q.signature.as_deref(), Some("a&state=pending"));
        assert!(q.state.is_none(), "no smuggled state filter");
        // a legit recipient with case-mixed letters decodes and validates
        let q = parse_activity_query(&format!("recipient={RECIPIENT}")).unwrap();
        assert_eq!(q.recipient.as_deref(), Some(RECIPIENT));
    }

    // ---- (25) literal route coexistence (matchit) ---------------------------
    #[test]
    fn step6_route_literals_coexist_without_panic() {
        async fn dummy() -> StatusCode {
            StatusCode::IM_A_TEAPOT
        }
        let build = || {
            axum::Router::<()>::new()
                .route("/api/agents/{id}", axum::routing::get(dummy))
                // PHASE 7 — leaderboard: literal sibling of the {id} route;
                // matchit rejects static/param conflicts at construction, so
                // adding it here keeps the REAL router's shape pinned.
                .route("/api/agents/leaderboard", axum::routing::get(dummy))
                .route("/api/agents/{id}/balance", axum::routing::get(dummy))
                .route("/api/agents/{id}/activity", axum::routing::get(dummy))
                .route("/api/agents/{id}/payments", axum::routing::post(dummy))
                .route(
                    "/api/agents/{id}/payments/reconcile",
                    axum::routing::post(dummy),
                )
                .route("/api/agents/triggers/payments", axum::routing::post(dummy))
                .route(
                    "/api/agents/triggers/payments/reconcile",
                    axum::routing::post(dummy),
                )
                .route(
                    "/api/agents/triggers/payments/activity",
                    axum::routing::get(dummy),
                )
        };
        let _router = build();
    }

    // ---- happy-path owner render through the real production-shaped dir ----
    #[tokio::test]
    async fn step6_owner_lane_renders_success_envelope_for_own_agent() {
        // NOTE: this exercises `agent_activity` against the PRODUCTION
        // intents root WITHOUT touching it: the resolved agent must own at
        // least a real record. We assert only the envelope shape and that
        // no mutation happened (hash comparison of the root dir).
        let agents_root = crate::agents::agents_dir();
        let mut owned: Option<(u64, String)> = None;
        if let Ok(entries) = fs::read_dir(&agents_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(agent) = crate::agents::read_agent(&path) {
                    owned = Some((agent.owner_user_id, agent.agent_id.clone()));
                    break;
                }
            }
        }
        let Some((owner_id, agent_id)) = owned else {
            return; // empty store: nothing to verify
        };
        let (state, sid) = test_state(owner_id);
        let before = snapshot(&crate::agents::intents_root().join(&agent_id));
        let resp = agent_activity(
            State(state),
            cookie(&sid),
            Path(agent_id.clone()),
            RawQuery(Some("limit=100".to_string())),
        )
        .await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 200);
        assert_eq!(json["success"], true);
        assert_eq!(json["agent_id"], agent_id.as_str());
        assert!(json["items"].is_array());
        assert!(json["next_cursor"].is_null() || json["next_cursor"].is_string());
        let after = snapshot(&crate::agents::intents_root().join(&agent_id));
        assert_eq!(before, after, "GET activity must not mutate the ledger");
    }

    // ---- handler plumbing (mirrors the step-8 test state, never real RPC) --
    fn test_state(user_id: u64) -> (crate::AppState, String) {
        let state = crate::AppState {
            client: reqwest::Client::new(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            redirect_uri: "http://localhost".to_string(),
            oauth_states: Arc::new(Mutex::new(std::collections::HashMap::new())),
            sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
            wallets: Arc::new(Mutex::new(std::collections::HashMap::new())),
            rialo: Arc::new(crate::rialo::RialoConfig {
                cli: PathBuf::from("/nonexistent/step6-test-rialo-cli"),
                rpc_url: "http://127.0.0.1:1".to_string(),
                program_id: None,
                program_dir: PathBuf::from("artifact"),
            }),
        };
        let sid = Uuid::new_v4().to_string();
        state.sessions.lock().unwrap().insert(
            sid.clone(),
            crate::GithubUser {
                id: user_id,
                login: "tester".to_string(),
                name: None,
                avatar_url: None,
            },
        );
        (state, sid)
    }

    fn cookie(sid: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("agentpay_session={sid}")).unwrap(),
        );
        headers
    }

    async fn envelope(resp: Response) -> (u16, serde_json::Value) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        (
            status,
            serde_json::from_slice(&bytes).expect("JSON envelope"),
        )
    }
}
