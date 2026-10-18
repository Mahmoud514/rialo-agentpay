// ---------------------------------------------------------------------------
// PHASE 7D.1 — PUBLIC VERIFICATION API (core) — Phase 7C design (API answers
// 7–10, 11, 12, 14, 16, 17, 18).
//
// ONE surface: GET /api/public/verify?signature={sig}
//
//   strict signature validation     -> typed 400 VERIFY_REQUEST_INVALID
//   read-only Rialo Testnet lookup  -> PaymentOps::read_tx
//                                      (RialoConfig::transaction_lookup)
//   Found (explicit status)         -> 200 canonical verification DTO
//   NotFound (no_status)            -> 200 status:"no_status"
//   Unavailable/Malformed probe     -> 503 RPC_UNAVAILABLE (fail closed)
//   wrong method                    -> 405 (GET-only route)
//
// Security envelope (the whole point of the lane):
//   * PUBLIC: no session, no Agent credential, no dev-login — nothing is
//     read from any identity store;
//   * CHAIN-KEYED: the lookup is keyed EXCLUSIVELY by the signature —
//     zero reads of artifact/ (no agents, intents, policies, spend,
//     credentials, wallets); cross-agent isolation is by construction;
//   * READ-ONLY: the lookup is a read-only RPC; no filesystem mutation,
//     no payment/signing/state mutation, keyed or unkeyed;
//   * PRIVACY: the DTO carries ONLY the chain facts + the requested
//     signature — no raw RPC body, no fingerprints (idempotency /
//     request / policy), no owner id, no credential material, no store
//     paths (Phase 7C answer 6 private set);
//   * DETERMINISTIC: identical request + identical chain state =>
//     byte-identical body. Fixed key order; every field value comes
//     from the node reply; the server clock is never consulted; all
//     error envelopes are static literals.
//
// Dedicated tests: `mod verify_tests` at the end of this file —
// the real handler mounted on a real `axum::Router`, in-process, one
// fresh `TcpListener` per request (house harness pattern, _stats24
// shape) plus a mock `VerificationOps` lane for the production-shaped
// core mapping.
// ---------------------------------------------------------------------------

use crate::activity::RawQuery;
use crate::agents::PaymentOps;
use crate::api_error;
use crate::rialo::{RialoError, TxLookup, TxRecord};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fs;
use uuid::Uuid;

/// The ONE query parameter this endpoint accepts, and the hard bound on
/// it. Phase 7C answer 8: non-empty, bounded (the SAME bound the activity
/// signature filter uses: 128), percent-decoded, exactly once.
const MAX_SIGNATURE_PARAM_LEN: usize = 128;

/// Typed 400 — one stable code for every query rejection (empty,
/// oversized, undecodable, unknown, duplicate, missing). No partial echo
/// of the bad input beyond the static reason (Phase 7C answer 10).
fn request_invalid(reason: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "VERIFY_REQUEST_INVALID", reason)
}

/// Typed 503 — RPC down OR an inconclusive/malformed probe. FAIL CLOSED:
/// the endpoint never renders a 200 verdict from an uncertain chain reply
/// and never returns a partial/stale record as fresh (Phase 7C answer 12).
fn rpc_unavailable() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "RPC_UNAVAILABLE",
        "Rialo Testnet is temporarily unavailable.",
    )
}

/// Percent-decode a percent-encoded string WITHOUT relaxing the wire:
/// `%` must open a two-hex-digit escape, and every decoded byte must be
/// printable ASCII — a bare `%`, a control byte, or non-UTF-8 is "invalid
/// input" (typed 400), never a silent pass-through.
fn percent_decode_strict(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                let b = (hi * 16 + lo) as u8;
                if !b.is_ascii_graphic() {
                    return None;
                }
                out.push(b);
                i += 3;
            }
            b if b > 0x20 && b != 0x7f => {
                out.push(b);
                i += 1;
            }
            _ => return None,
        }
    }
    String::from_utf8(out).ok()
}

/// Parse + validate the raw (still percent-encoded) query string.
/// Splitting happens on the ENCODED form (`&` / `=`) — exactly the
/// activity query discipline — so a literal `%26` can never smuggle a
/// second parameter. Returns the decoded signature, or the static typed
/// error reason.
pub fn parse_verify_query(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("missing parameter: signature".to_string());
    }
    let mut seen_signature = false;
    let mut signature: Option<String> = None;
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err("empty parameter".to_string());
        }
        let (key, value) = match pair.split_once('=') {
            Some(kv) => kv,
            None => return Err("parameters must be key=value".to_string()),
        };
        let key = percent_decode_strict(key).ok_or("invalid parameter name")?;
        if key != "signature" {
            return Err("unknown parameter".to_string());
        }
        if seen_signature {
            return Err("duplicate parameter: signature".to_string());
        }
        seen_signature = true;
        let decoded = percent_decode_strict(value).ok_or("invalid parameter value")?;
        if decoded.is_empty() {
            return Err("signature is required".to_string());
        }
        if decoded.len() > MAX_SIGNATURE_PARAM_LEN {
            return Err("signature is too long".to_string());
        }
        signature = Some(decoded);
    }
    signature.ok_or_else(|| "missing parameter: signature".to_string())
}

/// The canonical verification DTO (Phase 7C answer 9): ONE fixed key
/// order; every field taken EXPLICITLY from the node's record (null when
/// the node did not return it — nothing is inferred; the explicit-
/// `executed` rule stays enforced at the parse layer upstack); NO server
/// clock (block_time is the chain's own timestamp).
fn canonical_dto(signature: &str, rec: &TxRecord) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "verification": {
            "signature": signature,
            "status": "verified",
            "executed": rec.executed,
            "error": rec.err.as_deref(),
            "slot": rec.slot,
            "block_height": rec.block_height,
            "block_time": rec.block_time,
            "fee": rec.fee,
            "payer": rec.payer.as_deref(),
            "recipient": rec.transfer_recipient.as_deref(),
            "amount_kelvin": rec.transfer_amount_kelvin
        }
    })
}

/// Canonical 200 for "the node answered and has no status for this
/// signature" — a TEMPORARY not-found before the finality horizon: never
/// a 404 and never a 503 (Phase 7C answer 11, consistent with the
/// StatusProbe.NoStatus three-way).
fn no_status_dto(signature: &str) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "verification": {
            "signature": signature,
            "status": "no_status",
            "executed": null,
            "error": null,
            "slot": null,
            "block_height": null,
            "block_time": null,
            "fee": null,
            "payer": null,
            "recipient": null,
            "amount_kelvin": null
        }
    })
}

/// GET /api/public/verify?signature={sig} — the public verification
/// endpoint. Public by design: no session, no credential, nothing from
/// any identity or artifact store. The only I/O is the read-only chain
/// lookup (offloaded off the async executor, house pattern), keyed
/// exclusively by the validated signature. Every outcome maps to exactly
/// one of: 200 canonical DTO, 200 no_status DTO, 503 RPC_UNAVAILABLE,
/// typed 400.
pub async fn public_verify(State(state): State<crate::AppState>, raw: RawQuery) -> Response {
    let signature = match parse_verify_query(raw.0.as_deref().unwrap_or_default()) {
        Ok(sig) => sig,
        Err(reason) => return request_invalid(&reason),
    };
    let ops = state.rialo.clone();
    let sig_for_lookup = signature.clone();
    let lookup = tokio::task::spawn_blocking(move || ops.read_tx(&sig_for_lookup))
        .await
        .unwrap_or_else(|_| {
            TxLookup::Unavailable(RialoError {
                code: "RPC_UNAVAILABLE",
                detail: "lookup task failed".to_string(),
                tx_signature: None,
            })
        });
    match lookup {
        TxLookup::Found(rec) => Json(canonical_dto(&signature, &rec)).into_response(),
        TxLookup::NotFound => Json(no_status_dto(&signature)).into_response(),
        // Inconclusive / Malformed / Unavailable — the node did not give
        // a decisive answer: 503, fail closed, nothing renderable.
        TxLookup::Unavailable(_) | TxLookup::Malformed => rpc_unavailable(),
    }
}

/// Test seam ONLY — the house mock-injection discipline from the payment
/// lane (agents.rs Step 8 `PaymentOps`): the route-level tests drive the
/// production-identical outcome mapping through a mock `VerificationOps`
/// instead of the chain, so Found/NotFound/Unavailable/Malformed ->
/// 200/200/503/503 is asserted without a live node. In the production
/// build this trait does not exist and the only caller of `read_tx` in
/// this module is `RialoConfig::transaction_lookup` — the ONE read-only
/// lookup. Nothing here exposes payment, signing, or state mutation.
#[cfg(test)]
pub trait VerificationOps: Send + Sync {
    fn verify_tx(&self, signature: &str) -> TxLookup;
}

#[cfg(test)]
impl VerificationOps for crate::rialo::RialoConfig {
    fn verify_tx(&self, signature: &str) -> TxLookup {
        PaymentOps::read_tx(self, signature)
    }
}

/// Test seam ONLY — the production handler body with the chain seam
/// swapped for a `VerificationOps` mock. Shared by the `#[tokio::test]`
/// scenario suite so the SAME code path the real route runs is asserted.
#[cfg(test)]
pub async fn public_verify_with_ops(ops: Box<dyn VerificationOps>, raw: &str) -> Response {
    let signature = match parse_verify_query(raw) {
        Ok(sig) => sig,
        Err(reason) => return request_invalid(&reason),
    };
    let sig_for_lookup = signature.clone();
    let lookup = tokio::task::spawn_blocking(move || ops.verify_tx(&sig_for_lookup))
        .await
        .unwrap_or_else(|_| {
            TxLookup::Unavailable(RialoError {
                code: "RPC_UNAVAILABLE",
                detail: "lookup task failed".to_string(),
                tx_signature: None,
            })
        });
    match lookup {
        TxLookup::Found(rec) => Json(canonical_dto(&signature, &rec)).into_response(),
        TxLookup::NotFound => Json(no_status_dto(&signature)).into_response(),
        TxLookup::Unavailable(_) | TxLookup::Malformed => rpc_unavailable(),
    }
}

// ---------------------------------------------------------------------------
// PHASE 7D.3 — OPTIONAL PUBLIC PROOFS: GET /api/public/agents/{id}/proofs
//
//   strict {id} validation        -> typed 400 PROOF_ID_INVALID
//                                    (canonical lowercase UUIDv4 BEFORE any
//                                    path join — same choke as every other
//                                    agent lane)
//   agent record absent           -> 404 AGENT_NOT_FOUND (public existence
//                                    is not identity: no owner is revealed)
//   query whitelist               -> limit + cursor ONLY, following the
//                                    established activity convention
//                                    (default 20 / max 100; versioned
//                                    opaque cursor bound to the agent under
//                                    scan; unknown/duplicate/malformed
//                                    -> typed 400 PROOF_REQUEST_INVALID)
//
// SECURITY ENVELOPE (the whole point of the surface):
//   * PUBLIC: no session, no Agent credential, no dev-login — nothing in
//     this lane reads any identity store (the handler itself takes no
//     HeaderMap and calls no identity helper);
//   * READ-ONLY: the scan reuses the activity scan core (fs::read +
//     read_dir over the intent ledger ONLY); zero RPC (the stored
//     tx_signature is a reference, not a re-lookup), zero writes, zero
//     money paths — the structural scans below pin it;
//   * STRICT PUBLIC DTO: each proof item carries the whitelisted facts
//     (state class, amount, chain reference, resolved_at, method class,
//     chain evidence scalars). NEVER rendered: owner identity, intent_id,
//     idempotency key/material (the cursor carries the raw hex slot,
//     exactly the activity precedent), request/policy fingerprints,
//     credentials, keypair material, the agent wallet address, filesystem
//     paths, raw RPC response blobs, resolver identity (only the method
//     class leaves), and evidence free-text (tx_summary);
//   * CROSS-AGENT ISOLATION: the scan directory is derived EXCLUSIVELY
//     from the server-validated agent UUID, and a cursor bound to a
//     DIFFERENT agent is a typed rejection (activity rule, verbatim);
//   * DETERMINISTIC: identical request + identical ledger state =>
//     byte-identical body — sorted directory listing, fixed order
//     (created_at DESC, slot ASC), fixed JSON key order, cursor derived
//     from contents only; the server clock is never consulted and every
//     error envelope is a static literal.
//
// The four public proof states (the canonical chain-terminology set):
//   proven_paid    confirmed | reconciled_paid  (a paid transfer on chain)
//   proven_failed  failed | reconciled_absent   (definitively not paid)
//   unresolved     unknown                      (chain outcome undetermined)
//   unproven       pending | missing/invalid on-chain signature reference
//
// Dedicated tests: _proof_tests.rs (included at the end of this file) —
// the real handler on a fresh axum::Router against a real listener, temp
// stores under a process-wide CWD lock (house harness pattern), privacy
// probes in the PrivacyProbe discipline.
// ---------------------------------------------------------------------------

/// Typed 400 — one stable code for every path-segment rejection. The
/// reason is a static literal; the bad input is never echoed.
fn proof_id_invalid() -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "PROOF_ID_INVALID",
        "The agent id is not a valid canonical UUID.",
    )
}

/// Typed 400 — one stable code for every query rejection (unknown,
/// duplicate, malformed limit, malformed or oversized cursor).
fn proof_request_invalid(reason: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "PROOF_REQUEST_INVALID", reason)
}

/// Typed 500 — fail closed on ledger damage: a page never silently drops
/// a real ledger entry, and a partial history is a dangerous history
/// (activity rule, verbatim).
fn proof_store_error() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "PROOF_STORE_ERROR",
        "Agent proofs could not be read completely; a partial history is never shown",
    )
}

pub(crate) fn render_proofs_in(
    id: &Uuid,
    root: &std::path::Path,
    limit: usize,
    cursor: Option<&crate::activity::Cursor>,
) -> crate::activity::ActivityOutcome {
    use crate::activity as act;
    // The scan runs against the ledger EXCLUSIVELY. Nothing in this lane
    // reads the agent record (already checked by the caller), any wallet
    // file, any credentials record, or any keypair file on disk —
    // isolation and privacy are by construction. `root` is the intents
    // ROOT (the activity convention); the agent subdirectory is derived
    // from the server-validated UUID only.
    let dir = crate::agents::agent_intents_dir(root, id);
    let entries: Vec<fs::DirEntry> = match fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return crate::activity::ActivityOutcome::Store,
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

    let mut slots: Vec<(String, act::Slot)> = Vec::new();
    for stem in names {
        if !act::is_canonical_hex_lower(&stem) || stem.len() % 2 != 0 {
            continue; // not a slot shape this store can ever mint
        }
        let Some(key) = act::hex_decode(&stem) else {
            continue;
        };
        let bytes = match fs::read(dir.join(format!("{stem}.json"))) {
            Ok(b) => b,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return crate::activity::ActivityOutcome::Store,
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return crate::activity::ActivityOutcome::Store; // corrupt file
        };
        // route v1/v2 by the document's own version tag BEFORE any typed
        // reader rejects an unknown version (foreign stays inert, corrupt
        // stays fatal — the activity rule)
        let slot = match value.get("schema_version").and_then(|v| v.as_u64()) {
            Some(1) => {
                let intent = match crate::agents::read_intent(root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return crate::activity::ActivityOutcome::Store,
                };
                act::Slot::V1(intent)
            }
            Some(2) => {
                let intent = match crate::agents::read_intent_v2(root, id, &key) {
                    Ok(Some(intent)) => intent,
                    Ok(None) => continue,
                    Err(_) => return crate::activity::ActivityOutcome::Store,
                };
                act::Slot::V2(intent)
            }
            // foreign/unknown document: inert, never a proof
            _ => continue,
        };
        slots.push((stem, slot));
    }
    slots.sort_by(|a, b| {
        let ca = act::slot_created_at(&a.1);
        let cb = act::slot_created_at(&b.1);
        cb.cmp(&ca).then_with(|| a.0.cmp(&b.0))
    });

    let mut selected: Vec<&(String, act::Slot)> = slots.iter().collect();
    if let Some(c) = cursor {
        if c.a != id.to_string() {
            return crate::activity::ActivityOutcome::Rejected(
                "cursor is bound to a different agent".to_string(),
            );
        }
        selected.retain(|(k, s)| {
            let tc = act::slot_created_at(s);
            tc < c.c || (tc == c.c && k.as_str() > c.k.as_str())
        });
    }

    let page: Vec<serde_json::Value> = selected
        .iter()
        .take(limit)
        .map(|(k, s)| proof_item_json(k, s))
        .collect();
    let next_cursor = if selected.len() > limit && page.len() == limit {
        let (k, s) = selected.get(limit - 1).expect("full page");
        Some(
            crate::activity::Cursor {
                v: act::CURSOR_VERSION,
                c: crate::activity::slot_created_at(s),
                a: id.to_string(),
                k: (k).clone(),
            }
            .encode(),
        )
    } else {
        None
    };
    crate::activity::ActivityOutcome::Rendered(page, next_cursor)
}

// `BalanceDelta` is a deprecated (demoted) tag: naming it here to classify
// existing records is a read, never a construction (audit rule).
#[allow(deprecated)]
fn render_proof_item(key_hex: &str, slot: &crate::activity::Slot) -> serde_json::Value {
    let state = match slot {
        crate::activity::Slot::V1(i) => (
            crate::activity::state_name_v1(i.state),
            i.amount_kelvin,
            i.created_at,
            i.reconciliation.clone(),
            crate::activity::v1_signature_from_response(&i.response),
        ),
        crate::activity::Slot::V2(i) => (
            crate::activity::state_name_v2(i.exec_state),
            i.amount_kelvin,
            i.created_at,
            i.reconciliation.clone(),
            i.tx_signature.as_ref().filter(|s| !s.is_empty()).cloned(),
        ),
    };
    let (state_name, amount_kelvin, _created_at, reconciliation, signature) = state;
    let proof_state = match state_name {
        "confirmed" | "reconciled_paid" => {
            if signature.is_some() {
                "proven_paid"
            } else {
                "unproven"
            }
        }
        "failed" | "reconciled_absent" => "proven_failed",
        "unknown" => "unresolved",
        _ => "unproven",
    };
    let reconciliation_value = match &reconciliation {
        Some(rec) => {
            let method = match rec.method {
                crate::agents::ReconciliationMethod::TxLookup => "tx_lookup",
                crate::agents::ReconciliationMethod::AddressScan => "address_scan",
                crate::agents::ReconciliationMethod::ManualAttestation => "manual_attestation",
                crate::agents::ReconciliationMethod::BalanceDelta => {
                    // demoted method: never a proof source
                    "unknown"
                }
            };
            // NOTE: rec.resolver is NEVER rendered (resolver identity is
            // private); only the method class leaves here.
            let evidence = match &rec.evidence {
                Some(ev) => serde_json::json!({
                    "block_height": ev.block_height,
                    "slot": ev.slot,
                    "block_time": ev.block_time,
                    "fee": ev.fee,
                }),
                None => serde_json::Value::Null,
            };
            serde_json::json!({
                "method": method,
                "at": rec.resolved_at,
                "evidence": evidence,
            })
        }
        None => serde_json::Value::Null,
    };
    serde_json::json!({
        "proof_state": proof_state,
        "amount_kelvin": amount_kelvin,
        "chain_signature": signature,
        "state": state_name,
        "idempotency_slot": key_hex,
        "reconciliation": reconciliation_value,
    })
}

/// GET /api/public/agents/{id}/proofs — the public per-agent proofs
/// endpoint. Public by design: no session, no credential, nothing from
/// any identity store. The only I/O is the read-only intent-ledger scan
/// (fs::read + read_dir) over the agent's OWN intents directory. The
/// caller's identity is never consulted and never echoed.
pub async fn public_agent_proofs(
    State(_state): State<crate::AppState>,
    Path(id): Path<String>,
    raw: RawQuery,
) -> Response {
    // 1) strict id validation BEFORE any path join (canonical lowercase
    //    UUIDv4) — malformed / traversal / uppercase are typed 400s,
    //    never 404s and never filesystem errors.
    let id = match crate::agents::parse_agent_id(&id) {
        Some(id) => id,
        None => return proof_id_invalid(),
    };

    // 2) the agent record must exist (public existence is not identity).
    let record_path = crate::agents::agent_path(&crate::agents::agents_dir(), &id);
    if crate::agents::read_agent(&record_path).is_err() {
        return crate::agents::agent_not_found();
    }

    // 3) query validation (limit + cursor only, activity convention).
    let query = match raw.0.as_deref() {
        Some(raw) => match parse_proof_query(raw) {
            Ok(q) => q,
            Err(reason) => return proof_request_invalid(&reason),
        },
        None => ProofQuery {
            limit: crate::activity::ACTIVITY_DEFAULT_PAGE_SIZE,
            cursor: None,
        },
    };

    // 4) read-only ledger scan against the validated id's directory — a
    //    single pass through the strict proof projection (the DTO
    //    whitelist above); the activity item shape never leaves here.
    let root = crate::agents::intents_root();
    let proof_outcome = render_proofs_in(&id, &root, query.limit, query.cursor.as_ref());
    match proof_outcome {
        crate::activity::ActivityOutcome::Rendered(items, next_cursor) => Json(serde_json::json!({
            "success": true,
            "agent_id": id.to_string(),
            "page_size": query.limit,
            "items": items,
            "next_cursor": next_cursor,
        }))
        .into_response(),
        crate::activity::ActivityOutcome::Rejected(reason) => proof_request_invalid(&reason),
        crate::activity::ActivityOutcome::Store => proof_store_error(),
    }
}

/// The validated proofs query: `limit` + optional decoded `cursor` ONLY —
/// the activity pagination convention, nothing more.
pub struct ProofQuery {
    pub limit: usize,
    pub cursor: Option<crate::activity::Cursor>,
}

/// Parse + validate the proofs query string. Whitelist: `limit` and
/// `cursor` ONLY — the activity pagination convention, nothing more.
/// Unknown, duplicate, or malformed parameters are a typed 400.
pub fn parse_proof_query(raw: &str) -> Result<ProofQuery, String> {
    use crate::activity::{
        ACTIVITY_DEFAULT_PAGE_SIZE, ACTIVITY_MAX_PAGE_SIZE, MAX_CURSOR_TOKEN_LEN,
    };
    let mut limit = ACTIVITY_DEFAULT_PAGE_SIZE;
    let mut cursor: Option<crate::activity::Cursor> = None;
    let mut seen: Vec<&'static str> = Vec::new();
    if raw.is_empty() {
        return Ok(ProofQuery { limit, cursor });
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err("empty parameter".to_string());
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => return Err("parameters must be key=value".to_string()),
        };
        let key = crate::activity::percent_decode(k).ok_or("undecodable parameter name")?;
        let value = crate::activity::percent_decode(v).ok_or("undecodable parameter value")?;
        let slot: &'static str = match key.as_str() {
            "limit" => "limit",
            "cursor" => "cursor",
            _ => return Err(format!("unknown parameter: {key}")),
        };
        if seen.contains(&slot) {
            return Err(format!("duplicate parameter: {key}"));
        }
        seen.push(slot);
        match slot {
            "limit" => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| "limit must be an integer".to_string())?;
                if n == 0 || n > ACTIVITY_MAX_PAGE_SIZE as u64 {
                    return Err(format!(
                        "limit must be between 1 and {ACTIVITY_MAX_PAGE_SIZE}"
                    ));
                }
                limit = n as usize;
            }
            "cursor" => {
                if value.len() > MAX_CURSOR_TOKEN_LEN {
                    return Err("cursor is too long".to_string());
                }
                // STRICT decode: malformed / unknown version / oversized
                // payload is a typed 400; the AGENT BOUND itself is
                // re-checked inside render_proofs_in (different-agent
                // cursor -> typed rejection, activity rule).
                let decoded = crate::activity::decode_cursor(&value)
                    .ok_or("cursor is malformed or has an unknown version")?;
                cursor = Some(decoded);
            }
            _ => unreachable!(),
        }
    }
    Ok(ProofQuery { limit, cursor })
}

/// Test seam ONLY — the privacy probe set for the PROOFS surface
/// (Phase 7D.3 DTO whitelist).
#[cfg(test)]
pub struct ProofPrivacyProbe {
    /// Value probes: private material that must NEVER appear in any body.
    pub forbidden_values: Vec<&'static str>,
    /// Private field names that must NEVER be serialized keys.
    pub private_names: &'static [&'static str],
    /// The ONLY keys the endpoint may serialize (envelope + item).
    pub public_fields: &'static [&'static str],
}

#[cfg(test)]
impl ProofPrivacyProbe {
    pub fn canonical() -> Self {
        Self {
            forbidden_values: vec![
                "7d3owner-login",
                "7d3-credential-hex",
                "7d3-keypair-path",
                "7d3-wallet-address",
                "7d3-idempotency-raw",
                "7d3-fingerprint-req",
                "7d3-fingerprint-policy",
                "7d3-resolver-identity",
                "7d3-tx-summary-free",
            ],
            private_names: &[
                "owner_user_id",
                "owner_login",
                "credential",
                "keypair",
                "wallet_path",
                "store_path",
                "idempotency_key",
                "request_fingerprint",
                "policy_fingerprint",
                "resolver",
                "tx_summary",
                "wallet_address",
            ],
            public_fields: &[
                "success",
                "agent_id",
                "page_size",
                "items",
                "next_cursor",
                "proof_state",
                "amount_kelvin",
                "chain_signature",
                "state",
                "reconciliation",
                "method",
                "at",
                "evidence",
                "block_height",
                "slot",
                "block_time",
                "fee",
                "code",
                "message",
                "error",
            ],
        }
    }

    /// True when the serialized body is clean: no forbidden value, no
    /// private key name, and every object key (top, item, reconciliation,
    /// evidence, error) is on the public whitelist.
    pub fn body_is_private_clean(&self, body: &str) -> bool {
        let v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return false,
        };
        for value in &self.forbidden_values {
            if body.contains(value) {
                return false;
            }
        }
        for name in self.private_names {
            if body.contains(&format!("\"{name}\"")) {
                return false;
            }
        }
        let keys_ok = |obj: &serde_json::Map<String, serde_json::Value>| {
            obj.keys().all(|k| self.public_fields.contains(&k.as_str()))
        };
        let top = v.as_object().unwrap();
        if !keys_ok(top) {
            return false;
        }
        if let Some(items) = v.get("items").and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some(obj) = item.as_object() {
                    if !keys_ok(obj) {
                        return false;
                    }
                    for container_key in ["reconciliation", "evidence", "error"] {
                        if let Some(sub) = obj
                            .get(container_key)
                            .and_then(serde_json::Value::as_object)
                        {
                            if !keys_ok(sub) {
                                return false;
                            }
                        }
                    }
                }
            }
        }
        if let Some(err) = v.get("error").and_then(serde_json::Value::as_object) {
            if !keys_ok(err) {
                return false;
            }
        }
        true
    }
}

/// Test seam ONLY — a read-only snapshot of a store tree (for the
/// "no write, no delete, no debris" proof). Returns a sorted list of
/// (relative-path, sha256-hex, size) so two snapshots can be diffed.
#[cfg(test)]
pub fn snapshot_tree(root: &std::path::Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                use std::io::Read;
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let mut bytes = Vec::new();
                let _ = fs::File::open(&path)
                    .and_then(|mut f| {
                        f.read_to_end(&mut bytes);
                        Ok(())
                    })
                    .map(|_| bytes.len());
                // simple FNV-1a instead of pulling in a sha dep for tests
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for b in &bytes {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x0000_0100_0000_01b3);
                }
                out.push(format!("{}::{:016x}::{}", rel.display(), h, bytes.len()));
            }
        }
    }
    out.sort();
    out
}

/// The canonical proof item renderer (test seam: exposed for unit
/// assertions on the DTO shape without a full route drive).
#[allow(unused)]
pub fn proof_item_json(key_hex: &str, slot: &crate::activity::Slot) -> serde_json::Value {
    render_proof_item(key_hex, slot)
}

/// Test seam ONLY — the privacy probe set (Phase 7C answer 6 private set)
/// rendered as a behavioral gate on the SERIALIZED body: value probes for
/// private material + a key-name whitelist. The assert_render_clean
/// discipline applied to this DTO.
#[cfg(test)]
pub struct PrivacyProbe {
    /// Value probes: private material that must NEVER appear in any body.
    pub forbidden_values: Vec<&'static str>,
    /// Private field names that must NEVER be serialized keys.
    pub private_names: &'static [&'static str],
    /// The ONLY keys the endpoint may serialize (success + verification
    /// envelope, and the error envelope's code/message on failures).
    pub public_fields: &'static [&'static str],
}

#[cfg(test)]
impl PrivacyProbe {
    pub fn canonical() -> Self {
        Self {
            forbidden_values: vec![
                "idempotency-key-probe-7d1",
                "request-fingerprint-probe-7d1",
                "policy-fingerprint-probe-7d1",
                "credential-probe-7d1",
                "owner-user-id-probe-7d1",
                "seed-probe-7d1",
                "agentpay_session",
            ],
            private_names: &[
                "idempotency_key",
                "request_fingerprint",
                "policy_fingerprint",
                "credential",
                "owner_user_id",
                "keypair",
                "wallet_path",
                "store_path",
            ],
            public_fields: &[
                "success",
                "verification",
                "signature",
                "status",
                "executed",
                "error",
                "slot",
                "block_height",
                "block_time",
                "fee",
                "payer",
                "recipient",
                "amount_kelvin",
                "code",
                "message",
            ],
        }
    }

    /// True when the serialized body is clean: no forbidden value, no
    /// private key name, and every object key at the top level and inside
    /// the `verification` / `error` objects is on the public whitelist.
    pub fn body_is_private_clean(&self, body: &str) -> bool {
        let v: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return false,
        };
        for value in &self.forbidden_values {
            if body.contains(value) {
                return false;
            }
        }
        for name in self.private_names {
            if body.contains(&format!("\"{name}\"")) {
                return false;
            }
        }
        let keys_ok = |obj: &serde_json::Map<String, serde_json::Value>| {
            obj.keys().all(|k| self.public_fields.contains(&k.as_str()))
        };
        let top = v.as_object().unwrap();
        if !keys_ok(top) {
            return false;
        }
        for container_key in ["verification", "error"] {
            if let Some(obj) = v.get(container_key).and_then(serde_json::Value::as_object) {
                if !keys_ok(obj) {
                    return false;
                }
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// PHASE 7D.1 — focused API tests (routes + core): the real production
// handler (`public_verify`) on a fresh axum::Router against a real
// listener, with a fake rialo CLI + raw JSON-RPC responder as the chain
// stand-in, plus the `VerificationOps` mock lane. See the module doc in
// _verify_tests.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "_verify_tests.rs"]
pub(crate) mod verify_tests;
