//! receipts — PHASE 9 "Verifiable payment receipts" (projection scope).
//!
//! WHAT THIS IS (and the only thing it is): a DETERMINISTIC, READ-ONLY,
//! PURE PROJECTION of the existing authoritative evidence into one
//! verifiable receipt document. It creates NO second source of truth and
//! NO new authority:
//!
//! * Authoritative sources (unchanged, still authoritative):
//!   - the persisted payment intent (`agents::read_intent_any` — the same
//!     fail-closed, identity-verified reader family the engines use);
//!   - the spend ledger (NOT read here — a receipt carries no balance
//!     claims; `balance_after` is ALWAYS null because it cannot be
//!     authoritatively established without an RPC);
//!   - the reconciliation record inside the intent (THE authority for a
//!     proven outcome — the receipt never re-checks the chain);
//!   - the authorization/execution audit store (observational records
//!     written by the audit item — read here, never written);
//!   - the signer linkage (`SignerRecord`: public identity only);
//!   - the read-only chain verification surface (the frozen
//!     `/api/public/verify` + `/api/public/agents/{id}/proofs` lanes
//!     remain the public chain answers; this module performs ZERO RPC).
//!
//! * The receipt is a PURE FUNCTION of those records: same records in,
//!   byte-identical receipt out (determinism is test-pinned). Generation
//!   performs ZERO writes anywhere (module purity test-pinned).
//!
//! * UNKNOWN STAYS UNKNOWN: the `verification.status` mapping is the HONEST
//!   one — only a reconciliation terminal (or a decisive failure) can
//!   produce `proven_paid` / `proven_failed`. A `confirmed` intent with a
//!   signature is `signed_unverified` (never "paid": the receipt cannot
//!   infer chain completion without the reconciliation engine's verdict).
//!   `unknown` renders `unknown` — never upgraded, never downgraded.
//!
//! * NO SECRETS / NO PATHS: the receipt DTO is a strict whitelist of
//!   public facts. No credential, token, PHC hash, key material, keypair
//!   path, authorization header, filesystem path, or raw identity value
//!   can exist in it (hygiene scan test-pinned). The signer evidence is
//!   the persisted `SignerRecord` (kind + public address only). The
//!   reconciliation `resolver` is NEVER rendered (private identity — the
//!   frozen proofs projection discipline).
//!
//! * DISCLOSURE BOUNDARY: the receipt is OWNER-SCOPED ONLY. It exposes
//!   owner-sensitive facts (recipient, authorization snapshot, lane
//!   evidence), so NO credential-lane and NO public receipt surface
//!   exists. The frozen public proofs surface already answers the public
//!   questions and is NOT modified by this item.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Receipt document format version. Bumped only with a documented
/// amendment (the established schema-version rule).
pub const RECEIPT_SCHEMA_VERSION: u32 = 1;

/// The deterministic receipt builder: ONE pure function from the
/// authoritative records to the receipt document. Same inputs => the same
/// JSON bytes (fixed field order; no clocks, no randomness, no iteration
/// order dependence — audit entries are filtered deterministically by
/// (agent, key) with a stable latest-wins rule over the append-only file).
///
/// `audit` entries may be empty (no audit store / corrupt store) — every
/// audit-derived field then renders null HONESTLY. Intent facts are the
/// authority; audit facts only ENRICH (authorization outcome / lane
/// evidence) and can never contradict or override the intent state.
pub(crate) fn build_receipt(
    intent: crate::agents::ClaimedRecord,
    agent_id: &str,
    idempotency_key: &str,
    audit: &[crate::audit::AuditRecord],
) -> serde_json::Value {
    // ---- intent facts (authoritative) ----
    let (
        state_name,
        recipient,
        amount_kelvin,
        request_fingerprint,
        intent_id,
        created_at,
        updated_at,
        authz,
        signer,
        reconciliation,
        tx_signature,
    ) = match &intent {
        crate::agents::ClaimedRecord::V1(i) => (
            crate::activity::state_name_v1(i.state),
            i.recipient.clone(),
            i.amount_kelvin,
            i.request_fingerprint.clone(),
            None,
            i.created_at,
            i.updated_at,
            // V1 carries the additive audit snapshot (post-audit-item
            // records); pre-audit V1 records render honest nulls.
            i.authz
                .as_ref()
                .map(|a| (a.policy_fingerprint.clone(), a.authorized_at)),
            i.signer
                .as_ref()
                .map(|s| (s.kind.clone(), s.address.clone())),
            i.reconciliation.clone(),
            crate::activity::v1_signature_from_response(&i.response),
        ),
        crate::agents::ClaimedRecord::V2(i) => (
            crate::activity::state_name_v2(i.exec_state),
            i.recipient.clone(),
            i.amount_kelvin,
            i.request_fingerprint.clone(),
            Some(i.intent_id.clone()),
            i.created_at,
            i.updated_at,
            Some((i.authz.policy_fingerprint.clone(), i.authz.authorized_at)),
            i.signer
                .as_ref()
                .map(|s| (s.kind.clone(), s.address.clone())),
            i.reconciliation.clone(),
            i.tx_signature.as_ref().filter(|s| !s.is_empty()).cloned(),
        ),
    };

    // ---- audit-derived evidence (enrichment ONLY, deterministic) ----
    // Latest-wins per category, filtered by the correlation key; the audit
    // file is append-only, so the LAST matching record is the most recent
    // observation. (agent + key) is THE deterministic correlation key.
    let key_filter = |r: &crate::audit::AuditRecord| {
        r.idempotency_key.as_deref() == Some(idempotency_key)
            && r.agent_id.as_deref() == Some(agent_id)
    };
    let authorization = audit
        .iter()
        .filter(|r| r.category == crate::audit::AuditCategory::Authorization && key_filter(r))
        .last()
        .cloned();
    let lane = audit
        .iter()
        .filter(|r| r.category == crate::audit::AuditCategory::Lane && key_filter(r))
        .last()
        .cloned();
    let execution = audit
        .iter()
        .filter(|r| r.category == crate::audit::AuditCategory::Execution && key_filter(r))
        .last()
        .cloned();
    let replay = audit
        .iter()
        .filter(|r| r.category == crate::audit::AuditCategory::Replay && key_filter(r))
        .last()
        .cloned();

    // ---- authorization evidence ----
    let (auth_outcome, auth_code, auth_policy_fp, auth_at) = match &authorization {
        Some(record) => (
            Some(
                match record.outcome {
                    crate::audit::AuditOutcome::Allow => "allow",
                    crate::audit::AuditOutcome::Deny => "deny",
                    _ => "unknown",
                }
                .to_string(),
            ),
            record.code.clone(),
            record.policy_fingerprint.clone(),
            Some(record.at),
        ),
        None => (None, None, None, None),
    };
    // The intent's own authz snapshot is the AUTHORITATIVE authorization
    // evidence (written at claim); the audit record is the observation.
    // They cannot contradict: the snapshot exists only for claims that
    // passed the gate.
    let (snapshot_fp, snapshot_at) = match authz {
        Some((fp, at)) => (Some(fp), Some(at)),
        None => (None, None),
    };

    // ---- reconciliation evidence (authoritative verdict) ----
    // `#[allow(deprecated)]`: classifying the DEMOTED BalanceDelta method
    // in EXISTING records is a read, never a construction (the same audit
    // rule the frozen proofs projection applies).
    #[allow(deprecated)]
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
            // NOTE: rec.resolver is NEVER rendered (private identity — the
            // frozen proofs discipline). The receipt adds NO new exposure.
            let evidence = match &rec.evidence {
                Some(ev) => json!({
                    "block_height": ev.block_height,
                    "slot": ev.slot,
                    "block_time": ev.block_time,
                    "fee": ev.fee,
                }),
                None => serde_json::Value::Null,
            };
            json!({
                "method": method,
                "outcome": match rec.outcome {
                    crate::agents::ReconciliationOutcome::Paid => "paid",
                    crate::agents::ReconciliationOutcome::Absent => "absent",
                },
                "resolved_at": rec.resolved_at,
                "evidence": evidence,
            })
        }
        None => serde_json::Value::Null,
    };

    // ---- verification status (HONEST mapping — same gates as proofs) ----
    let verification = match state_name {
        "reconciled_paid" => {
            if tx_signature.is_some() {
                json!({
                    "status": "proven_paid",
                    "chain": chain_facts(&reconciliation),
                })
            } else {
                json!({ "status": "unproven", "chain": serde_json::Value::Null })
            }
        }
        "reconciled_absent" | "failed" => json!({
            "status": "proven_failed",
            "chain": serde_json::Value::Null,
        }),
        "confirmed" => {
            // signed, but NOT chain-proven: only the reconciliation engine
            // can prove completion. The receipt NEVER infers Paid.
            if tx_signature.is_some() {
                json!({ "status": "signed_unverified", "chain": serde_json::Value::Null })
            } else {
                json!({ "status": "unproven", "chain": serde_json::Value::Null })
            }
        }
        "unknown" => json!({
            "status": "unknown",
            "chain": serde_json::Value::Null,
        }),
        _ => json!({ "status": "none", "chain": serde_json::Value::Null }),
    };

    // ---- the receipt document (fixed field order, whitelist only) ----
    json!({
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "correlation": {
            "agent_id": agent_id,
            "idempotency_key": idempotency_key,
            "request_fingerprint": request_fingerprint,
            "intent_id": intent_id,
        },
        "payment": {
            "recipient": recipient,
            "amount_kelvin": amount_kelvin,
            "state": state_name,
            "created_at": created_at,
            "updated_at": updated_at,
        },
        "authorization": {
            // the authoritative claim-time snapshot (v2 always; v1 additive)
            "policy_fingerprint": snapshot_fp,
            "authorized_at": snapshot_at,
            // the audit observation (allow/deny outcome + code + time)
            "audit_outcome": auth_outcome,
            "audit_code": auth_code,
            "audit_at": auth_at,
            "audit_policy_fingerprint": auth_policy_fp,
        },
        "execution": {
            // lane evidence from the audit store (Native/Latch selection,
            // static reason, fallback) — observational enrichment only
            "lane": lane.as_ref().and_then(|l| l.lane.clone()),
            "lane_reason": lane.as_ref().and_then(|l| l.lane_reason.clone()),
            "fallback": lane.as_ref().and_then(|l| l.fallback),
            // the execution-outcome observation (Ok/Failed/Unknown/Aborted)
            "outcome": execution.as_ref().map(|e| outcome_name(e.outcome)),
            "outcome_code": execution.as_ref().and_then(|e| e.code.clone()),
            // replay evidence, kept separate from execution evidence
            "replay": replay.as_ref().map(|r| json!({
                "code": r.code,
                "at": r.at,
            })),
        },
        "signer": {
            "kind": signer.as_ref().map(|(k, _)| k.clone()),
            "address": signer.as_ref().map(|(_, a)| a.clone()),
        },
        "tx_signature": tx_signature,
        "reconciliation": reconciliation_value,
        "verification": verification,
        // HONEST: balance_after cannot be authoritatively established from
        // the existing records without an RPC — always null, never invented.
        "balance_after": serde_json::Value::Null,
    })
}

/// Reconciliation chain facts (public evidence only — the same whitelist
/// the frozen proofs projection renders).
fn chain_facts(reconciliation: &Option<crate::agents::ReconciliationRecord>) -> serde_json::Value {
    match reconciliation.as_ref().and_then(|r| r.evidence.as_ref()) {
        Some(ev) => json!({
            "block_height": ev.block_height,
            "slot": ev.slot,
            "block_time": ev.block_time,
            "fee": ev.fee,
        }),
        None => serde_json::Value::Null,
    }
}

/// The audit outcome vocabulary, rendered as stable strings.
pub(crate) fn outcome_name(outcome: crate::audit::AuditOutcome) -> &'static str {
    match outcome {
        crate::audit::AuditOutcome::Allow => "allow",
        crate::audit::AuditOutcome::Deny => "deny",
        crate::audit::AuditOutcome::Ok => "ok",
        crate::audit::AuditOutcome::Failed => "failed",
        crate::audit::AuditOutcome::Unknown => "unknown",
        crate::audit::AuditOutcome::Aborted => "aborted",
        crate::audit::AuditOutcome::Replayed => "replayed",
        crate::audit::AuditOutcome::Selected => "selected",
        crate::audit::AuditOutcome::Fallback => "fallback",
        crate::audit::AuditOutcome::Denied => "denied",
        crate::audit::AuditOutcome::Uncertain => "uncertain",
    }
}

// ---------------------------------------------------------------------------
// THE OWNER ROUTE — GET /api/agents/{id}/receipts/{key}
// ---------------------------------------------------------------------------
// Owner-scoped ONLY (session + the ONE ownership choke point). The receipt
// exposes owner-sensitive facts (recipient, authorization snapshot, lane
// evidence), so no credential-lane and no public receipt surface exists.
// The frozen public proofs surface already answers the public questions and
// is NOT modified by this item. Zero writes; the only I/O is the same
// fail-closed intent readers + the read-only audit reader.
pub async fn agent_payment_receipt(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    Path((id, key)): Path<(String, String)>,
) -> Response {
    let Some(user) = crate::session_user(&state, &headers) else {
        return crate::api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    // the ONE ownership choke point (missing, foreign, malformed, corrupt
    // all answer AGENT_NOT_FOUND)
    let agent = match crate::agents::load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = crate::agents::parse_agent_id(&agent.agent_id) else {
        return crate::agents::agent_not_found();
    };
    if !crate::agents::valid_idempotency_key(&key) {
        return crate::api_error(
            StatusCode::BAD_REQUEST,
            "RECEIPT_REQUEST_INVALID",
            "Idempotency key must be 1-128 characters from A-Z a-z 0-9 - _",
        );
    }

    let intents_dir = crate::agents::intents_root();
    let audit_dir = crate::audit::audit_dir_for(&intents_dir);

    // version-aware intent read (the same fail-closed identity-verified
    // reader family the engines use; cross-version identity mismatches
    // fail closed)
    let intent = match crate::agents::read_intent_any(&intents_dir, &uuid, &key) {
        Ok(Some(slot)) => slot,
        Ok(None) => {
            return crate::api_error(
                StatusCode::NOT_FOUND,
                "RECEIPT_NOT_FOUND",
                "No payment intent exists for this idempotency key",
            );
        }
        Err(_) => {
            return crate::api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "The receipt could not be read",
            );
        }
    };

    // read-only audit evidence (a corrupt/missing audit store renders the
    // audit-derived fields null — never an internal error, never an
    // inference; the intent facts stay authoritative)
    let audit_entries =
        crate::audit::read_entries(&audit_dir, Some(&uuid.to_string())).unwrap_or_default();

    let receipt = build_receipt(intent, &agent.agent_id, &key, &audit_entries);
    (StatusCode::OK, Json(receipt)).into_response()
}

#[cfg(test)]
#[path = "_receipts_i9_tests.rs"]
mod receipts_tests;
