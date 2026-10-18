//! PHASE 9 "Verifiable payment receipts" — focused tests for the
//! deterministic read-only receipt projection. All stores are fresh
//! std::env::temp_dir() subtrees; the real artifact/ tree is never opened.
//! The receipt is a PURE projection of the authoritative records: zero
//! writes, zero RPC, no new authority, Unknown stays Unknown.

use crate::audit::{AuditOutcome, AuditRecord};
use crate::receipts::{RECEIPT_SCHEMA_VERSION, build_receipt};
use serde_json::{Value, json};
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
const AGENT_WALLET: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

// ---------------------------------------------------------------------------
// fixture builders (authoritative record shapes, frozen semantics)
// ---------------------------------------------------------------------------

fn agent_id_str() -> String {
    Uuid::new_v4().to_string()
}

fn v1_intent(
    agent_id: &str,
    key: &str,
    state: &str,
    opts: IntentOpts,
) -> crate::agents::ClaimedRecord {
    let _ = agent_id;
    let doc = json!({
        "schema_version": 1,
        "agent_id": opts.agent_id_override.unwrap_or_default(),
        "idempotency_key": key,
        "request_fingerprint": opts.fingerprint.unwrap_or_else(|| format!("fp-{key}")),
        "recipient": RECIPIENT,
        "amount_kelvin": opts.amount.unwrap_or(1_000_000),
        "state": state,
        "response": opts.v1_response,
        "created_at": 1_700_000_000,
        "updated_at": 1_700_000_100,
        "reconciliation": opts.reconciliation,
        "signer": opts.signer,
        "authz": opts.authz,
    });
    crate::agents::ClaimedRecord::V1(serde_json::from_value(doc).unwrap())
}

fn v2_intent(
    agent_id: &str,
    key: &str,
    state: &str,
    opts: IntentOpts,
) -> crate::agents::ClaimedRecord {
    let doc = json!({
        "schema_version": 2,
        "intent_id": opts.intent_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        "agent_id": agent_id,
        "principal_kind": "agent",
        "recipient": RECIPIENT,
        "amount_kelvin": opts.amount.unwrap_or(1_000_000),
        "idempotency_key": key,
        "request_fingerprint": opts.fingerprint.unwrap_or_else(|| format!("fp-{key}")),
        "authz": opts.authz_v2.unwrap_or_else(|| json!({
            "policy_fingerprint": "pfp",
            "authorized_at": 1_700_000_000,
        })),
        "exec_state": state,
        "tx_signature": opts.tx_signature,
        "failure": null,
        "response": null,
        "signer": opts.signer,
        "reconciliation": opts.reconciliation,
        "created_at": 1_700_000_000,
        "updated_at": 1_700_000_100,
    });
    crate::agents::ClaimedRecord::V2(serde_json::from_value(doc).unwrap())
}

#[derive(Default)]
struct IntentOpts {
    agent_id_override: Option<String>,
    fingerprint: Option<String>,
    amount: Option<u64>,
    v1_response: Option<Value>,
    intent_id: Option<String>,
    authz_v2: Option<Value>,
    authz: Option<Value>,
    tx_signature: Option<String>,
    signer: Option<Value>,
    reconciliation: Option<Value>,
}

fn reconciliation_doc(method: &str, outcome: &str, at: i64, evidence: Value) -> Value {
    json!({
        "method": method,
        "outcome": outcome,
        "tx_signature": "SIGX",
        "resolved_at": at,
        "resolver": "owner:shaaker-test",
        "evidence": evidence,
    })
}

// ---------------------------------------------------------------------------
// (1) deterministic receipt
// ---------------------------------------------------------------------------

#[test]
fn deterministic_receipt_same_records_byte_identical() {
    let agent = agent_id_str();
    let mk = || {
        v2_intent(
            &agent,
            "kd",
            "confirmed",
            IntentOpts {
                tx_signature: Some("SIGD".into()),
                signer: Some(json!({"kind": "agent_wallet", "address": AGENT_WALLET})),
                intent_id: Some("int-kd-fixed".into()),
                ..Default::default()
            },
        )
    };
    let a = build_receipt(mk(), &agent, "kd", &[]);
    let b = build_receipt(mk(), &agent, "kd", &[]);
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
}

// ---------------------------------------------------------------------------
// (2) correlation
// ---------------------------------------------------------------------------

#[test]
fn correlation_keys_preserved() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kc",
        "unknown",
        IntentOpts {
            fingerprint: Some("fp-custom".into()),
            tx_signature: Some("SIGU".into()),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kc", &[]);
    assert_eq!(r["correlation"]["agent_id"], agent.as_str());
    assert_eq!(r["correlation"]["idempotency_key"], "kc");
    assert_eq!(r["correlation"]["request_fingerprint"], "fp-custom");
    assert!(r["correlation"]["intent_id"].as_str().is_some());
}

// ---------------------------------------------------------------------------
// (3) authorization evidence (V1/V2 differences, honest nulls)
// ---------------------------------------------------------------------------

#[test]
fn authorization_evidence_v2_snapshot_and_v1_honest_null() {
    let agent = agent_id_str();
    // V2: snapshot ALWAYS present
    let v2 = v2_intent(
        &agent,
        "kauth2",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGA".into()),
            ..Default::default()
        },
    );
    let r2 = build_receipt(v2, &agent, "kauth2", &[]);
    assert_eq!(r2["authorization"]["policy_fingerprint"], "pfp");
    assert_eq!(r2["authorization"]["authorized_at"], 1_700_000_000);
    // no audit records: audit fields honest nulls
    assert!(r2["authorization"]["audit_outcome"].is_null());
    assert!(r2["authorization"]["audit_at"].is_null());

    // V1 pre-audit record (no authz field): honest nulls, never inferred
    let v1 = v1_intent(
        &agent,
        "kauth1",
        "confirmed",
        IntentOpts {
            agent_id_override: Some(agent.clone()),
            tx_signature: None,
            v1_response: Some(json!({"payment": {"signature": "SIGV1"}})),
            ..Default::default()
        },
    );
    let r1 = build_receipt(v1, &agent, "kauth1", &[]);
    assert!(r1["authorization"]["policy_fingerprint"].is_null());
    assert!(r1["authorization"]["authorized_at"].is_null());
}

// ---------------------------------------------------------------------------
// (4) signer evidence
// ---------------------------------------------------------------------------

#[test]
fn signer_evidence_kind_and_address_only() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "ksig",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGS".into()),
            signer: Some(json!({"kind": "agent_wallet", "address": AGENT_WALLET})),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "ksig", &[]);
    assert_eq!(r["signer"]["kind"], "agent_wallet");
    assert_eq!(r["signer"]["address"], AGENT_WALLET);
    assert_eq!(r["tx_signature"], "SIGS");
    // no signer recorded => honest nulls
    let intent2 = v2_intent(&agent, "ksig2", "pending", IntentOpts::default());
    let r2 = build_receipt(intent2, &agent, "ksig2", &[]);
    assert!(r2["signer"]["kind"].is_null());
    assert!(r2["tx_signature"].is_null());
}

// ---------------------------------------------------------------------------
// (5-7) execution / lane evidence from the audit store
// ---------------------------------------------------------------------------

fn lane_record(agent_id: &str, key: &str, lane: &str, reason: &str, fallback: bool) -> AuditRecord {
    crate::audit::lane(
        1_700_010_000,
        if fallback {
            AuditOutcome::Fallback
        } else {
            AuditOutcome::Selected
        },
        None,
        agent_id,
        key,
        Some(lane),
        reason,
        fallback,
    )
}

#[test]
fn native_lane_evidence_rendered() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "knat",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGN".into()),
            ..Default::default()
        },
    );
    let entries = vec![lane_record(
        &agent,
        "knat",
        "native",
        "latch lane not enabled",
        false,
    )];
    let r = build_receipt(intent, &agent, "knat", &entries);
    assert_eq!(r["execution"]["lane"], "native");
    assert_eq!(r["execution"]["lane_reason"], "latch lane not enabled");
    assert_eq!(r["execution"]["fallback"], false);
}

#[test]
fn latch_lane_evidence_rendered() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "klat",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGL".into()),
            ..Default::default()
        },
    );
    let entries = vec![lane_record(
        &agent,
        "klat",
        "latch",
        "latch lane selected",
        false,
    )];
    let r = build_receipt(intent, &agent, "klat", &entries);
    assert_eq!(r["execution"]["lane"], "latch");
    assert_eq!(r["execution"]["fallback"], false);
}

#[test]
fn fallback_evidence_rendered() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kfb",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGF".into()),
            ..Default::default()
        },
    );
    let entries = vec![
        lane_record(&agent, "kfb", "latch", "latch lane selected", false),
        lane_record(
            &agent,
            "kfb",
            "native",
            "latch lane pre-execution failure after selection; native fallback",
            true,
        ),
    ];
    let r = build_receipt(intent, &agent, "kfb", &entries);
    // latest-wins: the fallback record is the most recent lane observation
    assert_eq!(r["execution"]["lane"], "native");
    assert_eq!(r["execution"]["fallback"], true);
}

// ---------------------------------------------------------------------------
// (8) reconciliation evidence
// ---------------------------------------------------------------------------

#[test]
fn reconciliation_evidence_rendered_without_resolver() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "krec",
        "reconciled_paid",
        IntentOpts {
            tx_signature: Some("SIGR".into()),
            reconciliation: Some(reconciliation_doc(
                "tx_lookup",
                "paid",
                1_700_010_000,
                json!({"block_height": 101, "slot": 101, "block_time": 1_700_000_060, "fee": 5000}),
            )),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "krec", &[]);
    assert_eq!(r["reconciliation"]["method"], "tx_lookup");
    assert_eq!(r["reconciliation"]["outcome"], "paid");
    assert_eq!(r["reconciliation"]["resolved_at"], 1_700_010_000);
    assert_eq!(r["reconciliation"]["evidence"]["slot"], 101);
    // the resolver identity is NEVER rendered (private — frozen discipline)
    assert!(
        r["reconciliation"]
            .as_object()
            .unwrap()
            .get("resolver")
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// (9) confirmed transaction with chain verification boundary
// ---------------------------------------------------------------------------

#[test]
fn confirmed_is_signed_unverified_never_paid() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kconf",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGC".into()),
            signer: Some(json!({"kind": "agent_wallet", "address": AGENT_WALLET})),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kconf", &[]);
    // HONEST: confirmed + signature WITHOUT a reconciliation terminal is
    // `signed_unverified` — the receipt can never infer Paid without the
    // reconciliation engine's verdict.
    assert_eq!(r["verification"]["status"], "signed_unverified");
    assert!(r["verification"]["chain"].is_null());
}

#[test]
fn reconciled_paid_is_proven_with_chain_facts() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kpaid",
        "reconciled_paid",
        IntentOpts {
            tx_signature: Some("SIGP".into()),
            reconciliation: Some(reconciliation_doc(
                "tx_lookup",
                "paid",
                1_700_010_000,
                json!({"block_height": 101, "slot": 101, "block_time": 1_700_000_060, "fee": 5000}),
            )),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kpaid", &[]);
    assert_eq!(r["verification"]["status"], "proven_paid");
    assert_eq!(r["verification"]["chain"]["slot"], 101);
}

// ---------------------------------------------------------------------------
// (10) Unknown settlement stays Unknown
// ---------------------------------------------------------------------------

#[test]
fn unknown_stays_unknown_never_upgraded() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kunk",
        "unknown",
        IntentOpts {
            tx_signature: Some("SIGU".into()),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kunk", &[]);
    assert_eq!(r["verification"]["status"], "unknown");
    assert!(r["verification"]["chain"].is_null());
    assert_eq!(r["payment"]["state"], "unknown");
}

// ---------------------------------------------------------------------------
// (11) missing chain evidence: no false confirmation
// ---------------------------------------------------------------------------

#[test]
fn missing_chain_evidence_never_confirms() {
    let agent = agent_id_str();
    // reconciled_paid WITHOUT a signature: unproven, never paid
    let intent = v2_intent(&agent, "knoch", "reconciled_paid", IntentOpts::default());
    let r = build_receipt(intent, &agent, "knoch", &[]);
    assert_eq!(r["verification"]["status"], "unproven");
    // pending: none, never anything stronger
    let intent2 = v2_intent(&agent, "kpend", "pending", IntentOpts::default());
    let r2 = build_receipt(intent2, &agent, "kpend", &[]);
    assert_eq!(r2["verification"]["status"], "none");
    // failed: proven_failed (decisive)
    let intent3 = v2_intent(&agent, "kfail", "failed", IntentOpts::default());
    let r3 = build_receipt(intent3, &agent, "kfail", &[]);
    assert_eq!(r3["verification"]["status"], "proven_failed");
}

// ---------------------------------------------------------------------------
// (12) field whitelist: no secrets / paths
// ---------------------------------------------------------------------------

#[test]
fn field_whitelist_no_secrets_or_paths() {
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kwh",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGW".into()),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kwh", &[]);
    let raw = serde_json::to_string(&r).unwrap();
    for forbidden in [
        "lat_",
        "Bearer",
        "argon2id",
        "$argon",
        "artifact/",
        ".json",
        "keypair",
        "private_key",
        "credential",
        "password",
        "token",
        "LATCH_TOKEN",
        "Authorization",
        "wallet_dir",
        "agent_wallets",
    ] {
        assert!(
            !raw.contains(forbidden),
            "receipt must never contain {forbidden}"
        );
    }
    // balance_after is ALWAYS null (honest — never inventable)
    assert!(r["balance_after"].is_null());
}

// ---------------------------------------------------------------------------
// (13-14) no writes / read-only behavior
// ---------------------------------------------------------------------------

#[test]
fn receipt_generation_performs_no_writes_and_is_read_only() {
    // Module purity: receipts.rs contains no write primitives at all.
    let src = include_str!("receipts.rs");
    let production = src.split("#[cfg(test)]").next().unwrap();
    let code: Vec<&str> = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let joined = code.join("\n");
    for forbidden in [
        "fs::write",
        "fs::create",
        "OpenOptions",
        "fs::rename",
        "remove_file",
        "write_json_atomic",
        "record(",
        "reserve_spend",
        "release_spend",
        "claim_intent",
        "transfer(",
        "reconcile_",
        "store_lock",
    ] {
        assert!(
            !joined.contains(forbidden),
            "receipts.rs must never reference {forbidden}"
        );
    }
    // and the projection itself is a pure function: calling it twice with
    // the same inputs yields identical bytes (no hidden state)
    let agent = agent_id_str();
    let mk = || {
        v2_intent(
            &agent,
            "kro",
            "confirmed",
            IntentOpts {
                tx_signature: Some("SIGRO".into()),
                intent_id: Some("int-kro-fixed".into()),
                ..Default::default()
            },
        )
    };
    let a = build_receipt(mk(), &agent, "kro", &[]);
    let b = build_receipt(mk(), &agent, "kro", &[]);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// (15) idempotent repeated generation: identical output, no duplicate evidence
// ---------------------------------------------------------------------------

#[test]
fn repeated_generation_identical_no_duplicate_evidence() {
    let agent = agent_id_str();
    let mk = || {
        v2_intent(
            &agent,
            "kidem",
            "confirmed",
            IntentOpts {
                tx_signature: Some("SIGI".into()),
                intent_id: Some("int-kidem-fixed".into()),
                ..Default::default()
            },
        )
    };
    let entries = vec![lane_record(
        &agent,
        "kidem",
        "native",
        "latch lane not enabled",
        false,
    )];
    let r1 = build_receipt(mk(), &agent, "kidem", &entries);
    let r2 = build_receipt(mk(), &agent, "kidem", &entries);
    assert_eq!(r1, r2, "repeated generation is identical");
    assert_eq!(r1["execution"]["lane"], "native");
    // the execution evidence block is a single object, not a list — the
    // receipt can never "duplicate" evidence
    assert!(r1["execution"].as_object().is_some());
}

// ---------------------------------------------------------------------------
// (16) owner/public disclosure boundary (structural)
// ---------------------------------------------------------------------------

#[test]
fn owner_scope_only_no_credential_or_public_surface() {
    // The receipt module exposes exactly ONE handler and it is owner-gated
    // (session + load_authorized). No credential-lane and no public route
    // exists; the frozen public proofs surface is untouched.
    let src = include_str!("receipts.rs");
    assert!(src.contains("pub async fn agent_payment_receipt"));
    let handler_count = src.matches("pub async fn").count();
    assert_eq!(handler_count, 1, "exactly one handler (owner-scoped)");
    assert!(src.contains("load_authorized"), "owner choke point present");
    assert!(src.contains("session_user"), "session gate present");
    // no credential-lane surface (the credential lane never reveals recipient)
    assert!(!src.contains("agent_trigger_payment"));
    // the receipt carries owner-sensitive facts — that is WHY it is owner-only
    let agent = agent_id_str();
    let intent = v2_intent(
        &agent,
        "kd1",
        "confirmed",
        IntentOpts {
            tx_signature: Some("SIGD1".into()),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "kd1", &[]);
    assert!(
        r["payment"]["recipient"].as_str().is_some(),
        "recipient exposed to OWNER only"
    );
}

// ---------------------------------------------------------------------------
// (17) malformed/missing evidence: honest null/unknown representation
// ---------------------------------------------------------------------------

#[test]
fn malformed_missing_evidence_honest_nulls() {
    let agent = agent_id_str();
    // EMPTY audit slice (missing/corrupt audit store): audit-derived fields
    // render null honestly; intent facts stay authoritative.
    let intent = v2_intent(
        &agent,
        "km",
        "unknown",
        IntentOpts {
            tx_signature: Some("SIGM".into()),
            ..Default::default()
        },
    );
    let r = build_receipt(intent, &agent, "km", &[]);
    assert!(r["execution"]["lane"].is_null());
    assert!(r["execution"]["lane_reason"].is_null());
    assert!(r["execution"]["fallback"].is_null());
    assert!(r["execution"]["outcome"].is_null());
    assert!(r["execution"]["replay"].is_null());
    assert!(r["authorization"]["audit_outcome"].is_null());
    assert!(r["reconciliation"].is_null());
    // and the receipt STILL says unknown (never inferred)
    assert_eq!(r["verification"]["status"], "unknown");

    // V1 pre-audit record: honest nulls for the additive snapshot
    let v1 = v1_intent(
        &agent,
        "km1",
        "failed",
        IntentOpts {
            agent_id_override: Some(agent.clone()),
            ..Default::default()
        },
    );
    let r1 = build_receipt(v1, &agent, "km1", &[]);
    assert!(r1["authorization"]["policy_fingerprint"].is_null());
    assert_eq!(r1["verification"]["status"], "proven_failed");
}

// keep the schema constant exercised (the version rule)
#[test]
fn receipt_schema_version_is_one() {
    let agent = agent_id_str();
    let intent = v2_intent(&agent, "kv", "pending", IntentOpts::default());
    let r = build_receipt(intent, &agent, "kv", &[]);
    assert_eq!(r["schema_version"], RECEIPT_SCHEMA_VERSION);
    assert_eq!(RECEIPT_SCHEMA_VERSION, 1);
}
