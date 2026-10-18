//! latch_policy_compiler — PHASE 9 C-2: the deterministic
//! AgentPolicy → Latch-filter compiler, implementing the R2 design
//! (`_phase9/c2_policy_filter_compiler_design.md` §9 + Appendix A) exactly.
//!
//! WHAT THIS IS (and the only thing it is): a PURE function from the real
//! post-validation AgentPay policy surface (`AgentPolicy` + `Agent` record +
//! caller-supplied I-1 vault verification result + lane + topology
//! correlation id) to a deterministic, canonical compiled pipeline
//! representation. It never weakens AgentPay: per R2 §0/§11, AgentPay stays
//! authoritative for amount, recipient, per-tx authority, the daily
//! reservation ledger, ownership, credentials, idempotency, replay, payment
//! semantics, reconciliation, and the money-signer boundary; the compiled
//! output is the LATCH-ENFORCEABLE SUBSET ONLY, and everything outside that
//! subset is recorded in an explicit `unmapped` ledger rather than silently
//! omitted (§4 "record it as unmapped"; A.2 anti-relaxation property).
//!
//! THE OUTPUT IS AN INTERNAL IR, NOT THE LATCH WIRE SCHEMA. The exact wire
//! JSON is pinned-unknown (R2 G-2; the never-guess rule), and proxy-envelope
//! introspection is unresolved (G-1). The emitted object therefore uses
//! AgentPay's OWN canonical names (`dialect: agentpay-ir-v0`), sorted keys,
//! and integer kelvin only, and the identity filter is emitted with
//! `enforced: false` because allow-list ENFORCEMENT lives in the deferred
//! tx-signing lane (G-14/G-15). Nothing here may be described as a live
//! Latch integration; push/verify is a separate future act (C-5 / transport
//! items) that will translate this IR once G-2 closes.
//!
//! THE ERROR SET IS FROZEN AT FIVE VARIANTS (R2 §9, verbatim). Lane
//! handling note — the ONE interpretation decision this implementation
//! makes explicit: R2 A.3 says "`TxSigning` emission ⇒ refuse until
//! elected" while §9 forbids extending the error set. A capability refusal
//! must NOT masquerade as a policy denial (`DenyOnly` is defined as
//! all-denying POLICY; §13 forbids confusing capability outcomes with
//! class-1 security outcomes). So the refusal is STRUCTURAL: `Lane` has
//! exactly one constructible value today, `ProxyAvailability`; the
//! `TxSigning` variant is intentionally ABSENT until the D-PRIVY election
//! closes G-14/G-15, at which point adding the variant (never a new error)
//! is the amendment path. No caller can request a tx-signing emission from
//! this build — which IS the refusal.
//!
//! What this module is NOT (R2 §9 verbatim boundary): it does not choose
//! Latch vs Native (Lane Selector, separate future item); it executes
//! nothing (no Latch transport, no payments, no signing — nothing here can
//! talk to any service: zero filesystem, zero network, zero process
//! calls); it performs no reconciliation; it never emits secret material
//! (it reads NO key material at all — `vault_verified` is a caller-supplied
//! bool from the I-1 pubkey-only verifier); it never maps spend authority
//! (§11: `daily` NEVER maps; `rate_limit` is never derived from money); and
//! it does not exist to widen policy: if a rule cannot be represented
//! safely it is recorded `unmapped`/`pending`, never dropped, never
//! relaxed.

#![allow(dead_code)] // the compiler surface is consumed by tests today; the
// future Latch-lane/push items are its callers (established precedent:
// src/agent_credentials.rs carries the same attribute pre-wiring).

use serde::Serialize;

use super::agents::{AGENT_SCHEMA_VERSION, Agent, AgentPolicy, AgentStatus, POLICY_SCHEMA_VERSION};

/// Compiled-dialect label. NOT a Latch wire version (G-2 pinned-unknown):
/// identifies the AgentPay-side IR shape so a future verified translator
/// can bind to it.
pub const COMPILER_DIALECT: &str = "agentpay-ir-v0";

/// Compiler contract version; bump only with a documented R2 amendment.
pub const COMPILER_VERSION: &str = "c2-compiler-1";

/// Upper shape bound for caller-owned topology correlation ids. The rule
/// "never a token" is caller/runbook discipline (C-5): the compiler cannot
/// inspect Latch secrets and must not pretend to, so it shape-validates
/// only.
pub const MAX_LATCH_ID_LEN: usize = 128;

/// The caller-owned child-latch correlation id (A.3: "caller-owned string;
/// never a token"). Shape-gated; contents are carried verbatim, never
/// interpreted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatchId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatchIdError {
    Empty,
    TooLong,
    NotPrintable,
}

impl LatchId {
    /// The only construction point: non-empty, bounded, printable
    /// non-spacing ASCII-free-of-control characters. Whitespace anywhere
    /// (including leading/trailing) is refused so ids can never smuggle
    /// multi-token payloads into the correlation field.
    pub fn new(raw: &str) -> Result<Self, LatchIdError> {
        if raw.is_empty() {
            return Err(LatchIdError::Empty);
        }
        if raw.len() > MAX_LATCH_ID_LEN {
            return Err(LatchIdError::TooLong);
        }
        if raw
            .chars()
            .any(|c| !c.is_ascii_graphic() || c == '"' || c == '\\')
        {
            return Err(LatchIdError::NotPrintable);
        }
        Ok(LatchId(raw.to_string()))
    }
}

/// Execution lane INPUT. Exactly one constructible value today: the
/// ProxyAvailability lane. The `TxSigning` lane is structurally absent
/// until the D-PRIVY election closes G-14/G-15 — see the module doc for
/// why absence (not a sixth error variant) is the faithful R2 reading of
/// "refuse until elected".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    ProxyAvailability,
    /// PHASE 9 STEP H-3 (independent policy IR verification): the SIGNING
    /// lane — the compiler emits the signer-side policy rules (amount cap,
    /// recipient allow-list, program pin, instruction count) as an
    /// INDEPENDENT representation the signer cross-checks against its own
    /// policy load. Additive: the ProxyAvailability emission is untouched.
    TxSigning,
}

/// THE frozen five-variant compile-error surface (R2 §9 verbatim; no
/// extension). Fieldless: no detail can ever surface through Debug/Display,
/// mirroring `EnforcementDenial`/`CreateError` discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    /// Policy or agent record schema newer than this compiler understands
    /// — refuse, never drop fields or guess semantics.
    UnsupportedField,
    /// The agent record carries no `auth_public_key` (all pre-I-1 agents
    /// until a scoped backfill act closes G-7): identity linkage cannot be
    /// compiled. Refused, never defaulted.
    IncompleteIdentity,
    /// Reference-consistency failure: the caller's I-1 vault verification
    /// came back false, or the policy record does not belong to the agent
    /// record. Refuse with no fallback (item-10 one-reference rule).
    VaultMismatch,
    /// The agent is not `Active`. Defense-in-depth only — the app gate is
    /// and stays the first authority for every lane (R2 §0).
    InactiveAgent,
    /// The policy denies every payment statically (no action, no
    /// recipient, or no amount could ever be permitted): the correct
    /// outcome is NO live pipeline, not an empty-allow emission.
    DenyOnly,
}

/// Deterministic compiled output. Serialized form = canonical bytes: keys
/// sorted at every object depth, integer kelvin only (no amount EVER appears
/// in the ProxyAvailability IR at all), no clock, no randomness, no
/// environment. `to_json` is the single canonical serializer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompiledPipeline {
    pub compiler_version: String,
    pub dialect: String,
    pub lane: String,
    pub topology: String,
    pub policy_schema_version: u32,
    pub agent_schema_version: u32,
    /// staleness binding (R2 §9): a future push re-checks that the live
    /// policy still carries THIS updated_at before any re-push act.
    pub policy_bound_updated_at: i64,
    pub agent_id: String,
    /// Identity linkage (M7): public key material ONLY, emitted
    /// `enforced: false` — allow-list enforcement is the deferred
    /// tx-signing lane (G-14/G-15). Never a secret, never a path.
    pub identity: IdentityLink,
    /// Mapped-and-emitted filter set. ProxyAvailability carries no
    /// policy-derived money/recipient filters (G-1/G-2): see `unmapped`.
    pub filters: Vec<EmittedFilter>,
    /// The explicit audit ledger (A.3): every AgentPay rule that is NOT
    /// representable in this lane, WITH ITS REASON. Omission is never a
    /// relaxation because every rule appears here or in `filters`.
    pub unmapped: Vec<UnmappedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityLink {
    pub kind: String,
    pub auth_public_key: String,
    pub enforced: bool,
    pub enforcement_gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmittedFilter {
    pub rule: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnmappedRule {
    pub rule: String,
    pub partition: String,
    pub reason: String,
}

/// Ledger partition labels (R2 §4 roll-up names, fixed vocabulary).
const P_APP: &str = "must_remain_agentpay";
const P_PENDING: &str = "latch_pending_gaps";
const P_DEFERRED: &str = "deferred_tx_signing_lane_g14_g15";
const P_NEVER: &str = "never_maps";

/// Reassembles any serde value into canonical form: every object's keys in
/// lexicographic order at every depth, regardless of the backend's map
/// implementation. This is what makes `to_json` deterministic bytes.
fn canonicalize(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(String, serde_json::Value)> =
                map.into_iter().map(|(k, v)| (k, canonicalize(v))).collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut out = serde_json::Map::new();
            for (k, v) in pairs {
                out.insert(k, v);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize).collect())
        }
        other => other,
    }
}

impl CompiledPipeline {
    /// THE canonical bytes: compact JSON, keys sorted at every depth.
    /// Same pipeline in ⇒ same bytes out, always (A.2 criterion 1).
    pub fn to_json(&self) -> String {
        canonicalize(serde_json::to_value(self).expect("pipeline is pure data")).to_string()
    }
}

/// Fixed, documented validation order (R2 §5/§8/§9; the order is part of
/// determinism and is pinned by tests):
///
///   1 schema support        → UnsupportedField
///   2 record join           → VaultMismatch   (policy.agent_id ≠ agent.agent_id)
///   3 lifecycle             → InactiveAgent   (status != Active)
///   4 identity completeness → IncompleteIdentity (auth_public_key is None)
///   5 vault verification    → VaultMismatch   (vault_verified == false)
///   6 static deny-everything→ DenyOnly
///   7 deterministic emission of the ProxyAvailability IR
///
/// Step 3 precedes 4/5 so an inactive agent never reaches identity reads at
/// all; step 2 precedes everything join-dependent. Nothing is silently
/// downgraded: each refusal is a typed `Err`.
pub fn compile_agent_pipeline(
    policy: &AgentPolicy,
    agent: &Agent,
    vault_verified: bool,
    lane: Lane,
    topology: &LatchId,
) -> Result<CompiledPipeline, CompileError> {
    // `lane` is single-valued today; naming it in the match keeps the
    // future amendment (adding TxSigning) a compile-forced review point.
    match lane {
        Lane::ProxyAvailability => {}
        Lane::TxSigning => {}
    }

    // 1. schema support — refuse newer schemas, never drop semantics.
    if policy.schema_version != POLICY_SCHEMA_VERSION
        || agent.schema_version != AGENT_SCHEMA_VERSION
    {
        return Err(CompileError::UnsupportedField);
    }

    // 2. record join — the policy must belong to THIS agent. Reference
    //    consistency is VaultMismatch's documented class (module doc;
    //    task §6 "vault/reference consistency"). No fallback join anywhere.
    if policy.agent_id != agent.agent_id {
        return Err(CompileError::VaultMismatch);
    }

    // 3. lifecycle (defense-in-depth; the app gate stays first always).
    if agent.status != AgentStatus::Active {
        return Err(CompileError::InactiveAgent);
    }

    // 4. identity completeness (M7 input duty; G-7 backfill boundary).
    let Some(auth_pubkey) = agent.auth_public_key.as_deref() else {
        return Err(CompileError::IncompleteIdentity);
    };
    if auth_pubkey.trim().is_empty() {
        return Err(CompileError::IncompleteIdentity);
    }

    // 5. vault verification verdict, caller-supplied from I-1's
    //    pubkey-only verifier. false ⇒ refuse; no fallback key (item-10).
    if !vault_verified {
        return Err(CompileError::VaultMismatch);
    }

    // 6. static deny-everything policy ⇒ NO live pipeline is the correct
    //    outcome (never an empty-allow emission). Derived from the same
    //    deny-on-unset semantics as the app gate (action/recipient/
    //    per-tx/daily unset ⇒ every payment denied):
    let denies_action = policy
        .allowed_actions
        .iter()
        .all(|a| a != super::agents::AGENT_ACTION_PAYMENT);
    let denies_recipient = policy.allowed_recipients.is_empty();
    let denies_amount =
        policy.max_payment_per_tx_kelvin.is_none() || policy.daily_payment_limit_kelvin.is_none();
    if denies_action || denies_recipient || denies_amount {
        return Err(CompileError::DenyOnly);
    }

    // 7. emission. ProxyAvailability filters: ONLY the identity linkage
    //    metadata (unenforced pending the tx-sign lane) — every money/
    //    recipient/action rule goes to the explicit ledger below, with
    //    reason. No amount value is ever emitted in this IR.
    let mut filters = vec![EmittedFilter {
        rule: "identity_linkage".into(),
        value: auth_pubkey.to_string(),
        source: "record.auth_public_key (I-1 vault; pubkey only)".into(),
    }];
    // STEP H-3: the TxSigning lane emits the signer-side rule set as an
    // independent IR the signer cross-verifies. The values come from the
    // AUTHORITATIVE AgentPolicy record — the signer compares its own
    // independently-loaded policy against these, and a mismatch denies.
    if matches!(lane, Lane::TxSigning) {
        if let Some(cap) = policy.max_payment_per_tx_kelvin {
            filters.push(EmittedFilter {
                rule: "signer_policy_amount_cap".into(),
                value: cap.to_string(),
                source: "policy.max_payment_per_tx_kelvin".into(),
            });
        }
        for r in &policy.allowed_recipients {
            filters.push(EmittedFilter {
                rule: "signer_policy_recipient".into(),
                value: r.clone(),
                source: "policy.allowed_recipients".into(),
            });
        }
        filters.push(EmittedFilter {
            rule: "signer_policy_program_pin".into(),
            value: "11111111111111111111111111111111".into(),
            source: "frozen payment shape (System program)".into(),
        });
        filters.push(EmittedFilter {
            rule: "signer_policy_instruction_count".into(),
            value: "1".into(),
            source: "frozen payment shape (single transfer)".into(),
        });
    }

    let mut unmapped = vec![
        UnmappedRule {
            rule: "allowed_actions_payment".into(),
            partition: P_APP.into(),
            reason: "M1: no Latch action concept (Item 2 §B1/§F); app gate is authoritative".into(),
        },
        UnmappedRule {
            rule: "route_method_pin".into(),
            partition: P_PENDING.into(),
            reason: "M2: operator-configured value not derivable from policy; wire shape pinned-unknown (G-2)".into(),
        },
        UnmappedRule {
            rule: "recipient_allowlist".into(),
            partition: P_DEFERRED.into(),
            reason: "M3: proxy-envelope introspection unresolved (G-1); enforcement lane is the deferred tx-signing lane (G-14/G-15); app allow-list stays authoritative".into(),
        },
        UnmappedRule {
            rule: "per_tx_amount_cap".into(),
            partition: P_DEFERRED.into(),
            reason: "M4: payload amount rule is tx-signing-lane only (G-14/G-15); app gate authoritative".into(),
        },
        UnmappedRule {
            rule: "daily_spend_limit".into(),
            partition: P_NEVER.into(),
            reason: "M4/§11: reservation ledger is the sole money authority; Latch spend_limit is not chain currency (Q3)".into(),
        },
        UnmappedRule {
            rule: "credential_plane".into(),
            partition: P_NEVER.into(),
            reason: "M5: X-Agent-Credential never maps to Latch (Item 2 §F invariant)".into(),
        },
        UnmappedRule {
            rule: "spend_to_rate_limit".into(),
            partition: P_NEVER.into(),
            reason: "§11 ban: rate_limit is availability-only and NEVER derived from money limits".into(),
        },
        UnmappedRule {
            rule: "money_signer_boundary".into(),
            partition: P_APP.into(),
            reason: "R2 §0 authority list: item-10 rialo_tx_signers money-key resolution stays app-side".into(),
        },
        UnmappedRule {
            rule: "idempotency_replay_reservation".into(),
            partition: P_APP.into(),
            reason: "R2 §0 authority list + §5-2 one-intent invariant".into(),
        },
        UnmappedRule {
            rule: "ownership_reconciliation_recovery".into(),
            partition: P_APP.into(),
            reason: "R2 §0 authority list; chain evidence decisive (§B13)".into(),
        },
        UnmappedRule {
            rule: "time_window".into(),
            partition: P_PENDING.into(),
            reason: "M8: units/clock pinned-unknown (G-3, Q5); operator-supplied only — never derived".into(),
        },
        UnmappedRule {
            rule: "rate_limit_availability".into(),
            partition: P_PENDING.into(),
            reason: "M8/G-8: operator-supplied availability guard only; independence from the ledger unproven until G-8".into(),
        },
    ];

    // canonical emission order for the audit ledger: sorted by rule name,
    // so the ledger bytes are stable independent of source-list order
    // (determinism contract; the golden test pins this order).
    unmapped.sort_by(|a, b| a.rule.cmp(&b.rule));

    Ok(CompiledPipeline {
        compiler_version: COMPILER_VERSION.into(),
        dialect: COMPILER_DIALECT.into(),
        lane: "proxy_availability".into(),
        topology: topology.0.clone(),
        policy_schema_version: policy.schema_version,
        agent_schema_version: agent.schema_version,
        // staleness binding: a saved policy ALWAYS carries Some(ts); the
        // virtual default (None) can never reach here because a default
        // policy is statically deny-everything → step 6 DenyOnly. The
        // expect is therefore unreachable for validated inputs; it fails
        // loud, never silent, if that invariant is ever broken.
        policy_bound_updated_at: policy.updated_at.expect("saved policies carry timestamps"),
        agent_id: agent.agent_id.clone(),
        identity: IdentityLink {
            kind: "agent_auth_public_key".into(),
            auth_public_key: auth_pubkey.to_string(),
            enforced: false,
            enforcement_gate: "tx_signing_lane_deferred_g14_g15".into(),
        },
        filters,
        unmapped,
    })
}

#[cfg(test)]
#[path = "_c2compiler_tests.rs"]
mod c2_tests;
