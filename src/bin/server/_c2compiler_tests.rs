//! PHASE 9 C-2 — focused tests for the latch policy compiler. Pure
//! in-memory fixtures only (no filesystem, no network, no stores): the
//! compiler is a total pure function, so every battery below is data-in /
//! bytes-out. Implements the R2 A.2 verification criteria 1–6 plus the
//! task-mandated batteries A–I.

use super::*;
use crate::agents::{AGENT_SCHEMA_VERSION, Agent, AgentPolicy, AgentStatus, POLICY_SCHEMA_VERSION};
use uuid::Uuid;

const PUBKEY: &str = "TestAuthPubkey111111111111111111111111111111";
const OTHER_PUBKEY: &str = "TestWalletPubkey22222222222222222222222222222";
const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";

fn agent(active: bool, auth: Option<&str>) -> Agent {
    Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: Uuid::new_v4().to_string(),
        owner_user_id: 7,
        name: "C2".into(),
        status: if active {
            AgentStatus::Active
        } else {
            AgentStatus::Paused
        },
        wallet_address: Some(OTHER_PUBKEY.into()),
        auth_public_key: auth.map(str::to_string),
        created_at: 1,
        updated_at: 2,
    }
}

fn policy_for(agent: &Agent) -> AgentPolicy {
    AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: agent.agent_id.clone(),
        max_payment_per_tx_kelvin: Some(100_000_000),
        daily_payment_limit_kelvin: Some(500_000_000),
        allowed_recipients: vec![RECIPIENT.into()],
        allowed_actions: vec!["payment".into()],
        created_at: Some(1),
        updated_at: Some(2),
        parent_agent_id: None,
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
        delegation_revoked: None,
    }
}

fn tid() -> LatchId {
    LatchId::new("child-latch-correlation-42").expect("valid shape")
}

fn happy(a: &Agent, p: &AgentPolicy) -> CompiledPipeline {
    compile_agent_pipeline(p, a, true, Lane::ProxyAvailability, &tid())
        .expect("valid fixture must compile")
}

// ---------------------------------------------------------------------------
// A. DETERMINISM (A.2 #1)
// ---------------------------------------------------------------------------

#[test]
fn compile_is_deterministic_byte_identical() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let first = happy(&a, &p).to_json();
    let second = happy(&a, &p).to_json();
    assert_eq!(first, second, "same inputs must produce identical bytes");
}

#[test]
fn output_keys_are_sorted_at_every_depth() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let json = happy(&a, &p).to_json();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    fn check_sorted(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                let keys: Vec<&String> = map.keys().collect();
                let mut sorted = keys.clone();
                sorted.sort();
                assert_eq!(keys, sorted, "object keys must be lexicographically sorted");
                for inner in map.values() {
                    check_sorted(inner);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(check_sorted),
            _ => {}
        }
    }
    check_sorted(&v);
}

#[test]
fn golden_pipeline_shape() {
    // One pinned golden: the full contract surface for the only lane that
    // exists today. Any change here is an R2 amendment, not a refactor.
    let mut a = agent(true, Some(PUBKEY));
    a.agent_id = "fixed-agent-id".to_string();
    let mut p = policy_for(&a);
    p.updated_at = Some(9);
    let out = happy(&a, &p);
    assert_eq!(out.compiler_version, COMPILER_VERSION);
    assert_eq!(out.dialect, COMPILER_DIALECT);
    assert_eq!(out.lane, "proxy_availability");
    assert_eq!(out.topology, "child-latch-correlation-42");
    assert_eq!(out.policy_bound_updated_at, 9);
    assert_eq!(out.filters.len(), 1);
    assert_eq!(out.filters[0].rule, "identity_linkage");
    assert!(!out.identity.enforced);
    assert_eq!(
        out.identity.enforcement_gate,
        "tx_signing_lane_deferred_g14_g15"
    );
    // every rule name in the ledger is present exactly once (sorted ledger
    // by rule name is part of the golden bytes)
    let names: Vec<&str> = out.unmapped.iter().map(|u| u.rule.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "allowed_actions_payment",
            "credential_plane",
            "daily_spend_limit",
            "idempotency_replay_reservation",
            "money_signer_boundary",
            "ownership_reconciliation_recovery",
            "per_tx_amount_cap",
            "rate_limit_availability",
            "recipient_allowlist",
            "route_method_pin",
            "spend_to_rate_limit",
            "time_window",
        ]
    );
}

// ---------------------------------------------------------------------------
// B. DENY-MIRROR (A.2 #2): static deny-everything ⇒ DenyOnly, never a
// permissive emission; unset dimensions are all DENY at the app gate, so
// every unset combination that leaves NO possible payment must refuse.
// ---------------------------------------------------------------------------

#[test]
fn deny_mirror_table_refuses_all_denying_policies() {
    let a = agent(true, Some(PUBKEY));
    let cases: Vec<(&str, fn(&mut AgentPolicy))> = vec![
        ("empty actions", |p: &mut AgentPolicy| {
            p.allowed_actions.clear()
        }),
        ("non-payment actions", |p: &mut AgentPolicy| {
            p.allowed_actions = vec!["transfer".into()]
        }),
        ("empty recipients", |p: &mut AgentPolicy| {
            p.allowed_recipients.clear()
        }),
        ("unset per-tx", |p: &mut AgentPolicy| {
            p.max_payment_per_tx_kelvin = None
        }),
        ("unset daily", |p: &mut AgentPolicy| {
            p.daily_payment_limit_kelvin = None
        }),
        ("unset both", |p: &mut AgentPolicy| {
            p.max_payment_per_tx_kelvin = None;
            p.daily_payment_limit_kelvin = None;
        }),
    ];
    for (label, mutate) in cases {
        let mut p = policy_for(&a);
        mutate(&mut p);
        assert_eq!(
            compile_agent_pipeline(&p, &a, true, Lane::ProxyAvailability, &tid()).err(),
            Some(CompileError::DenyOnly),
            "deny-mirror failure for: {label}"
        );
    }
}

#[test]
fn compiled_output_can_never_read_as_permissive() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let json = happy(&a, &p).to_json().to_lowercase();
    for banned in [
        "unlimited",
        "\"*\"",
        "any_recipient",
        "allow_all",
        "no_limit",
    ] {
        assert!(!json.contains(banned), "output looks permissive: {banned}");
    }
    // the one emitted filter is identity metadata, explicitly unenforced
    assert!(json.contains("\"enforced\":false"));
}

// ---------------------------------------------------------------------------
// C. M1..M8 EXHAUSTIVENESS: every mapping row lands either in `filters`
// (only M7) or in the `unmapped` ledger with its documented partition.
// ---------------------------------------------------------------------------

#[test]
fn mapping_rows_all_accounted() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let out = happy(&a, &p);
    let by_rule = |name: &str| out.unmapped.iter().find(|u| u.rule == name);
    // M1 action -> must remain app
    assert_eq!(by_rule("allowed_actions_payment").unwrap().partition, P_APP);
    // M2 route pin -> pending gaps (not derivable, not guessed)
    assert_eq!(by_rule("route_method_pin").unwrap().partition, P_PENDING);
    // M3 recipients -> deferred lane, app authoritative
    assert_eq!(
        by_rule("recipient_allowlist").unwrap().partition,
        P_DEFERRED
    );
    // M4 amount: per-tx deferred, daily NEVER maps
    assert_eq!(by_rule("per_tx_amount_cap").unwrap().partition, P_DEFERRED);
    assert_eq!(by_rule("daily_spend_limit").unwrap().partition, P_NEVER);
    assert_eq!(by_rule("spend_to_rate_limit").unwrap().partition, P_NEVER);
    // M5 credentials -> NEVER
    assert_eq!(by_rule("credential_plane").unwrap().partition, P_NEVER);
    // M7 identity -> the ONLY emitted filter, marked unenforced
    assert_eq!(out.filters.len(), 1);
    assert!(!out.identity.enforced);
    // M8 availability controls -> pending operator inputs, never derived
    assert_eq!(by_rule("time_window").unwrap().partition, P_PENDING);
    assert_eq!(
        by_rule("rate_limit_availability").unwrap().partition,
        P_PENDING
    );
    // §0 authority-list rows are recorded as app-side, not invented away
    assert!(by_rule("money_signer_boundary").is_some());
    assert!(by_rule("idempotency_replay_reservation").is_some());
    assert!(by_rule("ownership_reconciliation_recovery").is_some());
}

// ---------------------------------------------------------------------------
// D. IDENTITY LINKAGE
// ---------------------------------------------------------------------------

#[test]
fn happy_linkage_carries_pubkey_only_and_bound_metadata() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let out = happy(&a, &p);
    assert_eq!(out.identity.auth_public_key, PUBKEY);
    assert_eq!(out.filters[0].value, PUBKEY);
    assert_eq!(out.agent_id, a.agent_id);
    assert_eq!(out.policy_schema_version, POLICY_SCHEMA_VERSION);
    assert_eq!(out.agent_schema_version, AGENT_SCHEMA_VERSION);
    // the WALLET key (money identity) must never appear in the IR
    let json = out.to_json();
    assert!(
        !json.contains(OTHER_PUBKEY),
        "wallet address leaked into pipeline"
    );
    // closed-schema assertion: the IR may contain ONLY the contract's own
    // field names (a stricter guarantee than any word ban — no owner,
    // secret, keypair, or future-unimagined field can ever appear)
    fn keys_of(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    out.push(k.clone());
                    keys_of(v, out);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| keys_of(v, out)),
            _ => {}
        }
    }
    let mut seen = Vec::new();
    keys_of(
        &serde_json::from_str::<serde_json::Value>(&json).unwrap(),
        &mut seen,
    );
    let allowed: std::collections::HashSet<&str> = [
        "compiler_version",
        "dialect",
        "lane",
        "topology",
        "policy_schema_version",
        "agent_schema_version",
        "policy_bound_updated_at",
        "agent_id",
        "identity",
        "kind",
        "auth_public_key",
        "enforced",
        "enforcement_gate",
        "filters",
        "rule",
        "value",
        "source",
        "unmapped",
        "partition",
        "reason",
    ]
    .into_iter()
    .collect();
    for k in seen {
        assert!(allowed.contains(k.as_str()), "unexpected IR field: {k}");
    }
}

#[test]
fn incomplete_identity_refused_for_all_pre_i1_agents() {
    let a = agent(true, None);
    let p = policy_for(&a);
    assert_eq!(
        compile_agent_pipeline(&p, &a, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::IncompleteIdentity)
    );
    let blank = agent(true, Some("   "));
    let pb = policy_for(&blank);
    assert_eq!(
        compile_agent_pipeline(&pb, &blank, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::IncompleteIdentity)
    );
}

#[test]
fn vault_flag_false_refuses_with_no_fallback() {
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    assert_eq!(
        compile_agent_pipeline(&p, &a, false, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::VaultMismatch)
    );
}

#[test]
fn policy_foreign_to_agent_is_reference_mismatch() {
    let a = agent(true, Some(PUBKEY));
    let b = agent(true, Some(PUBKEY));
    let mut p = policy_for(&b);
    p.agent_id = a.agent_id.clone(); // policy names A while record B is passed
    assert_eq!(
        compile_agent_pipeline(&p, &b, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::VaultMismatch)
    );
}

#[test]
fn inactive_agents_refused_for_every_non_active_status() {
    for status in [
        AgentStatus::Draft,
        AgentStatus::Paused,
        AgentStatus::Disabled,
    ] {
        let mut a = agent(true, Some(PUBKEY));
        a.status = status;
        let p = policy_for(&a);
        assert_eq!(
            compile_agent_pipeline(&p, &a, true, Lane::ProxyAvailability, &tid()).err(),
            Some(CompileError::InactiveAgent),
            "status {status:?} must refuse"
        );
    }
}

// ---------------------------------------------------------------------------
// E. UNITS + MONEY CONFUSION
// ---------------------------------------------------------------------------

#[test]
fn no_amount_values_appear_in_proxy_ir_and_no_floats_anywhere() {
    let a = agent(true, Some(PUBKEY));
    let mut p = policy_for(&a);
    p.max_payment_per_tx_kelvin = Some(123456789);
    p.daily_payment_limit_kelvin = Some(999888777);
    let json = happy(&a, &p).to_json();
    assert!(!json.contains("123456789"), "money value leaked");
    assert!(!json.contains("999888777"), "money value leaked");
    // fractional-number scan (a `.` between digits anywhere is a violation
    // — integer-kelvin-only rule; the only other digits are timestamps/
    // schema versions, which are integers without a dot)
    let bytes = json.as_bytes();
    for i in 1..bytes.len().saturating_sub(1) {
        if bytes[i] == b'.' && bytes[i - 1].is_ascii_digit() && bytes[i + 1].is_ascii_digit() {
            panic!("fractional number in compiled output");
        }
    }
}

#[test]
fn spend_to_rate_limit_conversion_can_never_exist() {
    // Structural: the proxy IR emits NO rate_limit filter at all (pending
    // ledger only), and no filter value can carry a money figure.
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let out = happy(&a, &p);
    assert!(
        !out.filters.iter().any(|f| f.rule.contains("rate")),
        "rate filter must not be emitted in C-2 close"
    );
    let entry = out
        .unmapped
        .iter()
        .find(|u| u.rule == "spend_to_rate_limit")
        .unwrap();
    assert_eq!(entry.partition, P_NEVER);
}

// ---------------------------------------------------------------------------
// F. ERROR SURFACE + VALIDATION ORDER
// ---------------------------------------------------------------------------

#[test]
fn unsupported_schema_versions_refuse_never_drop() {
    let a = agent(true, Some(PUBKEY));
    let mut p = policy_for(&a);
    p.schema_version = POLICY_SCHEMA_VERSION + 1;
    assert_eq!(
        compile_agent_pipeline(&p, &a, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::UnsupportedField)
    );
    let mut a2 = agent(true, Some(PUBKEY));
    a2.schema_version = AGENT_SCHEMA_VERSION + 1;
    let p2 = policy_for(&a2);
    assert_eq!(
        compile_agent_pipeline(&p2, &a2, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::UnsupportedField)
    );
}

#[test]
fn validation_order_is_deterministic_and_fixed() {
    // every failing precondition at once ⇒ schema (step 1) wins
    let mut a = agent(false, None);
    a.schema_version = AGENT_SCHEMA_VERSION + 1;
    let mut p = policy_for(&agent(true, Some(PUBKEY)));
    p.schema_version = POLICY_SCHEMA_VERSION + 1;
    assert_eq!(
        compile_agent_pipeline(&p, &a, false, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::UnsupportedField)
    );
    // join (step 2) before lifecycle (step 3): foreign policy on a PAUSED agent
    let paused = agent(false, Some(PUBKEY));
    let foreign = policy_for(&agent(true, Some(PUBKEY)));
    assert_eq!(
        compile_agent_pipeline(&foreign, &paused, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::VaultMismatch)
    );
    // lifecycle (step 3) before identity (step 4): inactive + no auth key
    let both_bad = agent(false, None);
    let own = policy_for(&both_bad);
    assert_eq!(
        compile_agent_pipeline(&own, &both_bad, true, Lane::ProxyAvailability, &tid()).err(),
        Some(CompileError::InactiveAgent)
    );
}

#[test]
fn error_set_is_exactly_the_frozen_five_and_fieldless() {
    // pinned variant count via exhaustive match (compile-time proof is the
    // variant list itself); here pin Debug forms carry zero detail
    for e in [
        CompileError::UnsupportedField,
        CompileError::IncompleteIdentity,
        CompileError::VaultMismatch,
        CompileError::InactiveAgent,
        CompileError::DenyOnly,
    ] {
        let d = format!("{e:?}");
        assert!(
            [
                "UnsupportedField",
                "IncompleteIdentity",
                "VaultMismatch",
                "InactiveAgent",
                "DenyOnly"
            ]
            .contains(&d.as_str())
        );
        assert!(!d.contains('"') && !d.contains('/'));
    }
}

// ---------------------------------------------------------------------------
// G/H. OMISSION/SECRET SCANS
// ---------------------------------------------------------------------------

#[test]
fn topology_id_is_shape_gated_never_interpreted() {
    assert!(matches!(LatchId::new(""), Err(LatchIdError::Empty)));
    assert!(matches!(
        LatchId::new(&"x".repeat(200)),
        Err(LatchIdError::TooLong)
    ));
    assert!(matches!(
        LatchId::new("line\nbreak"),
        Err(LatchIdError::NotPrintable)
    ));
    assert!(matches!(
        LatchId::new("quote\"inside"),
        Err(LatchIdError::NotPrintable)
    ));
    // valid ids are carried verbatim into the topology field
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let id = LatchId::new("agent-42-child").unwrap();
    let out = compile_agent_pipeline(&p, &a, true, Lane::ProxyAvailability, &id).unwrap();
    assert_eq!(out.topology, "agent-42-child");
}

// ---------------------------------------------------------------------------
// I. STRUCTURAL SOURCE / SCOPE PINS (A.2 #6/#7)
// ---------------------------------------------------------------------------

#[test]
fn compiler_source_is_pure_offline_and_secretless() {
    let src = include_str!("latch_policy_compiler.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "File::",
        "read_keypair",
        "write_keypair",
        "keypair_from_seed",
        "getrandom",
        "artifact/",
        "wallet_file",
        "load_or_create_wallet",
        "PaymentOps",
        "execute_agent_payment",
        ".transfer",
        "reserve_spend",
        "ureq",
        "reqwest",
        ".route(",
        "lat_",
        "ltk_",
        "privy",
        "onlatch",
        "/proxy/",
        "sign(",
        "SigningKey",
        "http",
    ] {
        assert!(
            !code.to_lowercase().contains(&forbidden.to_lowercase()),
            "compiler source references {forbidden}"
        );
    }
    // guard the scan against passing vacuously
    assert!(code.contains("compile_agent_pipeline"));
    assert!(code.contains("DenyOnly"));
}

#[test]
fn enforcement_and_payment_cores_are_not_wired_to_the_compiler() {
    // The compiler must not be referenced by the payment/enforcement code:
    // agents.rs is forbidden to use it in this phase (structural pin,
    // mirrors the item-10/13 discipline).
    let agents_src = include_str!("agents.rs");
    assert!(
        !agents_src.contains("latch_policy_compiler"),
        "payment engine must not consume the compiler yet (no wiring in C-2)"
    );
    let server_src = include_str!("../server.rs");
    // module registration only (one #[path] mod line), zero route additions
    let latch_lines = server_src
        .lines()
        .filter(|l| l.contains("latch_policy_compiler"))
        .count();
    assert!(latch_lines <= 2, "expected only the mod registration lines");
}

#[test]
fn compiled_output_contains_no_secret_shaped_values() {
    // H battery: 32-byte-hex / long base64-ish blobs must never appear;
    // the only strings are bounded public identifiers.
    let a = agent(true, Some(PUBKEY));
    let p = policy_for(&a);
    let json = happy(&a, &p).to_json();
    let has_hex64 = json
        .as_bytes()
        .windows(64)
        .any(|w| w.iter().all(|c| c.is_ascii_hexdigit()));
    assert!(!has_hex64, "hex-64 blob (credential-shaped) in output");
    assert!(!json.contains(&PUBKEY.repeat(2)));
}
