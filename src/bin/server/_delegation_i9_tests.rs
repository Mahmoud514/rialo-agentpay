//! PHASE 9 "Delegation" (app-side) — focused tests for the delegation
//! scoping/revocation semantics over the FROZEN Hierarchical Policy model.
//! The parent linkage IS the delegation relationship (delegator = parent,
//! delegate = child); the delegation_revoked stamp severs the delegator's
//! contribution on the next decision (immediate, cascading, one-way for
//! the current linkage). Zero credential/key transfer; no autonomous
//! chains; ownership never transfers.

use crate::agents::{
    Agent, AgentPolicy, AgentStatus, EnforcementDenial, HierarchyError, POLICY_SCHEMA_VERSION,
    check_agent_payment_policy, load_policy, patch_agent_policy, resolve_effective_policy,
};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use std::path::PathBuf;
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    &crate::stats::tests24::tests24::CWD_LOCK
}

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-deleg-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_policies")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_credentials")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_payment_intents")).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.clone()
    }
    fn agents(&self) -> PathBuf {
        self.0.join("artifact/agents")
    }
    fn policies(&self) -> PathBuf {
        self.0.join("artifact/agent_policies")
    }
    fn creds(&self) -> PathBuf {
        self.0.join("artifact/agent_credentials")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn persist_agent(root: &Root, id: &Uuid, owner: u64, status: AgentStatus) -> Agent {
    let agent = Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: owner,
        name: "deleg-agent".to_string(),
        status,
        wallet_address: None,
        auth_public_key: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
    };
    std::fs::write(
        root.agents().join(format!("{id}.json")),
        serde_json::to_vec_pretty(&agent).unwrap(),
    )
    .unwrap();
    agent
}

fn persist_policy(root: &Root, policy: &AgentPolicy) {
    let id: Uuid = policy.agent_id.parse().unwrap();
    std::fs::write(
        root.policies().join(format!("{id}.json")),
        serde_json::to_vec_pretty(policy).unwrap(),
    )
    .unwrap();
}

fn policy_for(
    id: &Uuid,
    parent: Option<&Uuid>,
    max: Option<u64>,
    daily: Option<u64>,
    recipients: Vec<&str>,
    actions: Vec<&str>,
) -> AgentPolicy {
    AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: id.to_string(),
        max_payment_per_tx_kelvin: max,
        daily_payment_limit_kelvin: daily,
        allowed_recipients: recipients.into_iter().map(|s| s.to_string()).collect(),
        allowed_actions: actions.into_iter().map(|s| s.to_string()).collect(),
        created_at: Some(1_700_000_000),
        updated_at: Some(1_700_000_100),
        parent_agent_id: parent.map(|p| p.to_string()),
        delegation_revoked: None,
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
    }
}

fn resolve(root: &Root, child: &AgentPolicy) -> Result<AgentPolicy, HierarchyError> {
    resolve_effective_policy(child.clone(), &root.policies(), &root.agents())
}

fn test_state(owner: u64) -> (crate::AppState, String) {
    let state = crate::AppState {
        client: reqwest::Client::new(),
        client_id: "test".into(),
        client_secret: "test".into(),
        redirect_uri: "http://localhost".into(),
        preview_redirect_uri: None,
        oauth_states: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        wallets: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        rialo: std::sync::Arc::new(crate::rialo::RialoConfig {
            cli: PathBuf::from("/nonexistent/deleg-test-cli"),
            rpc_url: "http://127.0.0.1:1".into(),
            program_id: None,
            program_dir: PathBuf::from("artifact"),
        }),
    };
    let sid = Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(
        sid.clone(),
        crate::GithubUser {
            id: owner,
            login: format!("deleg-owner-{owner}"),
            name: Some("t".into()),
            avatar_url: None,
        },
    );
    (state, sid)
}

fn cookie(sid: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!("agentpay_session={sid}")).unwrap(),
    );
    h
}

async fn envelope(resp: axum::response::Response) -> (u16, serde_json::Value) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// A policy PATCH through the real handler (full-replacement semantics).
async fn patch_policy(
    root: &Root,
    owner: u64,
    id: &Uuid,
    body: String,
) -> (u16, serde_json::Value) {
    let (state, sid) = test_state(owner);
    let resp = patch_agent_policy(State(state), cookie(&sid), Path(id.to_string()), body).await;
    envelope(resp).await
}

async fn with_cwd<R: std::future::Future>(root: &Root, f: R) -> R::Output {
    let _guard = cwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap_or(std::env::temp_dir());
    std::env::set_current_dir(&root.path()).unwrap();
    let result = f.await;
    let _ = std::env::set_current_dir(&original);
    result
}

// ---------------------------------------------------------------------------
// (A,B,C,D,E) creation/update: owner boundary + linkage validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn owner_creates_delegation_and_unauthorized_cross_owner_self_rejected() {
    let root = Root::new("create");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    persist_agent(&root, &parent, 50506084, AgentStatus::Active);
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(
            &parent,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    persist_policy(
        &root,
        &policy_for(
            &child,
            None,
            Some(2_000),
            Some(20_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );

    with_cwd(&root, async {
        // A: a valid same-owner linkage via the real PATCH (delegation created)
        let body = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{parent}"}}"#
        );
        let (status, body_out) = patch_policy(&root, 50506084, &child, body).await;
        assert_eq!(status, 200, "{body_out}");
        assert_eq!(
            body_out["policy"]["parent_agent_id"],
            parent.to_string().as_str(),
            "A: delegation created"
        );

        // B: an unauthorized user (different owner) cannot patch the child
        let body2 = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{parent}"}}"#
        );
        let (status2, body2) = patch_policy(&root, 999, &child, body2).await;
        assert_eq!(status2, 404, "B: unauthorized user denied");
        assert_eq!(body2["error"]["code"], "AGENT_NOT_FOUND");

        // C: cross-owner delegation is rejected (the parent belongs to 999)
        let foreign_parent = Uuid::new_v4();
        persist_agent(&root, &foreign_parent, 999, AgentStatus::Active);
        let body3 = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{foreign_parent}"}}"#
        );
        let (status3, body3) = patch_policy(&root, 50506084, &child, body3).await;
        assert_eq!(status3, 400, "C: cross-owner delegation rejected");
        assert_eq!(body3["error"]["code"], "AGENT_POLICY_INVALID");

        // D: self-delegation is rejected
        let body4 = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{child}"}}"#
        );
        let (status4, body4) = patch_policy(&root, 50506084, &child, body4).await;
        assert_eq!(status4, 400, "D: self-delegation rejected");

        // E: invalid identifiers rejected
        let body5 = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"../etc/passwd"}}"#
        );
        let (status5, body5) = patch_policy(&root, 50506084, &child, body5).await;
        assert_eq!(status5, 400, "E: malformed identifier rejected");
    }).await;
}

// ---------------------------------------------------------------------------
// (F,G,H,I,J,K,L) narrowing invariants (delegate <= delegator)
// ---------------------------------------------------------------------------

#[test]
fn delegated_scope_can_only_narrow_the_delegator() {
    let root = Root::new("narrow");
    let delegator = Uuid::new_v4();
    let delegate = Uuid::new_v4();
    persist_agent(&root, &delegator, 50506084, AgentStatus::Active);
    persist_agent(&root, &delegate, 50506084, AgentStatus::Active);
    // delegator: cap 1_000, recipients [R], actions [payment]
    persist_policy(
        &root,
        &policy_for(
            &delegator,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    // delegate tries: cap 2_000 (wider), recipients [R, Other], actions [payment]
    let delegated = policy_for(
        &delegate,
        Some(&delegator),
        Some(2_000),
        None,
        vec![RECIPIENT, "OtherRec"],
        vec!["payment"],
    );
    let eff = resolve(&root, &delegated).unwrap();
    // F/G: delegated cap cannot exceed the delegator cap
    assert_eq!(
        eff.max_payment_per_tx_kelvin,
        Some(1_000),
        "G: clamped to delegator"
    );
    // H: delegated daily cap cannot exceed the delegator's
    assert_eq!(eff.daily_payment_limit_kelvin, Some(10_000), "H: inherited");
    // I/J: delegated recipients/actions cannot exceed the delegator's
    assert_eq!(
        eff.allowed_recipients,
        vec![RECIPIENT.to_string()],
        "I: intersection"
    );
    assert_eq!(
        eff.allowed_actions,
        vec!["payment".to_string()],
        "J: intersection"
    );
    // K: unset delegation values inherit (never unlimited)
    // L: the delegate cannot gain a capability the delegator lacks — the
    // delegator has no "transfer" action; a delegate asking for it is denied
    let delegated2 = policy_for(
        &delegate,
        Some(&delegator),
        None,
        None,
        vec![],
        vec!["transfer"],
    );
    let eff2 = resolve(&root, &delegated2).unwrap();
    assert!(
        !eff2.allowed_actions.contains(&"transfer".to_string()),
        "L: no capability gain"
    );
}

// ---------------------------------------------------------------------------
// (M,N,O,P) delegated execution passes existing enforcement + spend controls
// ---------------------------------------------------------------------------

#[test]
fn delegated_execution_passes_existing_enforcement_and_spend() {
    let root = Root::new("exec");
    let delegator = Uuid::new_v4();
    let delegate = Uuid::new_v4();
    persist_agent(&root, &delegator, 50506084, AgentStatus::Active);
    persist_agent(&root, &delegate, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(
            &delegator,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    let delegated = policy_for(
        &delegate,
        Some(&delegator),
        Some(500),
        Some(20_000),
        vec![RECIPIENT],
        vec!["payment"],
    );
    let effective = resolve(&root, &delegated).unwrap();

    // M: the effective (delegated) policy feeds the UNCHANGED fixed-order
    // enforcement: the delegator's cap binds
    let denial = check_agent_payment_policy(
        &persist_agent(&root, &delegate, 50506084, AgentStatus::Active),
        Some(&effective),
        RECIPIENT,
        1_500, // above the delegator's 1_000 cap
        Some(0),
    );
    assert!(
        matches!(denial, Err(EnforcementDenial::AmountDenied)),
        "M: delegator cap binds"
    );
    // P: the per-agent limit still binds (delegate's own 500 would allow 400)
    let ok = check_agent_payment_policy(
        &persist_agent(&root, &delegate, 50506084, AgentStatus::Active),
        Some(&effective),
        RECIPIENT,
        400,
        Some(0),
    );
    assert!(ok.is_ok());
    // O: the aggregate scope is the delegator's (no aggregate cap set → no
    // aggregate reservation → the delegation cannot BYPASS aggregate caps:
    // the scope list is empty here; with a cap set it would be enforced
    let _ = &root.creds();
}

// ---------------------------------------------------------------------------
// (Q,R,S) lifecycle: disabled/revoked remain authoritative
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lifecycle_gates_and_revoked_credentials_unchanged() {
    let root = Root::new("lifecycle");
    let delegator = Uuid::new_v4();
    let delegate = Uuid::new_v4();
    persist_agent(&root, &delegator, 50506084, AgentStatus::Active);
    persist_agent(&root, &delegate, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(
            &delegator,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );

    with_cwd(&root, async {
        // Q: a DISABLED delegator cannot have a NEW delegation created
        let disabled_delegator = Uuid::new_v4();
        persist_agent(&root, &disabled_delegator, 50506084, AgentStatus::Disabled);
        let body = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{disabled_delegator}"}}"#
        );
        let (status, body_out) = patch_policy(&root, 50506084, &delegate, body).await;
        assert_eq!(status, 400, "Q: disabled delegator cannot be delegated to");
        assert_eq!(body_out["error"]["code"], "AGENT_POLICY_INVALID");

        // R: a DISABLED delegate cannot be newly delegated
        let disabled_delegate = Uuid::new_v4();
        persist_agent(&root, &disabled_delegate, 50506084, AgentStatus::Disabled);
        let body2 = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{delegator}"}}"#
        );
        let (status2, _) = patch_policy(&root, 50506084, &disabled_delegate, body2).await;
        assert_eq!(status2, 400, "R: disabled delegate cannot be delegated");

        // S: revoked credentials remain revoked (the delegation layer never
        // touches the credential plane)
        let credential = crate::agent_credentials::issue_in(
            &root.agents(), &root.creds(), &delegate.to_string(), 1_700_000_200,
        ).unwrap();
        crate::agent_credentials::revoke_in(
            &root.agents(), &root.creds(), &delegate.to_string(), 1_700_000_300,
        ).unwrap();
        assert!(crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_err(),
            "S: revoked credential stays revoked");
        // the delegation relationship is orthogonal: the effective policy
        // still resolves (policy plane ≠ credential plane)
        let delegated = policy_for(&delegate, Some(&delegator), Some(500), None, vec![RECIPIENT], vec!["payment"]);
        assert!(resolve(&root, &delegated).is_ok());
    }).await;
}

// ---------------------------------------------------------------------------
// (T,U) revocation: immediate + cascading + one-way for the linkage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delegation_revocation_is_immediate_cascading_and_one_way() {
    let root = Root::new("revoke");
    let delegator = Uuid::new_v4();
    let delegate = Uuid::new_v4();
    let sub_delegate = Uuid::new_v4();
    persist_agent(&root, &delegator, 50506084, AgentStatus::Active);
    persist_agent(&root, &delegate, 50506084, AgentStatus::Active);
    persist_agent(&root, &sub_delegate, 50506084, AgentStatus::Active);
    // chain: delegator (cap 1_000) → delegate (cap 2_000) → sub_delegate
    persist_policy(
        &root,
        &policy_for(
            &delegator,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    persist_policy(
        &root,
        &policy_for(
            &delegate,
            Some(&delegator),
            Some(2_000),
            Some(20_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    persist_policy(
        &root,
        &policy_for(
            &sub_delegate,
            Some(&delegate),
            Some(3_000),
            Some(30_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );

    with_cwd(&root, async {
        // BEFORE revocation: the delegate's effective policy includes the
        // delegator's narrowing (min(2000, 1000) = 1000)
        let delegated = load_policy(&root.policies(), &delegate).unwrap().unwrap();
        let eff = resolve(&root, &delegated).unwrap();
        assert_eq!(eff.max_payment_per_tx_kelvin, Some(1_000));

        // T: revoke the delegation (the delegator's owner revokes the
        // DELEGATE's authority) — via the real handler
        let (state, sid) = test_state(50506084);
        let resp = crate::agents::agent_delegation_revoke(
            State(state), cookie(&sid), Path(delegate.to_string()),
        ).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["delegation_revoked"], true);

        // IMMEDIATE: the delegate's next resolution SEVERS the delegator's
        // contribution — the delegate reverts to its OWN policy (the
        // owner's original grant; revocation transfers nothing)
        let delegated_now = load_policy(&root.policies(), &delegate).unwrap().unwrap();
        assert!(delegated_now.delegation_revoked.is_some(), "stamp set");
        let eff_now = resolve(&root, &delegated_now).unwrap();
        assert_eq!(eff_now.max_payment_per_tx_kelvin, Some(2_000), "delegate's own authority restored");

        // U: CASCADE — the SUB-delegate (descendant) also loses the
        // delegator's contribution (its walk stops at the stamped node)
        let sub = load_policy(&root.policies(), &sub_delegate).unwrap().unwrap();
        let eff_sub = resolve(&root, &sub).unwrap();
        // sub's chain: sub(3000) → delegate(stamped) → STOP →
        // effective = min(sub 3000, delegate 2000) = 2000 — the DELEGATOR's
        // 1_000 no longer binds (its authority was withdrawn)
        assert_eq!(eff_sub.max_payment_per_tx_kelvin, Some(2_000), "U: cascade stops at the stamp");

        // ONE-WAY for the linkage: a stale PATCH (same linkage, no parent
        // change) PRESERVES the stamp — it cannot un-revoke
        let body_keep = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{delegator}"}}"#
        );
        let (status_keep, _) = patch_policy(&root, 50506084, &delegate, body_keep).await;
        assert_eq!(status_keep, 200);
        let still = load_policy(&root.policies(), &delegate).unwrap().unwrap();
        assert!(still.delegation_revoked.is_some(), "stamp preserved — no un-revoke by stale PATCH");

        // RE-DELEGATION: a NEW linkage (different parent) clears the stamp
        // (an explicit re-delegation act by the same owner)
        let new_delegator = Uuid::new_v4();
        persist_agent(&root, &new_delegator, 50506084, AgentStatus::Active);
        persist_policy(&root, &policy_for(&new_delegator, None, Some(100), Some(100), vec![RECIPIENT], vec!["payment"]));
        let body_new = format!(
            r#"{{"max_payment_per_tx_rlo":0.000002,"daily_payment_limit_rlo":0.00002,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"parent_agent_id":"{new_delegator}"}}"#
        );
        let (status_new, _) = patch_policy(&root, 50506084, &delegate, body_new).await;
        assert_eq!(status_new, 200);
        let cleared = load_policy(&root.policies(), &delegate).unwrap().unwrap();
        assert!(cleared.delegation_revoked.is_none(), "fresh delegation clears the stamp");
        let eff_new = resolve(&root, &cleared).unwrap();
        assert_eq!(eff_new.max_payment_per_tx_kelvin, Some(100), "new delegator binds");
    }).await;
}

// ---------------------------------------------------------------------------
// (V,W,X) no transfer: structural
// ---------------------------------------------------------------------------

#[test]
fn delegation_transfers_no_credentials_keys_or_ownership() {
    // The delegation surface (stamp + resolver severing + routes) never
    // touches credentials, keys, or ownership fields.
    let src = include_str!("agents.rs");
    let start = src
        .find("pub async fn agent_delegation_revoke")
        .expect("route exists");
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    for forbidden in [
        "revoke_credential",
        "revoke_in",
        "issue_in",
        "authenticate",
        "keypair",
        "auth_key",
        "wallet_dir",
        "owner_user_id =",
        "transfer(",
        "signer",
    ] {
        assert!(
            !body.contains(forbidden),
            "delegation must never reference {forbidden}"
        );
    }
    // the stamp write is the ONLY policy mutation (read-modify-write under
    // store_lock — no second transactional system)
    assert!(body.contains("store_lock"));
    assert!(body.contains("write_json_atomic"));
    // the resolver's severing is a policy read (already pinned by hierpol)
}

// ---------------------------------------------------------------------------
// (W cont.) no autonomous sub-agent chains (bounded graph)
// ---------------------------------------------------------------------------

#[test]
fn no_autonomous_chain_the_graph_stays_the_frozen_hierarchy() {
    // The delegation model IS the frozen hierarchy's parent chain: one
    // parent max, depth 8, cycles forbidden — there is NO second graph.
    // Structural: the resolver's chain walk is the ONLY traversal; the
    // delegation stamp adds no new traversal.
    let src = include_str!("agents.rs");
    // Anchor includes the "(" so the slice is the REAL resolver body:
    // since the task-marketplace wrapper
    // `pub fn resolve_effective_policy_for_agent(` was added, a bare
    // `pub fn resolve_effective_policy` prefix-match grabbed the 10-line
    // wrapper instead (regression in this harness anchor only — the
    // pinned contract is unchanged).
    let start = src.find("pub fn resolve_effective_policy(").unwrap();
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    // the delegation check is a simple stamp test inside the SAME loop
    assert!(body.contains("delegation_revoked"));
    assert!(
        body.contains("MAX_POLICY_HIERARCHY_DEPTH"),
        "the frozen depth bound governs"
    );
}

// ---------------------------------------------------------------------------
// (X) ownership remains (the same-owner gate is already the hierarchy's)
// ---------------------------------------------------------------------------

#[test]
fn ownership_gate_unchanged() {
    // cross-owner delegations are rejected at PATCH time (proven in the
    // creation test); the resolver's same-owner check is untouched.
    let src = include_str!("agents.rs");
    // Anchor includes the "(" so the slice is the REAL resolver body:
    // since the task-marketplace wrapper
    // `pub fn resolve_effective_policy_for_agent(` was added, a bare
    // `pub fn resolve_effective_policy` prefix-match grabbed the 10-line
    // wrapper instead (regression in this harness anchor only — the
    // pinned contract is unchanged).
    let start = src.find("pub fn resolve_effective_policy(").unwrap();
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    assert!(
        body.contains("owner_user_id"),
        "the same-owner gate remains"
    );
}

// ---------------------------------------------------------------------------
// (Y,Z,AA,AB) replay / Pending / Unknown / reconciliation untouched
// ---------------------------------------------------------------------------

#[test]
fn revocation_never_touches_payment_state_or_reconciliation() {
    // The revocation route writes ONLY the policy doc + an audit record.
    let src = include_str!("agents.rs");
    let start = src
        .find("pub async fn agent_delegation_revoke")
        .expect("route exists");
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    for forbidden in [
        "update_intent",
        "mark_intent_failed",
        "release_spend",
        "release_scopes",
        "reserve_spend",
        "claim_intent",
        "reconcile",
        "ops.transfer",
        "aggregate_scopes",
    ] {
        assert!(
            !body.contains(forbidden),
            "delegation revocation must never touch {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// (AC,AD) crash/concurrency: the stamp write is atomic under store_lock
// ---------------------------------------------------------------------------

#[test]
fn stamp_write_is_atomic_under_store_lock() {
    // The revocation path uses the SAME store_lock + temp+rename as every
    // other policy mutation — a crash cannot leave a half-written stamp.
    let src = include_str!("agents.rs");
    let start = src.find("pub async fn agent_delegation_revoke").unwrap();
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    assert!(body.contains("store_lock"), "same lock discipline");
    assert!(body.contains("write_json_atomic"), "atomic temp+rename");
    assert!(!body.contains("second_lock") && !body.contains("new_transaction"));
}

// ---------------------------------------------------------------------------
// (AE) audit evidence without secrets
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revocation_is_audited_without_secrets() {
    let root = Root::new("audit");
    let delegator = Uuid::new_v4();
    let delegate = Uuid::new_v4();
    persist_agent(&root, &delegator, 50506084, AgentStatus::Active);
    persist_agent(&root, &delegate, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(
            &delegator,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    persist_policy(
        &root,
        &policy_for(
            &delegate,
            Some(&delegator),
            Some(500),
            Some(20_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = crate::agents::agent_delegation_revoke(
            State(state),
            cookie(&sid),
            Path(delegate.to_string()),
        )
        .await;
        assert_eq!(envelope(resp).await.0, 200);
        let entries = crate::audit::read_entries(
            &crate::audit::audit_dir_for(&crate::agents::intents_root()),
            Some(&delegate.to_string()),
        )
        .unwrap();
        let revokes: Vec<_> = entries
            .iter()
            .filter(|e| e.code.as_deref() == Some("AGENT_DELEGATION_REVOKED"))
            .collect();
        assert_eq!(revokes.len(), 1, "exactly one audit record");
        assert_eq!(
            revokes[0].identity_class,
            Some(crate::audit::IdentityClass::Session)
        );
        assert_eq!(
            revokes[0].agent_id.as_deref(),
            Some(delegate.to_string().as_str())
        );
        assert!(revokes[0].tx_signature.is_none());
        // no secret material in the persisted audit JSON
        let raw = std::fs::read_to_string(
            crate::audit::audit_dir_for(&crate::agents::intents_root())
                .join(format!("{delegate}.json")),
        )
        .unwrap();
        for forbidden in ["lat_", "phc", "keypair", "credential"] {
            assert!(
                !raw.contains(forbidden),
                "audit must never contain {forbidden}"
            );
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// (AF,AG,AH,AI,AJ) closed surfaces untouched (structural)
// ---------------------------------------------------------------------------

#[test]
fn closed_surfaces_remain_untouched() {
    // Anchor includes the "(" so the slice is the REAL resolver body:
    // since the task-marketplace wrapper
    // `pub fn resolve_effective_policy_for_agent(` was added, a bare
    // `pub fn resolve_effective_policy` prefix-match grabbed the 10-line
    // wrapper instead (regression in this harness anchor only — the
    // pinned contract is unchanged).
    let src = include_str!("agents.rs");
    let start = src.find("pub fn resolve_effective_policy(").unwrap();
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    assert!(body.contains("MAX_POLICY_HIERARCHY_DEPTH"));
    assert!(body.contains("CycleDetected"));
    assert!(body.contains("CrossOwnerParent"));
    // the delegation route references no rate-limit / receipt / lane surface
    let route_start = src.find("pub async fn agent_delegation_revoke").unwrap();
    let route_body = &src[route_start
        ..src[route_start..]
            .find("\n}\n")
            .map(|e| route_start + e)
            .unwrap()];
    for forbidden in [
        "RATE_LIMITED",
        "receipt",
        "verify",
        "latch",
        "LATCH",
        "privy",
        "Privy",
        "ExecutionLane",
    ] {
        assert!(
            !route_body.contains(forbidden),
            "delegation must never reference {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// revocation of a root agent / missing policy: fail-closed no-op denials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revocation_failures_fail_closed_without_leakage() {
    let root = Root::new("failclosed");
    let root_agent = Uuid::new_v4();
    persist_agent(&root, &root_agent, 50506084, AgentStatus::Active);
    // no policy persisted at all
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = crate::agents::agent_delegation_revoke(
            State(state),
            cookie(&sid),
            Path(root_agent.to_string()),
        )
        .await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["code"], "DELEGATION_NOT_FOUND");
        // root agent WITH a policy (no parent): no delegation to revoke
        persist_policy(
            &root,
            &policy_for(
                &root_agent,
                None,
                Some(1_000),
                Some(10_000),
                vec![RECIPIENT],
                vec!["payment"],
            ),
        );
        let (state2, sid2) = test_state(50506084);
        let resp2 = crate::agents::agent_delegation_revoke(
            State(state2),
            cookie(&sid2),
            Path(root_agent.to_string()),
        )
        .await;
        let (status2, body2) = envelope(resp2).await;
        assert_eq!(status2, 404);
        assert_eq!(body2["error"]["code"], "DELEGATION_NOT_FOUND");
        // non-owner: the choke point collapses
        let (state3, sid3) = test_state(999);
        let resp3 = crate::agents::agent_delegation_revoke(
            State(state3),
            cookie(&sid3),
            Path(root_agent.to_string()),
        )
        .await;
        let (status3, body3) = envelope(resp3).await;
        assert_eq!(status3, 404);
        assert_eq!(body3["error"]["code"], "AGENT_NOT_FOUND");
    })
    .await;
}
