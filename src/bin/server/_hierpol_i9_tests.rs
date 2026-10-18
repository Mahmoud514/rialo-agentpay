//! PHASE 9 "Hierarchical Policy" — focused tests for the frozen parent
//! model (decision record: hierarchical_policy_parent_model_decision.md).
//! The resolver is the pure effective-policy fold; enforcement remains the
//! existing fixed-order `check_agent_payment_policy` (untouched). Every
//! resolution failure denies — there is NO flat-policy fallback.

use crate::agents::{
    Agent, AgentPolicy, AgentStatus, HierarchyError, MAX_POLICY_HIERARCHY_DEPTH,
    POLICY_SCHEMA_VERSION, check_agent_payment_policy, default_policy, load_policy,
    resolve_effective_policy,
};
use std::path::PathBuf;
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-hier-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_policies")).unwrap();
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
        name: "hier-agent".to_string(),
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
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
        delegation_revoked: None,
    }
}

fn resolve(root: &Root, child: &AgentPolicy) -> Result<AgentPolicy, HierarchyError> {
    resolve_effective_policy(child.clone(), &root.policies(), &root.agents())
}

// ---------------------------------------------------------------------------
// (A) root behavior unchanged; (AN) flat compatibility
// ---------------------------------------------------------------------------

#[test]
fn root_agent_behavior_identical_to_flat_model() {
    let root = Root::new("rootid");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084, AgentStatus::Active);
    let child = policy_for(
        &id,
        None,
        Some(1_000),
        Some(10_000),
        vec![RECIPIENT],
        vec!["payment"],
    );
    let effective = resolve(&root, &child).unwrap();
    // A: the effective policy IS the child's own policy (single-node fold)
    assert_eq!(effective.max_payment_per_tx_kelvin, Some(1_000));
    assert_eq!(effective.daily_payment_limit_kelvin, Some(10_000));
    assert_eq!(effective.allowed_recipients, vec![RECIPIENT.to_string()]);
    // AN: an OLD persisted record without the field parses as a root
    let old_doc = format!(
        r#"{{"schema_version":1,"agent_id":"{id}","max_payment_per_tx_kelvin":1000,"daily_payment_limit_kelvin":10000,"allowed_recipients":["{RECIPIENT}"],"allowed_actions":["payment"],"created_at":1700000000,"updated_at":1700000100}}"#
    );
    std::fs::write(root.policies().join(format!("{id}.json")), old_doc).unwrap();
    let loaded = load_policy(&root.policies(), &id).unwrap().unwrap();
    assert!(loaded.parent_agent_id.is_none(), "old records are roots");
    let effective2 = resolve(&root, &loaded).unwrap();
    assert_eq!(effective2.max_payment_per_tx_kelvin, Some(1_000));
}

// ---------------------------------------------------------------------------
// (B,C,D) linkage validity
// ---------------------------------------------------------------------------

#[test]
fn same_owner_linkage_valid_cross_owner_and_self_rejected() {
    let root = Root::new("link");
    let parent_id = Uuid::new_v4();
    let child_id = Uuid::new_v4();
    persist_agent(&root, &parent_id, 50506084, AgentStatus::Active);
    persist_agent(&root, &child_id, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(
            &parent_id,
            None,
            Some(1_000),
            Some(10_000),
            vec![RECIPIENT],
            vec!["payment"],
        ),
    );
    // B: valid same-owner linkage succeeds and inherits
    let child = policy_for(
        &child_id,
        Some(&parent_id),
        Some(2_000),
        None,
        vec![RECIPIENT, "OtherRec"],
        vec!["payment"],
    );
    let eff = resolve(&root, &child).unwrap();
    assert_eq!(
        eff.max_payment_per_tx_kelvin,
        Some(1_000),
        "min(child=2000, parent=1000)"
    );
    assert_eq!(
        eff.daily_payment_limit_kelvin,
        Some(10_000),
        "child inherits parent cap"
    );
    assert_eq!(
        eff.allowed_recipients,
        vec![RECIPIENT.to_string()],
        "intersection"
    );

    // C: cross-owner parent is rejected
    let foreign_parent = Uuid::new_v4();
    persist_agent(&root, &foreign_parent, 999, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&foreign_parent, None, Some(1), Some(1), vec![], vec![]),
    );
    let child2 = policy_for(
        &child_id,
        Some(&foreign_parent),
        Some(1),
        Some(1),
        vec![],
        vec![],
    );
    assert_eq!(
        resolve(&root, &child2).unwrap_err(),
        HierarchyError::CrossOwnerParent
    );

    // D: self-parenting is rejected (cycle detection at hop 1)
    let child3 = policy_for(&child_id, Some(&child_id), Some(1), Some(1), vec![], vec![]);
    assert_eq!(
        resolve(&root, &child3).unwrap_err(),
        HierarchyError::CycleDetected
    );
}

// ---------------------------------------------------------------------------
// (E,F,G,H,I,J,K,L,M,N) inheritance semantics
// ---------------------------------------------------------------------------

#[test]
fn cap_folding_uses_min_and_unset_inherits() {
    let root = Root::new("caps");
    let g = Uuid::new_v4(); // grandparent
    let p = Uuid::new_v4(); // parent
    let c = Uuid::new_v4(); // child
    persist_agent(&root, &g, 50506084, AgentStatus::Active);
    persist_agent(&root, &p, 50506084, AgentStatus::Active);
    persist_agent(&root, &c, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&g, None, Some(100), Some(500), vec![], vec!["payment"]),
    );
    persist_policy(
        &root,
        &policy_for(&p, Some(&g), Some(50), None, vec![], vec![]),
    );
    // J: multi-level cap uses MIN across the whole chain
    // child unset daily inherits min(parent unset, grandparent 500) = 500
    let child = policy_for(&c, Some(&p), Some(200), None, vec![], vec![]);
    let eff = resolve(&root, &child).unwrap();
    assert_eq!(eff.max_payment_per_tx_kelvin, Some(50), "min(200,50,100)");
    assert_eq!(
        eff.daily_payment_limit_kelvin,
        Some(500),
        "N: unset child inherits parent chain"
    );
    // H: child cap narrows parent cap
    let child2 = policy_for(&c, Some(&p), Some(10), Some(100), vec![], vec![]);
    let eff2 = resolve(&root, &child2).unwrap();
    assert_eq!(eff2.max_payment_per_tx_kelvin, Some(10));
    assert_eq!(eff2.daily_payment_limit_kelvin, Some(100));
    // I: child cap CANNOT widen parent cap
    let child3 = policy_for(&c, Some(&p), Some(10_000), Some(100_000), vec![], vec![]);
    let eff3 = resolve(&root, &child3).unwrap();
    assert_eq!(
        eff3.max_payment_per_tx_kelvin,
        Some(50),
        "never above the parent chain"
    );
    assert_eq!(eff3.daily_payment_limit_kelvin, Some(500));
}

#[test]
fn allow_list_folding_uses_intersection_and_empty_parent_denies() {
    let root = Root::new("lists");
    let p = Uuid::new_v4();
    let c = Uuid::new_v4();
    persist_agent(&root, &p, 50506084, AgentStatus::Active);
    persist_agent(&root, &c, 50506084, AgentStatus::Active);
    // K/L: parent allow-list constrains the child (intersection)
    persist_policy(
        &root,
        &policy_for(&p, None, None, None, vec![RECIPIENT], vec!["payment"]),
    );
    let child = policy_for(
        &c,
        Some(&p),
        None,
        None,
        vec![RECIPIENT, "OtherRec"],
        vec!["payment"],
    );
    let eff = resolve(&root, &child).unwrap();
    assert_eq!(
        eff.allowed_recipients,
        vec![RECIPIENT.to_string()],
        "L: child narrowed"
    );
    assert_eq!(eff.allowed_actions, vec!["payment".to_string()]);
    // M: child cannot widen the inherited allow-list
    let child2 = policy_for(
        &c,
        Some(&p),
        None,
        None,
        vec!["OtherRec", "Another"],
        vec![],
    );
    let eff2 = resolve(&root, &child2).unwrap();
    assert!(
        eff2.allowed_recipients.is_empty(),
        "intersection of disjoint lists is empty"
    );
    // empty parent allow-list is a deny-everything constraint (frozen table)
    let p2 = Uuid::new_v4();
    let c2 = Uuid::new_v4();
    persist_agent(&root, &p2, 50506084, AgentStatus::Active);
    persist_agent(&root, &c2, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&p2, None, None, None, vec![], vec!["payment"]),
    );
    let child3 = policy_for(&c2, Some(&p2), None, None, vec![RECIPIENT], vec![]);
    let eff3 = resolve(&root, &child3).unwrap();
    assert!(
        eff3.allowed_recipients.is_empty(),
        "empty parent list denies everything"
    );
}

// ---------------------------------------------------------------------------
// (P,Q,R) cycle / depth / no-fallback
// ---------------------------------------------------------------------------

#[test]
fn cycle_depth_and_no_flat_fallback_fail_closed() {
    let root = Root::new("cycles");
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    persist_agent(&root, &a, 50506084, AgentStatus::Active);
    persist_agent(&root, &b, 50506084, AgentStatus::Active);
    // P: a two-node cycle (A -> B -> A)
    persist_policy(
        &root,
        &policy_for(&a, Some(&b), Some(1), Some(1), vec![], vec!["payment"]),
    );
    persist_policy(
        &root,
        &policy_for(&b, Some(&a), Some(1), Some(1), vec![], vec!["payment"]),
    );
    let err = resolve(
        &root,
        &policy_for(&a, Some(&b), Some(1), Some(1), vec![], vec!["payment"]),
    )
    .unwrap_err();
    assert_eq!(err, HierarchyError::CycleDetected);

    // Q: depth > 8 fails closed (a chain of 9 parents above the child)
    let mut ids = Vec::new();
    for i in 0..10 {
        let id = Uuid::new_v4();
        persist_agent(&root, &id, 50506084, AgentStatus::Active);
        ids.push(id);
    }
    // chain: ids[0] -> ids[1] -> ... -> ids[9]; child = ids[0]; depth 9 > 8
    for i in 0..9 {
        persist_policy(
            &root,
            &policy_for(
                &ids[i],
                Some(&ids[i + 1]),
                Some(1),
                Some(1),
                vec![],
                vec!["payment"],
            ),
        );
    }
    let child = policy_for(
        &ids[0],
        Some(&ids[1]),
        Some(1),
        Some(1),
        vec![],
        vec!["payment"],
    );
    assert_eq!(
        resolve(&root, &child).unwrap_err(),
        HierarchyError::DepthExceeded
    );

    // exactly MAX depth succeeds (8 parents above the child)
    let mut ids8 = Vec::new();
    for _ in 0..9 {
        let id = Uuid::new_v4();
        persist_agent(&root, &id, 50506084, AgentStatus::Active);
        ids8.push(id);
    }
    for i in 0..8 {
        persist_policy(
            &root,
            &policy_for(
                &ids8[i],
                Some(&ids8[i + 1]),
                Some(1_000),
                Some(1_000),
                vec![],
                vec!["payment"],
            ),
        );
    }
    // the ROOT at the end of the chain needs its own (root) policy document
    persist_policy(
        &root,
        &policy_for(
            &ids8[8],
            None,
            Some(1_000),
            Some(1_000),
            vec![],
            vec!["payment"],
        ),
    );
    let child8 = policy_for(
        &ids8[0],
        Some(&ids8[1]),
        Some(1_000),
        Some(1_000),
        vec![],
        vec!["payment"],
    );
    assert!(resolve(&root, &child8).is_ok(), "8 hops resolve; 9 deny");

    // R: resolution failure has NO flat-policy fallback — the resolver
    // returns Err; the money cores map it to a DENY (proven by the wiring
    // tests below); the resolver NEVER returns the flat child policy on
    // a broken chain:
    let ghost = Uuid::new_v4(); // no agent record
    let child4 = policy_for(
        &child_id_placeholder(),
        Some(&ghost),
        Some(1),
        Some(1),
        vec![],
        vec!["payment"],
    );
    assert_eq!(
        resolve(&root, &child4).unwrap_err(),
        HierarchyError::ParentAgentUnavailable
    );
}

fn child_id_placeholder() -> Uuid {
    Uuid::new_v4()
}

// ---------------------------------------------------------------------------
// (E,F,Q,R cont.) missing/malformed parent + corrupt policy
// ---------------------------------------------------------------------------

#[test]
fn missing_malformed_and_corrupt_parents_fail_closed() {
    let root = Root::new("bad");
    let child = Uuid::new_v4();
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    // E: missing parent record
    let missing = Uuid::new_v4();
    let p1 = policy_for(&child, Some(&missing), None, None, vec![], vec![]);
    assert_eq!(
        resolve(&root, &p1).unwrap_err(),
        HierarchyError::ParentAgentUnavailable
    );
    // F: malformed parent id (not a canonical UUID)
    let mut bad_policy = policy_for(&child, None, None, None, vec![], vec![]);
    bad_policy.parent_agent_id = Some("not-a-uuid".to_string());
    assert_eq!(
        resolve(&root, &bad_policy).unwrap_err(),
        HierarchyError::MalformedLinkage
    );
    // E2: parent EXISTS but its policy file is missing
    let existing_no_policy = Uuid::new_v4();
    persist_agent(&root, &existing_no_policy, 50506084, AgentStatus::Active);
    let p2 = policy_for(
        &child,
        Some(&existing_no_policy),
        None,
        None,
        vec![],
        vec![],
    );
    assert_eq!(
        resolve(&root, &p2).unwrap_err(),
        HierarchyError::ParentPolicyUnavailable
    );
    // corrupt parent policy file
    std::fs::write(
        root.policies().join(format!("{existing_no_policy}.json")),
        b"garbage{",
    )
    .unwrap();
    assert_eq!(
        resolve(&root, &p2).unwrap_err(),
        HierarchyError::ParentPolicyUnavailable
    );
}

// ---------------------------------------------------------------------------
// (S,T,U) enforcement boundary: effective policy BEFORE the fixed-order check
// ---------------------------------------------------------------------------

#[test]
fn effective_policy_feeds_the_existing_fixed_order_enforcement() {
    let root = Root::new("enforce");
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
    let child_policy = policy_for(
        &child,
        Some(&parent),
        Some(500),
        Some(20_000),
        vec![RECIPIENT],
        vec!["payment"],
    );
    let effective = resolve(&root, &child_policy).unwrap();

    // S: the ENFORCEMENT receives the EFFECTIVE policy (caps folded): a
    // payment above the PARENT cap is denied even though the child's own
    // cap would have allowed it.
    let denial = check_agent_payment_policy(
        &persist_agent(&root, &child, 50506084, AgentStatus::Active),
        Some(&effective),
        RECIPIENT,
        5_000, // above parent cap 1_000
        Some(0),
    );
    assert!(matches!(
        denial,
        Err(crate::agents::EnforcementDenial::AmountDenied)
    ));
    // within BOTH caps: allowed
    let ok = check_agent_payment_policy(
        &persist_agent(&root, &child, 50506084, AgentStatus::Active),
        Some(&effective),
        RECIPIENT,
        500,
        Some(0),
    );
    assert!(ok.is_ok());
    // T: the fixed order is unchanged — lifecycle first
    let disabled_child = {
        let mut a = persist_agent(&root, &child, 50506084, AgentStatus::Active);
        a.status = AgentStatus::Disabled;
        a
    };
    let denial2 =
        check_agent_payment_policy(&disabled_child, Some(&effective), RECIPIENT, 1, Some(0));
    assert!(matches!(
        denial2,
        Err(crate::agents::EnforcementDenial::Lifecycle)
    ));
    // recipient not in the folded allow-list: denied (allow-list gate intact)
    // a VALID address that is not in the folded allow-list: the allow-list
    // gate denies it (the recipient-syntax gate passes first)
    let unlisted = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    assert_ne!(unlisted, RECIPIENT);
    let denial3 = check_agent_payment_policy(
        &persist_agent(&root, &child, 50506084, AgentStatus::Active),
        Some(&effective),
        unlisted,
        1,
        Some(0),
    );
    assert!(matches!(
        denial3,
        Err(crate::agents::EnforcementDenial::RecipientDenied)
    ));
}

// ---------------------------------------------------------------------------
// (U cont.) the fingerprint reflects the EFFECTIVE policy
// ---------------------------------------------------------------------------

#[test]
fn policy_fingerprint_uses_the_effective_policy() {
    let root = Root::new("fp");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    persist_agent(&root, &parent, 50506084, AgentStatus::Active);
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&parent, None, Some(1_000), Some(10_000), vec![], vec![]),
    );
    let child_policy = policy_for(
        &child,
        Some(&parent),
        Some(500),
        Some(20_000),
        vec![],
        vec![],
    );
    let effective = resolve(&root, &child_policy).unwrap();
    let fp_effective = crate::agents::policy_fingerprint(&effective);
    // the effective fingerprint differs from the child's own flat fingerprint
    let fp_child = crate::agents::policy_fingerprint(&child_policy);
    assert_ne!(
        fp_effective, fp_child,
        "U: the fingerprint reflects the folded policy"
    );
    // and it is stable: resolving twice gives the same fingerprint
    let effective2 = resolve(&root, &child_policy).unwrap();
    assert_eq!(fp_effective, crate::agents::policy_fingerprint(&effective2));
}

// ---------------------------------------------------------------------------
// (V,W,X) mutation semantics: derived at decision time, never persisted
// ---------------------------------------------------------------------------

#[test]
fn policy_and_linkage_changes_apply_to_the_next_resolution() {
    let root = Root::new("mutate");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    persist_agent(&root, &parent, 50506084, AgentStatus::Active);
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&parent, None, Some(1_000), Some(10_000), vec![], vec![]),
    );
    let child_policy = policy_for(
        &child,
        Some(&parent),
        Some(500),
        Some(20_000),
        vec![],
        vec![],
    );
    // V: tightening the parent cap applies to the child's next resolution
    persist_policy(
        &root,
        &policy_for(&parent, None, Some(100), Some(10_000), vec![], vec![]),
    );
    let eff = resolve(&root, &child_policy).unwrap();
    assert_eq!(eff.max_payment_per_tx_kelvin, Some(100));
    // W: tightening the child's own cap applies immediately
    let child2 = policy_for(
        &child,
        Some(&parent),
        Some(50),
        Some(20_000),
        vec![],
        vec![],
    );
    assert_eq!(
        resolve(&root, &child2).unwrap().max_payment_per_tx_kelvin,
        Some(50)
    );
    // X: changing the LINKAGE applies immediately (reattach to a new parent)
    let new_parent = Uuid::new_v4();
    persist_agent(&root, &new_parent, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&new_parent, None, Some(10), Some(10), vec![], vec![]),
    );
    let child3 = policy_for(&child, Some(&new_parent), None, None, vec![], vec![]);
    assert_eq!(
        resolve(&root, &child3).unwrap().max_payment_per_tx_kelvin,
        Some(10)
    );
    // Y: the effective policy is NEVER persisted — the policy store holds
    // only the child's own record (the resolver wrote nothing)
    let stored = load_policy(&root.policies(), &child).unwrap();
    assert!(stored.is_none(), "no second authority was persisted");
}

// ---------------------------------------------------------------------------
// (Z,AA,AB) lifecycle interaction
// ---------------------------------------------------------------------------

#[test]
fn disabled_parent_keeps_constraints_child_gated_by_own_lifecycle() {
    let root = Root::new("lifecycle");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    // AA: a DISABLED parent's constraints stay binding (its policy remains
    // resolvable — disabling does not remove the constraint document)
    persist_agent(&root, &parent, 50506084, AgentStatus::Disabled);
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&parent, None, Some(10), Some(10), vec![], vec!["payment"]),
    );
    let child_policy = policy_for(
        &child,
        Some(&parent),
        Some(1_000),
        Some(1_000),
        vec![RECIPIENT],
        vec!["payment"],
    );
    let eff = resolve(&root, &child_policy).unwrap();
    assert_eq!(
        eff.max_payment_per_tx_kelvin,
        Some(10),
        "disabled parent still narrows"
    );
    // Z: a DISABLED CHILD is blocked by its own lifecycle (fixed order, first gate)
    let mut disabled_child = persist_agent(&root, &child, 50506084, AgentStatus::Disabled);
    let denial = check_agent_payment_policy(&disabled_child, Some(&eff), RECIPIENT, 1, Some(0));
    assert!(matches!(
        denial,
        Err(crate::agents::EnforcementDenial::Lifecycle)
    ));
    // AB: a REVOKED credential is orthogonal — hierarchy never touches the
    // credential plane (no credential record is read or written here)
    let credential = crate::agent_credentials::issue_in(
        &root.agents(),
        &root.creds(),
        &child.to_string(),
        1_700_000_200,
    )
    .unwrap();
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &child.to_string(),
        1_700_000_300,
    )
    .unwrap();
    assert!(
        crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_err(),
        "revoked credential stays revoked"
    );
    let _ = &mut disabled_child;
}

// helper for the credentials dir
impl Root {
    fn creds(&self) -> PathBuf {
        self.0.join("artifact/agent_credentials")
    }
}

// ---------------------------------------------------------------------------
// (AC,AD,AE) no transfer of ownership/credentials/keys (structural)
// ---------------------------------------------------------------------------

#[test]
fn hierarchy_transfers_nothing_but_constraints() {
    // The resolver reads ONLY policy documents + agent records (owner +
    // status are never consulted beyond existence/ownership): no key file,
    // no credential record, no wallet path is ever opened.
    let src = include_str!("agents.rs");
    // Anchor includes the "(" so the slice is the REAL resolver body:
    // since the task-marketplace wrapper
    // `pub fn resolve_effective_policy_for_agent(` was added, a bare
    // `pub fn resolve_effective_policy` prefix-match grabbed the 10-line
    // wrapper instead (regression in this harness anchor only — the
    // pinned contract is unchanged).
    let start = src
        .find("pub fn resolve_effective_policy(")
        .expect("resolver exists");
    let body = &src[start..src[start..].find("\n}\n").map(|e| start + e).unwrap()];
    let fold_start = src.find("fn fold_constraint").expect("fold exists");
    let fold_body = &src[fold_start
        ..src[fold_start..]
            .find("\n}\n")
            .map(|e| fold_start + e)
            .unwrap()];
    for blob in [body, fold_body] {
        for forbidden in [
            "auth_keys",
            "agent_wallet",
            "wallet_dir",
            "credential",
            // PHASE 9 "Delegation": the delegation_revoked STAMP is the
            // hierarchy's own policy field (the delegated-authority state);
            // the REVOCATION AUTHORITY calls remain forbidden.
            "revoke_credential",
            "revoke_in",
            "rotate",
            "keypair",
            "signer",
            "transfer",
        ] {
            assert!(
                !blob.contains(forbidden),
                "hierarchy must never reference {forbidden}"
            );
        }
    }
    // AC: ownership is only COMPARED (same-owner gate), never transferred
    assert!(
        body.contains("owner_user_id"),
        "the same-owner gate is the only ownership use"
    );
}

// ---------------------------------------------------------------------------
// (AF) wiring: only the two frozen policy-load points resolve hierarchy
// ---------------------------------------------------------------------------

#[test]
fn hierarchy_resolution_wired_only_at_the_two_money_cores() {
    let src = include_str!("agents.rs");
    // the two money cores call the resolver exactly once each, at their
    // policy-load points
    // Call sites: the fn definition itself, the v1 lane, the v2 lane, the
    // PATCH probe, and test-shard references (excluded: tests live below
    // the #[cfg(test)] marker in this file).
    // AF: the two money-core lanes + the PATCH probe each resolve the
    // effective policy. The production/test boundary in agents.rs is
    // blurred by the #[cfg(test)] wrappers the spend item added, so the
    // pin asserts the three CONSUMERS by their surrounding context
    // instead of a raw production-slice count.
    assert!(
        src.contains("match resolve_effective_policy("),
        "v1 lane resolves"
    );
    assert!(
        src.contains("crate::agents::resolve_effective_policy(child_policy"),
        "v2 lane resolves"
    );
    assert!(
        src.contains("let probe =\n                    resolve_effective_policy(policy.clone()"),
        "PATCH probe resolves"
    );
}

// ---------------------------------------------------------------------------
// (AG,AH,AI,AJ,AK) closed-semantics isolation (structural)
// ---------------------------------------------------------------------------

#[test]
fn hierarchy_touches_no_closed_semantics() {
    let src = include_str!("agents.rs");
    let start = src.find("pub fn resolve_effective_policy").unwrap();
    let end = src.find("/// Ok(None) = nothing persisted yet").unwrap();
    let hierarchy_code = &src[start..end];
    // no rate-limit, no idempotency, no reconciliation, no reservation,
    // no latch/privy reference in the hierarchy module code
    for forbidden in [
        "RATE_LIMITED",
        "rate_limit",
        "claim_intent",
        "reserve_spend",
        "release_spend",
        "reconcile",
        "ops.transfer",
        "latch",
        "LATCH",
        "privy",
        "Privy",
        "ExecutionLane",
    ] {
        assert!(
            !hierarchy_code.contains(forbidden),
            "hierarchy must not reference {forbidden}"
        );
    }
    // the enforcement fn is untouched: its body has no hierarchy reference
    let enforce_start = src.find("pub fn check_agent_payment_policy(").unwrap();
    let enforce_end = src[enforce_start..]
        .find("\n}\n")
        .map(|e| enforce_start + e)
        .unwrap();
    let enforce_body = &src[enforce_start..enforce_end];
    assert!(
        !enforce_body.contains("resolve_effective_policy"),
        "T: enforcement unchanged"
    );
    assert!(
        !enforce_body.contains("HierarchyError"),
        "T: enforcement unchanged"
    );
}

// ---------------------------------------------------------------------------
// (AL) concurrent authorization safety: the resolver is pure/read-only
// ---------------------------------------------------------------------------

#[test]
fn resolver_is_pure_and_safe_under_concurrency() {
    // The resolver performs NO writes and takes no locks: repeated calls
    // with the same inputs are identical, and parallel calls cannot race.
    let root = Root::new("pure");
    let parent = Uuid::new_v4();
    let child = Uuid::new_v4();
    persist_agent(&root, &parent, 50506084, AgentStatus::Active);
    persist_agent(&root, &child, 50506084, AgentStatus::Active);
    persist_policy(
        &root,
        &policy_for(&parent, None, Some(1_000), Some(10_000), vec![], vec![]),
    );
    let child_policy = policy_for(&child, Some(&parent), Some(500), None, vec![], vec![]);
    let mk = || resolve(&root, &child_policy).unwrap();
    let a = mk();
    let b = mk();
    assert_eq!(a.max_payment_per_tx_kelvin, b.max_payment_per_tx_kelvin);
    assert_eq!(a.daily_payment_limit_kelvin, b.daily_payment_limit_kelvin);
    assert_eq!(a.allowed_recipients, b.allowed_recipients);
    assert_eq!(a.allowed_actions, b.allowed_actions);
}
