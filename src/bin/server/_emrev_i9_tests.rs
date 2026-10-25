//! PHASE 9 "Emergency kill/revoke controls" (D-REV(a), app-side) — focused
//! tests for the owner-scoped credential revocation route and its
//! semantics. The credential library is the enforcement (frozen); these
//! tests pin the WIRING (owner authorization boundary, immediacy,
//! idempotency, audit evidence, no-secret discipline) and the payment-state
//! non-interaction (Pending stays Pending, Unknown stays Unknown, no
//! history rewrite).

use crate::agents::{agent_credential_revoke, agent_payment};
use crate::audit::{AuditCategory, AuditOutcome, IdentityClass, read_entries};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use std::path::PathBuf;
use uuid::Uuid;

const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";

// ---------------------------------------------------------------------------
// fixture: real agent record + real credential record in one temp root
// (the production wrappers are CWD-relative, so handler tests chdir)
// ---------------------------------------------------------------------------

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-emrev-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
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
    fn creds(&self) -> PathBuf {
        self.0.join("artifact/agent_credentials")
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn persist_agent(root: &Root, id: &Uuid, owner: u64) -> crate::agents::Agent {
    let agent = crate::agents::Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: owner,
        name: "emrev-agent".to_string(),
        status: crate::agents::AgentStatus::Active,
        wallet_address: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
        auth_public_key: None,
    };
    let path = root.agents().join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&agent).unwrap()).unwrap();
    agent
}

fn issue(root: &Root, id: &Uuid) -> String {
    crate::agent_credentials::issue_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_200,
    )
    .unwrap()
}

fn authenticate(
    root: &Root,
    credential: &str,
) -> Result<Uuid, crate::agent_credentials::CredentialError> {
    crate::agent_credentials::authenticate_in(&root.creds(), credential)
}

fn write_intent(root: &Root, id: &Uuid, key: &str, state: &str) {
    let doc = format!(
        r#"{{"schema_version":2,"intent_id":"{key}-iid","agent_id":"{id}","principal_kind":"agent","recipient":"{RECIPIENT}","amount_kelvin":1000000,"idempotency_key":"{key}","request_fingerprint":"fp-{key}","authz":{{"policy_fingerprint":"pfp","authorized_at":1700000000}},"exec_state":"{state}","tx_signature":null,"failure":null,"response":null,"signer":null,"reconciliation":null,"created_at":1700000000,"updated_at":1700000100}}"#
    );
    let dir = root
        .path()
        .join("artifact/agent_payment_intents")
        .join(id.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{}.json", hexkey(key))), doc).unwrap();
}

fn hexkey(key: &str) -> String {
    key.bytes().map(|b| format!("{b:02x}")).collect()
}

fn read_intent(root: &Root, id: &Uuid, key: &str) -> String {
    std::fs::read_to_string(
        root.path()
            .join("artifact/agent_payment_intents")
            .join(id.to_string())
            .join(format!("{}.json", hexkey(key))),
    )
    .unwrap()
}

async fn with_cwd<R: std::future::Future>(root: &Root, f: R) -> R::Output {
    // Share the ESTABLISHED process-wide CWD lock (the same one the stats
    // shards use) so chdir windows never overlap across shards — the
    // documented parallel-flake class otherwise.
    let _guard = crate::stats::tests24::tests24::CWD_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let original = std::env::current_dir().unwrap_or(std::env::temp_dir());
    std::env::set_current_dir(&root.path()).unwrap();
    let result = f.await;
    let _ = std::env::set_current_dir(&original);
    result
}

// ---------------------------------------------------------------------------
// (A-D) library semantics: revoke, immediacy, idempotency
// ---------------------------------------------------------------------------

#[test]
fn owner_can_revoke_and_credential_dies_immediately() {
    let root = Root::new("revoke");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    assert!(
        authenticate(&root, &credential).is_ok(),
        "pre-revoke auth works"
    );

    // revoke via the SAME library the route calls
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();

    // IMMEDIATE: the old credential can NEVER authenticate again
    assert!(
        authenticate(&root, &credential).is_err(),
        "revoked credential must fail"
    );
    // and it stays dead
    assert!(authenticate(&root, &credential).is_err());
}

#[test]
fn repeated_revoke_is_idempotent_record_preserved() {
    let root = Root::new("idem");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();
    // repeated revoke: idempotent success, record preserved (never deleted)
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();
    let raw = std::fs::read_to_string(root.creds().join(format!("{id}.json"))).unwrap();
    assert!(
        raw.contains("revoked_at"),
        "record preserved with revoked_at"
    );
    assert!(
        raw.contains("phc"),
        "record retained (PHC hash still present, never deleted)"
    );
    assert!(authenticate(&root, &credential).is_err());
}

#[test]
fn revoked_credential_cannot_rotate() {
    let root = Root::new("rotate");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let _credential = issue(&root, &id);
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();
    // rotation is closed for revoked records (library semantics)
    assert!(
        crate::agent_credentials::rotate_in(
            &root.agents(),
            &root.creds(),
            &id.to_string(),
            1_700_000_400
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// (E,F,G) handler-level: owner route, audit, no-secret discipline
// ---------------------------------------------------------------------------

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
            cli: PathBuf::from("/nonexistent/emrev-test-cli"),
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
            login: format!("emrev-owner-{owner}"),
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

#[tokio::test]
async fn owner_revoke_route_succeeds_and_audits_without_secrets() {
    let root = Root::new("route");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = agent_credential_revoke(State(state), cookie(&sid), Path(id.to_string())).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 200);
        assert_eq!(body["success"], true);
        assert_eq!(body["credential_revoked"], true);
        assert_eq!(body["agent_id"], id.to_string().as_str());
        // NO credential material in the response
        let raw = serde_json::to_string(&body).unwrap();
        assert!(
            !raw.contains(&credential),
            "response must never echo the credential"
        );
        assert!(!raw.contains("phc"), "no PHC material in response");

        // the revoked credential is DEAD immediately
        assert!(authenticate(&root, &credential).is_err());

        // AUDIT: one observational record, session identity plane, the
        // stable code, correlated to the agent — no secret anywhere
        let entries = read_entries(
            &crate::audit::audit_dir_for(&crate::agents::intents_root()),
            Some(&id.to_string()),
        )
        .unwrap();
        let revoke_records: Vec<_> = entries
            .iter()
            .filter(|e| e.code.as_deref() == Some("AGENT_CREDENTIAL_REVOKED"))
            .collect();
        assert_eq!(
            revoke_records.len(),
            1,
            "exactly one audit record for the revoke"
        );
        let r = revoke_records[0];
        assert_eq!(r.category, AuditCategory::Authorization);
        assert_eq!(r.outcome, AuditOutcome::Deny);
        assert_eq!(r.identity_class, Some(IdentityClass::Session));
        assert_eq!(r.agent_id.as_deref(), Some(id.to_string().as_str()));
        assert!(
            r.idempotency_key.is_none(),
            "no key correlation for a credential action"
        );
        assert!(r.tx_signature.is_none());
        assert!(r.policy_fingerprint.is_none());
        // no secret can exist in the audit record: the record type has no
        // field for it; verify the persisted JSON too
        let audit_raw = std::fs::read_to_string(
            crate::audit::audit_dir_for(&crate::agents::intents_root()).join(format!("{id}.json")),
        )
        .unwrap();
        assert!(!audit_raw.contains(&credential));
        assert!(!audit_raw.contains("phc"));
        assert!(!audit_raw.contains("lat_"));
    })
    .await;
}

// ---------------------------------------------------------------------------
// (B,O,P,Q) authorization boundary: non-owner, unauthenticated, malformed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_owner_and_unauthenticated_are_denied_identically() {
    let root = Root::new("boundary");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    with_cwd(&root, async {
        // non-owner session: the ownership choke point collapses to the
        // SAME AGENT_NOT_FOUND (never 403 — anti-enumeration)
        let (state, sid) = test_state(999);
        let resp = agent_credential_revoke(State(state), cookie(&sid), Path(id.to_string())).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["code"], "AGENT_NOT_FOUND");
        // the credential is UNTOUCHED (non-owner cannot revoke)
        assert!(authenticate(&root, &credential).is_ok());

        // unauthenticated: NOT_AUTHENTICATED
        let (state2, _sid) = test_state(50506084);
        let resp =
            agent_credential_revoke(State(state2), HeaderMap::new(), Path(id.to_string())).await;
        let (status2, body2) = envelope(resp).await;
        assert_eq!(status2, 401);
        assert_eq!(body2["error"]["code"], "NOT_AUTHENTICATED");
        assert!(authenticate(&root, &credential).is_ok());
    })
    .await;
}

#[tokio::test]
async fn malformed_and_missing_targets_fail_safe_without_leakage() {
    let root = Root::new("malformed");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        // malformed / traversal ids collapse to the same AGENT_NOT_FOUND
        for bad in ["../etc/passwd", "not-a-uuid", ""] {
            let resp =
                agent_credential_revoke(State(state.clone()), cookie(&sid), Path(bad.to_string()))
                    .await;
            let (status, body) = envelope(resp).await;
            assert_eq!(status, 404, "id: {bad:?}");
            assert_eq!(body["error"]["code"], "AGENT_NOT_FOUND");
        }
        // nonexistent (but well-formed) agent owned by someone else: same
        // indistinguishable collapse
        let ghost = Uuid::new_v4().to_string();
        let resp = agent_credential_revoke(State(state), cookie(&sid), Path(ghost)).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["code"], "AGENT_NOT_FOUND");
        // the real credential is untouched
        assert!(authenticate(&root, &credential).is_ok());
    })
    .await;
}

// ---------------------------------------------------------------------------
// (H) lifecycle kill: disabled stays terminally blocked (shipped semantics)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disabled_agent_stays_blocked_for_payments() {
    let root = Root::new("lifecycle");
    let id = Uuid::new_v4();
    let mut agent = persist_agent(&root, &id, 50506084);
    agent.status = crate::agents::AgentStatus::Disabled;
    // rewrite the record as disabled
    let path = root.agents().join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&agent).unwrap()).unwrap();

    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        // a payment attempt on a disabled agent answers AGENT_LIFECYCLE_BLOCKED
        let resp = agent_payment(
            State(state),
            cookie(&sid),
            Path(id.to_string()),
            format!(r#"{{"to":"{RECIPIENT}","amount":0.001}}"#),
        )
        .await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 403);
        assert_eq!(body["error"]["code"], "AGENT_LIFECYCLE_BLOCKED");
    })
    .await;
}

// ---------------------------------------------------------------------------
// (I-N) payment-state non-interaction: revoke NEVER rewrites payment truth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_does_not_rewrite_pending_unknown_or_history() {
    let root = Root::new("states");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    write_intent(&root, &id, "kpend", "pending");
    write_intent(&root, &id, "kunk", "unknown");
    write_intent(&root, &id, "kconf", "confirmed");

    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = agent_credential_revoke(State(state), cookie(&sid), Path(id.to_string())).await;
        assert_eq!(envelope(resp).await.0, 200);

        // Pending stays Pending (the existing semantics: only the ENGINE's
        // stale normalization or reconciliation can move it — never a
        // credential action)
        let stored_pend = read_intent(&root, &id, "kpend");
        assert!(stored_pend.contains("\"pending\""), "{stored_pend}");
        // Unknown stays Unknown (never Failed, never Paid — the reservation
        // hold + reconciliation authority are untouched)
        let stored_unk = read_intent(&root, &id, "kunk");
        assert!(stored_unk.contains("\"unknown\""), "{stored_unk}");
        assert!(!stored_unk.contains("reconciled"));
        // Confirmed history is NOT rewritten
        let stored_conf = read_intent(&root, &id, "kconf");
        assert!(stored_conf.contains("\"confirmed\""), "{stored_conf}");
        // the credential is dead for the agent lane
        assert!(authenticate(&root, &credential).is_err());
        // and NO execution evidence was fabricated by the revoke: the audit
        // store holds exactly ONE record (the revoke), nothing else
        let entries = read_entries(
            &crate::audit::audit_dir_for(&crate::agents::intents_root()),
            Some(&id.to_string()),
        )
        .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the revoke writes exactly one audit record"
        );
        assert_eq!(entries[0].code.as_deref(), Some("AGENT_CREDENTIAL_REVOKED"));
    })
    .await;
}

#[tokio::test]
async fn revoked_credential_lane_denies_new_payments() {
    let root = Root::new("lane");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = issue(&root, &id);
    with_cwd(&root, async {
        // BEFORE revoke: the credential lane authenticates (verified by the
        // library-level tests); here we prove the revoke blocks the lane's
        // ENTRY: a new payment attempt with a revoked credential cannot
        // authenticate.
        crate::agent_credentials::revoke_in(
            &root.agents(),
            &root.creds(),
            &id.to_string(),
            1_700_000_300,
        )
        .unwrap();
        // authentication now fails (the trigger lane's first gate)
        assert!(crate::agent_credentials::authenticate_agent_credential(&credential).is_err());
        // the credential header shape is still valid, but the store denies:
        // AGENT_CREDENTIAL_INVALID (the frozen, information-free denial)
        assert!(matches!(
            crate::agent_credentials::authenticate_in(&root.creds(), &credential),
            Err(crate::agent_credentials::CredentialError::AuthenticationFailed)
        ));
    })
    .await;
}

// ---------------------------------------------------------------------------
// (R structural) no new authority: the route is a thin wire over the library
// ---------------------------------------------------------------------------

#[test]
fn revoke_route_is_a_thin_wire_no_new_authority() {
    let src = include_str!("agents.rs");
    let start = src
        .find("pub async fn agent_credential_revoke")
        .expect("route exists");
    let end = src[start..].find("\n}\n").map(|e| start + e).unwrap();
    let body = &src[start..end];
    // the route calls the EXISTING library (the only credential authority)
    assert!(body.contains("revoke_credential"));
    // it does NOT implement its own credential logic, store, or auth path
    for forbidden in [
        "argon2",
        "write_record",
        "load_record",
        "verify_against_phc",
        "fs::write",
        "OpenOptions",
    ] {
        assert!(
            !body.contains(forbidden),
            "route must not reimplement {forbidden}"
        );
    }
    // the ownership choke point is present
    assert!(body.contains("load_authorized"));
    // audit write is observational (record call, no read-back for decisions)
    assert!(body.contains("crate::audit::record"));
    assert!(!body.contains("read_entries"));
}
