//! PHASE 9 "Key rotation / lifecycle" — focused tests for the
//! authentication-key rotation and the policy-neutral credential TTL
//! mechanism. The vault module is the enforcement (frozen I-1 invariants:
//! O_EXCL, 0600-before-content, pubkey-only validation); these tests pin
//! the mandated ordering, atomicity/crash boundaries, current-record
//! authority, lifecycle interaction (revoke/disabled), the owner route,
//! and evidence hygiene. No funded-wallet key is ever touched.

use crate::agents::agent_auth_key_rotate;
use crate::audit::{AuditCategory, AuditOutcome, IdentityClass, read_entries};
use axum::{
    extract::{Path, State},
    http::HeaderMap,
};
use std::path::PathBuf;
use uuid::Uuid;

const AUTH_KEYS: &str = "artifact/agent_auth_keys";

fn cwd_lock() -> &'static std::sync::Mutex<()> {
    &crate::stats::tests24::tests24::CWD_LOCK
}

struct Root(PathBuf);

impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-keylife-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_auth_keys")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_credentials")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_payment_intents")).unwrap();
        Self(root)
    }
    fn path(&self) -> PathBuf {
        self.0.clone()
    }
    fn vault(&self) -> PathBuf {
        self.0.join(AUTH_KEYS)
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
    // provision a REAL auth keypair (the established I-1 mint) + record
    let pubkey = crate::agent_auth_keys::provision_agent_auth_key(&root.vault(), id).unwrap();
    let agent = crate::agents::Agent {
        schema_version: crate::agents::AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: owner,
        name: "keylife-agent".to_string(),
        status: crate::agents::AgentStatus::Active,
        wallet_address: None,
        auth_public_key: Some(pubkey.clone()),
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

fn record_auth_key(root: &Root, id: &Uuid) -> Option<String> {
    let bytes = std::fs::read(root.agents().join(format!("{id}.json"))).unwrap();
    let agent: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    agent["auth_public_key"].as_str().map(|s| s.to_string())
}

fn canonical_key_exists(root: &Root, id: &Uuid) -> bool {
    root.vault().join(format!("{id}.json")).exists()
}

/// THE authoritative check: the RECORD's key is the expectation; the vault
/// file must match it. This is exactly the check the Latch binding (and
/// every consumer) performs — the record is the current-key authority.
fn binding_check(root: &Root, id: &Uuid) -> bool {
    let recorded = record_auth_key(root, id).unwrap_or_default();
    crate::agent_auth_keys::verify_auth_public_address(&root.vault(), id, &recorded).is_ok()
}

/// Does the canonical vault file hold this key (file-level fact)?
fn verify_current(root: &Root, id: &Uuid, expected: &str) -> bool {
    crate::agent_auth_keys::verify_auth_public_address(&root.vault(), id, expected).is_ok()
}

fn sidecars(root: &Root, id: &Uuid) -> Vec<String> {
    std::fs::read_dir(&root.vault())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".rotate-"))
        .collect()
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
// (A,B,C,D,I) rotation ordering + old/new key behavior (library level)
// ---------------------------------------------------------------------------

#[test]
fn rotation_full_sequence_new_key_authoritative_old_key_gone() {
    let root = Root::new("seq");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let old_key = agent.auth_public_key.clone().unwrap();
    assert!(
        verify_current(&root, &id, &old_key),
        "pre-rotation: current key verifies"
    );

    // (1)+(2) mint + validate the sidecar
    let (new_pubkey, generation) =
        crate::agent_auth_keys::mint_rotated_auth_key(&root.vault(), &id).unwrap();
    assert_ne!(
        new_pubkey, old_key,
        "A: a genuinely NEW keypair was generated"
    );

    // (3) authoritative record switch
    let path = root.agents().join(format!("{id}.json"));
    let mut updated = agent.clone();
    updated.auth_public_key = Some(new_pubkey.clone());
    updated.updated_at = 1_700_010_000;
    std::fs::write(&path, serde_json::to_vec_pretty(&updated).unwrap()).unwrap();

    // (4) old key becomes non-authoritative (single atomic rename)
    crate::agent_auth_keys::promote_rotated_auth_key(&root.vault(), &id, &generation).unwrap();

    // B: the authoritative binding (record vs file) verifies with the NEW
    // key and the OLD key is no longer accepted: the canonical file is now
    // the NEW key, so the old public identity can never bind again.
    assert!(binding_check(&root, &id), "C: the new key authenticates");
    assert!(
        !verify_current(&root, &id, &old_key),
        "B: the old key is gone from the vault"
    );
    // D: an unrelated key fails the binding
    let unrelated_dir = std::env::temp_dir().join(format!("keylife-unrelated-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&unrelated_dir).unwrap();
    let unrelated =
        crate::agent_auth_keys::provision_agent_auth_key(&unrelated_dir, &Uuid::new_v4()).unwrap();
    assert!(!verify_current(&root, &id, &unrelated));
    // H: the record points ONLY to the new key
    assert_eq!(
        record_auth_key(&root, &id).as_deref(),
        Some(new_pubkey.as_str())
    );
    // I: no sidecar remains; the canonical file holds the new key only —
    // the old key was NEVER simultaneously authoritative with the new one
    assert!(
        sidecars(&root, &id).is_empty(),
        "sidecar promoted, none left"
    );
    assert!(canonical_key_exists(&root, &id));
}

#[test]
fn old_key_never_authoritative_during_the_window() {
    // The mandated ordering: record switch BEFORE promotion. Between them,
    // verify fails CLOSED (Mismatch) — the old key is no longer accepted
    // and the new key is not yet reachable: no two-key ambiguity ever.
    let root = Root::new("window");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let old_key = agent.auth_public_key.clone().unwrap();
    let (new_pubkey, generation) =
        crate::agent_auth_keys::mint_rotated_auth_key(&root.vault(), &id).unwrap();

    // (3) record switch done; promotion NOT yet
    let path = root.agents().join(format!("{id}.json"));
    let mut updated = agent.clone();
    updated.auth_public_key = Some(new_pubkey.clone());
    std::fs::write(&path, serde_json::to_vec_pretty(&updated).unwrap()).unwrap();

    // in the window: THE AUTHORITATIVE BINDING FAILS CLOSED (record=new
    // pubkey, canonical file=old key => Mismatch) — no silent acceptance,
    // no two-key ambiguity: neither key is authoritative during the window.
    assert!(
        !binding_check(&root, &id),
        "fail-closed window: no silent acceptance"
    );
    // FILE FACT during the window: the canonical file still holds the old
    // key material, but it is NOT authoritative (the record names the new
    // key — the binding above already failed). After promotion the file
    // fact and the record agree again, and the old key is GONE.
    assert!(
        verify_current(&root, &id, &old_key),
        "file fact: old bytes still at the canonical path"
    );
    assert!(
        !sidecars(&root, &id).is_empty(),
        "sidecar pending promotion"
    );

    // complete the rotation: the window closes
    crate::agent_auth_keys::promote_rotated_auth_key(&root.vault(), &id, &generation).unwrap();
    assert!(
        binding_check(&root, &id),
        "C: the new key authenticates after promotion"
    );
    assert!(
        !verify_current(&root, &id, &old_key),
        "B: the old key is gone from the vault"
    );
}

// ---------------------------------------------------------------------------
// (E,F) fail-closed on corrupt/missing current key state
// ---------------------------------------------------------------------------

#[test]
fn corrupt_and_missing_current_key_fail_closed() {
    let root = Root::new("corrupt");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let recorded = agent.auth_public_key.clone().unwrap();

    // corrupt the canonical vault file: verification must FAIL CLOSED
    let path = root.vault().join(format!("{id}.json"));
    std::fs::write(&path, b"not a keypair container at all").unwrap();
    assert!(
        !verify_current(&root, &id, &recorded),
        "corrupt vault fails closed"
    );

    // missing vault file: fails closed (NotFound), never a silent accept
    std::fs::remove_file(&path).unwrap();
    assert!(
        !verify_current(&root, &id, &recorded),
        "missing vault fails closed"
    );
}

// ---------------------------------------------------------------------------
// (U) crash boundary: record switched, promotion interrupted
// ---------------------------------------------------------------------------

#[test]
fn crash_before_promotion_recovers_on_retry_never_ambiguous() {
    let root = Root::new("crash");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let old_key = agent.auth_public_key.clone().unwrap();
    let (new_pubkey, generation) =
        crate::agent_auth_keys::mint_rotated_auth_key(&root.vault(), &id).unwrap();

    // simulate the crash: record switched, promotion never happened
    let path = root.agents().join(format!("{id}.json"));
    let mut updated = agent.clone();
    updated.auth_public_key = Some(new_pubkey.clone());
    std::fs::write(&path, serde_json::to_vec_pretty(&updated).unwrap()).unwrap();

    // the crash state is FAIL-CLOSED (no two-key acceptance, no silent auth)
    assert!(!binding_check(&root, &id));

    // retry: a NEW mint + record switch + promotion converges
    let (retry_pubkey, retry_generation) =
        crate::agent_auth_keys::mint_rotated_auth_key(&root.vault(), &id).unwrap();
    let mut retry_record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    retry_record["auth_public_key"] = retry_pubkey.clone().into();
    std::fs::write(&path, serde_json::to_vec_pretty(&retry_record).unwrap()).unwrap();
    crate::agent_auth_keys::promote_rotated_auth_key(&root.vault(), &id, &retry_generation)
        .unwrap();

    assert!(binding_check(&root, &id));
    assert!(!verify_current(&root, &id, &old_key));
    assert!(
        !verify_current(&root, &id, &new_pubkey),
        "the interrupted attempt's key is not authoritative"
    );
    assert_eq!(
        record_auth_key(&root, &id).as_deref(),
        Some(retry_pubkey.as_str())
    );
    // the interrupted attempt's sidecar is cleaned up by the discard primitive
    crate::agent_auth_keys::discard_rotated_auth_key(&root.vault(), &id, &generation);
    assert!(sidecars(&root, &id).is_empty());
}

// ---------------------------------------------------------------------------
// (J,K) safe/exclusive creation + restrictive permissions
// ---------------------------------------------------------------------------

#[test]
fn sidecar_creation_is_exclusive_and_0600_never_overwrites() {
    let root = Root::new("perms");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let (_, generation) =
        crate::agent_auth_keys::mint_rotated_auth_key(&root.vault(), &id).unwrap();
    let sidecar_path = root.vault().join(format!("{id}.rotate-{generation}.json"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sidecar_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "K: sidecar is 0600");
    }
    // the canonical file was untouched by the mint
    let agent = record_auth_key(&root, &id).unwrap();
    assert!(
        verify_current(&root, &id, &agent),
        "mint alone changed nothing authoritative"
    );
    // cleanup for the fixture drop
    crate::agent_auth_keys::discard_rotated_auth_key(&root.vault(), &id, &generation);
}

// ---------------------------------------------------------------------------
// (G,H) handler: route semantics + record identity change
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
            cli: PathBuf::from("/nonexistent/keylife-test-cli"),
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
            login: format!("keylife-owner-{owner}"),
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
async fn owner_rotate_route_swaps_identity_and_audits_public_only() {
    let root = Root::new("route");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let old_key = agent.auth_public_key.clone().unwrap();
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = agent_auth_key_rotate(State(state), cookie(&sid), Path(id.to_string())).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 200);
        assert_eq!(body["success"], true);
        let new_key = body["auth_public_key"].as_str().unwrap().to_string();
        assert_ne!(new_key, old_key, "G: the public reference changed");
        // L: the response carries NO private material — only the public half
        let raw = serde_json::to_string(&body).unwrap();
        assert!(!raw.contains("keypair"), "no keypair concept in response");
        assert!(!raw.contains("rotate-"), "no sidecar path in response");
        // H: the record points ONLY to the new key
        assert_eq!(
            record_auth_key(&root, &id).as_deref(),
            Some(new_key.as_str())
        );
        // B/C at the vault level
        assert!(verify_current(&root, &id, &new_key));
        assert!(!verify_current(&root, &id, &old_key));
        assert!(
            sidecars(&root, &id).is_empty(),
            "promoted, no sidecar remains"
        );
        // N: one observational audit record with the stable code
        let entries = read_entries(
            &crate::audit::audit_dir_for(&crate::agents::intents_root()),
            Some(&id.to_string()),
        )
        .unwrap();
        let rotates: Vec<_> = entries
            .iter()
            .filter(|e| e.code.as_deref() == Some("AGENT_AUTH_KEY_ROTATED"))
            .collect();
        assert_eq!(rotates.len(), 1);
        assert_eq!(rotates[0].category, AuditCategory::Authorization);
        assert_eq!(rotates[0].outcome, AuditOutcome::Allow);
        assert_eq!(rotates[0].identity_class, Some(IdentityClass::Session));
        assert_eq!(
            rotates[0].agent_id.as_deref(),
            Some(id.to_string().as_str())
        );
        // M: no secret in the audit store
        let audit_raw = std::fs::read_to_string(
            crate::audit::audit_dir_for(&crate::agents::intents_root()).join(format!("{id}.json")),
        )
        .unwrap();
        assert!(!audit_raw.contains("rotate-"));
        assert!(!audit_raw.contains("keypair"));
    })
    .await;
}

// ---------------------------------------------------------------------------
// (O,P,Q) authorization boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_owner_unauthenticated_and_malformed_denied_identically() {
    let root = Root::new("boundary");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let recorded = agent.auth_public_key.clone().unwrap();
    with_cwd(&root, async {
        // non-owner: the SAME indistinguishable AGENT_NOT_FOUND, key untouched
        let (state, sid) = test_state(999);
        let resp = agent_auth_key_rotate(State(state), cookie(&sid), Path(id.to_string())).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(body["error"]["code"], "AGENT_NOT_FOUND");
        assert!(
            verify_current(&root, &id, &recorded),
            "key untouched by a foreign caller"
        );
        // unauthenticated
        let (state2, _) = test_state(50506084);
        let resp =
            agent_auth_key_rotate(State(state2), HeaderMap::new(), Path(id.to_string())).await;
        let (status2, body2) = envelope(resp).await;
        assert_eq!(status2, 401);
        assert_eq!(body2["error"]["code"], "NOT_AUTHENTICATED");
        // malformed/traversal ids: same collapse, no enumeration
        let (state3, sid3) = test_state(50506084);
        for bad in ["../etc/passwd", "not-a-uuid", ""] {
            let resp =
                agent_auth_key_rotate(State(state3.clone()), cookie(&sid3), Path(bad.to_string()))
                    .await;
            let (status, body) = envelope(resp).await;
            assert_eq!(status, 404);
            assert_eq!(body["error"]["code"], "AGENT_NOT_FOUND");
        }
        assert!(verify_current(&root, &id, &recorded));
    })
    .await;
}

// ---------------------------------------------------------------------------
// (R,S,X) lifecycle interaction: revoke + disabled are NOT resurrected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotation_never_resurrects_revoked_credential_or_disabled_agent() {
    let root = Root::new("lifecycle");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let recorded = agent.auth_public_key.clone().unwrap();
    // a REVOKED credential on this agent
    crate::agent_credentials::issue_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_200,
    )
    .unwrap();
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_300,
    )
    .unwrap();
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let resp = agent_auth_key_rotate(State(state), cookie(&sid), Path(id.to_string())).await;
        let (status, body) = envelope(resp).await;
        assert_eq!(
            status, 200,
            "auth-key rotation is the identity plane, not the credential lane"
        );
        // R: the credential stays revoked (rotation touched NOTHING on the
        // credential lane — the credential record is not read or written here)
        let cred_raw = std::fs::read_to_string(root.creds().join(format!("{id}.json"))).unwrap();
        assert!(
            cred_raw.contains("revoked_at"),
            "credential record untouched"
        );
        assert!(crate::agent_credentials::authenticate_in(&root.creds(), &"0".repeat(64)).is_err());
        // S: a DISABLED agent refuses rotation entirely (no resurrection)
        let id2 = Uuid::new_v4();
        let mut agent2 = persist_agent(&root, &id2, 50506084);
        agent2.status = crate::agents::AgentStatus::Disabled;
        std::fs::write(
            root.agents().join(format!("{id2}.json")),
            serde_json::to_vec_pretty(&agent2).unwrap(),
        )
        .unwrap();
        let (state2, sid2) = test_state(50506084);
        let resp2 =
            agent_auth_key_rotate(State(state2), cookie(&sid2), Path(id2.to_string())).await;
        let (status2, body2) = envelope(resp2).await;
        assert_eq!(status2, 403);
        assert_eq!(body2["error"]["code"], "AGENT_LIFECYCLE_BLOCKED");
        // the disabled agent's key is untouched
        assert!(verify_current(
            &root,
            &id2,
            &agent2.auth_public_key.clone().unwrap()
        ));
        // X: the ORIGINAL agent's recorded key after its own rotation
        // (the first agent rotated: its recorded key is the new one)
        let now_recorded = record_auth_key(&root, &id).unwrap();
        assert_ne!(now_recorded, recorded, "the active agent's key did rotate");
    })
    .await;
}

// ---------------------------------------------------------------------------
// (T) repeated rotation is safe (each rotation is its own generation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repeated_rotation_is_safe_and_deterministic_in_outcome() {
    let root = Root::new("repeat");
    let id = Uuid::new_v4();
    let agent = persist_agent(&root, &id, 50506084);
    let first = agent.auth_public_key.clone().unwrap();
    with_cwd(&root, async {
        let (state, sid) = test_state(50506084);
        let mut current = first.clone();
        for _ in 0..2 {
            let resp =
                agent_auth_key_rotate(State(state.clone()), cookie(&sid), Path(id.to_string()))
                    .await;
            let (status, body) = envelope(resp).await;
            assert_eq!(status, 200);
            let next = body["auth_public_key"].as_str().unwrap().to_string();
            assert_ne!(next, current, "each rotation generates a genuinely new key");
            assert!(verify_current(&root, &id, &next));
            assert!(
                !verify_current(&root, &id, &current),
                "previous key is dead"
            );
            current = next;
        }
        assert!(canonical_key_exists(&root, &id));
        assert!(sidecars(&root, &id).is_empty());
    })
    .await;
}

// ---------------------------------------------------------------------------
// (Y,Z structural) funded-wallet + Latch/Privy untouched
// ---------------------------------------------------------------------------

#[test]
fn rotation_touches_no_funded_wallet_and_no_latch_topology() {
    // The rotation surface lives ONLY in the auth-key vault: no wallet-dir,
    // no keypair-reference, no latch/privy/tee reference anywhere.
    let src = include_str!("agent_auth_keys.rs");
    let production = src.split("#[cfg(test)]").next().unwrap();
    // strip //-comment lines (the module DOC legitimately names the future
    // Latch lanes as ABSENT — the scan asserts EXECUTED code, not prose)
    let code: Vec<&str> = production
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let hay = code
        .join("\n")
        .replace("agenerationt", "agent")
        .to_lowercase();
    for forbidden in [
        "agent_wallets",
        "keypair_reference",
        "latch",
        "privy",
        "transfer",
    ] {
        assert!(
            !hay.contains(forbidden),
            "auth-key vault must never reference {forbidden}"
        );
    }
    // and the funded wallet dir is untouched by the route handler
    let agents_src = include_str!("agents.rs");
    let start = agents_src
        .find("pub async fn agent_auth_key_rotate")
        .expect("route exists");
    let body = &agents_src[start..start + 6000];
    assert!(
        !body.contains("agent_wallet_dir"),
        "no funded wallet access"
    );
    assert!(!body.to_lowercase().contains("latch"), "no latch topology");
}

// ---------------------------------------------------------------------------
// credential TTL mechanism (policy-neutral): V = expired rejected, W = valid stays
// ---------------------------------------------------------------------------

#[test]
fn expired_credential_never_authenticates_unexpired_does() {
    let root = Root::new("ttl");
    let id = Uuid::new_v4();
    persist_agent(&root, &id, 50506084);
    let credential = crate::agent_credentials::issue_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_000_000,
    )
    .unwrap();
    let record_path = root.creds().join(format!("{id}.json"));
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    assert!(crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_ok());

    // V: set expires_at in the PAST — the credential can never authenticate
    record = serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    record["expires_at"] = 1_690_000_000.into(); // far past
    std::fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    assert!(
        crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_err(),
        "expired credential is rejected (fail-closed)"
    );

    // W: a FUTURE expiry stays valid
    record["expires_at"] = 2_000_000_000.into();
    std::fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    assert!(crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_ok());

    // revoked + expired: both gates hold (revoke still wins, expiry adds nothing)
    crate::agent_credentials::revoke_in(
        &root.agents(),
        &root.creds(),
        &id.to_string(),
        1_700_010_000,
    )
    .unwrap();
    assert!(crate::agent_credentials::authenticate_in(&root.creds(), &credential).is_err());
}
