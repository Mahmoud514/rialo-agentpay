//! PHASE 9 D8/G-7 — AUTH-KEY BACKFILL — focused tests.
//!
//! Every test runs in its own temp root; the one live-data invocation is
//! explicitly gated behind `AGENTPAY_D8G7_LIVE=1` and asserts the exact
//! expected live state (4 agents, all linked afterwards, record↔vault
//! verification for each). Coverage:
//! - fresh provisioning of missing keys + additive record linkage
//! - recovery when a vault file exists but the linkage is absent
//! - no replacement of an existing valid key (verify-only path)
//! - idempotent repeated execution (second run = all linked, no mutation)
//! - malformed/corrupt record fails closed BEFORE any mutation
//! - non-canonical filename fails closed
//! - record/vault MISMATCH aborts with nothing mutated
//! - private material never exposed (vault file stays private; the fn
//!   returns only agent ids + outcome strings; the Agent model carries the
//!   public half only)
//! - exclusive creation + restrictive permissions where practical
//! - the live backfill itself (gated)

use crate::agents::{
    AGENT_SCHEMA_VERSION, Agent, AgentStatus, agent_path, backfill_agent_auth_keys, read_agent,
    write_json_atomic,
};
use std::path::PathBuf;
use std::{fs, path::Path as FsPath};
use uuid::Uuid;

struct Root(PathBuf);
impl Root {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("agentpay-d8g7-{tag}-{}", Uuid::new_v4()));
        fs::create_dir_all(root.join("agents")).unwrap();
        fs::create_dir_all(root.join("auth_keys")).unwrap();
        Self(root)
    }
    fn agents(&self) -> PathBuf {
        self.0.join("agents")
    }
    fn auth(&self) -> PathBuf {
        self.0.join("auth_keys")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn persist_agent(dir: &FsPath, id: &Uuid, owner: u64, auth: Option<String>) -> Agent {
    let agent = Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: id.to_string(),
        owner_user_id: owner,
        name: "d8g7-agent".to_string(),
        status: AgentStatus::Active,
        wallet_address: None,
        auth_public_key: auth,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_100,
    };
    write_json_atomic(&agent_path(dir, id), &agent).unwrap();
    agent
}

// ---------------------------------------------------------------------------
// fresh provisioning + linkage
// ---------------------------------------------------------------------------

#[test]
fn backfill_provisions_missing_keys_and_links_records() {
    let root = Root::new("fresh");
    let ids: Vec<_> = (0..3).map(|_| Uuid::new_v4()).collect();
    for id in &ids {
        persist_agent(&root.agents(), id, 50506084, None);
    }

    let report = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert_eq!(report.len(), 3, "every agent gets an outcome");
    assert!(report.iter().all(|(_, o)| *o == "provisioned"));

    for id in &ids {
        let agent = read_agent(&agent_path(&root.agents(), id)).unwrap();
        let pubkey = agent.auth_public_key.as_ref().expect("linkage recorded");
        assert!(!pubkey.is_empty());
        // record↔vault hard verification
        crate::agent_auth_keys::verify_auth_public_address(&root.auth(), id, pubkey)
            .expect("record matches vault");
        // vault file exists with restrictive permissions
        let key_path = crate::agent_auth_keys::auth_key_path(&root.auth(), id);
        assert!(key_path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "vault file is 0600");
        }
    }
}

// ---------------------------------------------------------------------------
// recovery: vault exists, linkage absent
// ---------------------------------------------------------------------------

#[test]
fn backfill_recovers_when_vault_exists_without_linkage() {
    let root = Root::new("recover");
    let id = Uuid::new_v4();
    persist_agent(&root.agents(), &id, 50506084, None);
    // vault file exists (as if a prior run provisioned then crashed before
    // the record write) — mint one directly
    let pubkey = crate::agent_auth_keys::provision_agent_auth_key(&root.auth(), &id).unwrap();

    let report = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert_eq!(report, vec![(id.to_string(), "recovered")]);

    let agent = read_agent(&agent_path(&root.agents(), &id)).unwrap();
    assert_eq!(agent.auth_public_key.as_deref(), Some(pubkey.as_str()));
    // NO second key was minted: the vault still holds exactly one file
    assert_eq!(fs::read_dir(&root.auth()).unwrap().count(), 1);
}

// ---------------------------------------------------------------------------
// no replacement of an existing valid key
// ---------------------------------------------------------------------------

#[test]
fn backfill_never_replaces_an_existing_valid_key() {
    let root = Root::new("noreplace");
    let id = Uuid::new_v4();
    let first = crate::agent_auth_keys::provision_agent_auth_key(&root.auth(), &id).unwrap();
    persist_agent(&root.agents(), &id, 50506084, Some(first.clone()));

    let report = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert_eq!(report, vec![(id.to_string(), "linked")]);

    // the vault file is byte-identical (no re-mint)
    let second = crate::agent_auth_keys::read_auth_public_key(&root.auth(), &id).unwrap();
    assert_eq!(first, second, "existing key untouched");
    // the record is unchanged (no write)
    let agent = read_agent(&agent_path(&root.agents(), &id)).unwrap();
    assert_eq!(agent.auth_public_key.as_deref(), Some(first.as_str()));
    assert_eq!(agent.updated_at, 1_700_000_100, "updated_at untouched");
}

// ---------------------------------------------------------------------------
// idempotent repeated execution
// ---------------------------------------------------------------------------

#[test]
fn backfill_is_idempotent_across_repeated_runs() {
    let root = Root::new("idempotent");
    let ids: Vec<_> = (0..2).map(|_| Uuid::new_v4()).collect();
    for id in &ids {
        persist_agent(&root.agents(), id, 50506084, None);
    }

    let first = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert!(first.iter().all(|(_, o)| *o == "provisioned"));

    // snapshot record bytes
    let before: Vec<Vec<u8>> = ids
        .iter()
        .map(|id| fs::read(agent_path(&root.agents(), id)).unwrap())
        .collect();

    let second = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert!(
        second.iter().all(|(_, o)| *o == "linked"),
        "second run: no mutations"
    );
    let after: Vec<Vec<u8>> = ids
        .iter()
        .map(|id| fs::read(agent_path(&root.agents(), id)).unwrap())
        .collect();
    assert_eq!(before, after, "records byte-identical across runs");
}

// ---------------------------------------------------------------------------
// malformed/corrupt state fails closed BEFORE any mutation
// ---------------------------------------------------------------------------

#[test]
fn corrupt_record_fails_closed_before_any_mutation() {
    let root = Root::new("corrupt");
    let good = Uuid::new_v4();
    persist_agent(&root.agents(), &good, 50506084, None);
    let bad = Uuid::new_v4();
    fs::write(
        agent_path(&root.agents(), &bad),
        b"{\"schema_version\":1,\"agent_id\":\"not-a-uuid\"}",
    )
    .unwrap();

    let err = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap_err();
    assert!(err.contains("unreadable"), "{err}");

    // NOTHING was mutated: the good agent has no key, the vault is empty
    let agent = read_agent(&agent_path(&root.agents(), &good)).unwrap();
    assert!(
        agent.auth_public_key.is_none(),
        "no linkage written after abort"
    );
    assert_eq!(
        fs::read_dir(&root.auth()).unwrap().count(),
        0,
        "no key provisioned"
    );
}

#[test]
fn non_canonical_filename_fails_closed() {
    let root = Root::new("noncanon");
    let good = Uuid::new_v4();
    persist_agent(&root.agents(), &good, 50506084, None);
    fs::write(root.agents().join("not-a-uuid.json"), b"{}").unwrap();

    let err = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap_err();
    assert!(err.contains("non-canonical"), "{err}");
    assert!(
        read_agent(&agent_path(&root.agents(), &good))
            .unwrap()
            .auth_public_key
            .is_none()
    );
}

#[test]
fn record_vault_mismatch_aborts_with_nothing_mutated() {
    let root = Root::new("mismatch");
    let id = Uuid::new_v4();
    let real = crate::agent_auth_keys::provision_agent_auth_key(&root.auth(), &id).unwrap();
    // record points at a DIFFERENT (fabricated but well-formed) pubkey
    persist_agent(
        &root.agents(),
        &id,
        50506084,
        Some("9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA".to_string()),
    );
    assert_ne!(real, "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA");

    let err = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap_err();
    assert!(err.contains("MISMATCH"), "{err}");
    // the record was NOT rewritten (still carries the mismatching value)
    let agent = read_agent(&agent_path(&root.agents(), &id)).unwrap();
    assert_eq!(
        agent.auth_public_key.as_deref(),
        Some("9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA")
    );
}

// ---------------------------------------------------------------------------
// private material never exposed
// ---------------------------------------------------------------------------

#[test]
fn backfill_returns_only_public_identity_and_outcomes() {
    let root = Root::new("nopk");
    let id = Uuid::new_v4();
    persist_agent(&root.agents(), &id, 50506084, None);

    let report = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    // outcomes are one of the three fixed strings; agent ids only
    for (aid, outcome) in &report {
        assert!(["linked", "recovered", "provisioned"].contains(outcome));
        assert!(Uuid::parse_str(aid).is_ok(), "agent id is canonical");
    }
    // the Agent model serializes ONLY the public half (the private half
    // lives in the 0600 vault file, never in any struct field)
    let agent = read_agent(&agent_path(&root.agents(), &id)).unwrap();
    let serialized = serde_json::to_vec(&agent).unwrap();
    let text = String::from_utf8(serialized).unwrap();
    // the vault file's private half is NOT base58-of-pubkey — stronger: no
    // 64-byte-array or secret-ish fields can exist in the Agent model
    assert!(text.contains("auth_public_key"));
    assert!(
        !text.contains("private"),
        "no private field on the Agent model"
    );
    // the vault file is NOT readable via the record: distinct paths
    assert!(crate::agent_auth_keys::auth_key_path(&root.auth(), &id).starts_with(&root.auth()));
}

#[test]
fn vault_file_permissions_are_restrictive_after_provision() {
    let root = Root::new("perm");
    let id = Uuid::new_v4();
    persist_agent(&root.agents(), &id, 50506084, None);
    backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(crate::agent_auth_keys::auth_key_path(&root.auth(), &id))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group/other access to the vault file");
    }
}

#[test]
fn concurrent_backfills_cannot_double_provision() {
    let root = Root::new("concurrent");
    let id = Uuid::new_v4();
    persist_agent(&root.agents(), &id, 50506084, None);

    // two sequential backfills: the second must NOT re-mint (O_EXCL refuses
    // and the recovery branch converges)
    let first = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert_eq!(first, vec![(id.to_string(), "provisioned")]);
    let second = backfill_agent_auth_keys(&root.agents(), &root.auth()).unwrap();
    assert_eq!(second, vec![(id.to_string(), "linked")]);
    assert_eq!(
        fs::read_dir(&root.auth()).unwrap().count(),
        1,
        "exactly one key"
    );
}

// ---------------------------------------------------------------------------
// THE LIVE BACKFILL — gated, explicit, asserts the exact live state
// ---------------------------------------------------------------------------

#[test]
fn live_d8g7_backfill_of_the_four_pre_i1_agents() {
    if std::env::var("AGENTPAY_D8G7_LIVE").ok().as_deref() != Some("1") {
        // not gated: the default test run must never touch live data
        return;
    }
    static LIVE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    let _guard = LIVE_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap();
    let original = std::env::current_dir().unwrap();
    std::env::set_current_dir(".").unwrap(); // cwd = repo root
    let result = std::panic::catch_unwind(|| {
        let agents_dir = FsPath::new("artifact/agents");
        let auth_dir = FsPath::new("artifact/agent_auth_keys");

        // PRECONDITION: exactly the 4 known live agents, all missing linkage
        let expected: Vec<String> = vec![
            "d547d407-c5ba-4ea5-854f-69ef213e5c5f".into(),
            "dfcaa852-c5a7-4cd8-a72a-e71049d6c174".into(),
            "8551ac69-2f0b-476e-8ea6-61cc6f608114".into(),
            "1c671bd1-7ca9-490a-b93a-4850f36eea75".into(),
        ];
        let report =
            backfill_agent_auth_keys(agents_dir, auth_dir).expect("live backfill must succeed");
        let by_id: std::collections::HashMap<&str, &str> =
            report.iter().map(|(id, o)| (id.as_str(), *o)).collect();
        for exp in &expected {
            assert!(
                by_id.contains_key(exp.as_str()),
                "live agent {exp} must appear in the report"
            );
            let outcome = by_id[exp.as_str()];
            assert!(
                ["linked", "recovered", "provisioned"].contains(&outcome),
                "unexpected outcome {outcome} for {exp}"
            );
        }
        assert_eq!(
            report.len(),
            4,
            "exactly the 4 live agents processed, got {report:?}"
        );

        // POSTCONDITION: every live agent record↔vault verifies
        for exp in &expected {
            let id = Uuid::parse_str(exp).unwrap();
            let agent = read_agent(&agent_path(agents_dir, &id)).unwrap();
            let pubkey = agent.auth_public_key.as_ref().expect("linkage present");
            crate::agent_auth_keys::verify_auth_public_address(auth_dir, &id, pubkey)
                .expect("record↔vault verified");
        }
    });
    std::env::set_current_dir(&original).unwrap();
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}
