//! G21.11-FIX — Deterministic transfer kill-switch tests.
//!
//! Isolation model:
//! - Layer 1 (pure parse contract): runs in ANY process (no env/OnceLock).
//! - Layer 2/3 (enabled-state handlers + engine): #[ignore]d from shared
//!   runs; executed by the dedicated CI step with `--ignored`, in a process
//!   where AGENTPAY_DISABLE_TRANSFERS=1 is set before the first gate read,
//!   so the ONCE-cached value is deterministically TRUE.
//! - Disabled-state semantics (unset/0/false): proven by the entire
//!   existing FS suite (separate CI job, variable unset, separate process)
//!   plus the pure parse table here.

use axum::Json;

fn set_enabled() {
    // SAFETY: dedicated-process test; env set before first gate read.
    unsafe {
        std::env::set_var("AGENTPAY_DISABLE_TRANSFERS", "1");
    }
}

fn test_state() -> crate::AppState {
    crate::__unit_test_app_state()
}

fn session_cookie(state: &crate::AppState, user_id: u64, login: &str) -> String {
    let sid = uuid::Uuid::new_v4().to_string();
    state.sessions.lock().unwrap().insert(
        sid.clone(),
        crate::GithubUser {
            id: user_id,
            login: login.to_string(),
            name: None,
            avatar_url: None,
        },
    );
    sid
}

fn test_headers(cookie: &str) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&format!("agentpay_session={cookie}")).unwrap(),
    );
    h
}

fn body_bytes(body: axum::body::Body) -> Vec<u8> {
    // Runs inside the ambient MT runtime context; block_in_place keeps the
    // worker alive while collecting the body (no nested block_on).
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            axum::body::to_bytes(body, 4096)
                .await
                .expect("body bytes")
                .to_vec()
        })
    })
}

// ================= Layer 1: pure parse contract (always runs) ==============

#[test]
fn parse_rule_matches_documented_fail_safe_contract() {
    let cases: &[(&str, bool)] = &[
        ("0", false),
        ("false", false),
        ("FALSE", false),
        ("", false),
        ("  ", false),
        ("1", true),
        ("true", true),
        ("TRUE", true),
        ("banana", true), // malformed -> fail safe (enabled)
        ("2", true),
        (" 1", true), // untrimmed non-empty value -> not 0/false -> enabled
    ];
    for (raw, expect) in cases {
        assert_eq!(
            crate::parse_transfers_disabled_for_test(raw),
            *expect,
            "parse rule mismatch for {raw:?}"
        );
    }
    assert!(
        !crate::parse_transfers_disabled(&Err(std::env::VarError::NotPresent)),
        "unset arm must be disabled = false"
    );
}

// ============== Layer 2/3: enabled-state, dedicated process ================
// Each async body holds REQUIREMENTS verified in the enabled process.
// Sync #[ignore]d runners at bottom drive them on an MT runtime.

async fn enabled_direct_payment_rejected_before_state_change_impl() {
    let state = test_state();
    let cookie = session_cookie(&state, 555, "ks-user");

    let resp = crate::payment(
        axum::extract::State(state.clone()),
        test_headers(&cookie),
        Json(crate::PaymentRequest {
            to: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
            amount: 1.0,
        }),
    )
    .await;
    let (parts, body) = resp.into_parts();
    // auth (401) precedes kill-switch (503); both reject the transfer.
    assert!(
        matches!(
            parts.status,
            axum::http::StatusCode::UNAUTHORIZED | axum::http::StatusCode::SERVICE_UNAVAILABLE
        ),
        "unexpected status: {}",
        parts.status
    );
    let bytes = body_bytes(body);
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("\"success\":true"),
        "rejected payment must never be a success: {text}"
    );

    assert!(
        state.wallets.lock().unwrap().get(&555).is_none(),
        "rejected transfer must not mint or load a wallet (side-effect proof)"
    );
}

async fn enabled_faucet_rejected_impl() {
    let state = test_state();
    let cookie = session_cookie(&state, 555, "ks-user");
    let resp = crate::faucet(axum::extract::State(state.clone()), test_headers(&cookie)).await;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(String::from_utf8_lossy(&body_bytes(body)).contains("TRANSFERS_DISABLED"));
}

async fn enabled_read_only_endpoints_unaffected_impl() {
    let state = test_state();
    let cookie = session_cookie(&state, 556, "ks-ro");
    let Json(session) =
        crate::current_user(axum::extract::State(state), test_headers(&cookie)).await;
    let text = serde_json::to_string(&session).unwrap();
    assert!(!text.contains("TRANSFERS_DISABLED"));
}

async fn enabled_agent_owner_lane_rejected_before_state_change_impl() {
    let state = test_state();
    let cookie = session_cookie(&state, 777, "ks-owner");
    let resp = crate::agents::agent_payment(
        axum::extract::State(state.clone()),
        test_headers(&cookie),
        axum::extract::Path("11111111-1111-1111-1111-111111111111".to_string()),
        "{}".to_string(),
    )
    .await;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(String::from_utf8_lossy(&body_bytes(body)).contains("TRANSFERS_DISABLED"));
}

async fn enabled_engine_blocks_before_any_ops_or_writes_impl() {
    let root = std::env::temp_dir().join(format!("ks_engine_{}", std::process::id()));
    std::fs::create_dir_all(root.join("wallets")).unwrap();
    std::fs::create_dir_all(root.join("ledger")).unwrap();
    std::fs::create_dir_all(root.join("intents")).unwrap();

    let agent = crate::agents::Agent {
        schema_version: 1,
        agent_id: uuid::Uuid::new_v4().to_string(),
        owner_user_id: 1,
        name: "ks-agent".into(),
        status: crate::agents::AgentStatus::Active,
        wallet_address: None,
        auth_public_key: None,
        created_at: 0,
        updated_at: 0,
    };
    let policy = crate::agents::default_policy(&agent.agent_id);

    struct NeverOps;
    impl crate::agents::PaymentOps for NeverOps {
        fn uses_external_custody(&self) -> bool {
            false
        }
        fn balance(&self, _a: &str) -> Result<f64, crate::rialo::RialoError> {
            panic!("balance must not be reached when the switch is enabled");
        }
        fn transfer(
            &self,
            _k: &std::path::Path,
            _to: &str,
            _a: &str,
        ) -> Result<String, crate::rialo::RialoError> {
            panic!("transfer must not be reached when the switch is enabled");
        }
        fn read_tx(&self, _s: &str) -> crate::rialo::TxLookup {
            panic!("read_tx must not be reached when the switch is enabled");
        }
        fn signatures_for_address(
            &self,
            _a: &str,
            _until: Option<&str>,
            _limit: u64,
        ) -> Result<Vec<crate::rialo::SignatureInfoRecord>, crate::rialo::RialoError> {
            panic!("signatures_for_address must not be reached when enabled");
        }
    }
    let ops: &(dyn crate::agents::PaymentOps + Send + Sync) = &NeverOps;

    let result = crate::agents::execute_agent_payment(
        ops,
        &root.join("wallets"),
        &root.join("ledger"),
        &root.join("intents"),
        &agent,
        &policy,
        "ks-key-1",
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        1_000_000,
        1.0,
        40_000,
    );
    match result {
        Err(crate::agents::PaymentFailure::Recorded { status, code, .. }) => {
            assert_eq!((status, code.as_str()), (503, "TRANSFERS_DISABLED"));
        }
        other => panic!("engine must fail closed Recorded/503, got {other:?}"),
    }
    let entries = std::fs::read_dir(root.join("intents"))
        .map(|d| d.count())
        .unwrap_or(0);
    assert_eq!(entries, 0, "blocked request must not write intent rows");
    let _ = std::fs::remove_dir_all(&root);
}

async fn enabled_credential_trigger_lane_rejected_before_state_change_impl() {
    let state = test_state();

    // WRONG/absent credential still must hit the KILL-SWITCH FIRST (the gate
    // sits before credential parsing in the handler), so the response proves
    // gate precedence over authz: 503 + TRANSFERS_DISABLED — never a 401
    // credential error and never a reservation/ledger write.
    let resp = crate::agents::agent_trigger_payment(
        axum::extract::State(state.clone()),
        test_headers("no-session-needed"),
        "definitely-not-a-valid-credential".to_string(),
    )
    .await;
    let (parts, body) = resp.into_parts();
    assert_eq!(parts.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let bytes = body_bytes(body);
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("TRANSFERS_DISABLED"),
        "credential lane must hit the kill-switch before authz/engine, got: {text}"
    );
}

macro_rules! enabled_proc_test {
    ($name:ident, $impl:ident) => {
        #[test]
        #[ignore = "enabled-state: run via dedicated CI step / --ignored filter"]
        fn $name() {
            // Dedicated-process contract: env set before ANY gate read.
            unsafe {
                std::env::set_var("AGENTPAY_DISABLE_TRANSFERS", "1");
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("mt runtime");
            rt.block_on($impl());
        }
    };
}
enabled_proc_test!(
    enabled_direct_payment_rejected,
    enabled_direct_payment_rejected_before_state_change_impl
);
enabled_proc_test!(enabled_faucet_rejected, enabled_faucet_rejected_impl);
enabled_proc_test!(
    enabled_read_only_endpoints_unaffected,
    enabled_read_only_endpoints_unaffected_impl
);
enabled_proc_test!(
    enabled_agent_owner_lane_rejected,
    enabled_agent_owner_lane_rejected_before_state_change_impl
);
enabled_proc_test!(
    enabled_engine_blocks_before_writes,
    enabled_engine_blocks_before_any_ops_or_writes_impl
);
enabled_proc_test!(
    enabled_credential_trigger_lane_rejected,
    enabled_credential_trigger_lane_rejected_before_state_change_impl
);
