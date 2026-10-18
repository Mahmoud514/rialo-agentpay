// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.5.1 — credential lane, minimal route
// compilation tests (the full privacy test matrix is a LATER part).
//
// The real `agent_trigger_stats` handler (`stats.rs`) is mounted on a
// fresh `axum::Router` with the EXACT route set + relative registration
// order server.rs uses (literal `/api/agents/stats` -> parameterized
// `/api/agents/{id}/stats` -> literal `/api/agents/triggers/payments/stats`)
// and exercised IN-PROCESS against a bound `TcpListener` (the same
// harness pattern the tests24 suite uses).
//
// The credential store and the stats stores all bind the RELATIVE
// `artifact/` tree through their production wrappers, so each test
// chdir's into a fresh temp root (serialized by the process-wide CWD
// lock, held across the request await) and issues a REAL credential with
// the EXISTING `agent_credentials::issue_in` helper — no credential
// internals are reimplemented or touched here.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests251 {
    use super::*;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    use crate::stats::{agent_stats, agent_trigger_stats, owner_stats};

    /// The ONE credential-lane route this suite drills.
    const CRED_PATH: &str = "/api/agents/triggers/payments/stats";
    const AGENT_A: &str = "11111111-1111-4111-8111-111111111111";
    const OWNER_ID: u64 = 8001;
    const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";

    /// The SAME process-wide CWD lock the tests24 suite holds (declared
    /// once in the parent `stats` module — per-module statics would race
    /// across the parallel test threads, since cargo runs test functions
    /// from different modules concurrently).

    /// Mint a FRESH temp root: one active agent (AGENT_A) with ONE
    /// confirmed slot (4 RLO, recipient RECIPIENT). The canonical
    /// lowercase-hex slot file name is the hex of the idempotency key.
    fn hex_key(input: &str) -> String {
        let mut out = String::new();
        for b in input.as_bytes() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn v1_intent(key: &str) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{AGENT_A}","idempotency_key":"{key}","request_fingerprint":"0000000000000000","recipient":"{RECIPIENT}","amount_kelvin":4000000000,"state":"confirmed","response":null,"created_at":1700000000,"updated_at":1700000900,"reconciliation":null}}"#
        )
    }

    fn mint_tree() -> PathBuf {
        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rialo-stats251-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let agents = root.join("artifact/agents");
        std::fs::create_dir_all(&agents).unwrap();
        let intents = root.join(format!("artifact/agent_payment_intents/{AGENT_A}"));
        std::fs::create_dir_all(&intents).unwrap();
        let a_json = serde_json::json!({
            "schema_version": 1,
            "agent_id": AGENT_A,
            "owner_user_id": OWNER_ID,
            "name": "Cred-Agent",
            "status": "active",
            "wallet_address": null,
            "created_at": 1_700_000_000,
            "updated_at": 1_700_000_000,
        });
        std::fs::write(
            agents.join(format!("{AGENT_A}.json")),
            serde_json::to_vec(&a_json).unwrap(),
        )
        .unwrap();
        std::fs::write(
            intents.join(format!("{}.json", hex_key("iso-1"))),
            v1_intent("iso-1"),
        )
        .unwrap();
        root
    }

    /// Chdir into `root` (restoring afterwards) while holding the lock
    /// for the full `f.await`.
    async fn with_cwd<R: std::future::Future>(root: &std::path::Path, f: R) -> R::Output {
        let _guard = crate::stats::tests24::tests24::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let result = f.await;
        let _ = std::env::set_current_dir(&original);
        result
    }

    /// Issue a REAL credential for AGENT_A under `root` (the production
    /// wrappers bind the relative `artifact/` tree, so the issue MUST run
    /// while `root` is the CWD; it holds the same CWD lock).
    async fn issue_credential(root: &std::path::Path) -> String {
        let _guard = crate::stats::tests24::tests24::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let credential = crate::agent_credentials::issue_in(
            &crate::agent_credentials::production_agents_dir(),
            &crate::agent_credentials::production_credentials_dir(),
            AGENT_A,
            1_700_000_000,
        )
        .expect("credential issued for the fixture agent");
        let _ = std::env::set_current_dir(&original);
        credential
    }

    /// Production AppState for the focused suite (one owner session so
    /// the `{id}` family + owner lane can be exercised; the credential
    /// lane never consults it).
    fn app_state_for() -> crate::AppState {
        let user = crate::GithubUser {
            id: OWNER_ID,
            login: "owner".to_string(),
            name: None,
            avatar_url: None,
        };
        let session = Uuid::new_v4().to_string();
        let mut sessions = HashMap::new();
        sessions.insert(session.clone(), user);
        crate::AppState {
            client: reqwest::Client::new(),
            client_id: "x".into(),
            client_secret: "x".into(),
            redirect_uri: "http://localhost/callback".into(),
            oauth_states: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(sessions)),
            wallets: Arc::new(Mutex::new(HashMap::new())),
            rialo: Arc::new(crate::rialo::RialoConfig {
                cli: "rialo".into(),
                rpc_url: "http://127.0.0.1:4104".into(),
                program_id: None,
                program_dir: "artifact".into(),
            }),
        }
    }

    /// The ONE session cookie for the owner (owner-lane + `{id}`-family
    /// checks only).
    fn session_cookie(state: &crate::AppState) -> String {
        let sessions = state.sessions.lock().unwrap();
        let session_id = sessions
            .iter()
            .find(|(_, u)| u.id == OWNER_ID)
            .expect("session present")
            .0
            .clone();
        format!("agentpay_session={session_id}")
    }

    /// The production router for the Part-2.5.1 surface: the EXACT route
    /// set + relative order server.rs registers — literal stats, the
    /// parameterized `{id}` stats, then the literal trigger stats.
    fn stats251_router(state: crate::AppState) -> axum::Router {
        axum::Router::new()
            .route("/api/agents/stats", get(owner_stats))
            .route("/api/agents/{id}/stats", get(agent_stats))
            .route(CRED_PATH, get(agent_trigger_stats))
            .with_state(state)
    }

    /// Drive ONE request IN-PROCESS through the real `axum::serve` loop
    /// on a FRESH `TcpListener` (per-request listener: no shared-socket
    /// races). `credential` / `header` are optional extra headers
    /// (exactly one kind is ever set per drive).
    fn drive_request(
        router: &axum::Router,
        path: &str,
        credential: Option<&str>,
        cookie: Option<&str>,
    ) -> impl std::future::Future<Output = (u16, String)> {
        let router = router.clone();
        let url_path = path.to_string();
        let credential = credential.map(|c| c.to_string());
        let cookie = cookie.map(|c| c.to_string());
        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}{url_path}");
            let req = client.get(&url);
            let req = match credential.as_deref() {
                Some(c) => req.header("X-Agent-Credential", c),
                None => req,
            };
            let req = match cookie.as_deref() {
                Some(c) => req.header("COOKIE", c),
                None => req,
            };
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap();
            drop(server_task);
            (status, body)
        })
    }

    /// The auth-negative drive for a MULTI-VALUE header: reqwest joins
    /// multiple values with `", "` into one wire header, which the
    /// handler's shape gate (exactly 64 lowercase hex) rejects — the
    /// SAME stable 401 family a true duplicate header gets server-side.
    fn drive_request_multi(
        router: &axum::Router,
        path: &str,
        a: &str,
        b: &str,
    ) -> impl std::future::Future<Output = (u16, String)> {
        let router = router.clone();
        let url_path = path.to_string();
        let joined = format!("{a}, {b}");
        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}{url_path}");
            let resp = client
                .get(&url)
                .header("X-Agent-Credential", joined)
                .send()
                .await
                .unwrap();
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap();
            drop(server_task);
            (status, body)
        })
    }

    // -----------------------------------------------------------------------
    // 1) Auth gate: missing / malformed / duplicate header -> ONE stable
    //    401 AGENT_CREDENTIAL_INVALID
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn trigger_stats_auth_negative_returns_401_agent_credential_invalid() {
        let root = mint_tree();
        let state = app_state_for();
        let router = stats251_router(state);

        // MISSING header
        let (status, body) = with_cwd(&root, drive_request(&router, CRED_PATH, None, None)).await;
        assert_eq!(status, 401, "missing header must be 401, got: {status}");
        assert!(
            body.contains("AGENT_CREDENTIAL_INVALID"),
            "expected AGENT_CREDENTIAL_INVALID, got: {body}"
        );

        // MALFORMED (wrong length / wrong charset)
        let (status, body) = with_cwd(
            &root,
            drive_request(&router, CRED_PATH, Some("short"), None),
        )
        .await;
        assert_eq!(status, 401, "malformed header must be 401, got: {status}");
        assert!(
            body.contains("AGENT_CREDENTIAL_INVALID"),
            "expected AGENT_CREDENTIAL_INVALID, got: {body}"
        );

        // DUPLICATE / multi-value header (not exactly one 64-lowercase-hex
        // value)
        let (status, body) = with_cwd(
            &root,
            drive_request_multi(&router, CRED_PATH, &"0".repeat(64), &"1".repeat(64)),
        )
        .await;
        assert_eq!(status, 401, "duplicate header must be 401, got: {status}");
        assert!(
            body.contains("AGENT_CREDENTIAL_INVALID"),
            "expected AGENT_CREDENTIAL_INVALID, got: {body}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 2) Valid credential -> 200: the SAME per-agent DTO through the
    //    credential-safe path (scope agent_credential, recipient omitted,
    //    credential material never rendered) — and a query-supplied
    //    agent_id is INERT (the principal never comes from the URL)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn trigger_stats_valid_credential_returns_200_credential_safe_dto() {
        let root = mint_tree();
        let credential = issue_credential(&root).await;
        let state = app_state_for();
        let router = stats251_router(state);

        // a query-supplied agent_id MUST be ignored: the principal is the
        // credential-resolved agent, never the URL
        let path = format!("{CRED_PATH}?agent_id=00000000-0000-4000-8000-000000000000");
        let (status, body) = with_cwd(
            &root,
            drive_request(&router, &path, Some(&credential), None),
        )
        .await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            status, 200,
            "valid credential must be 200, got: {status} body={body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["scope"], "agent_credential");
        // the identity is the CREDENTIAL-RESOLVED agent, not the query
        assert_eq!(v["agent_id"], AGENT_A);
        assert_eq!(v["name"], "Cred-Agent");
        assert_eq!(v["status"], "active");
        // the one minted confirmed slot is visible (real stats core)
        assert_eq!(v["totals"]["confirmed_count"], 1);
        assert_eq!(v["totals"]["confirmed_volume_kelvin"], 4_000_000_000u64);
        // the credential-safe path: NO recipient field on any timeline entry
        let timeline = v["timeline"].as_array().expect("timeline array present");
        assert_eq!(timeline.len(), 1, "exactly one confirmed slot");
        assert!(
            timeline[0].get("recipient").is_none(),
            "credential lane must never render the recipient field, got: {}",
            timeline[0]
        );
        // credential material is never echoed into the response
        assert!(
            !body.contains(&credential),
            "credential leaked into the response body"
        );
    }

    // -----------------------------------------------------------------------
    // 3) Route resolution: the literal trigger route wins where it is
    //    registered; the `{id}` family and the owner lane stay intact
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn trigger_stats_route_resolution_no_collision_with_id_family() {
        let root = mint_tree();
        let state = app_state_for();
        let cookie = session_cookie(&state);
        let router = stats251_router(state);

        // a session cookie alone must NOT satisfy the credential lane —
        // the principal never comes from a session
        let (status, body) = with_cwd(
            &root,
            drive_request(&router, CRED_PATH, None, Some(&cookie)),
        )
        .await;
        assert_eq!(
            status, 401,
            "session alone must not authenticate the credential lane, got: {status}"
        );
        assert!(
            body.contains("AGENT_CREDENTIAL_INVALID"),
            "expected AGENT_CREDENTIAL_INVALID, got: {body}"
        );

        // a 2-segment path that ONLY `{id}/stats` can match with a valid
        // session: id = a real canonical uuid -> the owner lane's choke
        // point must answer (agent exists and is owned -> 200 readout)
        let path = format!("/api/agents/{AGENT_A}/stats");
        let (status, body) =
            with_cwd(&root, drive_request(&router, &path, None, Some(&cookie))).await;
        assert_eq!(
            status, 200,
            "the {{id}} family must stay intact, got: {status} body={body}"
        );
        let ok: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(ok["agent_id"], AGENT_A);

        // non-canonical id on the {id} family -> the established 404 choke
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                "/api/agents/not-a-canonical-uuid/stats",
                None,
                Some(&cookie),
            ),
        )
        .await;
        assert_eq!(status, 404, "non-canonical {{id}} must 404, got: {status}");
        assert!(
            body.contains("AGENT_NOT_FOUND"),
            "expected AGENT_NOT_FOUND from the {{id}} choke, got: {body}"
        );

        // the owner lane is UNTOUCHED by the new registration
        let (status, body) = with_cwd(
            &root,
            drive_request(&router, "/api/agents/stats", None, Some(&cookie)),
        )
        .await;
        assert_eq!(
            status, 200,
            "owner lane must stay intact, got: {status} body={body}"
        );
        assert!(
            body.contains("\"agents_total\""),
            "owner DTO intact, got: {body}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
