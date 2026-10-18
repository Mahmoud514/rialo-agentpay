// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.3 — focused API / auth tests (routes).
//
// Focused at the ROUTE level: the real production handlers
// (`owner_stats`, `agent_stats` in `stats.rs`) are mounted on a fresh
// `axum::Router` (the literal `/api/agents/stats` route BEFORE the
// parameterized `/api/agents/{id}/stats` — the EXACT relative order
// server.rs uses) and exercised IN-PROCESS against a real bound
// `TcpListener` (no mock, no fake router, no env mutation).
//
// The read-only cores read RELATIVE paths (`artifact/agents`,
// `artifact/agent_payment_intents`) via `crate::agents::agents_dir()` /
// `intents_root()`. We keep the test self-contained (no env, no server.rs
// edits) by chdir-ing into a fresh temp root for the duration of the
// request. A GLOBAL Mutex serializes the chdir tests so concurrent
// `#[tokio::test]` instances cannot race on the process CWD.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests24 {
    use super::*;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use uuid::Uuid;

    use crate::stats::{agent_stats, owner_stats};

    const AGENT_A: &str = "11111111-1111-4111-8111-111111111111";
    const AGENT_B: &str = "22222222-2222-4222-8222-222222222222";

    fn hex_key(input: &str) -> String {
        let mut out = String::new();
        for b in input.as_bytes() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn v1_intent(
        id: &str,
        key: &str,
        state: &str,
        amount: u64,
        created_at: i64,
        updated_at: i64,
        recipient: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{id}","idempotency_key":"{key}","request_fingerprint":"{fingerprint}","recipient":"{recipient}","amount_kelvin":{amount},"state":"{state}","response":null,"created_at":{created_at},"updated_at":{updated_at},"reconciliation":null}}"#,
            fingerprint = "0000000000000000"
        )
    }

    const OWNER_ID: u64 = 7001;
    const FOREIGN_ID: u64 = 7002;

    /// A GLOBAL CWD lock shared by EVERY chdir-based stats route test
    /// (tests24 + tests251): `cargo test` runs test functions from
    /// different modules in parallel threads, so per-module lock statics
    /// would let two suites flip the process CWD mid-request (the
    /// spawn_blocking scans read the RELATIVE `artifact/` tree at
    /// execution time). This static is the single process-wide
    /// serialization point for the whole suite, and the guard is held for
    /// the full `f.await` (a guard that fell out early made the suite
    /// silently read the real tree — it must be held across the await).
    pub(crate) static CWD_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    /// Mint a FRESH temp root (atomic counter + pid). The owner's agent
    /// (AGENT_A, active) and the foreign agent (AGENT_B, draft) are
    /// laid out at `root/artifact/agents/<uuid>.json`; the foreign
    /// agent's intents dir gets ONE confirmed slot (so an isolation
    /// bypass would be detectable), the owner's agent gets NO intents
    /// dir (valid empty store).
    fn mint_tree() -> PathBuf {
        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rialo-stats24-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let agents = root.join("artifact/agents");
        let intents = root.join("artifact/agent_payment_intents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::create_dir_all(&intents).unwrap();
        let a_json = serde_json::json!({
            "schema_version": 1,
            "agent_id": AGENT_A,
            "owner_user_id": OWNER_ID,
            "name": "Owner-Agent",
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
        let b_json = serde_json::json!({
            "schema_version": 1,
            "agent_id": AGENT_B,
            "owner_user_id": FOREIGN_ID,
            "name": "Foreign-Agent",
            "status": "draft",
            "wallet_address": null,
            "created_at": 1_700_000_000,
            "updated_at": 1_700_000_000,
        });
        std::fs::write(
            agents.join(format!("{AGENT_B}.json")),
            serde_json::to_vec(&b_json).unwrap(),
        )
        .unwrap();
        let foreign_dir = intents.join(AGENT_B);
        std::fs::create_dir_all(&foreign_dir).unwrap();
        std::fs::write(
            foreign_dir.join(format!("{}.json", hex_key("iso-1"))),
            &v1_intent(
                AGENT_B,
                "iso-1",
                "confirmed",
                12_345_000,
                1_700_000_000,
                1_700_000_999,
                "F2ISO",
            ),
        )
        .unwrap();
        root
    }

    /// Chdir into `root` (saving/restoring the original CWD) while
    /// holding the process-wide CWD lock for the FULL duration of
    /// `f.await` — the guard is acquired here, released only after the
    /// request future completes. (The old synchronous shape restored the
    /// CWD as soon as the future was CONSTRUCTED, before the request ran:
    /// the whole suite was silently hitting the real tree.)
    async fn with_cwd<R: std::future::Future>(root: &std::path::Path, f: R) -> R::Output {
        // Poison-safe: if a prior test panicked while holding the CWD
        // lock, recover and keep serializing the chdir window.
        let _guard = crate::stats::tests24::tests24::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let result = f.await;
        let _ = std::env::set_current_dir(&original);
        result
    }

    /// Build the production AppState for the focused test suite:
    /// in-memory sessions (one OWNER, one FOREIGN), fresh `RialoConfig`
    /// (no chain, no wallet, no credential store).
    fn app_state_for(owner: bool) -> crate::AppState {
        let user = crate::GithubUser {
            id: if owner { OWNER_ID } else { FOREIGN_ID },
            login: (if owner { "owner" } else { "foreign" }).to_string(),
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

    /// The production Router for the Part-2.3 surface ONLY: the literal
    /// `/api/agents/stats` route FIRST, then the parameterized
    /// `/api/agents/{id}/stats` route — the EXACT relative order server.rs
    /// uses in the full app.
    fn stats_router(state: crate::AppState) -> axum::Router {
        axum::Router::new()
            .route("/api/agents/stats", get(owner_stats))
            .route("/api/agents/{id}/stats", get(agent_stats))
            .with_state(state)
    }

    /// The one session cookie for the OWNER (or FOREIGN) user.
    fn session_cookie(state: &crate::AppState, owner: bool) -> String {
        let sessions = state.sessions.lock().unwrap();
        let session_id = sessions
            .iter()
            .find(|(_, u)| u.id == if owner { OWNER_ID } else { FOREIGN_ID })
            .expect("session present")
            .0
            .clone();
        format!("agentpay_session={session_id}")
    }

    /// Drive ONE request IN-PROCESS through the real `axum::serve` loop
    /// on a FRESH `TcpListener` (each request gets its own listener, so
    /// no two requests ever race on a shared connection; zero env
    /// mutation, no chdir INSIDE this fn — the caller's `with_cwd` owns
    /// the CWD). Returns `(status, body)` as a future the caller
    /// `block_on`s from within `with_cwd`.
    fn drive_request(
        router: &axum::Router,
        path: &str,
        cookie: Option<&str>,
    ) -> impl std::future::Future<Output = (u16, String)> {
        let router = router.clone();
        let url_path = path.to_string();
        let cookie = cookie.map(|c| c.to_string());
        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            // Brief yield: let the spawned serve loop accept the socket
            // before the client connects (the serve loop is a separate task).
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}{url_path}");
            let req = client.get(&url);
            let req = match cookie.as_deref() {
                Some(c) => req.header("COOKIE", c),
                None => req,
            };
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap();
            // No abort here: the serve task dies with the test runtime when
            // `#[tokio::test]` tears down. Aborting it immediately would race
            // the in-flight response and flake the test.
            drop(server_task);
            (status, body)
        })
    }

    // -----------------------------------------------------------------------
    // 1) Unauth -> 401 NOT_AUTHENTICATED (both routes, same envelope)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unauth_owner_stats_returns_401_not_authenticated() {
        let root = mint_tree();
        let state = app_state_for(true);
        let router = stats_router(state);
        let (status, body) =
            with_cwd(&root, drive_request(&router, "/api/agents/stats", None)).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 401, "expected 401, got: {status}");
        assert!(
            body.contains("NOT_AUTHENTICATED"),
            "expected NOT_AUTHENTICATED in body, got: {body}"
        );
    }

    #[tokio::test]
    async fn unauth_single_agent_stats_returns_401_not_authenticated() {
        let root = mint_tree();
        let state = app_state_for(true);
        let router = stats_router(state);
        let path = format!("/api/agents/{AGENT_A}/stats");
        let (status, body) = with_cwd(&root, drive_request(&router, &path, None)).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 401, "expected 401, got: {status}");
        assert!(
            body.contains("NOT_AUTHENTICATED"),
            "expected NOT_AUTHENTICATED in body, got: {body}"
        );
    }

    // -----------------------------------------------------------------------
    // 2) Valid empty store -> 200 / zero + empty + null (owner aggregate)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn owner_stats_valid_empty_store_returns_200_zero_empty_null() {
        let root = mint_tree();
        let state = app_state_for(true);
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let cookie_owned = cookie.clone();
        let (status, body) = with_cwd(&root, {
            let path = "/api/agents/stats";
            drive_request(&router, path, Some(&cookie_owned))
        })
        .await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 200, "expected 200, got: {status} body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let total = v["agents_total"].as_u64();
        assert_eq!(total, Some(1), "agents_total expected 1, got: {v}");
        // The owner aggregate shape: agents_total must equal the number
        // of agents we minted for OWNER_ID (just AGENT_A) and the
        // `totals` block must be all-zero with empty by_day. The
        // per-agent row must have an EMPTY timeline (the owner's agent
        // has no intents dir on disk).
        let row = &v["agents"][0];
        assert_eq!(row["agent_id"], AGENT_A);
        // The owner-aggregate per-agent row carries NO `timeline` field
        // (that belongs to the single-agent `/api/agents/{id}/stats` view);
        // for a valid empty store its by_day + recipients are EMPTY, its
        // first/last confirmed are NULL, and its totals are all ZERO.
        assert!(
            row["confirmed_volume_by_day"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(row["recipients"].as_array().unwrap().is_empty());
        assert!(row["totals"]["last_confirmed_at"].is_null());
        assert!(row["totals"]["first_confirmed_at"].is_null());
        let confirmed = row["totals"]["confirmed_count"].as_u64().unwrap();
        assert_eq!(confirmed, 0, "confirmed_count expected 0");
        assert!(v["confirmed_volume_by_day"].as_array().unwrap().is_empty());
        assert_eq!(v["totals"]["total_intent_count"].as_u64().unwrap(), 0);
    }

    // -----------------------------------------------------------------------
    // 3) Single-agent owner isolation: foreign + missing + non-canonical
    //    all collapse to ONE indistinguishable 404 AGENT_NOT_FOUND.
    //    The foreign agent HAS a confirmed slot — the 404 proves no leak.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn single_agent_foreign_owner_returns_404_agent_not_found() {
        let root = mint_tree();
        let state = app_state_for(true); // OWNER session
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let path = format!("/api/agents/{AGENT_B}/stats");
        let cookie_owned = cookie.clone();
        let (status, body) =
            with_cwd(&root, drive_request(&router, &path, Some(&cookie_owned))).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 404, "expected 404 (foreign), got: {status}");
        assert!(
            body.contains("AGENT_NOT_FOUND"),
            "expected AGENT_NOT_FOUND, got: {body}"
        );
    }

    #[tokio::test]
    async fn single_agent_missing_id_returns_404_agent_not_found() {
        let root = mint_tree();
        let state = app_state_for(true); // OWNER session
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let missing = "99999999-9999-4999-8999-999999999999";
        let path = format!("/api/agents/{missing}/stats");
        let cookie_owned = cookie.clone();
        let (status, body) =
            with_cwd(&root, drive_request(&router, &path, Some(&cookie_owned))).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 404, "expected 404 (missing), got: {status}");
        assert!(
            body.contains("AGENT_NOT_FOUND"),
            "expected AGENT_NOT_FOUND, got: {body}"
        );
    }

    #[tokio::test]
    async fn single_agent_non_canonical_id_returns_404_agent_not_found() {
        let root = mint_tree();
        let state = app_state_for(true); // OWNER session
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let path = "/api/agents/not-a-canonical-uuid/stats";
        let cookie_owned = cookie.clone();
        let (status, body) =
            with_cwd(&root, drive_request(&router, path, Some(&cookie_owned))).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            status, 404,
            "expected 404 (non-canonical), got: {status} body={body}"
        );
        assert!(
            body.contains("AGENT_NOT_FOUND"),
            "expected AGENT_NOT_FOUND, got: {body}"
        );
    }

    // -----------------------------------------------------------------------
    // 4) Store corruption -> 500 AGENT_STORE_ERROR (single-agent surface:
    //    valid agent record, but a TRUSTED intent slot is garbage bytes:
    //    the scan must fail closed, not zero out).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn single_agent_store_corruption_returns_500_agent_store_error() {
        let root = mint_tree();
        // Add a CORRUPT trusted intent slot for the OWNER's OWN agent:
        let intents_dir = root.join("artifact/agent_payment_intents").join(AGENT_A);
        std::fs::create_dir_all(&intents_dir).unwrap();
        std::fs::write(
            intents_dir.join(format!("{}.json", hex_key("poison-1"))),
            "{broken-json-not-parseable",
        )
        .unwrap();
        let state = app_state_for(true);
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let path = format!("/api/agents/{AGENT_A}/stats");
        let cookie_owned = cookie.clone();
        let (status, body) =
            with_cwd(&root, drive_request(&router, &path, Some(&cookie_owned))).await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(status, 500, "expected 500, got: {status} body={body}");
        assert!(
            body.contains("AGENT_STORE_ERROR"),
            "expected AGENT_STORE_ERROR, got: {body}"
        );
    }

    // -----------------------------------------------------------------------
    // 5) Route order: `/api/agents/stats` hits the OWNER handler (not
    //    the parameterized `{id}` branch with id="stats"). The OWNER
    //    handler with a session returns a 200 with `agents_total`
    //    present — an output ONLY the OWNER route can produce (the
    //    `{id}` branch would 404: no agent named "stats" exists).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn route_literal_agent_stats_wins_over_parameterized_id() {
        let root = mint_tree();
        let state = app_state_for(true);
        let cookie = session_cookie(&state, true);
        let router = stats_router(state);
        let cookie_owned = cookie.clone();
        let (status, body) = with_cwd(&root, {
            let path = "/api/agents/stats";
            drive_request(&router, path, Some(&cookie_owned))
        })
        .await;

        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(
            status, 200,
            "expected the OWNER handler (200), got {status} body={body} — \
             the literal /api/agents/stats route must win over {{id}}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["agents_total"].as_u64(),
            Some(1),
            "expected agents_total=1 from the OWNER handler, got: {v}"
        );
    }
}
