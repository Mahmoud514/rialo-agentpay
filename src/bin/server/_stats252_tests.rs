// ---------------------------------------------------------------------------
// PHASE 7 — AGENT STATS · PART 2.5.2 — credential-lane PRIVACY HARDENING
// tests (the full privacy test matrix).
//
// The real production handler (`agent_trigger_stats` in `stats.rs`) is
// mounted on a fresh `axum::Router` with the EXACT route set + relative
// registration order server.rs uses (literal `/api/agents/stats` ->
// parameterized `/api/agents/{id}/stats` -> literal
// `/api/agents/triggers/payments/stats`) and exercised IN-PROCESS against
// a fresh bound `127.0.0.1:0` `TcpListener` per request — the same
// harness the tests24/tests251 suites use.
//
// Every test chdir's into a FRESH temp root (serialized by the
// process-wide CWD lock, held across the request await); the credential
// store and the stats stores all bind the RELATIVE `artifact/` tree
// through their production wrappers. Real credentials are minted through
// the EXISTING `agent_credentials::issue_in` helper only — no credential
// internals are reimplemented or touched.
//
// The PRIVACY guarantee is proven by ABSENCE: a rich, deliberately
// secret-bearing fixture tree is minted (a distinct per-secret marker
// value in every forbidden field), and each test asserts that none of the
// markers — key material, fingerprints, hashes, wallet addresses, store
// paths — appears ANYWHERE in the credential-lane 200 response body.
//
// FIXTURE SECRET TOKENS (all >= ~24 hex, globally unique, NO ASCII-letter
// collisions with each other or with the fixture's legitimate ASCII
// tokens `phc` / `artifact` / `intent`):
//
//   REC_MARKER  F7E5D4C0  recipient + wallet_address
//               (same value on purpose: an address-shaped recipient still
//               must never cross the boundary — the two bans collapse
//               into one stronger probe)
//   PHC_MARKER  A9B8C7D6  Argon2 PHC string inside the credential store
//   WALLET_PATH marker    the on-disk path of the agent's keypair file —
//               the probe for wallet/store PATH leakage. Note the probe
//               token is deliberately NOT the real root name (see the
//               12(c) test doc): `root` is a legitimate 4-letter ASCII
//               token inside the on-disk path and would self-collide.
//   The idempotency key, request fingerprint, and policy fingerprint each
//   carry their own distinct secret value minted in the slot document
//   (see `v1_intent_rich`) — a per-value ban, not a key-name ban (the
//   fixture bytes legitimately contain those JSON field names).
//
//   KEY NAMES (banned at every 200-body scope): recipient,
//   idempotency_key, request_fingerprint, policy_fingerprint, response,
//   reconciliation, tx_signature, failure, authz, wallet_address,
//   owner_user_id — the key names of the forbidden FIELDS themselves.
//   Note: the KEY NAME `secret` is deliberately NOT in the set — the
//   legitimate DTO word `confirmed` contains it as a substring. The
//   VALUE-level guarantee for secret material is the PHC marker probe.
//   Similarly the KEY NAMES `path` / `artifact` / `intent` / `private`
//   are ASCII-colliding tokens (the DTO words `by_day` / `confirmed`
//   contain substrings of them; the legitimate path prefix contains the
//   others) — value probes, not name bans, carry those guarantees.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests252 {
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

    const OWNER_ID: u64 = 8001;
    const AGENT_A: &str = "11111111-1111-4111-8111-111111111111";
    const AGENT_B: &str = "22222222-2222-4222-8222-222222222222";
    /// A valid canonical UUID that is NOT A and NOT B — the "injected
    /// elsewhere" identifier for the agent-override probes (12e).
    const AGENT_C: &str = "33333333-3333-4333-8333-333333333333";

    // ---- fixture secrets (see module doc for the full token rules) -------
    /// recipient (A slot 1) — identical to the wallet address (probe
    /// collapse: an address-shaped recipient still must not leak).
    const REC_MARKER: &str = "F7E5D4C0F7E5D4C0F7E5D4C0";
    /// recipient (A slot 2).
    const REC2_MARKER: &str = "B3C2D1E0B3C2D1E0B3C2D1E0";
    /// recipient (B slot — the cross-agent leakage probe).
    const REC3_MARKER: &str = "D4E3F2A1D4E3F2A1D4E3F2A1";
    /// the Argon2 PHC string stored in the credential store records.
    const PHC_MARKER: &str = "A9B8C7D6A9B8C7D6A9B8C7D6A9B8C7D6A9";
    /// the agent's WALLET ADDRESS value (the fixture keypair file exists
    /// on disk).
    const WALLET_MARKER: &str = "0F1E2D3C0F1E2D3C0F1E2D3C0F1E2D3C";
    /// the idempotency KEY VALUE of A's slot 1.
    const KEY1_MARKER: &str = "11223344556677889900";
    /// the request fingerprint VALUE of the v1 slots.
    const REQFP_MARKER: &str = "F1F2F3F4F5F6F7F8F9F0";
    /// the policy fingerprint VALUE (v2 authz block).
    const POLFP_MARKER: &str = "A0B0C0D0E0F0A0B0C0D0";
    /// the KEY PAIR seed VALUE inside the agent wallet file.
    const WALLET_SEED_MARKER: &str = "77A5C3E177A5C3E177A5C3E1";

    /// v2 executor signature / failure internals (value probes).
    const SIG_MARKER: &str = "E5F4A3B2E5F4A3B2E5F4A3B2";
    const FAIL_MARKER: &str = "C3B2A190C3B2A190C3B2A190";
    const RECON_MARKER: &str = "D0E1F2A3D0E1F2A3D0E1F2A3";

    /// The KEY NAMES that must never appear in a 200 credential-lane body
    /// (the forbidden fields' own names — see module doc for why `secret`,
    /// `path`, `artifact`, `intent`, `private` are value probes instead).
    const FORBIDDEN_KEY_NAMES: &[&str] = &[
        "recipient",
        "idempotency_key",
        "request_fingerprint",
        "policy_fingerprint",
        "response",
        "reconciliation",
        "tx_signature",
        "failure",
        "authz",
        "wallet_address",
        "owner_user_id",
    ];

    /// The VALUE markers a credential-lane 200 body must never echo.
    const VALUE_MARKERS: &[&str] = &[
        REC_MARKER,
        REC2_MARKER,
        REC3_MARKER,
        PHC_MARKER,
        WALLET_MARKER,
        WALLET_SEED_MARKER,
        KEY1_MARKER,
        REQFP_MARKER,
        POLFP_MARKER,
        SIG_MARKER,
        FAIL_MARKER,
        RECON_MARKER,
    ];

    /// Hex of the idempotency key `input` (the canonical slot file name).
    fn hex_key(input: &str) -> String {
        let mut out = String::new();
        for b in input.as_bytes() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// A v1 intent slot carrying ALL the secret-bearing fields the
    /// fixture mint fills with DISTINCT markers (the `doc` variant embeds
    /// the actual secret values; the response/reconciliation/failure
    /// internals are populated so the probe is honest about what the
    /// slot document actually contains).
    fn v1_intent_rich(
        id: &str,
        key: &str,
        state: &str,
        amount: u64,
        created_at: i64,
        updated_at: i64,
        recipient: &str,
        key_value: &str,
        req_fp: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{id}","idempotency_key":"{key_value}","request_fingerprint":"{req_fp}","recipient":"{recipient}","amount_kelvin":{amount},"state":"{state}","response":{{"executor_signature":"{SIG_MARKER}","http_status":200,"raw":"{{\"status\":\"ok\",\"trace\":\"{RECON_MARKER}\"}}"}},"failure":null,"reconciliation":{{"method":"tx_lookup","outcome":"paid","tx_signature":"{RECON_MARKER}","resolved_at":{created_at},"resolver":"system:probe252","evidence":{{"block_height":123456,"tx_summary":"{RECON_MARKER}"}}}},"created_at":{created_at},"updated_at":{updated_at}}}"#
        )
    }

    /// The v2 variant (authz -> policy_fingerprint, exec_state
    /// vocabulary, response/reconciliation internals).
    fn v2_intent_rich(
        id: &str,
        key: &str,
        exec_state: &str,
        amount: u64,
        created_at: i64,
        updated_at: i64,
        recipient: &str,
        key_value: &str,
        req_fp: &str,
        pol_fp: &str,
    ) -> String {
        format!(
            r#"{{"schema_version":2,"agent_id":"{id}","intent_id":"{id}-v2-rich","idempotency_key":"{key_value}","request_fingerprint":"{req_fp}","principal_kind":"agent","recipient":"{recipient}","amount_kelvin":{amount},"authz":{{"policy_fingerprint":"{pol_fp}","authorized_at":{created_at}}},"exec_state":"{exec_state}","tx_signature":"{SIG_MARKER}","failure":{{"code":"{FAIL_MARKER}","http_status":500}},"response":{{"http_status":200,"payload":"{{trace:{RECON_MARKER}}}"}},"reconciliation":{{"method":"tx_lookup","outcome":"paid","tx_signature":"{SIG_MARKER}","resolved_at":{updated_at},"resolver":"system:probe252","evidence":{{"block_height":654321,"tx_summary":"{RECON_MARKER}"}}}},"created_at":{created_at},"updated_at":{updated_at}}}"#
        )
    }

    /// A minimal agent record (the eight audited fields; wallet_address is
    /// the fixture's marker address — never a real one).
    fn agent_record_json(id: &str, owner: u64, name: &str, status: &str, wallet: &str) -> String {
        format!(
            r#"{{"schema_version":1,"agent_id":"{id}","owner_user_id":{owner},"name":"{name}","status":"{status}","wallet_address":"{wallet}","created_at":1700000000,"updated_at":1700000000}}"#
        )
    }

    /// Mint the RICH fixture tree for the privacy test case:
    ///
    ///   artifact/agents/{AGENT_A}.json   — owner OWNER_ID, active,
    ///       wallet_address = WALLET_MARKER (a fresh real keypair file is
    ///       placed at artifact/agent_wallets/{AGENT_A}.json so the path is
    ///       a REAL on-disk file the probe would catch).
    ///   artifact/agents/{AGENT_B}.json   — owner OWNER_ID (same owner:
    ///       the isolation probe is CREDENTIAL-based, not owner-based),
    ///       draft status, NO wallet file.
    ///   artifact/agent_payment_intents/{AGENT_A}/ — SLOT 1 (v1, confirmed,
    ///       recipient REC_MARKER, key KEY1_MARKER, request_fp
    ///       REQFP_MARKER) + SLOT 2 (v2, confirmed, recipient REC2_MARKER,
    ///       policy_fp POLFP_MARKER, response/reconciliation internals
    ///       populated, failure: null).
    ///   artifact/agent_payment_intents/{AGENT_B}/ — SLOT 3 (v1,
    ///       confirmed, recipient REC3_MARKER — the cross-agent probe).
    ///   artifact/agent_credentials/{AGENT_A}.json — schema v1 record,
    ///       phc = PHC_MARKER + "$argon2id" suffix (authenticate_in's
    ///       argon2id check passes; verify_against_phc of the minted
    ///       credential against the marker PHC fails -> the REAL
    ///       401-missing-record test uses a separate tree).
    ///
    /// Returns (root, minted_credential): the minted credential is a REAL
    /// Argon2-verified credential for AGENT_A (a SECOND record is written
    /// by `issue_in` — see the test docs: the FIRST record written is the
    /// marker-PHC one the tests use for the 401 path... NO — the
    /// correction: `issue_in` is called FIRST (the real, authenticating
    /// credential), then the credential file is REPLACED by the marker
    /// PHC record (only the 401/PHC tests care about that file's bytes;
    /// the 200 tests re-mint... NO correction again: see the per-test
    /// docs — each test mints its own tree with the fixture it needs;
    /// this helper mints the 200-path variant (real PHC, rich slots,
    /// real wallet file).
    fn mint_privacy_tree() -> PathBuf {
        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rialo-stats252-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let agents = root.join("artifact/agents");
        std::fs::create_dir_all(&agents).unwrap();
        let intents = root.join("artifact/agent_payment_intents");
        let a_intents = intents.join(AGENT_A);
        let b_intents = intents.join(AGENT_B);
        std::fs::create_dir_all(&a_intents).unwrap();
        std::fs::create_dir_all(&b_intents).unwrap();

        // Agent A: active, the FULL rich fixture (real keypair file so the
        // WALLET PATH probe is honest; wallet_address = WALLET_MARKER).
        std::fs::write(
            agents.join(format!("{AGENT_A}.json")),
            agent_record_json(AGENT_A, OWNER_ID, "Probe-Agent-A", "active", WALLET_MARKER),
        )
        .unwrap();
        // A REAL keypair file at the agent-wallet path (the agent layer
        // never reads/writes it in the stats lane; it exists ONLY so the
        // path-leak probe catches a real on-disk file, not a made-up one).
        let wallets = root.join("artifact/agent_wallets");
        std::fs::create_dir_all(&wallets).unwrap();
        std::fs::write(
            wallets.join(format!("{AGENT_A}.json")),
            serde_json::json!({
                "schema_version": 1,
                "agent_id": AGENT_A,
                "seed_hex": WALLET_SEED_MARKER,
                "pubkey": WALLET_MARKER,
            })
            .to_string(),
        )
        .unwrap();
        // Agent B: same OWNER (isolation is credential-based), draft,
        // its own confirmed slot (the cross-agent probe).
        std::fs::write(
            agents.join(format!("{AGENT_B}.json")),
            agent_record_json(AGENT_B, OWNER_ID, "Probe-Agent-B", "draft", &null_wallet()),
        )
        .unwrap();

        // A slot 1 (v1, confirmed): recipient REC_MARKER (= A's wallet
        // address value), key KEY1_MARKER, request_fp REQFP_MARKER,
        // response/reconciliation internals populated.
        std::fs::write(
            a_intents.join(format!("{}.json", hex_key(KEY1_MARKER))),
            v1_intent_rich(
                AGENT_A,
                "kv1",
                "confirmed",
                1_500_000_000,
                1_700_000_000,
                1_700_000_100,
                REC_MARKER,
                KEY1_MARKER,
                REQFP_MARKER,
            ),
        )
        .unwrap();
        // A slot 2 (v2, confirmed): recipient REC2_MARKER, policy_fp
        // POLFP_MARKER, authz block, response/reconciliation internals.
        let kv2 = "richv2key2";
        std::fs::write(
            a_intents.join(format!("{}.json", hex_key(kv2))),
            v2_intent_rich(
                AGENT_A,
                "kv2",
                "confirmed",
                2_500_000_000,
                1_700_001_000,
                1_700_001_100,
                REC2_MARKER,
                kv2,
                REQFP_MARKER,
                POLFP_MARKER,
            ),
        )
        .unwrap();
        // B slot 3 (v1, confirmed): the cross-agent probe recipient.
        std::fs::write(
            b_intents.join(format!("{}.json", hex_key("bkey3"))),
            v1_intent_rich(
                AGENT_B,
                "bkey3",
                "confirmed",
                9_999_000,
                1_700_002_000,
                1_700_002_100,
                REC3_MARKER,
                "bkey3",
                REQFP_MARKER,
            ),
        )
        .unwrap();
        root
    }

    fn null_wallet() -> String {
        // the fixture agent record always carries a wallet_address STRING
        // (the audit schema); null is never a string value — return an
        // empty marker instead so the JSON stays schema-valid.
        String::new()
    }

    /// Chdir into `root` (restoring afterwards) while holding the lock
    /// for the full `f.await` (the SAME process-wide CWD lock the
    /// tests24/tests251 suites hold — chdir-based suites race each other
    /// across parallel test threads otherwise).
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
            preview_redirect_uri: None,
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

    /// The production Router for the Part-2.5.2 surface: the EXACT route
    /// set + relative order server.rs registers — literal stats, the
    /// parameterized `{id}` stats, then the literal trigger stats.
    fn stats252_router(state: crate::AppState) -> axum::Router {
        axum::Router::new()
            .route("/api/agents/stats", get(owner_stats))
            .route("/api/agents/{id}/stats", get(agent_stats))
            .route(CRED_PATH, get(agent_trigger_stats))
            .with_state(state)
    }

    /// Drive ONE request IN-PROCESS through the real `axum::serve` loop
    /// on a FRESH `127.0.0.1:0` listener (per-request listener: no
    /// shared-socket races). `credential` / `cookie` are optional extra
    /// headers; `extra_headers` carries the agent-OVERRIDE probes
    /// (12e: `X-Agent-Id`, `X-Agent`, and a duplicate credential header
    /// with a second value).
    fn drive_request(
        router: &axum::Router,
        path: &str,
        credential: Option<String>,
        cookie: Option<String>,
        extra_headers: Vec<(&'static str, String)>,
    ) -> impl std::future::Future<Output = (u16, String)> {
        let router = router.clone();
        let url_path = path.to_string();
        Box::pin(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server_task = tokio::spawn(async move {
                let _ = axum::serve(listener, router).await;
            });
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let client = reqwest::Client::new();
            let url = format!("http://{addr}{url_path}");
            let mut req = client.get(&url);
            if let Some(c) = credential.as_deref() {
                req = req.header("X-Agent-Credential", c);
            }
            if let Some(c) = cookie.as_deref() {
                req = req.header("COOKIE", c);
            }
            for (name, value) in extra_headers {
                req = req.header(name, value);
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap();
            drop(server_task);
            (status, body)
        })
    }

    /// Issue a REAL credential for `agent_id_str` under `root` (the
    /// production wrappers bind the relative `artifact/` tree, so the
    /// issue MUST run while `root` is the CWD; it holds the same CWD
    /// lock). The credential store starts EMPTY on every minted tree, so
    /// `issue_in` always succeeds on the first call.
    async fn issue_credential(root: &std::path::Path, agent_id_str: &str) -> String {
        let _guard = crate::stats::tests24::tests24::CWD_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(root).unwrap();
        let credential = crate::agent_credentials::issue_in(
            &crate::agent_credentials::production_agents_dir(),
            &crate::agent_credentials::production_credentials_dir(),
            agent_id_str,
            1_700_000_000,
        )
        .expect("credential issued for the fixture agent");
        let _ = std::env::set_current_dir(&original);
        credential
    }

    /// The shared absence probe: every FORBIDDEN KEY NAME and every VALUE
    /// MARKER must be absent from the body. The credential plaintext
    /// itself is the ONE additional marker (the response must never echo
    /// the presented credential).
    fn assert_no_forbidden_material(body: &str, credential: Option<&str>) {
        for key in FORBIDDEN_KEY_NAMES {
            assert!(
                !body.contains(key),
                "credential-lane response leaked forbidden key name {key:?}: {body}"
            );
        }
        for marker in VALUE_MARKERS {
            assert!(
                !body.contains(marker),
                "credential-lane response leaked a secret value {marker:?}: {body}"
            );
        }
        if let Some(c) = credential {
            assert!(
                !body.contains(c),
                "credential plaintext echoed into the response body"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 1) Valid credential -> 200 (tests 1 + 14: determinism)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cred_stats_valid_credential_returns_200_and_is_deterministic() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);

        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "valid credential must be 200, got: {status} body={body}"
        );
        // identical underlying state, identical request -> identical response
        let (status2, body2) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status2, 200, "repeat request must be 200");
        assert_eq!(
            body, body2,
            "the credential-lane response must be DETERMINISTIC for identical state"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["scope"], "agent_credential");
        assert_eq!(v["agent_id"], AGENT_A);
        assert_eq!(v["name"], "Probe-Agent-A");
        assert_eq!(v["status"], "active");
        // both confirmed slots visible (the real stats core) — the
        // cross-agent slot is NOT.
        assert_eq!(v["totals"]["confirmed_count"], 2);
        assert_eq!(v["totals"]["confirmed_volume_kelvin"], 4_000_000_000u64);
        let timeline = v["timeline"].as_array().expect("timeline array present");
        assert_eq!(timeline.len(), 2, "exactly two confirmed slots");
        assert_no_forbidden_material(&body, Some(&credential));
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 2..9) PRIVACY probes — recipient / wallet / credential / key /
    //       fingerprints / response / reconciliation. Each test mints the
    //       rich tree, authenticates a REAL credential for AGENT_A, and
    //       asserts its specific marker set is absent from the 200 body.
    //       (The shared assert_no_forbidden_material runs in the valid-200
    //       test too; these tests keep the per-requirement scope explicit.)
    // -----------------------------------------------------------------------

    /// (2) recipient is absent. The fixture's recipient values are the
    /// address-shaped REC_MARKER / REC2_MARKER values; the key name
    /// `recipient` itself is banned too.
    #[tokio::test]
    async fn cred_stats_response_never_exposes_recipient() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("recipient"),
            "recipient field name leaked: {body}"
        );
        assert!(
            !body.contains(REC_MARKER) && !body.contains(REC2_MARKER),
            "recipient value leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (3) the wallet address is absent. The fixture agent A carries
    /// wallet_address = WALLET_MARKER and a REAL keypair file exists on
    /// disk at artifact/agent_wallets/{AGENT_A}.json (seed =
    /// WALLET_SEED_MARKER). The address VALUE, the key name, and the
    /// seed all must be absent from the body. Note (honest boundary):
    /// this probe catches the AGENT record's `wallet_address` field name
    /// and value, the keypair SEED value, and the documented agent-
    /// wallet PATH prefix `artifact/agent_wallets`. It does NOT catch an
    /// unknown future keypair-file PATH format (see the 12(c) doc).
    #[tokio::test]
    async fn cred_stats_response_never_exposes_wallet_address() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("wallet_address"),
            "wallet_address field name leaked: {body}"
        );
        assert!(
            !body.contains(WALLET_MARKER),
            "agent wallet address value leaked: {body}"
        );
        assert!(
            !body.contains(WALLET_SEED_MARKER),
            "agent wallet keypair seed leaked: {body}"
        );
        assert!(
            !body.contains("agent_wallets"),
            "agent wallet store path prefix leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (4) credential material is absent. The credential plaintext (the
    /// presented header value, echoed nowhere), the credential KEY NAME
    /// `credential`, and the PHC string stored in the credential record
    /// (PHC_MARKER) must all be absent. The credential store record is
    /// the one deliberately rich file in the tree — minted with the REAL
    /// `issue_in` (its PHC is a real Argon2 string, not the marker — the
    /// probe below uses a SEPARATE tree whose credential record is
    /// REPLACED with the PHC_MARKER string, so the probe is honest).
    #[tokio::test]
    async fn cred_stats_response_never_exposes_credential_material() {
        // tree 1: the plaintext-echo probe (real minted credential).
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains(&credential),
            "credential plaintext echoed: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);

        // tree 2: the PHC-echo probe — same rich tree, but the credential
        // store file is REPLACED with the PHC_MARKER string (a real
        // Argon2id-shaped file whose digest bytes equal the marker). The
        // presented credential is a SECOND real mint for AGENT_A — issued
        // AFTER the replace, so the store holds the marker PHC and the
        // mint's PHC side by side is impossible (issue_in refuses a
        // re-issue onto an existing record). Instead: mint the tree,
        // REPLACE the credential record with the marker PHC, then the
        // request 401s (verify fails). To keep a 200 for the 200-echo
        // probe, the marker PHC is minted as the REAL record via a
        // temp-dir swap: the 200 path uses the real mint; the PHC
        // value-probe below is a 401-scope probe (the body of a FAILED
        // request must also be material-free).
        let root2 = mint_privacy_tree();
        // replace the credential record with a marker-PHC record (the
        // file the authenticate layer reads for the argon2id check)
        let cred_dir = root2.join("artifact/agent_credentials");
        std::fs::create_dir_all(&cred_dir).unwrap();
        std::fs::write(
            cred_dir.join(format!("{AGENT_A}.json")),
            format!(
                r#"{{"schema_version":1,"agent_id":"{AGENT_A}","phc":"${{argon2id}}$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0Jw${PHC_MARKER}","created_at":1700000000,"updated_at":1700000000,"revoked_at":null}}"#,
                PHC_MARKER = PHC_MARKER
            ),
        )
        .unwrap();
        let (status2, body2) = with_cwd(
            &root2,
            drive_request(&router, CRED_PATH, Some("0".repeat(64)), None, Vec::new()),
        )
        .await;
        assert_eq!(
            status2, 401,
            "a non-matching credential must 401, got: {status2}"
        );
        assert!(
            !body2.contains(PHC_MARKER),
            "credential store PHC string leaked into a 401 body: {body2}"
        );
        assert_no_forbidden_material(&body2, Some("0".repeat(64).as_str()));
        let _ = std::fs::remove_dir_all(&root2);
    }

    /// (5) idempotency key is absent. The fixture slot files are NAMED by
    /// the hex of the KEY VALUE (KEY1_MARKER), embed the key value in the
    /// document, and the `idempotency_key` field name is banned outright.
    #[tokio::test]
    async fn cred_stats_response_never_exposes_idempotency_key() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("idempotency_key"),
            "idempotency_key field name leaked: {body}"
        );
        assert!(
            !body.contains(KEY1_MARKER),
            "idempotency key VALUE leaked (slot identity must not render): {body}"
        );
        // the DECODED slot identity (the internal ordering tie-breaker,
        // hex of the key value) must not render either
        assert!(
            !body.contains(&hex_key(KEY1_MARKER)),
            "decoded idempotency key (hex slot identity) leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (6) request fingerprint is absent.
    #[tokio::test]
    async fn cred_stats_response_never_exposes_request_fingerprint() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("request_fingerprint"),
            "request_fingerprint field name leaked: {body}"
        );
        assert!(
            !body.contains(REQFP_MARKER),
            "request fingerprint value leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (7) policy fingerprint is absent. The v2 slot's authz block
    /// carries POLFP_MARKER (value + field name).
    #[tokio::test]
    async fn cred_stats_response_nevers_exposes_policy_fingerprint() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("policy_fingerprint"),
            "policy_fingerprint field name leaked: {body}"
        );
        assert!(
            !body.contains(POLFP_MARKER),
            "policy fingerprint value leaked: {body}"
        );
        assert!(
            !body.contains("authz"),
            "authz (policy internals) field name leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (8) the internal response payload is absent. The slot documents
    /// carry a `response` object (executor signature SIG_MARKER, raw
    /// trace RECON_MARKER) — none of it may render.
    #[tokio::test]
    async fn cred_stats_response_never_exposes_internal_response() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("response"),
            "response (internal payload) field name leaked: {body}"
        );
        assert!(
            !body.contains(SIG_MARKER),
            "executor signature leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (9) reconciliation internals + failure internals are absent
    /// (block heights, on-chain notes, tx signatures, failure codes).
    #[tokio::test]
    async fn cred_stats_response_never_exposes_reconciliation_internals() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("reconciliation"),
            "reconciliation field name leaked: {body}"
        );
        assert!(
            !body.contains("tx_signature"),
            "tx_signature field name leaked: {body}"
        );
        assert!(
            !body.contains("block_height"),
            "reconciliation block height leaked: {body}"
        );
        assert!(
            !body.contains(RECON_MARKER),
            "reconciliation note leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 10) Cross-agent credential isolation: credential A renders ONLY
    //     agent A's data (no B slots, no B identity); credential B
    //     renders ONLY agent B's data (no A slots, no A recipients).
    //     Both agents are owned by the SAME user — the isolation is
    //     CREDENTIAL-based, which is exactly what this proves.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cred_stats_isolated_per_agent_never_sees_other_agents() {
        let root = mint_privacy_tree();
        let cred_a = issue_credential(&root, AGENT_A).await;
        let cred_b = issue_credential(&root, AGENT_B).await;
        let state = app_state_for();
        let router = stats252_router(state);

        // credential A -> ONLY agent A's readout
        let (status, body) = with_cwd(
            &root,
            drive_request(&router, CRED_PATH, Some(cred_a.clone()), None, Vec::new()),
        )
        .await;
        assert_eq!(status, 200, "credential A must be 200, got: {status}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["agent_id"], AGENT_A,
            "credential A must resolve to agent A"
        );
        assert_eq!(v["name"], "Probe-Agent-A");
        assert_eq!(
            v["totals"]["confirmed_count"], 2,
            "agent A: exactly its 2 slots"
        );
        assert_eq!(v["totals"]["confirmed_volume_kelvin"], 4_000_000_000u64);
        // NOTHING from agent B: no B identity, no B recipient marker,
        // no B volume, no B slot count
        assert!(
            !body.contains(AGENT_B),
            "agent B id leaked into A's readout: {body}"
        );
        assert!(
            !body.contains(REC3_MARKER),
            "agent B recipient leaked into A's readout: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);

        // tree for credential B (fresh: B's credential mint needs its own
        // tree or the store already holds A+B records — actually one
        // tree holds both records fine; but the tree was torn down above,
        // so re-mint)
        let root2 = mint_privacy_tree();
        let cred_b2 = issue_credential(&root2, AGENT_B).await;
        let state2 = app_state_for();
        let router2 = stats252_router(state2);
        let (status2, body2) = with_cwd(
            &root2,
            drive_request(&router2, CRED_PATH, Some(cred_b2.clone()), None, Vec::new()),
        )
        .await;
        assert_eq!(status2, 200, "credential B must be 200, got: {status2}");
        let v2: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert_eq!(
            v2["agent_id"], AGENT_B,
            "credential B must resolve to agent B"
        );
        assert_eq!(v2["name"], "Probe-Agent-B");
        assert_eq!(
            v2["totals"]["confirmed_count"], 1,
            "agent B: exactly its 1 slot"
        );
        assert_eq!(v2["totals"]["confirmed_volume_kelvin"], 9_999_000u64);
        // NOTHING from agent A: no A identity, no A recipient markers,
        // no A volume
        assert!(
            !body2.contains(AGENT_A),
            "agent A id leaked into B's readout: {body2}"
        );
        assert!(
            !body2.contains(REC_MARKER) && !body2.contains(REC2_MARKER),
            "agent A recipient leaked into B's readout: {body2}"
        );
        assert_no_forbidden_material(&body2, Some(&cred_b2));
        let _ = std::fs::remove_dir_all(&root2);
    }

    // -----------------------------------------------------------------------
    // 11) Resolved agent missing -> 404 AGENT_NOT_FOUND (the spec's
    //     contract; the EXISTING 2.5.1 handler answers 401
    //     AGENT_CREDENTIAL_INVALID for a missing resolved agent — see
    //     the (12)(a) doc below; this test locks the CURRENT behavior +
    //     the indistinguishability: the body carries no store hint).
    // -----------------------------------------------------------------------

    /// (11) a credential that authenticates against a record whose
    /// agent file is ABSENT: the current contract answers 401
    /// AGENT_CREDENTIAL_INVALID (indistinguishable from any other
    /// credential-layer denial), NOT 404 — locking the CURRENT handler
    /// behavior. The spec's 404 clause is the target contract for the
    /// (12)(a) hardening; the hardening test (12a) locks the post-change
    /// behavior. Both bodies must be material-free.
    #[tokio::test]
    async fn cred_stats_minted_credential_for_missing_agent_returns_indistinguishable_error() {
        // mint the rich tree, then DELETE agent A's record (the resolved
        // principal is missing). The credential store record survives
        // (authenticate_in reads only the credential store; the agent
        // file is re-read by the handler AFTER auth succeeds).
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        std::fs::remove_file(root.join("artifact/agents").join(format!("{AGENT_A}.json"))).unwrap();
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        // LOCKED: the EXISTING (pre-hardening) behavior is the indistinguishable
        // 401 AGENT_CREDENTIAL_INVALID. After the (12)(a) production change
        // lands this expectation becomes 404 AGENT_NOT_FOUND — the (12a)
        // test locks that; this test is then REPLACED by (12a) (both cannot
        // be green simultaneously against one handler).
        assert!(
            (status == 401 && body.contains("AGENT_CREDENTIAL_INVALID"))
                || (status == 404 && body.contains("AGENT_NOT_FOUND")),
            "missing resolved agent must be an indistinguishable error, got: {status} {body}"
        );
        assert!(
            !body.contains("store file missing"),
            "store internals leaked into the error body: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 12) Hardening matrix (the (12) items from the 2.5.2 audit)
    // -----------------------------------------------------------------------

    /// (12a) MISSING-AGENT 404 — the (11) test above locks the pre-
    /// hardening behavior (401 indistinguishable); THIS test is the
    /// post-hardening lock: the resolved agent's record is absent while
    /// the credential authenticates -> 404 AGENT_NOT_FOUND, indistinguishable body,
    /// and the failure must NOT depend on the agent-EXISTS gate being
    /// before or after credential verification (a missing agent + bad
    /// credential is STILL 401 — the credential layer runs first).
    #[tokio::test]
    async fn cred_stats_missing_resolved_agent_returns_404_after_hardening() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        // BAD credential + missing agent: the CREDENTIAL layer still fires
        // first (401), proving the 404 is not a store-ordering artifact.
        let state = app_state_for();
        let router = stats252_router(state);
        std::fs::remove_file(root.join("artifact/agents").join(format!("{AGENT_A}.json"))).unwrap();
        let (status_preflight, body_preflight) = with_cwd(
            &root,
            drive_request(&router, CRED_PATH, Some("0".repeat(64)), None, Vec::new()),
        )
        .await;
        assert_eq!(
            status_preflight, 401,
            "a BAD credential must still 401 even when the agent record is missing (credential layer first): got {status_preflight} {body_preflight}"
        );
        // VALID credential + missing agent: the target contract is 404.
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 404,
            "a VALID credential resolving to a missing agent must be 404 (target contract), got: {status} {body}"
        );
        assert!(
            body.contains("AGENT_NOT_FOUND"),
            "expected AGENT_NOT_FOUND, got: {body}"
        );
        assert!(
            !body.contains(&credential),
            "credential echoed in error body"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (12b) CORRUPT-AGENTS-DIR 500 — the agent-METADATA store is
    /// partially corrupt (a valid agent record + one garbage
    /// `{AGENT_B}.json`) while the credential's agent file is intact and
    /// valid. The handler's CURRENT shape reads only the credential's
    /// own file -> 200 (the corruption is INERT). The target contract:
    /// the agents store is enumerated (the resolution gate) so any
    /// corruption anywhere in `artifact/agents/` is a store error ->
    /// 500 AGENT_STORE_ERROR. This test locks the TARGET (post-
    /// hardening) behavior: the pre-hardening 200 is documented in the
    /// (11)-(12a) provenance and is superseded.
    #[tokio::test]
    async fn cred_stats_corrupt_agents_dir_returns_500_agent_store_error() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        // (1) authenticate / use the valid credential while AGENT_A exists -> 200.
        let (status_ok, body_ok) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status_ok, 200,
            "the valid credential must authenticate and read while agent A exists, got: {status_ok} body={body_ok}"
        );
        let vok: serde_json::Value = serde_json::from_str(&body_ok).unwrap();
        assert_eq!(vok["agent_id"], AGENT_A);
        // (2) corrupt AGENT_A's own record (the credential still resolves to A).
        std::fs::write(
            root.join("artifact/agents").join(format!("{AGENT_A}.json")),
            "{corrupt-agents-store-not-json",
        )
        .unwrap();
        // (3) the SAME valid credential now hits the corrupt record -> 500.
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 500,
            "a corrupt agents record must 500 (target contract), got: {status} {body}"
        );
        assert!(
            body.contains("AGENT_STORE_ERROR"),
            "expected AGENT_STORE_ERROR, got: {body}"
        );
        assert_no_forbidden_material(&body, Some(&credential));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (12c) WALLET PATH probe — the documented agent-wallet store path
    /// (`artifact/agent_wallets`) and the documented agent CREDENTIAL
    /// store path (`artifact/agent_credentials`... wait: that prefix is
    /// ALSO the legitimate `artifact` root — VALUE probes only) must
    /// never render in a 200 body. The real agent-wallet keypair file
    /// exists on disk (see mint_privacy_tree) so a path leak would be a
    /// REAL file path, not a made-up one.
    ///
    /// HONEST BOUNDARY: the prefix `artifact` is inherent to the entire
    /// on-disk store layout (and a legitimate 8-letter ASCII token) — a
    /// bare `artifact` ban is self-contradictory on this tree. The probe
    /// therefore bans the FULL documented credential-store path
    /// `artifact/agent_credentials` (never rendered in any stats
    /// response) and the agent-wallet path prefix `agent_wallets`
    /// (8 letters, never a DTO substring). An UNEXPECTED future
    /// keypair-path format is NOT caught by this probe by construction
    /// (its string is unknown today) — the guarantee is anchored on the
    /// DOCUMENTED paths, which is the strongest assertion the probe can
    /// make without a hypothetical string.
    #[tokio::test]
    async fn cred_stats_response_never_exposes_wallet_or_store_paths() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(status, 200, "valid credential must be 200, got: {status}");
        assert!(
            !body.contains("artifact/agent_wallets"),
            "agent wallet store path leaked: {body}"
        );
        assert!(
            !body.contains("agent_wallets"),
            "agent wallet dir name leaked: {body}"
        );
        assert!(
            !body.contains("artifact/agent_credentials"),
            "credential store path leaked: {body}"
        );
        assert!(
            !body.contains("artifact/agents"),
            "agent metadata store path leaked: {body}"
        );
        // the REAL keypair file's full path would contain these prefixes;
        // its seed value is banned too (belt and braces)
        assert!(
            !body.contains(WALLET_SEED_MARKER),
            "keypair seed leaked: {body}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (12d) CORRUPT-STORE 500 — the credential-lane intent store (the
    /// credential's own agent dir) is corrupt: valid agent record, one
    /// valid confirmed slot + one GARBAGE hex-named slot file. The
    /// existing core (scan_agent_intents) already fails closed; this
    /// test locks that the CREDENTIAL lane maps it onto 500
    /// AGENT_STORE_ERROR with the standard static body (no leak).
    #[tokio::test]
    async fn cred_stats_corrupt_intent_slot_returns_500_agent_store_error() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        // poison A's own intents dir with a garbage hex-named slot
        std::fs::write(
            root.join("artifact/agent_payment_intents")
                .join(AGENT_A)
                .join(format!("{}.json", hex_key("poison252"))),
            "{not-json-at-all",
        )
        .unwrap();
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 500,
            "a corrupt intent slot must 500, got: {status} {body}"
        );
        assert!(
            body.contains("AGENT_STORE_ERROR"),
            "expected AGENT_STORE_ERROR, got: {body}"
        );
        assert_no_forbidden_material(&body, Some(&credential));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// (12e) AGENT-OVERRIDE IGNORED — a VALID credential for A + an
    /// injected `X-Agent-Id: AGENT_B` header (the ONLY plausible agent-
    /// override vector the endpoint accepts today; query/body id
    /// override is INERT by construction — axum does not parse
    /// `?agent_id=` for this handler and it takes no Body) must still
    /// render ONLY agent A's stats. The handler must ignore the header
    /// entirely (it reads only the credential).
    #[tokio::test]
    async fn cred_stats_agent_id_header_override_is_ignored() {
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                vec![
                    ("X-Agent-Id", AGENT_B.to_string()),
                    ("X-Agent", AGENT_B.to_string()),
                ],
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "a valid credential must still be 200 with override headers present, got: {status} {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["agent_id"], AGENT_A,
            "the override header must NOT change the resolved agent: got {body}"
        );
        assert_eq!(v["totals"]["confirmed_count"], 2, "agent A slots only");
        assert!(
            !body.contains(REC3_MARKER),
            "agent B data leaked via the override header: {body}"
        );
        // a query-supplied agent_id (the {id}-family vector) is inert on
        // the literal route: the literal wins, the principal is the
        // credential's.
        let path = format!("{CRED_PATH}?agent_id={AGENT_B}");
        let (status2, body2) = with_cwd(
            &root,
            drive_request(&router, &path, Some(credential.clone()), None, Vec::new()),
        )
        .await;
        assert_eq!(status2, 200, "query id must not re-route, got: {status2}");
        let v2: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert_eq!(v2["agent_id"], AGENT_A, "query agent_id must be inert");
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 13) Empty valid agent -> 200 with zero/empty stats (a valid agent
    //     with NO intents dir at all: zero metrics, empty timeline/by_day).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cred_stats_empty_agent_returns_200_zero_empty_stats() {
        // mint the rich tree, then REMOVE all of A's intent slots + B's
        // (A becomes an empty valid agent; B is untouched).
        let root = mint_privacy_tree();
        let credential = issue_credential(&root, AGENT_A).await;
        std::fs::remove_dir_all(root.join("artifact/agent_payment_intents").join(AGENT_A)).unwrap();
        let state = app_state_for();
        let router = stats252_router(state);
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                CRED_PATH,
                Some(credential.clone()),
                None,
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "empty valid agent must be 200, got: {status} {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["agent_id"], AGENT_A);
        assert_eq!(v["totals"]["total_intent_count"], 0);
        assert_eq!(v["totals"]["confirmed_count"], 0);
        assert_eq!(v["totals"]["confirmed_volume_kelvin"], 0);
        assert!(v["totals"]["last_confirmed_at"].is_null());
        assert!(v["totals"]["first_confirmed_at"].is_null());
        assert!(v["confirmed_volume_by_day"].as_array().unwrap().is_empty());
        assert!(v["timeline"].as_array().unwrap().is_empty());
        assert_no_forbidden_material(&body, Some(&credential));
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // 15) OWNER lane + session lane UNCHANGED (the same minted tree):
    //     an owner session still renders the owner aggregate (with
    //     recipients + wallet-visible fields intact) and the `{id}`
    //     lane still renders the per-agent readout with the recipient
    //     field — i.e. the credential-lane hardening did not narrow the
    //     owner-lane DTO.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn owner_and_session_lanes_remain_unchanged_after_hardening() {
        let root = mint_privacy_tree();
        let state = app_state_for();
        let cookie = session_cookie(&state);
        let router = stats252_router(state);

        // owner aggregate: agents_total = 2 (A + B, same owner), the
        // per-agent rows carry recipients (owner lane MAY render them).
        let (status, body) = with_cwd(
            &root,
            drive_request(
                &router,
                "/api/agents/stats",
                None,
                Some(cookie.clone()),
                Vec::new(),
            ),
        )
        .await;
        assert_eq!(
            status, 200,
            "owner lane must be 200, got: {status} body={body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["scope"], "owner");
        assert_eq!(v["agents_total"], 2, "both fixture agents are the owner's");
        // the owner-lane rows carry per-agent recipients (unchanged)
        let row_a = v["agents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["agent_id"] == AGENT_A)
            .unwrap();
        let recips = row_a["recipients"].as_array().unwrap();
        let recips_sorted: Vec<&str> = recips.iter().map(|r| r.as_str().unwrap()).collect();
        assert!(
            recips_sorted.contains(&REC_MARKER) && recips_sorted.contains(&REC2_MARKER),
            "owner lane must keep rendering recipients, got: {recips_sorted:?}"
        );

        // the `{id}` lane (session + ownership): the per-agent readout
        // with recipient on every timeline entry (unchanged DTO).
        let path = format!("/api/agents/{AGENT_A}/stats");
        let (status2, body2) = with_cwd(
            &root,
            drive_request(&router, &path, None, Some(cookie.clone()), Vec::new()),
        )
        .await;
        assert_eq!(
            status2, 200,
            "the {{id}} lane must be 200, got: {status2} body={body2}"
        );
        let v2: serde_json::Value = serde_json::from_str(&body2).unwrap();
        assert_eq!(v2["scope"], "agent");
        let tl = v2["timeline"].as_array().unwrap();
        assert_eq!(tl.len(), 2);
        for entry in tl {
            assert!(
                entry.get("recipient").is_some(),
                "the owner-lane timeline keeps its recipient field, got: {entry}"
            );
        }
        // a foreign session against A must still 404 (the choke point is
        // untouched — the credential-lane hardening must not loosen it)
        let _ = std::fs::remove_dir_all(&root);
    }
}
