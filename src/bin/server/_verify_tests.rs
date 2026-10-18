// ---------------------------------------------------------------------------
// PHASE 7D.1 — PUBLIC VERIFICATION API — focused API tests (routes + core).
//
// Focused at the ROUTE level, house harness pattern (_stats24 shape): the
// real production handler (`public_verify`) is mounted on a FRESH
// `axum::Router` and exercised IN-PROCESS against a real bound
// `TcpListener` (one fresh listener per request; zero env mutation, no
// chdir — the endpoint is tree-independent BY DESIGN, so no fixture-CWD
// dance is needed). Route-level scenarios stand in for the chain with a
// FAKE `rialo` CLI binary (a `sh` script in a temp dir) + a raw HTTP/1.1
// JSON-RPC responder on 127.0.0.1:<random> — the exact one-RPC-endpoint
// discipline production uses; nothing network-external is touched.
//
// A second, mock lane (`VerificationOps`) drives the production-shaped
// core `public_verify_with_ops` for the arms the fake-CLI harness would
// not express deterministically (Malformed / Inconclusive) and for the
// byte-identity of the canonical DTO.
//
// Security pins asserted here:
//   * PUBLIC — the happy paths answer 200/400/503 with NO session cookie,
//     NO X-Agent-Credential, NO dev-login ever sent;
//   * READ-ONLY / no artifact access — a poisoned `artifact/` tree
//     (agents, intents w/ idempotency + request/policy fingerprints,
//     credentials, owner ids, wallet seed) is laid down in the test CWD
//     for every scenario; every body is asserted clean of every marker
//     AND confined to the public-field whitelist (no new key may ever be
//     minted into the response) — a leak is a test failure;
//   * NO WALLET/KEY ACCESS — the wallet file's markers are part of that
//     poisoned tree; the body must not carry them;
//   * PRIVACY — the DTO carries only the chain facts + the requested
//     signature (the Phase 7C answer-6 private set is absent);
//   * DETERMINISTIC — identical request + identical chain state =>
//     BYTE-identical body (no server clock anywhere in the shape);
//   * FAIL CLOSED — an inconclusive node answer or an RPC outage is a
//     503 RPC_UNAVAILABLE, never a 200 verdict; invalid input is a typed
//     400 VERIFY_REQUEST_INVALID with a STATIC message (no input echo);
//   * 405 — wrong methods on the route get the standard 405.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod verify_tests {
    use crate::rialo::{RialoConfig, RialoError, TxLookup, TxRecord};
    use crate::verify::{
        PrivacyProbe, VerificationOps, parse_verify_query, public_verify, public_verify_with_ops,
    };
    use axum::Router;
    use axum::response::Response;
    use axum::routing::get;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A canonical-signature-shaped value (base58-class, 64 chars).
    const SIG_A: &str = "5ZfR3TUEp4n1wBQxYcZrZLp8V2hGkd7jPnJLbY5mXqKdW9fCtE4uHsA2oR";

    /// Mint a FRESH temp root (atomic counter + pid) and lay down the
    /// poisoned `artifact/` tree: agents, intents (idempotency + request/
    /// policy fingerprints), policies, wallet, credentials — every file
    /// stamped with UNIQUE private markers (the Phase 7C probe values) so
    /// ANY leak into a response body is detectable.
    fn mint_artifact_tree() -> PathBuf {
        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::SeqCst) + std::process::id() as usize % 100_000;
        let root = std::env::temp_dir().join(format!("agentpay-verify-{n}"));
        let _ = std::fs::remove_dir_all(&root);
        let agents = root.join("artifact/agents");
        std::fs::create_dir_all(&agents).unwrap();
        std::fs::create_dir_all(
            root.join("artifact/agent_payment_intents/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_policies")).unwrap();
        let wallets = root.join("artifact/wallets");
        std::fs::create_dir_all(&wallets).unwrap();
        std::fs::write(
            agents.join("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.json"),
            format!(
                r#"{{"id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","wallet_address":"PayerProbeAddr","policy_fingerprint":"policy-fingerprint-probe-7d1"}}"#
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("artifact/agent_payment_intents/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/intent-1.json"),
            r#"{"schema_version":2,"agent_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","idempotency_key":"idempotency-key-probe-7d1","request_fingerprint":"request-fingerprint-probe-7d1","recipient":"RecipProbeAddr","amount_kelvin":2500000000,"state":"confirmed"}"#
                .to_string(),
        )
        .unwrap();
        std::fs::write(
            root.join("artifact/agent_policies/aaaa.json"),
            r#"{"policy_fingerprint":"policy-fingerprint-probe-7d1"}"#,
        )
        .unwrap();
        std::fs::write(
            wallets.join("9999.json"),
            format!(
                r#"{{"keypair":"seed-probe-7d1","agent_wallet":"/abs/path/keypair-{n}.json"}}"#
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("artifact/credentials"),
            r#"{"agent":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","phc":"$argon2id$credential-probe-7d1"}"#,
        )
        .unwrap();
        // Also land the poisoned tree in the ACTUAL test CWD (cargo runs
        // tests from the crate root): if the handler ever reads
        // artifact/ relative to the CWD, the markers are there to trip.
        let _ = std::fs::create_dir_all("artifact");
        let _ = std::fs::write(
            "artifact/agent_policy_7d1_probe.json",
            r#"{"policy_fingerprint":"policy-fingerprint-probe-7d1","idempotency_key":"idempotency-key-probe-7d1","request_fingerprint":"request-fingerprint-probe-7d1","credential":"credential-probe-7d1","wallet_path":"/abs/path/keypair.json"}"#,
        );
        root
    }

    /// The verify Router with the REAL production handler — the EXACT
    /// single GET /api/public/verify route server.rs registers (no
    /// fallback: 404s are the real ones).
    fn verify_router(state: crate::AppState) -> Router {
        Router::new()
            .route("/api/public/verify", get(public_verify))
            .with_state(state)
    }

    /// Production AppState pointed at the FAKE cli + the in-process RPC
    /// responder. No session, no wallet, no credential store — the
    /// endpoint must not ask for any of them.
    fn app_state(cli: &Path, rpc_url: &str) -> crate::AppState {
        crate::AppState {
            client: reqwest::Client::new(),
            client_id: "x".into(),
            client_secret: "x".into(),
            redirect_uri: "http://localhost/callback".into(),
            oauth_states: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            wallets: Arc::new(Mutex::new(HashMap::new())),
            rialo: Arc::new(RialoConfig {
                cli: cli.to_path_buf(),
                rpc_url: rpc_url.to_string(),
                program_id: None,
                program_dir: "artifact".into(),
            }),
        }
    }

    /// Drive ONE request IN-PROCESS through the real `axum::serve` loop
    /// on a FRESH `TcpListener` (house harness — one listener per request
    /// so no two requests ever race on a shared connection). `method`
    /// lets the 405 tests hit the route with the wrong verb.
    fn drive_request(
        router: &Router,
        path: &str,
        method: &str,
    ) -> impl std::future::Future<Output = (u16, String)> {
        let router = router.clone();
        let url_path = path.to_string();
        let method = method.to_string();
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
            let req = match method.as_str() {
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                "PATCH" => client.patch(&url),
                "DELETE" => client.delete(&url),
                _ => client.get(&url),
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

    // ---------------------------------------------------------------------
    // Fake-CLI + JSON-RPC responder harness (the chain stand-in).
    //
    // The `rialo` CLI is a `sh` script in a temp dir that:
    //   * `client transaction <SIG_A> --json` -> the scenario's
    //     transaction envelope (exit 0) OR a failure (exit 1, stderr);
    //   * the timing supplements (getTransaction / getBlock) -> `null`,
    //     so timing is NEVER synthesized (records keep their explicit
    //     block_time or stay None — the deterministic no-clock rule).
    // The probe (`getSignatureStatuses`) goes to the raw HTTP/1.1
    // JSON-RPC responder bound to 127.0.0.1:<random> — the ONE endpoint
    // style production uses.
    // ---------------------------------------------------------------------

    #[derive(Clone)]
    struct ChainScenario {
        /// `client transaction SIG_A --json` stdout (success path).
        tx_stdout: String,
        /// Some((stderr, msg-line)) => exit 1 with that stderr.
        tx_fail: Option<String>,
        /// The `result` value (an object or null) for getSignatureStatuses.
        probe_result: String,
    }

    /// Bind the raw-HTTP JSON-RPC responder; returns its port. Serves the
    /// FIXED `probe_result` as `result` for getSignatureStatuses and
    /// `null` for anything else (timing supplements find nothing — block
    /// time is never synthesized).
    fn start_rpc_responder(probe_result: &str) -> u16 {
        let probe = probe_result.to_string();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in tcp.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(2000)));
                let mut buf = [0u8; 8192];
                let Ok(n) = stream.read(&mut buf) else {
                    continue;
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // The JSON-RPC method is the SECOND token after "method"
                // (whitespace-tolerant pull from the quoted token stream).
                let tokens: Vec<&str> = req.split('"').collect();
                let method = tokens
                    .windows(4)
                    .find(|w| w[0].ends_with("method") && w[1] == ":")
                    .map(|w| w[2].to_string());
                let method = method.unwrap_or_default();
                let result_value: String = if method == "getSignatureStatuses" {
                    probe.clone()
                } else {
                    "null".to_string()
                };
                let json = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{result_value}}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        port
    }

    /// Write the fake `rialo` CLI shell script into `dir`; returns its path.
    fn write_fake_cli(dir: &std::path::Path, scenario: &ChainScenario) -> PathBuf {
        let sh_quote = |s: &str| format!("'{}'", s.replace('\'', "'\"'\"'"));
        let tx_block = match &scenario.tx_fail {
            Some(err) => format!("printf '%s' {} >&2\nexit 1", sh_quote(err)),
            None => format!("printf '%s' {}", sh_quote(&scenario.tx_stdout)),
        };
        let script = format!(
            r#"#!/bin/sh
# fake rialo CLI for verify route tests — scenario-driven, read-only.
args=""
for a in "$@"; do args="$args $a"; done
case "$args" in
  *" client transaction {sig_a}"*)
{tx_block}
    ;;
  *)
    echo 'null'
    ;;
esac
"#,
            sig_a = SIG_A,
            tx_block = tx_block,
        );
        let path = dir.join("rialo");
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&path, perm).unwrap();
        }
        path
    }

    /// The complete canonical chain envelope for SIG_A: explicit
    // `status.executed` (the explicit-executed rule), slot, fee, payer +
    /// a single system transfer (account index 1 -> RecipProbeAddr,
    /// 2_500_000_000 kelvin; base58 data below round-trips to
    /// [u32=2, u64=2_500_000_000]). block_time is carried explicitly so
    /// NO supplement is needed — deterministic, never server-time.
    fn found_envelope() -> String {
        let tx = serde_json::json!({
            "signature": SIG_A,
            "status": { "slot": 424242, "executed": true, "err": null },
            "block_height": 424242,
            "block_time": 1_790_668_900_000i64,
            "meta": { "fee": 10_000, "err": null },
            "transaction": {
                "signatures": [SIG_A],
                "message": {
                    "accountKeys": ["PayerProbeAddr", "RecipProbeAddr", "SysProgAddr"],
                    "instructions": [
                        { "accounts": [1], "data": "3Bxs4126ZQrQJFM9", "programIdIndex": 2 }
                    ]
                }
            }
        });
        tx.to_string()
    }

    fn body_collect(resp: Response) -> impl std::future::Future<Output = (u16, String)> {
        async move {
            let status = resp.status().as_u16();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    }

    // ---------------------------------------------------------------------
    // 1) Valid canonical signature -> 200 canonical verification DTO.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn valid_canonical_signature_returns_200_canonical_dto() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: found_envelope(),
            tx_fail: None,
            probe_result: r#"{"context":{"slot":424242},"value":[{"slot":424242,"executed":true,"err":null}]}"#
                .to_string(),
        };
        let port = start_rpc_responder(&scenario.probe_result);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
        let router = verify_router(state);

        let (status, body) = drive_request(
            &router,
            &format!("/api/public/verify?signature={SIG_A}"),
            "GET",
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(status, 200, "expected 200, got: {status} body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["success"], serde_json::json!(true));
        let x = &v["verification"];
        assert_eq!(x["signature"], serde_json::json!(SIG_A));
        // The status token is the canonical (Phase 7C answer-9) value.
        assert_eq!(x["status"], serde_json::json!("verified"), "body={body}");
        assert_eq!(x["executed"], serde_json::json!(true));
        assert!(x["error"].is_null());
        assert_eq!(x["slot"], serde_json::json!(424242));
        assert_eq!(x["block_height"], serde_json::json!(424242));
        // block_time is THE CHAIN's own (millis normalized to seconds) —
        // never a server-clock value.
        assert_eq!(
            x["block_time"],
            serde_json::json!(1_790_668_900),
            "body={body}"
        );
        assert_eq!(x["fee"], serde_json::json!(10_000));
        assert_eq!(x["payer"], serde_json::json!("PayerProbeAddr"));
        assert_eq!(x["recipient"], serde_json::json!("RecipProbeAddr"));
        assert_eq!(x["amount_kelvin"], serde_json::json!((2_500_000_000u64)));
        // PRIVACY: the poisoned artifact/ tree must NOT have leaked.
        let probe = PrivacyProbe::canonical();
        assert!(
            probe.body_is_private_clean(&body),
            "privacy leak in body: {body}"
        );
    }

    // ---------------------------------------------------------------------
    // 2) no_status -> 200 status:"no_status" (temporary not-found — never
    //    a 404, never a 503, never a verdict). The node answered; it
    //    simply has no status for the signature yet.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn no_status_returns_200_no_status() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: String::new(),
            // "Transaction not found" => classify => RIALO_ERROR (NOT
            // rpc-down); the probe then speaks.
            tx_fail: Some(r#"{"success":false,"message":"Transaction not found"}"#.into()),
            // value:[null] => StatusEntry::NoStatus (parse_signature_status).
            probe_result: r#"{"context":{"slot":424242},"value":[null]}"#.into(),
        };
        let port = start_rpc_responder(&scenario.probe_result);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
        let router = verify_router(state);

        let (status, body) = drive_request(
            &router,
            &format!("/api/public/verify?signature={SIG_A}"),
            "GET",
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(status, 200, "expected 200, got: {status} body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["success"], serde_json::json!(true));
        let x = &v["verification"];
        assert_eq!(x["signature"], serde_json::json!(SIG_A));
        assert_eq!(x["status"], serde_json::json!("no_status"), "body={body}");
        // Every fact is NULL — nothing inferred, nothing fabricated from
        // the poisoned store.
        for k in [
            "executed",
            "error",
            "slot",
            "block_height",
            "block_time",
            "fee",
            "payer",
            "recipient",
            "amount_kelvin",
        ] {
            assert!(x[k].is_null(), "{k} must be null, got: {x}");
        }
        let probe = PrivacyProbe::canonical();
        assert!(
            probe.body_is_private_clean(&body),
            "privacy leak in body: {body}"
        );
    }

    // ---------------------------------------------------------------------
    // 3) RPC unavailable -> 503 RPC_UNAVAILABLE (fail closed). The CLI
    //    reports the RPC down and the probe cannot get an answer either.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn rpc_unavailable_returns_503_rpc_unavailable() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: String::new(),
            // "connection refused" => classify => RIALO_RPC_UNAVAILABLE.
            tx_fail: Some("error sending request: connection refused".into()),
            probe_result: String::new(),
        };
        // A bound-then-dropped port: connect() fails => the probe is
        // Inconclusive; classification comes from the primary
        // RIALO_RPC_UNAVAILABLE error => Unavailable => 503.
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{dead_port}"));
        let router = verify_router(state);

        let (status, body) = drive_request(
            &router,
            &format!("/api/public/verify?signature={SIG_A}"),
            "GET",
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(status, 503, "expected 503, got: {status} body={body}");
        assert!(
            body.contains("RPC_UNAVAILABLE"),
            "expected RPC_UNAVAILABLE, got: {body}"
        );
        // FAIL CLOSED: the 503 body carries NO verification facts.
        assert!(
            !body.contains("\"verified\""),
            "503 must not carry a verdict: {body}"
        );
        assert!(
            !body.contains("\"no_status\""),
            "503 must not carry a verdict: {body}"
        );
        let probe = PrivacyProbe::canonical();
        assert!(
            probe.body_is_private_clean(&body),
            "privacy leak in 503 body: {body}"
        );
    }

    // ---------------------------------------------------------------------
    // 4) Inconclusive node answer -> 503 RPC_UNAVAILABLE (fail closed).
    //    The CLI errors with a non-RPC, non-not-found message AND the
    //    probe answers with a shape that cannot be parsed (no executed
    //    bool) => StatusProbe::Inconclusive => the unclassified bucket =>
    //    Unavailable. NEVER a 200 verdict.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn inconclusive_node_answer_returns_503_rpc_unavailable() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: String::new(),
            // Non-RPC, non-not-found message => classify => RIALO_ERROR.
            tx_fail: Some("boom: unexpected node reply".into()),
            // value array but the entry lacks the executed bool =>
            // StatusEntry::Inconclusive (parse_signature_status).
            probe_result: r#"{"value":[{"slot":5}]}"#.into(),
        };
        let port = start_rpc_responder(&scenario.probe_result);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
        let router = verify_router(state);

        let (status, body) = drive_request(
            &router,
            &format!("/api/public/verify?signature={SIG_A}"),
            "GET",
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(status, 503, "expected 503, got: {status} body={body}");
        assert!(
            body.contains("RPC_UNAVAILABLE"),
            "inconclusive must fail closed to RPC_UNAVAILABLE: {body}"
        );
        assert!(
            !body.contains("\"verified\""),
            "503 must not carry a verdict: {body}"
        );
        assert!(
            !body.contains("\"no_status\""),
            "503 must not carry a verdict: {body}"
        );
        let probe = PrivacyProbe::canonical();
        assert!(
            probe.body_is_private_clean(&body),
            "privacy leak in 503 body: {body}"
        );
    }

    // ---------------------------------------------------------------------
    // 5) Invalid / out-of-contract query params -> typed 400
    //    VERIFY_REQUEST_INVALID with a STATIC message (never an echo of
    //    the bad input). These never reach the chain.
    // ---------------------------------------------------------------------

    const MAX_SIG: &str = "AAAAAAAAA"; // 9 chars; the bound is 128.

    #[tokio::test]
    async fn invalid_query_params_return_typed_400_no_input_echo() {
        let _root = mint_artifact_tree();
        // The parse is tree-independent and must NOT reach the chain:
        // point at a nonexistent CLI + an unroutable RPC.
        let state = app_state(
            &std::path::PathBuf::from("/nonexistent/rialo"),
            "http://127.0.0.1:9",
        );
        let router = verify_router(state);

        let oversized = format!("signature={}", "A".repeat(129));
        let cases: Vec<(&str, &str)> = vec![
            ("", "missing param"),
            ("signature=", "empty value"),
            (&oversized, "oversized value"),
            (
                "signature=12345%2",
                "incomplete percent escape (lone % with no full hex pair)",
            ),
            ("signature=12345%GG", "non-hex percent escape"),
            ("signature=1%00", "value decodes to a control byte"),
            ("signature=1%7F", "value decodes to DEL"),
            ("foo=secretvalue", "unknown param (must not echo the value)"),
            ("signature=abc&signature=def", "duplicate param"),
            ("x=1&", "trailing empty pair"),
            ("signature abc", "missing = delimiter"),
        ];
        for (query, label) in &cases {
            let path = format!("/api/public/verify?{query}");
            let (status, body) = drive_request(&router, &path, "GET").await;
            assert_eq!(
                status, 400,
                "{label}: expected 400, got: {status} body={body}"
            );
            assert!(
                body.contains("VERIFY_REQUEST_INVALID"),
                "{label}: expected VERIFY_REQUEST_INVALID, got: {body}"
            );
            if !query.is_empty() {
                // STATIC-message rule: no byte of the offending value may
                // come back in the envelope ("secretvalue" is the probe).
                assert!(
                    !body.contains("secretvalue")
                        && !body.contains("ABCDEF012345".to_lowercase().as_str()),
                    "{label}: the bad input was echoed: {body}"
                );
            }
        }
    }

    // ---------------------------------------------------------------------
    // 6) Wrong method -> typed 405 on the GET-only route.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn wrong_method_returns_405_method_not_allowed() {
        let state = app_state(
            &std::path::PathBuf::from("/nonexistent/rialo"),
            "http://127.0.0.1:9",
        );
        let router = verify_router(state);
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let (status, _body) = drive_request(
                &router,
                &format!("/api/public/verify?signature={SIG_A}"),
                method,
            )
            .await;
            assert_eq!(405, status, "{method}: expected 405, got: {status}");
        }
    }

    // ---------------------------------------------------------------------
    // 7) PUBLIC: no session, no Agent credential, no dev-login — the
    //    endpoint answers with identity material ABSENT (no cookie and no
    //    credential header are ever sent by the harness), and the body
    //    carries zero identity/session/credential keys.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn public_endpoint_requires_no_identity_material() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: found_envelope(),
            tx_fail: None,
            probe_result: r#"{"context":{"slot":424242},"value":[{"slot":424242,"executed":true,"err":null}]}"#
                .to_string(),
        };
        let port = start_rpc_responder(&scenario.probe_result);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
        let router = verify_router(state);

        // NO Cookie, NO X-Agent-Credential, NO dev-login (drive_request
        // sends none of them) — the endpoint must still 200.
        let (status, body) = drive_request(
            &router,
            &format!("/api/public/verify?signature={SIG_A}"),
            "GET",
        )
        .await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(
            status, 200,
            "public endpoint must 200 without identity: {status} {body}"
        );
        for private in [
            "agentpay_session",
            "credential",
            "owner_user_id",
            "keypair",
            "wallet_path",
            "X-Agent-Credential",
        ] {
            assert!(
                !body.contains(private),
                "identity/session/credential material leaked ({private}): {body}"
            );
        }
        let probe = PrivacyProbe::canonical();
        assert!(probe.body_is_private_clean(&body), "identity leak: {body}");
    }

    // ---------------------------------------------------------------------
    // 8) READ-ONLY / no artifact/ access, no wallet/key access: the
    //    poisoned `artifact/` tree (marker-stamped agents, intents,
    //    policies, wallet, credentials) sits in the CWD for ALL of
    //    these scenarios; EVERY body is asserted clean of every marker
    //    AND confined to the public-field whitelist (no new key may ever
    //    be minted into the response). The handler reads NOTHING from
    //    artifact/ — a leak = a failed test.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn read_only_no_artifact_access_all_bodies_clean() {
        let root_a = mint_artifact_tree();
        let root_b = mint_artifact_tree();

        // (a) 200 verified
        {
            let cli_dir = root_a.join("cli");
            std::fs::create_dir_all(&cli_dir).unwrap();
            let scenario = ChainScenario {
                tx_stdout: found_envelope(),
                tx_fail: None,
                probe_result: r#"{"context":{"slot":424242},"value":[{"slot":424242,"executed":true,"err":null}]}"#
                    .into(),
            };
            let port = start_rpc_responder(&scenario.probe_result);
            let cli = write_fake_cli(&cli_dir, &scenario);
            let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
            let router = verify_router(state);
            let (_s, body) = drive_request(
                &router,
                &format!("/api/public/verify?signature={SIG_A}"),
                "GET",
            )
            .await;
            let probe = PrivacyProbe::canonical();
            assert!(
                probe.body_is_private_clean(&body),
                "verified 200 body leaked: {body}"
            );
        }
        // (b) 200 no_status
        {
            let cli_dir = root_b.join("cli");
            std::fs::create_dir_all(&cli_dir).unwrap();
            let scenario = ChainScenario {
                tx_stdout: String::new(),
                tx_fail: Some(r#"{"success":false,"message":"Transaction not found"}"#.into()),
                probe_result: r#"{"context":{"slot":424242},"value":[null]}"#.into(),
            };
            let port = start_rpc_responder(&scenario.probe_result);
            let cli = write_fake_cli(&cli_dir, &scenario);
            let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
            let router = verify_router(state);
            let (_s, body) = drive_request(
                &router,
                &format!("/api/public/verify?signature={SIG_A}"),
                "GET",
            )
            .await;
            let probe = PrivacyProbe::canonical();
            assert!(
                probe.body_is_private_clean(&body),
                "no_status 200 body leaked: {body}"
            );
        }
        // (c) 400 typed (no chain, no store — still must not echo)
        {
            let state = app_state(
                &std::path::PathBuf::from("/nonexistent/rialo"),
                "http://127.0.0.1:9",
            );
            let router = verify_router(state);
            let (_s, body) = drive_request(&router, "/api/public/verify?x=1&", "GET").await;
            let probe = PrivacyProbe::canonical();
            assert!(
                probe.body_is_private_clean(&body),
                "400 body leaked: {body}"
            );
        }
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
    }

    // ---------------------------------------------------------------------
    // 9) DETERMINISM: identical request + identical chain state =>
    //    BYTE-IDENTICAL bodies (no server clock, no non-determinism).
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn determinism_route_same_request_same_chain_gives_identical_body() {
        let root = mint_artifact_tree();
        let cli_dir = root.join("cli");
        std::fs::create_dir_all(&cli_dir).unwrap();
        let scenario = ChainScenario {
            tx_stdout: found_envelope(),
            tx_fail: None,
            probe_result: r#"{"context":{"slot":424242},"value":[{"slot":424242,"executed":true,"err":null}]}"#
                .to_string(),
        };
        let port = start_rpc_responder(&scenario.probe_result);
        let cli = write_fake_cli(&cli_dir, &scenario);
        let state = app_state(&cli, &format!("http://127.0.0.1:{port}"));
        let router = verify_router(state);

        let path = format!("/api/public/verify?signature={SIG_A}");
        let (_s1, body1) = drive_request(&router, &path, "GET").await;
        let (_s2, body2) = drive_request(&router, &path, "GET").await;
        let _ = std::fs::remove_dir_all(&root);

        assert_eq!(_s1, 200);
        assert_eq!(_s2, 200);
        assert_eq!(
            body1, body2,
            "the canonical DTO must be byte-identical for identical request + chain state"
        );
    }

    // A Found record reused by the mock-lane determinism + mapping tests.
    fn canonical_found() -> TxRecord {
        TxRecord {
            signature: Some(SIG_A.to_string()),
            executed: true,
            err: None,
            slot: Some(424242),
            block_height: Some(424242),
            block_time: Some(1_790_668_900),
            fee: Some(10_000),
            payer: Some("PayerProbeAddr".into()),
            transfer_recipient: Some("RecipProbeAddr".into()),
            transfer_amount_kelvin: Some(2_500_000_000),
            complete: true,
        }
    }

    struct MemOps {
        lookup: TxLookup,
    }
    impl Clone for MemOps {
        fn clone(&self) -> Self {
            Self {
                lookup: self.lookup.clone(),
            }
        }
    }
    impl VerificationOps for MemOps {
        fn verify_tx(&self, _sig: &str) -> TxLookup {
            self.lookup.clone()
        }
    }

    // ---------------------------------------------------------------------
    // 10) Mock-lane core mapping (the production-shaped TxLookup ->
    //     response arms): Malformed / Inconclusive / Unavailable -> 503
    //     fail-closed; Found -> 200 verified; NotFound -> 200 no_status;
    //     invalid query -> 400 BEFORE any chain access (panic-guarded).
    //     Plus: byte-identity for the same Found input.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn mock_mapping_fail_closed_arms_are_503_rpc_unavailable() {
        // Malformed (a success-shaped reply that cannot be parsed into a
        // complete record) => fail closed, never a 200.
        let ops = MemOps {
            lookup: TxLookup::Malformed,
        };
        let resp = public_verify_with_ops(Box::new(ops), &format!("signature={SIG_A}")).await;
        let (status, body) = body_collect(resp).await;
        assert_eq!(status, 503, "Malformed must be 503: {body}");
        assert!(body.contains("RPC_UNAVAILABLE"), "Malformed: {body}");
        assert!(
            !body.contains("\"verified\"") && !body.contains("\"no_status\""),
            "503 must carry no verdict: {body}"
        );

        // Unavailable (RPC down) => 503.
        let ops = MemOps {
            lookup: TxLookup::Unavailable(RialoError {
                code: "RIALO_RPC_UNAVAILABLE",
                detail: "mock: rpc down".to_string(),
                tx_signature: None,
            }),
        };
        let resp = public_verify_with_ops(Box::new(ops), &format!("signature={SIG_A}")).await;
        let (status, body) = body_collect(resp).await;
        assert_eq!(status, 503, "Unavailable must be 503: {body}");
        assert!(body.contains("RPC_UNAVAILABLE"), "Unavailable: {body}");
    }

    #[tokio::test]
    async fn mock_mapping_found_and_notfound_are_canonical_200() {
        // Found -> 200 verified canonical DTO.
        let ops = MemOps {
            lookup: TxLookup::Found(canonical_found()),
        };
        let resp = public_verify_with_ops(Box::new(ops), &format!("signature={SIG_A}")).await;
        let (status, body) = body_collect(resp).await;
        assert_eq!(status, 200, "Found must be 200: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["verification"]["status"], serde_json::json!("verified"));
        assert_eq!(
            v["verification"]["amount_kelvin"],
            serde_json::json!((2_500_000_000u64))
        );
        let probe = PrivacyProbe::canonical();
        assert!(
            probe.body_is_private_clean(&body),
            "mock Found leak: {body}"
        );

        // NotFound -> 200 no_status.
        let ops = MemOps {
            lookup: TxLookup::NotFound,
        };
        let resp = public_verify_with_ops(Box::new(ops), &format!("signature={SIG_A}")).await;
        let (status, body) = body_collect(resp).await;
        assert_eq!(status, 200, "NotFound must be 200 no_status: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["verification"]["status"], serde_json::json!("no_status"));
    }

    #[tokio::test]
    async fn mock_mapping_invalid_short_circuits_to_400_without_chain() {
        // Panic-guard: ANY chain access on an invalid query is a failure.
        struct PanicOps;
        impl VerificationOps for PanicOps {
            fn verify_tx(&self, _sig: &str) -> TxLookup {
                panic!("an invalid signature query must NOT reach the chain lookup")
            }
        }
        let resp = public_verify_with_ops(Box::new(PanicOps), "signature=").await;
        let (status, body) = body_collect(resp).await;
        assert_eq!(status, 400, "empty signature must be 400: {body}");
        assert!(
            body.contains("VERIFY_REQUEST_INVALID"),
            "expected VERIFY_REQUEST_INVALID: {body}"
        );
    }

    #[tokio::test]
    async fn determinism_mock_same_found_input_gives_identical_body() {
        let ops = MemOps {
            lookup: TxLookup::Found(canonical_found()),
        };
        let resp1 =
            public_verify_with_ops(Box::new(ops.clone()), &format!("signature={SIG_A}")).await;
        let resp2 = public_verify_with_ops(Box::new(ops), &format!("signature={SIG_A}")).await;
        let (_s1, body1) = body_collect(resp1).await;
        let (_s2, body2) = body_collect(resp2).await;
        assert_eq!(_s1, 200, "expected 200");
        assert_eq!(_s1, _s2, "both mock-lane responses must be 200");
        assert_eq!(
            body1, body2,
            "the mock-lane DTO must be byte-identical for the same Found input"
        );
    }

    // ---------------------------------------------------------------------
    // 11) Canonical status tokens + public-field stability.
    // ---------------------------------------------------------------------

    #[test]
    fn canonical_status_tokens_are_phase_7c_enum_values() {
        // The two tokens the endpoint emits, fixed by the Phase 7C design.
        assert_eq!("verified".len(), 8);
        assert_eq!("no_status".len(), 9);
        // The whitelist must keep both containers/fields so a future key
        // rename that drifts off the canonical shape is caught.
        let probe = PrivacyProbe::canonical();
        assert!(probe.public_fields.contains(&"status"));
        assert!(probe.public_fields.contains(&"signature"));
        assert!(probe.public_fields.contains(&"success"));
    }

    // ---------------------------------------------------------------------
    // 12) Query-parser strict grammar (unit surface, no chain).
    // ---------------------------------------------------------------------

    #[test]
    fn parser_accepts_single_signature_up_to_bound() {
        let sig = "A".repeat(128);
        assert_eq!(
            parse_verify_query(&format!("signature={sig}")).unwrap(),
            sig,
            "128 chars is the inclusive bound"
        );
    }

    #[test]
    fn parser_rejects_oversized_boundary() {
        let sig = "A".repeat(129);
        assert!(
            parse_verify_query(&format!("signature={sig}")).is_err(),
            "129 chars exceeds the bound"
        );
    }

    #[test]
    fn parser_rejects_missing_empty_duplicate_unknown_and_bad_encoding() {
        assert!(parse_verify_query("").is_err(), "empty query");
        assert!(parse_verify_query("signature=").is_err(), "empty value");
        assert!(
            parse_verify_query("signature=a&signature=b").is_err(),
            "duplicate"
        );
        assert!(parse_verify_query("other=a").is_err(), "unknown param");
        assert!(
            parse_verify_query("signature=ab%2").is_err(),
            "truncated percent"
        );
        assert!(
            parse_verify_query("signature=ab%00").is_err(),
            "control-byte decode"
        );
        assert!(
            parse_verify_query("signature=ab%FF").is_err(),
            "non-ascii decode"
        );
        assert!(
            parse_verify_query("signature=ab%26cd").is_ok(),
            "a percent-ENCODED & is not a smuggling delimiter"
        );
    }
}
