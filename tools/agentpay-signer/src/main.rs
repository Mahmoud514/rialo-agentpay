//! agentpay-signer — the ISOLATED SIGNER process (PHASE 9 STEP 3 skeleton).
//!
//! Runtime behavior:
//!   * binds ONLY an explicit loopback endpoint (the endpoint type refuses
//!     anything else; the runtime re-checks the bound address),
//!   * serves exactly two paths: `GET /health` (minimal liveness) and
//!     `POST /sign` (validated, then DENIED — no signing capability exists
//!     in this step),
//!   * deny-by-default for everything else,
//!   * NO network egress: the process makes zero outbound connections —
//!     broadcast stays the app's responsibility (decision §12),
//!   * the store root comes ONLY from `AGENTPAY_SIGNER_STORE` (the signer's
//!     own domain; any `artifact`-rooted path is refused by the store type),
//!   * the listen endpoint comes ONLY from `AGENTPAY_SIGNER_ENDPOINT`
//!     (loopback-only, deterministic port),
//!   * no secret material in any log line (the process logs class labels
//!     only: method/path/status/bytes).
//!
//! Exit semantics are fail-closed: a missing/malformed env, a refused bind,
//! or an unavailable store aborts startup with a non-zero exit — the process
//! NEVER degrades into a permissive mode.

use agentpay_signer::{SignerEndpoint, SignerStore, SkeletonResponse, route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::sync::OnceLock;

/// The operator-supplied provisioning allow-list:
/// `AGENTPAY_SIGNER_PROVISION_AGENTS` = comma-separated `agent_id:auth_pubkey`.
/// The ONLY authoritative source of provisioning candidates the signer may
/// consult — the signer NEVER reads the app's store (`artifact/`).
fn provision_agents() -> &'static std::collections::HashMap<String, String> {
    static AGENTS: OnceLock<std::collections::HashMap<String, String>> = OnceLock::new();
    AGENTS.get_or_init(|| {
        std::env::var("AGENTPAY_SIGNER_PROVISION_AGENTS")
            .map(|v| {
                v.split(',')
                    .filter_map(|pair| {
                        let (id, pk) = pair.split_once(':')?;
                        Some((id.trim().to_string(), pk.trim().to_string()))
                    })
                    .collect::<std::collections::HashMap<String, String>>()
            })
            .unwrap_or_default()
    })
}

/// The live provisioning verdict: allow-list check + store work. Public
/// data only in the response; failures are typed and fieldless.

/// The REAL live sign chain (STEP 6 library, armed by
/// AGENTPAY_SIGNER_SIGNING_ENABLED=1 + a policy file at
/// AGENTPAY_SIGNER_POLICY). Returns None when unarmed — the deny-only
/// posture stands (fail-closed; the endpoint never silently gains signing).
fn live_sign_verdict(body: &[u8], store: &SignerStore) -> Option<(u16, String)> {
    use agentpay_signer::{SignDenial, signing_enabled};
    if !signing_enabled() {
        return None;
    }
    let Some(policy_path) = std::env::var("AGENTPAY_SIGNER_POLICY").ok() else {
        return Some((
            403u16,
            r#"{"error":"DENIED","code":"SIGNING_NOT_ENABLED"}"#.to_string(),
        ));
    };
    let Ok(policy_raw) = std::fs::read(&policy_path) else {
        return Some((
            403u16,
            r#"{"error":"DENIED","code":"SIGNING_NOT_ENABLED"}"#.to_string(),
        ));
    };
    let policy = match agentpay_signer::load_policy(&policy_raw) {
        Ok(p) => p,
        Err(_) => {
            return Some((
                403u16,
                r#"{"error":"DENIED","code":"SIGNING_NOT_ENABLED"}"#.to_string(),
            ));
        }
    };
    // parse the request into the STEP 5 semantic shape
    let parsed: Result<
        (
            uuid::Uuid,
            agentpay_signer::SemanticTransaction,
            String,
            Option<String>,
        ),
        (),
    > = (|| {
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| ())?;
        let agent_id = v
            .get("agent_id")
            .and_then(|x| x.as_str())
            .ok_or(())?
            .to_string();
        let auth_sig = v
            .get("auth_signature")
            .and_then(|x| x.get("signature"))
            .and_then(|x| x.as_str())
            .ok_or(())?
            .to_string();
        let tx_json = v.get("transaction").ok_or(())?;
        // the wire uses feePayer/recipient/amount_kelvin/validFrom/
        // configHashPrefix/occ (the documented schema); map to the library
        // SemanticTransaction
        let tx = agentpay_signer::SemanticTransaction {
            fee_payer: tx_json
                .get("feePayer")
                .and_then(|x| x.as_str())
                .ok_or(())?
                .to_string(),
            recipient: tx_json
                .get("recipient")
                .and_then(|x| x.as_str())
                .ok_or(())?
                .to_string(),
            amount_kelvin: tx_json
                .get("amount_kelvin")
                .and_then(|x| x.as_u64())
                .ok_or(())?,
            valid_from_ms: tx_json
                .get("validFrom")
                .and_then(|x| x.as_i64())
                .ok_or(())?,
            config_hash_prefix: tx_json
                .get("configHashPrefix")
                .and_then(|x| x.as_str())
                .ok_or(())?
                .to_string(),
            occ: tx_json
                .get("occ")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            canonical_hash: None,
            canonical_bytes: None,
        };
        let policy_ir = v
            .get("policy_ir")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());
        let uuid = uuid::Uuid::parse_str(&agent_id).map_err(|_| ())?;
        Ok((uuid, tx, auth_sig, policy_ir))
    })();
    let (agent_id, tx, auth_sig, policy_ir) = match parsed {
        Ok(p) => p,
        Err(()) => return Some((400u16, SignDenial::BadRequest.body())),
    };
    // STEP H-3: the independent policy IR cross-verification — the two
    // planes must agree BEFORE any policy evaluation or signing. When the
    // app supplied an IR, it is MANDATORY-matching. When it did not, the
    // signer refuses (the app-side policy store is part of the contract).
    if let Some(ir) = policy_ir.as_ref() {
        if let Err(d) = agentpay_signer::cross_verify_policy_ir(ir, &policy) {
            let wrapped = agentpay_signer::PreSignDenial::Policy(d);
            return Some((wrapped.status(), wrapped.body()));
        }
    } else {
        return Some((
            403u16,
            r#"{"error":"DENIED","code":"POLICY_IR_MISSING"}"#.to_string(),
        ));
    }
    match agentpay_signer::sign_transaction(store, &policy, &agent_id, &auth_sig, &tx, {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }) {
        Ok(envelope) => Some((200u16, serde_json::to_string(&envelope).unwrap())),
        Err(d) => Some((d.status(), d.body())),
    }
}

fn provision_verdict(body: &[u8], store: &SignerStore) -> (u16, String) {
    let req = match agentpay_signer::validate_provision_request(body) {
        Ok(r) => r,
        Err(d) => return (d.status(), d.body()),
    };
    let Ok(agent_id) = uuid::Uuid::parse_str(&req.agent_id) else {
        return (
            agentpay_signer::SignDenial::BadRequest.status(),
            agentpay_signer::SignDenial::BadRequest.body(),
        );
    };
    let auth = req.auth_pubkey.trim().to_string();
    // OPTION C: combined lookup (static allow-list + runtime registry + persisted wallets)
    match agentpay_signer::lookup_provision_auth(req.agent_id.trim(), &provision_agents(), store) {
        // exact match on BOTH fields (unknown agent / mismatched linkage
        // are indistinguishable denials to a non-authorized caller)
        Some(expected) if expected == auth => match store.provision_agent_wallet(&agent_id, &auth)
        {
            Ok(outcome) => {
                let (class, address) = match outcome {
                    agentpay_signer::ProvisionOutcome::Created { public_address } => {
                        ("created", public_address)
                    }
                    agentpay_signer::ProvisionOutcome::Recovered { public_address } => {
                        ("recovered", public_address)
                    }
                    agentpay_signer::ProvisionOutcome::Already { public_address } => {
                        ("already", public_address)
                    }
                };
                let body = serde_json::json!({
                    "success": true,
                    "outcome": class,
                    "public_address": address,
                })
                .to_string();
                (200, body)
            }
            Err(_) => (
                agentpay_signer::SignDenial::StoreUnavailable.status(),
                agentpay_signer::SignDenial::StoreUnavailable.body(),
            ),
        },
        Some(_) => (
            agentpay_signer::SignDenial::BadRequest.status(),
            agentpay_signer::SignDenial::BadRequest.body(),
        ),
        None => (
            404,
            r#"{"error":"DENIED","code":"UNKNOWN_AGENT"}"#.to_string(),
        ),
    }
}

/// OPTION C: Admin registration verdict — authenticated, loopback-only.
/// The admin secret MUST be configured via AGENTPAY_SIGNER_ADMIN_SECRET.
/// Registration is idempotent (same agent_id + auth_pubkey = success).
/// Conflicting registration (same agent_id, different auth_pubkey) = fail closed.
fn admin_register_verdict(body: &[u8], peer: &std::net::SocketAddr) -> (u16, String) {
    // Security boundary 1: loopback-only enforcement (defense in depth)
    if !peer.ip().is_loopback() {
        return (
            403u16,
            r#"{"error":"DENIED","code":"ADMIN_NOT_LOOPBACK"}"#.to_string(),
        );
    }

    // Security boundary 2: admin secret must be configured
    let admin_secret = match std::env::var("AGENTPAY_SIGNER_ADMIN_SECRET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            return (
                403u16,
                r#"{"error":"DENIED","code":"ADMIN_AUTH_NOT_CONFIGURED"}"#.to_string(),
            );
        }
    };

    // Parse the request body
    let req: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return (
                400u16,
                r#"{"error":"DENIED","code":"BAD_REQUEST"}"#.to_string(),
            );
        }
    };

    // Extract and validate fields
    let agent_id = req
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let auth_pubkey = req
        .get("auth_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let provided_secret = req
        .get("admin_secret")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Security boundary 3: constant-time secret comparison
    if !constant_time_eq(provided_secret, &admin_secret) {
        // Never reveal whether agent exists or not
        return (
            401u16,
            r#"{"error":"DENIED","code":"ADMIN_AUTH_FAILED"}"#.to_string(),
        );
    }

    // Validate UUID format
    if uuid::Uuid::parse_str(agent_id).is_err() {
        return (
            400u16,
            r#"{"error":"DENIED","code":"BAD_REQUEST"}"#.to_string(),
        );
    }

    // Validate auth_pubkey is non-empty base58-like
    if auth_pubkey.len() < 32 || auth_pubkey.len() > 44 {
        return (
            400u16,
            r#"{"error":"DENIED","code":"BAD_REQUEST"}"#.to_string(),
        );
    }

    // Perform registration (idempotent)
    match agentpay_signer::admin_register_agent(agent_id, auth_pubkey) {
        Ok(()) => (
            200u16,
            serde_json::json!({
                "success": true,
                "agent_id": agent_id,
                "registered": true,
            })
            .to_string(),
        ),
        Err(()) => (
            409u16,
            r#"{"error":"DENIED","code":"ADMIN_CONFLICTING_REGISTRATION"}"#.to_string(),
        ),
    }
}

/// Constant-time comparison to prevent timing attacks on the admin secret.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[tokio::main]
async fn main() {
    let code = run().await;
    std::process::exit(code);
}

async fn run() -> i32 {
    // --- configuration: fail-closed ---------------------------------------
    let Ok(endpoint_raw) = std::env::var("AGENTPAY_SIGNER_ENDPOINT") else {
        eprintln!("signer: AGENTPAY_SIGNER_ENDPOINT not set");
        return 2;
    };
    let endpoint = match SignerEndpoint::parse(&endpoint_raw) {
        Ok(ep) => ep,
        Err(_) => {
            eprintln!("signer: endpoint refused");
            return 2;
        }
    };
    let Ok(store_root) = std::env::var("AGENTPAY_SIGNER_STORE") else {
        eprintln!("signer: AGENTPAY_SIGNER_STORE not set");
        return 2;
    };
    let store = match SignerStore::open(std::path::Path::new(&store_root)) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("signer: store refused");
            return 2;
        }
    };

    // --- STEP H-2: binary trust pinning (fail-closed startup) ---------------
    // A configured pin that does not match the running binary refuses to
    // start: a substituted binary cannot become the signer.
    if agentpay_signer::verify_binary_pin().is_err() {
        eprintln!("signer: binary pin verification failed");
        return 2;
    }

    // --- bind: loopback-only, with a runtime double-check ------------------
    let listener = match tokio::net::TcpListener::bind(endpoint.socket_addr()).await {
        Ok(l) => l,
        Err(_) => {
            eprintln!("signer: bind refused");
            return 2;
        }
    };
    // defense-in-depth: the BOUND address must be the loopback we asked for
    let bound = match listener.local_addr() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("signer: bind verification failed");
            return 2;
        }
    };
    if !bound.ip().is_loopback() {
        eprintln!("signer: non-loopback bind refused");
        return 2;
    }

    // the store stays opened-and-owned for the signing step (the skeleton
    // only proves the boundary); reference it once so the ownership is real
    let _store_guard = store;
    eprintln!(
        "signer: listening on 127.0.0.1 loopback (port {}), store reserved",
        bound.port()
    );

    // --- serve: deny-by-default --------------------------------------------
    loop {
        let Ok((mut sock, peer)) = listener.accept().await else {
            eprintln!("signer: accept failed — shutting down fail-closed");
            return 1;
        };
        // defense-in-depth: only loopback peers are served
        if !peer.ip().is_loopback() {
            eprintln!("signer: non-loopback peer refused");
            continue;
        }
        let verdict = {
            let mut buf = vec![0u8; 16 * 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let mut parts = text.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            let body = text
                .split_once("\r\n\r\n")
                .map(|(_, b)| b.as_bytes().to_vec())
                .unwrap_or_default();
            (method, path.clone(), body, path)
        };
        let (method, path, body, _path_dbg) = verdict;
        let response_line = if method == "POST" && path == "/admin/register" {
            // OPTION C: Authenticated admin registration endpoint
            admin_register_verdict(&body, &peer)
        } else if method == "GET" && path.starts_with("/wallet/") {
            // STEP 4: the public wallet-address read (public data only; the
            // store-backed integrity check applies)
            match agentpay_signer::parse_wallet_read(&path) {
                Ok(agent_id) => match _store_guard.agent_public_address(&agent_id) {
                    Ok(Some(addr)) => (
                        200u16,
                        serde_json::json!({ "public_address": addr }).to_string(),
                    ),
                    Ok(None) => (
                        404u16,
                        r#"{"error":"DENIED","code":"UNKNOWN_AGENT"}"#.to_string(),
                    ),
                    Err(_) => (500u16, agentpay_signer::SignDenial::StoreUnavailable.body()),
                },
                Err(_) => (400u16, agentpay_signer::SignDenial::BadRequest.body()),
            }
        } else if method == "GET" && path == "/handshake" {
            // STEP H-2: the identity/digest handshake intercepts BEFORE
            // route(): a signed identity+digest exchange the adapter verifies
            // at startup (an unknown binary cannot present a valid channel
            // identity).
            let nonce = agentpay_signer::parse_nonce(&body).unwrap_or_default();
            match agentpay_signer::handshake_payload(&_store_guard, &nonce) {
                Ok((payload, sig, _pk)) => {
                    let mut obj: serde_json::Value =
                        serde_json::from_str(&payload).unwrap_or(serde_json::json!({}));
                    if let Some(o) = obj.as_object_mut() {
                        o.insert("signer_sig".to_string(), serde_json::json!(sig));
                    }
                    (200u16, obj.to_string())
                }
                Err(_) => (500u16, agentpay_signer::SignDenial::StoreUnavailable.body()),
            }
        } else {
            match route(&method, &path, &body) {
                SkeletonResponse::Health => (200u16, r#"{"status":"ok"}"#.to_string()),
                SkeletonResponse::AcceptedButNotImplemented(d) => {
                    // STEP 7: the REAL chain runs ONLY when the signing gate is
                    // armed AND a policy is configured; otherwise the historical
                    // deny-only response stands (fail-closed).
                    match live_sign_verdict(&body, &_store_guard) {
                        Some(verdict) => verdict,
                        None => (d.status(), d.body()),
                    }
                }
                SkeletonResponse::Denied(d) => (d.status(), d.body()),
                SkeletonResponse::Provisioned { .. } => {
                    // the router validated structure; the LIVE work happens here:
                    // re-parse (cheap), check the operator-supplied agent
                    // allow-list (the ONLY authoritative source the signer may
                    // consult — it NEVER reads the app's store), then provision.
                    provision_verdict(&body, &_store_guard)
                }
                SkeletonResponse::UnknownAgent => (
                    404u16,
                    r#"{"error":"DENIED","code":"UNKNOWN_AGENT"}"#.to_string(),
                ),
            }
        };
        let (status, payload) = response_line;
        // STEP H-1 (authenticated channel) / PHASE 10 ITEM 6: when the
        // request carried a channel nonce, the response is SEALED by the
        // single protocol function the signer's own tests exercise:
        // complete body (nonce included) → canonical serialization without
        // `signer_sig` → sign → attach `signer_sig`. Unsigned responses
        // (no nonce) are unchanged; the APP enforces presence and verifies
        // the identical canonical message.
        let request_nonce = agentpay_signer::parse_nonce(&body);
        let payload = agentpay_signer::seal_channel_response(&_store_guard, &payload, request_nonce.as_deref());
        // audit log line: class labels only — never a path with query, never
        // a body, never a secret
        eprintln!(
            "signer: {method} {path} -> {status} ({} bytes)",
            payload.len()
        );
        let head = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(payload.as_bytes()).await;
        let _ = sock.flush().await;
        let _ = sock.shutdown().await;
    }
}

// keep the store import meaningful for the skeleton: the store is opened at
// startup (reserved) — the signing step will use it. Silence the unused
// warning honestly by referencing the store root once.
#[allow(dead_code)]
fn _store_alive(store: &SignerStore) -> &std::path::Path {
    store.root()
}
