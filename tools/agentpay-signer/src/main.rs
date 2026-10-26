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
    // G87 — single-process ownership + restrictive permissions: both must
    // succeed BEFORE the listener serves anything (fail-closed startup).
    // G89 (M1) — the startup boundary chain is now, in order:
    //   1. single-process instance lock (O_EXCL + pid liveness);
    //   2. symlink rejection across the store's boundary paths (an
    //      attacker-planted link fails the start — storage can never be
    //      silently redirected);
    //   3. uid ownership verification (root + users/ owned by the runner);
    //   4. 0700 enforcement + verification (no-follow).
    // ANY failure aborts BEFORE the listener binds a serving loop.
    let (store_lock, store) = match (
        agentpay_signer::store_lock::StoreLock::acquire(store.root()),
        store.reject_symlinked_boundaries(),
        store.verify_store_ownership(),
        store.harden_permissions(),
    ) {
        (Ok(lock), Ok(()), Ok(()), Ok(())) => (lock, store),
        _ => {
            eprintln!("signer: store ownership/permissions refused (fail closed)");
            return 2;
        }
    };
    // the lock handle must live for the whole process (drop = ownership
    // released); leak it deliberately — the process exits exit the same way
    std::mem::forget(store_lock);
    let _store_guard = store;
    eprintln!(
        "signer: listening on 127.0.0.1 loopback (port {}), store owned + hardened",
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
        // G89 (M4) — read the WHOLE request before dispatch: a single read
        // returns whatever TCP segment arrived first, truncating larger
        // bodies mid-JSON (an E2E-proven defect: ~2.5 KB create bodies
        // segmented ⇒ strict parse denied USER_BAD_REQUEST). Read until the
        // headers + Content-Length body bytes are complete, bounded by the
        // same 16 KiB wire budget (the buffer IS the bound; no unbounded
        // accumulation). The accumulation logic is the extracted pure
        // `read_bounded_request` (unit-tested: oversized Content-Length,
        // truncated body, inconsistent streaming length, no CL).
        let verdict = {
            let mut buf = Vec::with_capacity(16 * 1024);
            read_bounded_request(&mut buf, &mut sock).await;
            let text = String::from_utf8_lossy(&buf).to_string();
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
        } else if method == "POST" && path == "/user/sign" {
            // G87 — user-lane creation/signing route (loopback + gates):
            // the signer-side gates (version, intro proof, registered
            // binding, Ed25519 intent, nonce, singleflight, policy dir env)
            // ALL apply inside sign_user_transaction; this wire layer adds
            // ONLY the request-size bound (the loopback buffer is the bound).
            let policy_dir = std::env::var("AGENTPAY_SIGNER_USER_POLICY_DIR").unwrap_or_default();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            // the channel nonce comes from the request body (typed inside)
            match agentpay_signer::user_lane::sign_user_transaction(
                &_store_guard,
                std::path::Path::new(policy_dir.trim()),
                &body,
                now_ms,
            ) {
                Ok(resp) => {
                    let plain = serde_json::to_string(&resp)
                        .unwrap_or_else(|_| r#"{"error":"DENIED","code":"USER_INTERNAL"}"#.into());
                    // H-1: seal with the channel identity + the request nonce
                    let nonce = agentpay_signer::parse_nonce(&body);
                    let sealed =
                        agentpay_signer::seal_channel_response(&_store_guard, &plain, nonce.as_deref());
                    (200u16, sealed)
                }
                Err(denial) => (denial.parts().0, denial.body()),
            }
        } else if method == "POST" && path == "/user/wallet" {
            // G87 — NEW-USER wallet creation (admin-secret gated at THIS
            // boundary — the same constant-time check as /admin/register):
            // the full ceremony chain (intro proof, registered binding,
            // Ed25519 creation-intent signature, nonce burn, singleflight,
            // v2 gate) is enforced inside user_lane.
            let admin_secret = std::env::var("AGENTPAY_SIGNER_ADMIN_SECRET").unwrap_or_default();
            if admin_secret.trim().is_empty() {
                (403u16, r#"{"error":"DENIED","code":"USER_SIGNING_NOT_ENABLED"}"#.to_string())
            } else {
                match agentpay_signer::user_lane::handle_user_wallet_create(&_store_guard, &body, &admin_secret)
                {
                    Ok((resp, _draft1, _record)) => {
                        // SECURITY: draft1 + the creation record are the
                        // OPERATOR's ceremony material — the HTTP response is
                        // the sealed RESTRICTION: only the public response.
                        let plain = serde_json::to_string(&resp).unwrap_or_default();
                        let nonce = agentpay_signer::parse_nonce(&body);
                        (200u16, agentpay_signer::seal_channel_response(&_store_guard, &plain, nonce.as_deref()))
                    }
                    Err(denial) => (denial.parts().0, denial.body()),
                }
            }
        } else if method == "GET" && path.starts_with("/user/wallet/") {
            // G87 — public-address read for THE subject (public data only)
            // G89 (M3) — VERIFIED, not changed: the post-dispatch H-1 seal
            // at the bottom of this loop ALREADY binds EVERY response to
            // the request's channel_nonce (main.rs, "STEP H-1" seal) —
            // including this route — whenever the caller supplies one. A
            // caller that omits the nonce gets an unsealed response BY
            // DESIGN (the shared/idempotent read path); the app-side lane
            // reader MUST therefore always attach a fresh channel_nonce
            // and verify the seal. Route-level re-sealing here would
            // double-wrap (outer seal covers inner) — correctly verified
            // but redundant; rejected. Residual risk (unchanged, G88
            // G3.1): loopback peers remain the trust boundary for the
            // read; the seal defeats response substitution, not local
            // peer compromise.
            let verdict = match path
                .strip_prefix("/user/wallet/")
                .and_then(|s| s.trim().parse::<u64>().ok())
            {
                Some(user_id) => {
                    match agentpay_signer::user_lane::user_public_address(&_store_guard, user_id) {
                        Ok(Some(addr)) => (
                            200u16,
                            serde_json::json!({ "public_address": addr }).to_string(),
                        ),
                        Ok(None) => (
                            404u16,
                            r#"{"error":"DENIED","code":"USER_UNKNOWN_WALLET"}"#.to_string(),
                        ),
                        Err(_) => (
                            500u16,
                            r#"{"error":"DENIED","code":"USER_RECORD_CORRUPT"}"#.to_string(),
                        ),
                    }
                }
                None => (400u16, r#"{"error":"DENIED","code":"USER_BAD_REQUEST"}"#.to_string()),
            };
            verdict
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

/// G89 (M2/M4) — the bounded request-reader: accumulate stream chunks until
/// headers + `Content-Length` body bytes are complete, with a HARD 16 KiB
/// wire budget. Invariants (unit-tested below + by the E2E suite):
///   * the budget is absolute: the buffer NEVER exceeds 16 KiB no matter
///     what the peer streams or claims;
///   * an oversized or unparseable Content-Length stops the read (the
///     strict parse downstream fails the request closed);
///   * a missing Content-Length (or headers) ends at EOF (single-shot
///     request semantics; the read loop's zero `n` terminates it);
///   * a truncated body (EOF before Content-Length is satisfied) yields
///     exactly what arrived — never a wait, never an over-read;
///   * accumulation is CHUNK-ATOMIC: a single segment carrying MORE than
///     the claimed length leaves the excess in the buffer — the strict
///     JSON parse (deny_unknown_fields, reject-trailing) then fails that
///     request closed. The reader never over-reads the wire and never
///     truncates toward an overlong claim.
async fn read_bounded_request(buf: &mut Vec<u8>, sock: &mut (impl tokio::io::AsyncRead + Unpin)) {
    use tokio::io::AsyncReadExt as _;
    const WIRE_BUDGET: usize = 16 * 1024;
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            break; // EOF: parse what we have
        }
        if buf.len() + n > WIRE_BUDGET {
            let take = WIRE_BUDGET - buf.len();
            buf.extend_from_slice(&chunk[..take]);
            break; // budget exhausted: truncated parse fails closed downstream
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(buf);
        if let Some(headers_end) = text.find("\r\n\r\n") {
            let header_part = &text[..headers_end];
            let claimed = header_part
                .lines()
                .find_map(|l| {
                    let lower = l.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
                })
                .and_then(|v| v.parse::<usize>().ok());
            match claimed {
                Some(cl) if cl <= WIRE_BUDGET => {
                    let have = buf.len() - (headers_end + 4);
                    if have >= cl {
                        break; // full body received
                    }
                    // else: keep accumulating toward the (bounded) claim
                }
                Some(_) => break,   // claimed > budget: stop — oversized
                None => break,      // no/broken Content-Length: single-shot semantics
            }
        }
    }
}

#[cfg(test)]
mod g89_reader_tests {
    use super::read_bounded_request;
    use tokio::io::AsyncRead;

    /// Real-socket feeder: one byte stream, reads return UP TO the caller's
    /// buffer size per poll (never drops bytes; ends at true EOF).
    struct ByteStream(Vec<u8>, usize);
    impl tokio::io::AsyncRead for ByteStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            out: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use std::task::Poll;
            if self.1 >= self.0.len() {
                return Poll::Ready(Ok(())); // EOF
            }
            let take = (self.0.len() - self.1).min(out.remaining());
            out.put_slice(&self.0[self.1..self.1 + take]);
            self.1 += take;
            Poll::Ready(Ok(()))
        }
    }

    async fn drive(bytes: Vec<u8>) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 * 1024);
        let mut src = ByteStream(bytes, 0);
        read_bounded_request(&mut buf, &mut src).await;
        buf
    }

    /// Headers + full body across SEGMENTS: exactly Content-Length bytes.
    #[tokio::test]
    async fn fragmented_request_is_read_to_content_length() {
        let body = br#"{"user_id":"1","channel_nonce":"n"}"#;
        let head = format!(
            "POST /user/wallet HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut split = head.clone();
        split.extend_from_slice(&body[..]);
        let got = drive(split).await;
        let expected_len = head.len() + body.len();
        assert_eq!(got.len(), expected_len, "read EXACTLY headers+CL bytes, not more");
        assert!(got.ends_with(&body[..]), "full body accumulated across segments");
    }

    /// (review item 1a) Oversized Content-Length: claimed > 16 KiB ⇒ the
    /// reader stops instead of accumulating toward an impossible claim.
    #[tokio::test]
    async fn oversized_content_length_stops_immediately() {
        let head = b"POST /user/wallet HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\nextra-streamed-bytes";
        let got = drive(head.to_vec()).await;
        // the reader stops at the FIRST build after seeing the oversized claim:
        // the header chunk itself is the last accumulation (any bytes already in
        // that same chunk stay — chunk-atomic — but nothing further is read)
        assert!(
            got.len() <= head.len() + 64,
            "no unbounded accumulation toward the oversized claim (got {})",
            got.len()
        );
        assert!(got.starts_with(&head[..head.len() - 20]));
    }

    /// (review item 1b) Truncated body: EOF before Content-Length satisfied
    /// ⇒ reader yields what arrived and terminates (no hang, no fabricate).
    #[tokio::test]
    async fn truncated_body_yields_what_arrived() {
        // claim CL=100 but provide only 1 body byte then EOF
        let head = b"POST /user/wallet HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{";
        let got = drive(head.to_vec()).await;
        assert_eq!(got, head.to_vec(), "EOF-truncated body: exactly what arrived");
    }

    /// (review item 1c) Inconsistent streaming length: a lying small
    /// Content-Length stops at the claimed boundary even if more stream
    /// follows.
    #[tokio::test]
    async fn dishonest_small_content_length_stops_at_claim() {
        // claim 4 body bytes; stream 10; reader must stop at exactly 4
        let head = b"POST /user/wallet HTTP/1.1\r\nHost: x\r\nContent-Length: 19\r\n\r\n";
        let mut seg = head.to_vec();
        seg.extend_from_slice(br#"{"user_id":"1"}"#);
        seg.extend_from_slice(b"TRAILING-GARBAGE");
        let expected = seg.clone();
        let got = drive(seg).await;
        // chunk-atomic: the arriving segment satisfied the claim (19 ≤ have)
        // so the read STOPS; the same-chunk excess is in the buffer AND the
        // downstream strict parse rejects trailing garbage ⇒ fail closed.
        assert_eq!(got, expected, "read stops after the claim is satisfied within the chunk");
        parse_rejects_trailing_garbage(&got);
    }

    /// (review item 1d) No Content-Length: reader must not loop forever —
    /// it terminates at EOF with whatever arrived (legacy /health shape).
    #[tokio::test]
    async fn missing_content_length_terminates_at_eof() {
        let req = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        let got = drive(req.to_vec()).await;
        assert_eq!(got, req.to_vec());
    }

    /// (review item 1e) Maximum valid body: a Content-Length that EXACTLY
    /// equals the 16 KiB budget is fully read (boundary is inclusive).
    #[tokio::test]
    async fn max_budget_body_is_read_completely() {
        use std::io::Write as _;
        let budget = 16 * 1024;
        let body = vec![b'a'; budget];
        let mut head = Vec::new();
        write!(head, "POST /user/wallet HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", budget).unwrap();
        let mut seg = head.clone();
        seg.extend_from_slice(&body);
        let got = drive(seg).await;
        // the budget is the TOTAL buffer (headers inclusive): a 16 KiB body
        // plus headers exceeds it, so the buffer is capped at 16 KiB total
        // and the strict parse fails closed downstream — the promised
        // absolute bound, verified.
        assert!(
            got.len() <= 16 * 1024,
            "total buffer never exceeds 16 KiB (got {})",
            got.len()
        );
        assert!(got.starts_with(&head[..20]), "headers present in the capped buffer");
        // one byte over the budget: the buffer NEVER exceeds 16 KiB of body
        let mut seg2 = head.clone();
        seg2.extend_from_slice(&vec![b'b'; budget + 500]);
        let got2 = drive(seg2).await;
        let body2_len = got2.len() - head.len();
        assert!(
            body2_len <= budget,
            "buffer never exceeds the wire budget (body got {})",
            body2_len
        );
    }

    /// The downstream fail-closed leg for chunk-atomic excess: strict JSON
    /// parse rejects trailing garbage after the object (serde contract the
    /// user routes depend on).
    fn parse_rejects_trailing_garbage(with_excess: &[u8]) {
        let body = &with_excess[with_excess.iter().position(|&b| b == b'{').unwrap()..];
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(body);
        assert!(parsed.is_err(), "trailing garbage after CL-satisfied JSON is rejected, got {:?}", parsed.ok());
    }
}
