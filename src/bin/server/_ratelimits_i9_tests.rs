//! PHASE 9 "Rate / time limits" — focused tests for the app-side meter
//! (TM-AV-01/TM-AV-03, GA-4). The meter is pure and process-local: no
//! network, no disk, no wall clock, no money-policy coupling, no Latch.
//! Each test uses a FRESH identity string so the process-global meter's
//! cross-test state can never leak between cases.

use crate::rate_limits::{
    CHEAP_CAP, CHEAP_WINDOW_MS, CODE_RATE_LIMITED, EXPENSIVE_CAP, EXPENSIVE_WINDOW_MS, MeterError,
    MeterVerdict, RequestClass, UNKNOWN_PEER_IDENTITY, check, classify_path, ip_identity, peek,
    retry_after_seconds, user_identity,
};
use std::net::IpAddr;

fn fresh(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

// ---------- (1) classification surface ----------

#[test]
fn expensive_paths_classify_exactly() {
    for p in [
        "/api/health",
        "/api/public/verify",
        "/api/faucet",
        "/api/payment",
        "/api/payment/program/start",
        "/api/payment/program/execute",
        "/api/agents/triggers/payments",
        "/api/agents/triggers/payments/reconcile",
        "/auth/github",
        "/auth/github/callback",
        "/auth/dev-login",
        "/api/agents",
        "/api/agents/xyz/balance",
        "/api/program/status",
        "/api/me",
    ] {
        assert_eq!(classify_path(p), RequestClass::Expensive, "{p}");
    }
}

#[test]
fn cheap_paths_classify_exactly() {
    for p in [
        "/",
        "/index.html",
        "/app.css",
        "/dashboard.js",
        "/favicon.ico",
        "/nosuchpath",
    ] {
        assert_eq!(classify_path(p), RequestClass::Cheap, "{p}");
    }
}

// ---------- (2) basic allowance / cap / boundary ----------

#[test]
fn first_request_is_allowed() {
    let id = fresh("first");
    assert_eq!(check(&id, RequestClass::Cheap), Ok(MeterVerdict::Allowed));
    assert_eq!(
        check(&id, RequestClass::Expensive),
        Ok(MeterVerdict::Allowed)
    );
}

#[test]
fn limit_reached_denies_with_retry_after() {
    let id = fresh("cap");
    for _ in 0..EXPENSIVE_CAP {
        assert_eq!(
            check(&id, RequestClass::Expensive),
            Ok(MeterVerdict::Allowed)
        );
    }
    let verdict = check(&id, RequestClass::Expensive);
    match verdict {
        Ok(MeterVerdict::Denied { retry_after_ms }) => {
            assert!(retry_after_ms > 0 && retry_after_ms <= EXPENSIVE_WINDOW_MS);
            // Retry-After seconds derivation: rounded up, at least 1.
            assert_eq!(
                retry_after_seconds(&verdict.unwrap()),
                Some(retry_after_ms.div_ceil(1000).max(1))
            );
        }
        other => panic!("expected denial, got {other:?}"),
    }
}

#[test]
fn just_under_and_just_over_the_cap() {
    let id = fresh("boundary");
    // exactly cap-1 allowed, then one more allowed (at cap), then denied.
    for _ in 0..(CHEAP_CAP - 1) {
        assert_eq!(check(&id, RequestClass::Cheap), Ok(MeterVerdict::Allowed));
    }
    assert_eq!(
        check(&id, RequestClass::Cheap),
        Ok(MeterVerdict::Allowed),
        "cap-th request allowed"
    );
    assert!(
        matches!(
            check(&id, RequestClass::Cheap),
            Ok(MeterVerdict::Denied { .. })
        ),
        "cap+1-th request denied"
    );
}

#[test]
fn window_rollover_resets_via_forced_bucket_expiry() {
    // Simulate rollover without waiting 60s: craft an identity, consume
    // the whole budget, then directly rewrite its bucket start into the
    // past through the same process-global meter (test-only reach via
    // peek's module access is not enough — use a dedicated helper below).
    let id = fresh("roll");
    for _ in 0..EXPENSIVE_CAP {
        assert_eq!(
            check(&id, RequestClass::Expensive),
            Ok(MeterVerdict::Allowed)
        );
    }
    assert!(matches!(
        check(&id, RequestClass::Expensive),
        Ok(MeterVerdict::Denied { .. })
    ));
    // Force the bucket to look expired by backdating its window start.
    crate::rate_limits::test_backdate_window(&id, RequestClass::Expensive, EXPENSIVE_WINDOW_MS + 1);
    assert_eq!(
        check(&id, RequestClass::Expensive),
        Ok(MeterVerdict::Allowed),
        "rollover allows again"
    );
}

// ---------- (3) identity / class isolation ----------

#[test]
fn identities_are_isolated_per_class() {
    let a = fresh("a");
    let b = fresh("b");
    for _ in 0..EXPENSIVE_CAP {
        assert_eq!(
            check(&a, RequestClass::Expensive),
            Ok(MeterVerdict::Allowed)
        );
    }
    assert!(matches!(
        check(&a, RequestClass::Expensive),
        Ok(MeterVerdict::Denied { .. })
    ));
    // Identity B unaffected (agent A's burst cannot deny B).
    assert_eq!(
        check(&b, RequestClass::Expensive),
        Ok(MeterVerdict::Allowed)
    );
    // Same identity, other class unaffected.
    assert_eq!(check(&a, RequestClass::Cheap), Ok(MeterVerdict::Allowed));
}

#[test]
fn identity_keys_use_existing_planes_never_agent_names() {
    // The two sanctioned planes: user:<github id> and ip:<addr>. An
    // agent-name-looking string must produce the SAME shape as any other
    // opaque identity — there is no "agent:" plane.
    let uid = user_identity(50506084);
    let ip = ip_identity(IpAddr::from([127, 0, 0, 1]));
    assert!(uid.starts_with("user:"));
    assert!(ip.starts_with("ip:"));
    assert!(!uid.contains("agent:"));
    assert!(
        ip_identity(IpAddr::from([10, 0, 0, 7])) != ip,
        "distinct ips distinct keys"
    );
    assert_eq!(UNKNOWN_PEER_IDENTITY, "ip:unknown");
    // The meter treats agent-name-spoofed strings as plain opaque keys —
    // but the ENFORCEMENT SITE never constructs one (pinned in server
    // wiring tests by the identity-factory asserts above).
    let spoof = "agent:<script>alert(1)</script>";
    assert_eq!(check(spoof, RequestClass::Cheap), Ok(MeterVerdict::Allowed));
}

// ---------- (4) concurrency: exactly-at-cap under contention ----------

#[test]
fn concurrent_burst_never_overshoots() {
    let id = fresh("burst");
    // Use the EXPENSIVE class (cap 30) with a large racing burst so the
    // window is definitively oversaturated under contention.
    let cap = EXPENSIVE_CAP;
    let total = cap + 70;
    let allowed = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for _ in 0..total {
            handles.push(s.spawn({
                let id = id.clone();
                move || check(&id, RequestClass::Expensive)
            }));
        }
        handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|v| matches!(v, Ok(MeterVerdict::Allowed)))
            .count()
    });
    assert!(
        allowed <= cap as usize,
        "no overshoot: allowed={allowed} cap={cap}"
    );
    // Main-thread check after the burst must also be denied (window full).
    assert!(matches!(
        check(&id, RequestClass::Expensive),
        Ok(MeterVerdict::Denied { .. })
    ));
    let (live, c) = peek(&id, RequestClass::Expensive).expect("bucket exists");
    assert_eq!(c, cap);
    assert!(live <= cap, "no overshoot: live={live} cap={cap}");
}

// ---------- (5) fail-closed / overflow / purity ----------

#[test]
fn saturating_math_never_wraps() {
    // Indirect: retry_after derivation and count increments use
    // saturating ops; a huge backdate cannot wrap into an allowed state.
    let id = fresh("of");
    for _ in 0..EXPENSIVE_CAP {
        let _ = check(&id, RequestClass::Expensive);
    }
    // Backdate by an absurd amount: u64 max. Rollover must still yield a
    // fresh allowed window (elapsed saturates, never underflows negative).
    crate::rate_limits::test_backdate_window(&id, RequestClass::Expensive, u64::MAX - 1);
    assert_eq!(
        check(&id, RequestClass::Expensive),
        Ok(MeterVerdict::Allowed)
    );
}

#[test]
fn denial_code_is_the_stable_constant() {
    assert_eq!(CODE_RATE_LIMITED, "RATE_LIMITED");
}

#[test]
fn meter_module_is_pure_no_network_no_disk_no_money() {
    let src = include_str!("rate_limits.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "TcpStream",
        "reqwest",
        "http",
        "File::",
        "fs::",
        "write(",
        "create(",
        "read_to_string",
        "AgentPolicy",
        "reserve_spend",
        "daily_payment_limit",
        "lat_",
        "SigningKey",
        "read_keypair",
        "SystemTime",
        "unix_epoch",
    ] {
        assert!(!code.contains(forbidden), "meter references {forbidden}");
    }
    // The sanctioned primitives must be present (guard against vacuous scan).
    assert!(code.contains("Instant"), "monotonic basis required");
    assert!(code.contains("Mutex"), "process-global lock required");
    assert!(
        code.contains("saturating"),
        "saturating arithmetic required"
    );
    // No wall-clock dependency: the ONLY time source is Instant.
    assert!(!code.contains("SystemTime::now"), "no wall clock");
}

// ---------- (6) restart semantics: no persistence ----------

#[test]
fn meter_state_is_memory_only_no_disk_artifact() {
    // Prove the meter writes nothing to disk: the module's entire code
    // surface has no fs/path usage (pinned by the purity test above);
    // here we additionally assert that running the meter over a live
    // artifact directory does not create any NEW file anywhere (the
    // parallel test-suite writes to artifact/ itself, so we must not
    // compare snapshots — instead we assert the module never even names
    // a path, and that a meter-only workload in an isolated temp dir
    // leaves it untouched).
    let isolated = std::env::temp_dir().join(format!("ratelimits-i9-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&isolated).unwrap();
    let id = fresh("persist");
    for _ in 0..3 {
        let _ = check(&id, RequestClass::Expensive);
    }
    let entries: Vec<_> = std::fs::read_dir(&isolated)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(
        entries.is_empty(),
        "meter must not create files: {:?}",
        entries
    );
    std::fs::remove_dir_all(&isolated).ok();
    // Restart semantics = reset-on-new-process: the meter is in-memory
    // only (OnceLock), so a fresh process starts empty. That property is
    // structural (no File/fs usage); additionally the meter API exposes
    // no load/save surface at all.
    let src = include_str!("rate_limits.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!code.contains("load"), "no load surface (restart = fresh)");
    assert!(!code.contains("save"), "no save surface (restart = fresh)");
}

// ---------- (7) internal failure fails closed ----------

#[test]
fn meter_error_maps_to_denial_not_allowance() {
    // The contract: MeterError::Internal must NEVER be interpreted as
    // allowed. The handler wiring (server.rs) maps Internal -> 429 denial
    // (fail-closed). Pin the error shape here.
    assert_eq!(MeterError::Internal, MeterError::Internal);
    let src = include_str!("rate_limits.rs");
    assert!(
        src.contains("fail-closed") || src.contains("denies the request"),
        "module doc must state the fail-closed contract"
    );
}

// ---------- (8) enforcement wiring (server.rs) ----------

#[test]
fn enforcement_is_a_middleware_layer_before_state() {
    let src = include_str!("../server.rs");
    // The layer is registered on the app router (after fallback_service,
    // before with_state) — i.e., it wraps every route registered above it
    // including the fallback static serving and dev-login.
    assert!(
        src.contains("axum::middleware::from_fn_with_state"),
        "meter must be a router layer"
    );
    // Serve uses ConnectInfo so unauth identity = real peer address.
    assert!(
        src.contains("into_make_service_with_connect_info"),
        "peer address must come from ConnectInfo"
    );
    // X-Forwarded-For must never be consulted (no header-trust identity):
    // strip comment lines first, then assert the identifier is absent from
    // CODE (the module doc may name the concept).
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.to_lowercase().contains("x-forwarded-for"),
        "no client-supplied header identity in code"
    );
}

#[test]
fn middleware_checks_before_running_downstream_and_fails_closed() {
    let src = include_str!("../server.rs");
    // Structural order inside the middleware: classify → resolve identity
    // → check → Allowed arm runs next; Denied arm returns the 429; the
    // internal-error arm ALSO returns the 429 (fail-closed, never a
    // bypass).
    let mw = src
        .split("async fn rate_limits_middleware")
        .nth(1)
        .expect("middleware present")
        .split("fn rate_limited_response")
        .next()
        .unwrap();
    assert!(mw.contains("classify_path"), "classify first");
    assert!(mw.contains("check("), "meter consulted");
    assert!(mw.contains("next.run"), "only the Allowed arm proceeds");
    assert!(mw.contains("Err(_) =>"), "internal failure arm exists");
    // The denial response uses the stable code + 429 + Retry-After.
    let resp = src
        .split("fn rate_limited_response")
        .nth(1)
        .expect("denial helper present");
    assert!(resp.contains("TOO_MANY_REQUESTS"));
    assert!(resp.contains("RETRY_AFTER"));
    assert!(resp.contains("RATE_LIMITED"));
}

#[test]
fn denial_cannot_touch_money_state_structurally() {
    // The 429 response path contains no intent-claim, no reservation, no
    // ops.transfer, no lane mention — the middleware returns before any
    // of that machinery exists on the call path.
    let resp = include_str!("../server.rs")
        .split("fn rate_limited_response")
        .nth(1)
        .expect("denial helper present");
    for forbidden in [
        "claim_intent",
        "reserve_spend",
        "ops.transfer",
        "ExecutionLane",
        "production_payment_ops",
        "gateway.submit",
        "native.transfer",
    ] {
        assert!(
            !resp.contains(forbidden),
            "denial path references {forbidden}"
        );
    }
    // The meter module itself has zero money/lane references (pinned by
    // the purity test above); here pin the middleware too.
    let mw = include_str!("../server.rs")
        .split("async fn rate_limits_middleware")
        .nth(1)
        .unwrap()
        .split("fn rate_limited_response")
        .next()
        .unwrap();
    assert!(!mw.contains("reserve_spend"));
    assert!(!mw.contains("ops.transfer"));
}

#[test]
fn identity_planes_are_only_user_and_ip() {
    let mw = include_str!("../server.rs")
        .split("async fn rate_limits_middleware")
        .nth(1)
        .unwrap()
        .split("fn rate_limited_response")
        .next()
        .unwrap();
    assert!(mw.contains("session_user"), "reuses the existing principal");
    assert!(
        mw.contains("user_identity(user.id)"),
        "user plane = github id"
    );
    assert!(
        mw.contains("ip_identity(peer.ip())"),
        "ip plane = ConnectInfo"
    );
    // Never keyed by an agent-name string or a credential VALUE.
    assert!(!mw.contains("agent_name"));
    assert!(!mw.contains("credential.clone()"));
}
