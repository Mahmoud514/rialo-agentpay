//! rate_limits — PHASE 9 "Rate / time limits" (app-side half; threat-model
//! TM-AV-01 / TM-AV-03, gap-matrix GA-4): the fixed-window request meter
//! that closes the unmetered-surface availability gap.
//!
//! WHAT THIS IS (and is not):
//! * A pure, process-local meter. Fixed windows on MONOTONIC time buckets
//!   (`std::time::Instant`), under ONE process-global mutex, keyed by
//!   identity + request class. Atomic check-and-consume: for a cap N, at
//!   most N requests succeed per identity/class/window — no overshoot, no
//!   lost update.
//! * FAIL-CLOSED: an internal error (unknown bucket shape, poisoned lock
//!   surface, malformed configuration) denies the request rather than
//!   allowing it — same posture as the frozen policy gate.
//! * No network, no disk persistence, no wall-clock dependency, no
//!   dependency on Latch, no private-key access, and NO money-policy
//!   coupling: budgets are never derived from `AgentPolicy` amounts or the
//!   spend ledger (C-2 §11 ban: rate_limit is availability-only and never
//!   money-derived). Restart resets every meter — acceptable under the
//!   documented single-process deployment assumption (GA-11); availability
//!   meters are not money state and must not be persisted.
//!
//! IDENTITY MODEL (existing planes reused; no new identity mechanism):
//! * Authenticated session lane: `user:<github id>` — the SAME principal
//!   `session_user` resolves; never an agent-name string.
//! * Credential trigger lane: keyed by CLIENT IP (`ip:<addr>`) with a
//!   STRICTER budget — the Argon2 scan runs per attempt BEFORE any
//!   principal is known, so per-IP metering is the only sound placement
//!   (TM-AV-03: each bogus credential costs a full-store scan; per-IP caps
//!   bound that amplification regardless of header content).
//! * Unauthenticated lanes: `ip:<addr>` from `ConnectInfo` (loopback
//!   deployment today; spoofing X-Forwarded-For is structurally irrelevant
//!   because the value is never consulted).
//! * A static unknown-peer fallback exists ONLY for direct test
//!   invocation without connect info; production serving always provides
//!   ConnectInfo.
//!
//! ENFORCEMENT POSITION (the whole point of this module): the check runs
//! BEFORE intent claim, spend reservation, `production_payment_ops`, lane
//! selection, and both Native and Latch execution. A denial therefore can
//! never create an intent, reserve money, or trigger a lane
//! fallback — the meter is strictly pre-execution (mirroring the
//! frozen PreExec-only fallback rule, but one plane earlier).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Request classes. Exactly two, per the approved discovery: EXPENSIVE
/// (live RPC / chain writes / Argon2 scans / OAuth round-trips) and CHEAP
/// (normal CRUD/read surfaces). The classification surface is the router
/// path; the mapping lives in `classify_path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RequestClass {
    Expensive,
    Cheap,
}

/// Static class label for audit export only (no decision semantics).
pub(crate) fn class_label(class: RequestClass) -> &'static str {
    match class {
        RequestClass::Expensive => "expensive",
        RequestClass::Cheap => "cheap",
    }
}

/// FIXED budgets and windows. Explicit constants (no hidden magic
/// numbers), conservative, and deliberately NOT derived from any payment
/// amount. Windows are in milliseconds of MONOTONIC time.
pub(crate) const EXPENSIVE_WINDOW_MS: u64 = 60_000;
pub(crate) const EXPENSIVE_CAP: u64 = 300;
pub(crate) const CHEAP_WINDOW_MS: u64 = 60_000;
pub(crate) const CHEAP_CAP: u64 = 480;

/// Stable client-visible denial code (the only new taxonomy entry; reuse
/// of the existing `api_error` envelope is the caller's job).
pub(crate) const CODE_RATE_LIMITED: &str = "RATE_LIMITED";

#[derive(Clone, Copy)]
struct Bucket {
    /// Monotonic window start (ms since an arbitrary fixed epoch — the
    /// process start's Instant base). Correctness never depends on the
    /// absolute value, only on arithmetic within one window.
    window_start_ms: u64,
    count: u64,
}

struct MeterState {
    buckets: HashMap<(String, RequestClass), Bucket>,
}

fn meter() -> &'static Mutex<MeterState> {
    static METER: OnceLock<Mutex<MeterState>> = OnceLock::new();
    METER.get_or_init(|| {
        Mutex::new(MeterState {
            buckets: HashMap::new(),
        })
    })
}

/// Internal failure shape. Fieldless on purpose: no identity strings, no
/// class details, no counters can ever leak through Debug/Display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeterError {
    /// The meter could not be consulted — the request is DENIED
    /// (fail-closed), never silently allowed.
    Internal,
}

/// An allowed-or-denied verdict with the Retry-After residue for denials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MeterVerdict {
    Allowed,
    Denied { retry_after_ms: u64 },
}

/// Map a router path to its request class. The classification surface is
/// deliberately small (the discovery's two-class model): exact-prefix
/// matches on the endpoints that drive RPC/chain/Argon2/OAuth work.
pub(crate) fn classify_path(path: &str) -> RequestClass {
    const EXPENSIVE_PREFIXES: [&str; 9] = [
        "/api/health",
        "/api/public/verify",
        "/api/faucet",
        "/api/payment",
        "/api/agents",
        "/auth/github",
        "/auth/dev-login",
        "/api/program/status",
        "/api/me",
    ];
    for prefix in EXPENSIVE_PREFIXES {
        if path == prefix || path.starts_with(prefix) {
            return RequestClass::Expensive;
        }
    }
    RequestClass::Cheap
}

/// Identity key for an authenticated session principal (the same GitHub
/// id `session_user` resolves). Agent-NAME strings are structurally
/// excluded: the caller passes the numeric id.
pub(crate) fn user_identity(user_id: u64) -> String {
    format!("user:{user_id}")
}

/// Identity key for a client peer address. The address comes from
/// `ConnectInfo` (production serving) — never from any client-supplied
/// header.
pub(crate) fn ip_identity(ip: std::net::IpAddr) -> String {
    format!("ip:{ip}")
}

/// Fallback identity for contexts with no peer address (direct test
/// invocation). Production serving always supplies ConnectInfo, so this
/// bucket is shared and STRICTLY the same strictness as an IP bucket.
pub(crate) const UNKNOWN_PEER_IDENTITY: &str = "ip:unknown";

/// The atomic check-and-consume. One call = one decision:
/// * builds the current window from monotonic time,
/// * rolls expired buckets,
/// * at cap → Denied with Retry-After = remaining window,
/// * under cap → count += 1, Allowed.
/// Any lock/access failure ⇒ Internal (fail-closed: the caller denies).
pub(crate) fn check(identity: &str, class: RequestClass) -> Result<MeterVerdict, MeterError> {
    let (cap, window_ms) = match class {
        RequestClass::Expensive => (EXPENSIVE_CAP, EXPENSIVE_WINDOW_MS),
        RequestClass::Cheap => (CHEAP_CAP, CHEAP_WINDOW_MS),
    };
    let now = monotonic_ms();
    let mut state = meter().lock().map_err(|_| MeterError::Internal)?;
    let entry = state
        .buckets
        .entry((identity.to_string(), class))
        .or_insert(Bucket {
            window_start_ms: now,
            count: 0,
        });
    if now.saturating_sub(entry.window_start_ms) >= window_ms {
        // Window rollover: reset in place (no allocation churn; the map
        // never grows per request, only per identity+class pair).
        entry.window_start_ms = now;
        entry.count = 0;
    }
    if entry.count >= cap {
        let elapsed = now.saturating_sub(entry.window_start_ms);
        let retry_after_ms = window_ms.saturating_sub(elapsed).max(1);
        return Ok(MeterVerdict::Denied { retry_after_ms });
    }
    // Overflow is structurally unreachable (count < cap and cap is a
    // small constant), but the saturating form documents the invariant.
    entry.count = entry.count.saturating_add(1);
    Ok(MeterVerdict::Allowed)
}

/// The Retry-After residue for a DENIED request (seconds, rounded up),
/// for the caller building the HTTP response. Allowed verdicts have no
/// residue.
pub(crate) fn retry_after_seconds(v: &MeterVerdict) -> Option<u64> {
    match v {
        MeterVerdict::Allowed => None,
        MeterVerdict::Denied { retry_after_ms } => Some(retry_after_ms.div_ceil(1000).max(1)),
    }
}

/// Monotonic milliseconds. `Instant` has no epoch semantics; the meter
/// reads "milliseconds since process start" offset by a large fixed
/// origin so the u64 math has ample headroom in both directions (this
/// also keeps the test-only backdating helper deterministic). The
/// absolute value never matters — only differences within one window —
/// and restart resets the base, which is exactly the documented
/// restart-reset behavior.
const MONOTONIC_ORIGIN_MS: u64 = 1 << 40;

fn monotonic_ms() -> u64 {
    // The static base makes repeated calls cheap and keeps the u64 math
    // in a stable monotonic territory.
    static BASE: OnceLock<Instant> = OnceLock::new();
    MONOTONIC_ORIGIN_MS.saturating_add(BASE.get_or_init(Instant::now).elapsed().as_millis() as u64)
}

/// Test-only observability: the live count for an identity/class without
/// consuming. Exists so the concurrency tests can assert "exactly at cap"
/// without racing a read; NOT part of any request path.
#[cfg(test)]
pub(crate) fn peek(identity: &str, class: RequestClass) -> Option<(u64, u64)> {
    let now = monotonic_ms();
    let state = meter().lock().ok()?;
    let (cap, window_ms) = match class {
        RequestClass::Expensive => (EXPENSIVE_CAP, EXPENSIVE_WINDOW_MS),
        RequestClass::Cheap => (CHEAP_CAP, CHEAP_WINDOW_MS),
    };
    let b = state.buckets.get(&(identity.to_string(), class))?;
    let live = if now.saturating_sub(b.window_start_ms) >= window_ms {
        0
    } else {
        b.count
    };
    Some((live, cap))
}

/// Test-only: backdate an identity's window start so a rollover can be
/// observed without waiting real time. NEVER called outside tests.
#[cfg(test)]
pub(crate) fn test_backdate_window(identity: &str, class: RequestClass, back_ms: u64) {
    let now = monotonic_ms();
    if let Ok(mut state) = meter().lock() {
        if let Some(b) = state.buckets.get_mut(&(identity.to_string(), class)) {
            b.window_start_ms = now.saturating_sub(back_ms);
        }
    }
}

#[cfg(test)]
#[path = "_ratelimits_i9_tests.rs"]
mod ratelimits_tests;
