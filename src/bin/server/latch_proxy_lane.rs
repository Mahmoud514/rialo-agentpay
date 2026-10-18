//! PHASE 9 I-5 — the armed D-PROXY transport lane.
//!
//! This module is the production network client the I-4 seam promised, and
//! it is deliberately NOT the classic Latch `/proxy` client: the rialo CLI
//! cannot attach an Authorization header, Latch proxy auth is header-only
//! Bearer, and the user-elected D-TRANSPORT answer is a localhost
//! bearer-attaching hop (tools/latch-transport-shim, a standalone operator
//! process). The server therefore points ONE cloned RPC surface at the
//! shim and NEVER touches a bearer token:
//!
//! ```text
//! execute_agent_payment(_v2)  (frozen cores, unchanged — one ops.transfer)
//!   -> LatchPaymentOps (I-4 seam: lane selection + one-shot guard)
//!       -> ProxyShimGateway.probe()  GET http://127.0.0.1:<port>/healthz
//!       -> ProxyShimGateway.submit() the SAME CLI transfer path with
//!          rpc_url = the loopback shim base  (build/sign/broadcast stay
//!          with the established rialo CLI + 0600 keypair FILE reference —
//!          no new custody, no new signing route)
//!             -> D-TRANSPORT shim (injects the Bearer lat_ once, from ITS
//!                env)  -> AgentPay-Master-Proxy latch -> Rialo RPC upstream
//! ```
//!
//! ARCHITECTURE LAWS PINNED BY THIS MODULE (I-5 spec, verbatim):
//! * AgentPay stays the policy/source-of-truth layer; the latch is a
//!   transport/policy proxy only. Nothing here compiles, duplicates, or
//!   re-checks money policy — the C-2 pipeline IR is consumed by reference
//!   through the seam's binding, exactly as I-4 designed.
//! * The AgentPay server must NOT handle or persist the Latch token. This
//!   process never reads the token VALUE, never reads LATCH_TOKEN at all,
//!   never constructs an Authorization header, and has no field, type, or
//!   constant that could hold a credential. The shim owns the bearer;
//!   it is injected exactly once there and nowhere else.
//! * Read-only operations stay native: only the two payment handler sites
//!   wrap their ops; balance/read_tx/signatures_for_address still delegate
//!   inside the seam (I-4 rule), and no read lane ever probes or forwards.
//! * Fallback matrix (frozen rule set, structurally enforced by the seam):
//!   - pre-execution Availability/Configuration/Capability -> native may
//!     run (probe failure lands here by construction);
//!   - policy/security denial, auth rejection, explicit Latch refusal ->
//!     NEVER fall back (stable LATCH_* codes ride the core's definitive
//!     Failed path);
//!   - timeout / outcome-uncertain / anything unprovable about whether the
//!     dispatch happened -> the core's single Unknown-hold channel
//!     (RIALO_TRANSFER_CONFIRMATION_TIMEOUT code); never refund, never
//!     retry, never switch lanes.
//!   `classify_lane_error` implements that taxonomy and is pure: the
//!   provably-pre-dispatch classes are named explicitly, everything else
//!   defaults to Uncertain (the safe direction).
//! * Exactly one execution attempt per intent: the seam's one-shot guard
//!   owns this; this module contributes a second structural pin — the
//!   submit path contains exactly ONE `.transfer(` call site and no retry
//!   grammar (the CLI's own bounded clock-skew re-sign retry is frozen
//!   pre-broadcast behavior living in rialo.rs, not a second settlement
//!   attempt; it is not duplicated or extended here).
//! * Configuration is env-only (names below, read by the seam's presence
//!   rules): AGENTPAY_LATCH_LANE ("1" = opt-in), AGENTPAY_LATCH_PROXY_URL
//!   (loopback http shim base ONLY — https/external/hosts with paths are
//!   refused at parse time), AGENTPAY_LATCH_ID (latch correlation id,
//!   public metadata). Nothing is stored in config.yaml, the repo, or logs.

use crate::agents::{Agent, AgentPolicy, PaymentOps};
use crate::audit::LaneAuditContext;
use crate::latch_policy_compiler::{Lane, LatchId, compile_agent_pipeline};
use crate::latch_transport::{
    CODE_TRANSFER_CONFIRMATION_TIMEOUT, DenialReason, LatchGateway, LatchLaneConfig,
    LatchPaymentOps, LatchPolicyBinding, LatchSubmitRequest, PreExecReason, TransportFailure,
    UncertainOutcome,
};
use crate::rialo::{RialoConfig, RialoError};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;

/// Probe budget for the loopback hop. The shim is localhost; anything
/// slower than this is indistinguishable from dead, and the lane decision
/// MUST stay bounded (a hanging probe must never hold a request worker).
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(750);
const PROBE_READ_TIMEOUT: Duration = Duration::from_millis(1500);

/// Parse the proxy-lane shim base. Loopback ONLY by construction:
/// `http://` scheme, host ∈ {IPv4 127/8, `::1`, `localhost`}, nonzero port,
/// and no path/query/userinfo — the shim's own base contract. Anything
/// else is a configuration refusal (the caller then stays native).
pub(crate) fn parse_proxy_url(raw: &str) -> Option<(String, SocketAddr)> {
    let rest = raw.trim().strip_prefix("http://")?;
    if rest.is_empty()
        || rest.contains('@')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('/')
        || rest.chars().any(char::is_whitespace)
    {
        return None;
    }
    // IPv6 literals carry their own brackets; everything else is host:port.
    let (host_str, port_str, bracketed) = match rest.strip_prefix('[') {
        Some(b) => {
            let (h, p) = b.split_once("]:")?;
            (h.to_string(), p.to_string(), true)
        }
        None => {
            let (h, p) = rest.rsplit_once(':')?;
            (h.to_string(), p.to_string(), false)
        }
    };
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    let ip: IpAddr = if !bracketed && host_str == "localhost" {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        match host_str.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) if v4.is_loopback() && !bracketed => IpAddr::V4(v4),
            IpAddr::V6(v6) if v6.is_loopback() && bracketed => IpAddr::V6(v6),
            _ => return None,
        }
    };
    // Canonical dial string for the CLI lane: rebuilt from the validated
    // address, so an accepted URL can never differ from the probed socket.
    let host_literal = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    Some((
        format!("http://{host_literal}:{port}"),
        SocketAddr::new(ip, port),
    ))
}

/// THE honest lane-error taxonomy: from the typed error the (shim-bound)
/// CLI executor produced, derive exactly one TransportFailure class.
/// Order matters: provable pre-dispatch classes first, then the explicit
/// refusal markers, then everything else falls into Uncertain — the ONLY
/// conservative direction when non-execution cannot be proven.
pub(crate) fn classify_lane_error(err: &RialoError) -> TransportFailure {
    let code = err.code;
    let detail = err.detail.to_lowercase();
    // Provable zero-dispatch classes (fallback-eligible, frozen rule:
    // pre-execution availability/configuration/capability ONLY).
    if code == "RIALO_CLI_UNAVAILABLE" || code == "RIALO_WALLET_ERROR" {
        return TransportFailure::PreExec(PreExecReason::Availability);
    }
    if detail.contains("pre-forward") {
        // The shim's own proof: its outbound connect never happened.
        return TransportFailure::PreExec(PreExecReason::Availability);
    }
    if code == "RIALO_RPC_UNAVAILABLE"
        && (detail.contains("connection refused") || detail.contains("network error"))
    {
        // Connection never established. NOTE: the RPC_UNAVAILABLE class
        // also covers "timed out waiting" — that is NOT pre-dispatch and
        // deliberately does not match here; it falls through to Uncertain.
        return TransportFailure::PreExec(PreExecReason::Availability);
    }
    // The core's established uncertainty surface wins over everything.
    if code == CODE_TRANSFER_CONFIRMATION_TIMEOUT {
        return TransportFailure::Uncertain(UncertainOutcome);
    }
    if detail.contains("post-dispatch") || detail.contains("outcome unknown") {
        // The shim's honest 504 class: written-but-unproven.
        return TransportFailure::Uncertain(UncertainOutcome);
    }
    // Explicit lane refusals: NEVER fall back (frozen rule).
    if detail.contains("deniedby")
        || detail.contains("request denied by policy")
        || detail.contains("too many requests")
        || detail.contains("rate limited")
    {
        return TransportFailure::Denial(DenialReason::PolicyDenied);
    }
    if detail.contains("invalid token") || detail.contains("unauthorized") {
        return TransportFailure::Denial(DenialReason::AuthRejected);
    }
    // Unknown-but-definitive-looking codes (e.g. a relayed RIALO_CLOCK_SKEW
    // or RIALO_TRANSFER_ERROR whose text carries no marker we can trust):
    // on an armed lane these are NOT provably pre-dispatch, so they ride
    // the safe direction — hold Unknown, let reconciliation decide on-chain
    // evidence. Never refund on unproven outcome, never native-rerun.
    TransportFailure::Uncertain(UncertainOutcome)
}

/// The production gateway: loopback health-probe + exactly ONE delegation
/// to the shim-bound executor carried as a plain PaymentOps. The bearer
/// never exists in this type — it is the shim's job by construction.
pub(crate) struct ProxyShimGateway {
    lane: Arc<dyn PaymentOps + Send + Sync>,
    addr: SocketAddr,
}

impl ProxyShimGateway {
    /// Pre-execution reachability check against the shim ONLY
    /// (`/healthz` is served locally by the shim and never reaches the
    /// network beyond the loopback interface). Nothing settles here.
    fn probe_healthz(&self) -> bool {
        let Ok(mut stream) = TcpStream::connect_timeout(&self.addr, PROBE_CONNECT_TIMEOUT) else {
            return false;
        };
        if stream
            .set_read_timeout(Some(PROBE_READ_TIMEOUT))
            .and(stream.set_write_timeout(Some(PROBE_CONNECT_TIMEOUT)))
            .is_err()
        {
            return false;
        }
        let _ = stream.write_all(
            b"GET /healthz HTTP/1.1\r\nHost: loopback.invalid\r\nConnection: close\r\n\r\n",
        );
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).unwrap_or(0);
        n >= 12 && buf[..n].starts_with(b"HTTP/1.1 200")
    }
}

impl LatchGateway for ProxyShimGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        if self.probe_healthz() {
            Ok(())
        } else {
            Err(TransportFailure::PreExec(PreExecReason::Availability))
        }
    }

    fn submit(&self, request: &LatchSubmitRequest) -> Result<String, TransportFailure> {
        // THE exactly-one lane dispatch: one call site, no retry grammar,
        // no second path. Pinned structurally by the module purity test.
        self.lane
            .transfer(
                &request.signer_reference,
                &request.recipient,
                &request.amount_rlo,
            )
            .map_err(|err| classify_lane_error(&err))
    }
}

/// Compile the per-agent lane binding, fail-closed. Order is the C-2
/// documented one: canonical id, recorded auth pubkey, I-1 vault
/// verification (pubkey-only), then the compiler's own gate chain. Every
/// refusal returns None — the caller then keeps the native lane; no
/// binding is ever guessed, defaulted, or backfilled.
pub(crate) fn proxy_binding(
    agent: &Agent,
    policy: &AgentPolicy,
    auth_keys_dir: &FsPath,
    latch_id: &LatchId,
) -> Option<LatchPolicyBinding> {
    // Canonical lowercase UUIDv4-shaped id (same rule as the handler
    // choke points; a corrupt record never reaches the vault read).
    let Ok(uuid) = uuid::Uuid::parse_str(&agent.agent_id) else {
        return None;
    };
    if uuid.to_string() != agent.agent_id {
        return None;
    }
    let recorded = agent.auth_public_key.as_deref()?;
    // I-1 vault check: the record's auth pubkey must be the vault file's
    // public half. Any error (missing, unreadable, mismatch) = no binding.
    if crate::agent_auth_keys::verify_auth_public_address(auth_keys_dir, &uuid, recorded).is_err() {
        return None;
    }
    match compile_agent_pipeline(policy, agent, true, Lane::ProxyAvailability, latch_id) {
        Ok(pipeline) => Some(LatchPolicyBinding::new(pipeline)),
        // DenyOnly / InactiveAgent / schema refusals are all "the lane is
        // not approvable for this intent" -> stay native, never an error.
        Err(_) => None,
    }
}

/// Assemble the seam around a concrete shim address with an injected lane
/// executor. Separate from `production_payment_ops` so tests can arm the
/// lane without touching the process environment.
#[allow(dead_code)] // consumed by the I-5 tests (lane assembly)
pub(crate) fn assemble_lane(
    native: Arc<dyn PaymentOps + Send + Sync>,
    lane: Arc<dyn PaymentOps + Send + Sync>,
    config: LatchLaneConfig,
    addr: SocketAddr,
    binding: Option<LatchPolicyBinding>,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let gateway = Arc::new(ProxyShimGateway { lane, addr });
    Arc::new(LatchPaymentOps::new(native, gateway, config, binding))
}

/// The env-independent factory core, exposed to tests so the full wiring
/// decision can be exercised without touching the process environment.
/// Selection rules are documented on `production_payment_ops`; every
/// refusal returns the plain native ops (the status quo, byte-for-byte).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // superseded by build_production_ops_audited on the money handlers; kept for the I-5 contract + tests
pub(crate) fn build_production_ops(
    native: Arc<RialoConfig>,
    config: &LatchLaneConfig,
    raw_url: Option<&str>,
    raw_latch_id: Option<&str>,
    agent: &Agent,
    policy: &AgentPolicy,
    auth_keys_dir: &FsPath,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let plain = native.clone() as Arc<dyn PaymentOps + Send + Sync>;
    if !config.enabled || !config.config_ok() {
        return plain;
    }
    let Some((rpc_url, addr)) = raw_url.and_then(parse_proxy_url) else {
        return plain;
    };
    let Some(latch_id) = raw_latch_id.and_then(|v| LatchId::new(v).ok()) else {
        return plain;
    };
    let binding = proxy_binding(agent, policy, auth_keys_dir, &latch_id);
    let mut lane_cfg = (*native).clone();
    lane_cfg.rpc_url = rpc_url;
    let lane = Arc::new(lane_cfg) as Arc<dyn PaymentOps + Send + Sync>;
    assemble_lane(plain, lane, *config, addr, binding)
}

/// THE wiring point used by both money handlers. Configuration is read
/// from the environment ONLY (names by the seam's presence rules):
/// AGENTPAY_LATCH_LANE ("1" = opt-in), AGENTPAY_LATCH_PROXY_URL (loopback
/// http shim base ONLY), AGENTPAY_LATCH_ID (public latch correlation id).
/// Any missing/invalid value keeps the plain native ops. The token plane
/// is never consulted here: the shim holds the bearer, the server only
/// dials loopback.
#[allow(dead_code)] // superseded by the audited wiring on the money handlers; kept for the I-5 contract + tests
pub fn production_payment_ops(
    native: Arc<RialoConfig>,
    agent: &Agent,
    policy: &AgentPolicy,
    auth_keys_dir: &FsPath,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let config = LatchLaneConfig::from_proxy_env();
    build_production_ops(
        native,
        &config,
        std::env::var(LatchLaneConfig::ENV_PROXY_URL)
            .ok()
            .as_deref(),
        std::env::var(LatchLaneConfig::ENV_LATCH_ID).ok().as_deref(),
        agent,
        policy,
        auth_keys_dir,
    )
}

/// PHASE 9 audit: the SAME wiring decision as `production_payment_ops`
/// (unchanged behavior) plus the OBSERVATIONAL audit context. When the
/// factory keeps the plain native lane, the EXISTING wiring decision is
/// mirrored as one lane record (selection reason). When the seam IS armed,
/// the seam itself records selection/fallback/denial/uncertainty — the
/// factory then records nothing (no duplicate evidence).
pub fn production_payment_ops_audited(
    native: Arc<RialoConfig>,
    agent: &Agent,
    policy: &AgentPolicy,
    auth_keys_dir: &FsPath,
    audit_ctx: Option<Arc<LaneAuditContext>>,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let config = LatchLaneConfig::from_proxy_env();
    build_production_ops_audited(
        native,
        &config,
        std::env::var(LatchLaneConfig::ENV_PROXY_URL)
            .ok()
            .as_deref(),
        std::env::var(LatchLaneConfig::ENV_LATCH_ID).ok().as_deref(),
        agent,
        policy,
        auth_keys_dir,
        audit_ctx,
    )
}

/// The audited factory core: IDENTICAL selection rules to
/// `build_production_ops` (every refusal returns the plain native ops — the
/// status quo, byte-for-byte), plus the audit mirror on the plain-native
/// refusals only.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_production_ops_audited(
    native: Arc<RialoConfig>,
    config: &LatchLaneConfig,
    raw_url: Option<&str>,
    raw_latch_id: Option<&str>,
    agent: &Agent,
    policy: &AgentPolicy,
    auth_keys_dir: &FsPath,
    audit_ctx: Option<Arc<LaneAuditContext>>,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let plain = native.clone() as Arc<dyn PaymentOps + Send + Sync>;
    if !config.enabled || !config.config_ok() {
        if let Some(ctx) = audit_ctx.as_ref() {
            crate::audit::record(
                crate::audit::lane(
                    crate::agents::now_unix(),
                    crate::audit::AuditOutcome::Selected,
                    None,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("native"),
                    if !config.enabled {
                        "latch lane not enabled"
                    } else {
                        "latch lane not configured"
                    },
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        return plain;
    }
    let Some((rpc_url, addr)) = raw_url.and_then(parse_proxy_url) else {
        if let Some(ctx) = audit_ctx.as_ref() {
            crate::audit::record(
                crate::audit::lane(
                    crate::agents::now_unix(),
                    crate::audit::AuditOutcome::Selected,
                    None,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("native"),
                    "latch proxy url invalid; native lane kept",
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        return plain;
    };
    let Some(latch_id) = raw_latch_id.and_then(|v| LatchId::new(v).ok()) else {
        if let Some(ctx) = audit_ctx.as_ref() {
            crate::audit::record(
                crate::audit::lane(
                    crate::agents::now_unix(),
                    crate::audit::AuditOutcome::Selected,
                    None,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("native"),
                    "latch id invalid; native lane kept",
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        return plain;
    };
    let binding = proxy_binding(agent, policy, auth_keys_dir, &latch_id);
    let Some(binding) = binding else {
        // proxy_binding returned None (no compiled policy binding for the
        // lane) — an EXISTING AgentPay-owned wiring decision; mirror it.
        if let Some(ctx) = audit_ctx.as_ref() {
            crate::audit::record(
                crate::audit::lane(
                    crate::agents::now_unix(),
                    crate::audit::AuditOutcome::Selected,
                    None,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("native"),
                    "no compiled policy binding for the Latch lane",
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        return plain;
    };
    let mut lane_cfg = (*native).clone();
    lane_cfg.rpc_url = rpc_url;
    let lane = Arc::new(lane_cfg) as Arc<dyn PaymentOps + Send + Sync>;
    let gateway = Arc::new(ProxyShimGateway { lane, addr });
    match audit_ctx {
        Some(ctx) => Arc::new(LatchPaymentOps::new_with_audit(
            plain,
            gateway,
            *config,
            Some(binding),
            ctx,
        )) as Arc<dyn PaymentOps + Send + Sync>,
        None => Arc::new(LatchPaymentOps::new(plain, gateway, *config, Some(binding)))
            as Arc<dyn PaymentOps + Send + Sync>,
    }
}

#[cfg(test)]
#[path = "_latch_i5_proxy_tests.rs"]
mod i5_proxy_tests;
