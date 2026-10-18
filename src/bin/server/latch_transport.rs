//! PHASE 9 I-4 — Latch transport behind PaymentOps (bounded seam).
//!
//! This module adds the OPTIONAL Latch execution lane between the frozen
//! payment cores and the real execution boundary, WITHOUT duplicating or
//! touching PaymentOps logic:
//!
//! ```text
//! PaymentOps (core calls, unchanged trait & semantics)
//!   -> policy/payment decision (stays app-side in agents.rs — untouched)
//!   -> lane selection (this module, BEFORE execution only)
//!       -> Latch transport (LatchGateway trait; production default =
//!          fail-closed UnconfiguredLatchGateway)
//!       -> Native existing execution (the wrapped real PaymentOps impl)
//!   -> settlement result (same typed error/Ok surface the cores already
//!      classify: commit / refund / unknown-hold)
//! ```
//!
//! ARCHITECTURE LAWS PINNED BY THIS MODULE (frozen Phase 9 rules):
//! * AgentPay is the payment engine and sole policy authority; this module
//!   makes NO policy decisions. It never compiles a policy (the C-2
//!   `CompiledPipeline` is CONSUMED by reference, never constructed), never
//!   touches the app gate, and never re-checks money limits.
//! * Lane selection happens strictly BEFORE execution. There is no path
//!   from a post-dispatch outcome back into lane selection.
//! * One intent may produce AT MOST ONE settlement attempt: every
//!   `LatchPaymentOps` instance carries a one-shot attempt guard; once the
//!   guard is spent (a native dispatch was entered or a gateway submit ran)
//!   any further transfer is REFUSED. Because refusal cannot prove that no
//!   money moved, it rides the confirmation-timeout code so the core takes
//!   its established unknown-hold exit (reservation held, replay gated) —
//!   never a refund, never a retry, never a lane switch.
//! * Native fallback happens ONLY pre-execution and ONLY for
//!   Availability / Configuration / Capability failures of the Latch lane.
//! * A policy denial, a security denial, or an authentication rejection
//!   from the Latch lane NEVER falls back to native. The core then records
//!   a definitive Failed intent (no dispatch happened, so releasing the
//!   reservation is safe) and burns the idempotency key exactly as it does
//!   for any other definitive failure.
//! * Uncertain post-dispatch outcomes map onto the core's ONE established
//!   uncertainty surface — the confirmation-timeout code — so reservation
//!   hold + Unknown + reconciliation remain the single mechanism (I-0/§13
//!   Q5 and item 2 §D-Q8 resolve to that existing surface; no second
//!   uncertainty channel is invented).
//! * The production network client for the D-PROXY transport lane lives in
//!   `latch_proxy_lane.rs` (armed by I-5; it talks ONLY to the localhost
//!   D-TRANSPORT shim, which holds the bearer in ITS environment — this
//!   module and its neighbor never read, transport, or store any Latch
//!   token value). The enclave-style submit client (G-14/G-15 tx-signing
//!   lane) remains deliberately NOT implemented; a real gateway for it may
//!   only be built against the documented `/proxy/{path}` surface.
//!   `UnconfiguredLatchGateway` stays the fail-closed default for every
//!   other construction site.

//! * Read-only plane stays native: `balance`, `read_tx` and
//!   `signatures_for_address` always delegate — item 2 §C audited that reads
//!   and reconciliation are not routed through Latch.

// The seam is built BEFORE it is armed: no production handler wires it
// until D1..D3 provisioning + the D-PROXY election land (item 2 §I /
// I-3 gate). Every item is exercised by tests today and consumed by the
// wiring item tomorrow — same discipline as the I-1 vault readers and
// TxSigner::User.
#![allow(dead_code)]

use crate::agents::PaymentOps;
use crate::audit::{self, AuditOutcome, LaneAuditContext};
use crate::latch_policy_compiler::CompiledPipeline;
use crate::rialo::{RialoError, SignatureInfoRecord, TxLookup};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The uncertainty surface the cores already classify as "outcome unknown:
/// hold the reservation, gate replay". Same value as the private
/// agents.rs constant — the cross-module binding is pinned by a test.
pub(crate) const CODE_TRANSFER_CONFIRMATION_TIMEOUT: &str = "RIALO_TRANSFER_CONFIRMATION_TIMEOUT";

/// Definitive pre-dispatch refusals from the Latch lane. Stable, fieldless
/// codes: no reason detail can ever surface through them.
pub(crate) const CODE_LATCH_POLICY_DENIED: &str = "LATCH_POLICY_DENIED";
pub(crate) const CODE_LATCH_SECURITY_DENIED: &str = "LATCH_SECURITY_DENIED";
pub(crate) const CODE_LATCH_AUTH_REJECTED: &str = "LATCH_AUTH_REJECTED";

/// WHY the Latch lane was not taken, before any dispatch. These three —
/// and ONLY these three — permit native fallback (frozen rule 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreExecReason {
    Availability,
    Configuration,
    Capability,
}

/// Explicit Latch policy/security refusals. NEVER eligible for native
/// fallback (frozen rule 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialReason {
    PolicyDenied,
    SecurityDenied,
    AuthRejected,
}

/// The post-dispatch uncertainty signal the transport layer accepts: the
/// dispatch may have reached settlement and the outcome is not provable
/// from here. Maps to the core's confirmation-timeout hold path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UncertainOutcome;

/// The one transport result type. Exactly one fallback-eligible failure
/// class per variant: PreExec -> native may run; Denial -> nothing may
/// run; Uncertain -> nothing may run, the core holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFailure {
    /// Nothing was dispatched.
    PreExec(PreExecReason),
    /// The dispatch was explicitly refused by policy/security/auth.
    /// Nothing reached settlement.
    Denial(DenialReason),
    /// The dispatch happened; the outcome is uncertain.
    Uncertain(UncertainOutcome),
}

/// A settlement request as the Latch seam sees it. OPAQUE data only: the
/// recipient, the already-normalized amount string the core handed to
/// `PaymentOps::transfer`, the owning agent, and the G-2 compiled policy
/// IR as its canonical bytes (pass-through; the transport never parses
/// or mutates it). Keypair references are deliberately NOT part of it —
/// the Latch lane does not take custody of any key material here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatchSubmitRequest {
    pub agent_id: String,
    pub recipient: String,
    pub amount_rlo: String,
    pub policy_ir_json: String,
    /// PHASE 9 I-5 (D-PROXY/D-TRANSPORT wiring): the signer's keypair FILE
    /// REFERENCE — a path only, never key material, never a seed, never a
    /// key byte. The proxy lane's local executor (the rialo CLI hop, bound
    /// to the localhost shim) resolves settlement through this reference
    /// exactly as the native lane does; custody stays with the established
    /// 0600-file + CLI path — no new signing route is introduced here.
    pub signer_reference: PathBuf,
}

impl LatchSubmitRequest {
    /// True when the request carries the agent's policy IR bytes verbatim
    /// (a transport that dropped or edited them is a contract break).
    pub fn carries_ir(&self, pipeline: &CompiledPipeline) -> bool {
        self.policy_ir_json == pipeline.to_json()
    }
}

/// The bounded transport boundary. The ONLY Latch-facing surface in the
/// server. Implementations must uphold the variant discipline of
/// `TransportFailure`: PreExec proves nothing was dispatched; Uncertain
/// is reserved for dispatched-but-unprovable outcomes; denial codes may
/// not be invented.
pub trait LatchGateway: Send + Sync {
    /// Pre-execution reachability + capability probe. Never dispatches
    /// anything, never blocks on the network in production (the default
    /// impl is a pure fail-closed check).
    fn probe(&self) -> Result<(), TransportFailure>;

    /// Hand the settlement request to the Latch lane. A submit that may
    /// actually move money MUST have proven it is not pre-execution
    /// refused first; the seam here is exactly where the future
    /// documented `/proxy/{path}` client will live.
    fn submit(&self, request: &LatchSubmitRequest) -> Result<String, TransportFailure>;
}

/// The production default: no Latch is configured (D1–D3 pending user
/// provisioning; D-PROXY is an outstanding USER election). Fails closed
/// at Configuration, pre-execution, every time — which by design yields
/// the native path unchanged.
pub struct UnconfiguredLatchGateway;

impl LatchGateway for UnconfiguredLatchGateway {
    fn probe(&self) -> Result<(), TransportFailure> {
        Err(TransportFailure::PreExec(PreExecReason::Configuration))
    }
    fn submit(&self, _request: &LatchSubmitRequest) -> Result<String, TransportFailure> {
        Err(TransportFailure::PreExec(PreExecReason::Configuration))
    }
}

/// The G-2 compiled policy representation as the lane consumes it: bound
/// to exactly one agent. Absent = the Latch lane is not selected (the
/// app never guesses an IR).
pub struct LatchPolicyBinding {
    agent_id: String,
    pipeline: CompiledPipeline,
}

impl LatchPolicyBinding {
    pub fn new(pipeline: CompiledPipeline) -> Self {
        Self {
            agent_id: pipeline.agent_id.clone(),
            pipeline,
        }
    }
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    pub fn pipeline_json(&self) -> String {
        self.pipeline.to_json()
    }
}

/// Lane selection outcome. `reason` is a static label for audit/log use —
/// it carries no detail values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneDecision {
    pub lane: ExecutionLane,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionLane {
    Native,
    Latch,
}

/// Latch lane configuration. Values are all local booleans; NO credential,
/// URL, or token value lives here. `from_env` reads env var NAMES' presence
/// only — `env::var_os` is never unwrapped into a stored value.
#[derive(Debug, Clone, Copy, Default)]
pub struct LatchLaneConfig {
    /// Operator opt-in (the feature flag). Default false: the native path
    /// is byte-for-byte the status quo when this is false.
    pub enabled: bool,
    /// Name-presence of the documented official env `LATCH_URL`. Presence
    /// gates selection; the value is never read or held by this module.
    pub url_present: bool,
    /// Name-presence of the documented official env `LATCH_TOKEN`. Same
    /// rule: presence only; the value never enters this module — a token
    /// is consumed (if ever) only inside a future gateway implementation.
    pub token_present: bool,
    /// PHASE 9 I-5 (D-TRANSPORT): true when the lane's bearer lives in the
    /// localhost shim's environment and NEVER in this process. The proxy
    /// lane then needs no `LATCH_TOKEN` presence of its own — reachability
    /// and refusal are proven by the probe/submit contract instead.
    pub bearer_hosted_externally: bool,
}

impl LatchLaneConfig {
    pub const ENV_FLAG: &'static str = "AGENTPAY_LATCH_LANE";
    pub const ENV_URL: &'static str = "LATCH_URL";
    pub const ENV_TOKEN: &'static str = "LATCH_TOKEN";
    /// I-5 proxy lane: base URL of the localhost D-TRANSPORT shim
    /// (loopback `http://127.…:PORT` only, parsed by `latch_proxy_lane`).
    pub const ENV_PROXY_URL: &'static str = "AGENTPAY_LATCH_PROXY_URL";
    /// I-5 proxy lane: the master latch id this lane is bound to (public
    /// correlation metadata, never a credential).
    pub const ENV_LATCH_ID: &'static str = "AGENTPAY_LATCH_ID";

    pub fn from_env() -> Self {
        Self {
            enabled: matches_env_enabled(Self::ENV_FLAG),
            url_present: env_name_present(Self::ENV_URL),
            token_present: env_name_present(Self::ENV_TOKEN),
            bearer_hosted_externally: false,
        }
    }

    /// PHASE 9 I-5: the D-PROXY transport lane. Presence checks read NAMES
    /// only (same rule as `from_env`); the bearer lives in the shim's
    /// environment exclusively, so this process never requires or reads
    /// a `LATCH_TOKEN` of its own.
    pub fn from_proxy_env() -> Self {
        Self {
            enabled: matches_env_enabled(Self::ENV_FLAG),
            url_present: env_name_present(Self::ENV_PROXY_URL),
            token_present: false,
            bearer_hosted_externally: true,
        }
    }

    /// Config-level pre-condition, checked before the gateway is consulted.
    pub(crate) fn config_ok(&self) -> bool {
        self.enabled && self.url_present && (self.token_present || self.bearer_hosted_externally)
    }
}

fn env_name_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn matches_env_enabled(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

/// Pure lane selection: config first, then binding (cheap local checks),
/// probe last (the only side-effect-capable step). Runs BEFORE execution
/// and consumes no policy decision state — the policy IR arrives already
/// compiled. Every non-Latch verdict names one of the three
/// fallback-eligible classes; nothing here can deny money (denials belong
/// to the pipeline evaluation inside Latch, surfaced later).
pub fn select_lane(
    config: &LatchLaneConfig,
    gateway: &dyn LatchGateway,
    binding: Option<&LatchPolicyBinding>,
    agent_id: &str,
) -> LaneDecision {
    let latch = |reason| LaneDecision {
        lane: ExecutionLane::Latch,
        reason,
    };
    let native = |reason| LaneDecision {
        lane: ExecutionLane::Native,
        reason,
    };
    if !config.enabled {
        return native("latch lane not enabled");
    }
    if !config.config_ok() {
        return native("latch lane not configured");
    }
    // Cheap local checks first: an unbound intent never triggers a probe.
    match binding {
        None => return native("no compiled policy binding for the Latch lane"),
        Some(b) if b.agent_id() != agent_id => {
            return native("policy binding agent mismatch");
        }
        Some(_) => {}
    }
    if let Err(failure) = gateway.probe() {
        return native(match failure {
            TransportFailure::PreExec(PreExecReason::Availability) => "latch lane unavailable",
            TransportFailure::PreExec(PreExecReason::Configuration) => "latch lane not configured",
            TransportFailure::PreExec(PreExecReason::Capability) => "latch lane not capable",
            // A probe never dispatches; denial/uncertainty at probe time is
            // treated as capability failure and stays native. It can never
            // execute the request because probes don't execute.
            _ => "latch lane not capable",
        });
    }
    latch("latch lane selected")
}

/// THE seam implementation: a `PaymentOps` decorator that routes the ONE
/// transfer per intent through the selected lane, preserving the wrapped
/// native impl's behavior in every non-Latch case (including ALL read
/// calls, always).
///
/// ONE INSTANCE PER INTENT (construction site = claim site): the guard is
/// per-instance, so cross-intent reuse of a single value would be a wiring
/// bug; the frozen cores are structurally pinned to exactly one
/// `ops.transfer(` call per execution anyway.
pub struct LatchPaymentOps {
    native: Arc<dyn PaymentOps + Send + Sync>,
    gateway: Arc<dyn LatchGateway + Send + Sync>,
    config: LatchLaneConfig,
    binding: Option<LatchPolicyBinding>,
    /// One-shot settlement guard. Spent by the first dispatch attempt of
    /// either lane (or by a refusal of a spent lane).
    attempted: AtomicBool,
    /// PHASE 9 audit context: when present, the EXISTING lane decisions
    /// (selection / fallback / denial / uncertainty) are mirrored into the
    /// append-only audit store. Purely observational — never read back, and
    /// never consulted by any decision.
    audit: Option<Arc<LaneAuditContext>>,
}

impl LatchPaymentOps {
    pub fn new(
        native: Arc<dyn PaymentOps + Send + Sync>,
        gateway: Arc<dyn LatchGateway + Send + Sync>,
        config: LatchLaneConfig,
        binding: Option<LatchPolicyBinding>,
    ) -> Self {
        Self {
            native,
            gateway,
            config,
            binding,
            attempted: AtomicBool::new(false),
            audit: None,
        }
    }

    /// The production constructor: config from env names only + the
    /// fail-closed default gateway. NOT wired anywhere yet (that is the
    /// post-D1..D3 wiring item): wiring it changes NOTHING observable
    /// because the default gateway keeps the native path, but the feature
    /// stays honestly "present, unarmed" until provisioning exists.
    #[allow(dead_code)] // future lane; consumed by tests and the wiring item
    pub fn for_production(native: Arc<dyn PaymentOps + Send + Sync>) -> Self {
        Self::new(
            native,
            Arc::new(UnconfiguredLatchGateway),
            LatchLaneConfig::from_env(),
            None,
        )
    }

    /// PHASE 9 audit: the same seam carrying the OBSERVATIONAL audit
    /// context (agent + idempotency key + audit dir). Nothing behavioral
    /// changes: `new` and `new_with_audit` differ ONLY in whether the
    /// existing lane decisions are ALSO mirrored into the append-only
    /// audit store. `new` stays byte-identical for every existing caller.
    pub fn new_with_audit(
        native: Arc<dyn PaymentOps + Send + Sync>,
        gateway: Arc<dyn LatchGateway + Send + Sync>,
        config: LatchLaneConfig,
        binding: Option<LatchPolicyBinding>,
        audit_ctx: Arc<LaneAuditContext>,
    ) -> Self {
        Self {
            native,
            gateway,
            config,
            binding,
            attempted: AtomicBool::new(false),
            audit: Some(audit_ctx),
        }
    }

    /// Mirror one EXISTING lane decision into the audit store (best-effort;
    /// an audit failure can never affect the dispatch).
    fn audit_lane(
        &self,
        at: i64,
        outcome: AuditOutcome,
        code: Option<&str>,
        lane: Option<&str>,
        reason: &str,
        fallback: bool,
    ) {
        if let Some(ctx) = self.audit.as_ref() {
            audit::record(
                audit::lane(
                    at,
                    outcome,
                    code,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    lane,
                    reason,
                    fallback,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
    }

    /// Spend the one-shot guard. False = a settlement attempt already
    /// happened on this instance.
    fn claim_attempt(&self) -> bool {
        !self.attempted.swap(true, Ordering::SeqCst)
    }

    /// The core's uncertainty surface, reused as the single channel:
    /// same code the frozen cores classify as "hold the reservation,
    /// gate replay". Static message; no detail values.
    fn uncertain_error() -> RialoError {
        RialoError {
            code: CODE_TRANSFER_CONFIRMATION_TIMEOUT,
            detail: "latch transport: settlement attempt already made or outcome uncertain"
                .to_string(),
            tx_signature: None,
        }
    }

    fn denial_error(reason: DenialReason) -> RialoError {
        let code = match reason {
            DenialReason::PolicyDenied => CODE_LATCH_POLICY_DENIED,
            DenialReason::SecurityDenied => CODE_LATCH_SECURITY_DENIED,
            DenialReason::AuthRejected => CODE_LATCH_AUTH_REJECTED,
        };
        RialoError {
            code,
            detail: "latch lane refused the settlement attempt".to_string(),
            tx_signature: None,
        }
    }
}

impl PaymentOps for LatchPaymentOps {
    fn balance(&self, address: &str) -> Result<f64, RialoError> {
        // Read-only plane is always native (item 2 §C).
        self.native.balance(address)
    }

    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError> {
        // One intent, at most one settlement attempt — refuse a second
        // attempt through the core's own uncertainty surface so the
        // reservation is HELD (never refunded, never retried).
        if !self.claim_attempt() {
            // PHASE 9 audit: the refusal is an EXISTING decision (the
            // one-shot guard); mirror it — uncertainty stays uncertainty.
            self.audit_lane(
                crate::agents::now_unix(),
                AuditOutcome::Uncertain,
                Some(CODE_TRANSFER_CONFIRMATION_TIMEOUT),
                None,
                "one-shot settlement guard already spent",
                false,
            );
            return Err(Self::uncertain_error());
        }

        let agent_id = self
            .binding
            .as_ref()
            .map(|b| b.agent_id().to_string())
            .unwrap_or_default();
        let decision = select_lane(
            &self.config,
            self.gateway.as_ref(),
            self.binding.as_ref(),
            &agent_id,
        );
        // PHASE 9 audit: mirror the EXISTING selection (lane + static
        // reason). Observational only — `decision` is consumed exactly as
        // before, and no audit value ever feeds back into it.
        let now = crate::agents::now_unix();
        self.audit_lane(
            now,
            AuditOutcome::Selected,
            None,
            Some(match decision.lane {
                ExecutionLane::Native => "native",
                ExecutionLane::Latch => "latch",
            }),
            decision.reason,
            false,
        );

        match decision.lane {
            ExecutionLane::Native => self.native.transfer(keypair_path, to, amount_rlo),
            ExecutionLane::Latch => {
                // The binding exists and matches (selection proved it).
                let binding = self.binding.as_ref().expect("selection guaranteed binding");
                let request = LatchSubmitRequest {
                    agent_id: binding.agent_id().to_string(),
                    recipient: to.to_string(),
                    amount_rlo: amount_rlo.to_string(),
                    policy_ir_json: binding.pipeline_json(),
                    signer_reference: keypair_path.to_path_buf(),
                };
                match self.gateway.submit(&request) {
                    Ok(signature) => Ok(signature),
                    Err(TransportFailure::Denial(reason)) => {
                        // PHASE 9 audit: the EXISTING terminal denial (never
                        // a fallback) — stable LATCH_* code, mirrored.
                        self.audit_lane(
                            crate::agents::now_unix(),
                            AuditOutcome::Denied,
                            Some(Self::denial_error(reason).code),
                            Some("latch"),
                            "latch lane refused the settlement attempt",
                            false,
                        );
                        Err(Self::denial_error(reason))
                    }
                    Err(TransportFailure::Uncertain(_)) => {
                        // PHASE 9 audit: mirror the uncertainty EXACTLY —
                        // never upgraded, never resolved here.
                        self.audit_lane(
                            crate::agents::now_unix(),
                            AuditOutcome::Uncertain,
                            Some(CODE_TRANSFER_CONFIRMATION_TIMEOUT),
                            Some("latch"),
                            "latch transport: settlement attempt already made or outcome uncertain",
                            false,
                        );
                        Err(Self::uncertain_error())
                    }
                    // Pre-execution failure after selection: the probe
                    // passed and selection chose Latch, so a PreExec here
                    // still proves NOTHING was dispatched — native
                    // fallback stays legal (frozen rule 7).
                    Err(TransportFailure::PreExec(_)) => {
                        // PHASE 9 audit: record the EXISTING fallback
                        // decision explicitly (latch selected, native
                        // performs the single dispatch).
                        self.audit_lane(
                            crate::agents::now_unix(),
                            AuditOutcome::Fallback,
                            None,
                            Some("native"),
                            "latch lane pre-execution failure after selection; native fallback",
                            true,
                        );
                        self.native.transfer(keypair_path, to, amount_rlo)
                    }
                }
            }
        }
    }

    fn read_tx(&self, signature: &str) -> TxLookup {
        self.native.read_tx(signature)
    }

    fn signatures_for_address(
        &self,
        address: &str,
        until_signature: Option<&str>,
        limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
        self.native
            .signatures_for_address(address, until_signature, limit)
    }
}

#[cfg(test)]
#[path = "_latch_i4_tests.rs"]
mod i4_tests;
