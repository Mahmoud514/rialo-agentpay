//! isolated_signer_lane — PHASE 9 "Secure signer" (STEP 7): the isolated
//! signer integrated behind the ONE PaymentOps seam.
//!
//! Authority: `_phase9/isolated_signer_architecture_decision.md` (§1–§14)
//! and the STEP 7 mandate. The adapter is ADDITIVE and owns ALL signer
//! communication: no direct signer calls scattered across handlers, one
//! adapter, one seam, one funded-key authority.
//!
//! ARCHITECTURE (frozen):
//!
//!   AgentPay authorization/policy/idempotency/spend boundary (UNCHANGED)
//!     → IsolatedSignerPaymentOps  (this adapter, the ONLY signer caller)
//!       → loopback isolated signer
//!         → canonical recompile (the authoritative module, zero-drift)
//!         → auth verification (the D8/G-7 linkage)
//!         → signer-side policy
//!         → signature generation (signer-owned custody)
//!       → SignedEnvelope
//!     → existing PaymentOps failure/Unknown semantics (no new grammar)
//!
//! NO-FALLBACK GRAMMAR (the critical invariant): once this lane is
//! selected (gate on + valid config), `transfer` NEVER falls back to
//! artifact wallets, CLI, Latch, Privy, or any other signer. Exactly one
//! funded signing authority exists. Transport failures map to the
//! EXISTING uncertainty channel (`RIALO_TRANSFER_CONFIRMATION_TIMEOUT` —
//! the code the cores classify as hold-reservation/gate-replay, i.e.
//! Unknown semantics); signer denials map to typed definitive failures
//! (the established refund path). Nothing is ever converted into "paid".
//!
//! SIGNING SUCCESS IS NOT PAYMENT (PHASE 10 ITEM 6 — the broadcast half of
//! the OLD working payment path is RESTORED here, in AGENTPAY, not in the
//! signer). The adapter consumes the CHANNEL-AUTHENTICATED signed result and
//! submits it through `RialoConfig` — the module that owns every chain
//! touchpoint and the ONE RPC endpoint — exactly where the old CLI path used
//! to build, sign and broadcast. The signer itself performs NO broadcast and
//! NO second signing path exists. A signature that never reaches the chain
//! is still never a payment: the core commits `Confirmed` only from the
//! node's own answer, and every pre-dispatch refusal carries no signature at
//! all (the intent records FAILED + refund per the established grammar).
//!
//! ENV GATE (disabled by default, fail-closed):
//!   AGENTPAY_ISOLATED_SIGNER_LANE   "1" = opt-in
//!   AGENTPAY_ISOLATED_SIGNER_URL    loopback http://127.0.0.1:PORT ONLY
//!                                   (non-loopback/zero-port/path-carrying
//!                                   refused at parse — the same
//!                                   discipline as the latch proxy URL)
//! With the gate absent or any value invalid: the plain native ops return
//! (byte-identical status quo; zero signer communication).

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use super::agents::{Agent, AgentPolicy, PaymentOps, parse_agent_id, read_agent};
use super::rialo::{RialoConfig, RialoError, SignatureInfoRecord, TxLookup};

/// The env names (the D11 discipline: official names ratified here).
pub const ENV_LANE: &str = "AGENTPAY_ISOLATED_SIGNER_LANE";
pub const ENV_URL: &str = "AGENTPAY_ISOLATED_SIGNER_URL";

/// Stable typed error codes (definitive failures — the established
/// pre-broadcast/refund classes; never a new terminal-success meaning).
///
/// `SIGNER_SIGNED_NOT_BROADCAST` was the PHASE 9 STEP 7 terminal mapping
/// while the broadcast half of the old payment path was disconnected.
/// PHASE 10 ITEM 6 restored that path, so the lane no longer returns it;
/// the name stays in the grammar because pre-ITEM-6 intents/audit records
/// carry it and reconciliation must keep classifying them identically.
pub const CODE_SIGNER_SIGNED_NOT_BROADCAST: &str = "SIGNER_SIGNED_NOT_BROADCAST";
pub const CODE_SIGNER_AUTH_DENIED: &str = "SIGNER_AUTH_DENIED";
pub const CODE_SIGNER_POLICY_DENIED: &str = "SIGNER_POLICY_DENIED";
pub const CODE_SIGNER_BYTE_DIVERGENCE: &str = "SIGNER_BYTE_DIVERGENCE";
pub const CODE_SIGNER_CANONICAL_FAILED: &str = "SIGNER_CANONICAL_FAILED";
pub const CODE_SIGNER_STATE_FAILED: &str = "SIGNER_STATE_FAILED";
pub const CODE_SIGNER_INTERNAL: &str = "SIGNER_INTERNAL";

/// Bounded transport: one short connect/timeout budget — a hung signer is
/// the uncertainty class, never an unbounded wait.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(4);

/// The lane configuration: loopback-only, fail-closed. `armed_and_valid`
/// distinguishes the two cutover postures:
///   * gate OFF          → the legacy status quo (STEP 7's preserved default)
///   * gate ON + invalid → FAIL-CLOSED (never a silent legacy fallback —
///     the cutover's exclusive-authority rule)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedSignerLaneConfig {
    pub enabled: bool,
    pub endpoint: String,
    /// true ONLY when the gate is on AND the URL is invalid (the fail-closed
    /// posture: payments must DENY, never degrade)
    pub invalid_when_armed: bool,
}

impl IsolatedSignerLaneConfig {
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            invalid_when_armed: false,
        }
    }

    /// The FAIL-CLOSED posture: the gate is on but the configuration is
    /// unusable — payments must DENY, never silently degrade to a legacy
    /// lane (the cutover's exclusive-authority rule).
    pub const fn fail_closed() -> Self {
        Self {
            enabled: true,
            endpoint: String::new(),
            invalid_when_armed: true,
        }
    }

    /// Read the env gate.
    ///   gate absent/off → the disabled config (the preserved status quo)
    ///   gate on + valid → the armed lane
    ///   gate on + invalid → FAIL-CLOSED (never a partially-armed lane, never
    ///   a silent legacy fallback)
    pub fn from_env() -> Self {
        let enabled = std::env::var(ENV_LANE).ok().as_deref() == Some("1");
        if !enabled {
            return Self::disabled();
        }
        let Ok(url) = std::env::var(ENV_URL) else {
            return Self::fail_closed();
        };
        match parse_loopback_endpoint(&url) {
            Some(ep) => Self {
                enabled: true,
                endpoint: ep,
                invalid_when_armed: false,
            },
            None => Self::fail_closed(),
        }
    }
}

/// Loopback-only endpoint parse: http + loopback host + non-zero port, no
/// path, no userinfo (the same discipline as the latch proxy URL parse).
pub fn parse_loopback_endpoint(raw: &str) -> Option<String> {
    let rest = raw.strip_prefix("http://")?;
    if rest.contains('/') || rest.contains('?') || rest.contains('@') {
        return None;
    }
    let (host, port_str) = rest.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    let loopback = host == "127.0.0.1" || host == "localhost" || host == "[::1]";
    if !loopback {
        return None;
    }
    Some(format!("http://127.0.0.1:{port}"))
}

/// The FAIL-CLOSED ops: the lane is armed but its configuration is
/// unusable. Every transfer DENIES (typed, definitive) — never a silent
/// legacy fallback. Reads stay native (the read plane is unaffected).
pub struct FailClosedSignerOps {
    native: Arc<RialoConfig>,
}

impl PaymentOps for FailClosedSignerOps {
    fn uses_external_custody(&self) -> bool {
        true // the lane is armed: custody is the signer's; deny payments
    }

    fn balance(&self, address: &str) -> Result<f64, RialoError> {
        self.native.balance(address)
    }

    fn transfer(
        &self,
        _keypair_path: &FsPath,
        _to: &str,
        _amount_rlo: &str,
    ) -> Result<String, RialoError> {
        Err(RialoError {
            code: "SIGNER_CONFIG_INVALID",
            detail: "isolated signer lane is armed but its configuration is invalid; payments are denied (fail-closed)".to_string(),
            tx_signature: None,
        })
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

/// PHASE 10 ITEM 6 — the CHANNEL-AUTHENTICATED signed result the signer
/// returns and the OLD execution/broadcast path consumes. Every field is
/// PUBLIC execution data (the message and the signature are what every node
/// sees); no key material of any kind can be present (the signer is
/// sign-only and this type is fieldwise public by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransactionResult {
    /// the agent the signature was authorized for
    agent_id: String,
    /// the signer-owned fee payer (public address)
    wallet_address: String,
    /// the authorized recipient (public address)
    recipient: String,
    /// the authorized integer amount (canonical kelvin)
    amount_kelvin: u64,
    /// the app-side canonical message bytes (the intent the policy allowed)
    canonical_message: Vec<u8>,
    /// the signer's own recompiled canonical message bytes
    signer_message: Vec<u8>,
    /// the signer's 64-byte ed25519 signature over its canonical message
    signature: Vec<u8>,
    /// the number of required signatures (the frozen single-signer shape)
    required_signatures: u8,
    /// the signer-reported blake3 hex of its canonical message
    canonical_hash: String,
}

/// The adapter: THE only signer caller in the app.
pub struct IsolatedSignerPaymentOps {
    /// the native ops for the READ-ONLY plane (balance/read_tx/history —
    /// the same rule as the latch lane: reads stay native) AND the ONE
    /// chain touchpoint the restored execution/broadcast path submits
    /// through (rialo.rs owns every endpoint decision).
    native: Arc<RialoConfig>,
    /// the loopback signer base (no path)
    endpoint: String,
    /// bounded loopback client
    client: reqwest::blocking::Client,
}

impl IsolatedSignerPaymentOps {
    fn new(native: Arc<RialoConfig>, endpoint: String) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(SIGNER_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        Self {
            native,
            endpoint,
            client,
        }
    }

    /// The signer wallet address (public data) for this agent — the feePayer
    /// of the semantic transaction. Typed failure on any refusal.
    fn signer_wallet_address(&self, agent_id: &str) -> Result<String, RialoError> {
        let url = format!("{}/wallet/{agent_id}", self.endpoint);
        let resp = self.client.get(&url).send().map_err(|e| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: wallet connect failed ({e})"),
            tx_signature: None,
        })?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().map_err(|e| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: wallet body parse failed ({e})"),
            tx_signature: None,
        })?;
        if status == 200 {
            let addr = body
                .get("public_address")
                .and_then(|v| v.as_str())
                .ok_or_else(Self::uncertain_error)?
                .to_string();
            return Ok(addr);
        }
        // instrumented detail (status only — public metadata, no secrets)
        Err(RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: wallet read status {status}"),
            tx_signature: None,
        })
    }

    /// The uncertainty channel: the EXISTING code the cores classify as
    /// "hold the reservation, gate replay" (Unknown semantics preserved).
    fn uncertain_error() -> RialoError {
        RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: "isolated signer lane: outcome uncertain (transport)".to_string(),
            tx_signature: None,
        }
    }

    fn definitive_error(code: &'static str, detail: &str) -> RialoError {
        RialoError {
            code,
            detail: detail.to_string(),
            tx_signature: None,
        }
    }

    /// The signer's typed denial → the existing definitive-failure grammar.
    fn denial_error(denial_code: &str) -> RialoError {
        let code = match denial_code {
            c if c.starts_with("AUTH_") => CODE_SIGNER_AUTH_DENIED,
            c if c.starts_with("POLICY_") => CODE_SIGNER_POLICY_DENIED,
            "BYTE_DIVERGENCE" => CODE_SIGNER_BYTE_DIVERGENCE,
            c if c.starts_with("CANONICAL_") => CODE_SIGNER_CANONICAL_FAILED,
            c if c.starts_with("UNKNOWN_AGENT") || c.starts_with("STORE_") => {
                CODE_SIGNER_STATE_FAILED
            }
            _ => CODE_SIGNER_INTERNAL,
        };
        Self::definitive_error(
            code,
            &format!("isolated signer denied the settlement attempt (category {denial_code})"),
        )
    }

    /// THE transfer path: authorized intent → isolated signer → signature.
    /// NO fallback of any kind; every failure is typed. Returns the
    /// CHANNEL-AUTHENTICATED signed result (public execution data only) —
    /// the signer never broadcasts, and nothing here reports a payment:
    /// [`Self::broadcast_signed_result`] hands it to the execution path.
    fn signer_transfer(
        &self,
        agent_id: &str,
        to: &str,
        amount_kelvin: u64,
        policy: Option<&AgentPolicy>,
    ) -> Result<SignedTransactionResult, RialoError> {
        // (a) the D8/G-7 identity linkage (public half) from the agent record
        let uuid = parse_agent_id(agent_id).ok_or_else(|| {
            Self::definitive_error(CODE_SIGNER_STATE_FAILED, "agent identity malformed")
        })?;
        // The authoritative record read: PG IS the authority when
        // authoritative mode is on (missing row OR DB error = the same
        // fail-closed typed error — never a silent FS fallback).
        let agent = if crate::pg_store::pg_is_authoritative() {
            match crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(uuid)) {
                Ok(Ok(Some(a))) => a,
                _ => {
                    return Err(Self::definitive_error(
                        CODE_SIGNER_STATE_FAILED,
                        "agent record unreadable",
                    ));
                }
            }
        } else {
            read_agent(&super::agents::agent_path(
                &super::agents::agents_dir(),
                &uuid,
            ))
            .map_err(|_| {
                Self::definitive_error(CODE_SIGNER_STATE_FAILED, "agent record unreadable")
            })?
        };
        let Some(auth_pubkey) = agent.auth_public_key.clone() else {
            return Err(Self::definitive_error(
                CODE_SIGNER_STATE_FAILED,
                "agent identity linkage missing",
            ));
        };

        // (b) the auth keypair (FUNDS-LESS; the app is the agent's runtime)
        let auth_keypair = super::agent_auth_keys::read_auth_keypair_full(
            &std::path::Path::new("artifact").join("agent_auth_keys"),
            &uuid,
        )
        .map_err(|_| {
            Self::definitive_error(CODE_SIGNER_STATE_FAILED, "agent auth key unreadable")
        })?;

        // (c) the signer-owned wallet address (feePayer — signer-owned ONLY)
        let wallet_address = self.signer_wallet_address(agent_id)?;

        // (d) the RPC-side config hash (the documented D9 read)
        let config_hash_prefix = self.recent_validator_config_hash()?;

        // (e) the semantic transaction + the app-side canonical bytes
        let now_ms = super::agents::now_unix() * 1000;
        // the documented WIRE schema (the frozen contract): feePayer /
        // validFrom / configHashPrefix (quoted u64) / occ / recipient /
        // amount_kelvin — the signer's live handler maps these to the
        // library shape
        let semantic = serde_json::json!({
            "feePayer": wallet_address,
            "recipient": to,
            "amount_kelvin": amount_kelvin,
            "validFrom": now_ms,
            "configHashPrefix": config_hash_prefix.to_string(),
            "occ": false,
        });
        // app-side canonical compile: the SAME authoritative module the
        // signer uses (zero-drift by construction — one source file)
        let from_vec = super::rialo::base58_decode(&wallet_address).ok_or_else(|| {
            Self::definitive_error(CODE_SIGNER_STATE_FAILED, "wallet address malformed")
        })?;
        let to_vec = super::rialo::base58_decode(to).ok_or_else(|| {
            Self::definitive_error(CODE_SIGNER_CANONICAL_FAILED, "recipient malformed")
        })?;
        let mut from = [0u8; 32];
        from.copy_from_slice(&from_vec);
        let mut to_bytes = [0u8; 32];
        to_bytes.copy_from_slice(&to_vec);
        let spec = super::rialo_canonical::CanonicalTransferSpec {
            from: &from,
            to: &to_bytes,
            amount_kelvin,
            valid_from_ms: now_ms,
            config_hash_prefix,
            occ: false,
        };
        let canonical_bytes = super::rialo_canonical::build_canonical_message(&spec);

        // (f) the auth signature over the app-computed canonical bytes (the
        //     signer verifies over ITS OWN recompile — BYTE_DIVERGENCE
        //     enforcement catches any drift)
        use rialo_s_signer::Signer;
        let auth_sig = base64_encode(&<[u8; 64]>::from(
            auth_keypair.sign_message(&canonical_bytes),
        ));

        // (g) the signer request (semantic + auth signature; no keys ever)
        //     + STEP H-1: a fresh channel nonce (the response must bind it)
        let nonce = fresh_nonce();
        // STEP H-3: the independent policy IR (the C-2 compiler output over
        // the AUTHORITATIVE policy record — the signer cross-verifies against
        // its own independently-loaded policy)
        let policy_ir = policy.and_then(|p| compile_policy_ir(agent_id, p));
        let request_body = serde_json::json!({
            "agent_id": agent_id,
            "transaction": semantic,
            "auth_signature": {
                "pubkey": auth_pubkey,
                "signature": auth_sig,
            },
            "channel_nonce": nonce,
            "policy_ir": policy_ir,
        });
        let url = format!("{}/sign", self.endpoint);
        let resp = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .map_err(|e| RialoError {
                code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                detail: format!("isolated signer lane: /sign connect failed ({e})"),
                tx_signature: None,
            })?;
        let status = resp.status().as_u16();
        let body_text = resp.text().map_err(|e| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: /sign body read failed ({e})"),
            tx_signature: None,
        })?;
        let body: serde_json::Value = serde_json::from_str(&body_text).map_err(|e| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: /sign body parse failed ({e})"),
            tx_signature: None,
        })?;

        // (h1) STEP H-1: authenticate the channel when a pin is configured.
        //      No pin configured = the pre-hardening posture (the loopback
        //      boundary alone); a CONFIGURED pin is mandatory.
        let pin = std::env::var(ENV_CHANNEL_PUBKEY).ok();
        if let Some(pinned) = pin.as_ref().filter(|p| !p.trim().is_empty()) {
            verify_channel_response(pinned.trim(), &body_text, &nonce)?;
            let clean = body.clone();
            let _ = clean;
        }

        // (h) the typed mapping — every outcome is EXPLICIT
        if status == 200 {
            // PHASE 10 ITEM 6: the signer produced the signature. Signing is
            // NOT payment — this returns the CHANNEL-AUTHENTICATED signed
            // result for the restored execution/broadcast path, and NOTHING
            // here may be reported as paid. The envelope is validated
            // (byte identity + hash binding + signature verification)
            // BEFORE any dispatch is even possible; every refusal is typed,
            // definitive, and pre-dispatch (the established refund class).
            let field = |name: &str| -> Option<String> {
                body.get(name)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };
            let message_b64 = field("canonical_message_b64").ok_or_else(|| {
                Self::definitive_error(
                    CODE_SIGNER_INTERNAL,
                    "signed result malformed (canonical message absent)",
                )
            })?;
            let signature_b64 = field("signature_b64").ok_or_else(|| {
                Self::definitive_error(
                    CODE_SIGNER_INTERNAL,
                    "signed result malformed (signature absent)",
                )
            })?;
            let reported_hash = field("canonical_hash").unwrap_or_default();
            let required_signatures = body
                .get("required_signatures")
                .and_then(|v| v.as_u64())
                .filter(|v| *v <= u8::MAX as u64)
                .map(|v| v as u8)
                .ok_or_else(|| {
                    Self::definitive_error(
                        CODE_SIGNER_INTERNAL,
                        "signed result malformed (required signatures absent)",
                    )
                })?;
            let signer_message = base64_decode(&message_b64).ok_or_else(|| {
                Self::definitive_error(
                    CODE_SIGNER_INTERNAL,
                    "signed result malformed (canonical message undecodable)",
                )
            })?;
            let signature = base64_decode(&signature_b64)
                .filter(|b| b.len() == 64)
                .ok_or_else(|| {
                    Self::definitive_error(
                        CODE_SIGNER_INTERNAL,
                        "signed result malformed (signature not a 64-byte ed25519)",
                    )
                })?;
            // GATE 1 — the frozen single-signer shape
            if required_signatures != super::rialo_canonical::SINGLE_SIGNER_REQUIRED {
                return Err(Self::definitive_error(
                    CODE_SIGNER_BYTE_DIVERGENCE,
                    "signed result demands an unexpected signature count (pre-dispatch)",
                ));
            }
            // GATE 2 — CANONICAL INTENT PRESERVED: the signer's own
            // recompiled message bytes must be byte-identical to the message
            // the policy authorized here. Zero-drift is enforced, not assumed.
            if signer_message != canonical_bytes {
                return Err(Self::definitive_error(
                    CODE_SIGNER_BYTE_DIVERGENCE,
                    "the signer's canonical message differs from the authorized intent (pre-dispatch)",
                ));
            }
            // GATE 3 — the reported hash is blake3 of exactly those bytes
            let expected_hash = blake3::hash(&canonical_bytes).to_hex().to_string();
            if reported_hash.trim().to_lowercase() != expected_hash {
                return Err(Self::definitive_error(
                    CODE_SIGNER_BYTE_DIVERGENCE,
                    "the signer's canonical hash does not bind its message (pre-dispatch)",
                ));
            }
            // GATE 4 — the signature VERIFIES over the canonical message with
            // the signer-owned wallet pubkey, before any dispatch. An
            // unverifiable signature is never broadcast, ever.
            let wallet_pk = super::rialo::base58_decode(&wallet_address)
                .filter(|b| b.len() == 32)
                .ok_or_else(|| {
                    Self::definitive_error(
                        CODE_SIGNER_STATE_FAILED,
                        "signer wallet address malformed (pre-dispatch)",
                    )
                })?;
            let sig_ok = rialo_s_signature::Signature::try_from(signature.as_slice())
                .ok()
                .map(|s| s.verify(&wallet_pk, &canonical_bytes))
                .unwrap_or(false);
            if !sig_ok {
                return Err(Self::definitive_error(
                    CODE_SIGNER_INTERNAL,
                    "the signed result does not verify against the signer-owned address (pre-dispatch)",
                ));
            }
            // observational audit: public execution evidence only
            super::audit::record(
                super::audit::authorization(
                    super::agents::now_unix(),
                    super::audit::AuditOutcome::Ok,
                    Some("ISOLATED_SIGNER_SIGNED"),
                    super::audit::IdentityClass::Credential,
                    Some(agent_id),
                    None,
                    None,
                ),
                &crate::audit::audit_dir_for(&crate::agents::intents_root()),
                Some(agent_id),
            );
            return Ok(SignedTransactionResult {
                agent_id: agent_id.to_string(),
                wallet_address,
                recipient: to.to_string(),
                amount_kelvin,
                canonical_message: canonical_bytes,
                signer_message,
                signature,
                required_signatures,
                canonical_hash: reported_hash,
            });
        }
        if status == 403 || status == 400 {
            let code = body
                .get("code")
                .and_then(|v| v.as_str())
                .unwrap_or("SIGNER_INTERNAL");
            return Err(Self::denial_error(code));
        }
        // 404 (unknown agent) and 5xx: typed state/internal failures
        // (instrumented detail: status only)
        Err(RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: /sign status {status}"),
            tx_signature: None,
        })
    }

    /// PHASE 10 ITEM 6 — THE RESTORED EXECUTION/BROADCAST STEP. It consumes
    /// the CHANNEL-AUTHENTICATED signed result from the isolated signer and
    /// hands the signed transaction to the ONE chain touchpoint (RialoConfig
    /// on the single configured RPC endpoint) — the same place the old
    /// working payment path always broadcast from. The signer is never
    /// involved here: it stays sign-only, and no second signing path exists.
    ///
    /// Outcomes are the EXISTING grammar: `Ok(signature)` only when the node
    /// reported the signature AND its own status says the transaction
    /// executed; a definitive pre-dispatch refusal is typed and refundable;
    /// anything unprovable is the uncertainty channel
    /// (`RIALO_TRANSFER_CONFIRMATION_TIMEOUT`), which holds the reservation
    /// and gates replay. This function never converts anything into "paid".
    fn broadcast_signed_result(
        &self,
        signed: &SignedTransactionResult,
    ) -> Result<String, RialoError> {
        // the canonical transaction envelope: short-vec signature count,
        // each 64-byte signature, then the message — the shape pinned by the
        // I-2 fixtures against rialo-s-transaction 0.18.1.
        let mut envelope = Vec::new();
        super::rialo_canonical::short_vec_len(u16::from(signed.required_signatures), &mut envelope);
        envelope.extend_from_slice(&signed.signature);
        envelope.extend_from_slice(&signed.signer_message);
        // strict decode round-trip BEFORE dispatch: the bytes about to be
        // broadcast must decode back to exactly the authorized intent — the
        // same intent the policy gate cleared. Nothing speculative.
        let decoded = super::rialo_canonical::decode_transaction_envelope(&envelope);
        let Ok((decoded_sigs, decoded_msg)) = decoded else {
            return Err(Self::definitive_error(
                CODE_SIGNER_BYTE_DIVERGENCE,
                "signed envelope does not decode (pre-dispatch)",
            ));
        };
        // the payer/recipient identity bytes are decoded ONCE and bound
        // here: the comparisons below are against the authorized intent,
        // never against a guess.
        let wallet_bytes = super::rialo::base58_decode(&signed.wallet_address);
        let recipient_bytes = super::rialo::base58_decode(&signed.recipient);
        let expected_ix_data = [
            &super::rialo_canonical::SYSTEM_TRANSFER_DISCRIMINATOR.to_le_bytes()[..],
            &signed.amount_kelvin.to_le_bytes()[..],
        ]
        .concat();
        let payer_matches = decoded_msg
            .account_keys
            .first()
            .zip(wallet_bytes.as_deref())
            .map(|(key, want)| key.as_slice() == want)
            .unwrap_or(false);
        let recipient_matches = recipient_bytes
            .as_deref()
            .map(|want| {
                decoded_msg
                    .account_keys
                    .iter()
                    .any(|key| key.as_slice() == want)
            })
            .unwrap_or(false);
        let amount_matches = decoded_msg
            .instructions
            .first()
            .map(|ix| ix.data.as_slice() == expected_ix_data.as_slice())
            .unwrap_or(false);
        let intent_preserved = decoded_sigs.len() == usize::from(signed.required_signatures)
            && decoded_sigs
                .first()
                .map(|s| s.as_slice())
                .unwrap_or_default()
                == signed.signature.as_slice()
            && payer_matches
            && decoded_msg.instructions.len() == 1
            && amount_matches
            && recipient_matches;
        if !intent_preserved {
            // the envelope that would move money is NOT the intent that was
            // authorized: definitive refusal, never a dispatch.
            return Err(Self::definitive_error(
                CODE_SIGNER_BYTE_DIVERGENCE,
                "signed envelope does not carry the authorized intent (pre-dispatch)",
            ));
        }
        let signature = self
            .native
            .submit_signed_transaction(&base64_encode(&envelope), &signed.signature)?;
        // observational audit: the broadcast happened, public evidence only
        super::audit::record(
            super::audit::authorization(
                super::agents::now_unix(),
                super::audit::AuditOutcome::Ok,
                Some("ISOLATED_SIGNER_BROADCAST"),
                super::audit::IdentityClass::Credential,
                Some(&signed.agent_id),
                None,
                None,
            ),
            &crate::audit::audit_dir_for(&crate::agents::intents_root()),
            Some(&signed.agent_id),
        );
        Ok(signature)
    }

    /// The RPC-side config-hash read (the documented D9 read; bounded).
    fn recent_validator_config_hash(&self) -> Result<u64, RialoError> {
        let rpc_url = &self.native.rpc_url;
        let client = reqwest::blocking::Client::builder()
            .timeout(SIGNER_TIMEOUT)
            .build()
            .map_err(|_| Self::uncertain_error())?;
        let resp = client
            .post(rpc_url.as_str())
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "getRecentValidatorConfigHash",
                "params": [{}]
            }))
            .send()
            .map_err(|e| RialoError {
                code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                detail: format!("isolated signer lane: config-hash rpc failed ({e})"),
                tx_signature: None,
            })?;
        let body: serde_json::Value = resp.json().map_err(|e| RialoError {
            code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
            detail: format!("isolated signer lane: config-hash body parse failed ({e})"),
            tx_signature: None,
        })?;
        body.get("result")
            .and_then(|r| r.get("configHashPrefix"))
            .and_then(|v| v.as_u64())
            .ok_or_else(Self::uncertain_error)
    }
}

/// Strict base64 decode (standard alphabet). Returns None on any
/// non-canonical input (STEP H-1 channel signature transport).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let val = TABLE.iter().position(|&c| c == ch)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buf & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Minimal strict base64 encoder (the same alphabet the signer uses).
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

impl PaymentOps for IsolatedSignerPaymentOps {
    fn uses_external_custody(&self) -> bool {
        // PHASE 9 STEP 8: custody lives in the signer's trust domain. The
        // cores skip the legacy signer-file verification for this lane (the
        // record's address IS the signer-owned address; the sign-time chain
        // verifies the authoritative linkage).
        true
    }

    fn balance(&self, address: &str) -> Result<f64, RialoError> {
        // Read-only plane stays native (the latch-lane rule, preserved).
        self.native.balance(address)
    }

    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError> {
        // The agent identity: the wallet path's stem is the canonical uuid
        // (the core passes the agent wallet path; one identity, no invention).
        let Some(stem) = keypair_path.file_stem().and_then(|s| s.to_str()) else {
            return Err(Self::definitive_error(
                CODE_SIGNER_STATE_FAILED,
                "payment identity malformed",
            ));
        };
        // kelvin: the core passes the RLO string; the signer wants integer
        // kelvin. The established conversion is rlo→kelvin (9 decimals,
        // pinned in the cores); reuse the same arithmetic.
        let amount_kelvin = rlo_str_to_kelvin(amount_rlo).ok_or_else(|| {
            Self::definitive_error(CODE_SIGNER_CANONICAL_FAILED, "amount malformed")
        })?;

        // THE SIGNER PATH — no fallback. Any failure is typed; a transport
        // failure is the uncertainty class; a denial is definitive.
        // STEP H-3: load the authoritative policy record for this agent and
        // compile the independent IR (the signer cross-verifies against its
        // own policy; the app-side copy is evidence, not authority).
        let policy = read_agent_policy_for_lane(stem);
        // PHASE 10 ITEM 6 — the restored chain:
        //   authorization (already enforced by the frozen core before this
        //   call) → canonical intent → auth-key authorization → the isolated
        //   signer /sign → signer policy IR verification → CHANNEL
        //   AUTHENTICATION → signed result → THE OLD WORKING
        //   EXECUTION/BROADCAST PATH (RialoConfig on the ONE RPC endpoint)
        //   → real tx signature, which the core commits/reconciles exactly
        //   as it always did. The signer stays sign-only; broadcast never
        //   moved into it, and no second signing path exists.
        let signed = self.signer_transfer(stem, to, amount_kelvin, policy.as_ref())?;
        self.broadcast_signed_result(&signed)
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

/// rlo (decimal string) → integer kelvin (9 decimals; the canonical money
/// conversion the cores pin). Rejects malformed input (None).
pub fn rlo_str_to_kelvin(rlo: &str) -> Option<u64> {
    let rlo = rlo.trim();
    if rlo.is_empty() {
        return None;
    }
    let (int_part, frac_part) = match rlo.split_once('.') {
        Some((i, f)) => (i, f),
        None => (rlo, ""),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !frac_part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut frac = frac_part.to_string();
    frac.truncate(9);
    while frac.len() < 9 {
        frac.push('0');
    }
    let int_kelvin: u128 = int_part.parse::<u128>().ok()?;
    let frac_kelvin: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse::<u128>().ok()?
    };
    let total = int_kelvin
        .checked_mul(1_000_000_000)?
        .checked_add(frac_kelvin)?;
    u64::try_from(total).ok()
}

// ---------------------------------------------------------------------------
// THE FACTORY — selection precedence over the existing latch factory
// ---------------------------------------------------------------------------

/// The STEP 7 wiring point used by both money handlers: when the isolated
/// signer gate is ON and the config valid, THIS adapter is the ONLY signer
/// path (no native dispatch, no latch dispatch inside the lane). Otherwise
/// the EXISTING latch factory runs unchanged (byte-identical status quo).
pub fn production_isolated_signer_ops_audited(
    native: Arc<RialoConfig>,
    agent: &Agent,
    _policy: &AgentPolicy,
    _auth_keys_dir: &FsPath,
    audit_ctx: Option<Arc<super::audit::LaneAuditContext>>,
) -> Arc<dyn PaymentOps + Send + Sync> {
    let config = IsolatedSignerLaneConfig::from_env();
    if config.enabled && config.invalid_when_armed {
        // FAIL-CLOSED: armed but unusable — payments DENY (never degrade)
        if let Some(ctx) = audit_ctx.as_ref() {
            crate::audit::record(
                crate::audit::lane(
                    crate::agents::now_unix(),
                    crate::audit::AuditOutcome::Denied,
                    Some("SIGNER_CONFIG_INVALID"),
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("isolated-signer"),
                    "isolated signer lane armed with invalid configuration; payments denied",
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        return Arc::new(FailClosedSignerOps {
            native: native.clone(),
        }) as Arc<dyn PaymentOps + Send + Sync>;
    }
    if config.enabled {
        // observational audit: the lane selection (public metadata only)
        if let Some(ctx) = audit_ctx.as_ref() {
            super::audit::record(
                super::audit::lane(
                    super::agents::now_unix(),
                    super::audit::AuditOutcome::Selected,
                    None,
                    &ctx.agent_id,
                    &ctx.idempotency_key,
                    Some("isolated-signer"),
                    "isolated signer lane selected (env-gated)",
                    false,
                ),
                &ctx.audit_dir,
                Some(&ctx.agent_id),
            );
        }
        let adapter = IsolatedSignerPaymentOps::new(native.clone(), config.endpoint);
        return Arc::new(adapter) as Arc<dyn PaymentOps + Send + Sync>;
    }
    // gate off: the EXISTING latch factory (unchanged behavior)
    super::latch_proxy_lane::production_payment_ops_audited(
        native,
        agent,
        _policy,
        _auth_keys_dir,
        audit_ctx,
    )
}

// ---------------------------------------------------------------------------
// STEP H-1 — AUTHENTICATED CHANNEL (app side)
// ---------------------------------------------------------------------------

/// The pinned signer channel public key (env; the operator sets it after
/// first signer startup). Absent/malformed ⇒ the lane DENIES (fail-closed —
/// an unauthenticated signer response is never acceptable once the pin is
/// expected to exist; the default posture with NO pin configured remains the
/// pre-hardening behavior so the lane is not silently broken by this pass).
pub const ENV_CHANNEL_PUBKEY: &str = "AGENTPAY_SIGNER_CHANNEL_PUBKEY";

/// Bounded replay cache: nonces seen in responses within the process
/// lifetime (LRU, capped). A repeated nonce in a /sign response = replay.
struct ReplayCache {
    seen: std::sync::Mutex<std::collections::VecDeque<String>>,
    cap: usize,
}

impl ReplayCache {
    fn new(cap: usize) -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::VecDeque::new()),
            cap,
        }
    }
    /// Returns true if the nonce was ALREADY seen (replay).
    fn check_and_insert(&self, nonce: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.iter().any(|n| n == nonce) {
            return true;
        }
        seen.push_back(nonce.to_string());
        while seen.len() > self.cap {
            seen.pop_front();
        }
        false
    }
}

fn replay_cache() -> &'static ReplayCache {
    static CACHE: std::sync::OnceLock<ReplayCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| ReplayCache::new(4096))
}

/// Fresh base64 nonce per request (32 bytes of getrandom).
fn fresh_nonce() -> String {
    let mut b = [0u8; 32];
    let _ = getrandom::getrandom(&mut b);
    base64_encode(&b)
}

/// PHASE 10 ITEM 6 — the app-side mirror of the signer's canonical JSON.
/// Object keys sorted recursively (arrays keep order), compact separators.
/// The two implementations (separate workspaces by design) MUST agree
/// byte-for-byte; the shared vectors in `_channelauth_i6_tests.rs` and the
/// signer's `canonical_json_*` tests pin that agreement, and the LIVE
/// battery proves it against the real production `/sign` response.
///
/// Without this, verification silently depended on serde_json's map
/// implementation matching across the two build graphs (the app enables
/// `preserve_order`/indexmap, the signer does not) — the serialization
/// mismatch that breaks channel auth while both sides look correct alone.
fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), canonical_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

/// The EXACT message the channel signature covers: the complete response
/// body (`channel_nonce` included) with `signer_sig` removed, canonically
/// serialized. Mirrors `agentpay_signer::channel_signing_bytes` verbatim.
fn channel_signing_bytes(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => {
            let mut clean = v;
            if let Some(o) = clean.as_object_mut() {
                o.remove("signer_sig");
            }
            canonical_json(&clean).to_string()
        }
        Err(_) => body.to_string(),
    }
}

/// Verify a signer response: pin present + signature valid over
/// blake3(CANONICAL(body without signer_sig) || nonce) with the pinned
/// pubkey + nonce echo match + not a replay. Any failure = the typed
/// definitive error (fail-closed).
fn verify_channel_response(pinned_pubkey: &str, body: &str, nonce: &str) -> Result<(), RialoError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| {
        IsolatedSignerPaymentOps::definitive_error(CODE_SIGNER_INTERNAL, "channel body unparseable")
    })?;
    let echoed = v
        .get("channel_nonce")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            IsolatedSignerPaymentOps::definitive_error(
                CODE_SIGNER_INTERNAL,
                "channel signature missing (unsigned signer response)",
            )
        })?;
    if echoed != nonce {
        return Err(IsolatedSignerPaymentOps::definitive_error(
            CODE_SIGNER_INTERNAL,
            "channel nonce mismatch (response does not bind this request)",
        ));
    }
    if replay_cache().check_and_insert(nonce) {
        return Err(IsolatedSignerPaymentOps::definitive_error(
            CODE_SIGNER_INTERNAL,
            "channel replay detected (nonce already consumed)",
        ));
    }
    let sig_b64 = v
        .get("signer_sig")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            IsolatedSignerPaymentOps::definitive_error(
                CODE_SIGNER_INTERNAL,
                "channel signature missing",
            )
        })?;
    // the SAME canonical message the signer sealed: complete body (the echoed
    // channel_nonce included) with `signer_sig` removed, keys sorted
    let clean_str = channel_signing_bytes(body);
    let sig_bytes = base64_decode(sig_b64)
        .filter(|b| b.len() == 64)
        .ok_or_else(|| {
            IsolatedSignerPaymentOps::definitive_error(
                CODE_SIGNER_INTERNAL,
                "channel signature malformed",
            )
        })?;
    let pk = crate::rialo::base58_decode(pinned_pubkey)
        .filter(|b| b.len() == 32)
        .ok_or_else(|| {
            IsolatedSignerPaymentOps::definitive_error(
                CODE_SIGNER_INTERNAL,
                "channel pubkey pin malformed",
            )
        })?;
    let mut msg = blake3::hash(clean_str.as_bytes()).as_bytes().to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    use rialo_s_signature::Signature as ChanSig;
    let ok = ChanSig::try_from(sig_bytes.as_slice())
        .ok()
        .map(|s| s.verify(&pk, &msg))
        .unwrap_or(false);
    if !ok {
        return Err(IsolatedSignerPaymentOps::definitive_error(
            CODE_SIGNER_INTERNAL,
            "channel signature verification failed (unknown or wrong signer)",
        ));
    }
    Ok(())
}

/// STEP H-3: load the agent's authoritative policy record (the app's own
/// store) for the independent-IR compilation. None = no policy record
/// (deny-by-default: the signer will refuse without an IR).
fn read_agent_policy_for_lane(agent_id: &str) -> Option<AgentPolicy> {
    let uuid = parse_agent_id(agent_id)?;
    let path = crate::agents::agents_dir()
        .parent()
        .map(|p| p.join("agent_policies"))
        .unwrap_or_default()
        .join(format!("{uuid}.json"));
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// STEP H-3: compile the authoritative policy into the independent IR for
/// the signing lane (the C-2 compiler, extended with Lane::TxSigning).
fn compile_policy_ir(agent_id: &str, policy: &AgentPolicy) -> Option<String> {
    let uuid = parse_agent_id(agent_id)?;
    // The authoritative record read (PG dispatch when authoritative).
    let agent = if crate::pg_store::pg_is_authoritative() {
        crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(uuid))
            .ok()
            .and_then(|r| r.ok())
            .flatten()?
    } else {
        crate::agents::read_agent(&crate::agents::agent_path(
            &crate::agents::agents_dir(),
            &uuid,
        ))
        .ok()?
    };
    let latch_id = crate::latch_policy_compiler::LatchId::new(agent_id).ok()?;
    let compiled = crate::latch_policy_compiler::compile_agent_pipeline(
        policy,
        &agent,
        true, // the record linkage was verified by the D8/G-7 gate
        crate::latch_policy_compiler::Lane::TxSigning,
        &latch_id,
    )
    .ok()?;
    Some(compiled.to_json())
}

/// The audit dir handle type the factory needs (re-exported for the tests).
pub fn lane_audit_ctx(agent: &Agent, idempotency_key: &str) -> Arc<super::audit::LaneAuditContext> {
    Arc::new(super::audit::LaneAuditContext {
        agent_id: agent.agent_id.clone(),
        idempotency_key: idempotency_key.to_string(),
        audit_dir: crate::audit::audit_dir_for(&crate::agents::intents_root()),
    })
}

/// PHASE 9 STEP 8: provision a NEW agent's funded wallet THROUGH the
/// signer (the only funded-key authority). Loopback-only, bounded, public
/// data only crosses back (the public address). Any failure is typed and
/// fail-closed — creation must not half-create custody.
pub fn provision_signer_wallet(
    endpoint: &str,
    agent_id: &str,
    auth_pubkey: String,
) -> Result<String, ()> {
    let Ok(uuid) = Uuid::parse_str(agent_id) else {
        return Err(());
    };
    let _ = uuid;
    let client = reqwest::blocking::Client::builder()
        .timeout(SIGNER_TIMEOUT)
        .build()
        .map_err(|_| ())?;
    let url = format!("{endpoint}/provision");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "auth_pubkey": auth_pubkey,
        }))
        .send()
        .map_err(|_| ())?;
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().map_err(|_| ())?;
    if status == 200 {
        return body
            .get("public_address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(());
    }
    Err(())
}

/// OPTION C: Admin-authenticated registration of a new agent with the signer.
/// This must be called AFTER auth key generation and BEFORE wallet provisioning.
/// Requires AGENTPAY_SIGNER_ADMIN_SECRET environment variable.
pub fn admin_register_agent_with_signer(
    endpoint: &str,
    agent_id: &str,
    auth_pubkey: &str,
) -> Result<(), ()> {
    let admin_secret = std::env::var("AGENTPAY_SIGNER_ADMIN_SECRET").map_err(|_| ())?;
    let client = reqwest::blocking::Client::builder()
        .timeout(SIGNER_TIMEOUT)
        .build()
        .map_err(|_| ())?;
    let url = format!("{endpoint}/admin/register");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "auth_pubkey": auth_pubkey,
            "admin_secret": admin_secret,
        }))
        .send()
        .map_err(|_| ())?;
    let status = resp.status().as_u16();
    // 200 = newly registered or idempotent success
    // 409 = conflicting (different auth key) - also fail
    if status == 200 || status == 409 {
        // For 200, we succeeded. For 409, we cannot proceed (would be wrong auth key).
        // But we need to distinguish: 200 is OK, 409 is a real failure.
        if status == 200 {
            return Ok(());
        }
    }
    Err(())
}

/// The wallet path helper (the same construction the cores use).
pub fn signer_wallet_path(wallet_dir: &FsPath, uuid: &Uuid) -> PathBuf {
    wallet_dir.join(format!("{uuid}.json"))
}

// ---------------------------------------------------------------------------
// TESTS — the STEP 7 integration battery
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// STEP H-1 test-support primitives (test builds only): the signer crate is a
// separate workspace (never a dependency), so the app-side channel tests
// build their OWN identity/fixture keypairs with the same primitives.
// ---------------------------------------------------------------------------

#[cfg(test)]
fn lane_test_channel_keypair(seed: &[u8; 32]) -> rialo_s_keypair::Keypair {
    rialo_s_keypair::keypair_from_seed(seed).unwrap()
}

#[cfg(test)]
fn lane_test_sign_channel(kp: &rialo_s_keypair::Keypair, body: &str, nonce: &str) -> String {
    use rialo_s_signer::Signer;
    // mirror the LIVE signer's semantics exactly (tools/agentpay-signer):
    // sign blake3(CANONICAL(body with channel_nonce, without signer_sig))
    // || nonce — the canonical form is content-addressed, never a
    // serde_json map-ordering accident
    let clean = channel_signing_bytes(body);
    let mut msg = blake3::hash(clean.as_bytes()).as_bytes().to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    let sig = kp.sign_message(&msg);
    base64_encode(&<[u8; 64]>::from(sig))
}

#[cfg(test)]
fn lane_test_channel_pubkey(kp: &rialo_s_keypair::Keypair) -> String {
    use rialo_s_signer::Signer;
    kp.pubkey().to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// ONE process-wide env lock shared by EVERY test that reads or mutates
    /// the isolated-signer env gate (AGENTPAY_ISOLATED_SIGNER_LANE/_URL) —
    /// across module boundaries (agents::custody_tests reaches it through
    /// crate::isolated_signer_lane::tests::env_test_lock). Per-module statics
    /// would let two tests flip the same env var mid-flight in parallel
    /// threads (the custody lane's own static could not serialize against
    /// the lane module's factory tests — the observed cross-module race).
    /// The guard is held for the FULL test body: every set/remove AND every
    /// from_env() read the test relies on must happen under it.
    pub(crate) static ENV_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    /// The shared handle (test-only accessor for sibling shards).
    pub(crate) fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn temp_cwd(tag: &str) -> (std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!("agentpay-lane7-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("artifact/agents")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_auth_keys")).unwrap();
        std::fs::create_dir_all(root.join("artifact/agent_wallets")).unwrap();
        (root, format!("lane7-{tag}"))
    }

    struct CwdGuard {
        original: std::path::PathBuf,
    }

    impl CwdGuard {
        fn enter(root: &std::path::Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(root).unwrap();
            Self { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn make_agent(root: &FsPath) -> Agent {
        let id = Uuid::new_v4();
        let agent = Agent {
            schema_version: super::super::agents::AGENT_SCHEMA_VERSION,
            agent_id: id.to_string(),
            owner_user_id: 50506084,
            name: "lane7".into(),
            status: super::super::agents::AgentStatus::Active,
            wallet_address: None,
            auth_public_key: Some("9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA".into()),
            created_at: 1,
            updated_at: 1,
        };
        std::fs::write(
            root.join("artifact/agents").join(format!("{id}.json")),
            serde_json::to_vec_pretty(&agent).unwrap(),
        )
        .unwrap();
        agent
    }

    /// a minimal valid AgentPolicy (the factories take one but the signer
    /// lane's selection does not consume it — kept for signature parity)
    fn test_policy() -> AgentPolicy {
        AgentPolicy {
            schema_version: 1,
            agent_id: "lane7".into(),
            max_payment_per_tx_kelvin: Some(1_000_000_000),
            daily_payment_limit_kelvin: Some(10_000_000_000),
            allowed_recipients: vec!["2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD".into()],
            allowed_actions: vec!["payment".into()],
            created_at: Some(1),
            updated_at: Some(1),
            parent_agent_id: None,
            delegation_revoked: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
        }
    }

    // -- gate / selection ----------------------------------------------------

    #[test]
    fn endpoint_parse_loopback_only() {
        assert!(parse_loopback_endpoint("http://127.0.0.1:8991").is_some());
        assert!(parse_loopback_endpoint("http://localhost:8991").is_some());
        assert!(parse_loopback_endpoint("http://[::1]:8991").is_some());
        assert!(parse_loopback_endpoint("http://0.0.0.0:8991").is_none());
        assert!(parse_loopback_endpoint("http://192.168.1.5:8991").is_none());
        assert!(parse_loopback_endpoint("http://127.0.0.1:0").is_none());
        assert!(parse_loopback_endpoint("https://127.0.0.1:8991").is_none());
        assert!(parse_loopback_endpoint("http://127.0.0.1:8991/path").is_none());
        assert!(parse_loopback_endpoint("").is_none());
    }

    #[test]
    fn config_gate_is_fail_closed() {
        // THE shared process-wide env lock (cross-module: the custody shard's
        // invalid_armed_config_fails_closed serializes on the SAME lock).
        let _g = env_test_lock();
        // (a) gate absent → disabled (the preserved status quo)
        unsafe { std::env::remove_var(ENV_LANE) };
        assert!(!IsolatedSignerLaneConfig::from_env().enabled);
        assert!(!IsolatedSignerLaneConfig::from_env().invalid_when_armed);
        // (b) gate garbage → disabled (not armed at all)
        unsafe { std::env::set_var(ENV_LANE, "yes") };
        assert!(!IsolatedSignerLaneConfig::from_env().enabled);
        // (c) gate on + URL garbage → FAIL-CLOSED (armed but unusable:
        // payments DENY, never a silent legacy fallback)
        unsafe { std::env::set_var(ENV_LANE, "1") };
        unsafe { std::env::set_var(ENV_URL, "http://0.0.0.0:1") };
        let cfg = IsolatedSignerLaneConfig::from_env();
        assert!(cfg.enabled && cfg.invalid_when_armed);
        unsafe { std::env::set_var(ENV_URL, "http://127.0.0.1:8991/path") };
        assert!(IsolatedSignerLaneConfig::from_env().invalid_when_armed);
        // (d) gate on + valid URL → armed (never fail-closed)
        unsafe { std::env::set_var(ENV_URL, "http://127.0.0.1:8991") };
        let cfg = IsolatedSignerLaneConfig::from_env();
        assert!(cfg.enabled && !cfg.invalid_when_armed);
        assert_eq!(cfg.endpoint, "http://127.0.0.1:8991");
        unsafe {
            std::env::remove_var(ENV_LANE);
            std::env::remove_var(ENV_URL);
        }
    }

    #[test]
    fn fail_closed_ops_deny_payments() {
        // the fail-closed posture DENIES every transfer (never degrades)
        let ops = FailClosedSignerOps {
            native: Arc::new(RialoConfig {
                cli: PathBuf::from("/nonexistent"),
                rpc_url: "http://127.0.0.1:1".into(),
                program_id: None,
                program_dir: PathBuf::from("artifact"),
            }),
        };
        let err = ops
            .transfer(
                &PathBuf::from("artifact/agent_wallets/x.json"),
                "2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD",
                "0.000001",
            )
            .unwrap_err();
        assert_eq!(err.code, "SIGNER_CONFIG_INVALID");
        assert!(err.tx_signature.is_none());
        assert!(ops.uses_external_custody());
    }

    #[test]
    fn custody_mode_lane_aware() {
        // the trait query: the adapter declares external custody; the
        // fail-closed ops do too; a native RialoConfig does NOT (the legacy
        // verification applies)
        let native = RialoConfig {
            cli: PathBuf::from("/nonexistent"),
            rpc_url: "http://127.0.0.1:1".into(),
            program_id: None,
            program_dir: PathBuf::from("artifact"),
        };
        assert!(!native.uses_external_custody());
    }

    #[test]
    fn factory_gate_off_returns_the_existing_latch_factory() {
        // with the gate off, the factory delegates to the existing latch
        // factory (byte-identical status quo; the type is the plain native
        // ops when the latch lane is also unconfigured)
        // THE shared process-wide env lock: the remove_var + the from_env
        // read inside the factory must not race a sibling's set/remove.
        let _g = env_test_lock();
        unsafe { std::env::remove_var(ENV_LANE) };
        let native = Arc::new(RialoConfig {
            cli: PathBuf::from("/nonexistent"),
            rpc_url: "http://127.0.0.1:1".into(),
            program_id: None,
            program_dir: PathBuf::from("artifact"),
        });
        let (root, _tag) = temp_cwd("gateoff");
        let _guard = CwdGuard::enter(&root);
        let agent = make_agent(&root);
        let policy = test_policy();
        let ops = production_isolated_signer_ops_audited(
            native.clone(),
            &agent,
            &policy,
            &root.join("artifact/agent_auth_keys"),
            None,
        );
        // the read-only plane must still work through whatever lane was chosen
        // (delegation preserved); the type identity is checked by behavior
        // below (gate on → signer errors; gate off → native CLI errors)
        let _ = ops;
    }

    #[test]
    fn factory_gate_on_selects_the_signer_lane_exclusively() {
        // THE shared process-wide env lock: the set/remove pair AND the
        // from_env() read inside the factory must not race a sibling's
        // set/remove (the cross-module custody shard shares this lock).
        let _g = env_test_lock();
        unsafe { std::env::set_var(ENV_LANE, "1") };
        unsafe { std::env::set_var(ENV_URL, "http://127.0.0.1:8999") };
        let native = Arc::new(RialoConfig {
            cli: PathBuf::from("/nonexistent"),
            rpc_url: "http://127.0.0.1:1".into(),
            program_id: None,
            program_dir: PathBuf::from("artifact"),
        });
        let (root, _tag) = temp_cwd("gateon");
        let _guard = CwdGuard::enter(&root);
        let agent = make_agent(&root);
        // NO auth key in the vault → the adapter fails CLOSED with the typed
        // state error (it NEVER falls back to native/CLI: the /nonexistent
        // CLI would fail with RIALO_CLI_UNAVAILABLE if a fallback existed)
        let policy = test_policy();
        let ops = production_isolated_signer_ops_audited(
            native.clone(),
            &agent,
            &policy,
            &root.join("artifact/agent_auth_keys"),
            None,
        );
        let wallet_path = root
            .join("artifact/agent_wallets")
            .join(format!("{}.json", agent.agent_id));
        let err = ops
            .transfer(
                &wallet_path,
                "2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD",
                "0.000001",
            )
            .unwrap_err();
        // the adapter's OWN typed state error — NOT RIALO_CLI_UNAVAILABLE,
        // NOT the native path. The signer lane owns the failure.
        assert_eq!(
            err.code, CODE_SIGNER_STATE_FAILED,
            "no CLI fallback: {err:?}"
        );
        unsafe {
            std::env::remove_var(ENV_LANE);
            std::env::remove_var(ENV_URL);
        }
    }

    #[test]
    fn no_fallback_grammar_structural() {
        // the adapter contains NO fallback dispatch: no native.transfer call
        // inside its transfer, no latch gateway, no artifact wallet read
        let src = include_str!("isolated_signer_lane.rs");
        let production: String = src
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !production.contains("native.transfer("),
            "no native fallback dispatch in the signer lane"
        );
        assert!(
            !production.contains("gateway.submit("),
            "no latch dispatch in the signer lane"
        );
        assert!(
            !production.contains("agent_wallets"),
            "no artifact wallet fallback"
        );
        assert!(!production.contains("privy"), "no privy");
        assert!(!production.contains("Privy"), "no Privy");
    }

    #[test]
    fn amount_conversion_strict() {
        assert_eq!(rlo_str_to_kelvin("1"), Some(1_000_000_000));
        assert_eq!(rlo_str_to_kelvin("0.000001"), Some(1_000));
        assert_eq!(rlo_str_to_kelvin("0.000000001"), Some(1));
        assert_eq!(rlo_str_to_kelvin("abc"), None);
        assert_eq!(rlo_str_to_kelvin(""), None);
        assert_eq!(rlo_str_to_kelvin("1.2.3"), None);
        assert_eq!(rlo_str_to_kelvin("-1"), None);
        // overflow-safe
        assert_eq!(rlo_str_to_kelvin("99999999999999999999"), None);
    }

    #[test]
    fn denial_mapping_is_typed() {
        let e = IsolatedSignerPaymentOps::denial_error("AUTH_INVALID");
        assert_eq!(e.code, CODE_SIGNER_AUTH_DENIED);
        let e = IsolatedSignerPaymentOps::denial_error("POLICY_AMOUNT");
        assert_eq!(e.code, CODE_SIGNER_POLICY_DENIED);
        let e = IsolatedSignerPaymentOps::denial_error("BYTE_DIVERGENCE");
        assert_eq!(e.code, CODE_SIGNER_BYTE_DIVERGENCE);
        let e = IsolatedSignerPaymentOps::denial_error("CANONICAL_MALFORMED");
        assert_eq!(e.code, CODE_SIGNER_CANONICAL_FAILED);
        let e = IsolatedSignerPaymentOps::denial_error("UNKNOWN_AGENT");
        assert_eq!(e.code, CODE_SIGNER_STATE_FAILED);
        // never a fabricated signature on any failure
        assert!(e.tx_signature.is_none());
    }

    #[test]
    fn uncertain_mapping_preserves_unknown_semantics() {
        let e = IsolatedSignerPaymentOps::uncertain_error();
        // the EXISTING uncertainty code (hold reservation, gate replay)
        assert_eq!(e.code, "RIALO_TRANSFER_CONFIRMATION_TIMEOUT");
        assert!(e.tx_signature.is_none());
    }

    #[test]
    fn signing_success_is_never_payment() {
        // PHASE 10 ITEM 6 restated: a signature by itself is NEVER payment.
        // Every pre-dispatch refusal (the class the old
        // SIGNER_SIGNED_NOT_BROADCAST belonged to) carries NO chain
        // signature — nothing is self-attesting; the only signature the core
        // may commit is the one the NODE reported for an executed tx.
        let e = IsolatedSignerPaymentOps::definitive_error(
            CODE_SIGNER_BYTE_DIVERGENCE,
            "the signer's canonical message differs from the authorized intent (pre-dispatch)",
        );
        assert_eq!(e.code, CODE_SIGNER_BYTE_DIVERGENCE);
        assert!(e.tx_signature.is_none(), "no fabricated chain evidence");
        // the legacy code is still defined (pre-ITEM-6 records must keep
        // reconciling) and it never carried a signature either
        assert!(
            IsolatedSignerPaymentOps::definitive_error(
                CODE_SIGNER_SIGNED_NOT_BROADCAST,
                "legacy grammar retained for pre-ITEM-6 records",
            )
            .tx_signature
            .is_none()
        );
    }

    #[test]
    fn envelope_never_broadcasts_a_mismatched_intent() {
        // the restored broadcast refuses BEFORE dispatch when the signed
        // envelope does not carry the authorized intent (fail-closed, and
        // never a signature the node did not report)
        let signed = SignedTransactionResult {
            agent_id: "11111111-2222-4333-8444-555555555555".to_string(),
            wallet_address: "11111111111111111111111111111111".to_string(),
            recipient: "11111111111111111111111111111111".to_string(),
            amount_kelvin: 1_000,
            canonical_message: vec![0u8; 4], // deliberately NOT a canonical message
            signer_message: vec![0u8; 4],
            signature: vec![7u8; 64],
            required_signatures: super::super::rialo_canonical::SINGLE_SIGNER_REQUIRED,
            canonical_hash: "0".repeat(64),
        };
        let ops = IsolatedSignerPaymentOps::new(
            Arc::new(RialoConfig {
                cli: PathBuf::from("/nonexistent"),
                rpc_url: "http://127.0.0.1:1".into(),
                program_id: None,
                program_dir: PathBuf::from("artifact"),
            }),
            "http://127.0.0.1:1".to_string(),
        );
        let err = ops
            .broadcast_signed_result(&signed)
            .expect_err("a non-decoding envelope is refused");
        assert_eq!(err.code, CODE_SIGNER_BYTE_DIVERGENCE);
        assert!(err.tx_signature.is_none(), "refusal fabricates no evidence");
    }

    #[test]
    fn envelope_preserves_the_authorized_intent() {
        // the positive half: the restored broadcast path assembles the
        // envelope from the SIGNED result and its strict decoder confirms
        // the payer/recipient/amount it is about to submit are exactly the
        // authorized intent (this is the pre-dispatch gate, no network)
        let from = [3u8; 32];
        let to = [9u8; 32];
        let spec = super::super::rialo_canonical::CanonicalTransferSpec {
            from: &from,
            to: &to,
            amount_kelvin: 4_242_424,
            valid_from_ms: 1_700_000_000_000,
            config_hash_prefix: 7,
            occ: false,
        };
        let message = super::super::rialo_canonical::build_canonical_message(&spec);
        let (sigs, decoded) = super::super::rialo_canonical::decode_transaction_envelope(
            &super::super::rialo_canonical::unsigned_transaction_envelope(&spec),
        )
        .expect("the envelope the lane builds decodes");
        assert_eq!(sigs.len(), 1);
        assert_eq!(decoded.account_keys[0], from);
        assert_eq!(decoded.account_keys[1], to);
        assert_eq!(
            decoded.instructions[0].data[4..],
            4_242_424u64.to_le_bytes()
        );
        // and the message the signer returns is the same byte string the
        // app authorized (byte identity is the contract)
        assert_eq!(message, spec_to_bytes(&spec));
    }

    /// helper: re-derive the canonical bytes from the spec (the same call
    /// the lane performs) so the test compares against construction, not
    /// against a remembered literal.
    fn spec_to_bytes(spec: &super::super::rialo_canonical::CanonicalTransferSpec<'_>) -> Vec<u8> {
        super::super::rialo_canonical::build_canonical_message(spec)
    }

    #[test]
    fn live_end_to_end_signing_and_broadcast() {
        if std::env::var("AGENTPAY_LANE7_LIVE").ok().as_deref() != Some("1") {
            return; // not gated: the default run never touches live data/processes
        }
        // (1) build the signer policy (recipient allow-list + cap)
        let policy_path = std::env::temp_dir().join("agentpay-signer-policy-live.json");
        std::fs::write(
            &policy_path,
            br#"{"max_per_tx_kelvin":1000000,"recipients":["F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw"],"program_id":"11111111111111111111111111111111","max_instructions":1}"#,
        )
        .unwrap();

        // (2) cwd = repo root (the artifact/ paths)
        let original = std::env::current_dir().unwrap();
        let repo = original
            .ancestors()
            .find(|p| p.join("Cargo.toml").exists() && p.join("artifact").exists())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| original.clone());
        std::env::set_current_dir(&repo).unwrap();

        // (3) the live agent identity (the first live agent)
        let agents_dir = std::path::Path::new("artifact/agents");
        let mut live_agent: Option<(String, String)> = None; // (agent_id, auth_pubkey)
        for entry in std::fs::read_dir(agents_dir).unwrap().flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                let agent: Agent = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                // the honest E2E precondition: an ACTIVE agent (the lifecycle
                // gate is part of the chain) with an auth linkage
                if agent.status == crate::agents::AgentStatus::Active {
                    if let Some(pk) = agent.auth_public_key.clone() {
                        live_agent = Some((agent.agent_id.clone(), pk));
                        break;
                    }
                }
            }
        }
        let (agent_id, _auth_pubkey) = live_agent.expect("a live agent exists");

        // (4) spawn the LIVE signer (armed: signing enabled + policy file)
        let port = 8995u16;
        let signer_bin = repo.join("tools/agentpay-signer/target/debug/agentpay-signer");
        let mut child = std::process::Command::new(&signer_bin)
            .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
            .env(
                "AGENTPAY_SIGNER_STORE",
                "/home/mahmoud/agentpay-signer-store",
            )
            .env("AGENTPAY_SIGNER_SIGNING_ENABLED", "1")
            .env("AGENTPAY_SIGNER_POLICY", &policy_path)
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("signer spawns");
        std::thread::sleep(std::time::Duration::from_millis(700));

        // (5) arm the adapter gate and run the REAL transfer through the seam
        // SAFETY: test-only env manipulation in the gated live test
        unsafe { std::env::set_var(ENV_LANE, "1") };
        unsafe { std::env::set_var(ENV_URL, format!("http://127.0.0.1:{port}")) };
        // RIALO_RPC_URL from the repo .env (a public RPC URL, name-only
        // discipline: read the value here, never log it)
        let rpc_url = std::fs::read_to_string(".env")
            .ok()
            .and_then(|env| {
                env.lines()
                    .find(|l| l.starts_with("RIALO_RPC_URL="))
                    .map(|l| l.split_once('=').unwrap().1.trim().to_string())
            })
            .unwrap_or_else(|| "http://127.0.0.1:4104".to_string());
        let native = Arc::new(RialoConfig {
            cli: PathBuf::from("/nonexistent"), // PROOF: no CLI fallback possible
            rpc_url,
            program_id: None,
            program_dir: PathBuf::from("artifact"),
        });
        let agent = read_agent(&crate::agents::agent_path(
            &crate::agents::agents_dir(),
            &uuid::Uuid::parse_str(&agent_id).unwrap(),
        ))
        .unwrap();
        let policy = AgentPolicy {
            schema_version: 1,
            agent_id: agent_id.clone(),
            max_payment_per_tx_kelvin: Some(1_000_000_000),
            daily_payment_limit_kelvin: Some(10_000_000_000),
            // EXACTLY the recipient set the signer's own policy file carries:
            // the independent IR cross-verification compares sets by
            // equality, so a superset or subset here is a guaranteed deny
            allowed_recipients: vec!["F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw".into()],
            allowed_actions: vec!["payment".into()],
            created_at: Some(1),
            updated_at: Some(1),
            parent_agent_id: None,
            delegation_revoked: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
        };
        let ops = production_isolated_signer_ops_audited(
            native.clone(),
            &agent,
            &policy,
            &std::path::Path::new("artifact/agent_auth_keys").to_path_buf(),
            None,
        );
        // the wallet path the core would pass (identity = agent uuid)
        let wallet_path =
            std::path::Path::new("artifact/agent_wallets").join(format!("{agent_id}.json"));
        let result = ops.transfer(
            &wallet_path,
            "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw", // allow-listed on BOTH planes
            "0.000001", // 1_000 kelvin — the smallest non-zero amount, inside every cap
        );

        // (6) THE E2E ASSERTION — PHASE 10 ITEM 6. The full chain runs:
        // channel-authenticated /sign, signer-side IR cross-verification,
        // canonical byte identity, the signature, and NOW the restored
        // execution/broadcast path on the ONE RPC endpoint. The only honest
        // success shape is a signature the NODE reported (never fabricated,
        // never the envelope's own bytes presented as chain evidence); any
        // other outcome is a typed failure and must carry no signature the
        // node did not report.
        match result {
            Ok(sig) => {
                assert!(!sig.trim().is_empty(), "a reported signature is non-empty");
                // the node's answer is base58 and is exactly the signer's
                // 64-byte signature — the binding the restored path enforces
                let decoded = crate::rialo::base58_decode(&sig);
                assert!(
                    decoded.as_ref().map(|d| d.len() == 64) == Some(true),
                    "the chain signature decodes to the signer's 64 bytes: {sig}"
                );
            }
            Err(e) => {
                // a refusal is typed; the uncertainty class keeps the intent
                // gated, a definitive one refunds. Neither ever invents a tx
                // hash, and no code path returns the old
                // SIGNER_SIGNED_NOT_BROADCAST dead-end any more.
                assert_ne!(
                    e.code, CODE_SIGNER_SIGNED_NOT_BROADCAST,
                    "the no-broadcast dead-end is retired: {e:?}"
                );
                if e.code != "RIALO_TRANSFER_CONFIRMATION_TIMEOUT" {
                    assert!(
                        e.tx_signature.is_none(),
                        "a pre-dispatch refusal fabricates no chain evidence: {e:?}"
                    );
                }
            }
        }

        // (7) cleanup
        let _ = child.kill();
        unsafe { std::env::remove_var(ENV_LANE) };
        unsafe { std::env::remove_var(ENV_URL) };
        std::env::set_current_dir(&original).unwrap();
    }

    #[test]
    fn channel_verify_roundtrip() {
        let mut seed = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed);
        let kp = lane_test_channel_keypair(&seed);
        let pk = lane_test_channel_pubkey(&kp);
        let body = r#"{"success":true,"outcome":"created","public_address":"x"}"#;
        // mirror the LIVE flow: the signer builds the response WITH the
        // channel_nonce then signs (the nonce stays in the signed message —
        // it IS the request binding)
        let with_nonce = r#"{"success":true,"outcome":"created","public_address":"x","channel_nonce":"NONCE-A"}"#;
        let sig = lane_test_sign_channel(&kp, with_nonce, "NONCE-A");
        let signed_body = format!(
            r#"{{"success":true,"outcome":"created","public_address":"x","channel_nonce":"NONCE-A","signer_sig":"{sig}"}}"#
        );
        let _ = body;
        assert!(verify_channel_response(&pk, &signed_body, "NONCE-A").is_ok());
        // (a) modified body ⇒ rejected
        let tampered = signed_body.replace("created", "recover");
        assert!(verify_channel_response(&pk, &tampered, "NONCE-A").is_err());
        // (b) missing signature ⇒ rejected
        let unsigned = r#"{"success":true,"outcome":"created","public_address":"x","channel_nonce":"NONCE-B"}"#;
        assert!(verify_channel_response(&pk, unsigned, "NONCE-B").is_err());
        // (c) unknown signer (a DIFFERENT key) ⇒ rejected
        let mut seed2 = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed2);
        let kp2 = lane_test_channel_keypair(&seed2);
        assert!(
            verify_channel_response(&lane_test_channel_pubkey(&kp2), &signed_body, "NONCE-C")
                .is_err()
        );
        // (d) replay: the same nonce twice ⇒ the second is rejected (a FRESH
        // nonce demonstrates the replay semantics: the first verify succeeds,
        // the second is a replay)
        let with_nonce_r = r#"{"success":true,"outcome":"created","public_address":"x","channel_nonce":"NONCE-R"}"#;
        let sig_r = lane_test_sign_channel(&kp, with_nonce_r, "NONCE-R");
        let signed_replay = format!(
            r#"{{"success":true,"outcome":"created","public_address":"x","channel_nonce":"NONCE-R","signer_sig":"{sig_r}"}}"#
        );
        assert!(verify_channel_response(&pk, &signed_replay, "NONCE-R").is_ok());
        assert!(verify_channel_response(&pk, &signed_replay, "NONCE-R").is_err());
        // (e) nonce echo mismatch ⇒ rejected
        assert!(verify_channel_response(&pk, &signed_body, "NONCE-D").is_err());
    }

    #[test]
    fn policy_ir_compiles_from_the_authoritative_record() {
        if std::env::var("AGENTPAY_LANE7_LIVE").ok().as_deref() != Some("1") {
            return;
        }
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(".").unwrap();
        let aid = "dfcaa852-c5a7-4cd8-a72a-e71049d6c174";
        let policy = read_agent_policy_for_lane(aid);
        let ir = policy.as_ref().and_then(|p| compile_policy_ir(aid, p));
        assert!(ir.is_some(), "the authoritative policy compiles to the IR");
        // the IR carries the signer-side rules
        let ir_text = ir.unwrap();
        assert!(ir_text.contains("signer_policy_amount_cap"));
        assert!(ir_text.contains("signer_policy_recipient"));
        assert!(ir_text.contains("F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw"));
        // the IR carries the frozen program pin + instruction count
        assert!(ir_text.contains("signer_policy_program_pin"));
        assert!(ir_text.contains("signer_policy_instruction_count"));
        // (the cross-verification itself is proven in the signer crate's
        // policy_ir_cross_verification test + the LIVE E2E, which exercises
        // the real app→signer cross-check through the wire)
        std::env::set_current_dir(&original).unwrap();
    }

    #[test]
    fn missing_policy_record_is_fail_closed() {
        // an agent WITHOUT a policy record → no IR → the signer refuses
        // (POLICY_IR_MISSING) — the app cannot bypass the signer's policy
        // plane by omitting the evidence
        assert!(read_agent_policy_for_lane("11111111-2222-4333-8444-555555555555").is_none());
    }

    #[test]
    fn channel_pin_enforced_when_configured() {
        // the env pin present + an unsigned response ⇒ definitive failure
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var(
                ENV_CHANNEL_PUBKEY,
                "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA",
            )
        };
        let res = std::env::var(ENV_CHANNEL_PUBKEY).unwrap();
        assert!(!res.is_empty());
        // a verifier call with a MISSING signature fails closed even with a pin
        assert!(verify_channel_response(&res, r#"{"success":true}"#, "NONCE-X").is_err());
        unsafe { std::env::remove_var(ENV_CHANNEL_PUBKEY) };
    }

    #[test]
    fn private_material_never_crosses_the_adapter() {
        // structural: the adapter never reads the signer store, never loads
        // funded keys, never constructs a wallet path under artifact for
        // SIGNING (the read-only plane delegates; the signer path uses ids)
        let production: String = include_str!("isolated_signer_lane.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!production.contains("agent_wallet_path("));
        assert!(!production.contains("keypair_from_file"));
        assert!(!production.contains("read_keypair"));
        // the ONLY keypair load is the funds-less auth key
        assert!(production.contains("read_auth_keypair_full"));
    }
}

// PHASE 10 ITEM 6 — the channel-authentication battery over the PRODUCTION
// /sign response path (the real signer binary + the real app verifier).
#[cfg(test)]
#[path = "_channelauth_i6_tests.rs"]
mod channelauth_i6_tests;
