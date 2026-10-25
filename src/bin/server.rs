use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Form, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tower_http::services::ServeDir;
use uuid::Uuid;

use rialo_s_keypair::Keypair;
use rialo_s_signer::Signer;

#[path = "server/rialo.rs"]
mod rialo;
use rialo::{RialoConfig, RialoError};

/// PHASE 5 STEP 2+ — Agent layer: CRUD, independent agent-wallet
/// provisioning, balance, lifecycle, policy model/enforcement, and
/// explicit agent payments (agent-wallet-only; the user wallet and
/// funding paths stay outside this module).
#[path = "server/agents.rs"]
mod agents;

/// PHASE 6 STEP 6 — Activity tracking: a DERIVED read-only projection of
/// the existing intent ledger (artifact/agent_payment_intents). No new
/// storage, no locks, no chain calls, no money paths — see the module doc.
#[path = "server/activity.rs"]
mod activity;

/// PHASE 7 — Leaderboard: a DERIVED read-only projection across the owner's
/// agents (artifact/agents) + their payment intents
/// (artifact/agent_payment_intents). ZERO chain calls (no balance column),
/// no new storage, no locks, no payment paths — see the module doc.
#[path = "server/leaderboard.rs"]
mod leaderboard;

/// PHASE 11 — Tasks Marketplace: owner-posted tasks, worker claims/submissions,
/// manual review, and the reservation ledger. Built against the PG-authoritative
/// pg_store (task_reservations); wired so `crate::tasks::Task` resolves for the
/// legacy import path.
#[path = "server/tasks.rs"]
mod tasks;

/// PHASE 7 — AGENT STATS · PART 2.1: the read-only CORE + data readers
/// (typed internal projections over `artifact/agents` +
/// `artifact/agent_payment_intents`, via the authoritative readers).
/// Zero chain calls, no new storage, no routes in this part — see the
/// module doc and the `stats21` focused tests.
#[path = "server/stats.rs"]
mod stats;

/// PHASE 5 — Agent credential store (Argon2id PHC records on disk, keyed by
/// canonical agent UUID). Minimal non-payment wiring: the module compiles as
/// part of this target and its tests run here; NO route, handler, payment,
/// wallet, or funding behavior references it yet.
#[path = "../agent_credentials.rs"]
mod agent_credentials;
#[path = "../pg_store.rs"]
mod pg_store;

/// PHASE 7D.1 — PUBLIC VERIFICATION API (core): ONE public, sessionless,
/// credentialless surface — GET /api/public/verify?signature={sig}.
/// Chain-KEYED read-only lookup (Rialo Testnet transaction_lookup); the
/// canonical verification DTO is the ONLY thing that leaves the process.
/// NO artifact/ reads, no wallet/key access, no credential access, no
/// policy/fingerprint/idempotency data, no filesystem mutation, no
/// payment/signing/state mutation — see the module doc in verify.rs.
#[path = "server/verify.rs"]
mod verify;

// PHASE 8 Item 10 — the canonical transaction-signer boundary. Models
// "which keypair reference is authorized to sign THIS payment" as a
// named type with deterministic failure modes; signing itself remains
// exclusively the rialo CLI's job (see rialo.rs). See the module doc.
#[path = "server/rialo_tx_signers.rs"]
mod rialo_tx_signers;

// PHASE 9 Item I-1 (capability C-1) — the funds-less per-agent
// authentication keypair vault: identity material only. No funding, no
// transport, no payment use; the money-signer boundary above is
// unchanged. See the module doc.
#[path = "server/agent_auth_keys.rs"]
mod agent_auth_keys;

// PHASE 9 Item I-2 (byte-identity spike) — canonical transaction builder
// and strict decoder for the FUTURE Latch signing lane. PURE, OFFLINE,
// and ISOLATED: no production payment path references it (test-pinned);
// Latch byte identity (G-15) stays UNRESOLVED pending the live-enclave
// spike. See the module doc and the I-2 closure note.
#[path = "server/rialo_canonical.rs"]
mod rialo_canonical;

// PHASE 9 Item C-2 (R2 design) — the deterministic AgentPolicy → Latch
// filter compiler. PURE: no transport, no routes, no execution, no key
// reads; emits the AgentPay-side IR only (wire schema stays pinned-unknown
// per G-2). It never chooses a lane and never joins the payment path.
// See the module doc and `_phase9/c2_policy_filter_compiler_design.md`.
#[path = "server/latch_policy_compiler.rs"]
mod latch_policy_compiler;

// PHASE 9 Item I-4 — the bounded Latch transport seam behind PaymentOps.
// LANE SELECTION + transport abstraction ONLY: no policy decisions (the
// frozen cores and app gate stay authoritative), no provisioning, no
// network client — the production default gateway fails closed and keeps
// the native path byte-for-byte the status quo. I-5 armed it: the D-PROXY
// proxy-lane client and handler wiring live in `latch_proxy_lane` (the
// localhost D-TRANSPORT shim hop); the seam module itself stays
// network-free and the frozen cores never reference it (pinned by test).
// See the module doc.
#[path = "server/latch_transport.rs"]
mod latch_transport;

// PHASE 9 Item I-5 — the armed D-PROXY transport lane: the only production
// LatchGateway (proxy-mode over the localhost bearer-attaching shim) plus
// the env-only wiring decision used by the two money handlers. This module
// never touches a Latch token value — the shim holds the bearer; the
// server only dials loopback. See the module doc.
/// PHASE 9 "Secure signer" STEP 7 — the isolated signer integrated behind
/// the ONE PaymentOps seam: env-gated loopback-only lane, no fallback
/// grammar, typed failure mapping, signing-success-is-not-payment.
#[path = "server/isolated_signer_lane.rs"]
mod isolated_signer_lane;
#[path = "server/latch_proxy_lane.rs"]
mod latch_proxy_lane;

// PHASE 9 "Rate / time limits" (app-side half; TM-AV-01/TM-AV-03, GA-4) —
// the fixed-window request meter. PURE: monotonic buckets, process-global
// mutex, identity+class keys, fail-closed, no network, no disk, no money
// coupling, no Latch dependency. Enforcement sits BEFORE intent claim /
// reservation / lane selection, so a denial can never touch money state.
// See the module doc.
#[path = "server/rate_limits.rs"]
mod rate_limits;

// PHASE 9 "Authorization / execution audit" — the APPEND-ONLY, observational
// evidence projection of decisions the EXISTING authorities already made.
// It is NOT an authority: it never gates, never re-checks, never feeds back
// into authorization/payment/settlement/retry/lane selection. Agent-scoped
// store `artifact/agent_audit/<uuid>.json` + `_system.json` for agent-less
// facts; bounded, atomic (temp+0600+rename), best-effort writers. See the
// module doc.
#[path = "server/audit.rs"]
mod audit;

// PHASE 9 "Verifiable payment receipts" — the deterministic READ-ONLY
// projection of existing authoritative evidence (intent + reconciliation +
// audit + signer linkage) into one verifiable receipt document. PURE
// projection: zero writes, zero RPC, no new authority, no second source of
// truth; Unknown stays Unknown. OWNER-SCOPED only (the frozen public
// proofs/verify surfaces are unchanged). See the module doc.
#[path = "server/receipts.rs"]
mod receipts;

// PHASE 10 Security headers middleware (defense in depth)
#[path = "server/middleware/security_headers.rs"]
mod security_headers;

pub use security_headers::add_security_headers;

/// Shared guard for the program-mediated payment endpoints. Returns Ok(())
/// when the path may proceed, or a ready-to-return error Response otherwise.
///
/// Layers, in order:
/// 1. Program ID configured (else PROGRAM_NOT_CONFIGURED).
/// 2. Manifest-integrity guard (else PROGRAM_MANIFEST_*): an unfixed/buggy
///    manifest must NEVER drive an invocation — checked again inside
///    program_invoke, but refusing at the API boundary gives a clear error.
/// 3. Explicit operator cap AGENTPAY_PROGRAM_TEST_MAX_RLO must be set and
///    positive (else PROGRAM_ESCROW_BUG refusal). Unset = path disabled.
///    Fix-B was verified live on 2026-09-28; the cap deliberately remains
///    the kill-switch and is NOT enabled automatically.
fn program_payment_guard(state: &AppState, amount_rlo: Option<f64>) -> Result<(), Response> {
    use rialo::program_test_cap;

    if state.rialo.program_id.is_none() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PROGRAM_NOT_CONFIGURED",
            "AGENTPAY_PROGRAM_ID is not set; program payments are unavailable.",
        ));
    }

    if let Err(err) = state.rialo.validate_program_manifest() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            err.code,
            &format!(
                "Program manifest failed the integrity guard — refusing invocation: {}",
                err.detail
            ),
        ));
    }

    let cap = program_test_cap().unwrap_or(0.0);
    if cap <= 0.0 {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "PROGRAM_ESCROW_BUG",
            "Program payments are disabled by default. Fix-B (correct execute account order via the validated manifest) was verified live on 2026-09-28, but the path stays kill-switched until an operator sets AGENTPAY_PROGRAM_TEST_MAX_RLO > 0. Use POST /api/payment for direct transfers.",
        ));
    }
    if let Some(amount) = amount_rlo {
        if amount > cap {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "PROGRAM_AMOUNT_OVER_TEST_CAP",
                &format!(
                    "Program path is test-capped at {} RLO (AGENTPAY_PROGRAM_TEST_MAX_RLO)",
                    cap
                ),
            ));
        }
    }
    Ok(())
}

/// Additive preview-only OAuth callback. The production `/auth/github`
/// callback remains `GITHUB_REDIRECT_URI` and is not altered by this lane.
const PREVIEW_GITHUB_REDIRECT_URI: &str =
    "https://rialo-agentpay-preview.pages.dev/auth/github/preview/callback";

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    /// Optional second GitHub OAuth redirect for the isolated static preview.
    /// This is additive: the production `/auth/github` flow keeps using
    /// `redirect_uri` above and is never changed by the preview lane.
    preview_redirect_uri: Option<String>,
    oauth_states: Arc<Mutex<HashMap<String, Instant>>>,
    sessions: Arc<Mutex<HashMap<String, GithubUser>>>,
    wallets: Arc<Mutex<HashMap<u64, Keypair>>>,
    rialo: Arc<RialoConfig>,
}

/// PHASE 11 — process-global Rialo config handle for the tasks payout
/// bridge. Set once at startup (after AppState construction); the bridge
/// reads it without needing the full AppState (the task handlers already
/// authenticated/authorized before reaching the engine).
static TASKS_RIALO: OnceLock<Arc<RialoConfig>> = OnceLock::new();

pub(crate) fn tasks_set_rialo_handle(config: Arc<RialoConfig>) -> bool {
    TASKS_RIALO.set(config).is_ok()
}

pub(crate) fn tasks_rialo_handle() -> Option<Arc<RialoConfig>> {
    TASKS_RIALO.get().cloned()
}

/// Standard error envelope for all API handlers — stable machine-readable
/// codes so the frontend and callers can distinguish app vs infra failures.
fn api_error(status: StatusCode, code: &str, detail: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "success": false,
            "error": { "code": code, "message": detail }
        })),
    )
        .into_response()
}

fn rialo_error_response(err: &RialoError) -> Response {
    // G31 — three-way status mapping with honest semantics:
    //   * RIALO_RPC_UNAVAILABLE / _CLI_UNAVAILABLE / confirmation-timeout
    //     ⇒ 503 SERVICE_UNAVAILABLE (transient infrastructure — retryable
    //     later, never a client fault, never a tx result).
    //   * RIALO_WALLET_ERROR ⇒ 500 INTERNAL (operator remediation required:
    //     wallet integrity/registry issues are server-side state).
    //   * everything else (RIALO_ERROR / RIALO_TRANSFER_ERROR / CLOCK_SKEW
    //     / PROGRAM_ERROR — node refusals with real on-chain reasoning)
    //     ⇒ 400 BAD_REQUEST: the node answered with a decision about THIS
    //     transaction; the previous blanket 502 (a gateway-code for an
    //     app-authored decision) is what muddied the original diagnosis.
    //     The client still sees the full refusal detail through the JSON
    //     error body — nothing is hidden or softened.
    let status = if err.is_rpc_down()
        || err.code == "RIALO_CLI_UNAVAILABLE"
        || err.code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"
        || err.code == "RIALO_ERROR_CONFIRMATION_UNKNOWN"
    {
        // transient-infrastructure / uncertainty band: retryable later, never
        // a client fault, never a tx verdict (hold + on-chain verify instead)
        StatusCode::SERVICE_UNAVAILABLE
    } else if err.code == "RIALO_WALLET_ERROR" {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        // G32 correction — split the RIALO_ERROR bucket honestly:
        // deterministically-known client-actionable refusals (balance/rent/
        // account-missing at send time) ⇐ 400 with the node's verbatim
        // detail preserved; EVERYTHING ELSE stays 502 (unknown upstream —
        // never blanket-stuff unknown-cause failures into 4xx per the G32
        // review rule: unknown infrastructure failures must not be
        // re-labelled as client faults merely to eliminate a 502).
        // G33 — match against the FIRST line only: multi-line CLI stderr
        // can carry unrelated trailing context whose keywords must not
        // leak into the classification of the primary refusal.
        let lower = err.detail.lines().next().unwrap_or("").to_lowercase();
        if lower.contains("insufficient")
            || lower.contains("account not found")
            || lower.contains("account does not exist")
            || lower.contains("no such account")
            || lower.contains("not owned by program")
        {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::BAD_GATEWAY
        }
    };
    // G24 — server-side record for every rialo failure surfaced as 5xx: the
    // 502 investigation proved these details died in the HTTP body alone.
    // Sanitized preview only (diag_text: first line, ≤200 chars, paths
    // neutralized); signature values are reported as presence, never logged.
    let detail_preview = crate::rialo::diag_text(&err.detail);
    eprintln!(
        "[rialo-err] status={} op-code={} sig_evidence={} detail={}",
        status.as_u16(),
        err.code,
        err.tx_signature.is_some(),
        detail_preview
    );
    // G34 — the HTTP body carries the SAME sanitized preview: vendor CLI
    // failure envelopes can embed internal keypair paths (proven:
    // "Failed to load ... /app/artifact/wallets/<uid>.json" flows through
    // the envelope into err.detail). Never emit the raw detail to clients.
    api_error(status, err.code, &detail_preview)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GithubUserResponse {
    id: u64,
    login: String,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct WalletNonceRequest {
    address: String,
}

#[derive(Deserialize)]
struct WalletVerifyRequest {
    address: String,
    nonce: String,
    signature_hex: String,
}

#[derive(Serialize)]
struct WalletNonceResponse {
    success: bool,
    nonce: String,
    message: String,
}

#[derive(Serialize)]
struct SessionResponse {
    logged_in: bool,
    user: Option<GithubUser>,
    wallet_address: Option<String>,
    /// null when logged out / unavailable — never a fake "0".
    balance: Option<String>,
    /// "ok" | "unavailable" | "no_wallet" — explicit balance status so the
    /// frontend can distinguish "zero" from "RPC down".
    balance_status: String,
    balance_error: Option<serde_json::Value>,
}

fn balance_error_json(err: &RialoError) -> serde_json::Value {
    serde_json::json!({ "code": err.code, "message": err.detail })
}

/// G21.12 — wallet integrity bridge (sync contexts): PG-only gate.
/// Returns Err when a registered wallet's file is missing (fail-closed,
/// no silent replacement). FS mode: always Ok (legacy).
fn wallet_integrity_check(user_id: u64) -> Result<(), String> {
    if !matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        return Ok(());
    }
    static REG_RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    let rt = REG_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("wallet registry runtime")
    });
    match rt.block_on(crate::pg_store::registry_get_user_wallet(user_id)) {
        Ok(Some(_)) => {
            if wallet_file(user_id).exists() {
                Ok(())
            } else {
                Err("WALLET_FILE_MISSING: registered wallet file is missing; operator recovery required".into())
            }
        }
        Ok(None) => Ok(()), // genuinely new user
        Err(e) => Err(format!("WALLET_REGISTRY_DOWN: {e:?}")),
    }
}

#[derive(Clone)]
struct WalletRecoveryEntry {
    user_id: u64,
    expires: Instant,
}

static WALLET_RECOVERY: OnceLock<Mutex<HashMap<String, WalletRecoveryEntry>>> = OnceLock::new();

fn wallet_recovery_tokens() -> &'static Mutex<HashMap<String, WalletRecoveryEntry>> {
    WALLET_RECOVERY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn issue_wallet_recovery_token(user_id: u64) -> String {
    let token = Uuid::new_v4().to_string();
    let mut tokens = wallet_recovery_tokens().lock().unwrap();
    let now = Instant::now();
    tokens.retain(|_, entry| entry.expires > now);
    tokens.insert(
        token.clone(),
        WalletRecoveryEntry {
            user_id,
            expires: now + Duration::from_secs(600),
        },
    );
    token
}

fn take_wallet_recovery_token(token: &str) -> Option<u64> {
    let mut tokens = wallet_recovery_tokens().lock().unwrap();
    let now = Instant::now();
    let entry = tokens.remove(token)?;
    (entry.expires > now).then_some(entry.user_id)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn wallet_recovery_page(login: &str, token: &str) -> axum::response::Html<String> {
    let login = escape_html(login);
    let token = escape_html(token);
    axum::response::Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wallet recovery | Rialo AgentPay</title>
<style>
:root{{color-scheme:dark}}body{{margin:0;background:#0c0f0a;color:#e7f0dc;font:15px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;display:grid;place-items:center;min-height:100vh}}
main{{width:min(620px,calc(100% - 32px));border:1px solid #3a4522;background:#11150c;padding:28px;border-radius:14px;box-shadow:0 18px 60px #0008}}
h1{{font-size:20px;margin:0 0 10px;color:#caf76a}}p{{color:#b9c6a8}}code{{color:#caf76a}}button{{background:#caf76a;color:#0c0f0a;border:0;border-radius:8px;padding:12px 18px;font:700 13px ui-monospace,monospace;letter-spacing:.08em;cursor:pointer}}small{{display:block;margin-top:16px;color:#86927a}}
</style></head><body><main>
<h1>Wallet file missing</h1>
<p>GitHub account <strong>@{login}</strong> has a registered Rialo wallet, but its key file is missing on this server. AgentPay refuses to silently replace wallet identity.</p>
<p>You can create a <strong>new wallet</strong> only if the old wallet has no on-chain balance. This is a deliberate recovery step; the old wallet file cannot be reconstructed.</p>
<form method="post" action="/auth/wallet-recover">
<input type="hidden" name="token" value="{token}">
<button type="submit">Create new wallet and continue</button>
</form>
<small>If the old wallet holds funds, recovery is refused. Contact the operator with the account name above.</small>
</main></body></html>"#
    ))
}

fn wallet_recovery_error_page(message: &str) -> axum::response::Html<String> {
    let message = escape_html(message);
    axum::response::Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wallet recovery | Rialo AgentPay</title>
<style>body{{margin:0;background:#0c0f0a;color:#e7f0dc;font:15px/1.5 ui-monospace,monospace;display:grid;place-items:center;min-height:100vh}}main{{width:min(620px,calc(100% - 32px));border:1px solid #5a2a2a;background:#150f0f;padding:28px;border-radius:14px}}h1{{font-size:20px;color:#ff9c8a}}a{{color:#caf76a}}</style></head>
<body><main><h1>Recovery not completed</h1><p>{message}</p><p><a href="/auth/github">Try GitHub login again</a></p></main></body></html>"#
    ))
}

#[derive(Deserialize)]
struct WalletRecoveryForm {
    token: String,
}

fn recovery_registry_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("wallet recovery runtime")
    })
}

fn mint_wallet_file(user_id: u64) -> Result<Keypair, String> {
    let path = wallet_file(user_id);
    if path.exists() {
        return Err("WALLET_FILE_EXISTS: refusing to overwrite an existing wallet file".into());
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("WALLET_RNG_FAILED: {e}"))?;
    let keypair = rialo_s_keypair::keypair_from_seed(&seed)
        .map_err(|e| format!("WALLET_KEYPAIR_FAILED: {e}"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("WALLET_CREATE_FAILED: {e}"))?;
    rialo_s_keypair::write_keypair(&keypair, &mut file)
        .map_err(|e| format!("WALLET_WRITE_FAILED: {e}"))?;
    harden_wallet_permissions(&path);
    Ok(keypair)
}

async fn recover_wallet(
    State(state): State<AppState>,
    Form(form): Form<WalletRecoveryForm>,
) -> Response {
    let user_id = match take_wallet_recovery_token(&form.token) {
        Some(user_id) => user_id,
        None => {
            return wallet_recovery_error_page(
                "This recovery link is invalid or expired. Start the GitHub login again.",
            )
            .into_response()
        }
    };

    if wallet_file(user_id).exists() {
        return wallet_recovery_error_page(
            "A wallet file is present now; no replacement was made. Try logging in again.",
        )
        .into_response();
    }

    let old_pubkey = match tokio::task::spawn_blocking(move || {
        recovery_registry_runtime()
            .block_on(crate::pg_store::registry_get_user_wallet(user_id))
            .map_err(|e| e.to_string())
    })
    .await
    .expect("spawn_blocking join")
    {
        Ok(Some(pubkey)) => pubkey,
        Ok(None) => {
            return wallet_recovery_error_page(
                "No registered wallet was found for this account; try logging in again.",
            )
            .into_response()
        }
        Err(e) => {
            return wallet_recovery_error_page(&format!(
                "The wallet registry is unavailable ({e}); recovery was not performed."
            ))
            .into_response()
        }
    };

    // Never rotate a wallet that may still hold value. The old key file is
    // gone; an on-chain balance means the operator must recover the file.
    let old_for_balance = old_pubkey.clone();
    let rialo = Arc::clone(&state.rialo);
    let balance = tokio::task::spawn_blocking(move || rialo.balance(&old_for_balance)).await;
    match balance {
        Ok(Ok(amount)) if amount > 0.0 => {
            return wallet_recovery_error_page(
                "The registered wallet still has an on-chain balance. Recovery is refused to avoid losing funds; contact the operator.",
            )
            .into_response()
        }
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return wallet_recovery_error_page(&format!(
                "Could not verify the old wallet balance ({}); recovery was not performed.",
                e.code
            ))
            .into_response()
        }
        Err(e) => {
            return wallet_recovery_error_page(&format!(
                "Could not verify the old wallet balance ({e}); recovery was not performed."
            ))
            .into_response()
        }
    }

    let keypair = match tokio::task::spawn_blocking(move || mint_wallet_file(user_id)).await {
        Ok(Ok(keypair)) => keypair,
        Ok(Err(e)) => {
            return wallet_recovery_error_page(&format!("Could not create a new wallet: {e}"))
                .into_response()
        }
        Err(e) => {
            return wallet_recovery_error_page(&format!(
                "Could not create a new wallet: {e}"
            ))
            .into_response()
        }
    };
    let new_pubkey = keypair.pubkey().to_string();
    let old_for_update = old_pubkey.clone();
    let new_for_update = new_pubkey.clone();
    let now = agents::now_unix();
    let rotated = tokio::task::spawn_blocking(move || {
        recovery_registry_runtime().block_on(crate::pg_store::registry_replace_user_wallet(
            user_id,
            &old_for_update,
            &new_for_update,
            now,
        ))
    })
    .await;
    match rotated {
        Ok(Ok(())) => Redirect::temporary("/auth/github").into_response(),
        Ok(Err(e)) => {
            let _ = std::fs::remove_file(wallet_file(user_id));
            wallet_recovery_error_page(&format!(
                "The registry could not be updated ({}); recovery was rolled back.",
                e
            ))
            .into_response()
        }
        Err(e) => {
            let _ = std::fs::remove_file(wallet_file(user_id));
            wallet_recovery_error_page(&format!(
                "The registry task failed ({e}); recovery was rolled back."
            ))
            .into_response()
        }
    }
}

/// G21.12 — strict load/mint used by money paths in PG mode.
/// PG is the source of truth: registered-but-file-missing refuses (no
/// replacement). First mint (no file, no registry row) registers pubkey.
fn load_wallet_strict(user_id: u64) -> Result<Keypair, String> {
    wallet_integrity_check(user_id)?;
    let path = wallet_file(user_id);

    if path.exists() {
        harden_wallet_permissions(&path);
        let mut file =
            std::fs::File::open(&path).map_err(|e| format!("WALLET_UNREADABLE: open: {e}"))?;
        let keypair = rialo_s_keypair::read_keypair(&mut file)
            .map_err(|e| format!("WALLET_UNREADABLE: parse: {e}"))?;
        // Identity binding: derived pubkey must equal the registered one.
        static REG_RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        let rt = REG_RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("verify runtime")
        });
        let reg_row = rt
            .block_on(crate::pg_store::registry_get_user_wallet(user_id))
            .map_err(|e| format!("WALLET_REGISTRY_DOWN: {e:?}"))?;
        let reg = if let Some(reg) = reg_row {
            Some(reg)
        } else {
            None
        };
        if let Some(reg) = reg {
            let file_pubkey = keypair.pubkey().to_string();
            if file_pubkey != reg {
                return Err(
                    "WALLET_IDENTITY_MISMATCH: file pubkey does not match the registered pubkey"
                        .into(),
                );
            }
        }
        return Ok(keypair);
    }

    // Mint new (first-time): FS create + PG register. On register failure,
    // file is KEPT (durable identity) and request fails; next attempt
    // re-registers the same pubkey idempotently.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("failed to generate secure wallet seed");
    let keypair = rialo_s_keypair::keypair_from_seed(&seed)
        .expect("failed to create keypair from wallet seed");
    let mut file = std::fs::File::create(&path).expect("failed to create wallet file");
    rialo_s_keypair::write_keypair(&keypair, &mut file).expect("failed to write wallet keypair");
    harden_wallet_permissions(&path);

    static REG_RT2: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    let rt = REG_RT2.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("register runtime")
    });
    let pubkey = keypair.pubkey().to_string();
    let now = agents::now_unix();
    if let Err(e) = rt.block_on(crate::pg_store::registry_register_user_wallet(
        user_id, &pubkey, now,
    )) {
        eprintln!("wallet register failed for user {user_id} (file kept for retry): {e:?}");
        return Err(format!("WALLET_REGISTRY_DOWN: {e:?}"));
    }
    Ok(keypair)
}

/// HTTP-shaped strict loader: FS mode legacy; PG mode fail-closed with
/// typed error codes.
fn strict_wallet_load_or_mint(user_id: u64) -> Result<Keypair, String> {
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        load_wallet_strict(user_id)
    } else {
        Ok(load_or_create_wallet(user_id))
    }
}

fn wallet_file(user_id: u64) -> PathBuf {
    let dir = Path::new("artifact").join("wallets");

    std::fs::create_dir_all(&dir).expect("failed to create wallet directory");

    dir.join(format!("{}.json", user_id))
}

/// Restrict a wallet keypair file to owner read/write (private keys must
/// never be world-readable).
fn harden_wallet_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn load_or_create_wallet(user_id: u64) -> Keypair {
    let path = wallet_file(user_id);

    if path.exists() {
        harden_wallet_permissions(&path);

        let mut file = std::fs::File::open(&path).expect("failed to open wallet file");

        return rialo_s_keypair::read_keypair(&mut file).expect("failed to read wallet keypair");
    }

    let mut seed = [0u8; 32];

    getrandom::getrandom(&mut seed).expect("failed to generate secure wallet seed");

    let keypair = rialo_s_keypair::keypair_from_seed(&seed)
        .expect("failed to create keypair from wallet seed");

    let mut file = std::fs::File::create(&path).expect("failed to create wallet file");

    rialo_s_keypair::write_keypair(&keypair, &mut file).expect("failed to write wallet keypair");

    harden_wallet_permissions(&path);

    keypair
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let client_id =
        env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID is missing in the environment");
    let client_secret = env::var("GITHUB_CLIENT_SECRET")
        .expect("GITHUB_CLIENT_SECRET is missing in the environment");
    let redirect_uri =
        env::var("GITHUB_REDIRECT_URI").expect("GITHUB_REDIRECT_URI is missing in the environment");

    let rialo = Arc::new(RialoConfig::from_env());

    // Infrastructure probe at startup is informational only — AgentPay must
    // boot and serve login/wallet identity even when the node is down.
    let probe_rialo: Arc<RialoConfig> = Arc::clone(&rialo);
    match tokio::task::spawn_blocking(move || probe_rialo.health())
        .await
        .unwrap()
    {
        Ok(height) => println!(
            "[rialo] RPC online at {} (block height {})",
            rialo.rpc_url, height
        ),
        Err(err) => eprintln!(
            "[rialo] RPC unavailable at {} — {} (chain features will report RIALO_RPC_UNAVAILABLE)",
            rialo.rpc_url, err.detail
        ),
    }

    // PHASE 11 — capture the process-global Rialo handle for the tasks
    // payout bridge BEFORE any request can reach the marketplace routes.
    let _ = tasks_set_rialo_handle(rialo.clone());
    let preview_redirect_uri = Some(
        env::var("GITHUB_PREVIEW_REDIRECT_URI")
            .unwrap_or_else(|_| PREVIEW_GITHUB_REDIRECT_URI.to_string()),
    );
    let state = AppState {
        client: reqwest::Client::builder()
            .user_agent("Rialo-AgentPay/0.1")
            .build()
            .expect("failed to create HTTP client"),
        client_id,
        client_secret,
        redirect_uri,
        preview_redirect_uri,
        oauth_states: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        wallets: Arc::new(Mutex::new(HashMap::new())),
        rialo,
    };

    let static_dir = if Path::new("frontend/src/index.html").exists() {
        "frontend/src"
    } else if Path::new("public/index.html").exists() {
        "public"
    } else {
        "."
    };

    let app = Router::new()
        .route("/auth/github", get(github_login))
        .route("/auth/github/callback", get(github_callback))
        // Additive, isolated preview lane. Uses the same OAuth app credentials
        // but a distinct redirect URI; the production routes above are unchanged.
        .route("/auth/github/preview", get(github_login_preview))
        .route(
            "/auth/github/preview/callback",
            get(github_callback_preview),
        )
        // Wallet sign-in: nonce + ed25519 signature (no OAuth redirect).
        .route("/auth/wallet/nonce", post(wallet_login_nonce))
        .route("/auth/wallet/verify", post(wallet_login_verify))
        .route("/auth/wallet-recover", post(recover_wallet))
        .route("/auth/logout", post(logout))
        .route("/api/me", get(current_user))
        .route("/api/faucet", post(faucet))
        .route("/api/payment", post(payment))
        .route("/api/program/status", get(program_status))
        .route("/api/payment/program/start", post(program_start))
        .route("/api/payment/program/execute", post(program_execute))
        .route("/api/health", get(health))
        // PHASE 5 — agent layer: CRUD + independent wallet provisioning +
        // balance readout + lifecycle + policy model/enforcement +
        // explicit agent payments (owner-scoped server-side;
        // artifact/agent_wallets/ holds agent keypairs,
        // artifact/agent_policies/ holds policy config,
        // artifact/agent_spend/ holds the daily-spend ledger,
        // artifact/agent_payment_intents/ holds the idempotency/replay
        // ledger. Agent payments transfer ONLY from the agent's own
        // wallet; the human owner's wallet path is unreachable here.
        // No funding, no autonomy, no scheduled payments anywhere).
        .route(
            "/api/agents",
            get(agents::list_agents).post(agents::create_agent),
        )
        .route(
            "/api/agents/{id}",
            get(agents::get_agent)
                .patch(agents::patch_agent)
                .delete(agents::delete_agent),
        )
        .route("/api/agents/{id}/balance", get(agents::agent_balance))
        .route("/api/agents/{id}/status", patch(agents::patch_agent_status))
        .route(
            "/api/agents/{id}/policy",
            get(agents::get_agent_policy).patch(agents::patch_agent_policy),
        )
        .route("/api/agents/{id}/payments", post(agents::agent_payment))
        // PHASE 11 — Tasks Marketplace routes. Every handler authenticates
        // with the EXISTING session model (session_user) and gates on the
        // task/agent ownership checks inside the handler. No new auth.
        .route(
            "/api/tasks",
            get(tasks::list_tasks).post(tasks::create_task),
        )
        .route("/api/tasks/open", get(tasks::list_tasks))
        .route("/api/tasks/{id}", get(tasks::get_task))
        .route("/api/tasks/{id}/cancel", post(tasks::cancel_task))
        .route("/api/tasks/{id}/claim", post(tasks::claim_task))
        .route(
            "/api/tasks/{id}/submit",
            post(tasks::submit_task).layer(DefaultBodyLimit::max(12 * 1024 * 1024)),
        )
        .route("/api/tasks/{id}/review", post(tasks::review_task))
        // PHASE 2 — task-payout recovery: owner-authenticated recovery of
        // PaymentPending payouts from the AUTHORITATIVE payment intent.
        // Read-only against the chain (the intent record already carries
        // the committed verdict); never transfers; idempotent.
        .route(
            "/api/tasks/{id}/payout/reconcile",
            post(tasks::recover_task_payout),
        )
        .route(
            "/api/tasks/payout/reconcile/sweep",
            post(tasks::recover_task_payouts_sweep),
        )
        // PHASE 6 STEP 3 — credential-triggered agent payment (Intent v2).
        // Literal route (no {id}): the Agent principal comes EXCLUSIVELY
        // from authenticate_agent_credential. No session, no dev-login, no
        // scheduler, no webhook; money movement runs through the same
        // Step-8 primitives, writing schema_version=2 intent records.
        .route(
            "/api/agents/triggers/payments",
            post(agents::agent_trigger_payment),
        )
        // PHASE 6 STEP 4 — reconciliation of Unknown payment outcomes.
        // Two surfaces, both using the EXISTING authentication
        // architecture (never a new one): the owner route below gates on
        // the single ownership choke point and may attest manually; the
        // credential lane below is deterministic-evidence only. Both
        // lanes are READ-ONLY against the chain — reconciliation never
        // transfers, never reserves, and is idempotent.
        .route(
            "/api/agents/{id}/payments/reconcile",
            post(agents::agent_payment_reconcile),
        )
        // PHASE 9 "Crash recovery" (TM-AV-02): owner-authenticated sweep
        // of THIS agent's stale Pending/Unknown intents through the
        // existing reconciliation engine only (no second settlement
        // authority; never transfers; safe-by-default Unknown semantics).
        .route(
            "/api/agents/{id}/payments/reconcile/sweep",
            post(agents::agent_payment_reconcile_sweep),
        )
        // PHASE 9 "Verifiable payment receipts": owner-scoped deterministic
        // receipt projection over the authoritative evidence (read-only).
        .route(
            "/api/agents/{id}/payments/receipts/{key}",
            get(receipts::agent_payment_receipt),
        )
        // PHASE 9 "Emergency kill/revoke controls" (D-REV(a), app-side):
        // the owner-scoped emergency revocation of THIS agent's credential.
        // The existing credential library is the enforcement; the route only
        // wires the owner session + the ONE ownership choke point in front
        // of it. Immediate, idempotent, fail-closed, audited (observational).
        .route(
            "/api/agents/{id}/credentials/revoke",
            post(agents::agent_credential_revoke),
        )
        // PHASE 9 "Key rotation / lifecycle": the owner-scoped rotation of
        // THIS agent's funds-less authentication key (mint → validate →
        // atomic record switch → atomic promotion). The vault module is the
        // enforcement; the route wires the owner session + the ONE ownership
        // choke point, refuses disabled agents (no lifecycle bypass), and
        // returns the PUBLIC identity only.
        .route(
            "/api/agents/{id}/auth-key/rotate",
            post(agents::agent_auth_key_rotate),
        )
        // PHASE 9 "Delegation": the owner-scoped revocation of THIS agent's
        // delegated authority through its current parent linkage — one-way
        // for the linkage, immediate (decision-time resolution), cascading
        // to descendants, and observationally audited. The stamp lives on
        // the SAME authoritative policy document the hierarchy reads.
        .route(
            "/api/agents/{id}/delegation/revoke",
            post(agents::agent_delegation_revoke),
        )
        .route(
            "/api/agents/triggers/payments/reconcile",
            post(agents::agent_trigger_payment_reconcile),
        )
        // PHASE 6 STEP 6 — ACTIVITY (derived read-only projection of the
        // intent ledger). GET-only, zero chain calls, zero writes: the
        // owner lane below gates on the single ownership choke point; the
        // credential lane resolves its principal EXCLUSIVELY from
        // X-Agent-Credential and reads only its own agent's directory.
        .route(
            "/api/agents/leaderboard",
            get(leaderboard::agent_leaderboard),
        )
        // PHASE 7 — AGENT STATS (Part 2.3): the OWNER + SINGLE-AGENT HTTP
        // surface. The literal `/api/agents/stats` is registered BEFORE
        // the parameterized `/api/agents/{id}` family so it wins matching;
        // session auth, owner isolation, zero query parameters — see the
        // module doc in stats.rs.
        .route("/api/agents/stats", get(stats::owner_stats))
        .route("/api/agents/{id}/stats", get(stats::agent_stats))
        .route("/api/agents/{id}/activity", get(activity::agent_activity))
        .route(
            "/api/agents/triggers/payments/activity",
            get(activity::agent_trigger_activity),
        )
        // PHASE 7D.3 — OPTIONAL PUBLIC PROOFS: the per-agent, sessionless,
        // credentialless, read-only proof listing (limit + cursor only,
        // following the activity pagination convention). Strict public
        // DTO; private material never leaves the process. See the 7D.3
        // section in verify.rs.
        .route(
            "/api/public/agents/{id}/proofs",
            get(verify::public_agent_proofs),
        )
        // PHASE 7D.1 — PUBLIC VERIFICATION API (core): the ONE public,
        // sessionless, credentialless surface. GET-only -> wrong methods
        // 405; the query param is validated strictly (typed 400); the
        // chain answer maps to the canonical verification DTO (200),
        // the no_status DTO (200), or a fail-closed 503 RPC_UNAVAILABLE.
        // Chain-keyed read-only lookup; zero artifact/ reads, zero
        // wallet/key access, zero filesystem mutation — verify.rs.
        .route("/api/public/verify", get(verify::public_verify))
        // PHASE 7 — AGENT STATS (Part 2.5.1): the CREDENTIAL-lane stats
        // handler core. The literal `/api/agents/triggers/payments/stats`
        // is registered BEFORE the one-segment-parameterized
        // `/api/agents/{id}` family, so it wins matching exactly as the
        // sibling trigger route does (a single segment matches exactly
        // one segment — `triggers` + a literal `payments` segment never
        // resolve to an `{id}` path). The principal comes exclusively
        // from X-Agent-Credential; no session, no owner, zero query
        // parameters — see the module doc in stats.rs.
        .route(
            "/api/agents/triggers/payments/stats",
            get(stats::agent_trigger_stats),
        )
        // Landing page: public schema view endpoint (file-based; no auth; sync)
        .route("/api/schema", get(schema_handler))
        // Clean URL routes: serve HTML files without .html extension
        .route("/wallet", get(serve_wallet))
        .route("/dashboard", get(serve_dashboard))
        .route("/agents", get(serve_agents))
        .route("/leaderboard", get(serve_leaderboard))
        .route("/marketplace", get(serve_marketplace))
        .route("/activity", get(serve_activity))
        .route("/verify", get(serve_verify));

    // Local-development login shortcut: creates a session for a known GitHub
    // user id so chain flows can be tested without the OAuth round-trip.
    // Only mounted when DEV_LOGIN_USER_ID is explicitly set. NEVER set this
    // in any deployed environment.
    let app = match env::var("DEV_LOGIN_USER_ID") {
        Ok(id) if !id.is_empty() => {
            // RELEASE-AUDIT FAIL-CLOSED WARNING: this env var enables an
            // authentication bypass (session without OAuth/credentials).
            // It must be unset in any shared/public deployment — warn loudly
            // at startup so misconfiguration cannot pass unnoticed.
            eprintln!(
                "WARNING: DEV_LOGIN_USER_ID is set — the unauthenticated \
                 /auth/dev-login route is ENABLED. This must NEVER be set in \
                 a shared or public deployment. NOTE: a loopback bind does NOT \
                 fully protect this route — a reverse proxy that forwards to \
                 this address exposes it publicly. In production, unset \
                 DEV_LOGIN_USER_ID (the 404 on /auth/dev-login is the proof)."
            );
            app.route("/auth/dev-login", get(dev_login))
        }
        _ => app,
    }
    .fallback_service(ServeDir::new(static_dir))
    // PHASE 9 "Rate / time limits": the process-wide request meter runs
    // FIRST — before session resolution, intent claim, spend reservation,
    // lane selection, and both execution lanes. Identity: the session
    // principal when one resolves (`user:<id>`), otherwise the client
    // peer address from ConnectInfo (`ip:<addr>`); never any agent-name
    // string, never a client-supplied header. Class comes from the
    // router path (two classes, see rate_limits::classify_path).
    // Denial = 429 RATE_LIMITED + Retry-After (the remaining monotonic
    // window); no intent, no reservation, no ledger state, and no lane
    // fallback can possibly be triggered by it.
    .layer(axum::middleware::from_fn_with_state(
        state.clone(),
        rate_limits_middleware,
    ))
    // PHASE 10: Security headers (X-Frame-Options, Referrer-Policy)
    .layer(axum::middleware::from_fn(add_security_headers))
    .with_state(state);

    // G21.12.36.5 (Render/Koyeb PORT convention): if SERVER_ADDR is unset
    // but the platform injects PORT, bind 0.0.0.0:$PORT. SERVER_ADDR always
    // wins when explicitly set (documented deployment contract).
    let address = match std::env::var("SERVER_ADDR") {
        Ok(a) if !a.is_empty() => a,
        _ => match std::env::var("PORT") {
            Ok(p) if !p.is_empty() => format!("0.0.0.0:{p}"),
            _ => "127.0.0.1:8080".to_string(),
        },
    };

    // RELEASE-AUDIT FAIL-CLOSED (auth bypass guard): the development-login
    // bypass must never be publicly reachable. Refuse to bind a non-loopback
    // address while DEV_LOGIN_USER_ID enables the unauthenticated
    // /auth/dev-login route. Loopback-only deployment (the documented testnet
    // posture: reverse proxy on the same host) is unaffected.
    if dev_login_bind_guard(&address).is_err() {
        eprintln!(
            "FATAL: DEV_LOGIN_USER_ID is set while SERVER_ADDR binds a \
             non-loopback address ({address}). This would expose the \
             unauthenticated /auth/dev-login bypass publicly. Aborting."
        );
        std::process::exit(2);
    }

    println!();
    println!("╔══════════════════════════════════════╗");
    println!("║       Rialo AgentPay Server          ║");
    println!("╚══════════════════════════════════════╝");
    println!();
    println!("Running at: http://{}", address);
    println!("GitHub OAuth: http://{}/auth/github", address);
    println!();

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("failed to bind port 8080");

    // G21.12.27: PG bootstrap BEFORE accepting connections, on a dedicated
    // thread-owned current_thread runtime (keeper pattern). Fixes BOTH prior
    // failures: (a) pre-bind await deadlocked (nested block_on), (b) post-bind
    // gate raced early requests into an uninitialized global client (panic).
    // init_async failure exits the process — PG mode never runs half-initialized.
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let url = std::env::var("DATABASE_URL").unwrap_or_default();
        if url.is_empty() {
            eprintln!("[pg] DATABASE_URL not set (Postgres mode) — fail closed");
            std::process::exit(1);
        }
        crate::pg_store::bootstrap_thread(url);
        crate::pg_store::wait_ready();
    }

    let srv_handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("server error");
    });

    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        crate::pg_store::wait_ready();
        eprintln!("[pg] startup complete: client wired, migrations applied");
    }

    srv_handle.await.expect("server error join");
}

/// The single meter enforcement point (TM-AV-01/TM-AV-03). Resolves the
/// identity plane (session principal → user:<id>; otherwise peer addr →
/// ip:<addr>), classifies the path, consults the meter, and on denial
/// answers the stable 429 envelope — BEFORE anything downstream runs.
/// An internal meter failure FAILS CLOSED (429), never allows.
async fn rate_limits_middleware(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use rate_limits::{MeterVerdict, check, ip_identity, retry_after_seconds, user_identity};

    let class = rate_limits::classify_path(request.uri().path());
    // Identity plane: the existing session principal when present (the
    // SAME resolution handlers use — no new identity mechanism); the
    // client IP otherwise (the credential lane's Argon2 scan is metered
    // per-IP because no principal is knowable before the scan runs —
    // TM-AV-03). The peer address comes exclusively from ConnectInfo;
    // X-Forwarded-For is structurally never consulted (no header trust).
    let identity = match session_user(&state, request.headers()) {
        Some(user) => user_identity(user.id),
        None => ip_identity(peer.ip()),
    };

    match check(&identity, class) {
        Ok(MeterVerdict::Allowed) => next.run(request).await,
        Ok(v @ MeterVerdict::Denied { .. }) => {
            // PHASE 9 audit: the meter stays THE enforcement authority; this
            // is the minimal best-effort persistence of its denial — identity
            // CLASS only (never the raw value), no amount, no headers.
            audit::record(
                audit::rate_limited(
                    agents::now_unix(),
                    identity_class_of(&identity),
                    rate_limits::class_label(class),
                ),
                &audit_root_cwd(),
                None,
            );
            // UX: OAuth entry points redirect to landing page instead of raw JSON.
            let path = request.uri().path();
            if path == "/auth/github" || path == "/auth/dev-login" {
                let retry_sec = retry_after_seconds(&v).unwrap_or(1);
                return axum::response::Redirect::to(&format!(
                    "/?rate_limited=oauth&retry_after={}",
                    retry_sec
                ))
                .into_response();
            }
            rate_limited_response(retry_after_seconds(&v).unwrap_or(1))
        }
        // Fail-closed: an internal meter failure denies the request —
        // identical shape to the normal denial (never a bypass). The
        // unknown-peer fallback identity documents the no-ConnectInfo
        // context; production serving always supplies ConnectInfo.
        Err(_) => {
            let _ = rate_limits::UNKNOWN_PEER_IDENTITY;
            audit::record(
                audit::rate_limited(
                    agents::now_unix(),
                    audit::IdentityClass::Ip,
                    rate_limits::class_label(class),
                ),
                &audit_root_cwd(),
                None,
            );
            rate_limited_response(1000)
        }
    }
}

/// The audit identity class for a meter identity string. The identity VALUE
/// is never persisted; only its plane is (the meter's own identity grammar:
/// `user:` or `ip:` prefixes — pinned by the rate-limits tests).
fn identity_class_of(identity: &str) -> audit::IdentityClass {
    if identity.starts_with("user:") {
        audit::IdentityClass::Session
    } else {
        audit::IdentityClass::Ip
    }
}

/// The production audit root (cwd-relative, same store discipline as every
/// other `artifact/` store).
fn audit_root_cwd() -> std::path::PathBuf {
    std::path::Path::new("artifact").join("agent_audit")
}

/// The stable 429 denial: existing error envelope + RATE_LIMITED code +
/// Retry-After (remaining monotonic window, seconds, rounded up, ≥1).
fn rate_limited_response(retry_after_ms: u64) -> Response {
    let seconds = retry_after_ms.div_ceil(1000).max(1);
    let mut response = api_error(
        StatusCode::TOO_MANY_REQUESTS,
        rate_limits::CODE_RATE_LIMITED,
        "Request rate limit reached for this identity and window; retry after the indicated interval",
    );
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

async fn github_login(State(state): State<AppState>) -> Response {
    let redirect_uri = state.redirect_uri.clone();
    github_login_with_redirect(state, redirect_uri).await
}

async fn github_login_preview(State(state): State<AppState>) -> Response {
    match state.preview_redirect_uri.clone() {
        Some(redirect_uri) => github_login_with_redirect(state, redirect_uri).await,
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Preview login is not configured",
        )
            .into_response(),
    }
}

async fn github_login_with_redirect(state: AppState, redirect_uri: String) -> Response {
    let oauth_state = Uuid::new_v4().to_string();

    {
        let mut states = state.oauth_states.lock().unwrap();

        // Remove states older than 10 minutes.
        states.retain(|_, created| created.elapsed() < Duration::from_secs(600));

        states.insert(oauth_state.clone(), Instant::now());
    }

    // PG mode: also persist authoritatively so the state is single-use
    // across instances/restarts (the in-memory map alone cannot coordinate
    // multi-instance callbacks). A PG failure here is fail-closed: refuse
    // to start the OAuth flow rather than risk a state that cannot be
    // validated later.
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let persisted = tokio::task::block_in_place(|| {
            let oauth_state = oauth_state.clone();
            tokio::runtime::Handle::current().block_on(async move {
                // G21.12.86 — retry-ONCE on connection-level failures only.
                // insert_oauth_state uses ON CONFLICT (state) DO NOTHING, so a
                // retried INSERT is idempotent-safe. Recovery failure keeps the
                // ORIGINAL error and the handler below still fails closed.
                match crate::pg_store::insert_oauth_state_authoritative(
                    &oauth_state,
                    agents::now_unix(),
                )
                .await
                {
                    Ok(()) => Ok(()),
                    Err(first_err) => {
                        eprintln!(
                            "[oauth] oauth_states insert failed; checking reconnect path: {first_err}"
                        );
                        match crate::pg_store::reconnect_global_client().await {
                            Ok(()) => {
                                eprintln!(
                                    "[oauth] reconnected; retrying insert once (idempotent ON CONFLICT DO NOTHING)"
                                );
                                crate::pg_store::insert_oauth_state_authoritative(
                                    &oauth_state,
                                    agents::now_unix(),
                                )
                                .await
                            }
                            Err(re) => {
                                eprintln!("[oauth] reconnect failed: {re}");
                                Err(first_err)
                            }
                        }
                    }
                }
            })
        });
        if let Err(err) = persisted {
            eprintln!("oauth state persist failed (PG, fail-closed): {err}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Login persistence unavailable; login failed closed",
            )
                .into_response();
        }
    }

    let authorize_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read%3Auser&state={}",
        url_encode(&state.client_id),
        url_encode(&redirect_uri),
        url_encode(&oauth_state),
    );

    Redirect::temporary(&authorize_url).into_response()
}

async fn github_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let redirect_uri = state.redirect_uri.clone();
    github_callback_with_redirect(state, query, redirect_uri).await
}

async fn github_callback_preview(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    match state.preview_redirect_uri.clone() {
        Some(redirect_uri) => github_callback_with_redirect(state, query, redirect_uri).await,
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Preview login is not configured",
        )
            .into_response(),
    }
}

async fn github_callback_with_redirect(
    state: AppState,
    query: CallbackQuery,
    redirect_uri: String,
) -> Response {
    if let Some(error) = query.error {
        return (
            StatusCode::BAD_REQUEST,
            format!("GitHub authorization failed: {}", error),
        )
            .into_response();
    }

    let code = match query.code {
        Some(code) => code,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing GitHub authorization code".to_string(),
            )
                .into_response();
        }
    };

    let returned_state = match query.state {
        Some(state_value) => state_value,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing OAuth state".to_string()).into_response();
        }
    };

    // Verify state to protect against CSRF.
    // PG mode: consume authoritatively (atomic DELETE ... WHERE state=$1
    // returning rowcount) so the state is single-use across instances
    // and restarts. FS mode: legacy in-memory remove, unchanged.
    let valid_state = if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let consumed = tokio::task::block_in_place(|| {
            let returned_state = returned_state.clone();
            tokio::runtime::Handle::current().block_on(async move {
                crate::pg_store::consume_oauth_state_authoritative(&returned_state).await
            })
        });
        match consumed {
            Ok(true) => true,
            // Unknown/absent or already-consumed state → replay/replay-of-replay.
            Ok(false) => false,
            Err(err) => {
                eprintln!("oauth state consume failed (PG, fail-closed): {err}");
                false
            }
        }
    } else {
        let mut states = state.oauth_states.lock().unwrap();

        match states.remove(&returned_state) {
            Some(created) => created.elapsed() < Duration::from_secs(600),
            None => false,
        }
    };

    if !valid_state {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid or expired OAuth state".to_string(),
        )
            .into_response();
    }

    // Exchange authorization code for an access token.
    let token_response = match state
        .client
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .form(&[
            ("client_id", state.client_id.as_str()),
            ("client_secret", state.client_secret.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            eprintln!("GitHub token request failed: {}", error);

            return (
                StatusCode::BAD_GATEWAY,
                "Failed to contact GitHub".to_string(),
            )
                .into_response();
        }
    };

    let token: GithubTokenResponse = match token_response.json().await {
        Ok(token) => token,
        Err(error) => {
            eprintln!("Invalid GitHub token response: {}", error);

            return (
                StatusCode::BAD_GATEWAY,
                "Invalid response from GitHub".to_string(),
            )
                .into_response();
        }
    };

    if let Some(error) = token.error {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "GitHub token exchange failed: {} {}",
                error,
                token.error_description.unwrap_or_default()
            ),
        )
            .into_response();
    }

    let access_token = match token.access_token {
        Some(token) => token,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub did not return an access token".to_string(),
            )
                .into_response();
        }
    };

    // Fetch the authenticated GitHub user.
    let github_user: GithubUserResponse = match state
        .client
        .get("https://api.github.com/user")
        .bearer_auth(&access_token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
    {
        Ok(response) => match response.json().await {
            Ok(user) => user,
            Err(error) => {
                eprintln!("GitHub user response failed: {}", error);

                return (
                    StatusCode::BAD_GATEWAY,
                    "Failed to read GitHub user".to_string(),
                )
                    .into_response();
            }
        },
        Err(error) => {
            eprintln!("GitHub user request failed: {}", error);

            return (
                StatusCode::BAD_GATEWAY,
                "Failed to contact GitHub API".to_string(),
            )
                .into_response();
        }
    };

    let user = GithubUser {
        id: github_user.id,
        login: github_user.login,
        name: github_user.name,
        avatar_url: github_user.avatar_url,
    };

    // Create/reuse a dedicated Rialo wallet for this GitHub account.
    // G21.12.3 Phase B: PG mode uses the strict loader (registry-bound
    // identity, fail-closed on missing/corrupt/mismatch). FS keeps legacy.
    let (wallet_address, session_needs_map_insert) = if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let uid_for_blocking = user.id;
        let wallet_result = tokio::task::spawn_blocking(move || {
            load_wallet_strict(uid_for_blocking).map(|kp| kp.pubkey().to_string())
        })
        .await
        .expect("spawn_blocking join");
        let addr_pubkey = match wallet_result {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("wallet integrity failure for user {uid_for_blocking}: {e}");
                if e.contains("WALLET_FILE_MISSING") {
                    let token = issue_wallet_recovery_token(user.id);
                    return wallet_recovery_page(&user.login, &token).into_response();
                }
                eprintln!(
                    "login blocked: wallet integrity failure for user {}",
                    user.id
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "success": false,
                        "error": {
                            "code": "WALLET_INTEGRITY",
                            "message": "Wallet integrity failure; contact the operator."
                        }
                    })),
                )
                    .into_response();
            }
        };
        (addr_pubkey, false)
    } else {
        let mut wallets = state.wallets.lock().unwrap();
        let addr = wallets
            .entry(user.id)
            .or_insert_with(|| load_or_create_wallet(user.id))
            .pubkey()
            .to_string();
        (addr, false)
    };
    let _ = session_needs_map_insert;

    println!("GitHub @{} -> Rialo wallet {}", user.login, wallet_address);

    // Create our own AgentPay session.
    let session_id = Uuid::new_v4().to_string();

    // Persist first (PG = source of truth), then mint the cookie. In PG
    // mode a persistence failure MUST fail closed: no cookie is issued on
    // a session that no other instance could validate. In FS mode the
    // in-memory insert is the store (cannot realistically fail).
    match crate::pg_store::storage_mode() {
        crate::pg_store::StorageMode::Postgres => {
            let persisted = tokio::task::block_in_place(|| {
                let session_id = session_id.clone();
                let (uid, login) = (user.id, user.login.clone());
                tokio::runtime::Handle::current().block_on(async move {
                    crate::pg_store::insert_session_authoritative(
                        &session_id,
                        uid,
                        &login,
                        agents::now_unix(),
                    )
                    .await
                })
            });
            if let Err(err) = persisted {
                eprintln!("session persist failed (PG mode, fail-closed): {err}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Session persistence unavailable; login failed closed",
                )
                    .into_response();
            }
        }
        crate::pg_store::StorageMode::Filesystem => {}
    }

    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), user.clone());
    }

    let mut headers = HeaderMap::new();

    let cookie = format!(
        "agentpay_session={}; Path=/; HttpOnly; SameSite=Lax{}",
        session_id,
        cookie_secure_attr()
    );

    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());

    (headers, Redirect::temporary("/")).into_response()
}

/// Exact UTF-8 message a wallet must sign for the preview wallet lane.
fn wallet_login_message(address: &str, nonce: &str) -> String {
    format!(
        "Rialo AgentPay wallet login\nAddress: {}\nNonce: {}",
        address, nonce
    )
}

fn wallet_nonce_key(address: &str, nonce: &str) -> String {
    format!("wallet-login:{}:{}", address, nonce)
}

fn wallet_user_id(address: &str) -> u64 {
    let hash = blake3::hash(address.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    (u64::from_be_bytes(bytes) & 0x3fff_ffff_ffff_ffff) | 0x4000_0000_0000_0000
}

fn decode_hex_bytes(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 || input.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn normalize_evm_address(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.len() != 42 || !trimmed.starts_with("0x") {
        return None;
    }
    if !trimmed[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", trimmed[2..].to_ascii_lowercase()))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn eip191_message_hash(message: &str) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn recover_evm_address(message: &str, signature_hex: &str) -> Option<String> {
    let bytes = decode_hex_bytes(signature_hex).filter(|b| b.len() == 65)?;
    let recovery_byte = bytes[64];
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(
        recovery_byte.checked_sub(27).unwrap_or(recovery_byte),
    )?;
    let signature = k256::ecdsa::Signature::from_slice(&bytes[..64]).ok()?;
    let digest = eip191_message_hash(message);
    let verifying = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &signature,
        recovery_id,
    )
    .ok()?;
    let encoded = verifying.to_encoded_point(false);
    let public = &encoded.as_bytes()[1..];
    use sha3::Digest;
    let address_hash = sha3::Keccak256::digest(public);
    Some(format!("0x{}", encode_hex(&address_hash[12..])))
}

async fn wallet_login_nonce(
    State(state): State<AppState>,
    Json(request): Json<WalletNonceRequest>,
) -> Response {
    let Some(normalized_address) = normalize_evm_address(&request.address) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "WALLET_ADDRESS_INVALID",
            "A 0x-prefixed EVM wallet address is required.",
        );
    };
    let nonce = Uuid::new_v4().to_string();
    let key = wallet_nonce_key(&normalized_address, &nonce);
    let now = agents::now_unix();

    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let persisted = tokio::task::block_in_place(|| {
            let key = key.clone();
            tokio::runtime::Handle::current().block_on(async move {
                crate::pg_store::insert_oauth_state_authoritative(&key, now).await
            })
        });
        if let Err(err) = persisted {
            eprintln!("wallet nonce persist failed (PG, fail-closed): {err}");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "WALLET_LOGIN_UNAVAILABLE",
                "Wallet login persistence is unavailable.",
            );
        }
    } else {
        let mut states = state.oauth_states.lock().unwrap();
        states.retain(|_, created| created.elapsed() < Duration::from_secs(600));
        states.insert(key, Instant::now());
    }

    Json(WalletNonceResponse {
        success: true,
        message: wallet_login_message(&request.address, &nonce),
        nonce,
    })
    .into_response()
}

async fn wallet_login_verify(
    State(state): State<AppState>,
    Json(request): Json<WalletVerifyRequest>,
) -> Response {
    let Some(normalized_address) = normalize_evm_address(&request.address) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "WALLET_ADDRESS_INVALID",
            "A 0x-prefixed EVM wallet address is required.",
        );
    };
    if request.nonce.len() < 8 || request.nonce.len() > 128 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "WALLET_NONCE_INVALID",
            "A valid login nonce is required.",
        );
    }

    let key = wallet_nonce_key(&normalized_address, &request.nonce);
    let valid = if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let key_for_block = key.clone();
        let consumed = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                crate::pg_store::consume_oauth_state_authoritative(&key_for_block).await
            })
        });
        match consumed {
            Ok(value) => value,
            Err(err) => {
                eprintln!("wallet nonce consume failed (PG, fail-closed): {err}");
                false
            }
        }
    } else {
        let mut states = state.oauth_states.lock().unwrap();
        states
            .remove(&key)
            .map(|created| created.elapsed() < Duration::from_secs(600))
            .unwrap_or(false)
    };
    if !valid {
        return api_error(
            StatusCode::BAD_REQUEST,
            "WALLET_NONCE_INVALID",
            "Invalid or expired wallet login nonce.",
        );
    }

    let message = wallet_login_message(&request.address, &request.nonce);
    let Some(recovered) = recover_evm_address(&message, &request.signature_hex) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "WALLET_SIGNATURE_INVALID",
            "A 65-byte EVM personal_sign signature is required.",
        );
    };
    if recovered != normalized_address {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "WALLET_SIGNATURE_INVALID",
            "The wallet signature does not verify for this address and nonce.",
        );
    }

    let user = GithubUser {
        id: wallet_user_id(&normalized_address),
        login: request.address.clone(),
        name: Some("Wallet user".to_string()),
        avatar_url: None,
    };

    // Wallet login is an identity, not a browser-side money signer. The app's
    // existing server-side payment lane keeps its own wallet; this mints or
    // loads that wallet through the same strict path as a GitHub first login.
    let uid = user.id;
    let wallet = tokio::task::spawn_blocking(move || strict_wallet_load_or_mint(uid))
        .await
        .expect("wallet spawn_blocking join");
    if let Err(err) = wallet {
        eprintln!("wallet login wallet load/mint failed for user {uid}: {err}");
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "WALLET_LOGIN_UNAVAILABLE",
            "The account wallet is temporarily unavailable.",
        );
    }

    let session_id = Uuid::new_v4().to_string();
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let persisted = tokio::task::block_in_place(|| {
            let session_id = session_id.clone();
            let (uid, login) = (user.id, user.login.clone());
            tokio::runtime::Handle::current().block_on(async move {
                crate::pg_store::insert_session_authoritative(
                    &session_id,
                    uid,
                    &login,
                    agents::now_unix(),
                )
                .await
            })
        });
        if let Err(err) = persisted {
            eprintln!("wallet session persist failed (PG, fail-closed): {err}");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "WALLET_LOGIN_UNAVAILABLE",
                "Session persistence is unavailable; login failed closed.",
            );
        }
    }

    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), user.clone());
    }

    let cookie = format!(
        "agentpay_session={}; Path=/; HttpOnly; SameSite=Lax{}",
        session_id,
        cookie_secure_attr()
    );
    let mut response = Json(serde_json::json!({
        "success": true,
        "user": user,
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// Resolve the session user from the request cookies (no side effects).
fn session_user(state: &AppState, headers: &HeaderMap) -> Option<GithubUser> {
    session_user_authoritative(state, headers)
}

/// Look up a session authoritatively for the ACTIVE storage mode.
/// - Filesystem mode: unchanged legacy behavior (in-memory map).
/// - Postgres mode: PG is the source of truth (sessions survive
///   restarts/scale-to-zero across instances). The in-memory map, when
///   present in PG mode, is only a short-lived cache primed on first use.
/// DB errors (lost connectivity, exhausted pool) fail CLOSED: None is
/// returned so the caller answers NOT_AUTHENTICATED instead of trusting
/// a possibly-revoked session.
fn session_user_authoritative(state: &AppState, headers: &HeaderMap) -> Option<GithubUser> {
    let session_id = get_cookie(headers, "agentpay_session")?;
    match crate::pg_store::storage_mode() {
        crate::pg_store::StorageMode::Filesystem => {
            let sessions = state.sessions.lock().unwrap();
            sessions.get(&session_id).cloned()
        }
        crate::pg_store::StorageMode::Postgres => {
            // Block briefly on the DB via the blocking pool — global_client()
            // is async and must not run on the runtime worker threads.
            let user = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    crate::pg_store::get_session_authoritative(&session_id, agents::now_unix())
                        .await
                })
            });
            match user {
                Ok(Some((id, login))) => Some(GithubUser {
                    id,
                    login,
                    // sessions table intentionally stores only (id, login);
                    // display fields are re-derivable and never security-
                    // relevant (kept None here, matching /api/me consumers).
                    name: None,
                    avatar_url: None,
                }),
                // Revoked/unknown/expired session, OR a DB failure: both are
                // treated as unauthenticated (fail-closed by decision).
                _ => None,
            }
        }
    }
}

/// Get (or lazily load/create) the persisted wallet pubkey for a user.
fn wallet_address_for(state: &AppState, user_id: u64) -> String {
    let mut wallets = state.wallets.lock().unwrap();

    wallets
        .entry(user_id)
        .or_insert_with(|| load_or_create_wallet(user_id))
        .pubkey()
        .to_string()
}

/// Get (or lazily load/create) the wallet keypair FILE path for a user — the
/// only wallet representation the Rialo CLI understands. Key material never
/// leaves this file; it is never logged or returned over HTTP.
fn wallet_path_for(user_id: u64) -> PathBuf {
    // Ensure the file exists (load_or_create_wallet persists it); the
    // in-memory Keypair cache in AppState is for pubkey display only.
    let path = wallet_file(user_id);
    if !path.exists() {
        load_or_create_wallet(user_id);
    }
    path
}

async fn current_user(State(state): State<AppState>, headers: HeaderMap) -> Json<SessionResponse> {
    let user = session_user(&state, &headers);

    // G21.12.5: PG mode uses the strict loader (fail-closed on missing/
    // corrupt/mismatch); degrade gracefully instead of minting replacements.
    let wallet_address = match user.as_ref() {
        Some(u) => {
            if matches!(
                crate::pg_store::storage_mode(),
                crate::pg_store::StorageMode::Postgres
            ) {
                let uid = u.id;
                match tokio::task::spawn_blocking(move || load_wallet_strict(uid))
                    .await
                    .expect("spawn_blocking join")
                {
                    Ok(kp) => Some(kp.pubkey().to_string()),
                    Err(e) => {
                        eprintln!("wallet integrity failure for user {uid}: {e}");
                        None
                    }
                }
            } else {
                Some(wallet_address_for(&state, u.id))
            }
        }
        None => None,
    };

    // Balance requires the Rialo RPC. A failure must never be reported as
    // "0" or crash the handler — degrade with an explicit status instead.
    let mut balance = None;
    let mut balance_status = "no_wallet".to_string();
    let mut balance_error = None;

    if let Some(address) = wallet_address.as_deref() {
        let rialo = Arc::clone(&state.rialo);
        let address = address.to_string();
        balance_status = match tokio::task::spawn_blocking(move || rialo.balance(&address)).await {
            Ok(Ok(amount)) => {
                balance = Some(format!("{} RLO", amount));
                "ok".to_string()
            }
            Ok(Err(err)) => {
                let json = balance_error_json(&err);
                balance_error = Some(json);
                "unavailable".to_string()
            }
            Err(join_err) => {
                balance_error = Some(serde_json::json!({
                    "code": "RIALO_ERROR",
                    "message": join_err.to_string()
                }));
                "unavailable".to_string()
            }
        };
    }

    Json(SessionResponse {
        logged_in: user.is_some(),
        user,
        wallet_address,
        balance,
        balance_status,
        balance_error,
    })
}

async fn faucet(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // G21.11 kill-switch: reject before any faucet/airdrop operation.
    // G21 scoped-gate exception: AGENTPAY_ENABLE_FAUCET=1 allows ONLY this
    // testnet faucet through while AGENTPAY_DISABLE_TRANSFERS=1 keeps every
    // direct/agent payment lane fail-closed (their checks are untouched).
    if transfers_disabled() && !faucet_enabled() {
        return transfers_disabled_error();
    }
    let user = match session_user(&state, &headers) {
        Some(user) => user,
        None => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "NOT_AUTHENTICATED",
                "Not logged in",
            );
        }
    };

    // G21.12.3 Phase B: strict integrity — refuse when a registered wallet's
    // file is missing/corrupt (no silent mint replacement).
    let wallet_strict =
        match tokio::task::spawn_blocking(move || strict_wallet_load_or_mint(user.id))
            .await
            .expect("spawn_blocking join")
        {
            Ok(k) => k,
            Err(e) => {
                eprintln!("wallet integrity failure for user {}: {e}", user.id);
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WALLET_INTEGRITY",
                    "Wallet integrity failure; contact the operator.",
                );
            }
        };
    let wallet_address = wallet_strict.pubkey().to_string();

    let result = {
        let rialo = Arc::clone(&state.rialo);
        let address = wallet_address.clone();
        tokio::task::spawn_blocking(move || rialo.airdrop(&address, "1")).await
    };

    match result {
        Ok(Ok(())) => {
            // Read back the true balance; if that fails, report success with
            // an unknown balance rather than a misleading number.
            let rialo = Arc::clone(&state.rialo);
            let address = wallet_address.clone();
            let balance = tokio::task::spawn_blocking(move || rialo.balance(&address))
                .await
                .ok()
                .and_then(|r| r.ok())
                .map(|amount| format!("{} RLO", amount));

            Json(serde_json::json!({
                "success": true,
                "wallet_address": wallet_address,
                "balance": balance
            }))
            .into_response()
        }
        Ok(Err(err)) => rialo_error_response(&err),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RIALO_ERROR",
            &join_err.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct PaymentRequest {
    to: String,
    amount: f64,
}

/// Validate a Rialo address string (shared by direct + program payment paths).
fn valid_rialo_address(addr: &str) -> bool {
    addr.len() >= 32 && addr.len() <= 44 && addr.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Validate a client-supplied workflow slug: 64 hex chars (32 bytes).
fn valid_workflow_slug(slug: &str) -> bool {
    slug.len() == 64 && slug.chars().all(|c| c.is_ascii_hexdigit())
}

/// RLO (decimal) → kelvin (integer, 1 RLO = 1e9 kelvin). Rejects
/// non-finite, zero/negative, or sub-kelvin amounts.
fn rlo_to_kelvin(amount: f64) -> Option<String> {
    if !amount.is_finite() || amount <= 0.0 {
        return None;
    }
    let kelvin = (amount * 1e9).round();
    if kelvin < 1.0 || kelvin > u64::MAX as f64 {
        return None;
    }
    Some(kelvin as u64).map(|k| k.to_string())
}

// ---------------------------------------------------------------------------
// Program-mediated payment endpoints (Venus workflow: start → execute)
// ---------------------------------------------------------------------------
//
// Both endpoints run the two-step workflow inside ONE request: start(amount,
// recipient, slug) then execute(slug, recipient), signed by the caller's own
// wallet file via an ephemeral per-invocation CLI config (see rialo.rs —
// `program invoke` has no --keypair; no permanent aliases, no key copies).
//
// VERIFIED LIMITATION (testnet, 2026-09-28): on the deployed program
// (CuevBS…ZtH3) the system-transfer CPI inside `execute` lands on the wrong
// account — funds move payer → workflow-PDA instead of payer → recipient.
// The bug is in the deployed bytecode's account layout (recipient index),
// NOT in this integration layer: a caller-side manifest fix was proven to
// change the outer account order but not the CPI destination. The program
// PDA holds the funds and the workflow state machine is executable
// (executed=true blocks refunds). These endpoints therefore REFUSE to
// escrow real funds until a fixed program is deployed: amounts above the
// AGENTPAY_PROGRAM_TEST_MAX_RLO cap (default 0) return
// PROGRAM_ESCROW_BUG. The routes exist for the integration plumbing and
// become active the moment the program is redeployed correctly — flip the
// cap via env, no code change. /api/payment (direct transfer) remains the
// working payment path.

#[derive(Deserialize)]
struct ProgramStartRequest {
    to: String,
    amount: f64,
    /// Optional 32-byte hex slug; server generates one when omitted.
    #[serde(default)]
    slug: Option<String>,
}

/// 32 random bytes as lowercase hex (workflow slug).
fn random_slug_hex() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// GET /api/program/status — read-only program readiness snapshot:
/// configuration, manifest-integrity alignment with the deployed bytecode,
/// test-cap state, and a read-only on-chain existence probe. Never submits
/// a transaction and never exposes secrets.
async fn program_status(State(state): State<AppState>) -> Response {
    let rialo = Arc::clone(&state.rialo);
    match tokio::task::spawn_blocking(move || rialo.program_status()).await {
        Ok(snapshot) => {
            let mut snapshot = snapshot;
            // Fold in RPC health for the status view (read-only probe).
            let rialo2 = Arc::clone(&state.rialo);
            snapshot["rpc"] = match tokio::task::spawn_blocking(move || rialo2.health()).await {
                Ok(Ok(height)) => serde_json::json!({ "status": "ok", "block_height": height }),
                Ok(Err(err)) => serde_json::json!({
                    "status": "unavailable",
                    "error": { "code": err.code, "message": err.detail }
                }),
                Err(_) => serde_json::json!({ "status": "error" }),
            };
            snapshot["payment_route_note"] =
                "POST /api/payment (direct transfer) is the normal payment route; program payments require an explicit AGENTPAY_PROGRAM_TEST_MAX_RLO > 0 set by an operator.".into();
            Json(snapshot).into_response()
        }
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PROGRAM_STATUS_ERROR",
            &join_err.to_string(),
        ),
    }
}

async fn program_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProgramStartRequest>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Some(user) => user,
        None => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "NOT_AUTHENTICATED",
                "Not logged in",
            );
        }
    };

    // G21.12.5: strict wallet integrity (PG mode) — fail closed on missing/
    // corrupt/mismatch BEFORE any program transfer attempt.
    // G21.12.10: verify first, then pin the exact file path for execution —
    // no mint-on-miss may run after this point in PG mode.
    #[allow(unused_mut)]
    let mut verified_wallet_path: Option<std::path::PathBuf> = None;
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let uid = user.id;
        match tokio::task::spawn_blocking(move || load_wallet_strict(uid))
            .await
            .expect("spawn_blocking join")
        {
            Ok(kp) => {
                let _ = kp;
                verified_wallet_path = Some(wallet_file(uid));
            }
            Err(e) => {
                eprintln!("wallet integrity failure for user {uid}: {e}");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WALLET_INTEGRITY",
                    "Wallet integrity failure; contact the operator.",
                );
            }
        }
    }

    if let Err(refusal) = program_payment_guard(&state, None) {
        return refusal;
    }

    let program_id = state.rialo.program_id.clone().unwrap_or_default();

    if !valid_rialo_address(&request.to) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECIPIENT",
            "Recipient is not a valid Rialo address",
        );
    }
    let kelvin = match rlo_to_kelvin(request.amount) {
        Some(k) => k,
        None => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_AMOUNT",
                "Amount must be a positive number of RLO with kelvin precision",
            );
        }
    };
    if let Err(refusal) = program_payment_guard(&state, Some(request.amount)) {
        return refusal;
    }

    let slug = match request.slug {
        Some(slug) if valid_workflow_slug(&slug) => slug,
        Some(_) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_SLUG",
                "Slug must be 64 hex characters (32 bytes)",
            );
        }
        None => random_slug_hex(),
    };

    // G21.12.10: use the verified path (PG) or legacy FS path; never mint
    // past this point in PG mode.
    let wallet_path = verified_wallet_path.unwrap_or_else(|| wallet_path_for(user.id));
    let to = request.to.clone();
    let amount_rlo = request.amount;
    let slug_out = slug.clone();

    let result = {
        let rialo = Arc::clone(&state.rialo);
        tokio::task::spawn_blocking(move || {
            let args = vec![
                format!("workflow_pda_slug={}", slug),
                format!("amount={}", kelvin),
                format!("recipient={}", to),
            ];
            rialo.program_invoke(&wallet_path, "start", &args)
        })
        .await
    };

    match result {
        Ok(Ok(signature)) => Json(serde_json::json!({
            "success": true,
            "step": "start",
            "program_id": program_id,
            "workflow_slug": slug_out,
            "signature": signature,
            "recipient": request.to,
            "amount_rlo": amount_rlo,
            "warning": "funds are held by the program workflow PDA until /api/payment/program/execute; with the current deployed program execute pays the PDA, not the recipient",
            "next": "POST /api/payment/program/execute { slug, to }"
        }))
        .into_response(),
        Ok(Err(err)) => rialo_error_response(&err),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RIALO_ERROR",
            &join_err.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct ProgramExecuteRequest {
    slug: String,
    to: String,
}

async fn program_execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProgramExecuteRequest>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Some(user) => user,
        None => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "NOT_AUTHENTICATED",
                "Not logged in",
            );
        }
    };

    // G21.12.5: strict wallet integrity (PG mode) — fail closed on missing/
    // corrupt/mismatch BEFORE any program transfer attempt.
    // G21.12.10: verify first, then pin the exact file path for execution —
    // no mint-on-miss may run after this point in PG mode.
    #[allow(unused_mut)]
    let mut verified_wallet_path: Option<std::path::PathBuf> = None;
    if matches!(
        crate::pg_store::storage_mode(),
        crate::pg_store::StorageMode::Postgres
    ) {
        let uid = user.id;
        match tokio::task::spawn_blocking(move || load_wallet_strict(uid))
            .await
            .expect("spawn_blocking join")
        {
            Ok(kp) => {
                let _ = kp;
                verified_wallet_path = Some(wallet_file(uid));
            }
            Err(e) => {
                eprintln!("wallet integrity failure for user {uid}: {e}");
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WALLET_INTEGRITY",
                    "Wallet integrity failure; contact the operator.",
                );
            }
        }
    }

    if let Err(refusal) = program_payment_guard(&state, None) {
        return refusal;
    }

    let program_id = state.rialo.program_id.clone().unwrap_or_default();

    if !valid_workflow_slug(&request.slug) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_SLUG",
            "Slug must be 64 hex characters (32 bytes)",
        );
    }
    if !valid_rialo_address(&request.to) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECIPIENT",
            "Recipient is not a valid Rialo address",
        );
    }

    // G21.12.10: use the verified path (PG) or legacy FS path; never mint
    // past this point in PG mode.
    let wallet_path = verified_wallet_path.unwrap_or_else(|| wallet_path_for(user.id));
    let to = request.to.clone();
    let slug = request.slug.clone();

    let result = {
        let rialo = Arc::clone(&state.rialo);
        tokio::task::spawn_blocking(move || {
            let args = vec![
                format!("workflow_pda_slug={}", slug),
                format!("recipient={}", to),
            ];
            rialo.program_invoke(&wallet_path, "execute", &args)
        })
        .await
    };

    match result {
        Ok(Ok(signature)) => Json(serde_json::json!({
            "success": true,
            "step": "execute",
            "program_id": program_id,
            "workflow_slug": request.slug,
            "signature": signature,
            "recipient": request.to,
            "warning": "on the currently deployed program the transfer is credited to the workflow PDA, NOT the recipient (verified 2026-09-28)"
        }))
        .into_response(),
        Ok(Err(err)) => rialo_error_response(&err),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RIALO_ERROR",
            &join_err.to_string(),
        ),
    }
}

/// Transfer RLO from the caller's persisted wallet to another address.
/// Signing happens in the Rialo CLI against the wallet file; the server never
/// handles or transmits key material.
///
/// Flow: validate recipient/amount → read the true on-chain balance
/// (a failure is RIALO_RPC_UNAVAILABLE, never a fake zero) → reject with
/// INSUFFICIENT_FUNDS when the balance (minus fee headroom) cannot cover the
/// amount → transfer → re-read and return the updated balance when available.
async fn payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PaymentRequest>,
) -> Response {
    let user = match session_user(&state, &headers) {
        Some(user) => user,
        None => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "NOT_AUTHENTICATED",
                "Not logged in",
            );
        }
    };
    // G21.11 kill-switch: reject BEFORE balance reads, wallet minting, or
    // any transfer execution.
    if transfers_disabled() {
        return transfers_disabled_error();
    }
    // G21.12.3 Phase B: strict wallet integrity (PG): registered-but-missing
    // file refuses with WALLET_FILE_MISSING instead of minting a replacement.
    let wallet = match tokio::task::spawn_blocking(move || strict_wallet_load_or_mint(user.id))
        .await
        .expect("spawn_blocking join")
    {
        Ok(k) => k,
        Err(e) => {
            eprintln!("wallet integrity failure for user {}: {e}", user.id);
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "WALLET_INTEGRITY",
                "Wallet integrity failure; contact the operator.",
            );
        }
    };
    let wallet_path = wallet_file(user.id);
    let _ = &wallet;

    if !valid_rialo_address(&request.to) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECIPIENT",
            "Recipient is not a valid Rialo address",
        );
    }

    if !request.amount.is_finite() || request.amount <= 0.0 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AMOUNT",
            "Amount must be a positive number of RLO",
        );
    }
    // Kelvin-precision check: amounts finer than 1 kelvin (1e-9 RLO) cannot
    // be transferred and would silently round.
    if rlo_to_kelvin(request.amount).is_none() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AMOUNT",
            "Amount must be a positive multiple of 1 kelvin (1e-9 RLO)",
        );
    }

    let wallet_path = wallet_file(user.id);

    // Resolve the payer address from the wallet file (public key only).
    let from = {
        let wallet_path = wallet_path.clone();
        match tokio::task::spawn_blocking(move || {
            let mut file = std::fs::File::open(&wallet_path).ok()?;
            let kp = rialo_s_keypair::read_keypair(&mut file).ok()?;
            Some(kp.pubkey().to_string())
        })
        .await
        {
            Ok(Some(address)) => address,
            Ok(None) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RIALO_WALLET_ERROR",
                    "Wallet file could not be read to resolve the payer address",
                );
            }
            Err(join_err) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RIALO_ERROR",
                    &join_err.to_string(),
                );
            }
        }
    };

    // Pre-check the balance against the REAL chain state. An RPC failure is
    // surfaced as RIALO_RPC_UNAVAILABLE (503) — never treated as "0".
    let balance_before = {
        let rialo = Arc::clone(&state.rialo);
        let from = from.clone();
        match tokio::task::spawn_blocking(move || rialo.balance(&from)).await {
            Ok(Ok(amount)) => amount,
            Ok(Err(err)) => return rialo_error_response(&err),
            Err(join_err) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "RIALO_ERROR",
                    &join_err.to_string(),
                );
            }
        }
    };

    // Leave a small headroom for the transaction fee; if the node reports a
    // fee-adjusted shortfall the transfer itself will fail with a real error.
    const FEE_HEADROOM_RLO: f64 = 0.001;
    if balance_before < request.amount + FEE_HEADROOM_RLO {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INSUFFICIENT_FUNDS",
            &format!(
                "Wallet balance is {} RLO; payment of {} RLO (+fee headroom) is not covered. Use POST /api/faucet to fund the wallet.",
                balance_before, request.amount
            ),
        );
    }

    let to = request.to.clone();
    let amount = request.amount.to_string();

    let result = {
        let rialo = Arc::clone(&state.rialo);
        let wallet_path = wallet_path.clone();
        let to = to.clone();
        let amount = amount.clone();
        tokio::task::spawn_blocking(move || rialo.transfer(&wallet_path, &to, &amount)).await
    };

    match result {
        Ok(Ok(signature)) => {
            // Best-effort updated balance; unknown (null) is reported as
            // unknown, never as a fake number.
            let rialo = Arc::clone(&state.rialo);
            let from2 = from.clone();
            let balance_after = tokio::task::spawn_blocking(move || rialo.balance(&from2))
                .await
                .ok()
                .and_then(|r| r.ok());

            Json(serde_json::json!({
                "success": true,
                "signature": signature,
                "from": from,
                "to": to,
                "amount": amount,
                "balance_before_rlo": balance_before,
                "balance_after_rlo": balance_after,
            }))
            .into_response()
        }
        Ok(Err(err)) => rialo_error_response(&err),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RIALO_ERROR",
            &join_err.to_string(),
        ),
    }
}

/// Infrastructure health endpoint: reports Rialo RPC state without requiring
/// RELEASE-AUDIT: session-cookie Secure attribute, opt-in via
/// AGENTPAY_COOKIE_SECURE=1. Default OFF keeps plain-HTTP local/testnet
/// development working; MUST be set whenever the app is served over HTTPS
/// (directly or behind a TLS-terminating reverse proxy) so the session
/// cookie is never transmitted over plaintext.
/// G21.11 — centralized transfer kill-switch.
///
/// AGENTPAY_DISABLE_TRANSFERS=1 (exactly "1" or "true", case-insensitive)
/// blocks every money-movement execution path: direct transfers, faucet
/// airdrops, agent payment execution (owner + credential lanes), task
/// payout bridging, and program-mediated payments. Read-only endpoints
/// (auth, balances, listings, verification, reconciliation, activity)
/// remain untouched.
///
/// Malformed values fail SAFE: anything other than unset/empty/0/false
/// (case-insensitive) is treated as ENABLED (logged once at first read).
/// Rejection happens BEFORE wallet minting, balance reads, reservations,
/// signing, or submission — so no state is created for rejected requests.
fn transfers_disabled() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| parse_transfers_disabled(&std::env::var("AGENTPAY_DISABLE_TRANSFERS")))
}

/// G21 — scoped testnet faucet gate. Controls ONLY the `/api/faucet`
/// handler so the testnet faucet can be enabled independently while
/// `AGENTPAY_DISABLE_TRANSFERS=1` keeps every direct/agent payment lane
/// fail-closed. Pure parse rule (fail-safe, mirrors the transfers rule
/// but inverted semantics: the flag ENABLES):
///   unset / empty / "0" / "false" (any case) -> false (faucet stays gated)
///   "1" / "true" (any case)                  -> true  (faucet allowed)
///   any other non-empty value                -> false (FAIL-SAFE: an invalid
///   configuration is never silently treated as "faucet enabled")
fn parse_faucet_enabled(raw: &Result<String, std::env::VarError>) -> bool {
    match raw {
        Ok(v) if v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") => true,
        Ok(other) => {
            if !other.trim().is_empty()
                && !other.eq_ignore_ascii_case("0")
                && !other.eq_ignore_ascii_case("false")
            {
                eprintln!(
                    "AGENTPAY_ENABLE_FAUCET has invalid value {:?}; failing SAFE (faucet gated)",
                    other
                );
            }
            false
        }
        Err(_) => false,
    }
}

fn faucet_enabled() -> bool {
    static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| parse_faucet_enabled(&std::env::var("AGENTPAY_ENABLE_FAUCET")))
}

/// Pure parse rule (documented contract):
///   unset / empty / "0" / "false" (any case)  -> false (transfers allowed)
///   "1" / "true" (any case)                   -> true  (transfers blocked)
///   any other non-empty value                 -> true  (FAIL-SAFE: invalid
///   configuration is never silently treated as "transfers allowed")
fn parse_transfers_disabled(raw: &Result<String, std::env::VarError>) -> bool {
    match raw {
        Ok(v) if v.trim().is_empty() => false,
        Ok(v) if v.eq_ignore_ascii_case("0") || v.eq_ignore_ascii_case("false") => false,
        Ok(v) if v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") => true,
        Ok(other) => {
            eprintln!(
                "AGENTPAY_DISABLE_TRANSFERS has invalid value {:?}; failing SAFE (transfers disabled)",
                other
            );
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
fn parse_transfers_disabled_for_test(raw: &str) -> bool {
    parse_transfers_disabled(&Ok(raw.to_string()))
}

#[cfg(test)]
fn parse_faucet_enabled_for_test(raw: &str) -> bool {
    parse_faucet_enabled(&Ok(raw.to_string()))
}

#[cfg(test)]
mod scoped_faucet_gate_tests {
    use super::*;

    /// G21 scoped-gate T1 — faucet flag parses exactly per contract:
    /// only "1"/"true" (any case) enable; everything else (unset handled by
    /// the VarError arm; empty/0/false/invalid) stays gated.
    #[test]
    fn faucet_enabled_parse_contract() {
        assert!(parse_faucet_enabled_for_test("1"));
        assert!(parse_faucet_enabled_for_test("true"));
        assert!(parse_faucet_enabled_for_test("TRUE"));
        assert!(!parse_faucet_enabled_for_test(""));
        assert!(!parse_faucet_enabled_for_test("0"));
        assert!(!parse_faucet_enabled_for_test("false"));
        assert!(!parse_faucet_enabled_for_test("yes")); // invalid → FAIL-SAFE gated
        assert!(!parse_faucet_enabled_for_test(" on ")); // invalid → FAIL-SAFE gated
    }

    /// T2 — the scoped rule: kill-switch ON + faucet ON ⇒ faucet proceeds
    /// (passed the gate); kill-switch ON + faucet OFF ⇒ blocked; and the
    /// combined predicate used by the handler matches this table exactly.
    #[test]
    fn scoped_gate_truth_table() {
        let blocked = |transfers: bool, faucet: bool| transfers && !faucet;
        // production default: transfers ON(disabled), faucet OFF ⇒ /api/faucet blocked
        assert!(blocked(true, false));
        // scoped enable: transfers ON(disabled), faucet ON ⇒ faucet proceeds
        assert!(!blocked(true, true));
        // transfers fully allowed (env unset): gate irrelevant
        assert!(!blocked(false, false));
        assert!(!blocked(false, true));
    }

    /// T3 — CRITICAL regression proof: all OTHER kill-switch guards still use
    /// `transfers_disabled()` alone. Enforced structurally (grep of guarded
    /// sites in CI + review): server.rs `/api/payment`, agents.rs
    /// `execute_agent_payment`, `agent_payment`, `execute_agent_payment_v2`,
    /// `agent_trigger_payment` — all gate on `transfers_disabled()` ONLY;
    /// `faucet_enabled()` appears in exactly one guard (`/api/faucet`).
    /// This test pins the PURE predicates (env-independent): with the
    /// documented production defaults (DISABLE_TRANSFERS=1, ENABLE_FAUCET
    /// unset) the scoped gate must block, with the scoped exception it must
    /// pass — matching the T2 truth table.
    #[test]
    fn scoped_gate_matches_production_defaults() {
        // parse layer: production default env values
        assert!(parse_transfers_disabled_for_test("1")); // kill-switch ON
        assert!(
            !parse_transfers_disabled(&Err(std::env::VarError::NotPresent)),
            "transfers gate defaults OPEN only when env ABSENT (not deployed state)"
        );
        // faucet: unset env ⇒ parse arm Err(_) ⇒ gated (default disabled)
        assert!(!parse_faucet_enabled(&Err(std::env::VarError::NotPresent)));
        // the actual production-default scenario
        let transfers_on = parse_transfers_disabled_for_test("1"); // true
        let faucet_off = parse_faucet_enabled(&Err(std::env::VarError::NotPresent)); // false
        assert!(transfers_on && !faucet_off, "blocked(true,false) must hold");
    }
}

fn transfers_disabled_error() -> Response {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "TRANSFERS_DISABLED",
        "Transfers are disabled by operator configuration (AGENTPAY_DISABLE_TRANSFERS).",
    )
}

fn cookie_secure_attr() -> &'static str {
    match std::env::var("AGENTPAY_COOKIE_SECURE").as_deref() {
        Ok("1") | Ok("true") => "; Secure",
        _ => "",
    }
}

/// login, so operators and the frontend can show node status.
async fn health(State(state): State<AppState>) -> Response {
    let rialo: Arc<RialoConfig> = Arc::clone(&state.rialo);
    match tokio::task::spawn_blocking(move || rialo.health()).await {
        // SECURITY (release audit): this endpoint is UNAUTHENTICATED — it
        // must not disclose the configured RPC URL (which can embed
        // credentials in query strings) or upstream error detail text.
        // Operators inspecting RPC details should use server-side logs.
        Ok(Ok(block_height)) => Json(serde_json::json!({
            "agentpay": "ok",
            "rialo_rpc": "ok",
            "block_height": block_height
        }))
        .into_response(),
        Ok(Err(_err)) => Json(serde_json::json!({
            "agentpay": "ok",
            "rialo_rpc": "unavailable"
        }))
        .into_response(),
        Err(_) => Json(serde_json::json!({
            "agentpay": "ok",
            "rialo_rpc": "error"
        }))
        .into_response(),
    }
}

/// Release-audit guard: returns Err only when the unauthenticated
/// development-login bypass is enabled AND the bind address would expose it
/// beyond loopback. Pure function of the (dev-login-state, address) pair so
/// the production fail-closed behavior is testable without process exit.
pub(crate) fn dev_login_bind_guard(address: &str) -> Result<(), &'static str> {
    let dev_enabled = std::env::var("DEV_LOGIN_USER_ID")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if !dev_enabled {
        return Ok(());
    }
    // Extract the host portion of a socket address. Forms handled:
    //   "127.0.0.1:8080" | "8080" (port-only) | "::1" (bare IPv6) |
    //   "[::1]:8080" (bracketed IPv6) | "localhost:8080" | "" (empty).
    // Fail-closed rule: only KNOWN loopback forms pass; anything unparseable
    // or hostname-based is treated as exposed. "localhost" additionally
    // requires that it still resolves to loopback — but DNS is operator
    // territory, so "localhost" is accepted as the documented local form
    // while a hostile /etc/hosts entry is an operator-machine compromise,
    // outside the threat model.
    let host = if address.starts_with('[') {
        // bracketed IPv6: [::1]:8080 → ::1
        address
            .split_once(']')
            .and_then(|(h, _)| h.strip_prefix('['))
            .unwrap_or(address)
    } else if address.matches(':').count() == 1 {
        // host:port
        address.split_once(':').map(|(h, _)| h).unwrap_or(address)
    } else if address.matches(':').count() >= 2 {
        // bare IPv6 (e.g. "::1") — contains multiple colons, no brackets
        address
    } else {
        // no colon: either a bare hostname or garbage — treated as exposed
        address
    };

    let loopback = match host.parse::<std::net::IpAddr>() {
        // Genuine IP: must actually BE a loopback address (128.* ranges are
        // NOT loopback; only 127.0.0.0/8 and ::1 are).
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost", // hostname form: documented local name
    };
    if loopback {
        Ok(())
    } else {
        Err("dev-login enabled on non-loopback bind")
    }
}

/// Local-development login: creates a session for the configured user id so
/// chain flows (balance/faucet/payment) can be exercised without GitHub OAuth.
/// Route only exists when DEV_LOGIN_USER_ID is set at startup.
async fn dev_login(State(state): State<AppState>) -> Response {
    let user_id: u64 = match env::var("DEV_LOGIN_USER_ID")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        Some(id) => id,
        None => return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "dev login disabled"),
    };

    let user = GithubUser {
        id: user_id,
        login: "dev-user".to_string(),
        name: Some("Dev User (local only)".to_string()),
        avatar_url: None,
    };

    let session_id = Uuid::new_v4().to_string();

    // Persist first (PG = source of truth), then mint the cookie. In PG
    // mode a persistence failure MUST fail closed: no cookie is issued on
    // a session no other instance could validate.
    match crate::pg_store::storage_mode() {
        crate::pg_store::StorageMode::Postgres => {
            let persisted = tokio::task::block_in_place(|| {
                let session_id = session_id.clone();
                let login = user.login.clone();
                tokio::runtime::Handle::current().block_on(async move {
                    crate::pg_store::insert_session_authoritative(
                        &session_id,
                        user_id,
                        &login,
                        agents::now_unix(),
                    )
                    .await
                })
            });
            if let Err(err) = persisted {
                eprintln!("dev-login session persist failed (PG, fail-closed): {err}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Session persistence unavailable; login failed closed",
                )
                    .into_response();
            }
        }
        crate::pg_store::StorageMode::Filesystem => {}
    }

    {
        let mut sessions = state.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), user.clone());
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "agentpay_session={}; Path=/; HttpOnly; SameSite=Lax{}",
            session_id,
            cookie_secure_attr()
        ))
        .unwrap(),
    );

    (headers, Redirect::temporary("/wallet")).into_response()
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = get_cookie(&headers, "agentpay_session") {
        // FS mode: in-memory removal only (legacy behavior preserved).
        {
            let mut sessions = state.sessions.lock().unwrap();
            sessions.remove(&session_id);
        }
        // PG mode: authoritative deletion so the session cannot remain
        // valid on any other instance or after a restart. A DB failure
        // here is logged but does not block cookie clearing (the failed
        // row can be re-revoked; review requires the same cookie anyway).
        if matches!(
            crate::pg_store::storage_mode(),
            crate::pg_store::StorageMode::Postgres
        ) {
            let revoked = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    crate::pg_store::delete_session_authoritative(&session_id).await
                })
            });
            if let Err(err) = revoked {
                eprintln!("logout: PG session revocation failed: {err}");
            }
        }
    }

    let mut response_headers = HeaderMap::new();

    response_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "agentpay_session=; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=0",
            cookie_secure_attr()
        ))
        .unwrap(),
    );

    (StatusCode::OK, response_headers, "logged out").into_response()
}

// Landing page: public schema view handler (no auth required)
async fn schema_handler() -> ([(&'static str, &'static str); 1], &'static str) {
    (
        [("content-type", "application/json")],
        include_str!("../schema/credentials.schema.json"),
    )
}

// Clean URL handlers: serve HTML files without .html extension
async fn serve_wallet() -> impl IntoResponse {
    serve_html_file("wallet.html").await
}
async fn serve_dashboard() -> impl IntoResponse {
    serve_html_file("dashboard.html").await
}
async fn serve_agents() -> impl IntoResponse {
    serve_html_file("agents.html").await
}
async fn serve_leaderboard() -> impl IntoResponse {
    serve_html_file("leaderboard.html").await
}
async fn serve_marketplace() -> impl IntoResponse {
    serve_html_file("marketplace.html").await
}
async fn serve_activity() -> impl IntoResponse {
    serve_html_file("activity.html").await
}
async fn serve_verify() -> impl IntoResponse {
    serve_html_file("verify.html").await
}

async fn serve_html_file(filename: &str) -> impl IntoResponse {
    let static_dir = if Path::new("frontend/src/index.html").exists() {
        "frontend/src"
    } else if Path::new("public/index.html").exists() {
        "public"
    } else {
        "."
    };
    let path = Path::new(static_dir).join(filename);
    match tokio::fs::read_to_string(path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html")],
            content,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();

        if let Some(value) = cookie.strip_prefix(&format!("{}=", name)) {
            return Some(value.to_string());
        }
    }

    None
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{:02X}", byte),
        })
        .collect()
}

#[cfg(test)]
fn __unit_test_app_state() -> AppState {
    AppState {
        client: reqwest::Client::new(),
        client_id: "test".into(),
        client_secret: "test".into(),
        redirect_uri: "http://127.0.0.1:8080/auth/github/callback".into(),
        preview_redirect_uri: Some("https://preview.example/auth/github/preview/callback".into()),
        oauth_states: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        wallets: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        rialo: std::sync::Arc::new(RialoConfig::from_env()),
    }
}

#[cfg(test)]
fn unit_wallet_file_exists_for(user_id: u64) -> bool {
    wallet_file(user_id).exists()
}

#[cfg(test)]
#[path = "server/_transferswitch_tests.rs"]
mod transferswitch_tests;

#[cfg(test)]
mod set_cookie_regression_tests {
    use super::*;
    use axum::body::HttpBody;

    fn set_cookie_of(resp: &Response) -> String {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .find(|v| v.starts_with("agentpay_session="))
            .expect("agentpay_session Set-Cookie must be present")
    }

    fn app_state() -> AppState {
        AppState {
            client: reqwest::Client::new(),
            client_id: "x".into(),
            client_secret: "x".into(),
            redirect_uri: "http://localhost/callback".into(),
            preview_redirect_uri: Some(
                "https://preview.example/auth/github/preview/callback".into(),
            ),
            oauth_states: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            wallets: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            rialo: std::sync::Arc::new(crate::rialo::RialoConfig {
                cli: "/nonexistent".into(),
                rpc_url: "http://127.0.0.1:4104".into(),
                program_id: None,
                program_dir: "artifact".into(),
            }),
        }
    }

    fn validate_shape(cookie: &str, expect_secure: bool, label: &str) {
        // 1. The cookie VALUE must be exactly the synthetic session id.
        let value = cookie
            .strip_prefix("agentpay_session=")
            .and_then(|rest| rest.split(';').next())
            .unwrap();
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "{label}: cookie VALUE must be the session id, got {cookie:?}",
        );
        // 2. Mandatory attributes present exactly once.
        assert!(cookie.contains("HttpOnly"), "{label}: HttpOnly {cookie:?}");
        assert!(
            cookie.contains("SameSite=Lax"),
            "{label}: SameSite=Lax {cookie:?}"
        );
        // 3. Secure present/absent EXACTLY as gated, and never merged with
        //    the session id (no malformed attribute like "; Secure<uuid>").
        let secure_count = cookie.matches("Secure").count();
        if expect_secure {
            assert_eq!(secure_count, 1, "{label}: Secure expected: {cookie:?}");
            assert!(
                cookie.contains("SameSite=Lax; Secure"),
                "{label}: Secure must directly follow SameSite=Lax: {cookie:?}"
            );
        } else {
            assert_eq!(
                secure_count, 0,
                "{label}: Secure must be absent: {cookie:?}"
            );
        }
        // 4. No session-id characters may appear after the Lax/Secure
        //    attribute segment (guards against argument-order regression).
        let after_lax = cookie.split("SameSite=Lax").nth(1).unwrap();
        let attr_only = after_lax
            .trim_start_matches("; Secure")
            .trim_start_matches("; Path=/")
            .trim();
        assert!(
            !attr_only
                .chars()
                .any(|c| c.is_ascii_hexdigit() && !attr_only.contains("Max-Age")),
            "{label}: unexpected id characters after attributes: {cookie:?}"
        );
    }

    #[tokio::test]
    async fn dev_login_set_cookie_value_and_attributes() {
        let _env_guard = crate::dev_login_endpoint_tests::DEV_LOGIN_ENV_LOCK
            .lock()
            .unwrap();
        // SEQUENTIAL phases in ONE test: the Secure attribute is read from
        // process-global env at response-build time — two parallel tests
        // flipping it would race. Phases:
        //   1. Secure disabled: cookie value = session id, no Secure.
        //   2. Secure enabled: identical cookie + "; Secure" attribute.
        // Both prove the value/attribute ordering via the ACTUAL response
        // headers (the G7 argument-order regression guard).
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "42") };
        unsafe { std::env::remove_var("AGENTPAY_COOKIE_SECURE") };

        // ---- Phase 1: Secure disabled ----
        let state = app_state();
        state.sessions.lock().unwrap().clear();
        let resp = dev_login(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let cookie_off = set_cookie_of(&resp);
        validate_shape(&cookie_off, false, "secure-off/dev_login");
        let minted: Vec<String> = state.sessions.lock().unwrap().keys().cloned().collect();
        assert_eq!(minted.len(), 1);
        assert!(
            cookie_off.starts_with(&format!("agentpay_session={}", minted[0])),
            "cookie value must equal the stored session id: {cookie_off:?} vs {}",
            minted[0]
        );

        // ---- Phase 2: Secure enabled ----
        unsafe { std::env::set_var("AGENTPAY_COOKIE_SECURE", "1") };
        let state2 = app_state();
        state2.sessions.lock().unwrap().clear();
        let resp2 = dev_login(State(state2.clone())).await;
        assert_eq!(resp2.status(), StatusCode::TEMPORARY_REDIRECT);
        let cookie_on = set_cookie_of(&resp2);
        validate_shape(&cookie_on, true, "secure-on/dev_login");
        let minted2: Vec<String> = state2.sessions.lock().unwrap().keys().cloned().collect();
        assert_eq!(minted2.len(), 1);
        assert!(cookie_on.starts_with(&format!("agentpay_session={}", minted2[0])));

        unsafe { std::env::remove_var("AGENTPAY_COOKIE_SECURE") };
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
    }
}

#[cfg(test)]
pub(crate) mod dev_login_endpoint_tests {
    use super::*;
    use axum::body::HttpBody;
    pub(crate) static DEV_LOGIN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn app_state() -> AppState {
        AppState {
            client: reqwest::Client::new(),
            client_id: "x".into(),
            client_secret: "x".into(),
            redirect_uri: "http://localhost/callback".into(),
            preview_redirect_uri: Some(
                "https://preview.example/auth/github/preview/callback".into(),
            ),
            oauth_states: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            wallets: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            rialo: std::sync::Arc::new(crate::rialo::RialoConfig {
                cli: "/nonexistent".into(),
                rpc_url: "http://127.0.0.1:4104".into(),
                program_id: None,
                program_dir: "artifact".into(),
            }),
        }
    }

    fn extract_cookie_value(resp: &Response) -> Option<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("agentpay_session="))
            .and_then(|c| {
                c.strip_prefix("agentpay_session=")
                    .and_then(|rest| rest.split(';').next())
                    .map(|s| s.to_string())
            })
    }

    /// 1. UNSET env: per-request handler re-check returns 404 and mints NO
    ///    session — the defense works even if the route were somehow mounted.
    #[tokio::test]
    async fn dev_login_404_when_env_unset() {
        let _env_guard = DEV_LOGIN_ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
        let state = app_state();
        state.sessions.lock().unwrap().clear();
        let resp = dev_login(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            extract_cookie_value(&resp).is_none(),
            "denied dev-login must NOT mint a session cookie"
        );
        assert!(
            state.sessions.lock().unwrap().is_empty(),
            "denied dev-login must NOT register a session"
        );
    }

    /// 2. EMPTY env: same fail-closed treatment as unset.
    #[tokio::test]
    async fn dev_login_404_when_env_empty() {
        let _env_guard = DEV_LOGIN_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "") };
        let state = app_state();
        state.sessions.lock().unwrap().clear();
        let resp = dev_login(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(extract_cookie_value(&resp).is_none());
        assert!(state.sessions.lock().unwrap().is_empty());
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
    }

    /// 3. UNPARSEABLE env (non-numeric): fail-closed 404, no session.
    #[tokio::test]
    async fn dev_login_404_when_env_unparseable() {
        let _env_guard = DEV_LOGIN_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "not-a-number") };
        let state = app_state();
        state.sessions.lock().unwrap().clear();
        let resp = dev_login(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(extract_cookie_value(&resp).is_none());
        assert!(state.sessions.lock().unwrap().is_empty());
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
    }

    /// 4. Number-like env ("007") parses legitimately — proves the check is
    ///    a real numeric gate, not a string-compare quirk.
    #[tokio::test]
    async fn dev_login_mints_session_when_env_numeric() {
        let _env_guard = DEV_LOGIN_ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "42") };
        let state = app_state();
        state.sessions.lock().unwrap().clear();
        let resp = dev_login(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let sid = extract_cookie_value(&resp).expect("cookie minted");
        assert!(
            state.sessions.lock().unwrap().contains_key(&sid),
            "minted sid must be a registered session"
        );
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
    }

    /// 5. ROUTE-LEVEL check: the router only exposes /auth/dev-login when
    ///    startup mounted it. Mirrors the main() mount condition: with
    ///    DEV_LOGIN_USER_ID unset the route is NOT registered — prove via a
    ///    minimal router built by the same match logic the server uses, then
    ///    one request must yield 404 from the FALLBACK (route absent), and
    ///    zero sessions ever created.
    #[tokio::test]
    async fn router_does_not_mount_dev_login_when_env_unset() {
        let _env_guard = DEV_LOGIN_ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
        let state = app_state();
        state.sessions.lock().unwrap().clear();

        // Same mount logic as main() (server.rs:615-629).
        let app = match std::env::var("DEV_LOGIN_USER_ID") {
            Ok(id) if !id.is_empty() => {
                axum::Router::new().route("/auth/dev-login", axum::routing::get(dev_login))
            }
            _ => axum::Router::new(),
        }
        .fallback_service(axum::routing::get(|| async {
            axum::http::StatusCode::NOT_FOUND
        }))
        .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let http = reqwest::Client::new();
        let resp = http
            .get(&format!("http://{addr}/auth/dev-login"))
            .send()
            .await
            .unwrap();
        // Route absent → fallback 404, never an auth bypass or redirect.
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(
            state.sessions.lock().unwrap().is_empty(),
            "no session may be minted when the route is unmounted"
        );
        srv.abort();
    }
}

#[cfg(test)]
mod dev_login_bind_guard_tests {
    use super::*;

    // ONE sequential test: the guard reads process-global env
    // (DEV_LOGIN_USER_ID); parallel tests flipping it would race.
    // Phases: public-bind refusal, loopback allowance, unset/empty inertness.
    #[test]
    fn dev_login_bind_guard_matrix() {
        // Phase 1 — dev-login ENABLED: non-loopback refused, loopback allowed.
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "42") };
        for addr in [
            "0.0.0.0:8080",
            "192.168.1.10:8080",
            "example.com:8080",
            "128.0.0.1:8080", // 128/8 is NOT loopback (IpAddr-parse guard)
            "8080",           // port-only form binds 0.0.0.0
        ] {
            assert!(
                dev_login_bind_guard(addr).is_err(),
                "dev-login on {addr} must be refused"
            );
        }
        for addr in [
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
            "::1", // bare IPv6 loopback (multiple-colon form)
        ] {
            assert!(
                dev_login_bind_guard(addr).is_ok(),
                "loopback dev-login {addr} must be allowed (local testnet posture)"
            );
        }

        // Phase 2 — dev-login UNSET or EMPTY: guard inert even on public binds
        // (the guard's purpose is dev-config conflict; plain prod binds are a
        // deployment choice, not an auth bypass).
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
        for addr in ["0.0.0.0:8080", "127.0.0.1:8080"] {
            assert!(dev_login_bind_guard(addr).is_ok());
        }
        unsafe { std::env::set_var("DEV_LOGIN_USER_ID", "") };
        assert!(dev_login_bind_guard("0.0.0.0:8080").is_ok());
        unsafe { std::env::remove_var("DEV_LOGIN_USER_ID") };
    }
}

mod cookie_secure_tests {
    use super::*;

    #[test]
    fn cookie_secure_attr_is_gated_by_env() {
        // Default (unset): no Secure attribute — plain-HTTP local/testnet
        // development keeps working.
        unsafe { std::env::remove_var("AGENTPAY_COOKIE_SECURE") };
        assert_eq!(cookie_secure_attr(), "");
        // Opt-in: Secure attribute present for HTTPS deployments.
        unsafe { std::env::set_var("AGENTPAY_COOKIE_SECURE", "1") };
        assert_eq!(cookie_secure_attr(), "; Secure");
        unsafe { std::env::set_var("AGENTPAY_COOKIE_SECURE", "true") };
        assert_eq!(cookie_secure_attr(), "; Secure");
        // Any other value: treated as unset (fail-closed to the default).
        unsafe { std::env::set_var("AGENTPAY_COOKIE_SECURE", "0") };
        assert_eq!(cookie_secure_attr(), "");
        unsafe { std::env::remove_var("AGENTPAY_COOKIE_SECURE") };
    }
}

#[cfg(test)]
mod program_helpers_tests {
    use super::*;

    #[test]
    fn kelvin_conversion() {
        assert_eq!(rlo_to_kelvin(1.0).as_deref(), Some("1000000000"));
        assert_eq!(rlo_to_kelvin(0.000000001).as_deref(), Some("1"));
        assert_eq!(rlo_to_kelvin(0.017).as_deref(), Some("17000000"));
        assert_eq!(rlo_to_kelvin(0.0), None);
        assert_eq!(rlo_to_kelvin(-1.0), None);
        assert_eq!(rlo_to_kelvin(f64::NAN), None);
        assert_eq!(rlo_to_kelvin(f64::INFINITY), None);
        // sub-kelvin amounts are rejected, never rounded to zero
        assert_eq!(rlo_to_kelvin(0.0000000001), None);
    }

    #[test]
    fn slug_validation() {
        assert!(valid_workflow_slug(
            "1111111111111111111111111111111111111111111111111111111111111111"
        ));
        assert!(!valid_workflow_slug("short"));
        assert!(!valid_workflow_slug(
            "zz11111111111111111111111111111111111111111111111111111111111111"
        ));
        let generated = random_slug_hex();
        assert_eq!(generated.len(), 64);
        assert!(valid_workflow_slug(&generated));
    }

    #[test]
    fn address_validation() {
        assert!(valid_rialo_address(
            "ERwi2QKP2iDNbjSBUNJHhWhgK5eJyUTGwQL5N5i8EBq8"
        ));
        assert!(!valid_rialo_address("has spaces"));
        assert!(!valid_rialo_address("short"));
    }
}
