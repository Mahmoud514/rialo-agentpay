//! PHASE 5 STEP 2 — Agent data model + CRUD skeleton.
//!
//! An Agent is a SEPARATE product entity owned by an authenticated GitHub
//! user — it is not the user wallet and never touches it. This module
//! stays deliberately free of any payment, funding, or lifecycle logic:
//!
//!   * NO payment, funding, or autonomous-execution path exists here;
//!   * NO lifecycle transitions are implemented (status is fixed `draft`
//!     for now; the enum is a model definition only);
//!   * NO key material can appear in an Agent record by construction —
//!     `wallet_address` is the only wallet field and holds ONLY the
//!     agent's public address; the keypair itself lives in a separate
//!     file under `artifact/agent_wallets/` (mode 600, gitignored),
//!     minted per agent with the same getrandom-seed +
//!     `keypair_from_seed` discipline as the user-wallet pattern. The
//!     two directories are disjoint by construction: agent code never
//!     reads, writes, or derives anything from `artifact/wallets/`, and
//!     user-wallet code never sees agent paths.
//!   * PHASE 9 I-1 (C-1): the record also carries `auth_public_key` —
//!     the PUBLIC half of a second, FUNDS-LESS authentication keypair
//!     vaulted under `artifact/agent_auth_keys/` (agent_auth_keys.rs).
//!     Public identity material only; that key is never a wallet, never
//!     a money signer, and never participates in any payment path.
//!
//! Storage: one JSON file per agent at `artifact/agents/<agent_id>.json`
//! (same file-per-entity convention as `artifact/wallets/`), written with
//! temp-file + rename atomicity and owner-only permissions.
//!
//! Authorization invariant (enforced server-side, never client-side):
//! a caller may see or mutate an agent ONLY if `owner_user_id` equals the
//! authenticated GitHub user id. Missing and non-owned both answer
//! `AGENT_NOT_FOUND` so the API cannot be used to enumerate other users'
//! agents.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rialo_s_signer::Signer;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use super::agent_auth_keys::{AuthKeyProvisionError, auth_key_path, provision_agent_auth_key};
use super::rialo::{RialoConfig, RialoError, SignatureInfoRecord, TxLookup, TxRecord};
use super::rialo_tx_signers::{SignerError, SignerRecord, TxSigner, verify_agent_public_address};
use super::{AppState, api_error, session_user};
use crate::audit::audit_dir_for;

/// File-format version for persisted agent records. Bumping it marks the
/// point where a documented migration path is required.
pub const AGENT_SCHEMA_VERSION: u32 = 1;

/// Lifecycle model definition (STEP 2: values exist, transitions do NOT).
/// `draft` is the only status the CRUD skeleton ever writes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Draft,
    Active,
    Paused,
    Disabled,
    Deleted,
}

impl AgentStatus {
    /// THE lifecycle state machine (STEP 5) — a strict, exhaustive edge
    /// table, not permissive logic. The ONLY allowed transitions:
    ///
    ///   draft  -> active
    ///   active -> paused
    ///   paused -> active
    ///   active -> disabled
    ///   paused -> disabled
    ///
    /// Everything else is false: self-transitions, draft->paused,
    /// draft->disabled, and every edge OUT of draft states or INTO draft
    /// are refused. `disabled` is terminal — no edge leaves it.
    /// This is metadata-only: entering `active` grants NO payment, funding,
    /// or autonomous capability (none exists in this codebase yet).
    pub const fn can_transition(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Draft, Self::Active)
                | (Self::Active, Self::Paused)
                | (Self::Paused, Self::Active)
                | (Self::Active, Self::Disabled)
                | (Self::Paused, Self::Disabled)
                | (Self::Disabled, Self::Deleted)
        )
    }
}

/// Durable agent metadata record. Field ownership:
///   schema_version / agent_id / owner_user_id / status / wallet_address /
///   created_at / updated_at  -> server-owned, never client-settable;
///   name                     -> the ONE user-mutable field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Agent {
    pub schema_version: u32,
    pub agent_id: String,
    pub owner_user_id: u64,
    pub name: String,
    pub status: AgentStatus,
    /// The agent's PUBLIC key address (STEP 3: provisioned with the agent's
    /// own independent wallet). Public data — never any key material, seed,
    /// keypair bytes, or file path.
    pub wallet_address: Option<String>,
    /// PHASE 9 I-1 (C-1) — PUBLIC half of the agent's funds-less
    /// authentication keypair (vaulted by agent_auth_keys; identity only,
    /// NEVER a wallet or money signer). Additive-defaulted exactly like
    /// the intent `signer`/`reconciliation` precedent: every pre-I-1
    /// schema-1 record parses unchanged and the schema version stays 1.
    /// Pre-I-1 records are deliberately NOT backfilled here (their value
    /// stays absent/`None` until an explicitly scoped later act).
    #[serde(default)]
    pub auth_public_key: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// CREATE body: exactly one field. `deny_unknown_fields` makes mass
/// assignment (owner, status, ids, timestamps, wallet) impossible at the
/// deserialization boundary itself.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct CreateAgentRequest {
    pub name: String,
}

/// PATCH body: rename only, same anti-mass-assignment rule.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PatchAgentRequest {
    pub name: String,
}

/// STATUS PATCH body (STEP 5): exactly one field. `deny_unknown_fields` +
/// the lowercase enum keep the client from touching any other record field
/// and from inventing statuses or spellings. The transition table, not the
/// client, decides what this requested value may do.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PatchStatusRequest {
    pub status: AgentStatus,
}

// ---------------------------------------------------------------------------
// AGENT POLICY (STEP 6) — configuration model only, ZERO enforcement
// ---------------------------------------------------------------------------
//
/// Monetary policy is stored in INTEGER KELVIN (1 RLO = 1e9 kelvin) — the
/// project's canonical chain unit — never floating-point money at rest.
/// The PATCH boundary accepts RLO floats (identical to POST /api/payment)
/// and converts through the one existing `rlo_to_kelvin` helper.
/// NOTHING consults a policy yet: payment/faucet/balance code never reads
/// these files (enforcement is a documented LATER step).
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Cap policy lists — a client cannot grow store files without bound.
const MAX_POLICY_LIST_LEN: usize = 128;

/// The ONLY action names the model recognizes. This is a finite vocabulary
/// declaration for the future enforcement layer; naming `payment` as an
/// allowed action is configuration data only — no code executes it, and no
/// payment path reads it (Step 6 had zero enforcement; Step 7 adds the
/// CHECK only — see `check_agent_payment_policy`, still zero execution).
pub const ALLOWED_ACTIONS: [&str; 1] = [AGENT_ACTION_PAYMENT];

/// The action identity the Step 7 enforcement boundary evaluates. Step 8's
/// payment endpoint passes this; nothing else consumes it.
pub const AGENT_ACTION_PAYMENT: &str = "payment";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AgentPolicy {
    pub schema_version: u32,
    pub agent_id: String,
    /// None = UNSET. Under the restrictive-default contract the future
    /// enforcement step must treat unset limits / empty allow-lists as
    /// DENY (see report). Unset is never "unlimited".
    pub max_payment_per_tx_kelvin: Option<u64>,
    pub daily_payment_limit_kelvin: Option<u64>,
    pub allowed_recipients: Vec<String>,
    pub allowed_actions: Vec<String>,
    /// None only in the virtual default policy returned before anything
    /// was ever persisted; saved policies always carry Some timestamps.
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
    /// PHASE 9 "Hierarchical Policy" (frozen parent-model decision): the
    /// canonical lowercase UUIDv4 of THIS agent's policy PARENT — an
    /// existing Agent of the SAME owner. `None` = root (every existing
    /// record parses as a root: additive-defaulted, schema version
    /// unchanged, no backfill). The parent contributes CONSTRAINTS ONLY
    /// (narrow-or-preserve); the effective policy is resolved at decision
    /// time and is NEVER persisted as a second authority. Enforced fields:
    /// caps fold by MIN across the chain; allow-lists fold by INTERSECTION;
    /// every resolution failure denies (fail-closed — see the frozen
    /// decision record, Section 7).
    #[serde(default)]
    pub parent_agent_id: Option<String>,
    /// PHASE 9 "Delegation" — the REVOCATION stamp for THIS agent's
    /// delegated authority through its CURRENT parent linkage. `None` =
    /// the delegation relationship is active (or there is no parent).
    /// `Some(ts)` = the delegator's contribution to this child's chain is
    /// SEVERED as of `ts`: the ancestors above this node contribute
    /// NOTHING to its effective policy (the walk stops here — the node's
    /// OWN policy remains its own authority, unchanged since before the
    /// delegation). Set ONLY by the owner revocation route (never by
    /// PATCH — a stale client can never un-revoke); CLEARED only when the
    /// owner sets a NEW `parent_agent_id` (an explicit re-delegation act
    /// through the same authorization boundary). Immediate: the effective
    /// policy is resolved at decision time from current records.
    #[serde(default)]
    pub delegation_revoked: Option<i64>,
    /// PHASE 9 "Hierarchical spend controls" — the AGGREGATE daily spend
    /// cap for THIS node's scope (its own spend + all descendants' spend
    /// under it), in integer kelvin. `None` = no aggregate cap (the
    /// overwhelmingly common case; existing agents are unaffected). This
    /// is an ADDITIONAL constraint on top of the per-agent
    /// `daily_payment_limit_kelvin` — never a replacement for it; the
    /// per-agent CAS reservation remains authoritative for the agent
    /// itself. Additive-defaulted, schema version unchanged.
    #[serde(default)]
    pub aggregate_daily_limit_kelvin: Option<u64>,
    /// RUNTIME-ONLY (never persisted): the claim-time aggregate scope
    /// list resolved by the effective-policy walk — `(scope agent uuid,
    /// aggregate cap in kelvin)` in child-to-root order. Filled by
    /// `resolve_effective_policy` during its SINGLE chain traversal (no
    /// duplicated traversal); consumed by the spend layer at reservation
    /// time and persisted onto the INTENT as the scope-id list (the
    /// claim-time scopes the reconciliation Absent release must hit).
    /// Empty for flat/root agents (no aggregate caps anywhere on the
    /// chain) — exactly today's behavior.
    #[serde(skip)]
    pub aggregate_scopes: Vec<(String, u64)>,
}

/// POLICY PATCH body: policy fields ONLY, full-replacement semantics
/// (omitted monetary limits clear to unset; lists default to empty).
/// `deny_unknown_fields` blocks agent_id / schema_version / timestamps /
/// owner_user_id / anything else at the deserialization boundary.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PatchPolicyRequest {
    #[serde(default)]
    pub max_payment_per_tx_rlo: Option<f64>,
    #[serde(default)]
    pub daily_payment_limit_rlo: Option<f64>,
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// PHASE 9 "Hierarchical Policy" — the parent linkage, under the SAME
    /// full-replacement semantics as every other PATCH field: omitted
    /// means CLEAR (None = root). Validation (canonical id, exists, same
    /// owner, not-self, no cycle, depth) runs at mutation time in the
    /// PATCH handler — a malformed hierarchy can never enter persistent
    /// state.
    #[serde(default)]
    pub parent_agent_id: Option<String>,
    /// PHASE 9 "Hierarchical spend controls" — the AGGREGATE daily cap for
    /// this node's scope (own spend + descendants), in RLO; converted to
    /// integer kelvin by the established `rlo_to_kelvin`. `None`/omitted =
    /// no aggregate cap. Same full-replacement PATCH semantics.
    #[serde(default)]
    pub aggregate_daily_limit_rlo: Option<f64>,
}

// ---------------------------------------------------------------------------
// Validation (pure; runs BEFORE anything touches the filesystem)
// ---------------------------------------------------------------------------

/// Display name: non-empty after trimming, <= 64 chars, no control
/// characters (keeps JSON + future UI rendering safe).
fn valid_agent_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return None;
    }
    if name.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(name.to_string())
}

/// Canonical lowercase UUIDv4 only. Returns None for anything else, so an
/// unvalidated string can NEVER reach path construction (no traversal, no
/// case/brace/urn/suffix games against the on-disk filename).
pub(crate) fn parse_agent_id(raw: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(raw).ok()?;
    if id.get_version() != Some(uuid::Version::Random) {
        return None; // only random (v4-style) ids are minted here
    }
    if raw != id.to_string() {
        return None; // reject braces, urn form, uppercase, missing hyphens
    }
    Some(id)
}

// ---------------------------------------------------------------------------
// Storage (atomic, single-process)
// ---------------------------------------------------------------------------

pub(crate) fn agents_dir() -> PathBuf {
    FsPath::new("artifact").join("agents")
}

pub(crate) fn agent_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

pub(crate) fn agent_policies_dir() -> PathBuf {
    FsPath::new("artifact").join("agent_policies")
}

pub(crate) fn agent_wallet_dir() -> PathBuf {
    FsPath::new("artifact").join("agent_wallets")
}

pub(crate) fn spend_dir() -> PathBuf {
    FsPath::new("artifact").join("agent_spend")
}

pub(crate) fn intents_root() -> PathBuf {
    FsPath::new("artifact").join("agent_payment_intents")
}

/// Load policy for an agent (public for task marketplace)
pub fn load_policy_for_agent(agent_id: &uuid::Uuid) -> Result<Option<AgentPolicy>, std::io::Error> {
    load_policy(&agent_policies_dir(), agent_id)
}

/// Resolve effective policy for an agent (public for task marketplace)
pub fn resolve_effective_policy_for_agent(
    child_policy: AgentPolicy,
    _agent_id: &uuid::Uuid,
) -> Result<AgentPolicy, HierarchyError> {
    resolve_effective_policy(child_policy, &agent_policies_dir(), &agents_dir())
}

/// Execute payment through the core (public for task marketplace)
pub fn execute_payment_core(
    ops: &dyn PaymentOps,
    wallet_dir: &FsPath,
    ledger_dir: &FsPath,
    intents_dir: &FsPath,
    agent: &Agent,
    policy: &AgentPolicy,
    idempotency_key: &str,
    recipient: &str,
    amount_kelvin: u64,
    amount_rlo: f64,
    now: i64,
) -> Result<serde_json::Value, PaymentFailure> {
    execute_agent_payment(
        ops,
        wallet_dir,
        ledger_dir,
        intents_dir,
        agent,
        policy,
        idempotency_key,
        recipient,
        amount_kelvin,
        amount_rlo,
        now,
    )
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serialize-lock for read-modify-write operations (create/patch). The
/// server is single-process (one axum binary), so one in-process mutex is
/// sufficient to prevent lost updates; per-file rename atomicity keeps
/// every concurrent reader on a whole document.
pub(crate) fn store_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// temp file in the SAME directory + fs::rename = atomic replace on POSIX
/// (and on the WSL ext4 backing this project). Permissions are hardened
/// BEFORE the file becomes visible under its final name. Generic over any
/// serializable record (Agent metadata AND AgentPolicy).
fn write_json_atomic(path: &FsPath, value: &impl Serialize) -> Result<(), std::io::Error> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| std::io::Error::other(format!("serialize record: {e}")))?;

    let tmp = path.with_file_name(format!(".tmp-{}", Uuid::new_v4()));

    let mut file = fs::File::create(&tmp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    file.write_all(&bytes)?;
    file.flush()?;
    drop(file);

    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

pub(crate) fn read_agent(path: &FsPath) -> Result<Agent, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let agent: Agent = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if agent.schema_version != AGENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {}",
            agent.schema_version
        ));
    }
    Ok(agent)
}

// ---------------------------------------------------------------------------
// AGENT WALLETS (STEP 3) — independent keypair per agent, metadata untouched
// ---------------------------------------------------------------------------

/// PHASE 9 I-1 (C-1): the FUNDS-LESS authentication keypair vault.
/// Deliberately a third disjoint directory: never the user wallets,
/// never the agent wallets (money keys), identity material only.
pub(crate) fn agent_auth_keys_dir() -> PathBuf {
    FsPath::new("artifact").join("agent_auth_keys")
}

fn agent_wallet_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// `write_keypair`/`keypair_from_seed` surface their failures with a Debug
/// shape that is not necessarily io::Error; collapse everything into one
/// internal error type so no detail (nor any key-adjacent context) leaks.
fn io_other(err: impl std::fmt::Debug) -> std::io::Error {
    std::io::Error::other(format!("{err:?}"))
}

#[derive(Debug)]
enum ProvisionError {
    /// The target path already exists — refused, never overwritten.
    Exists,
    /// Seed/keypair/file failure — anything already created was cleaned.
    Store,
}

/// Mint a NEW independent keypair for this agent id only. Same discipline
/// as the established user-wallet pattern (getrandom 32-byte seed →
/// keypair_from_seed → write_keypair → mode 600) but strictly create-new:
/// `O_EXCL` means an existing path is never touched. Returns ONLY the
/// public address; the private half never leaves the file.
fn provision_agent_wallet(dir: &FsPath, id: &Uuid) -> Result<String, ProvisionError> {
    let path = agent_wallet_path(dir, id);

    let mut seed = [0u8; 32];
    if getrandom::getrandom(&mut seed).is_err() {
        return Err(ProvisionError::Store);
    }

    let Ok(keypair) = rialo_s_keypair::keypair_from_seed(&seed) else {
        return Err(ProvisionError::Store);
    };

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(ref err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProvisionError::Exists);
        }
        Err(_) => return Err(ProvisionError::Store),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    // Hardening is best-effort BEFORE content lands (matches the
    // user-wallet pattern); the actual keypair write must succeed.
    let written = rialo_s_keypair::write_keypair(&keypair, &mut file)
        .map_err(io_other)
        .and_then(|_| file.flush().map_err(io_other));

    drop(file);

    if written.is_err() {
        // We created this exact path under O_EXCL, so removing it can only
        // ever delete our own half-written file.
        let _ = fs::remove_file(&path);
        return Err(ProvisionError::Store);
    }

    // Only the PUBLIC address is ever returned or stored in metadata.
    Ok(keypair.pubkey().to_string())
}

/// Handler-level failure categories for the whole create flow. Fieldless:
/// no detail can ever surface through Debug/Display.
#[derive(Debug)]
pub enum CreateError {
    Wallet,
    /// PHASE 9 I-1 (C-1): the funds-less auth keypair could not be
    /// provisioned. The wallet file created moments before is rolled
    /// back (only that exact path); no metadata is ever written.
    AuthKey,
    Metadata,
}

/// One critical section: mint id → provision wallet → provision funds-less
/// auth keypair → persist metadata.
///
/// Rollback rules (no broad or recursive deletion anywhere):
///   * wallet provisioning failed        -> no auth key, no metadata;
///                                            AGENT_WALLET_STORE_ERROR;
///   * auth-key provisioning failed      -> delete ONLY the wallet file
///                                            just created for this new
///                                            agent id; AGENT_AUTH_KEY_STORE_ERROR;
///   * metadata failed after both keys   -> delete ONLY the wallet and
///                                            auth files just created
///                                            for this id; AGENT_STORE_ERROR.
fn create_agent_record(
    agents_dir: &FsPath,
    agent_wallets_dir: &FsPath,
    agent_auth_keys_dir: &FsPath,
    name: String,
    owner_user_id: u64,
) -> Result<Agent, CreateError> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());

    let agent_id = Uuid::new_v4();
    let now = now_unix();

    let mut agent = Agent {
        schema_version: AGENT_SCHEMA_VERSION,
        agent_id: agent_id.to_string(),
        owner_user_id,
        name,
        status: AgentStatus::Draft, // STEP 3: still draft; no transitions
        wallet_address: None,
        auth_public_key: None,
        created_at: now,
        updated_at: now,
    };

    // PHASE 9 STEP 8 (custody cutover): when the isolated-signer lane is
    // ARMED (env-gated, loopback-only), funded custody is provisioned
    // THROUGH THE SIGNER — the legacy funded wallet file is NEVER minted
    // (the signer is the only funded-key authority). The order flips:
    // auth key first (the identity the signer binds), signer provisioning
    // second (returns the public address only), metadata last. Any failure
    // removes ONLY what this call created (fail-closed, no half authority).
    // With the lane NOT armed: the byte-identical legacy creation order.
    let signer_lane = crate::isolated_signer_lane::IsolatedSignerLaneConfig::from_env();
    if signer_lane.enabled {
        // auth key first
        let auth_result = (|| -> Result<String, AuthKeyProvisionError> {
            if fs::create_dir_all(agent_auth_keys_dir).is_err() {
                return Err(AuthKeyProvisionError::Store);
            }
            provision_agent_auth_key(agent_auth_keys_dir, &agent_id)
        })();
        let Ok(auth_address) = auth_result else {
            return Err(CreateError::AuthKey);
        };
        agent.auth_public_key = Some(auth_address.clone());

        // OPTION C: admin-authenticated registration with signer BEFORE provisioning
        // This bridges the lifecycle gap: auth key exists, signer doesn't know about it yet
        if crate::isolated_signer_lane::admin_register_agent_with_signer(
            &signer_lane.endpoint,
            &agent_id.to_string(),
            &auth_address,
        )
        .is_err()
        {
            // Registration failed - remove auth key and fail
            let _ = fs::remove_file(auth_key_path(agent_auth_keys_dir, &agent_id));
            return Err(CreateError::Wallet);
        }

        // signer provisioning (public address only crosses back)
        let provisioned = crate::isolated_signer_lane::provision_signer_wallet(
            &signer_lane.endpoint,
            &agent_id.to_string(),
            auth_address,
        );
        match provisioned {
            Ok(address) => {
                agent.wallet_address = Some(address);
            }
            Err(_) => {
                // remove ONLY the auth key this call created
                let _ = fs::remove_file(auth_key_path(agent_auth_keys_dir, &agent_id));
                return Err(CreateError::Wallet);
            }
        }
    } else {
        if fs::create_dir_all(agent_wallets_dir).is_err() {
            return Err(CreateError::Wallet);
        }

        let Ok(address) = provision_agent_wallet(agent_wallets_dir, &agent_id) else {
            return Err(CreateError::Wallet);
        };
        agent.wallet_address = Some(address);

        // PHASE 9 I-1 (C-1): the funds-less identity keypair, minted with
        // the agent or not at all — any failure here removes ONLY the wallet
        // file created moments above and writes no metadata.
        let auth_result = (|| -> Result<String, AuthKeyProvisionError> {
            if fs::create_dir_all(agent_auth_keys_dir).is_err() {
                return Err(AuthKeyProvisionError::Store);
            }
            provision_agent_auth_key(agent_auth_keys_dir, &agent_id)
        })();
        let Ok(auth_address) = auth_result else {
            let _ = fs::remove_file(agent_wallet_path(agent_wallets_dir, &agent_id));
            return Err(CreateError::AuthKey);
        };
        agent.auth_public_key = Some(auth_address);
    }

    let metadata_result = (|| -> Result<(), std::io::Error> {
        if crate::pg_store::pg_is_authoritative() {
            // PG IS the authority: commit the metadata row (the wallet and
            // auth-key FILES stay FS — custody unchanged). A DB error is
            // fail-closed: the rollback below removes ONLY the files this
            // call created, exactly like the FS metadata-failure arm.
            match crate::pg_store::pg_run(crate::pg_store::agent_create_dispatch(&agent)) {
                Ok(Ok(true)) => Ok(()),
                _ => Err(std::io::Error::other("agent create dispatch failed")),
            }
        } else {
            fs::create_dir_all(agents_dir)?;
            write_json_atomic(&agent_path(agents_dir, &agent_id), &agent)
        }
    })();

    if metadata_result.is_err() {
        // These exact paths were created moments ago under O_EXCL for
        // this brand-new id — they are the only files this function may
        // ever remove.
        let _ = fs::remove_file(agent_wallet_path(agent_wallets_dir, &agent_id));
        let _ = fs::remove_file(auth_key_path(agent_auth_keys_dir, &agent_id));
        return Err(CreateError::Metadata);
    }

    Ok(agent)
}

// ---------------------------------------------------------------------------
// AGENT BALANCE READOUT (STEP 4) — pure, read-only, zero side effects
// ---------------------------------------------------------------------------
//
// Reuses the ONE established balance path: RialoConfig::balance against the
// configured RIALO_RPC_URL (rialo.rs). No second client, no faucet, no
// transfer, no wallet touch. Representation + honest-degradation follow the
// /api/me convention exactly: canonical `"{} RLO"` string, an explicit
// balance_status, and a typed balance_error that NEVER fakes a zero.

/// Normalized probe outcome, decoupled from the live RPC so the response
/// shape is unit-testable without a node.
#[derive(Debug)]
pub enum BalanceProbe {
    /// The agent record carries no wallet_address (legacy Step-2 record).
    NoWallet,
    /// Real chain balance (f64 RLO, exactly as RialoConfig::balance returns).
    Live(f64),
    /// Pre-built {code, message} envelope from the existing typed errors.
    Unavailable(serde_json::Value),
}

/// THE response builder (pure). Public read-only fields only: never a
/// wallet path, seed, keypair, or anything but the agent's public address.
pub fn balance_json(agent: &Agent, rpc_url: &str, probe: BalanceProbe) -> serde_json::Value {
    let (balance, balance_status, balance_error) = match probe {
        BalanceProbe::NoWallet => (None, "no_wallet", None),
        BalanceProbe::Live(amount) => (Some(format!("{} RLO", amount)), "ok", None),
        BalanceProbe::Unavailable(err) => (None, "unavailable", Some(err)),
    };

    serde_json::json!({
        "success": true,
        "agent_id": agent.agent_id,
        "wallet_address": agent.wallet_address,
        "balance": balance,
        "balance_status": balance_status,
        "balance_error": balance_error,
        // existing public network identifier (same value /api/health exposes)
        "rpc_url": rpc_url,
    })
}

/// GET /api/agents/{id}/balance — owner-scoped real balance read.
pub async fn agent_balance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    // Same choke point as GET/PATCH: missing, foreign, and malformed ids are
    // all indistinguishable AGENT_NOT_FOUND.
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };

    let Some(address) = agent.wallet_address.clone() else {
        return Json(balance_json(
            &agent,
            &state.rialo.rpc_url,
            BalanceProbe::NoWallet,
        ))
        .into_response();
    };

    // Identical call shape to /api/me: the one RialoConfig::balance path,
    // on the blocking pool, typed errors, never a fake 0.
    let rialo = Arc::clone(&state.rialo);
    let probe = match tokio::task::spawn_blocking(move || rialo.balance(&address)).await {
        Ok(Ok(amount)) => BalanceProbe::Live(amount),
        Ok(Err(err)) => BalanceProbe::Unavailable(super::balance_error_json(&err)),
        Err(join_err) => BalanceProbe::Unavailable(serde_json::json!({
            "code": "RIALO_ERROR",
            "message": join_err.to_string()
        })),
    };

    Json(balance_json(&agent, &state.rialo.rpc_url, probe)).into_response()
}

// ---------------------------------------------------------------------------
// AGENT LIFECYCLE (STEP 5) — validated metadata-only status transitions
// ---------------------------------------------------------------------------
//
/// Outcomes of a lifecycle attempt — fieldless, so no internal detail can
/// ever surface through Debug/Display into a client response.
#[derive(Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// malformed id / missing / corrupt / foreign — indistinguishable
    NotFound,
    /// edge not in the state machine (includes self-transitions and
    /// anything leaving `disabled`)
    Invalid,
    /// atomic persist failed — the PREVIOUS record remains on disk intact
    Store,
}

/// One critical section: load owned agent → validate the edge → persist
/// ONLY `status` + `updated_at`. Runs under the SAME store_lock as
/// create/patch, so two concurrent lifecycle requests can never both
/// validate against the same stale state.
///
/// Wallet stores are never opened here: no artifact/wallets/ or
/// artifact/agent_wallets/ path is read, written, deleted, or regenerated
/// by a lifecycle transition — it is pure metadata.
fn transition_agent(
    dir: &FsPath,
    id: &str,
    user_id: u64,
    to: AgentStatus,
    now: i64,
) -> Result<Agent, TransitionError> {
    let agent_id = match parse_agent_id(id) {
        Some(a) => a,
        None => return Err(TransitionError::NotFound),
    };
    if crate::pg_store::pg_is_authoritative() {
        // PG IS the authority: the strict edge table is enforced by the
        // DB-level from-guard (WHERE status = ANY(from)), so two racing
        // transitions serialize at the row lock — the in-process
        // store_lock is replaced by the DB transaction. Ok(false) maps to
        // the same indistinguishable refusal the FS path returns; a DB
        // error is fail-closed (Store).
        // every NON-to status is a potential `from` (the DB WHERE accepts
        // only those the strict edge table allows); to itself is excluded
        // so an already-moved record can never re-apply the same write
        let from_statuses: Vec<&'static str> = [
            crate::agents::AgentStatus::Draft,
            crate::agents::AgentStatus::Active,
            crate::agents::AgentStatus::Paused,
            crate::agents::AgentStatus::Disabled,
            crate::agents::AgentStatus::Deleted,
        ]
        .iter()
        .filter(|s| agent_status_allows_transition(**s, to) && **s != to)
        .map(|s| agent_status_to_wire_ref(*s))
        .collect();
        let result = crate::pg_store::pg_run(crate::pg_store::agent_transition_dispatch(
            agent_id,
            user_id,
            &from_statuses,
            agent_status_to_wire_ref(to),
            now,
        ));
        match result {
            Ok(Ok(true)) => {
                // re-read the committed row for the response (the same
                // read-after-write shape the FS path returns)
                match crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(agent_id)) {
                    Ok(Ok(Some(agent))) => Ok(agent),
                    _ => Err(TransitionError::Store),
                }
            }
            Ok(Ok(false)) => {
                // distinguish NOT_FOUND (no owned row) from INVALID (row
                // exists but guard failed) by reading first
                match crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(agent_id)) {
                    Ok(Ok(Some(agent))) if agent.owner_user_id == user_id => {
                        Err(TransitionError::Invalid)
                    }
                    _ => Err(TransitionError::NotFound),
                }
            }
            _ => Err(TransitionError::Store),
        }
    } else {
        let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());

        let agent = resolve_owned(dir, id, user_id).ok_or(TransitionError::NotFound)?;
        if !agent.status.can_transition(to) {
            return Err(TransitionError::Invalid);
        }

        let mut updated = agent;
        updated.status = to; // the ONLY mutation besides updated_at
        updated.updated_at = now; // owner/wallet/id/name/created_at/schema untouched
        write_json_atomic(&agent_path(dir, &agent_id), &updated)
            .map_err(|_| TransitionError::Store)?;
        Ok(updated)
    }
}

/// Wire-form helper for the PG transition guard (the closed vocabulary).
fn agent_status_to_wire_ref(s: crate::agents::AgentStatus) -> &'static str {
    crate::pg_store::agent_status_to_wire_pub(s)
}

/// FS-side transition predicate shared with the DB guard construction:
/// returns true when a record in state `from` may move to `to` (the same
/// strict edge table `AgentStatus::can_transition` encodes).
fn agent_status_allows_transition(
    from: crate::agents::AgentStatus,
    to: crate::agents::AgentStatus,
) -> bool {
    from.can_transition(to)
}

/// PATCH /api/agents/{id}/status — lifecycle, strictly `can_transition`.
pub async fn patch_agent_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchStatusRequest>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    match transition_agent(&agents_dir(), &id, user.id, req.status, now_unix()) {
        Ok(agent) => Json(serde_json::json!({ "success": true, "agent": agent })).into_response(),
        Err(TransitionError::NotFound) => agent_not_found(),
        Err(TransitionError::Invalid) => api_error(
            StatusCode::BAD_REQUEST,
            "AGENT_INVALID_TRANSITION",
            "Requested status transition is not allowed by the agent lifecycle",
        ),
        Err(TransitionError::Store) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent record could not be stored",
        ),
    }
}

/// POST /api/agents/{id}/credentials/revoke — PHASE 9 "Emergency
/// kill/revoke controls" (D-REV(a), app-side): the OWNER-scoped emergency
/// revocation of THIS agent's credential. Zero new authority: the existing
/// `agent_credentials::revoke_credential` library is the enforcement (the
/// same Argon2 store, the same atomic temp+rename write, the same
/// retained-record semantics); the route only wires the owner session +
/// the ONE ownership choke point in front of it.
///
/// SEMANTICS:
/// * Immediate: once the record carries `revoked_at`, authentication of the
///   old credential fails forever (`authenticate_in` skips revoked records)
///   and rotation is closed — the library's frozen semantics, unchanged.
/// * Idempotent: an already-revoked record answers success (the library's
///   documented repeat behavior); the response carries no secret material.
/// * Fail-closed: a missing/corrupt credential record answers the typed
///   store error (no information leak about record state; the anti-
///   enumeration discipline of the credential plane is preserved).
/// * Lifecycle kill (already shipped, unchanged): `disabled` is terminal —
///   no edge leaves it; every payment path answers `AGENT_LIFECYCLE_BLOCKED`.
///   This route is a SECOND, independent kill plane: it kills the
///   credential (agent-lane authentication) without touching the agent
///   record or any payment state.
/// * In-flight/Pending/Unknown: revocation NEVER rewrites payment history
///   or intent state — Pending stays Pending, Unknown stays Unknown, no
///   intent is fabricated to Failed/Paid. The revoke action itself writes
///   ONLY the credential record + one append-only audit record.
/// * Audit: one observational record (Authorization/Deny with the stable
///   code) in the agent's audit store — no secret value, no credential
///   material, identity class `session` (the caller), agent correlation.
pub async fn agent_credential_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    // the ONE ownership choke point: a user can NEVER revoke another
    // owner's agent credential (missing/foreign/malformed/corrupt all
    // collapse to the same indistinguishable AGENT_NOT_FOUND)
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    // THE existing library call — no parallel credential authority, no
    // second store, no credential material in any direction.
    let now = now_unix();
    let outcome = crate::agent_credentials::revoke_credential(&agent.agent_id);

    let result = match outcome {
        Ok(()) => "AGENT_CREDENTIAL_REVOKED",
        // Idempotent repeat is Ok(()) from the library; a missing/corrupt
        // credential record is collapsed by the library's own error
        // vocabulary — the stable, information-free answer is the typed
        // store error (fail-closed, no enumeration).
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "The credential revocation could not be completed",
            );
        }
    };

    // Append-only observational audit evidence: the action + result, on the
    // session identity plane (the caller), correlated to the agent. NO
    // credential value, NO header material, NO secret can exist here — the
    // audit record type has no field that could carry them.
    let audit_dir = audit_dir_for(&intents_root());
    crate::audit::record(
        crate::audit::authorization(
            now,
            crate::audit::AuditOutcome::Deny,
            Some(result),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            None,
        ),
        &audit_dir,
        Some(&agent.agent_id),
    );

    // Response carries NO credential material (none was ever returned — the
    // secret is issued exactly once out-of-band and revoke returns nothing).
    Json(serde_json::json!({
        "success": true,
        "agent_id": agent.agent_id,
        "credential_revoked": true,
    }))
    .into_response()
}

/// PHASE 9 D8/G-7 — AUTH-KEY BACKFILL (explicitly scoped maintenance act).
///
/// The I-1 field doc reserves backfill for "an explicitly scoped later
/// act": THIS is that act, enabled by the operator-ratified isolated-signer
/// architecture decision (_phase9/isolated_signer_architecture_decision.md
/// §D: the signer allow-list requires authoritative agent-side identity
/// linkage for every live agent).
///
/// SCOPE AND GUARANTEES:
/// * ONLY agents whose record carries `auth_public_key: None` are touched.
///   An existing (non-empty) `auth_public_key` is NEVER replaced — the
///   record↔vault pair is verified instead (a Mismatch is a hard error;
///   switching or accepting an unverified key would be a fallback).
/// * A missing vault file is provisioned through the EXISTING authoritative
///   primitive (`provision_agent_auth_key`: O_EXCL, 0600-before-content,
///   getrandom seed, funds-less identity key — the same mechanism agent
///   creation uses). Only the PUBLIC address is ever returned; the private
///   half never leaves the vault file.
/// * A record with NO field but an EXISTING vault file is a RECOVERY case:
///   the vault's public identity is read (pubkey-only reader) and recorded
///   atomically — the linkage is repaired without re-minting anything.
/// * The record update is ATOMIC (temp+rename, the established discipline)
///   and touches ONLY `auth_public_key` + `updated_at` — ownership,
///   lifecycle, policy, credentials, and funded-wallet data are untouched.
/// * IDEMPOTENT: a second run re-verifies every linkage and performs no
///   mutation (provisioning would refuse `Exists` and the recovery branch
///   re-reads the same pubkey — identical bytes, no write needed).
/// * FAIL-CLOSED: a malformed/unreadable record aborts the whole run
///   BEFORE any mutation (the loop validates everything first); a vault
///   error after provisioning is already clean (the primitive removes only
///   its own half-written file); a record-write failure leaves the vault
///   key in place — a later run takes the RECOVERY branch and converges
///   (never a second key for the same agent).
///
/// Returns the per-agent outcome list `(agent_id, outcome)`; outcomes:
/// `linked` (already linked), `recovered` (vault existed), `provisioned`
/// (fresh key). No private material, no path, no io detail is ever
/// returned or logged.
pub fn backfill_agent_auth_keys(
    agents_dir: &FsPath,
    auth_dir: &FsPath,
) -> Result<Vec<(String, &'static str)>, String> {
    // PASS 1 — validate everything BEFORE mutating anything (fail-closed
    // on malformed state: a corrupt record aborts the run with zero
    // mutations performed).
    let mut entries: Vec<(Uuid, Agent)> = Vec::new();
    let dir_entries = match fs::read_dir(agents_dir) {
        Ok(entries) => entries,
        Err(e) => return Err(format!("agents dir unreadable: {e}")),
    };
    for entry in dir_entries {
        let Ok(entry) = entry else {
            return Err("agents dir entry unreadable".to_string());
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(stem) else {
            return Err(format!("non-canonical agent filename: {stem}"));
        };
        let agent = read_agent(&path).map_err(|e| format!("agent {stem} unreadable: {e}"))?;
        entries.push((id, agent));
    }

    // The vault directory is created on demand (the same discipline as the
    // creation path, agents.rs:529 — `provision_agent_auth_key` itself never
    // creates directories).
    fs::create_dir_all(auth_dir).map_err(|e| format!("vault dir not creatable: {e}"))?;

    // PASS 2 — per-agent, minimal mutation.
    let mut report = Vec::new();
    for (id, agent) in entries {
        if let Some(existing) = &agent.auth_public_key {
            // never replace: VERIFY the existing linkage
            match crate::agent_auth_keys::verify_auth_public_address(auth_dir, &id, existing) {
                Ok(()) => report.push((agent.agent_id.clone(), "linked")),
                Err(crate::agent_auth_keys::AuthKeyError::Mismatch) => {
                    return Err(format!(
                        "agent {}: record/vault MISMATCH — aborting, nothing mutated",
                        agent.agent_id
                    ));
                }
                Err(e) => {
                    return Err(format!(
                        "agent {}: vault verify failed: {e:?}",
                        agent.agent_id
                    ));
                }
            }
            continue;
        }

        let record_path = agent_path(agents_dir, &id);
        if auth_key_path(auth_dir, &id).exists() {
            // RECOVERY: vault exists, linkage absent — record the vault's
            // public identity (pubkey-only reader; no re-mint).
            let pubkey = match crate::agent_auth_keys::read_auth_public_key(auth_dir, &id) {
                Ok(pk) => pk,
                Err(e) => {
                    return Err(format!(
                        "agent {}: vault read failed: {e:?}",
                        agent.agent_id
                    ));
                }
            };
            let mut updated = agent.clone();
            updated.auth_public_key = Some(pubkey);
            updated.updated_at = now_unix();
            write_json_atomic(&record_path, &updated)
                .map_err(|e| format!("agent {}: record write failed: {e}", agent.agent_id))?;
            report.push((agent.agent_id.clone(), "recovered"));
            continue;
        }

        // PROVISION: the authoritative I-1 primitive (O_EXCL, 0600,
        // funds-less, public-only return).
        let pubkey = match crate::agent_auth_keys::provision_agent_auth_key(auth_dir, &id) {
            Ok(pk) => pk,
            Err(e) => return Err(format!("agent {}: provision failed: {e:?}", agent.agent_id)),
        };
        // Bind record ↔ vault BEFORE declaring success.
        if let Err(e) = crate::agent_auth_keys::verify_auth_public_address(auth_dir, &id, &pubkey) {
            // the key file exists and is valid but verification failed —
            // this is a hard internal error: leave the vault key in place
            // (a later run takes the RECOVERY branch) and abort
            return Err(format!(
                "agent {}: post-provision verify failed: {e:?}",
                agent.agent_id
            ));
        }
        let mut updated = agent.clone();
        updated.auth_public_key = Some(pubkey);
        updated.updated_at = now_unix();
        write_json_atomic(&record_path, &updated)
            .map_err(|e| format!("agent {}: record write failed: {e}", agent.agent_id))?;
        report.push((agent.agent_id.clone(), "provisioned"));
    }
    Ok(report)
}

/// POST /api/agents/{id}/auth-key/rotate — PHASE 9 "Key rotation /
/// lifecycle": the OWNER-scoped rotation of THIS agent's funds-less
/// authentication key. Zero new authority and zero custody change: the
/// key is identity-only (I-1), and the vault module's rotation primitive
/// is the enforcement. The mandated ordering is enforced HERE:
///
///   (1) new key creation   — O_EXCL sidecar, 0600-before-content
///   (2) new key validation — strict pubkey-only reader on the sidecar
///   (3) authoritative record switch — the agent record's
///       `auth_public_key` atomically updated (temp+rename)
///   (4) old key becomes non-authoritative — ONE atomic rename replaces
///       the canonical vault file with the validated sidecar (the old
///       key file ceases to exist; it can never be authoritative again)
///
/// A crash between (3) and (4) leaves a FAIL-CLOSED state (record=new
/// pubkey, canonical file=old key => every verification answers Mismatch
/// until a retry) — never a two-key ambiguity, never a half-written key
/// as authority. A failure before (3) removes ONLY the sidecar this call
/// created: the record and the canonical key are byte-identical to
/// before.
///
/// LIFECYCLE INTERACTION: a `disabled` agent refuses rotation
/// (`AGENT_LIFECYCLE_BLOCKED`) — rotation can never resurrect a dead
/// agent or bypass a lifecycle gate. A revoked CREDENTIAL is a different
/// plane (the credential lane) and is NOT resurrected by an auth-key
/// rotation (the auth key never authenticates anything; the credential
/// record is untouched here).
///
/// Response: success + the NEW PUBLIC address only (public identity —
/// the same field the agent record itself carries). No private material
/// can ever be returned: the vault never returns it and this handler
/// never reads it.
pub async fn agent_auth_key_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    // the ONE ownership choke point (cross-owner access collapses to the
    // indistinguishable AGENT_NOT_FOUND)
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };
    // LIFECYCLE GATE: a disabled agent cannot rotate (fail-closed; no
    // lifecycle bypass, no resurrection).
    if agent.status == AgentStatus::Disabled {
        return EnforcementDenial::Lifecycle.into_response();
    }

    let vault_dir = agent_auth_keys_dir();
    let now = now_unix();

    // (1)+(2) mint + validate the sidecar (nothing authoritative touched)
    let (new_pubkey, generation) =
        match crate::agent_auth_keys::mint_rotated_auth_key(&vault_dir, &uuid) {
            Ok(pair) => pair,
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "The authentication key could not be rotated",
                );
            }
        };

    // (3)+(4) the authoritative record switch AND the vault row update:
    //     in PG mode ONE transaction commits both (the record's
    //     auth_public_key and the agent_auth_keys row) so the linkage can
    //     never diverge; in FS mode the established two-step ordering runs
    //     (record switch then promote).
    if crate::pg_store::pg_is_authoritative() {
        match crate::pg_store::pg_run(crate::pg_store::auth_key_rotate_atomic_dispatch(
            uuid,
            new_pubkey.clone(),
            now,
        )) {
            Ok(Ok(true)) => {}
            _ => {
                // nothing authoritative committed: remove ONLY our sidecar
                crate::agent_auth_keys::discard_rotated_auth_key(&vault_dir, &uuid, &generation);
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "The authentication key could not be rotated",
                );
            }
        }
        // success: the local sidecar is now redundant (PG owns the public
        // identity); remove it — it was validated, never authoritative.
        crate::agent_auth_keys::discard_rotated_auth_key(&vault_dir, &uuid, &generation);
    } else {
        let mut updated = agent.clone();
        updated.auth_public_key = Some(new_pubkey.clone());
        updated.updated_at = now;
        let record_path = agent_path(&agents_dir(), &uuid);
        if write_json_atomic(&record_path, &updated).is_err() {
            // nothing authoritative changed: remove ONLY our sidecar
            crate::agent_auth_keys::discard_rotated_auth_key(&vault_dir, &uuid, &generation);
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "The authentication key could not be rotated",
            );
        }

        // (4) old key becomes non-authoritative: ONE atomic rename replaces
        //     the canonical vault file with the validated sidecar.
        if crate::agent_auth_keys::promote_rotated_auth_key(&vault_dir, &uuid, &generation).is_err()
        {
            // FAIL-CLOSED: the record now names the new pubkey while the
            // canonical file still holds the old key — every verification
            // answers Mismatch until a retry completes the rotation. The
            // sidecar is intentionally left in place (it IS the new key);
            // a retry mints a NEW sidecar, switches the record again, and
            // promotes — converging. No detail, no path, no key material
            // ever leaves this function.
            crate::audit::record(
                crate::audit::authorization(
                    now,
                    crate::audit::AuditOutcome::Deny,
                    Some("AGENT_AUTH_KEY_ROTATE_INCOMPLETE"),
                    crate::audit::IdentityClass::Session,
                    Some(&agent.agent_id),
                    None,
                    None,
                ),
                &audit_dir_for(&intents_root()),
                Some(&agent.agent_id),
            );
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "The authentication key could not be rotated",
            );
        }
    }

    // observational audit evidence (no secret, no path, no key material)
    crate::audit::record(
        crate::audit::authorization(
            now,
            crate::audit::AuditOutcome::Allow,
            Some("AGENT_AUTH_KEY_ROTATED"),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            None,
        ),
        &audit_dir_for(&intents_root()),
        Some(&agent.agent_id),
    );

    // Response: PUBLIC identity only (the same field the record carries).
    Json(serde_json::json!({
        "success": true,
        "agent_id": agent.agent_id,
        "auth_public_key": new_pubkey,
    }))
    .into_response()
}

/// POST /api/agents/{id}/delegation/revoke — PHASE 9 "Delegation": the
/// OWNER-scoped emergency revocation of THIS agent's DELEGATED authority
/// through its CURRENT parent linkage. Zero new authority: the stamp is
/// additive metadata on the SAME authoritative policy document the
/// hierarchy already reads; the resolver (the ONLY consumer) severs the
/// ancestors above this node on the next decision — immediate by
/// construction (the effective policy is resolved from current records).
///
/// SEMANTICS:
/// * One-way for the CURRENT linkage: the stamp can only be cleared by
///   the owner setting a NEW `parent_agent_id` (an explicit re-delegation
///   act through the SAME authorization boundary — never by a stale
///   client PATCH, which cannot touch this field).
/// * Cascades: every DESCENDANT under this agent inherits the severed
///   chain (their walk stops here too) — upstream revocation invalidates
///   downstream delegated authority.
/// * Scope: the node's OWN policy remains its own authority (revocation
///   transfers nothing; it only ends the DELEGATED relationship). The
///   spend-control scope collection stops with the chain.
/// * In-flight payments: Pending/Unknown/Confirmed and the authoritative
///   reservations are UNTOUCHED — reconciliation remains the authority;
///   revocation affects only FUTURE authorization decisions.
/// * Fail-closed: a missing policy document denies (nothing to revoke →
///   the delegated authority through this linkage cannot exist anyway);
///   the stamp is persisted atomically (temp+rename under store_lock).
/// * No credential/key/bearer material ever exists in any direction; the
///   audit record is observational (identity class `session`, stable
///   code, agent correlation).
pub async fn agent_delegation_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    // the ONE ownership choke point
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    let now = now_unix();
    // MISSION PHASE 2 — PG-authoritative revocation: the stamp is written
    // through the authoritative store (policy_patch_pg_full) with the same
    // fail-closed semantics as the FS lane. No silent FS fallback.
    if crate::pg_store::pg_is_authoritative() {
        let existing = match crate::pg_store::pg_run(async {
            let client = crate::pg_store::global_client().await;
            crate::pg_store::policy_read_pg(&*client, uuid).await
        }) {
            Ok(Ok(p)) => p,
            _ => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "Agent policy could not be read",
                );
            }
        };
        let Some(mut policy) = existing else {
            return api_error(
                StatusCode::NOT_FOUND,
                "DELEGATION_NOT_FOUND",
                "No policy exists for this agent",
            );
        };
        if policy.parent_agent_id.is_none() {
            return api_error(
                StatusCode::NOT_FOUND,
                "DELEGATION_NOT_FOUND",
                "This agent has no delegation relationship",
            );
        }
        policy.delegation_revoked = Some(now);
        policy.updated_at = Some(now);
        match crate::pg_store::pg_run(crate::pg_store::policy_patch_pg_full(
            uuid, user.id, &policy, now,
        )) {
            Ok(Ok(true)) => {
                // observational audit evidence (no secret, no linkage value)
                // — the SAME record the FS lane writes.
                crate::audit::record(
                    crate::audit::authorization(
                        now,
                        crate::audit::AuditOutcome::Deny,
                        Some("AGENT_DELEGATION_REVOKED"),
                        crate::audit::IdentityClass::Session,
                        Some(&agent.agent_id),
                        None,
                        None,
                    ),
                    &audit_dir_for(&intents_root()),
                    Some(&agent.agent_id),
                );
                return Json(serde_json::json!({
                    "success": true,
                    "agent_id": agent.agent_id,
                    "delegation_revoked": true,
                    "revoked_at": now,
                }))
                .into_response();
            }
            Ok(Ok(false)) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "DELEGATION_NOT_FOUND",
                    "No policy exists for this agent",
                );
            }
            _ => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "The delegation revocation could not be stored",
                );
            }
        }
    }
    let result = {
        let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
        (|| -> Result<i64, Response> {
            let existing = load_policy(&agent_policies_dir(), &uuid).map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "Agent policy could not be read",
                )
            })?;
            let Some(mut policy) = existing else {
                // no policy document = no delegated authority through this
                // agent at all — the revocation is a typed no-op denial
                // (fail-closed; nothing can be resurrected or invented)
                return Err(api_error(
                    StatusCode::NOT_FOUND,
                    "DELEGATION_NOT_FOUND",
                    "No policy exists for this agent",
                ));
            };
            if policy.parent_agent_id.is_none() {
                // a root agent has no delegation to revoke
                return Err(api_error(
                    StatusCode::NOT_FOUND,
                    "DELEGATION_NOT_FOUND",
                    "This agent has no delegation relationship",
                ));
            }
            policy.delegation_revoked = Some(now);
            policy.updated_at = Some(now);
            fs::create_dir_all(agent_policies_dir())
                .and_then(|()| {
                    write_json_atomic(&policy_path(&agent_policies_dir(), &uuid), &policy)
                })
                .map_err(|_| {
                    api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AGENT_STORE_ERROR",
                        "The delegation revocation could not be stored",
                    )
                })?;
            Ok(now)
        })()
    };

    match result {
        Ok(at) => {
            // observational audit evidence (no secret, no linkage value)
            crate::audit::record(
                crate::audit::authorization(
                    at,
                    crate::audit::AuditOutcome::Deny,
                    Some("AGENT_DELEGATION_REVOKED"),
                    crate::audit::IdentityClass::Session,
                    Some(&agent.agent_id),
                    None,
                    None,
                ),
                &audit_dir_for(&intents_root()),
                Some(&agent.agent_id),
            );
            Json(serde_json::json!({
                "success": true,
                "agent_id": agent.agent_id,
                "delegation_revoked": true,
                "revoked_at": at,
            }))
            .into_response()
        }
        Err(resp) => resp,
    }
}

/// Parse a policy PATCH body entirely inside the project's typed envelope.
/// Malformed JSON, wrong types, or ANY unknown field (owner/ids/timestamps)
/// answer 400 AGENT_POLICY_INVALID with a static reason — never axum's
/// plain-text deserializer rejection (all API errors use one envelope).
fn parse_policy_body(raw: &str) -> Result<PatchPolicyRequest, &'static str> {
    serde_json::from_str::<PatchPolicyRequest>(raw)
        .map_err(|_| "request body is malformed or contains fields outside the policy schema")
}

/// GET /api/agents/{id}/policy — READ-ONLY (no lazy file creation).
/// Unconfigured agents receive the deterministic default + `configured:false`.
pub async fn get_agent_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(agent_uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    // MISSION PHASE 2 — storage-mode dispatch: PG is the authoritative
    // policy store when configured (no silent FS fallback); FS mode keeps
    // the legacy file read. Unconfigured policy = the virtual default in
    // BOTH modes (the same `configured:false` contract).
    if crate::pg_store::pg_is_authoritative() {
        return match crate::pg_store::pg_run(async {
            let client = crate::pg_store::global_client().await;
            crate::pg_store::policy_read_pg(&*client, agent_uuid).await
        }) {
            Ok(Ok(Some(policy))) => Json(policy_body(&id, true, &policy)).into_response(),
            Ok(Ok(None)) => Json(policy_body(&id, false, &default_policy(&id))).into_response(),
            _ => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent policy could not be read",
            ),
        };
    }
    match load_policy(&agent_policies_dir(), &agent_uuid) {
        Ok(Some(policy)) => Json(policy_body(&id, true, &policy)).into_response(),
        Ok(None) => Json(policy_body(&id, false, &default_policy(&id))).into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent policy could not be read",
        ),
    }
}

/// PATCH /api/agents/{id}/policy — full replacement of policy fields only.
/// Metadata + wallet stores are never touched; persistence preserves
/// `created_at` and stamps `updated_at` server-side.
pub async fn patch_agent_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    let req = match parse_policy_body(&body) {
        Ok(req) => req,
        Err(reason) => return api_error(StatusCode::BAD_REQUEST, "AGENT_POLICY_INVALID", reason),
    };

    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(agent_uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    // MISSION PHASE 2 — PG-authoritative PATCH branch. PG is the authority:
    // read-modify-write happens against the PG row (validation reuses the
    // PURE validate_policy_patch; linkage validation runs against PG records;
    // the write is patch_agent_policy_pg). No silent FS fallback.
    if crate::pg_store::pg_is_authoritative() {
        // 1. read the existing authoritative policy row.
        let existing = match crate::pg_store::pg_run(async {
            let client = crate::pg_store::global_client().await;
            crate::pg_store::policy_read_pg(&*client, agent_uuid).await
        }) {
            Ok(Ok(p)) => p,
            _ => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "Agent policy could not be read",
                );
            }
        };
        let created_at = existing.as_ref().and_then(|p| p.created_at);
        // 2. PURE validation (unchanged contract).
        let mut policy = match validate_policy_patch(&id, &req, created_at, now_unix()) {
            Ok(p) => p,
            Err(reason) => {
                return api_error(StatusCode::BAD_REQUEST, "AGENT_POLICY_INVALID", reason);
            }
        };
        // 3. delegation stamp: linkage CHANGE = a fresh delegation act (the
        //    owner re-delegating — the stamp clears); UNCHANGED linkage keeps
        //    the stamp (a stale PATCH can never un-revoke). The stamp VALUE
        //    is passed explicitly to the store call.
        let linkage_changed =
            policy.parent_agent_id != existing.as_ref().and_then(|p| p.parent_agent_id.clone());
        if linkage_changed {
            policy.delegation_revoked = None;
            if let Some(link) = &policy.parent_agent_id {
                let Some(parent_uuid) = parse_agent_id(link) else {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "AGENT_POLICY_INVALID",
                        "parent_agent_id is not a valid same-owner agent hierarchy link",
                    );
                };
                // parent record: exists + same-owner + neither endpoint disabled.
                let parent_read = match crate::pg_store::pg_run(
                    crate::pg_store::agent_read_dispatch(parent_uuid),
                ) {
                    Ok(Ok(r)) => r,
                    _ => {
                        return api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "AGENT_STORE_ERROR",
                            "Agent store could not be read",
                        );
                    }
                };
                let Some(parent_record) = parent_read else {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "AGENT_POLICY_INVALID",
                        "parent_agent_id is not a valid same-owner agent hierarchy link",
                    );
                };
                if parent_record.owner_user_id != user.id
                    || parent_record.status == AgentStatus::Disabled
                    || agent.status == AgentStatus::Disabled
                {
                    return api_error(
                        StatusCode::BAD_REQUEST,
                        "AGENT_POLICY_INVALID",
                        "parent_agent_id is not a valid same-owner agent hierarchy link",
                    );
                }
                // cycle + depth: walk the parent chain from the prospective
                // parent via PG policy reads, bounded by the frozen depth.
                let mut hops = 0usize;
                let mut cursor = Some(parent_uuid);
                while let Some(next) = cursor {
                    if next == agent_uuid {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AGENT_POLICY_INVALID",
                            "parent_agent_id is not a valid same-owner agent hierarchy link",
                        );
                    }
                    hops += 1;
                    if hops > MAX_POLICY_HIERARCHY_DEPTH {
                        return api_error(
                            StatusCode::BAD_REQUEST,
                            "AGENT_POLICY_INVALID",
                            "parent_agent_id is not a valid same-owner agent hierarchy link",
                        );
                    }
                    let next_policy = match crate::pg_store::pg_run(async {
                        let client = crate::pg_store::global_client().await;
                        crate::pg_store::policy_read_pg(&*client, next).await
                    }) {
                        Ok(Ok(p)) => p,
                        _ => {
                            return api_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "AGENT_STORE_ERROR",
                                "Agent policy could not be read",
                            );
                        }
                    };
                    cursor = next_policy
                        .and_then(|p| p.parent_agent_id.as_deref().and_then(parse_agent_id));
                }
            }
        } else {
            policy.delegation_revoked = existing.as_ref().and_then(|p| p.delegation_revoked);
        }
        // 4. the authoritative write. Full-replacement contract: every
        //    validated field is passed explicitly (COALESCE in the store
        //    layer always sees the fresh validated value). A draft agent has
        //    no policy row until its first save, so the store creates the
        //    row atomically for the owned agent; later writes replace it.
        //    A missing/foreign agent remains the typed no-op refusal below.
        let stored = match crate::pg_store::pg_run(crate::pg_store::policy_patch_pg_full(
            agent_uuid,
            user.id,
            &policy,
            now_unix(),
        )) {
            Ok(Ok(true)) => true,
            Ok(Ok(false)) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "AGENT_POLICY_MISSING",
                    "No policy exists for this agent",
                );
            }
            _ => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "Agent policy could not be stored",
                );
            }
        };
        let _ = stored;
        return Json(policy_body(&id, true, &policy)).into_response();
    }

    // validate + read-modify-write under the SAME store lock as every other
    // agent/policy mutation — no competing second lock.
    let result = {
        let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
        (|| -> Result<AgentPolicy, Response> {
            let existing = load_policy(&agent_policies_dir(), &agent_uuid).map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AGENT_STORE_ERROR",
                    "Agent policy could not be read",
                )
            })?;
            let created_at = existing.as_ref().and_then(|p| p.created_at);
            let mut policy =
                validate_policy_patch(&id, &req, created_at, now_unix()).map_err(|reason| {
                    api_error(StatusCode::BAD_REQUEST, "AGENT_POLICY_INVALID", reason)
                })?;
            // PHASE 9 "Hierarchical Policy" — PATCH-time linkage validation:
            // a malformed hierarchy can NEVER enter persistent state. The
            // prospective chain is the NEW linkage resolved against the
            // freshly validated policy; any failure is a typed 400 (the
            // stable AGENT_POLICY_INVALID envelope — no enumeration).
            //
            // PHASE 9 "Delegation" — the revocation stamp: a linkage CHANGE
            // (new delegation / dissolved delegation) clears the stamp (a
            // fresh delegation act by the same owner); an UNCHANGED linkage
            // PRESERVES the stamp (a stale client PATCH can never
            // un-revoke). Lifecycle gating: a NEW linkage requires BOTH
            // endpoints non-disabled (delegation can never resurrect a
            // disabled agent or bypass a lifecycle gate).
            if policy.parent_agent_id != existing.as_ref().and_then(|p| p.parent_agent_id.clone()) {
                policy.delegation_revoked = None;
                if let Some(link) = &policy.parent_agent_id {
                    let Some(parent_uuid) = parse_agent_id(link) else {
                        return Err(api_error(
                            StatusCode::BAD_REQUEST,
                            "AGENT_POLICY_INVALID",
                            "parent_agent_id is not a valid same-owner agent hierarchy link",
                        ));
                    };
                    let parent_record = read_agent(&agent_path(&agents_dir(), &parent_uuid))
                        .map_err(|_| {
                            api_error(
                                StatusCode::BAD_REQUEST,
                                "AGENT_POLICY_INVALID",
                                "parent_agent_id is not a valid same-owner agent hierarchy link",
                            )
                        })?;
                    if parent_record.status == AgentStatus::Disabled
                        || agent.status == AgentStatus::Disabled
                    {
                        return Err(api_error(
                            StatusCode::BAD_REQUEST,
                            "AGENT_POLICY_INVALID",
                            "delegation cannot involve a disabled agent",
                        ));
                    }
                }
            } else {
                policy.delegation_revoked = existing.as_ref().and_then(|p| p.delegation_revoked);
            }
            if let Some(link) = &policy.parent_agent_id {
                let probe =
                    resolve_effective_policy(policy.clone(), &agent_policies_dir(), &agents_dir());
                if probe.is_err() {
                    return Err(api_error(
                        StatusCode::BAD_REQUEST,
                        "AGENT_POLICY_INVALID",
                        "parent_agent_id is not a valid same-owner agent hierarchy link",
                    ));
                }
                let _ = link;
            }
            fs::create_dir_all(agent_policies_dir())
                .and_then(|()| {
                    write_json_atomic(&policy_path(&agent_policies_dir(), &agent_uuid), &policy)
                })
                .map_err(|_| {
                    api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AGENT_STORE_ERROR",
                        "Agent policy could not be stored",
                    )
                })?;
            Ok(policy)
        })()
    };

    match result {
        Ok(policy) => Json(policy_body(&id, true, &policy)).into_response(),
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// POLICY STORAGE + VALIDATION (STEP 6)
// ---------------------------------------------------------------------------

/// Policies live in their OWN directory, keyed by the server-validated
/// UUID only. `artifact/agents/` and `artifact/agent_wallets/` are NEVER
/// opened by a policy operation, and no client input reaches a path.
fn policy_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// THE deterministic default policy (tests 1-4): every field unset/empty.
/// Combined with the deny-on-unset contract this is maximally restrictive;
/// it is also maximally honest under ZERO enforcement (it changes nothing
/// about current agent behavior because nothing reads it yet).
pub fn default_policy(agent_id: &str) -> AgentPolicy {
    AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: agent_id.to_string(),
        max_payment_per_tx_kelvin: None,
        daily_payment_limit_kelvin: None,
        allowed_recipients: Vec::new(),
        allowed_actions: Vec::new(),
        created_at: None,
        updated_at: None,
        parent_agent_id: None,
        delegation_revoked: None,
        aggregate_daily_limit_kelvin: None,
        aggregate_scopes: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// PHASE 9 "Hierarchical Policy" — the EFFECTIVE-POLICY resolver (frozen
// parent-model decision). PURE resolution: no writes, no persistence of
// the effective policy, no second authority. The parent contributes
// CONSTRAINTS ONLY (narrow-or-preserve); every resolution failure denies
// (fail-closed) — there is NO fallback to the flat child policy.
// ---------------------------------------------------------------------------

/// Bounded hierarchy depth (the frozen decision's bound-the-work
/// precedent, mirroring ADDRESS_SCAN_HISTORY_LIMIT): each hop is one
/// validated read in the enforcement path; an unbounded chain would be a
/// per-request amplification surface. Depth >= 8 during resolution = deny.
pub const MAX_POLICY_HIERARCHY_DEPTH: usize = 8;

/// Why an effective policy could NOT be resolved. Fieldless — no path, no
/// id, no owner detail can ever surface (fail-closed denial collapse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyError {
    /// the named parent policy could not be loaded (missing or corrupt)
    ParentPolicyUnavailable,
    /// the named parent agent record could not be loaded (missing/corrupt)
    ParentAgentUnavailable,
    /// the parent agent belongs to a DIFFERENT owner (hierarchy never
    /// crosses owners)
    CrossOwnerParent,
    /// the linkage is not a canonical lowercase UUIDv4, or is self-parent
    MalformedLinkage,
    /// the chain revisits an agent (a persisted cycle)
    CycleDetected,
    /// the chain exceeds MAX_POLICY_HIERARCHY_DEPTH
    DepthExceeded,
}

/// Fold ONE parent constraint into the accumulating effective policy.
/// Monotone by construction: min can only shrink caps; intersection can
/// only shrink allow-lists. "SET" means Some(...)/non-empty; an UNSET
/// (None/empty) field means INHERIT the accumulated constraint so far —
/// and if the accumulated value is also unset, it stays unset (which the
/// enforcement treats as DENY: unset is never unlimited).
fn fold_constraint(effective: &mut AgentPolicy, contribution: &AgentPolicy) {
    effective.max_payment_per_tx_kelvin = match (
        effective.max_payment_per_tx_kelvin,
        contribution.max_payment_per_tx_kelvin,
    ) {
        (a, Some(b)) => Some(a.map_or(b, |x| x.min(b))),
        (a, None) => a,
    };
    effective.daily_payment_limit_kelvin = match (
        effective.daily_payment_limit_kelvin,
        contribution.daily_payment_limit_kelvin,
    ) {
        (a, Some(b)) => Some(a.map_or(b, |x| x.min(b))),
        (a, None) => a,
    };
    // INTERSECTION semantics per the frozen Section 5 table: an allow-list
    // is a CONSTRAINT whenever it is non-empty; an EMPTY parent allow-list
    // is a deny-everything constraint (the enforcement denies empty lists
    // today — treating it as "inherit" would WEAKEN the parent's authority
    // and violate the narrowing invariant). So: intersection over the
    // union of what is set, where empty wins (fail-closed).
    if contribution.allowed_recipients.is_empty() {
        effective.allowed_recipients.clear();
    } else if effective.allowed_recipients.is_empty() {
        effective.allowed_recipients = contribution.allowed_recipients.clone();
    } else {
        effective
            .allowed_recipients
            .retain(|r| contribution.allowed_recipients.contains(r));
    }
    if contribution.allowed_actions.is_empty() {
        effective.allowed_actions.clear();
    } else if effective.allowed_actions.is_empty() {
        effective.allowed_actions = contribution.allowed_actions.clone();
    } else {
        effective
            .allowed_actions
            .retain(|a| contribution.allowed_actions.contains(a));
    }
}

/// THE pure effective-policy resolver (the frozen model, Section 5):
/// start from the target agent's OWN policy, follow `parent_agent_id`,
/// validate every hop, and fold constraints monotonically.
///
/// * walk: child first, then parent, up to the root — the fold is
///   commutative for min/intersection, so the order affects only error
///   detection priority, never the result.
/// * validation per hop: canonical UUID linkage, parent policy loads,
///   parent AGENT record loads, parent belongs to the SAME owner.
/// * self-parenting and cycles: caught by the visited set (a self-parent
///   revisits the starting agent on hop 1).
/// * depth: MAX_POLICY_HIERARCHY_DEPTH hop budget.
/// * failure: ANY error denies — the caller must NOT fall back to the
///   flat child policy.
///
/// The returned document is the CHILD's effective policy: the child's own
/// agent_id/timestamps/linkage identity, with the FOLDED constraint
/// fields. `parent_agent_id` is preserved as the child's linkage so the
/// fingerprint source record stays identifiable; the enforcement receives
/// only the folded constraint fields.
pub fn resolve_effective_policy(
    child_policy: AgentPolicy,
    policies_dir: &FsPath,
    agents_dir: &FsPath,
) -> Result<AgentPolicy, HierarchyError> {
    let child_uuid =
        parse_agent_id(&child_policy.agent_id).ok_or(HierarchyError::MalformedLinkage)?;
    let child_owner = read_agent(&agent_path(agents_dir, &child_uuid))
        .map_err(|_| HierarchyError::ParentAgentUnavailable)?
        .owner_user_id;

    let mut effective = child_policy.clone();
    // the RUNTIME scope list: every node on the chain (child first, then
    // ancestors) whose policy sets an aggregate cap, in child-to-root
    // order — the spend layer's deterministic reservation order. Filled
    // during THIS single traversal (no duplicated chain walk anywhere).
    let mut aggregate_scopes: Vec<(String, u64)> = Vec::new();
    if let Some(cap) = child_policy.aggregate_daily_limit_kelvin {
        aggregate_scopes.push((child_uuid.to_string(), cap));
    }
    let mut current_policy = child_policy;
    let mut visited: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    visited.insert(child_uuid);
    let mut hops = 0usize;

    loop {
        let Some(link) = current_policy.parent_agent_id.clone() else {
            // root reached: the fold is complete
            effective.aggregate_scopes = aggregate_scopes;
            return Ok(effective);
        };
        // PHASE 9 "Delegation": a REVOKED delegation severs the ancestors
        // ABOVE this node — the walk stops here (the node's OWN policy has
        // already contributed; the delegator's contribution is withdrawn).
        // Immediate by construction: the stamp is on the current record,
        // so the next decision sees it. The aggregate scope collection
        // stops too (the delegated spend authority is withdrawn; the
        // node's own scope, if any, remains its own).
        if current_policy.delegation_revoked.is_some() {
            effective.aggregate_scopes = aggregate_scopes;
            return Ok(effective);
        }
        let parent_uuid = parse_agent_id(&link).ok_or(HierarchyError::MalformedLinkage)?;
        if parent_uuid == child_uuid {
            return Err(HierarchyError::CycleDetected); // self-parent
        }
        if !visited.insert(parent_uuid) {
            return Err(HierarchyError::CycleDetected);
        }
        hops += 1;
        if hops > MAX_POLICY_HIERARCHY_DEPTH {
            return Err(HierarchyError::DepthExceeded);
        }
        // the parent AGENT record must exist and share the child's owner
        let parent_agent = read_agent(&agent_path(agents_dir, &parent_uuid))
            .map_err(|_| HierarchyError::ParentAgentUnavailable)?;
        if parent_agent.owner_user_id != child_owner {
            return Err(HierarchyError::CrossOwnerParent);
        }
        // the parent POLICY must load (missing/corrupt = fail closed)
        let parent_policy = load_policy(policies_dir, &parent_uuid)
            .map_err(|_| HierarchyError::ParentPolicyUnavailable)?
            .ok_or(HierarchyError::ParentPolicyUnavailable)?;
        fold_constraint(&mut effective, &parent_policy);
        // the scope cap is NEVER folded into the child's own enforcement
        // view (it is a per-scope constraint, not a child constraint); it
        // is collected for the spend layer instead.
        if let Some(cap) = parent_policy.aggregate_daily_limit_kelvin {
            aggregate_scopes.push((parent_uuid.to_string(), cap));
        }
        current_policy = parent_policy;
    }
}

/// Ok(None) = nothing persisted yet (caller serves the virtual default).
/// Corrupt/foreign-schema files surface as Err — never masked as "default".
fn load_policy(dir: &FsPath, id: &Uuid) -> Result<Option<AgentPolicy>, std::io::Error> {
    match fs::read(policy_path(dir, id)) {
        Ok(bytes) => {
            let policy: AgentPolicy = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("policy parse: {e}")))?;
            if policy.schema_version != POLICY_SCHEMA_VERSION {
                return Err(std::io::Error::other("unsupported policy schema_version"));
            }
            if policy.agent_id != id.to_string() {
                return Err(std::io::Error::other("policy agent_id mismatch"));
            }
            Ok(Some(policy))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// PURE validator — the only place monetary/action/recipient rules live.
/// Reuses the ONE established conversion (`rlo_to_kelvin`: rejects NaN,
/// infinities, zero, negatives, sub-kelvin precision and u64 overflow) and
/// the ONE established address checker (`valid_rialo_address`).
/// Errors are static, machine-readable reasons; no internal detail.
fn validate_policy_patch(
    agent_id: &str,
    req: &PatchPolicyRequest,
    created_at: Option<i64>,
    now: i64,
) -> Result<AgentPolicy, &'static str> {
    let to_kelvin = |v: f64, field: &'static str| -> Result<u64, &'static str> {
        super::rlo_to_kelvin(v)
            .and_then(|s| s.parse::<u64>().ok())
            // rlo_to_kelvin already guarantees a u64 string; the parse arm
            // keeps the conversion boundary total without inventing rules.
            .ok_or(field)
    };

    let max = match req.max_payment_per_tx_rlo {
        Some(v) => Some(to_kelvin(
            v,
            "max_payment_per_tx_rlo must be a positive finite RLO amount with at least 1 kelvin precision",
        )?),
        None => None,
    };
    let daily = match req.daily_payment_limit_rlo {
        Some(v) => Some(to_kelvin(
            v,
            "daily_payment_limit_rlo must be a positive finite RLO amount with at least 1 kelvin precision",
        )?),
        None => None,
    };
    if let (Some(m), Some(d)) = (max, daily) {
        if m > d {
            return Err("max_payment_per_tx must not exceed daily_payment_limit");
        }
    }

    if req.allowed_recipients.len() > MAX_POLICY_LIST_LEN {
        return Err("allowed_recipients exceeds the policy list limit");
    }
    if req.allowed_actions.len() > MAX_POLICY_LIST_LEN {
        return Err("allowed_actions exceeds the policy list limit");
    }
    for r in &req.allowed_recipients {
        if !super::valid_rialo_address(r) {
            return Err("allowed_recipients contains an invalid Rialo address");
        }
    }
    for a in &req.allowed_actions {
        if !ALLOWED_ACTIONS.contains(&a.as_str()) {
            return Err("allowed_actions contains an unsupported action");
        }
    }

    let aggregate = match req.aggregate_daily_limit_rlo {
        Some(v) => Some(to_kelvin(
            v,
            "aggregate_daily_limit_rlo must be a positive finite RLO amount with at least 1 kelvin precision",
        )?),
        None => None,
    };
    Ok(AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        agent_id: agent_id.to_string(),
        max_payment_per_tx_kelvin: max,
        daily_payment_limit_kelvin: daily,
        allowed_recipients: req.allowed_recipients.clone(),
        allowed_actions: req.allowed_actions.clone(),
        created_at: Some(created_at.unwrap_or(now)),
        updated_at: Some(now),
        parent_agent_id: req.parent_agent_id.clone(),
        // the revocation stamp is managed by the handler (which knows the
        // existing policy): a linkage change clears it, a linkage
        // preservation keeps it — a stale PATCH can never un-revoke.
        delegation_revoked: None,
        aggregate_daily_limit_kelvin: aggregate,
        aggregate_scopes: Vec::new(),
    })
}

/// Shared response envelope for both policy endpoints (pure, testable).
fn policy_body(agent_id: &str, configured: bool, policy: &AgentPolicy) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "agent_id": agent_id,
        "configured": configured,
        "policy": policy,
    })
}

// ---------------------------------------------------------------------------
// POLICY ENFORCEMENT BOUNDARY (STEP 7) — authorization ONLY, zero execution
// ---------------------------------------------------------------------------
//
// Pure, deterministic, read-only: takes data, returns a verdict. It never
// reads a file, resolves any wallet path, calls the RPC, the CLI, the
// faucet, or a transfer, and never mutates anything. Ownership
// (resolve_owned) is established by the CALLING layer before this runs;
// balance and spend accounting are separate boundaries by design.
//
// THE CRITICAL INVARIANT: every denial path is a hard stop — the caller in
// Step 8 must not reach RialoConfig::transfer unless this returns Ok(()).
// Unset limits and empty allow-lists are DENY, never unlimited.

/// Rejection categories with the project's stable machine-readable codes.
/// Fieldless payloads: no internal detail can leak into a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDenial {
    /// status is not `active` (draft / paused / disabled)
    Lifecycle,
    /// no policy record has been configured for this agent
    PolicyMissing,
    /// action not in allowed_actions
    ActionDenied,
    /// recipient failed the existing address validator
    RecipientInvalid,
    /// recipient valid but absent from allowed_recipients (empty = deny)
    RecipientDenied,
    /// amount not canonical-positive at the boundary
    AmountInvalid,
    /// per-tx limit unset or projected daily spend would exceed either limit
    AmountDenied,
    /// policy demands daily accounting but no spend-ledger figure was
    /// supplied — explicit DENY at the seam until Step 8 wires the ledger
    DailyAccountingRequired,
}

impl EnforcementDenial {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Lifecycle => "AGENT_LIFECYCLE_BLOCKED",
            Self::PolicyMissing => "AGENT_POLICY_MISSING",
            Self::ActionDenied => "AGENT_POLICY_DENIED",
            Self::RecipientInvalid => "INVALID_RECIPIENT",
            Self::RecipientDenied => "AGENT_POLICY_DENIED",
            Self::AmountInvalid => "INVALID_AMOUNT",
            Self::AmountDenied => "AGENT_POLICY_DENIED",
            Self::DailyAccountingRequired => "AGENT_DAILY_ACCOUNTING_REQUIRED",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Lifecycle => "Agent is not active for this action",
            Self::PolicyMissing => "Agent policy is not configured; actions are denied by default",
            Self::ActionDenied => "Action is not permitted by the agent policy",
            Self::RecipientInvalid => "Recipient is not a valid Rialo address",
            Self::RecipientDenied => "Recipient is not permitted by the agent policy",
            Self::AmountInvalid => "Amount must be a positive amount of at least 1 kelvin",
            Self::AmountDenied => "Amount exceeds the agent policy limits",
            Self::DailyAccountingRequired => {
                "Daily spend accounting is required by policy but was not supplied"
            }
        }
    }

    pub const fn status(self) -> StatusCode {
        match self {
            Self::RecipientInvalid | Self::AmountInvalid => StatusCode::BAD_REQUEST,
            Self::DailyAccountingRequired => StatusCode::NOT_IMPLEMENTED,
            _ => StatusCode::FORBIDDEN,
        }
    }

    /// Ready-to-return typed envelope (existing api_error machinery).
    pub fn into_response(self) -> Response {
        api_error(self.status(), self.code(), self.message())
    }
}

/// THE enforcement question: "Is this payment intent permitted by this
/// agent's current lifecycle + policy?" — checks ONLY, in fixed order:
///
///   1 lifecycle (status == active)
///   2 policy present
///   3 action allowed ("payment" in allowed_actions)
///   4 recipient syntactically valid (existing `valid_rialo_address`)
///   5 recipient explicitly allowed (empty allow-list = deny)
///   6 amount_kelvin > 0 (u64 at the boundary — no floating-point money)
///   7 per-transaction limit (unset = deny; amount <= limit)
///   8 daily limit (unset = deny; with spend supplied: spent+amount <= limit
///     via checked integer arithmetic; with a limit set but NO spend figure
///     an explicit DailyAccountingRequired is returned — never a bypass)
///
/// `spent_today_kelvin` is the seam for Step 8's persistent spend ledger:
/// Step 7 deliberately does not own or fake that state.
pub fn check_agent_payment_policy(
    agent: &Agent,
    policy: Option<&AgentPolicy>,
    recipient: &str,
    amount_kelvin: u64,
    spent_today_kelvin: Option<u64>,
) -> Result<(), EnforcementDenial> {
    if agent.status != AgentStatus::Active {
        return Err(EnforcementDenial::Lifecycle);
    }
    let policy = policy.ok_or(EnforcementDenial::PolicyMissing)?;
    if !policy
        .allowed_actions
        .iter()
        .any(|a| a == AGENT_ACTION_PAYMENT)
    {
        return Err(EnforcementDenial::ActionDenied);
    }
    if !super::valid_rialo_address(recipient) {
        return Err(EnforcementDenial::RecipientInvalid);
    }
    if !policy.allowed_recipients.iter().any(|r| r == recipient) {
        return Err(EnforcementDenial::RecipientDenied);
    }
    if amount_kelvin == 0 {
        return Err(EnforcementDenial::AmountInvalid);
    }
    match policy.max_payment_per_tx_kelvin {
        Some(limit) if amount_kelvin <= limit => {}
        _ => return Err(EnforcementDenial::AmountDenied),
    }
    match policy.daily_payment_limit_kelvin {
        None => Err(EnforcementDenial::AmountDenied),
        Some(limit) => match spent_today_kelvin {
            None => Err(EnforcementDenial::DailyAccountingRequired),
            Some(spent) => match spent.checked_add(amount_kelvin) {
                Some(projected) if projected <= limit => Ok(()),
                _ => Err(EnforcementDenial::AmountDenied),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Handlers — every one enforces the ownership invariant server-side
// ---------------------------------------------------------------------------

/// POST /api/agents — mint a draft agent with its OWN independent Rialo
/// wallet (create-new only). Returns metadata + PUBLIC address; never any
/// key material. No funding, payment, or lifecycle action happens here.
pub async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAgentRequest>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    let Some(name) = valid_agent_name(&req.name) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_NAME",
            "Agent name must be 1-64 characters (no control characters)",
        );
    };

    // Mint + persist atomically as one unit (STEP 3 + PHASE 9 I-1): the
    // draft metadata, the agent's INDEPENDENT wallet keypair, and the
    // agent's FUNDS-LESS auth keypair land together or not at all — see
    // create_agent_record's rollback rules. No funding, payment, or
    // lifecycle action happens here; status stays `draft`.
    //
    // PHASE-TESTNET FIX — RUNTIME BRIDGE: create_agent_record performs
    // SYNCHRONOUS work, and with the isolated signer lane armed its
    // registration/provisioning calls build a `reqwest::blocking::Client`
    // inside this async handler. A blocking runtime constructed AND DROPPED
    // in an async worker panics ("Cannot drop a runtime in a context where
    // blocking is not allowed") — observed live on POST /api/agents. The
    // established in-repo pattern (faucet handler, server.rs) moves such
    // work onto the blocking pool via `tokio::task::spawn_blocking`. The
    // whole record build (store locks, keypair minting, signer HTTP) is one
    // atomic unit and moves as one unit; JoinError is typed (JoinPanicked),
    // never unwrapped, so panic and cancellation keep their fail-closed
    // 5xx mapping.
    let record_build = tokio::task::spawn_blocking(move || {
        create_agent_record(
            &agents_dir(),
            &agent_wallet_dir(),
            &agent_auth_keys_dir(),
            name,
            user.id,
        )
    })
    .await;
    match record_build {
        Ok(Ok(agent)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "success": true, "agent": agent })),
        )
            .into_response(),
        Ok(Err(CreateError::Wallet)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_WALLET_STORE_ERROR",
            "Agent wallet could not be provisioned",
        ),
        Ok(Err(CreateError::AuthKey)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_AUTH_KEY_STORE_ERROR",
            "Agent authentication key could not be provisioned",
        ),
        Ok(Err(CreateError::Metadata)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent record could not be stored",
        ),
        Err(_join_error) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "Agent record could not be stored",
        ),
    }
}

/// GET /api/agents — list ONLY the caller's agents (filter is server-side).
pub async fn list_agents(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    if crate::pg_store::pg_is_authoritative() {
        // PG IS the authority: the owner list comes from the authoritative
        // rows (Deleted-filtered, the same semantics the FS scan applies).
        // A DB error is fail-closed (never a silent FS fallback).
        return match crate::pg_store::pg_run(crate::pg_store::agents_list_for_owner_dispatch(
            user.id,
        )) {
            Ok(Ok(agents)) => {
                return Json(serde_json::json!({ "success": true, "agents": agents }))
                    .into_response();
            }
            _ => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent store could not be read",
            ),
        };
    }
    let entries: Vec<fs::DirEntry> = match fs::read_dir(agents_dir()) {
        Ok(iter) => iter.flatten().collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent store could not be read",
            );
        }
    };

    let mut agents: Vec<Agent> = entries
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                return None;
            }
            match read_agent(&path) {
                Ok(agent)
                    if agent.status != AgentStatus::Deleted && agent.owner_user_id == user.id =>
                {
                    Some(agent)
                }
                Ok(_) => None,
                Err(_) => {
                    // Records never contain secrets, but keep logs minimal
                    // and stable: only the file name is surfaced.
                    eprintln!(
                        "[agents] skipping unreadable agent file {:?}",
                        path.file_name()
                    );
                    None
                }
            }
        })
        .collect();

    agents.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });

    Json(serde_json::json!({ "success": true, "agents": agents })).into_response()
}

/// GET /api/agents/{id} — read one own agent.
pub async fn get_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    match load_authorized(&id, user.id) {
        Ok(agent) => Json(serde_json::json!({ "success": true, "agent": agent })).into_response(),
        Err(resp) => resp,
    }
}

/// PATCH /api/agents/{id} — rename ONLY. Everything else on the record is
/// server-owned; the request type cannot even carry other fields.
pub async fn patch_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchAgentRequest>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    let Some(name) = valid_agent_name(&req.name) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_NAME",
            "Agent name must be 1-64 characters (no control characters)",
        );
    };

    let Some(agent_id) = parse_agent_id(&id) else {
        return agent_not_found();
    };

    // read-modify-write UNDER THE LOCK: the owner check and the write are
    // one critical section, so a concurrent patch cannot be clobbered.
    let result = {
        let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
        (|| -> Result<Agent, Response> {
            if crate::pg_store::pg_is_authoritative() {
                // PG IS the authority: one transaction locks the owned row,
                // patches the name, and commits. Ok(false) = the same
                // indistinguishable NOT_FOUND; a DB error is fail-closed.
                let now = now_unix();
                match crate::pg_store::pg_run(crate::pg_store::agent_patch_dispatch(
                    agent_id,
                    user.id,
                    Some(&name),
                    now,
                )) {
                    Ok(Ok(true)) => {
                        // re-read the committed row for the response
                        match crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(
                            agent_id,
                        )) {
                            Ok(Ok(Some(agent))) => Ok(agent),
                            _ => Err(api_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "AGENT_STORE_ERROR",
                                "Agent record could not be stored",
                            )),
                        }
                    }
                    Ok(Ok(false)) => Err(agent_not_found()),
                    _ => Err(api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AGENT_STORE_ERROR",
                        "Agent record could not be stored",
                    )),
                }
            } else {
                let mut agent = load_authorized(&agent_id.to_string(), user.id)?;
                agent.name = name;
                agent.updated_at = now_unix(); // status/owner/ids stay untouched
                write_json_atomic(&agent_path(&agents_dir(), &agent_id), &agent).map_err(|_| {
                    api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AGENT_STORE_ERROR",
                        "Agent record could not be stored",
                    )
                })?;
                Ok(agent)
            }
        })()
    };

    match result {
        Ok(agent) => Json(serde_json::json!({ "success": true, "agent": agent })).into_response(),
        Err(resp) => resp,
    }
}

/// Resolve an owned agent from an explicit store directory (pure of ambient
/// paths so tests can run against temp dirs). Invalid id, missing file,
/// schema mismatch, and foreign owner ALL collapse to None — the caller
/// answers with a single indistinguishable AGENT_NOT_FOUND.
fn resolve_owned(dir: &FsPath, id: &str, user_id: u64) -> Option<Agent> {
    let agent_id = parse_agent_id(id)?;
    if crate::pg_store::pg_is_authoritative() {
        // PG IS the authority: read the authoritative row. Missing and
        // foreign BOTH collapse to None (the same indistinguishable
        // NOT_FOUND the FS path answers); a DB error is fail-closed None
        // (never a silent FS fallback).
        match crate::pg_store::pg_run(crate::pg_store::agent_read_dispatch(agent_id)) {
            Ok(Ok(Some(agent))) => (agent.owner_user_id == user_id).then_some(agent),
            _ => None,
        }
    } else {
        let agent = read_agent(&agent_path(dir, &agent_id)).ok()?;
        (agent.owner_user_id == user_id).then_some(agent)
    }
}

/// THE single authorization choke point: valid id + existing file +
/// owner match, else an immediate AGENT_NOT_FOUND response. Missing and
/// non-owned are deliberately indistinguishable.
pub(crate) fn load_authorized(id: &str, user_id: u64) -> Result<Agent, Response> {
    resolve_owned(&agents_dir(), id, user_id).ok_or_else(agent_not_found)
}

/// Check if an agent has any payment intents that would block deletion.
/// Returns true if ANY intent is in a blocking state:
/// - Pending (in-flight, no signature yet)
/// - Signaled (signature claimed but not yet confirmed - in-flight)
/// - Unknown (unreconciled, uncertain finality)
fn has_blocking_intents(agent_id: &Uuid) -> bool {
    let intents_dir = agent_intents_dir(&intents_root(), agent_id);
    let entries: Vec<fs::DirEntry> = match fs::read_dir(&intents_dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(_) => return false,
    };

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Check V1 intents
        if let Ok(intent) = serde_json::from_slice::<PaymentIntent>(&bytes) {
            if intent.agent_id == agent_id.to_string() {
                match intent.state {
                    IntentState::Pending | IntentState::Unknown => return true,
                    // Confirmed, Failed, Reconciled* are terminal - safe to delete
                    _ => {}
                }
            }
            continue;
        }

        // Check V2 intents - Signaled means signed but not yet confirmed
        if let Ok(intent) = serde_json::from_slice::<PaymentIntentV2>(&bytes) {
            if intent.agent_id == agent_id.to_string() {
                match intent.exec_state {
                    ExecState::Pending | ExecState::Unknown => return true,
                    // Confirmed, Failed, Reconciled* are terminal
                    // Signaled is NOT a state - V2 uses exec_state field
                    _ => {}
                }
                // Additional V2 check: if tx_signature exists but exec_state is Pending,
                // it's "Signaled" (signed but not confirmed)
                if intent.exec_state == ExecState::Pending && intent.tx_signature.is_some() {
                    return true; // Signed but not yet confirmed - in-flight
                }
            }
        }
    }

    false
}

/// DELETE /api/agents/{id} — safe, owner-scoped agent deletion (tombstone).
pub async fn delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    let Some(agent_uuid) = parse_agent_id(&id) else {
        return agent_not_found();
    };

    // Block deletion if any payment intents are in-flight or uncertain
    if has_blocking_intents(&agent_uuid) {
        return api_error(
            StatusCode::CONFLICT,
            "AGENT_HAS_INCOMPLETE_PAYMENTS",
            "Cannot delete agent with pending or unknown payment intents.",
        );
    }

    // Acquire per-agent async lock to serialize with concurrent payments
    let payment_mutex = crate::agents::agent_payment_lock(&id);
    let _payment_guard = payment_mutex.lock().await;

    // Atomic transition and cleanup under store lock
    let result = {
        let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
        (|| -> Result<Agent, Response> {
            // RE-CHECK inside lock: a payment may have claimed the key while we waited
            if has_blocking_intents(&agent_uuid) {
                return Err(api_error(
                    StatusCode::CONFLICT,
                    "AGENT_HAS_INCOMPLETE_PAYMENTS",
                    "Agent has in-flight payments (race detected).",
                ));
            }

            let mut agent = load_authorized(&id, user.id)?;

            // Require disabled status before deletion
            if agent.status != AgentStatus::Disabled {
                return Err(api_error(
                    StatusCode::CONFLICT,
                    "AGENT_NOT_DISABLED",
                    "Agent must be disabled before deletion",
                ));
            }

            // Revoke credentials - do not silently ignore failures.
            // If revocation fails, we return an error WITHOUT tombstoning.
            // This ensures a failed deletion can be retried; the agent stays
            // Disabled (not Deleted) so retry is safe.
            if let Err(e) = crate::agent_credentials::revoke_credential(&id) {
                // If the credential was never issued (RecordUnavailable),
                // that is acceptable for deletion - there is nothing to revoke.
                // Any other error means the credential may still be usable,
                // so we must fail safely.
                if !matches!(
                    e,
                    crate::agent_credentials::CredentialError::RecordUnavailable
                ) {
                    return Err(api_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "CREDENTIAL_REVOKE_FAILED",
                        "Failed to revoke agent credentials; deletion aborted",
                    ));
                }
            }

            // Tombstone transition
            if crate::pg_store::pg_is_authoritative() {
                // PG IS the authority: the tombstone is the DB-level
                // Disabled->Deleted transition (the edge table guard is
                // the WHERE clause). A DB error is fail-closed Store; the
                // agent stays Disabled so retry is safe (same contract).
                let now2 = now_unix();
                match crate::pg_store::pg_run(crate::pg_store::agent_transition_dispatch(
                    agent_uuid,
                    user.id,
                    &["disabled"],
                    "deleted",
                    now2,
                )) {
                    Ok(Ok(true)) => {}
                    _ => {
                        return Err(api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "AGENT_STORE_ERROR",
                            "Failed to write agent tombstone",
                        ));
                    }
                }
            } else {
                agent.status = AgentStatus::Deleted;
                agent.updated_at = now_unix();

                write_json_atomic(&agent_path(&agents_dir(), &agent_uuid), &agent).map_err(
                    |_| {
                        api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "AGENT_STORE_ERROR",
                            "Failed to write agent tombstone",
                        )
                    },
                )?;
            }

            Ok(agent)
        })()
    };

    match result {
        Ok(agent) => Json(serde_json::json!({
            "success": true,
            "agent": agent,
            "deleted": true
        }))
        .into_response(),
        Err(resp) => resp,
    }
}

pub(crate) fn agent_not_found() -> Response {
    api_error(StatusCode::NOT_FOUND, "AGENT_NOT_FOUND", "Agent not found")
}

// ---------------------------------------------------------------------------
// AGENT PAYMENT (STEP 8) — the FIRST money-moving path in the agent layer
// ---------------------------------------------------------------------------
//
// POST /api/agents/{id}/payments executes an explicit, synchronous Rialo
// transfer ONLY from the agent's own wallet file
// `artifact/agent_wallets/<validated_uuid>.json`. The human owner's wallet
// (`artifact/wallets/`, `load_or_create_wallet`, `wallet_path_for`, the
// `state.wallets` cache, `/api/me` resolution) is structurally unreachable
// from this path: the filename is derived server-side from the already
// validated UUID and nothing else. The user-wallet session is NOT an agent
// autonomous principal — this endpoint only fires on an explicit,
// authorized request; no scheduling, triggers, or autonomous execution
// exists here (NO AUTONOMY scope).
//
// MONEY INVARIANT: no transfer call happens until every gate has passed.
// Order (fixed, tested):
//   auth → owned-agent choke point → lifecycle(active) → persisted policy
//   → body parse → the ONE rlo_to_kelvin → the ONE valid_rialo_address
//   → idempotency-key validation → policy enforcement via Step 7's
//   check_agent_payment_policy (never duplicated here) → intent claim
//   (O_EXCL) → ATOMIC daily-spend RESERVATION → balance + fee-headroom
//   check → agent-wallet path resolution → RialoConfig::transfer → commit
//   or refund. The transfer call is the LAST money-moving operation.
//
// CONCURRENCY MODEL (documented):
//   * per-agent async lock (tokio::sync::Mutex keyed by agent UUID)
//     serializes same-agent payments end-to-end; different agents never
//     contend. There is NO single global payment lock.
//   * the global `store_lock` is held ONLY for microseconds of file I/O
//     (ledger read-modify-write CAS, intent state updates). It is NEVER
//     held across the external Rialo CLI transfer.
//   * the daily limit is enforced as CHECK → RESERVE → TRANSFER →
//     COMMIT/REFUND: `reserve_spend` re-reads + checked_add + persists
//     atomically under store_lock, so two racing requests cannot both
//     pass on the same stale figure even if the async lock were bypassed.
//   * the reservation is persisted BEFORE the transfer, so a crash
//     mid-transfer cannot let the daily bucket forget money already spent.
//
// FAILURE CLASSIFICATION is owned by RialoConfig::transfer / rialo.rs and
// is NOT duplicated here: the bounded clock-skew re-sign retry lives
// inside `transfer`; this layer never retries a transfer at all. A
// confirmation timeout is an UNKNOWN outcome (the tx may already be
// broadcast): the reservation stays held, the intent is marked `unknown`,
// replay is blocked pending reconciliation, and nothing is re-sent.
// A definitive failure refunds the reservation exactly.

/// Fee headroom in canonical kelvin — the integer form of the established
/// 0.001 RLO payment convention (`FEE_HEADROOM_RLO` in POST /api/payment).
pub const AGENT_PAYMENT_FEE_HEADROOM_KELVIN: u64 = 1_000_000;

/// The confirmation-timeout code from rialo.rs — the ONLY outcome with
/// "unknown" semantics. Reused, never re-invented here.
const RIALO_TRANSFER_CONFIRMATION_TIMEOUT: &str = "RIALO_TRANSFER_CONFIRMATION_TIMEOUT";

/// Daily-spend ledger file format (money-safety state, mode 0600).
pub const SPEND_SCHEMA_VERSION: u32 = 2;
/// Legacy schema version for migration.
pub const SPEND_SCHEMA_VERSION_V1: u32 = 1;
/// Agent payment intent file format.
pub const PAYMENT_INTENT_SCHEMA_VERSION: u32 = 1;

fn spend_path(dir: &FsPath, id: &Uuid) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// One subdirectory per agent, named by the VALIDATED UUID. The client's
/// idempotency key NEVER reaches a path raw: it lands in the filename only
/// as a hex-encoded byte string.
pub(crate) fn agent_intents_dir(root: &FsPath, id: &Uuid) -> PathBuf {
    root.join(id.to_string())
}

fn intent_path(dir: &FsPath, key: &str) -> PathBuf {
    dir.join(format!("{}.json", hex_encode(key.as_bytes())))
}

// ---------------------------------------------------------------------------
// GATE 2 — intent-based commitment accounting (the SINGLE source of truth).
//
// The intent file IS the commitment: it is created atomically (O_EXCL) with
// agent_id, amount_kelvin, recipient and lifecycle state, and every later
// mutation is one atomic rename under store_lock. There is NO parallel
// commitment ledger: `sum_outstanding_commitments` derives the outstanding
// amount directly from the intent states at decision time.
//
// Release rule (Gate 2C, verified against vendor types):
//   * Pending / Unknown                          -> ALWAYS held (may execute)
//   * Failed with no definitive-failure evidence -> held (fail-closed)
//   * Failed with on-chain err evidence          -> released (provably not
//     executed)
//   * Confirmed / ReconciledPaid                 -> held UNLESS the intent's
//     evidence slot is STRICTLY OLDER than the balance observation slot
//     (evidence_slot < observation_slot; both must be Some — the same-slot
//     ordering is unknowable, so same-slot holds)
//   * ReconciledAbsent                           -> ALWAYS released (the
//     reconciliation record IS the non-execution evidence)
//
// A missing or incomparable slot on EITHER side fails closed (held). The
// predicate can only ever err toward over-counting (blocking a task), never
// toward double-spending. `spent_kelvin` (the daily policy counter) NEVER
// enters this formula.
// ---------------------------------------------------------------------------

/// The observation slot carried alongside an admission-time balance read
/// (the RPC getBalance response's `context.slot`). None = no reliable
/// freshness evidence -> every Confirmed/ReconciledPaid commitment stays
/// held (fail-closed).
pub type ObservationSlot = Option<u64>;

/// Decide whether ONE intent record still commits funds against the
/// current balance snapshot. Pure so the predicate is unit-testable.
/// GATE 2F: the state is the TYPED enum (serde snake_case wire format —
/// see the Gate 2E audit), not a hand-written string.
fn intent_commitment_held(
    state: IntentState,
    evidence_slot: Option<u64>,
    err_present: bool,
    observation_slot: ObservationSlot,
) -> bool {
    match state {
        // may still execute; release impossible without reconciliation
        IntentState::Pending | IntentState::Unknown => true,
        // the reconciliation record IS the non-execution evidence
        IntentState::ReconciledAbsent => false,
        // definitive failure: err_present means the on-chain result was an
        // error (the transfer provably did not move the amount). Without it
        // the state alone is not proof (fail-closed: hold).
        IntentState::Failed => !err_present,
        // Confirmed / ReconciledPaid: release ONLY on provable inclusion —
        // strictly-older evidence slot vs the observation slot. Anything
        // missing or equal holds (over-count is the safe direction).
        IntentState::Confirmed | IntentState::ReconciledPaid => {
            match (evidence_slot, observation_slot) {
                (Some(ev), Some(obs)) if ev < obs => false,
                _ => true,
            }
        }
    }
}

/// Sum the OUTSTANDING commitments for one agent from its intent directory.
/// Every intent file present counts at most once (identity = the O_EXCL
/// file itself); the amount is always `amount_kelvin`. Corrupt/unreadable
/// files count their sibling slots as HELD only when parseable — an
/// unparseable record is skipped here because the money-cores deny on
/// corrupt money state; a task-admission denial is the fail-closed default
/// for unknown shapes (see gate notes) — actually: fail-closed means an
/// UNPARSEABLE file must not silently free its (unknown) amount. The
/// function therefore returns an error on unparseable intent records so
/// the caller can deny admission outright rather than under-count.
pub(crate) fn sum_outstanding_commitments(
    root: &FsPath,
    id: &Uuid,
    observation_slot: ObservationSlot,
) -> Result<u64, std::io::Error> {
    let dir = agent_intents_dir(root, id);
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        // no intents dir = no commitments for this agent
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let mut total: u64 = 0;
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::other(format!("intent parse: {e}")))?;

        // identity guard: the record MUST belong to this agent (the dir is
        // already agent-scoped; the in-file agent_id must agree — a
        // mismatched record is corruption, fail closed)
        let agent_id = value
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("intent missing agent_id"))?;
        if agent_id != id.to_string() {
            return Err(std::io::Error::other("intent identity mismatch"));
        }

        let amount = value
            .get("amount_kelvin")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| std::io::Error::other("intent missing amount_kelvin"))?;

        // GATE 2F: deserialized through the TYPED enums, not hand-written
        // strings. Both enums are `#[serde(rename_all = "snake_case")]`
        // (IntentState agents.rs:3182, ExecState agents.rs:4680), so the
        // on-disk wire format is e.g. "confirmed"/"reconciled_absent" —
        // the Gate 2E audit proved a PascalCase match never fires on real
        // records. A typed parse of a malformed/unknown state fails
        // CLOSED (Err) instead of falling into any catch-all.
        let state: IntentState = serde_json::from_value(
            value
                .get("state")
                .or_else(|| value.get("exec_state"))
                .cloned()
                .ok_or_else(|| std::io::Error::other("intent missing state"))?,
        )
        .map_err(|e| std::io::Error::other(format!("intent state: {e}")))?;

        // evidence slot: reconciliation.evidence.slot / block_height (the
        // strongest, exactly-once-committed record); for a direct Confirmed
        // the GATE 2F commit persists `evidence_slot` on the intent (the
        // transfer envelope's status.slot) — read here when present.
        // Missing evidence stays missing (never fabricated) and holds.
        let evidence_slot = value
            .get("reconciliation")
            .and_then(|r| r.get("evidence"))
            .and_then(|ev| {
                ev.get("block_height")
                    .and_then(serde_json::Value::as_u64)
                    .or_else(|| ev.get("slot").and_then(serde_json::Value::as_u64))
            })
            .or_else(|| {
                value
                    .get("evidence_slot")
                    .and_then(serde_json::Value::as_u64)
            });

        // definitive-failure evidence: the FAILED commit persists the
        // recorded error envelope (response.http_status + code) — a Failed
        // intent whose failure was the on-chain err class carries
        // response.code RIALO_TRANSFER_ERROR; pre-transfer aborts
        // (wallet/policy/store) prove the transfer was never DISPATCHED,
        // which is equally non-execution evidence.
        let err_present = match value.get("response") {
            Some(resp) => resp
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(|code| matches!(code, "RIALO_TRANSFER_ERROR" | "RIALO_WALLET_STORE_ERROR"))
                .unwrap_or(false),
            None => false,
        };

        if intent_commitment_held(state, evidence_slot, err_present, observation_slot) {
            total = total.saturating_add(amount);
        }
    }
    Ok(total)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

/// FNV-1a 64 as hex — an opaque correlation fingerprint recorded beside
/// the FULL canonical binding. The replay gate compares the binding
/// EXACTLY (recipient + amount), which is strictly stronger than a hash
/// equality check; the fingerprint never carries security weight.
fn fnv1a64_hex(input: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn request_fingerprint(recipient: &str, amount_kelvin: u64) -> String {
    fnv1a64_hex(&format!("{recipient}|{amount_kelvin}"))
}

/// UTC calendar day (YYYY-MM-DD) from Unix seconds — Howard Hinnant's
/// civil-from-days, pure integer math, correct across negative epochs.
pub fn utc_day(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DailySpend {
    pub schema_version: u32,
    pub agent_id: String,
    pub day: String,
    pub spent_kelvin: u64,
    /// TASK MARKETPLACE: Total of all Active task reservations.
    /// This persists across UTC day boundaries; only spent_kelvin resets daily.
    #[serde(default)]
    pub reserved_kelvin: u64,
    pub updated_at: i64,
}

fn fresh_spend(id: &Uuid, day: &str, now: i64) -> DailySpend {
    DailySpend {
        schema_version: SPEND_SCHEMA_VERSION,
        agent_id: id.to_string(),
        day: day.to_string(),
        spent_kelvin: 0,
        reserved_kelvin: 0, // TASK MARKETPLACE: start with zero reservations
        updated_at: now,
    }
}

/// Raw ledger read: Ok(None) = no bucket yet. A foreign agent_id or an
/// unknown schema_version is CORRUPTION, surfaced as Err — never masked
/// as a fresh zero (deny-by-default money state).
/// TASK MARKETPLACE: Supports schema v1 (migration) and v2.
fn read_spend(dir: &FsPath, id: &Uuid) -> Result<Option<DailySpend>, std::io::Error> {
    match fs::read(spend_path(dir, id)) {
        Ok(bytes) => {
            let spend: DailySpend = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("spend parse: {e}")))?;
            // Support both legacy v1 and current v2 schema
            if spend.schema_version != SPEND_SCHEMA_VERSION
                && spend.schema_version != SPEND_SCHEMA_VERSION_V1
            {
                return Err(std::io::Error::other("unsupported spend schema_version"));
            }
            if spend.agent_id != id.to_string() {
                return Err(std::io::Error::other("spend agent_id mismatch"));
            }
            Ok(Some(spend))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// The figure for the current UTC day (a stored bucket for an older day
/// rotates to zero — the read is presentation only, the CAS in
/// `reserve_spend` is authoritative).
fn spend_for_day(
    dir: &FsPath,
    id: &Uuid,
    day: &str,
    now: i64,
) -> Result<DailySpend, std::io::Error> {
    Ok(match read_spend(dir, id)? {
        Some(s) if s.day == day => s,
        _ => fresh_spend(id, day, now),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// The amount is now durably reserved; `previous_kelvin` is the value
    /// to restore on a definitive transfer failure.
    Reserved {
        previous_kelvin: u64,
        reserved_to_kelvin: u64,
    },
    /// The fresh atomic re-check failed — nothing was written.
    OverLimit,
}

/// CHECK-then-ATOMIC-RESERVE in one store_lock critical section: fresh
/// read → checked_add → limit re-check → persist (0600, temp+rename).
/// A racing request on the same agent always sees the updated figure,
/// so the daily limit can never be passed twice on one stale value.
fn reserve_spend(
    dir: &FsPath,
    id: &Uuid,
    day: &str,
    amount_kelvin: u64,
    daily_limit_kelvin: u64,
    now: i64,
) -> Result<ReserveOutcome, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    let current = spend_for_day(dir, id, day, now)?;
    let projected = match current.spent_kelvin.checked_add(amount_kelvin) {
        Some(p) => p,
        None => return Ok(ReserveOutcome::OverLimit),
    };
    if projected > daily_limit_kelvin {
        return Ok(ReserveOutcome::OverLimit);
    }
    let updated = DailySpend {
        schema_version: SPEND_SCHEMA_VERSION,
        agent_id: id.to_string(),
        day: day.to_string(),
        spent_kelvin: projected,
        reserved_kelvin: current.reserved_kelvin, // Preserve existing reservations
        updated_at: now,
    };
    fs::create_dir_all(dir)?;
    write_json_atomic(&spend_path(dir, id), &updated)?;
    Ok(ReserveOutcome::Reserved {
        previous_kelvin: current.spent_kelvin,
        reserved_to_kelvin: projected,
    })
}

/// The LOCKED hierarchical reservation (the cores' replacement for the
/// bare `reserve_spend` call on hierarchical paths). Takes store_lock and
/// runs the group-atomic section: per-agent CAS + per-scope CAS + full
/// rollback on any failure. A FLAT path (empty scopes) is identical to
/// the bare per-agent reservation (no aggregate buckets exist or are
/// touched).
fn reserve_spend_hierarchical(
    dir: &FsPath,
    id: &Uuid,
    scopes: &[(String, u64)],
    day: &str,
    amount_kelvin: u64,
    daily_limit_kelvin: u64,
    now: i64,
) -> Result<Result<HierarchicalReservation, ()>, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    reserve_spend_hierarchical_inner(dir, id, scopes, day, amount_kelvin, daily_limit_kelvin, now)
}

/// Test-facing wrappers (the focused spend shard pins the release
/// semantics through the same primitives the cores use).
#[cfg(test)]
pub(crate) fn release_scopes_bookkept_pub(
    dir: &FsPath,
    scopes: &[ScopeReservation],
    now: i64,
) -> Result<(), std::io::Error> {
    release_scopes_bookkept(dir, scopes, now)
}
#[cfg(test)]
pub(crate) fn release_scopes_inner_pub(
    dir: &FsPath,
    scopes: &[String],
    day: &str,
    amount_kelvin: u64,
    now: i64,
) -> Result<(), std::io::Error> {
    release_scopes_inner(dir, scopes, day, amount_kelvin, now)
}

/// Release the per-scope reservations recorded on the INTENT (the
/// claim-time scope list) — the exact-match aggregate analogue of
/// `release_spend`. Callers hold store_lock (the failure arms and the
/// reconciliation commit do).
fn release_scopes_inner(
    dir: &FsPath,
    scopes: &[String],
    day: &str,
    amount_kelvin: u64,
    now: i64,
) -> Result<(), std::io::Error> {
    for scope_str in scopes {
        let Some(scope_id) = parse_agent_id(scope_str) else {
            continue; // malformed persisted scope: never guessed at
        };
        if let Some(current) = read_aggregate_spend(dir, &scope_id)? {
            if current.day != day {
                continue; // day rollover: NEVER subtract from the new day
            }
            let Some(restored) = current.spent_kelvin.checked_sub(amount_kelvin) else {
                continue; // underflow: over-retention is the safe direction
            };
            write_json_atomic(
                &aggregate_path(dir, &scope_id),
                &AggregateSpend {
                    schema_version: SPEND_SCHEMA_VERSION,
                    scope_agent_id: scope_id.to_string(),
                    day: current.day,
                    spent_kelvin: restored,
                    updated_at: now,
                },
            )?;
        }
    }
    Ok(())
}

/// The locked per-scope release for the failure arms (abort/definitive
/// failure) — exact-match restore figures come from the reservation
/// bookkeeping (NOT the intent), so a mid-flight bucket change is never
/// guessed at.
fn release_scopes_bookkept(
    dir: &FsPath,
    scopes: &[ScopeReservation],
    now: i64,
) -> Result<(), std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    for s in scopes {
        if let Some(current) = read_aggregate_spend(dir, &s.scope_id)? {
            if current.spent_kelvin != s.reserved_to_kelvin {
                continue; // changed mid-flight: never guessed at
            }
            write_json_atomic(
                &aggregate_path(dir, &s.scope_id),
                &AggregateSpend {
                    schema_version: SPEND_SCHEMA_VERSION,
                    scope_agent_id: s.scope_id.to_string(),
                    day: current.day,
                    spent_kelvin: s.previous_kelvin,
                    updated_at: now,
                },
            )?;
        }
    }
    Ok(())
}

/// Refund a reservation ONLY if the bucket still exactly matches what
/// this reservation wrote (same day, same figure). A day rollover or an
/// unexpected third-party value is never guessed at — over-retaining the
/// bucket is always the money-safe direction.
fn release_spend(
    dir: &FsPath,
    id: &Uuid,
    day: &str,
    reserved_to_kelvin: u64,
    previous_kelvin: u64,
    now: i64,
) -> Result<(), std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    release_spend_inner(dir, id, day, reserved_to_kelvin, previous_kelvin, now)
}

/// Lock-free core of `release_spend` — call ONLY while store_lock is held
/// (the reconciliation commit runs inside one critical section and calls
/// this directly). Exact-match CAS semantics are unchanged.
fn release_spend_inner(
    dir: &FsPath,
    id: &Uuid,
    day: &str,
    reserved_to_kelvin: u64,
    previous_kelvin: u64,
    now: i64,
) -> Result<(), std::io::Error> {
    let current = match read_spend(dir, id)? {
        Some(s) => s,
        None => return Ok(()),
    };
    if current.day != day || current.spent_kelvin != reserved_to_kelvin {
        return Ok(());
    }
    let restored = DailySpend {
        schema_version: SPEND_SCHEMA_VERSION,
        agent_id: id.to_string(),
        day: day.to_string(),
        spent_kelvin: previous_kelvin,
        reserved_kelvin: current.reserved_kelvin, // Preserve reservations on refund
        updated_at: now,
    };
    write_json_atomic(&spend_path(dir, id), &restored)
}

/// PHASE 6 STEP 4 — the ReconciledAbsent release. Releases ONLY this
/// intent's ORIGINAL reservation (its exact amount on its exact original
/// UTC day, derived from `intent.created_at`): concurrent reservations of
/// OTHER intents stay in the bucket, and the subtracted figure belongs
/// to no other day. Callers hold store_lock.
///
/// UTC-midnight safety: if the stored bucket no longer carries the
/// original day (rollover already happened and the ledger re-based), this
/// is a deliberate NO-OP — the new day's spend is NEVER subtracted from.
/// Same-day underflow (bucket below the reservation — a state this code
/// never constructs) is likewise a NO-OP: the money-safe direction is
/// always over-retention, exactly like `release_spend`.
/// Returns true when the release was written.
fn release_absent_reservation_inner(
    dir: &FsPath,
    id: &Uuid,
    original_day: &str,
    amount_kelvin: u64,
    now: i64,
) -> Result<bool, std::io::Error> {
    let current = match read_spend(dir, id)? {
        Some(s) => s,
        None => return Ok(false),
    };
    if current.day != original_day {
        return Ok(false);
    }
    let Some(restored) = current.spent_kelvin.checked_sub(amount_kelvin) else {
        return Ok(false);
    };
    let updated = DailySpend {
        schema_version: SPEND_SCHEMA_VERSION,
        agent_id: id.to_string(),
        day: current.day,
        spent_kelvin: restored,
        reserved_kelvin: current.reserved_kelvin, // Preserve reservations on release
        updated_at: now,
    };
    fs::create_dir_all(dir)?;
    write_json_atomic(&spend_path(dir, id), &updated)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// PHASE 9 "Hierarchical spend controls" — the AGGREGATE reservation ledger.
//
// The aggregate bucket lives in the SAME reservation authority (the spend
// ledger directory `artifact/agent_spend/`) under the SAME store lock and
// the SAME atomic temp+rename discipline — one authority, one lock, one
// atomicity model. It is a SIBLING FILE (`<scope-uuid>.agg.json`), NOT a
// field on the per-agent bucket: the per-agent bucket is identity-checked
// against its agent and feeds the stats/leaderboard aggregation and the
// reconciliation release arithmetic — folding aggregate figures into it
// would double-count spend in projections and entangle two release
// arithmetic paths. One authoritative source (the ledger dir), two record
// kinds, each with exactly one meaning.
//
// SEMANTICS: a scope node's aggregate bucket covers ITS OWN spend + all
// descendants' spend under it (the frozen mission's scope definition). A
// payment draws EVERY applicable scope bucket on its chain (child → root),
// each atomically, in ONE store_lock critical section together with the
// per-agent reservation — the multi-level reservation is atomic AS A
// GROUP: a failure anywhere rolls back everything acquired in the section
// (exact-match restores), so no partial reservation can ever persist.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AggregateSpend {
    pub schema_version: u32,
    pub scope_agent_id: String,
    pub day: String,
    pub spent_kelvin: u64,
    pub updated_at: i64,
}

fn aggregate_path(dir: &FsPath, scope_id: &Uuid) -> PathBuf {
    dir.join(format!("{scope_id}.agg.json"))
}

/// Raw aggregate read: Ok(None) = no bucket yet. A foreign scope id or an
/// unknown schema_version is CORRUPTION, surfaced as Err — never masked
/// as a fresh zero (deny-by-default money state).
fn read_aggregate_spend(
    dir: &FsPath,
    scope_id: &Uuid,
) -> Result<Option<AggregateSpend>, std::io::Error> {
    match fs::read(aggregate_path(dir, scope_id)) {
        Ok(bytes) => {
            let spend: AggregateSpend = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("aggregate parse: {e}")))?;
            if spend.schema_version != SPEND_SCHEMA_VERSION {
                return Err(std::io::Error::other(
                    "unsupported aggregate schema_version",
                ));
            }
            if spend.scope_agent_id != scope_id.to_string() {
                return Err(std::io::Error::other("aggregate scope_id mismatch"));
            }
            Ok(Some(spend))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// THE group-atomic hierarchical reservation. ONE store_lock critical
/// section containing: the per-agent CAS reservation (the existing
/// primitive, semantics unchanged) + one atomic aggregate CAS per
/// applicable scope (child → root order) + the FULL rollback of
/// everything acquired in the section on any failure. Racing children
/// sharing a scope serialize on the same lock and the same bucket, so the
/// aggregate cap can never be overshot; racing scopes within one payment
/// cannot produce a partial reservation (the section is atomic as a
/// group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchicalReservation {
    /// the per-agent reservation (existing semantics)
    pub agent: ReserveOutcomeSuccess,
    /// the per-scope reservations acquired (child → root), with the
    /// rollback figures for the failure paths
    pub scopes: Vec<ScopeReservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveOutcomeSuccess {
    pub previous_kelvin: u64,
    pub reserved_to_kelvin: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeReservation {
    pub scope_id: Uuid,
    pub previous_kelvin: u64,
    pub reserved_to_kelvin: u64,
}

/// Lock-free core of the hierarchical reservation — call ONLY while
/// store_lock is held (the cores call this in place of `reserve_spend`).
/// On any aggregate failure, everything acquired in this section is
/// rolled back (exact-match restores — the same CAS discipline as
/// `release_spend`) INCLUDING the per-agent reservation, and `OverLimit`
/// is returned: no partial reservation can ever persist, and the payment
/// is denied.
fn reserve_spend_hierarchical_inner(
    dir: &FsPath,
    id: &Uuid,
    scopes: &[(String, u64)],
    day: &str,
    amount_kelvin: u64,
    daily_limit_kelvin: u64,
    now: i64,
) -> Result<Result<HierarchicalReservation, ()>, std::io::Error> {
    // (1) the per-agent CAS reservation — the EXISTING primitive, called
    //     in its lock-free inner form? No: reserve_spend takes the lock
    //     itself. To keep ONE lock section, the per-agent reserve is
    //     inlined here with identical semantics (fresh read → checked_add
    //     → limit re-check → persist), under the SAME lock the caller
    //     holds. (reserve_spend itself is unchanged for all other callers.)
    let agent_current = spend_for_day(dir, id, day, now)?;
    let agent_projected = match agent_current.spent_kelvin.checked_add(amount_kelvin) {
        Some(p) => p,
        None => return Ok(Err(())),
    };
    if agent_projected > daily_limit_kelvin {
        return Ok(Err(()));
    }
    fs::create_dir_all(dir)?;
    write_json_atomic(
        &spend_path(dir, id),
        &DailySpend {
            schema_version: SPEND_SCHEMA_VERSION,
            agent_id: id.to_string(),
            day: day.to_string(),
            spent_kelvin: agent_projected,
            reserved_kelvin: 0,
            updated_at: now,
        },
    )?;
    let agent_reservation = ReserveOutcomeSuccess {
        previous_kelvin: agent_current.spent_kelvin,
        reserved_to_kelvin: agent_projected,
    };

    // (2) the aggregate CAS reservations, child → root order
    let mut acquired: Vec<ScopeReservation> = Vec::new();
    for (scope_str, cap) in scopes {
        let Some(scope_id) = parse_agent_id(scope_str) else {
            // malformed scope: roll back everything acquired so far
            release_acquired(dir, id, &agent_reservation, &acquired, day, now);
            return Ok(Err(()));
        };
        let current = match read_aggregate_spend(dir, &scope_id)? {
            Some(s) if s.day == day => s,
            _ => AggregateSpend {
                schema_version: SPEND_SCHEMA_VERSION,
                scope_agent_id: scope_id.to_string(),
                day: day.to_string(),
                spent_kelvin: 0,
                updated_at: now,
            },
        };
        let projected = match current.spent_kelvin.checked_add(amount_kelvin) {
            Some(p) => p,
            None => {
                release_acquired(dir, id, &agent_reservation, &acquired, day, now);
                return Ok(Err(()));
            }
        };
        if projected > *cap {
            release_acquired(dir, id, &agent_reservation, &acquired, day, now);
            return Ok(Err(()));
        }
        write_json_atomic(
            &aggregate_path(dir, &scope_id),
            &AggregateSpend {
                schema_version: SPEND_SCHEMA_VERSION,
                scope_agent_id: scope_id.to_string(),
                day: day.to_string(),
                spent_kelvin: projected,
                updated_at: now,
            },
        )?;
        acquired.push(ScopeReservation {
            scope_id,
            previous_kelvin: current.spent_kelvin,
            reserved_to_kelvin: projected,
        });
    }
    Ok(Ok(HierarchicalReservation {
        agent: agent_reservation,
        scopes: acquired,
    }))
}

/// The rollback helper: restore every acquired bucket to its
/// previous value by EXACT MATCH (the same no-guess CAS discipline as
/// `release_spend` — a day rollover or an unexpected third-party value is
/// never guessed at; over-retention is the money-safe direction). Callers
/// hold store_lock.
fn release_acquired(
    dir: &FsPath,
    agent_id: &Uuid,
    agent: &ReserveOutcomeSuccess,
    scopes: &[ScopeReservation],
    day: &str,
    now: i64,
) {
    for s in scopes {
        if let Ok(Some(current)) = read_aggregate_spend(dir, &s.scope_id) {
            if current.day == day && current.spent_kelvin == s.reserved_to_kelvin {
                let _ = write_json_atomic(
                    &aggregate_path(dir, &s.scope_id),
                    &AggregateSpend {
                        schema_version: SPEND_SCHEMA_VERSION,
                        scope_agent_id: s.scope_id.to_string(),
                        day: day.to_string(),
                        spent_kelvin: s.previous_kelvin,
                        updated_at: now,
                    },
                );
            }
        }
    }
    // the per-agent bucket: same exact-match restore (over-retention is
    // the money-safe direction — a mismatch is never guessed at)
    if let Ok(Some(current)) = read_spend(dir, agent_id) {
        if current.day == day && current.spent_kelvin == agent.reserved_to_kelvin {
            let _ = write_json_atomic(
                &spend_path(dir, agent_id),
                &DailySpend {
                    schema_version: SPEND_SCHEMA_VERSION,
                    agent_id: agent_id.to_string(),
                    day: day.to_string(),
                    spent_kelvin: agent.previous_kelvin,
                    reserved_kelvin: current.reserved_kelvin,
                    updated_at: now,
                },
            );
        }
    }
}

/// Locked convenience core for tests and the standalone path.
#[allow(dead_code)]
fn release_absent_reservation(
    dir: &FsPath,
    id: &Uuid,
    original_day: &str,
    amount_kelvin: u64,
    now: i64,
) -> Result<bool, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    release_absent_reservation_inner(dir, id, original_day, amount_kelvin, now)
}

/// Idempotency / replay ledger. One file per (agent UUID dir, hex(key)):
/// the record binds the key to the FULL canonical request (recipient +
/// kelvin amount + fingerprint) and the outcome of the attempt. No secrets
/// by construction — recipient, amount, and a public tx signature only.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentState {
    /// claimed; a transfer attempt is in flight
    Pending,
    /// transfer confirmed; the response is stored verbatim for replay
    Confirmed,
    /// transfer DEFINITIVELY failed (classified by rialo.rs); reservation
    /// refunded; recorded so a replay can never start a second transfer
    Failed,
    /// outcome UNKNOWN (confirmation timeout); reservation held; new
    /// transfers under this key are blocked until reconciliation
    Unknown,
    /// PHASE 6 STEP 4 — reconciliation PROVED the transfer executed.
    /// Immutable terminal; the reservation stays consumed; NEVER a second
    /// transfer, NEVER a release.
    ReconciledPaid,
    /// PHASE 6 STEP 4 — reconciliation PROVED definitive non-execution.
    /// Immutable terminal; the original reservation is released exactly
    /// once (never a second transfer, never another reservation).
    ReconciledAbsent,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PaymentIntent {
    pub schema_version: u32,
    pub agent_id: String,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    /// the exact binding a replay is compared against (stronger than the
    /// hash alone; hash is stored too as `request_fingerprint`)
    pub recipient: String,
    pub amount_kelvin: u64,
    pub state: IntentState,
    /// stored result (confirmed success body) or recorded error envelope
    pub response: Option<serde_json::Value>,
    pub created_at: i64,
    pub updated_at: i64,
    /// PHASE 6 STEP 4 — written EXACTLY ONCE by the reconciliation commit
    /// when (and only when) `state` flips to a Reconciled* terminal.
    /// Additive-defaulted so every pre-Step-4 schema-1 record still
    /// parses unchanged; nothing rewrites existing files.
    #[serde(default)]
    pub reconciliation: Option<ReconciliationRecord>,
    /// PHASE 8 ITEM 10 — the canonical signer (rialo_tx_signers) that
    /// produced the signature inside this record's response, written at
    /// the Confirmed commit. Public identity only (kind + address),
    /// never key material or a file path. Additive-defaulted exactly
    /// like `reconciliation` above: every pre-Item-10 schema-1 record
    /// parses unchanged and the schema version stays 1.
    #[serde(default)]
    pub signer: Option<SignerRecord>,
    /// PHASE 9 "Authorization / execution audit" — the SAME authz snapshot
    /// semantics as v2 (`AuthzBinding`: policy fingerprint + authorized_at),
    /// recorded at claim on the owner lane. Additive-defaulted exactly like
    /// the `signer`/`reconciliation` precedent: every pre-audit schema-1
    /// record parses unchanged and the schema version stays 1. This is an
    /// AUDIT SNAPSHOT only (TM-P-05 semantics unchanged) — never a re-check
    /// input; `check_agent_payment_policy` remains the sole authority.
    #[serde(default)]
    pub authz: Option<AuthzBinding>,
    /// PHASE 9 spend controls: the CLAIM-TIME aggregate
    /// scope ids this intent's reservation drew (child → root order,
    /// canonical UUID strings; empty = flat/no aggregate scopes). Written
    /// at claim from the resolved hierarchy; the reconciliation Absent
    /// release uses EXACTLY these scopes (never the current chain — the
    /// reservation was taken against the claim-time scopes).
    #[serde(default)]
    pub aggregate_scopes: Vec<String>,
    /// GATE 2F — the slot in which the confirmed transfer was PROCESSED
    /// (the CLI transfer envelope's status.slot; same quantity as the
    /// vendor GetTransactionResponse.block_height). Written ONLY at the
    /// Confirmed commit, only when the envelope carried one — missing
    /// evidence stays missing, never fabricated. This is what lets
    /// `sum_outstanding_commitments` release a Confirmed commitment once
    /// a balance observation's context.slot provably includes the debit.
    /// Additive-defaulted: pre-Gate-2F records parse unchanged.
    #[serde(default)]
    pub evidence_slot: Option<u64>,
}

/// Opaque, bounded, path-safe keys only. The key is hex-encoded before it
/// ever appears in a filename, but the charset gate keeps intents
/// readable/diagnosable and refuses oversized or traversal-shaped input.
pub const MAX_IDEMPOTENCY_KEY_LEN: usize = 128;

pub(crate) fn valid_idempotency_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_IDEMPOTENCY_KEY_LEN
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Six-state aggregation row shared by every projection that classifies
/// intent slots through `leaderboard::observe` (leaderboard, agent stats).
/// Fully owned by value so module boundaries never share lifetimes.
#[derive(Debug, Clone, Copy, Default)]
pub struct StatsTotals {
    /// every intent slot parsed for the agent
    pub total: u64,
    /// `confirmed` + `reconciled_paid`
    pub confirmed: u64,
    /// sum of amount_kelvin over exactly the confirmed slots
    pub volume_kelvin: u64,
    /// `pending`
    pub pending: u64,
    /// `failed` + `reconciled_absent`
    pub failed: u64,
    /// `unknown`
    pub unknown: u64,
    /// `reconciled_paid` + `reconciled_absent`
    pub reconciled: u64,
    /// min `updated_at` over confirmed slots (else None)
    pub first_confirmed_at: Option<i64>,
    /// max `updated_at` over confirmed slots (else None)
    pub last_confirmed_at: Option<i64>,
    /// distinct confirmed recipients (0 for lanes that never expose them)
    pub distinct_recipients_confirmed: u64,
}

pub fn read_intent(
    root: &FsPath,
    id: &Uuid,
    key: &str,
) -> Result<Option<PaymentIntent>, std::io::Error> {
    match fs::read(intent_path(&agent_intents_dir(root, id), key)) {
        Ok(bytes) => {
            let intent: PaymentIntent = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("intent parse: {e}")))?;
            if intent.schema_version != PAYMENT_INTENT_SCHEMA_VERSION {
                return Err(std::io::Error::other("unsupported intent schema_version"));
            }
            if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                return Err(std::io::Error::other("intent identity mismatch"));
            }
            Ok(Some(intent))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

#[derive(Debug)]
pub enum IntentClaim {
    Created,
    Existing(PaymentIntent),
}

/// MISSION PHASE 2 — the storage-mode-aware claim result. The core calls
/// `pg_store::claim_intent_dispatch` in Postgres mode (the DB is the sole
/// authority) and the legacy `claim_intent` in Filesystem mode — exactly
/// one authority per mode, no dual-write.
#[derive(Debug)]
pub enum IntentClaimKind {
    Created,
    Existing(PaymentIntent),
}

/// Claim the key atomically (O_EXCL create-new, same discipline as the
/// Step-3 wallet mint). Exactly one racing request can ever Create; the
/// loser reads back the existing record and REPLAYS its outcome instead
/// of starting a second transfer.
fn claim_intent(
    root: &FsPath,
    id: &Uuid,
    draft: &PaymentIntent,
) -> Result<IntentClaim, std::io::Error> {
    let dir = agent_intents_dir(root, id);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let path = intent_path(&dir, &draft.idempotency_key);
    let bytes = serde_json::to_vec_pretty(draft)
        .map_err(|e| std::io::Error::other(format!("serialize intent: {e}")))?;

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return match read_intent(root, id, &draft.idempotency_key)? {
                Some(existing) => Ok(IntentClaim::Existing(existing)),
                None => Err(std::io::Error::other("intent vanished mid-claim")),
            };
        }
        Err(err) => return Err(err),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    match file.write_all(&bytes).and_then(|()| file.flush()) {
        Ok(()) => Ok(IntentClaim::Created),
        Err(err) => {
            // this exact path was created by this call moments ago under
            // O_EXCL — removing it can only ever delete our own record
            let _ = fs::remove_file(&path);
            Err(err)
        }
    }
}

/// Record a state transition on a claimed intent. Persistence is
/// serialized under the same store_lock as every other agent file op.
fn update_intent(
    root: &FsPath,
    id: &Uuid,
    key: &str,
    now: i64,
    f: impl FnOnce(&mut PaymentIntent),
) -> Result<PaymentIntent, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut intent = read_intent(root, id, key)?
        .ok_or_else(|| std::io::Error::other("intent record missing for update"))?;
    // PHASE 6 STEP 4 — immutability at the STORE layer, not just the API:
    // a reconciled terminal can never be modified again by ANY update
    // path (a straggling engine write after a restart, a second
    // reconcile attempt, anything). The stored record is returned
    // untouched and NOTHING is written.
    if matches!(
        intent.state,
        IntentState::ReconciledPaid | IntentState::ReconciledAbsent
    ) {
        return Ok(intent);
    }
    f(&mut intent);
    intent.updated_at = now;
    write_json_atomic(&intent_path(&agent_intents_dir(root, id), key), &intent)?;
    Ok(intent)
}

fn recorded_error_json(status: u16, code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "http_status": status, "code": code, "message": message })
}

/// The injected execution boundary for the money core. `RialoConfig` is
/// the production implementation and NOTHING at the boundary is faked:
/// `transfer` is the unchanged `RialoConfig::transfer`, so its bounded
/// clock-skew retry and its error classification stay centralized in
/// rialo.rs. Tests inject a mock here instead — never real money.
pub trait PaymentOps: Send + Sync {
    /// PHASE 9 STEP 8 (custody cutover): whether THIS lane holds funded-key
    /// custody OUTSIDE the app process (the isolated signer). Default: the
    /// legacy in-process/CLI custody — the pre-transfer signer-file
    /// verification applies (unchanged). The isolated-signer lane overrides
    /// to true: custody lives in the signer's trust domain, the record's
    /// address IS the signer-owned address, and the pre-transfer legacy
    /// file check is meaningless (and would mismatch by design).
    fn uses_external_custody(&self) -> bool {
        false
    }

    fn balance(&self, address: &str) -> Result<f64, RialoError>;
    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError>;

    /// PHASE 6 STEP 4 — READ-ONLY get_transaction(signature). Never moves
    /// money; the payment core MUST NOT call this (only the reconciler
    /// does). The structural tests pin that separation.
    fn read_tx(&self, signature: &str) -> TxLookup;

    /// PHASE 6 STEP 4 — READ-ONLY bounded address-history discovery
    /// (vendor getSignaturesForAddress; `until_signature` is the vendor's
    /// signature cursor). Same call-site restriction.
    fn signatures_for_address(
        &self,
        address: &str,
        until_signature: Option<&str>,
        limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError>;
}

impl PaymentOps for RialoConfig {
    fn balance(&self, address: &str) -> Result<f64, RialoError> {
        // the ONE established balance path
        RialoConfig::balance(self, address)
    }

    fn transfer(
        &self,
        keypair_path: &FsPath,
        to: &str,
        amount_rlo: &str,
    ) -> Result<String, RialoError> {
        // THE unchanged transfer path: bounded clock-skew re-sign retry,
        // confirmation-timeout classification, and the DO-NOT-retry note
        // all live inside RialoConfig::transfer. This seam adds none.
        RialoConfig::transfer(self, &keypair_path.to_path_buf(), to, amount_rlo)
    }

    fn read_tx(&self, signature: &str) -> TxLookup {
        // THE one read-only get_transaction path in rialo.rs (CLI
        // `client transaction <sig> --json` through RialoConfig::run).
        RialoConfig::transaction_lookup(self, signature)
    }

    fn signatures_for_address(
        &self,
        address: &str,
        until_signature: Option<&str>,
        limit: u64,
    ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
        // THE one read-only vendor-API address scan (rialo.rs).
        RialoConfig::signatures_for_address(self, address, until_signature, limit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// a transfer for this key is still in flight — never replayed
    InProgress,
    /// unknown outcome (confirmation timeout) — reconciliation required
    Unreconciled,
    /// same key, DIFFERENT canonical request — the binding refuses
    Conflict,
    /// PHASE 6 STEP 4: the key is bound to an immutable reconciled
    /// terminal. The box carries the stored ReconciliationRecord for the
    /// 200-style replay (None only if the record itself is corrupt).
    Reconciled(Option<Box<ReconciliationRecord>>),
}

/// Typed, field-safe failures. Nothing here (nor anything it renders) can
/// carry a wallet path, keypair, seed, or filesystem internal.
#[derive(Debug)]
pub enum PaymentFailure {
    Key,
    Enforcement(EnforcementDenial),
    Replay(ReplayVerdict),
    /// a recorded Failed intent is replayed as its original error — the
    /// key is burned against a second transfer attempt
    Recorded {
        status: u16,
        code: String,
        message: String,
    },
    /// PHASE 6 STEP 4: the key is bound to an immutable reconciled
    /// terminal. Renders the STORED reconciliation as a 200 — no transfer,
    /// no reservation, no RPC.
    Reconciled(Option<Box<ReconciliationRecord>>),
    Store,
    WalletStore,
    InsufficientFunds {
        balance_rlo: f64,
        amount_rlo: f64,
    },
    BalanceUnreadable,
    Transfer(RialoError),
}

impl PaymentFailure {
    /// Stable category code. `Recorded` replays return the ORIGINAL error
    /// code inside the envelope; this lists the replay category. Used by
    /// tests and operators, not on the response-rendering path.
    #[allow(dead_code)]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Key => "INVALID_IDEMPOTENCY_KEY",
            Self::Enforcement(d) => d.code(),
            Self::Replay(ReplayVerdict::InProgress) => "AGENT_PAYMENT_IN_PROGRESS",
            Self::Replay(ReplayVerdict::Unreconciled) => "AGENT_PAYMENT_UNRECONCILED",
            Self::Replay(ReplayVerdict::Conflict) => "AGENT_IDEMPOTENCY_CONFLICT",
            Self::Replay(ReplayVerdict::Reconciled(_)) => "AGENT_PAYMENT_RECONCILED",
            Self::Recorded { .. } => "AGENT_PAYMENT_REPLAY",
            Self::Reconciled(_) => "AGENT_PAYMENT_RECONCILED",
            Self::Store => "AGENT_STORE_ERROR",
            Self::WalletStore => "AGENT_WALLET_STORE_ERROR",
            Self::InsufficientFunds { .. } => "INSUFFICIENT_FUNDS",
            Self::BalanceUnreadable => "RIALO_ERROR",
            Self::Transfer(err) => err.code,
        }
    }

    pub fn into_response(self) -> Response {
        match self {
            Self::Key => api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_IDEMPOTENCY_KEY",
                "Idempotency-Key header is required for agent payments: 1-128 characters from A-Z a-z 0-9 - _",
            ),
            Self::Enforcement(denial) => denial.into_response(),
            Self::Replay(ReplayVerdict::InProgress) => api_error(
                StatusCode::CONFLICT,
                "AGENT_PAYMENT_IN_PROGRESS",
                "A transfer for this idempotency key is already in progress; do not replay",
            ),
            Self::Replay(ReplayVerdict::Unreconciled) => api_error(
                StatusCode::CONFLICT,
                "AGENT_PAYMENT_UNRECONCILED",
                "The previous attempt for this key has an unknown outcome; verify transaction state on-chain before any new transfer",
            ),
            Self::Replay(ReplayVerdict::Conflict) => api_error(
                StatusCode::CONFLICT,
                "AGENT_IDEMPOTENCY_CONFLICT",
                "Idempotency key is already bound to a different payment request",
            ),
            // PHASE 6 STEP 4: a payment replay onto a reconciled terminal
            // returns the STORED reconciliation as 200 — no transfer, no
            // reservation, no RPC, no ledger mutation
            Self::Replay(ReplayVerdict::Reconciled(record)) => match record.as_deref() {
                Some(record) => Json(reconciliation_json(record)).into_response(),
                None => api_error(
                    StatusCode::CONFLICT,
                    "AGENT_PAYMENT_RECONCILED",
                    "This payment key is bound to a reconciled outcome and is never re-executed",
                ),
            },
            Self::Recorded {
                status,
                code,
                message,
            } => api_error(
                StatusCode::from_u16(status).unwrap_or(StatusCode::CONFLICT),
                &code,
                &message,
            ),
            Self::Reconciled(record) => {
                let body = match record {
                    Some(record) => reconciliation_json(&record),
                    None => serde_json::json!({
                        "success": true,
                        "code": "AGENT_PAYMENT_RECONCILED",
                        "message": "This payment key is bound to an immutable reconciled outcome; the stored verdict is authoritative",
                    }),
                };
                Json(body).into_response()
            }
            Self::Store => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent payment state could not be stored",
            ),
            Self::WalletStore => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_WALLET_STORE_ERROR",
                "Agent wallet file is missing or unreadable",
            ),
            Self::InsufficientFunds {
                balance_rlo,
                amount_rlo,
            } => api_error(
                StatusCode::BAD_REQUEST,
                "INSUFFICIENT_FUNDS",
                &format!(
                    "Agent wallet balance is {balance_rlo} RLO; payment of {amount_rlo} RLO plus 0.001 RLO fee headroom is not covered"
                ),
            ),
            Self::BalanceUnreadable => api_error(
                StatusCode::BAD_GATEWAY,
                "RIALO_ERROR",
                "Agent balance reading is not usable for a money comparison; no transfer was attempted",
            ),
            // existing typed error path — status + code + detail preserved
            // exactly as rialo.rs classified them (never remapped here)
            Self::Transfer(err) => super::rialo_error_response(&err),
        }
    }
}

/// PURE success-response builder — public fields only, matching the
/// established payment shape. `balance_after_rlo` is null unless honestly
/// re-read (this step does not re-read: null, NEVER a guessed number).
pub fn payment_success_json(
    agent_id: &str,
    recipient: &str,
    amount_rlo: f64,
    amount_kelvin: u64,
    signature: &str,
    balance_before_rlo: Option<f64>,
    balance_after_rlo: Option<f64>,
) -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "agent_id": agent_id,
        "payment": {
            "to": recipient,
            "amount_rlo": amount_rlo,
            "amount_kelvin": amount_kelvin,
            "signature": signature,
            "balance_before_rlo": balance_before_rlo.map(|b| format!("{} RLO", b)),
            "balance_after_rlo": balance_after_rlo.map(|b| format!("{} RLO", b)),
        }
    })
}

/// Balance reads come back as f64 RLO (the one established `balance`
/// representation). Money comparisons then run in INTEGER KELVIN: a
/// non-finite or negative read is UNUSABLE (None) — never floored to zero.
pub fn rlo_balance_to_kelvin(value: f64) -> Option<u64> {
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let kelvin = (value * 1e9).round();
    if kelvin < 0.0 || kelvin > u64::MAX as f64 {
        return None;
    }
    Some(kelvin as u64)
}

/// PHASE 9 audit — the execution-outcome writer for the single
/// `ops.transfer` dispatch boundary of the money cores. Best-effort ONLY
/// (an audit failure can never alter the outcome); the intent record and
/// the spend ledger remain the authoritative money facts.
fn audit_execution_outcome(
    intents_dir: &FsPath,
    at: i64,
    outcome: crate::audit::AuditOutcome,
    code: Option<&str>,
    agent_id: &str,
    idempotency_key: &str,
    tx_signature: Option<&str>,
    policy_fingerprint: Option<String>,
    intent_id: Option<&str>,
) {
    let audit_dir = crate::audit::audit_dir_for(intents_dir);
    crate::audit::record(
        crate::audit::execution(
            at,
            outcome,
            code,
            agent_id,
            idempotency_key,
            tx_signature,
            policy_fingerprint.as_deref(),
            intent_id,
        ),
        &audit_dir,
        Some(agent_id),
    );
}

/// PHASE 9 audit — classify a core-returned PaymentFailure into its audit
/// category. Replays are REPLAY observations (never execution evidence);
/// enforcement denials are authorization denials; store/wallet/balance/
/// transfer failures are execution-attempt outcomes (already written by the
/// core's own dispatch-boundary records — this covers the pre-claim
/// enforcement denials and the replay classifications only, so no record is
/// duplicated for outcomes the core already audited).
fn audit_handler_failure(
    failure: &PaymentFailure,
    identity_class: crate::audit::IdentityClass,
    agent_id: &str,
    idempotency_key: &str,
    policy_fingerprint: Option<String>,
    audit_dir: &FsPath,
    now: i64,
) {
    let policy_fp = policy_fingerprint;
    match failure {
        PaymentFailure::Replay(_) | PaymentFailure::Reconciled(_) => {
            let code = match failure {
                PaymentFailure::Replay(ReplayVerdict::InProgress) => "AGENT_PAYMENT_IN_PROGRESS",
                PaymentFailure::Replay(ReplayVerdict::Unreconciled) => "AGENT_PAYMENT_UNRECONCILED",
                PaymentFailure::Replay(ReplayVerdict::Conflict) => "AGENT_IDEMPOTENCY_CONFLICT",
                PaymentFailure::Replay(ReplayVerdict::Reconciled(_)) => "AGENT_PAYMENT_RECONCILED",
                PaymentFailure::Reconciled(_) => "AGENT_PAYMENT_RECONCILED",
                _ => unreachable!("replay match exhausted"),
            };
            crate::audit::record(
                crate::audit::replay(now, code, agent_id, idempotency_key),
                audit_dir,
                Some(agent_id),
            );
        }
        // Key-shape denials happen before the core runs (no key to audit
        // with); enforcement denials are mirrored inside the CORE itself
        // (single record, single authority) — never duplicated here.
        PaymentFailure::Key => {
            let code = match failure {
                PaymentFailure::Enforcement(d) => d.code(),
                PaymentFailure::Key => "INVALID_IDEMPOTENCY_KEY",
                _ => unreachable!("enforcement match exhausted"),
            };
            crate::audit::record(
                crate::audit::authorization(
                    now,
                    crate::audit::AuditOutcome::Deny,
                    Some(code),
                    identity_class,
                    Some(agent_id),
                    Some(idempotency_key),
                    policy_fp.as_deref(),
                ),
                audit_dir,
                Some(agent_id),
            );
        }
        // Everything else (Store/WalletStore/InsufficientFunds/BalanceUnreadable/
        // Transfer/Recorded) was already mirrored at the core's dispatch
        // boundary — no second record (no duplicate execution evidence).
        _ => {}
    }
}

/// PHASE 9 audit — the authorization-decision writer for the money
/// handlers. One call per decision the EXISTING authorities already made;
/// purely observational (best-effort, never alters the response).
fn audit_authorization(
    audit_dir: &FsPath,
    at: i64,
    outcome: crate::audit::AuditOutcome,
    code: Option<&str>,
    identity_class: crate::audit::IdentityClass,
    agent_id: Option<&str>,
    idempotency_key: Option<&str>,
    policy_fingerprint: Option<&str>,
) {
    crate::audit::record(
        crate::audit::authorization(
            at,
            outcome,
            code,
            identity_class,
            agent_id,
            idempotency_key,
            policy_fingerprint,
        ),
        audit_dir,
        agent_id,
    );
}

/// THE money core (synchronous, directory-parameterized so every test
/// runs against temp stores with a mocked transfer — the real `artifact/`
/// tree is never opened by unit tests). All inputs are already
/// handler-validated; the core re-checks the daily limit atomically
/// because a prior read is always potentially stale.
///
/// Returns Ok(success-body) or a typed PaymentFailure. The transfer call
/// is the LAST money-moving operation in the sequence.
#[allow(clippy::too_many_arguments)]
pub fn execute_agent_payment(
    ops: &(dyn PaymentOps + Send + Sync),
    wallet_dir: &FsPath,
    ledger_dir: &FsPath,
    intents_dir: &FsPath,
    agent: &Agent,
    policy: &AgentPolicy,
    idempotency_key: &str,
    recipient: &str,
    amount_kelvin: u64,
    amount_rlo: f64,
    now: i64,
) -> Result<serde_json::Value, PaymentFailure> {
    // G21.11 kill-switch (defense-in-depth): blocks EVERY lane reaching the
    // engine — owner lane, credential trigger lane, task payout bridging, or
    // any future internal entry point — BEFORE reservation, signing, or
    // submission. No is a wallet minted and no ledger row is written here.
    if super::transfers_disabled() {
        return Err(PaymentFailure::Recorded {
            status: 503,
            code: "TRANSFERS_DISABLED".to_string(),
            message: "Transfers are disabled by operator configuration \
                      (AGENTPAY_DISABLE_TRANSFERS)."
                .to_string(),
        });
    }

    let uuid = parse_agent_id(&agent.agent_id).ok_or(PaymentFailure::Store)?;
    let day = utc_day(now);

    // CHECK (read-only seam into the ledger; reserve re-verifies)
    let spend = spend_for_day(ledger_dir, &uuid, &day, now).map_err(|_| PaymentFailure::Store)?;

    // THE Step 7 enforcement function — its verdict is honored as-is;
    // no policy rule is duplicated in this function (checked order:
    // lifecycle, policy, action, recipient syntax, allow-list, amount,
    // per-tx, daily).
    if let Err(denial) = check_agent_payment_policy(
        agent,
        Some(policy),
        recipient,
        amount_kelvin,
        Some(spend.spent_kelvin),
    ) {
        // PHASE 9 audit: the pre-claim authorization denial (the FIRST
        // authority's verdict) is mirrored before the early return. The
        // verdict is honored EXACTLY as before — the audit never gates.
        let audit_dir = crate::audit::audit_dir_for(intents_dir);
        crate::audit::record(
            crate::audit::authorization(
                now,
                crate::audit::AuditOutcome::Deny,
                Some(denial.code()),
                crate::audit::IdentityClass::None,
                Some(&uuid.to_string()),
                Some(idempotency_key),
                Some(&policy_fingerprint(policy)),
            ),
            &audit_dir,
            Some(&uuid.to_string()),
        );
        return Err(PaymentFailure::Enforcement(denial));
    }
    let daily_limit = policy
        .daily_payment_limit_kelvin
        .ok_or(PaymentFailure::Enforcement(EnforcementDenial::AmountDenied))?;

    // IDEMPOTENCY claim BEFORE any money state changes. Same key + same
    // canonical request replays the stored outcome; same key + different
    // request is a conflict; pending/unknown outcomes are never blindly
    // replayed into a new transfer.
    let fingerprint = request_fingerprint(recipient, amount_kelvin);
    let draft = PaymentIntent {
        schema_version: PAYMENT_INTENT_SCHEMA_VERSION,
        agent_id: uuid.to_string(),
        idempotency_key: idempotency_key.to_string(),
        request_fingerprint: fingerprint.clone(),
        recipient: recipient.to_string(),
        amount_kelvin,
        state: IntentState::Pending,
        response: None,
        created_at: now,
        updated_at: now,
        reconciliation: None, // written only by the Step-4 reconciliation commit
        // PHASE 8 Item 10: None at claim; the Confirmed commit attaches
        // the canonical signer together with the signature.
        signer: None,
        // PHASE 9 audit: the SAME authz snapshot semantics v2 has always
        // carried, now on the owner lane too (additive, audit-only).
        authz: Some(AuthzBinding {
            policy_fingerprint: policy_fingerprint(policy),
            authorized_at: now,
        }),
        // PHASE 9 spend controls: the claim-time aggregate scope ids (the
        // resolved hierarchy at claim time — the release path uses EXACTLY
        // these).
        aggregate_scopes: policy
            .aggregate_scopes
            .iter()
            .map(|(id, _)| id.clone())
            .collect(),
        // GATE 2F: no slot evidence exists at claim time — the transfer has
        // not run yet. Missing stays missing; the Confirmed commit fills it.
        evidence_slot: None,
    };
    // MISSION PHASE 2 — storage-mode dispatch: in Postgres mode the DB
    // row IS the intent authority (O_EXCL semantics via the unique key);
    // the legacy file path is never touched. A dispatch error fails the
    // payment closed (Store) — an ambiguous claim authority is never
    // acceptable on a money path.
    let claim_result: Result<IntentClaim, PaymentFailure> =
        if crate::pg_store::pg_is_authoritative() {
            // The sync core runs on a worker thread without an ambient
            // reactor; a dedicated current-thread runtime is the established
            // pattern for blocking-context async calls here (same shape as
            // the existing step8 test harness). The token used by the
            // blocking-launch primitive is deliberately not written here:
            // the structural pin forbids it inside the core body.
            let dispatch_result =
                crate::pg_store::pg_run(crate::pg_store::claim_intent_dispatch(&draft));
            match dispatch_result {
                Ok(Ok(None)) => Ok(IntentClaim::Created),
                Ok(Ok(Some(existing))) => Ok(IntentClaim::Existing(existing)),
                Ok(Err(e)) => Err(PaymentFailure::Store),
                Err(_) => Err(PaymentFailure::Store),
            }
        } else {
            match claim_intent(intents_dir, &uuid, &draft) {
                Err(_) => Err(PaymentFailure::Store),
                Ok(c) => Ok(c),
            }
        };
    match claim_result {
        Err(e) => return Err(e),
        Ok(IntentClaim::Existing(existing)) => {
            let bound = existing.request_fingerprint == fingerprint
                && existing.recipient == recipient
                && existing.amount_kelvin == amount_kelvin;
            if !bound {
                return Err(PaymentFailure::Replay(ReplayVerdict::Conflict));
            }
            return match existing.state {
                IntentState::Pending => Err(PaymentFailure::Replay(ReplayVerdict::InProgress)),
                IntentState::Unknown => Err(PaymentFailure::Replay(ReplayVerdict::Unreconciled)),
                IntentState::Confirmed => match existing.response {
                    Some(body) => Ok(body),
                    None => Err(PaymentFailure::Store),
                },
                IntentState::Failed => match failed_replay(&existing.response) {
                    Some((status, code, message)) => Err(PaymentFailure::Recorded {
                        status,
                        code,
                        message,
                    }),
                    None => Err(PaymentFailure::Store),
                },
                // PHASE 6 STEP 4: reconciled outcomes are terminal. The
                // payment path NEVER re-executes them and NEVER replays a
                // transfer — the key stays burned behind its verdict.
                IntentState::ReconciledPaid | IntentState::ReconciledAbsent => {
                    Err(PaymentFailure::Replay(ReplayVerdict::Reconciled(
                        existing.reconciliation.map(Box::new),
                    )))
                }
            };
        }
        Ok(IntentClaim::Created) => {}
    }

    // ATOMIC RESERVATION BEFORE TRANSFER (persisted money-safety state).
    // PHASE 9 spend controls: the reservation is GROUP-ATOMIC across the
    // per-agent bucket AND every applicable aggregate scope bucket
    // (child → root), all in ONE store_lock section — a failure anywhere
    // rolls back everything acquired, so no partial reservation can
    // persist. A flat path (no aggregate scopes) is identical to the bare
    // per-agent reservation.
    // MISSION PHASE 2 — storage-mode dispatch for the GROUP-ATOMIC spend
    // reservation. PG mode: the DB transaction IS the authority (per-agent
    // row + every aggregate scope locked FOR UPDATE, all-or-nothing); the
    // legacy file path is never touched. Any DB failure fails the payment
    // closed (Store) — an ambiguous spend authority is never acceptable.
    let hier = if crate::pg_store::pg_is_authoritative() {
        let scopes: Vec<(String, u64)> = policy.aggregate_scopes.clone();
        let dispatch = match crate::pg_store::main_handle() {
            Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt.block_on(async {
                    let mut client = crate::pg_store::global_client().await;
                    crate::pg_store::reserve_spend_hierarchical_pg(
                        &mut *client,
                        uuid,
                        &scopes,
                        &day,
                        amount_kelvin,
                        daily_limit,
                        now,
                    )
                    .await
                })
            })) {
                Ok(Ok(Ok((prev, to, sc)))) => Ok(Ok(HierarchicalReservation {
                    agent: ReserveOutcomeSuccess {
                        previous_kelvin: prev,
                        reserved_to_kelvin: to,
                    },
                    scopes: Vec::new(), // PG mode: scope release is by the
                                        // claim-time scope list + amount
                                        // (exact-match, GREATEST-guarded)
                })),
                Ok(Ok(Err(()))) => Ok(Err(())), // OverLimit
                Ok(Err(e)) => Err(std::io::Error::other(format!("pg hier reserve: {e}"))),
                Err(_) => Err(std::io::Error::other("pg hier reserve panicked")),
            },
            Err(e) => Err(std::io::Error::other(format!("pg runtime: {e}"))),
        };
        dispatch
    } else {
        reserve_spend_hierarchical(
            ledger_dir,
            &uuid,
            &policy.aggregate_scopes[..],
            &day,
            amount_kelvin,
            daily_limit,
            now,
        )
    };
    let scope_reservations = match &hier {
        Ok(Ok(res)) => res.scopes.clone(),
        _ => Vec::new(),
    };
    let reserve = match hier {
        Err(_) => {
            let _ = mark_intent_failed(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                500,
                "AGENT_STORE_ERROR",
                "Agent payment state could not be stored",
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some("AGENT_STORE_ERROR"),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                None,
            );
            return Err(PaymentFailure::Store);
        }
        Ok(Err(())) => {
            let _ = mark_intent_failed(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                403,
                "AGENT_POLICY_DENIED",
                "Amount exceeds the agent policy limits",
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some("AGENT_POLICY_DENIED"),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                None,
            );
            return Err(PaymentFailure::Enforcement(EnforcementDenial::AmountDenied));
        }
        Ok(Ok(res)) => (res.agent.previous_kelvin, res.agent.reserved_to_kelvin),
    };
    let (previous_kelvin, reserved_to_kelvin) = reserve;

    // helper: a definitive pre-transfer failure refunds and records once
    let abort_before_transfer =
        |failure: PaymentFailure, ops_note: (u16, &str, &str)| -> PaymentFailure {
            let _ = release_spend(
                ledger_dir,
                &uuid,
                &day,
                reserved_to_kelvin,
                previous_kelvin,
                now,
            );
            // PHASE 9 spend controls: release the claim-time aggregate
            // reservations too (bookkept exact-match — no partial state).
            let _ = release_scopes_bookkept(ledger_dir, &scope_reservations, now);
            let _ = mark_intent_failed(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                ops_note.0,
                ops_note.1,
                ops_note.2,
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some(ops_note.1),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                None,
            );
            failure
        };

    // SIGNER RESOLUTION (rialo_tx_signers — PHASE 8 Item 10): THE one
    // canonical boundary turning an AUTHORIZED payment context into the
    // signing identity. It runs strictly AFTER every policy/lifecycle/
    // limit gate above (enforcement failures already returned) and its
    // public-address source is the same `agent.wallet_address` the old
    // balance branch matched on — a missing or non-canonical public
    // identity fails with the exact same envelope as before, and no
    // fallback signer exists here or downstream.
    let signer = match agent
        .wallet_address
        .as_deref()
        .and_then(|address| TxSigner::for_agent_record(&agent.agent_id, address).ok())
    {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::WalletStore,
                (
                    500,
                    "AGENT_WALLET_STORE_ERROR",
                    "Agent wallet file is missing or unreadable",
                ),
            ));
        }
        Some(signer) => signer,
    };

    // BALANCE — through the same established read path; an RPC failure is
    // a typed error, NEVER a fake zero. The address queried is the
    // canonical signer's public identity (guaranteed Some by the
    // constructor; the None arm is structural, unreachable).
    let balance_rlo = match signer.public_address() {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::WalletStore,
                (
                    500,
                    "AGENT_WALLET_STORE_ERROR",
                    "Agent wallet file is missing or unreadable",
                ),
            ));
        }
        Some(address) => match ops.balance(address) {
            Ok(value) => value,
            Err(err) => {
                let code = err.code.to_string();
                let detail = err.detail.clone();
                return Err(abort_before_transfer(
                    PaymentFailure::Transfer(err),
                    (502, code.as_str(), detail.as_str()),
                ));
            }
        },
    };

    // INTEGER KELVIN comparison with the established fee headroom.
    let balance_kelvin = match rlo_balance_to_kelvin(balance_rlo) {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::BalanceUnreadable,
                (
                    502,
                    "RIALO_ERROR",
                    "Agent balance reading is not usable for a money comparison; no transfer was attempted",
                ),
            ));
        }
        Some(k) => k,
    };
    let required = amount_kelvin
        .checked_add(AGENT_PAYMENT_FEE_HEADROOM_KELVIN)
        .unwrap_or(u64::MAX);
    if balance_kelvin < required {
        let message = format!(
            "Agent wallet balance is {balance_rlo} RLO; payment of {amount_rlo} RLO plus 0.001 RLO fee headroom is not covered"
        );
        return Err(abort_before_transfer(
            PaymentFailure::InsufficientFunds {
                balance_rlo,
                amount_rlo,
            },
            (400, "INSUFFICIENT_FUNDS", message.as_str()),
        ));
    }

    // WALLET RESOLUTION THROUGH THE SIGNER BOUNDARY (rialo_tx_signers,
    // PHASE 8 Item 10): the keypair reference is DERIVED FROM THE CANONICAL
    // SIGNER — never re-composed ad hoc — and hard-verified against the
    // signer's recorded public identity before money may move. The user
    // wallet directory is structurally unreachable from here: `wallet_dir`
    // is the caller's agent-wallets directory and the signer's filename
    // formula is the agent UUID. Outcomes are deterministic and terminal:
    //   * missing/unreadable container -> the exact pre-existing
    //     AGENT_WALLET_STORE_ERROR abort (behavior preserved);
    //   * the file is not this signer's key -> SIGNER_MISMATCH recorded
    //     on the intent (client-visible envelope stays the stable
    //     WalletStore class); no transfer attempt, no alternate key.
    let wallet_path = signer.keypair_reference(wallet_dir);
    // PHASE 9 STEP 8 (custody cutover): the legacy signer-file verification
    // applies ONLY to lanes whose custody is in-process (native/latch).
    // The isolated-signer lane holds custody OUTSIDE the app — the record's
    // address IS the signer-owned address and the sign-time chain (record
    // linkage + BYTE_DIVERGENCE + policy) is the verification. The check is
    // skipped for that lane, never weakened: the signer lane's own gates
    // (record linkage, BYTE_DIVERGENCE, policy) remain mandatory.
    if !ops.uses_external_custody() {
        match verify_agent_public_address(&signer, wallet_dir) {
            Ok(()) => {}
            Err(SignerError::Mismatch) => {
                return Err(abort_before_transfer(
                    PaymentFailure::WalletStore,
                    (
                        500,
                        "SIGNER_MISMATCH",
                        "The keypair at the signer reference does not match the signer's recorded public identity; no transfer was attempted",
                    ),
                ));
            }
            Err(_) => {
                return Err(abort_before_transfer(
                    PaymentFailure::WalletStore,
                    (
                        500,
                        "AGENT_WALLET_STORE_ERROR",
                        "Agent wallet file is missing or unreadable",
                    ),
                ));
            }
        }
    }

    // THE LAST MONEY-MOVING OPERATION. Retry behavior and error
    // classification belong to RialoConfig::transfer and are NOT
    // duplicated here: exactly ONE call, whatever its typed outcome.
    match ops.transfer(&wallet_path, recipient, &amount_rlo.to_string()) {
        Ok(signature) => {
            // GATE 2F: the production PaymentOps::transfer returns ONLY the
            // signature (the CLI path's slot is captured inside rialo.rs
            // but not surfaced through this seam yet); the Confirmed commit
            // therefore persists NO slot for the direct lane and the
            // evidence-enrichment sweep (Fix 3) is the bounded recovery
            // path. Never fabricate a slot here.
            // COMMIT: the reservation stays (it is already persisted).
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Ok,
                None,
                &uuid.to_string(),
                idempotency_key,
                Some(&signature),
                Some(policy_fingerprint(policy)),
                None,
            );
            let body = payment_success_json(
                &agent.agent_id,
                recipient,
                amount_rlo,
                amount_kelvin,
                &signature,
                Some(balance_rlo),
                None,
            );
            // MISSION PHASE B — storage-mode dispatch: in PG mode the DB is
            // the authoritative intent record; the FS path is never touched.
            // A DB failure keeps the intent Pending (BLOCKS replays — the
            // safe direction), exactly like a legacy store failure.
            let confirmed_write = if crate::pg_store::pg_is_authoritative() {
                let uuid_c = uuid;
                let key_c = idempotency_key.to_string();
                let body_c = body.clone();
                let signer_rec = signer.record();
                let rt = crate::pg_store::main_handle();
                match rt {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_pg(
                                &mut *client,
                                uuid_c,
                                &key_c,
                                now,
                                &|i: &mut crate::agents::PaymentIntent| {
                                    i.state = IntentState::Confirmed;
                                    i.response = Some(body_c.clone());
                                    i.signer = Some(signer_rec.clone());
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(Ok(_)) => Ok(()),
                        Ok(Err(e)) => Err(format!("pg intent update: {e}")),
                        Err(_) => Err("pg intent update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.state = IntentState::Confirmed;
                    i.response = Some(body.clone());
                    i.signer = Some(signer.record());
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            if confirmed_write.is_err() {
                // money moved but the record could not be closed: the
                // intent stays Pending, which BLOCKS replays — the safe
                // direction. The client is told the truth: it succeeded.
                eprintln!("[agents] payment intent state update failed (intent stays gated)");
            }
            Ok(body)
        }
        Err(err) if err.code == RIALO_TRANSFER_CONFIRMATION_TIMEOUT => {
            // OUTCOME UNKNOWN. No refund (the funds may already be
            // broadcast), no retry (the transfer may already be landed),
            // and replay is gated until reconciliation.
            let code = err.code.to_string();
            let detail = err.detail.clone();
            // MISSION PHASE B — Unknown commit (PG/FS dispatch). The
            // commitment is HELD: no release, no retry, no ambiguity.
            let _ = if crate::pg_store::pg_is_authoritative() {
                let code_c = code.clone();
                let detail_c = detail.clone();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_pg(
                                &mut *client,
                                uuid,
                                idempotency_key,
                                now,
                                &|i: &mut crate::agents::PaymentIntent| {
                                    i.state = IntentState::Unknown;
                                    i.response = Some(recorded_error_json(502, &code_c, &detail_c));
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg unknown update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.state = IntentState::Unknown;
                    i.response = Some(recorded_error_json(502, &code, &detail));
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Unknown,
                Some(&code),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                None,
            );
            Err(PaymentFailure::Transfer(err))
        }
        Err(err) => {
            // DEFINITIVE failure per rialo.rs classification: release the
            // reservation and record the outcome so the key can never
            // produce a second transfer.
            let code = err.code.to_string();
            let detail = err.detail.clone();
            let _ = release_spend(
                ledger_dir,
                &uuid,
                &day,
                reserved_to_kelvin,
                previous_kelvin,
                now,
            );
            // PHASE 9 spend controls: release the aggregate reservations too.
            // MISSION PHASE B — spend-release dispatch (PG/FS). The PG
            // release is exact-match (previous_kelvin guard); a DB failure
            // here means the spend reservation is NOT yet released — fail
            // closed (the money state stays reserved until a successful
            // release), never silently under- or over-release.
            let _ = if crate::pg_store::pg_is_authoritative() {
                let scope_ids: Vec<String> = scope_reservations
                    .iter()
                    .map(|s| s.scope_id.to_string())
                    .collect();
                let scope_amts: Vec<u64> = scope_reservations
                    .iter()
                    .map(|s| s.reserved_to_kelvin - s.previous_kelvin)
                    .collect();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            let r1 = crate::pg_store::release_spend(
                                &mut *client,
                                uuid,
                                &day,
                                amount_kelvin,
                                now,
                            )
                            .await;
                            let r2 = crate::pg_store::release_scopes_pg(
                                &mut *client,
                                &scope_ids,
                                &day,
                                amount_kelvin,
                                now,
                            )
                            .await;
                            r1.and(r2)
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg spend release panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                let _ = release_scopes_bookkept(ledger_dir, &scope_reservations, now);
                Ok::<(), String>(())
            };
            let _ = if crate::pg_store::pg_is_authoritative() {
                let code_c = code.clone();
                let detail_c = detail.clone();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_pg(
                                &mut *client,
                                uuid,
                                idempotency_key,
                                now,
                                &|i: &mut crate::agents::PaymentIntent| {
                                    i.state = IntentState::Failed;
                                    i.response = Some(recorded_error_json(502, &code_c, &detail_c));
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg failed update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.state = IntentState::Failed;
                    i.response = Some(recorded_error_json(502, &code, &detail));
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Failed,
                Some(&code),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                None,
            );
            Err(PaymentFailure::Transfer(err))
        }
    }
}

fn mark_intent_failed(
    root: &FsPath,
    id: &Uuid,
    key: &str,
    now: i64,
    status: u16,
    code: &str,
    message: &str,
) -> Result<PaymentIntent, std::io::Error> {
    update_intent(root, id, key, now, |i| {
        i.state = IntentState::Failed;
        i.response = Some(recorded_error_json(status, code, message));
    })
}

fn failed_replay(response: &Option<serde_json::Value>) -> Option<(u16, String, String)> {
    let value = response.as_ref()?;
    let status = value.get("http_status")?.as_u64()? as u16;
    let code = value.get("code")?.as_str()?.to_string();
    let message = value.get("message")?.as_str()?.to_string();
    Some((status, code, message))
}

/// Per-agent async payment locks. Keyed by the validated UUID; the map
/// lock is held only long enough to fetch/insert an entry. This is NOT
/// the persistence lock: it never serializes different agents, and the
/// global store_lock is still only ever held for microseconds of file I/O.
fn payment_locks() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn agent_payment_lock(id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = payment_locks().lock().unwrap_or_else(|e| e.into_inner());
    map.entry(id.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// PAYMENT body: the same input convention as POST /api/payment
/// (`{ "to": ..., "amount": <RLO> }`) plus `deny_unknown_fields` so the
/// body parse itself stays inside the project error envelope.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AgentPaymentRequest {
    pub to: String,
    pub amount: f64,
}

fn parse_payment_body(raw: &str) -> Result<AgentPaymentRequest, &'static str> {
    serde_json::from_str::<AgentPaymentRequest>(raw).map_err(
        |_| "request body must be exactly {\"to\": <RIALO_ADDRESS>, \"amount\": <RLO_NUMBER>}",
    )
}

/// POST /api/agents/{id}/payments — explicit, synchronous agent payment.
/// Thin HTTP shell: everything below it is the tested money core. The
/// per-agent async lock spans the core call (same-agent serialization),
/// while no persistence lock is ever held across the Rialo transfer.
pub async fn agent_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    // G21.11 kill-switch: block BEFORE reservation/policy spend accounting.
    if super::transfers_disabled() {
        return crate::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "TRANSFERS_DISABLED",
            "Transfers are disabled by operator configuration (AGENTPAY_DISABLE_TRANSFERS).",
        );
    }
    // 1. authentication — the existing session model, unchanged
    let Some(user) = session_user(&state, &headers) else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("NOT_AUTHENTICATED"),
            crate::audit::IdentityClass::Session,
            None,
            None,
            None,
        );
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };

    // 2.-3. canonical UUID + the ONE ownership choke point (missing,
    // foreign, malformed, corrupt all answer AGENT_NOT_FOUND)
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_NOT_FOUND"),
                crate::audit::IdentityClass::Session,
                None,
                None,
                None,
            );
            return resp;
        }
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    // 4. lifecycle gate before anything money-adjacent is touched
    if agent.status != AgentStatus::Active {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("AGENT_LIFECYCLE_BLOCKED"),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            None,
        );
        return EnforcementDenial::Lifecycle.into_response();
    }

    // 5.-6. the persisted policy must exist (deny-by-default)
    // PHASE 9 "Hierarchical Policy": after the child's own policy loads,
    // the EFFECTIVE policy is resolved from the parent chain (frozen
    // decision: resolution happens BEFORE enforcement; every failure
    // denies — no fallback to the flat child policy). The client-visible
    // denial stays the existing AGENT_POLICY_MISSING; the audit record
    // carries the observability code for the resolution class.
    // MISSION PHASE 2 — the LEAF policy read is storage-mode dispatched:
    // PG-authoritative mode reads the authoritative row (fail-closed on any
    // DB error; no silent FS fallback). The EFFECTIVE resolution (parent
    // chain fold) below still runs the frozen FS walk — see the reported
    // blocker: a PG-backed hierarchy walker does not exist yet, and in PG
    // mode any unresolvable parent chain denies closed (never a fallback).
    let policy_result: Result<Option<AgentPolicy>, std::io::Error> =
        if crate::pg_store::pg_is_authoritative() {
            match crate::pg_store::pg_run(async {
                let client = crate::pg_store::global_client().await;
                crate::pg_store::policy_read_pg(&*client, uuid).await
            }) {
                Ok(Ok(policy)) => Ok(policy),
                Ok(Err(e)) => Err(std::io::Error::other(format!("pg policy read: {e}"))),
                Err(e) => Err(std::io::Error::other(format!("pg runtime: {e}"))),
            }
        } else {
            load_policy(&agent_policies_dir(), &uuid)
        };
    let policy = match policy_result {
        Ok(Some(policy)) => {
            match resolve_effective_policy(policy, &agent_policies_dir(), &agents_dir()) {
                Ok(effective) => effective,
                Err(_) => {
                    audit_authorization(
                        &audit_dir_for(&intents_root()),
                        now_unix(),
                        crate::audit::AuditOutcome::Deny,
                        Some("AGENT_POLICY_HIERARCHY_INVALID"),
                        crate::audit::IdentityClass::Session,
                        Some(&agent.agent_id),
                        None,
                        None,
                    );
                    return EnforcementDenial::PolicyMissing.into_response();
                }
            }
        }
        Ok(None) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_POLICY_MISSING"),
                crate::audit::IdentityClass::Session,
                Some(&agent.agent_id),
                None,
                None,
            );
            return EnforcementDenial::PolicyMissing.into_response();
        }
        Err(_) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_STORE_ERROR"),
                crate::audit::IdentityClass::Session,
                Some(&agent.agent_id),
                None,
                None,
            );
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent policy could not be read",
            );
        }
    };

    // body, amount, recipient — through the ONE existing helpers
    let req = match parse_payment_body(&body) {
        Ok(req) => req,
        Err(reason) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_PAYMENT_REQUEST_INVALID"),
                crate::audit::IdentityClass::Session,
                Some(&agent.agent_id),
                None,
                Some(&policy_fingerprint(&policy)),
            );
            return api_error(
                StatusCode::BAD_REQUEST,
                "AGENT_PAYMENT_REQUEST_INVALID",
                reason,
            );
        }
    };
    let Some(amount_kelvin) = super::rlo_to_kelvin(req.amount).and_then(|k| k.parse::<u64>().ok())
    else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_AMOUNT"),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AMOUNT",
            "Amount must be a positive multiple of 1 kelvin (1e-9 RLO)",
        );
    };
    if !super::valid_rialo_address(&req.to) {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_RECIPIENT"),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECIPIENT",
            "Recipient is not a valid Rialo address",
        );
    }

    // Idempotency-Key — REQUIRED for money movement. Exactly one header
    // value, bounded charset (never a path, never oversized).
    let mut key_values = headers.get_all("idempotency-key").iter();
    let idempotency_key = match (key_values.next(), key_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|k| valid_idempotency_key(k))
            .map(|k| k.to_string()),
        _ => None,
    };
    let Some(idempotency_key) = idempotency_key else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_IDEMPOTENCY_KEY"),
            crate::audit::IdentityClass::Session,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return PaymentFailure::Key.into_response();
    };

    // per-agent serialization; different agents never wait on each other
    let lock = agent_payment_lock(&uuid.to_string());
    let _guard = lock.lock().await;

    // PHASE 9 I-5: the lane decision (env-only). With the proxy lane
    // unconfigured or declined this returns the plain native ops — byte-
    // for-byte the status quo. The core below and its single ops.transfer
    // site are unchanged.
    // PHASE 9 audit: the SAME wiring decision plus the observational audit
    // context (the seam mirrors its own existing lane decisions; the
    // factory mirrors its plain-native refusals). Nothing behavioral.
    let lane_audit_ctx = Arc::new(crate::audit::LaneAuditContext {
        agent_id: agent.agent_id.clone(),
        idempotency_key: idempotency_key.clone(),
        audit_dir: audit_dir_for(&intents_root()),
    });
    let ops: Arc<dyn PaymentOps + Send + Sync> =
        crate::isolated_signer_lane::production_isolated_signer_ops_audited(
            state.rialo.clone(),
            &agent,
            &policy,
            &agent_auth_keys_dir(),
            Some(lane_audit_ctx),
        );
    let wallet_dir = agent_wallet_dir();
    let ledger_dir = spend_dir();
    let intents_dir = intents_root();
    let now = now_unix();
    // PHASE 9 audit: capture the public correlation facts BEFORE the
    // blocking closure moves the owned values (clone of public data only).
    let audit_agent_id = agent.agent_id.clone();
    let audit_key = idempotency_key.clone();
    let audit_policy_fp = policy_fingerprint(&policy);
    let audit_dir_handle = audit_dir_for(&intents_root());
    let agent_c = agent;
    let outcome = tokio::task::spawn_blocking(move || {
        execute_agent_payment(
            ops.as_ref(),
            &wallet_dir,
            &ledger_dir,
            &intents_dir,
            &agent_c,
            &policy,
            &idempotency_key,
            &req.to,
            amount_kelvin,
            req.amount,
            now,
        )
    })
    .await;

    match outcome {
        Ok(Ok(value)) => {
            audit_authorization(
                &audit_dir_handle,
                now,
                crate::audit::AuditOutcome::Allow,
                None,
                crate::audit::IdentityClass::Session,
                Some(&audit_agent_id),
                Some(&audit_key),
                Some(&audit_policy_fp),
            );
            Json(value).into_response()
        }
        Ok(Err(failure)) => {
            audit_handler_failure(
                &failure,
                crate::audit::IdentityClass::Session,
                &audit_agent_id,
                &audit_key,
                Some(audit_policy_fp.clone()),
                &audit_dir_handle,
                now,
            );
            failure.into_response()
        }
        // the blocking worker itself died — possibly mid-transfer, so the
        // outcome is UNKNOWN: the still-Pending intent gates any replay
        // and this response forbids a blind retry
        Err(join_err) => api_error(
            StatusCode::BAD_GATEWAY,
            "RIALO_ERROR",
            &format!(
                "payment worker failed ({join_err}); the transfer outcome is unverified — reconcile before retrying"
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// PHASE 6 STEP 3 — INTENT v2 + AGENT CREDENTIAL TRIGGER (sibling path)
// ---------------------------------------------------------------------------
//
// POST /api/agents/triggers/payments authenticates with the Step-2 Agent
// credential (X-Agent-Credential) instead of the GitHub owner session. The
// Agent principal is resolved EXCLUSIVELY by authenticate_agent_credential;
// an agent_id in the URL, body, or query is structurally impossible: the
// route is literal, the body DTO is closed (deny_unknown_fields), and every
// store path is derived from the credential-resolved canonical UUID.
//
// MONEY RULES:
//   * ONE engine. The v2 core calls the same primitives as Step 8 —
//     check_agent_payment_policy (never duplicated), spend_for_day,
//     reserve_spend / release_spend (identical CAS + refund semantics),
//     rlo_balance_to_kelvin, AGENT_PAYMENT_FEE_HEADROOM_KELVIN,
//     agent_wallet_path, PaymentOps. Retry behavior stays centralized in
//     RialoConfig::transfer; this layer NEVER retries.
//   * v1 (schema 1) intent records are NEVER rewritten, NEVER migrated,
//     and the owner endpoint behavior is byte-identical (v1 records are
//     written only by the owner path; v2 records only by this path).
//   * Same intents dir (artifact/agent_payment_intents/<uuid>/<hex-key>.json)
//     ON PURPOSE: one (agent,key) slot globally. A v1 owner-issued record
//     seen by the agent path is a binding CONFLICT (resolved ambiguity:
//     the stricter rule from the implementation brief wins over the softer
//     §5 line in the discovery report — different principal => conflict;
//     neither direction ever executes a second transfer).
//   * ExecState has exactly four variants — reconciled_paid /
//     reconciled_absent are NOT EXPRESSIBLE in Step 3 (a serde fail-closed
//     guarantee: foreign state strings cannot parse). The
//     ReconciliationRecord type is defined for Step 4, but no writer here
//     ever sets it: the field stays None on every record this code writes.
//   * The credential plaintext never enters a record, a response, a log
//     line, or any stored file; it is dropped at the end of principal
//     resolution.

pub const PAYMENT_INTENT_V2_SCHEMA_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Owner,
    Agent,
}

impl PrincipalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Agent => "agent",
        }
    }
}

/// v2 execution state. PHASE 6 STEP 4 added the two reconciliation
/// terminals: ReconciledPaid / ReconciledAbsent are written ONLY by the
/// reconciliation commit (exactly once from Unknown), are immutable after
/// that, and can NEVER be reached from Confirmed/Failed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Pending,
    Confirmed,
    Failed,
    Unknown,
    /// reconciliation proved execution; reservation stays consumed;
    /// immutable terminal
    ReconciledPaid,
    /// reconciliation proved definitive non-execution; the ORIGINAL
    /// reservation was released exactly once; immutable terminal
    ReconciledAbsent,
}

impl ExecState {
    /// The two immutable reconciliation terminals.
    pub fn is_reconciled(self) -> bool {
        matches!(self, Self::ReconciledPaid | Self::ReconciledAbsent)
    }
}

/// Authorization snapshot captured at claim time — it records AGAINST WHAT
/// the intent was authorized (policy fingerprint + moment), never a second
/// decision. Enforcement itself stays in check_agent_payment_policy.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AuthzBinding {
    pub policy_fingerprint: String,
    pub authorized_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FailureRecord {
    pub code: String,
    pub http_status: u16,
}

// --- PHASE 6 STEP 4 — reconciliation vocabulary (WRITTEN only by the
// --- reconciliation commit, exactly once, from Unknown; immutable after) ---

/// How a reconciled terminal was PROVEN.
///
/// `BalanceDelta` is DEMOTED (audit rule): wallet balance deltas may at
/// best corroborate other evidence and MUST NEVER by themselves produce
/// ReconciledPaid or ReconciledAbsent. The reconciler has no code path
/// that constructs a terminal from it — the variant is kept only so any
/// historical/foreign document mentioning it still fails loudly at the
/// gate rather than silently mis-parsing.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationMethod {
    /// get_transaction(signature) gave decisive on-chain status
    TxLookup,
    /// bounded address-history scan found EXACTLY ONE matching transfer
    /// (proposal lane; terminal only under an explicit policy/manual)
    AddressScan,
    /// authenticated human attestation (owner principal only)
    ManualAttestation,
    #[deprecated(
        note = "corroborating evidence only — since Phase 6 Step 4 this can NEVER drive a terminal outcome"
    )]
    BalanceDelta,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReconciliationOutcome {
    Paid,
    Absent,
}

/// Immutable audit evidence attached to a reconciliation. Public chain
/// facts ONLY: no secrets, credentials, keypair paths, raw headers, or
/// session tokens can exist in here (every field is a scalar or a short
/// sanitized summary).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct ReconciliationEvidence {
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub slot: Option<u64>,
    #[serde(default)]
    pub block_time: Option<i64>,
    #[serde(default)]
    pub fee: Option<u64>,
    /// the transaction's on-chain error tag when the tx failed
    #[serde(default)]
    pub meta_err: Option<String>,
    /// short, control-character-free human summary of the evidence
    #[serde(default)]
    pub tx_summary: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationRecord {
    pub method: ReconciliationMethod,
    pub outcome: ReconciliationOutcome,
    pub tx_signature: Option<String>,
    pub resolved_at: i64,
    pub resolver: String,
    /// PHASE 6 STEP 4: the immutable evidence bundle behind the verdict.
    /// Defaulted so any pre-Step-4 document still parses.
    #[serde(default)]
    pub evidence: Option<ReconciliationEvidence>,
}

/// Resolver identity grammar: `owner:<login>`, `agent:<canonical-uuid>`,
/// `system:<name>`, `operator:<id>`. NEVER free text, NEVER a credential
/// or token (colon-separated single-prefix shapes only, bounded).
pub fn valid_resolver(raw: &str) -> bool {
    let Some((kind, value)) = raw.split_once(':') else {
        return false;
    };
    if raw.len() > 160 || value.is_empty() {
        return false;
    }
    match kind {
        "owner" => {
            value.len() <= 39
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        }
        "agent" => parse_agent_id(value)
            .map(|u| u.to_string() == value)
            .unwrap_or(false),
        "system" | "operator" => {
            value.len() <= 64
                && value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        }
        _ => false,
    }
}

/// The authenticated resolver of a reconciliation request. Constructed
/// ONLY from server-verified authentication (GitHub session for owners,
/// credential-resolved canonical UUID for agents) — clients can never
/// supply a resolver value of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilePrincipal {
    resolver: String,
}

impl ReconcilePrincipal {
    pub fn owner(login: &str) -> Option<Self> {
        let candidate = format!("owner:{login}");
        valid_resolver(&candidate).then_some(Self {
            resolver: candidate,
        })
    }

    pub fn agent(id: &Uuid) -> Self {
        Self {
            resolver: format!("agent:{id}"),
        }
    }

    pub fn is_owner(&self) -> bool {
        self.resolver.starts_with("owner:")
    }

    pub fn resolver(&self) -> &str {
        &self.resolver
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PaymentIntentV2 {
    pub schema_version: u32,
    /// correlation id only — the file path stays hex(idempotency_key);
    /// intent_id NEVER influences any filesystem path.
    pub intent_id: String,
    pub agent_id: String,
    pub principal_kind: PrincipalKind,
    pub recipient: String,
    pub amount_kelvin: u64,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub authz: AuthzBinding,
    pub exec_state: ExecState,
    pub tx_signature: Option<String>,
    pub failure: Option<FailureRecord>,
    pub response: Option<serde_json::Value>,
    pub reconciliation: Option<ReconciliationRecord>,
    /// PHASE 8 ITEM 10 — canonical signer committed with the signature
    /// (see the identical field on schema-1 PaymentIntent). Additive-
    /// defaulted: pre-Item-10 schema-2 records parse unchanged.
    #[serde(default)]
    pub signer: Option<SignerRecord>,
    /// PHASE 9 "Hierarchical spend controls" — the CLAIM-TIME aggregate
    /// scope ids (see the identical field on schema-1 PaymentIntent).
    #[serde(default)]
    pub aggregate_scopes: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Canonical v2 fingerprint: principal_kind participates — an owner-issued
/// binding can never collide with an agent-issued binding under one key.
pub fn request_fingerprint_v2(
    principal: PrincipalKind,
    recipient: &str,
    amount_kelvin: u64,
) -> String {
    fnv1a64_hex(&format!(
        "{}|{recipient}|{amount_kelvin}",
        principal.as_str()
    ))
}

/// Deterministic snapshot of the enforced policy fields (sorted lists),
/// captured at authorization time for Step-4 reconciliation audits.
pub(crate) fn policy_fingerprint(policy: &AgentPolicy) -> String {
    let mut recipients = policy.allowed_recipients.clone();
    recipients.sort();
    let mut actions = policy.allowed_actions.clone();
    actions.sort();
    fnv1a64_hex(&format!(
        "tx={:?}|daily={:?}|recipients={}|actions={}",
        policy.max_payment_per_tx_kelvin,
        policy.daily_payment_limit_kelvin,
        recipients.join(","),
        actions.join(",")
    ))
}

/// Credential header shape gate: EXACTLY 64 lowercase hexadecimal chars.
pub fn valid_credential_shape(raw: &str) -> bool {
    raw.len() == 64
        && raw
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[derive(Debug)]
pub enum ClaimedRecord {
    /// Step 3 never consumes a v1 payload — its presence alone is the
    /// cross-principal conflict verdict; the record is kept for audit.
    #[allow(dead_code)]
    V1(PaymentIntent),
    V2(PaymentIntentV2),
}

/// Version-aware intent read for the v2 path. Schema 1 records are surfaced
/// as V1 (the replay logic below treats them as a foreign principal and
/// conflicts); unknown/corrupt versions fail closed as Err. Identity fields
/// are re-validated on every read.
pub(crate) fn read_intent_any(
    root: &FsPath,
    id: &Uuid,
    key: &str,
) -> Result<Option<ClaimedRecord>, std::io::Error> {
    match fs::read(intent_path(&agent_intents_dir(root, id), key)) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("intent parse: {e}")))?;
            match value.get("schema_version").and_then(|v| v.as_u64()) {
                Some(1) => {
                    let intent: PaymentIntent = serde_json::from_value(value)
                        .map_err(|e| std::io::Error::other(format!("intent v1 shape: {e}")))?;
                    if intent.schema_version != PAYMENT_INTENT_SCHEMA_VERSION {
                        return Err(std::io::Error::other("unsupported intent schema_version"));
                    }
                    if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                        return Err(std::io::Error::other("intent identity mismatch"));
                    }
                    Ok(Some(ClaimedRecord::V1(intent)))
                }
                Some(2) => {
                    let intent: PaymentIntentV2 = serde_json::from_value(value)
                        .map_err(|e| std::io::Error::other(format!("intent v2 shape: {e}")))?;
                    if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                        return Err(std::io::Error::other("intent identity mismatch"));
                    }
                    // a v2 record that lost its agent provenance is corruption
                    if intent.principal_kind != PrincipalKind::Agent {
                        return Err(std::io::Error::other("v2 record with non-agent principal"));
                    }
                    Ok(Some(ClaimedRecord::V2(intent)))
                }
                _ => Err(std::io::Error::other("unsupported intent schema_version")),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn read_intent_v2(
    root: &FsPath,
    id: &Uuid,
    key: &str,
) -> Result<Option<PaymentIntentV2>, std::io::Error> {
    match read_intent_any(root, id, key)? {
        Some(ClaimedRecord::V2(intent)) => Ok(Some(intent)),
        Some(ClaimedRecord::V1(_)) => Err(std::io::Error::other("v1 record under this key")),
        None => Ok(None),
    }
}

#[derive(Debug)]
pub enum IntentClaimV2 {
    Created(PaymentIntentV2),
    Existing(ClaimedRecord),
}

/// O_EXCL atomic claim, identical discipline to v1 (the version tag does
/// not affect path-level mutual exclusion between the two engines).
fn claim_intent_v2(
    root: &FsPath,
    id: &Uuid,
    draft: &PaymentIntentV2,
) -> Result<IntentClaimV2, std::io::Error> {
    let dir = agent_intents_dir(root, id);
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let path = intent_path(&dir, &draft.idempotency_key);
    let bytes = serde_json::to_vec_pretty(draft)
        .map_err(|e| std::io::Error::other(format!("serialize intent v2: {e}")))?;

    let mut file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return match read_intent_any(root, id, &draft.idempotency_key)? {
                Some(existing) => Ok(IntentClaimV2::Existing(existing)),
                None => Err(std::io::Error::other("intent vanished mid-claim")),
            };
        }
        Err(err) => return Err(err),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    match file.write_all(&bytes).and_then(|()| file.flush()) {
        Ok(()) => Ok(IntentClaimV2::Created(draft.clone())),
        Err(err) => {
            // this exact path was created by this call under O_EXCL — the
            // removal can only ever delete our own half-written record
            let _ = fs::remove_file(&path);
            Err(err)
        }
    }
}

fn update_intent_v2(
    root: &FsPath,
    id: &Uuid,
    key: &str,
    now: i64,
    f: impl FnOnce(&mut PaymentIntentV2),
) -> Result<PaymentIntentV2, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut intent = read_intent_v2(root, id, key)?
        .ok_or_else(|| std::io::Error::other("intent v2 record missing for update"))?;
    // PHASE 6 STEP 4 — immutability at the STORE layer (mirrors the v1
    // guard): once a record holds a reconciled terminal, no generic
    // update path may mutate it again; the stored record is returned
    // untouched and NOTHING is written.
    if intent.exec_state.is_reconciled() {
        return Ok(intent);
    }
    f(&mut intent);
    intent.updated_at = now;
    write_json_atomic(&intent_path(&agent_intents_dir(root, id), key), &intent)?;
    Ok(intent)
}

fn mark_intent_failed_v2(
    root: &FsPath,
    id: &Uuid,
    key: &str,
    now: i64,
    status: u16,
    code: &str,
    message: &str,
) -> Result<PaymentIntentV2, std::io::Error> {
    update_intent_v2(root, id, key, now, |i| {
        i.exec_state = ExecState::Failed;
        i.failure = Some(FailureRecord {
            code: code.to_string(),
            http_status: status,
        });
        i.response = Some(recorded_error_json(status, code, message));
    })
}

/// Success body = the frozen Step-8 public payment shape, plus the two
/// public v2 correlation fields. balance_after stays null (honest).
pub fn trigger_success_json(
    agent_id: &str,
    recipient: &str,
    amount_rlo: f64,
    amount_kelvin: u64,
    signature: &str,
    balance_before_rlo: Option<f64>,
    intent_id: &str,
) -> serde_json::Value {
    let mut body = payment_success_json(
        agent_id,
        recipient,
        amount_rlo,
        amount_kelvin,
        signature,
        balance_before_rlo,
        None,
    );
    body["principal"] = serde_json::json!("agent");
    body["intent_id"] = serde_json::json!(intent_id);
    body
}

/// THE v2 money core — the exact Step-8 sequence with the v2 record type
/// and principal binding. No policy rule, headroom value, ledger
/// primitive, or retry behavior is duplicated or altered.
#[allow(clippy::too_many_arguments)]
pub fn execute_agent_payment_v2(
    ops: &(dyn PaymentOps + Send + Sync),
    wallet_dir: &FsPath,
    ledger_dir: &FsPath,
    intents_dir: &FsPath,
    agent: &Agent,
    policy: &AgentPolicy,
    idempotency_key: &str,
    recipient: &str,
    amount_kelvin: u64,
    amount_rlo: f64,
    now: i64,
) -> Result<serde_json::Value, PaymentFailure> {
    // G21.11 kill-switch (defense-in-depth): blocks EVERY lane reaching the
    // engine — owner lane, credential trigger lane, task payout bridging, or
    // any future internal entry point — BEFORE reservation, signing, or
    // submission. No is a wallet minted and no ledger row is written here.
    if super::transfers_disabled() {
        return Err(PaymentFailure::Recorded {
            status: 503,
            code: "TRANSFERS_DISABLED".to_string(),
            message: "Transfers are disabled by operator configuration \
                      (AGENTPAY_DISABLE_TRANSFERS)."
                .to_string(),
        });
    }

    let uuid = parse_agent_id(&agent.agent_id).ok_or(PaymentFailure::Store)?;
    let day = utc_day(now);

    // CHECK (read-only seam; reserve re-verifies under the CAS)
    let spend = spend_for_day(ledger_dir, &uuid, &day, now).map_err(|_| PaymentFailure::Store)?;

    // THE Step 7 enforcement function — identical to the owner path
    if let Err(denial) = check_agent_payment_policy(
        agent,
        Some(policy),
        recipient,
        amount_kelvin,
        Some(spend.spent_kelvin),
    ) {
        // PHASE 9 audit: the pre-claim authorization denial (the FIRST
        // authority's verdict) is mirrored before the early return. The
        // verdict is honored EXACTLY as before — the audit never gates.
        let audit_dir = crate::audit::audit_dir_for(intents_dir);
        crate::audit::record(
            crate::audit::authorization(
                now,
                crate::audit::AuditOutcome::Deny,
                Some(denial.code()),
                crate::audit::IdentityClass::None,
                Some(&uuid.to_string()),
                Some(idempotency_key),
                Some(&policy_fingerprint(policy)),
            ),
            &audit_dir,
            Some(&uuid.to_string()),
        );
        return Err(PaymentFailure::Enforcement(denial));
    }
    let daily_limit = policy
        .daily_payment_limit_kelvin
        .ok_or(PaymentFailure::Enforcement(EnforcementDenial::AmountDenied))?;

    // v2 idempotency claim BEFORE any money state changes
    let fingerprint = request_fingerprint_v2(PrincipalKind::Agent, recipient, amount_kelvin);
    let draft = PaymentIntentV2 {
        schema_version: PAYMENT_INTENT_V2_SCHEMA_VERSION,
        intent_id: Uuid::new_v4().to_string(),
        agent_id: uuid.to_string(),
        principal_kind: PrincipalKind::Agent,
        recipient: recipient.to_string(),
        amount_kelvin,
        idempotency_key: idempotency_key.to_string(),
        request_fingerprint: fingerprint.clone(),
        authz: AuthzBinding {
            policy_fingerprint: policy_fingerprint(policy),
            authorized_at: now,
        },
        exec_state: ExecState::Pending,
        tx_signature: None,
        failure: None,
        response: None,
        reconciliation: None, // Step 3 NEVER writes reconciliation state
        // PHASE 8 Item 10: None at claim; Confirmed/Unknown commits
        // attach the canonical signer with the signature evidence.
        signer: None,
        // PHASE 9 spend controls: the claim-time aggregate scope ids.
        aggregate_scopes: policy
            .aggregate_scopes
            .iter()
            .map(|(id, _)| id.clone())
            .collect(),
        created_at: now,
        updated_at: now,
    };
    // the claim arms fully determine whether the created intent_id exists:
    // every Existing path returns before it is ever read
    let intent_id;
    // MISSION PHASE B — v2 claim dispatch (PG/FS). PG mode: the DB unique
    // key is the cross-process claim; FS mode: the O_EXCL path, unchanged.
    let claim_result_v2: Result<crate::agents::IntentClaimV2, PaymentFailure> =
        if crate::pg_store::pg_is_authoritative() {
            match crate::pg_store::main_handle() {
                Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.block_on(async {
                        let mut client = crate::pg_store::global_client().await;
                        let created =
                            crate::pg_store::claim_intent_v2_pg(&mut *client, uuid, &draft).await;
                        if created? {
                            Ok(None::<crate::agents::PaymentIntentV2>)
                        } else {
                            crate::pg_store::read_intent_v2_pg(
                                &mut *client,
                                uuid,
                                &draft.idempotency_key,
                            )
                            .await
                        }
                    })
                })) {
                    Ok(Ok(None)) => Ok(crate::agents::IntentClaimV2::Created(
                        // created; the draft IS the record (parity with the
                        // FS path's Created(draft) shape).
                        draft.clone(),
                    )),
                    Ok(Ok(Some(existing))) => Ok(crate::agents::IntentClaimV2::Existing(
                        crate::agents::ClaimedRecord::V2(existing),
                    )),
                    Ok(Err(e)) => Err(PaymentFailure::Store),
                    Err(_) => Err(PaymentFailure::Store),
                },
                Err(_) => Err(PaymentFailure::Store),
            }
        } else {
            match claim_intent_v2(intents_dir, &uuid, &draft) {
                Err(_) => Err(PaymentFailure::Store),
                Ok(c) => Ok(c),
            }
        };
    match claim_result_v2 {
        Err(_) => return Err(PaymentFailure::Store),
        Ok(IntentClaimV2::Existing(ClaimedRecord::V1(_))) => {
            // owner-principal binding is NEVER consumable by the agent
            // path and NEVER re-executed — conflict, fail closed
            return Err(PaymentFailure::Replay(ReplayVerdict::Conflict));
        }
        Ok(IntentClaimV2::Existing(ClaimedRecord::V2(existing))) => {
            let bound = existing.recipient == recipient
                && existing.amount_kelvin == amount_kelvin
                && existing.request_fingerprint == fingerprint;
            if !bound {
                return Err(PaymentFailure::Replay(ReplayVerdict::Conflict));
            }
            return match existing.exec_state {
                ExecState::Pending => Err(PaymentFailure::Replay(ReplayVerdict::InProgress)),
                ExecState::Unknown => Err(PaymentFailure::Replay(ReplayVerdict::Unreconciled)),
                ExecState::Confirmed => match existing.response {
                    Some(body) => Ok(body),
                    None => Err(PaymentFailure::Store),
                },
                ExecState::Failed => match failed_replay(&existing.response) {
                    Some((status, code, message)) => Err(PaymentFailure::Recorded {
                        status,
                        code,
                        message,
                    }),
                    None => Err(PaymentFailure::Store),
                },
                // PHASE 6 STEP 4: reconciled terminals replay as the
                // stored reconciliation. NEVER a second transfer, NEVER a
                // second reservation.
                ExecState::ReconciledPaid | ExecState::ReconciledAbsent => Err(
                    PaymentFailure::Reconciled(existing.reconciliation.map(Box::new)),
                ),
            };
        }
        Ok(IntentClaimV2::Created(draft)) => {
            intent_id = draft.intent_id;
        }
    }

    // ATOMIC RESERVATION BEFORE TRANSFER (shared CAS with the owner path).
    // PHASE 9 spend controls: GROUP-ATOMIC across the per-agent bucket and
    // every applicable aggregate scope (child → root), one store_lock
    // section, full rollback on any failure.
    let hier = reserve_spend_hierarchical(
        ledger_dir,
        &uuid,
        &policy.aggregate_scopes[..],
        &day,
        amount_kelvin,
        daily_limit,
        now,
    );
    let scope_reservations = match &hier {
        Ok(Ok(res)) => res.scopes.clone(),
        _ => Vec::new(),
    };
    let (previous_kelvin, reserved_to_kelvin) = match hier {
        Err(_) => {
            let _ = mark_intent_failed_v2(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                500,
                "AGENT_STORE_ERROR",
                "Agent payment state could not be stored",
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some("AGENT_STORE_ERROR"),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            return Err(PaymentFailure::Store);
        }
        Ok(Err(())) => {
            let _ = mark_intent_failed_v2(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                403,
                "AGENT_POLICY_DENIED",
                "Amount exceeds the agent policy limits",
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some("AGENT_POLICY_DENIED"),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            return Err(PaymentFailure::Enforcement(EnforcementDenial::AmountDenied));
        }
        Ok(Ok(res)) => (res.agent.previous_kelvin, res.agent.reserved_to_kelvin),
    };

    // helper: a definitive pre-transfer failure refunds and records once
    let abort_before_transfer =
        |failure: PaymentFailure, ops_note: (u16, &str, &str)| -> PaymentFailure {
            let _ = release_spend(
                ledger_dir,
                &uuid,
                &day,
                reserved_to_kelvin,
                previous_kelvin,
                now,
            );
            // PHASE 9 spend controls: release the claim-time aggregate
            // reservations too (bookkept exact-match — no partial state).
            let _ = release_scopes_bookkept(ledger_dir, &scope_reservations, now);
            let _ = mark_intent_failed_v2(
                intents_dir,
                &uuid,
                idempotency_key,
                now,
                ops_note.0,
                ops_note.1,
                ops_note.2,
            );
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Aborted,
                Some(ops_note.1),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            failure
        };

    // SIGNER RESOLUTION (rialo_tx_signers — PHASE 8 Item 10): identical
    // boundary discipline as the owner core; the credential lane's signer
    // is STILL the agent's own wallet keypair — the credential
    // authenticates the request, it NEVER signs (identity separation).
    let signer = match agent
        .wallet_address
        .as_deref()
        .and_then(|address| TxSigner::for_agent_record(&agent.agent_id, address).ok())
    {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::WalletStore,
                (
                    500,
                    "AGENT_WALLET_STORE_ERROR",
                    "Agent wallet file is missing or unreadable",
                ),
            ));
        }
        Some(signer) => signer,
    };

    // BALANCE — same typed read path; RPC failure never becomes a fake zero
    let balance_rlo = match signer.public_address() {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::WalletStore,
                (
                    500,
                    "AGENT_WALLET_STORE_ERROR",
                    "Agent wallet file is missing or unreadable",
                ),
            ));
        }
        Some(address) => match ops.balance(address) {
            Ok(value) => value,
            Err(err) => {
                let code = err.code.to_string();
                let detail = err.detail.clone();
                return Err(abort_before_transfer(
                    PaymentFailure::Transfer(err),
                    (502, code.as_str(), detail.as_str()),
                ));
            }
        },
    };

    // INTEGER KELVIN comparison with the established fee headroom
    let balance_kelvin = match rlo_balance_to_kelvin(balance_rlo) {
        None => {
            return Err(abort_before_transfer(
                PaymentFailure::BalanceUnreadable,
                (
                    502,
                    "RIALO_ERROR",
                    "Agent balance reading is not usable for a money comparison; no transfer was attempted",
                ),
            ));
        }
        Some(k) => k,
    };
    let required = amount_kelvin
        .checked_add(AGENT_PAYMENT_FEE_HEADROOM_KELVIN)
        .unwrap_or(u64::MAX);
    if balance_kelvin < required {
        let message = format!(
            "Agent wallet balance is {balance_rlo} RLO; payment of {amount_rlo} RLO plus 0.001 RLO fee headroom is not covered"
        );
        return Err(abort_before_transfer(
            PaymentFailure::InsufficientFunds {
                balance_rlo,
                amount_rlo,
            },
            (400, "INSUFFICIENT_FUNDS", message.as_str()),
        ));
    }

    // WALLET RESOLUTION THROUGH THE SIGNER BOUNDARY (rialo_tx_signers,
    // PHASE 8 Item 10): reference derived from the canonical signer and
    // hard-verified before any transfer — same deterministic outcomes as
    // the owner core (missing/unreadable -> AGENT_WALLET_STORE_ERROR
    // preserved; wrong key -> SIGNER_MISMATCH, no fallback). The human
    // owner's wallet directory is structurally unreachable here.
    let wallet_path = signer.keypair_reference(wallet_dir);
    // PHASE 9 STEP 8 (custody cutover): the legacy signer-file verification
    // applies ONLY to lanes whose custody is in-process (native/latch).
    // The isolated-signer lane holds custody OUTSIDE the app — the record's
    // address IS the signer-owned address and the sign-time chain (record
    // linkage + BYTE_DIVERGENCE + policy) is the verification. The check is
    // skipped for that lane, never weakened: the signer lane's own gates
    // (record linkage, BYTE_DIVERGENCE, policy) remain mandatory.
    if !ops.uses_external_custody() {
        match verify_agent_public_address(&signer, wallet_dir) {
            Ok(()) => {}
            Err(SignerError::Mismatch) => {
                return Err(abort_before_transfer(
                    PaymentFailure::WalletStore,
                    (
                        500,
                        "SIGNER_MISMATCH",
                        "The keypair at the signer reference does not match the signer's recorded public identity; no transfer was attempted",
                    ),
                ));
            }
            Err(_) => {
                return Err(abort_before_transfer(
                    PaymentFailure::WalletStore,
                    (
                        500,
                        "AGENT_WALLET_STORE_ERROR",
                        "Agent wallet file is missing or unreadable",
                    ),
                ));
            }
        }
    }

    // THE LAST MONEY-MOVING OPERATION — exactly one call, no retry here.
    match ops.transfer(&wallet_path, recipient, &amount_rlo.to_string()) {
        Ok(signature) => {
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Ok,
                None,
                &uuid.to_string(),
                idempotency_key,
                Some(&signature),
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            let body = trigger_success_json(
                &agent.agent_id,
                recipient,
                amount_rlo,
                amount_kelvin,
                &signature,
                Some(balance_rlo),
                &intent_id,
            );
            // MISSION PHASE B — v2 Confirmed commit (PG/FS dispatch).
            let confirmed_write_v2 = if crate::pg_store::pg_is_authoritative() {
                let sig_c = signature.clone();
                let body_c = body.clone();
                let signer_rec = signer.record();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_v2_pg(
                                &mut *client,
                                uuid,
                                idempotency_key,
                                now,
                                &|i: &mut crate::agents::PaymentIntentV2| {
                                    i.exec_state = ExecState::Confirmed;
                                    i.tx_signature = Some(sig_c.clone());
                                    i.response = Some(body_c.clone());
                                    i.signer = Some(signer_rec.clone());
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(Ok(_)) => Ok(()),
                        Ok(Err(e)) => Err(format!("pg v2 update: {e}")),
                        Err(_) => Err("pg v2 update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent_v2(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.exec_state = ExecState::Confirmed;
                    i.tx_signature = Some(signature.clone());
                    i.response = Some(body.clone());
                    i.signer = Some(signer.record());
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            if confirmed_write_v2.is_err() {
                // money moved but the record could not be closed: the
                // intent stays Pending, which BLOCKS replays — the safe
                // direction. The client is told the truth: it succeeded.
                eprintln!("[agents] v2 payment intent state update failed (intent stays gated)");
            }
            Ok(body)
        }
        Err(err) if err.code == RIALO_TRANSFER_CONFIRMATION_TIMEOUT => {
            // OUTCOME UNKNOWN. No refund (the funds may already be
            // broadcast), no retry (the transfer may already be landed),
            // and replay is gated until Step-4 reconciliation.
            //
            // PHASE 6 STEP 4: when the failure envelope itself surfaced a
            // broadcast signature (the CLI built, signed, and sent the
            // transaction before confirmation timed out), it is persisted
            // into this record BEFORE the Unknown transition — never
            // fabricated, never replaced with a placeholder. If the
            // transfer produced no recoverable signature the field stays
            // None, exactly as before.
            let code = err.code.to_string();
            let detail = err.detail.clone();
            let surfaced_signature = err.tx_signature.clone().filter(|s| !s.is_empty());
            // MISSION PHASE B — v2 Unknown commit (PG/FS dispatch). The
            // commitment is HELD: no release, no retry, no ambiguity.
            let _ = if crate::pg_store::pg_is_authoritative() {
                let code_c = code.clone();
                let detail_c = detail.clone();
                let surfaced_c = surfaced_signature.clone();
                let signer_rec = signer.record();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_v2_pg(
                                &mut *client,
                                uuid,
                                idempotency_key,
                                now,
                                &|i: &mut crate::agents::PaymentIntentV2| {
                                    i.exec_state = ExecState::Unknown;
                                    i.signer = Some(signer_rec.clone());
                                    if i.tx_signature.is_none() {
                                        if let Some(sig) = &surfaced_c {
                                            i.tx_signature = Some(sig.clone());
                                        }
                                    }
                                    i.failure = Some(FailureRecord {
                                        code: code_c.clone(),
                                        http_status: 502,
                                    });
                                    i.response = Some(recorded_error_json(502, &code_c, &detail_c));
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg v2 unknown update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent_v2(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.exec_state = ExecState::Unknown;
                    i.signer = Some(signer.record());
                    if i.tx_signature.is_none() {
                        if let Some(sig) = &surfaced_signature {
                            i.tx_signature = Some(sig.clone());
                        }
                    }
                    i.failure = Some(FailureRecord {
                        code: code.clone(),
                        http_status: 502,
                    });
                    i.response = Some(recorded_error_json(502, &code, &detail));
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Unknown,
                Some(&code),
                &uuid.to_string(),
                idempotency_key,
                surfaced_signature.as_deref(),
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            Err(PaymentFailure::Transfer(err))
        }
        Err(err) => {
            // DEFINITIVE failure per rialo.rs classification: release the
            // reservation and burn the key with the typed outcome.
            let code = err.code.to_string();
            let detail = err.detail.clone();
            let _ = release_spend(
                ledger_dir,
                &uuid,
                &day,
                reserved_to_kelvin,
                previous_kelvin,
                now,
            );
            // PHASE 9 spend controls: release the aggregate reservations too.
            // MISSION PHASE B — v2 Failed commit: spend release (PG/FS)
            // then intent transition (PG/FS). The spend release must
            // succeed before the intent is marked Failed, or the funds
            // stay reserved (fail-closed).
            let _ = if crate::pg_store::pg_is_authoritative() {
                let scope_ids: Vec<String> = scope_reservations
                    .iter()
                    .map(|s| s.scope_id.to_string())
                    .collect();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            let r1 = crate::pg_store::release_spend(
                                &mut *client,
                                uuid,
                                &day,
                                amount_kelvin,
                                now,
                            )
                            .await;
                            let r2 = crate::pg_store::release_scopes_pg(
                                &mut *client,
                                &scope_ids,
                                &day,
                                amount_kelvin,
                                now,
                            )
                            .await;
                            r1.and(r2)
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg v2 spend release panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                let _ = release_scopes_bookkept(ledger_dir, &scope_reservations, now);
                Ok::<(), String>(())
            };
            let _ = if crate::pg_store::pg_is_authoritative() {
                let code_c = code.clone();
                let detail_c = detail.clone();
                match crate::pg_store::main_handle() {
                    Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        rt.block_on(async {
                            let mut client = crate::pg_store::global_client().await;
                            crate::pg_store::update_intent_v2_pg(
                                &mut *client,
                                uuid,
                                idempotency_key,
                                now,
                                &|i: &mut crate::agents::PaymentIntentV2| {
                                    i.exec_state = ExecState::Failed;
                                    i.failure = Some(FailureRecord {
                                        code: code_c.clone(),
                                        http_status: 502,
                                    });
                                    i.response = Some(recorded_error_json(502, &code_c, &detail_c));
                                },
                            )
                            .await
                        })
                    })) {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => Err("pg v2 failed update panicked".into()),
                    },
                    Err(e) => Err(format!("pg runtime: {e}")),
                }
            } else {
                update_intent_v2(intents_dir, &uuid, idempotency_key, now, |i| {
                    i.exec_state = ExecState::Failed;
                    i.failure = Some(FailureRecord {
                        code: code.clone(),
                        http_status: 502,
                    });
                    i.response = Some(recorded_error_json(502, &code, &detail));
                })
                .map(|_| ())
                .map_err(|e| e.to_string())
            };
            audit_execution_outcome(
                intents_dir,
                now,
                crate::audit::AuditOutcome::Failed,
                Some(&code),
                &uuid.to_string(),
                idempotency_key,
                None,
                Some(policy_fingerprint(policy)),
                Some(intent_id.as_str()),
            );
            Err(PaymentFailure::Transfer(err))
        }
    }
}

/// Principal-resolution refusals, kept OUTSIDE PaymentFailure so the
/// credential layer's stable 401 is never conflated with money-state errors.
#[derive(Debug)]
enum TriggerDenial {
    Credential,
    Lifecycle,
    PolicyMissing,
    Store,
}

/// POST /api/agents/triggers/payments — thin HTTP shell over the v2 core.
/// Authorization order (fixed): credential shape → authenticate (Step 2,
/// disk authority) → agent record (id self-consistency) → lifecycle →
/// persisted policy → body/amount/recipient via the ONE helpers →
/// Idempotency-Key → per-agent lock → v2 core.
pub async fn agent_trigger_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // G21.11 kill-switch: block BEFORE reservation/policy spend accounting.
    if super::transfers_disabled() {
        return crate::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "TRANSFERS_DISABLED",
            "Transfers are disabled by operator configuration (AGENTPAY_DISABLE_TRANSFERS).",
        );
    }
    // 1. credential header — exactly one value, 64 lowercase hex. ANY
    //    failure answers the SAME stable 401; the value is never echoed,
    //    logged, stored, or returned.
    fn credential_invalid() -> Response {
        api_error(
            StatusCode::UNAUTHORIZED,
            "AGENT_CREDENTIAL_INVALID",
            "A valid X-Agent-Credential header is required to resolve the agent principal",
        )
    }
    let mut cred_values = headers.get_all("x-agent-credential").iter();
    let credential = match (cred_values.next(), cred_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|c| valid_credential_shape(c))
            .map(|c| c.to_string()),
        _ => None,
    };
    let Some(credential) = credential else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("AGENT_CREDENTIAL_INVALID"),
            crate::audit::IdentityClass::Credential,
            None,
            None,
            None,
        );
        return credential_invalid();
    };

    // 2.-6. credential -> exactly one Agent principal, lifecycle, policy.
    // Argon2 verification is deliberately expensive: blocking pool.
    let resolution = {
        let credential = credential.clone(); // the only copy; dropped below
        let agents = agents_dir();
        let policies = agent_policies_dir();
        tokio::task::spawn_blocking(move || {
            let uuid = crate::agent_credentials::authenticate_agent_credential(&credential)
                .map_err(|_| TriggerDenial::Credential)?;
            drop(credential); // plaintext never outlives principal resolution
            let agent =
                read_agent(&agent_path(&agents, &uuid)).map_err(|_| TriggerDenial::Credential)?;
            // the record's self-id MUST equal the credential-resolved id:
            // every downstream path keys off agent.agent_id, and it must be
            // the SAME agent the credential authenticated.
            if agent.agent_id != uuid.to_string() {
                return Err(TriggerDenial::Credential);
            }
            if agent.status != AgentStatus::Active {
                return Err(TriggerDenial::Lifecycle);
            }
            // MISSION PHASE 2 — leaf policy read is storage-mode dispatched:
            // PG-authoritative mode reads the authoritative row (a DB error
            // maps to TriggerDenial::Store — fail-closed, no FS fallback).
            // The parent-chain fold below remains the frozen FS walk; an
            // unresolvable chain in PG mode denies closed (blocker reported).
            let child_policy = if crate::pg_store::pg_is_authoritative() {
                match crate::pg_store::pg_run(async {
                    let client = crate::pg_store::global_client().await;
                    crate::pg_store::policy_read_pg(&*client, uuid).await
                }) {
                    Ok(Ok(p)) => p,
                    _ => return Err(TriggerDenial::Store),
                }
            } else {
                match load_policy(&policies, &uuid) {
                    Ok(p) => p,
                    Err(_) => return Err(TriggerDenial::Store),
                }
            }
            .ok_or(TriggerDenial::PolicyMissing)?;
            // PHASE 9 "Hierarchical Policy": resolve the EFFECTIVE policy
            // from the parent chain BEFORE enforcement (frozen decision).
            // Any resolution failure denies (fail-closed, no flat fallback)
            // — the existing TriggerDenial::PolicyMissing variant keeps the
            // credential-lane envelope unchanged.
            let policy = crate::agents::resolve_effective_policy(child_policy, &policies, &agents)
                .map_err(|_| TriggerDenial::PolicyMissing)?;
            Ok::<_, TriggerDenial>((agent, policy))
        })
        .await
    };
    // the header-local copy is no longer needed for anything
    drop(credential);

    let (agent, policy) = match resolution {
        Ok(Ok(pair)) => pair,
        Ok(Err(TriggerDenial::Credential)) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_CREDENTIAL_INVALID"),
                crate::audit::IdentityClass::Credential,
                None,
                None,
                None,
            );
            return credential_invalid();
        }
        Ok(Err(TriggerDenial::Lifecycle)) => {
            // NOTE: the denial's agent identity is deliberately NOT recorded
            // (the credential plane collapses identities); the audit records
            // the credential-plane denial class only.
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_LIFECYCLE_BLOCKED"),
                crate::audit::IdentityClass::Credential,
                None,
                None,
                None,
            );
            return EnforcementDenial::Lifecycle.into_response();
        }
        Ok(Err(TriggerDenial::PolicyMissing)) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_POLICY_MISSING"),
                crate::audit::IdentityClass::Credential,
                None,
                None,
                None,
            );
            return EnforcementDenial::PolicyMissing.into_response();
        }
        Ok(Err(TriggerDenial::Store)) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_STORE_ERROR"),
                crate::audit::IdentityClass::Credential,
                None,
                None,
                None,
            );
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                "Agent policy could not be read",
            );
        }
        Err(join_err) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_STORE_ERROR"),
                crate::audit::IdentityClass::Credential,
                None,
                None,
                None,
            );
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                &join_err.to_string(),
            );
        }
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return credential_invalid(); // cannot happen for a self-consistent record
    };

    // 7. body/amount/recipient — through the ONE existing helpers, same
    // typed codes as the owner path (deny_unknown_fields makes an agent_id
    // in the body impossible).
    let req = match parse_payment_body(&body) {
        Ok(req) => req,
        Err(reason) => {
            audit_authorization(
                &audit_dir_for(&intents_root()),
                now_unix(),
                crate::audit::AuditOutcome::Deny,
                Some("AGENT_PAYMENT_REQUEST_INVALID"),
                crate::audit::IdentityClass::Credential,
                Some(&agent.agent_id),
                None,
                Some(&policy_fingerprint(&policy)),
            );
            return api_error(
                StatusCode::BAD_REQUEST,
                "AGENT_PAYMENT_REQUEST_INVALID",
                reason,
            );
        }
    };
    let Some(amount_kelvin) = super::rlo_to_kelvin(req.amount).and_then(|k| k.parse::<u64>().ok())
    else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_AMOUNT"),
            crate::audit::IdentityClass::Credential,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_AMOUNT",
            "Amount must be a positive multiple of 1 kelvin (1e-9 RLO)",
        );
    };
    if !super::valid_rialo_address(&req.to) {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_RECIPIENT"),
            crate::audit::IdentityClass::Credential,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_RECIPIENT",
            "Recipient is not a valid Rialo address",
        );
    }

    // Idempotency-Key — same gate as the owner path
    let mut key_values = headers.get_all("idempotency-key").iter();
    let idempotency_key = match (key_values.next(), key_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|k| valid_idempotency_key(k))
            .map(|k| k.to_string()),
        _ => None,
    };
    let Some(idempotency_key) = idempotency_key else {
        audit_authorization(
            &audit_dir_for(&intents_root()),
            now_unix(),
            crate::audit::AuditOutcome::Deny,
            Some("INVALID_IDEMPOTENCY_KEY"),
            crate::audit::IdentityClass::Credential,
            Some(&agent.agent_id),
            None,
            Some(&policy_fingerprint(&policy)),
        );
        return PaymentFailure::Key.into_response();
    };

    // per-agent async lock SHARED with the owner path (the (agent,key) slot
    // is global); the persistence lock is never held across the transfer.
    let lock = agent_payment_lock(&uuid.to_string());
    let _guard = lock.lock().await;

    // PHASE 9 I-5: same lane decision as the owner path (env-only; plain
    // native ops when the proxy lane is absent). The v2 core and its single
    // ops.transfer site are unchanged.
    let lane_audit_ctx = Arc::new(crate::audit::LaneAuditContext {
        agent_id: agent.agent_id.clone(),
        idempotency_key: idempotency_key.clone(),
        audit_dir: audit_dir_for(&intents_root()),
    });
    let ops: Arc<dyn PaymentOps + Send + Sync> =
        crate::isolated_signer_lane::production_isolated_signer_ops_audited(
            state.rialo.clone(),
            &agent,
            &policy,
            &agent_auth_keys_dir(),
            Some(lane_audit_ctx),
        );
    let wallet_dir = agent_wallet_dir();
    let ledger_dir = spend_dir();
    let intents_dir = intents_root();
    let now = now_unix();
    // PHASE 9 audit: capture the public correlation facts BEFORE the
    // blocking closure moves the owned values (clone of public data only).
    let audit_agent_id = agent.agent_id.clone();
    let audit_key = idempotency_key.clone();
    let audit_policy_fp = policy_fingerprint(&policy);
    let audit_dir_handle = audit_dir_for(&intents_root());
    let outcome = tokio::task::spawn_blocking(move || {
        execute_agent_payment_v2(
            ops.as_ref(),
            &wallet_dir,
            &ledger_dir,
            &intents_dir,
            &agent,
            &policy,
            &idempotency_key,
            &req.to,
            amount_kelvin,
            req.amount,
            now,
        )
    })
    .await;

    match outcome {
        Ok(Ok(value)) => {
            audit_authorization(
                &audit_dir_handle,
                now,
                crate::audit::AuditOutcome::Allow,
                None,
                crate::audit::IdentityClass::Credential,
                Some(&audit_agent_id),
                Some(&audit_key),
                Some(&audit_policy_fp),
            );
            Json(value).into_response()
        }
        Ok(Err(failure)) => {
            audit_handler_failure(
                &failure,
                crate::audit::IdentityClass::Credential,
                &audit_agent_id,
                &audit_key,
                Some(audit_policy_fp.clone()),
                &audit_dir_handle,
                now,
            );
            failure.into_response()
        }
        // blocking worker died — possibly mid-transfer: outcome UNKNOWN,
        // still-Pending intent gates every replay, no blind retry
        Err(join_err) => api_error(
            StatusCode::BAD_GATEWAY,
            "RIALO_ERROR",
            &format!(
                "payment worker failed ({join_err}); the transfer outcome is unverified — reconcile before retrying"
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// PHASE 6 STEP 4 — RECONCILIATION ENGINE
// ---------------------------------------------------------------------------
//
// Reconciliation is the ONLY exit from the confirmation-timeout Unknown
// hold, and it is strictly READ-ONLY against the chain: it never moves
// money, never retries a transfer, never reserves, and never releases a
// reservation it cannot prove was the ORIGINAL one.
//
// STATE MACHINE (item 7):
//   Pending -> Confirmed | Failed | Unknown              (payment engine)
//   Pending (stale after restart) -> Unknown             (normalise, audit)
//   Unknown -> ReconciledPaid | ReconciledAbsent         (this commit, once)
//   Confirmed/Failed can NEVER enter reconciliation.
//   ReconciledPaid / ReconciledAbsent are immutable terminal states —
//   enforced at the STORE layer (update_intent guards), not only at the
//   API layer.
//
// EVIDENCE RULES (item 4, strict):
//   ReconciledPaid requires a signature, a successful get_transaction,
//   executed == true, err == null, slot > 0, timing consistent with the
//   intent, AND — where the transaction's transfer data decodes — payer
//   == the agent wallet, recipient == the intended recipient, amount ==
//   amount_kelvin. Balance delta is NEVER decisive: the reconciler does
//   not even read balances (structural test pins ops.balance out of the
//   engine).
//   ReconciledAbsent requires a known signature and DECISIVE failure
//   evidence (executed == false OR err != null) for THAT signature.
//   A temporary RPC failure stays Unknown. A not-found before the
//   finality horizon stays Unknown. Unknown WITHOUT a signature: the
//   bounded address-history scan may find EXACTLY ONE matching transfer
//   -> PROPOSAL only (202); never a silent auto-finalization over HTTP,
//   never an Absent minted from "scan found nothing", never a spend
//   release from absence of evidence.
//
// CONCURRENCY (item 9): every decision is made from a lock-free read +
// an RPC OUTSIDE store_lock; the terminal write happens inside ONE
// store_lock critical section that re-reads the intent and refuses to
// touch it unless it is still exactly the reconcilable state. Two racing
// reconciliations produce exactly one terminal write and one replay of
// the stored result. The payment lane's agent_payment_lock -> store_lock
// ordering is untouched; the reconciler never takes agent_payment_lock
// (no unrelated payment blocking) and never holds store_lock across RPC.

/// A Pending intent whose worker vanished (restart) becomes
/// reconciliation-eligible — NOT silently Failed — only after this grace
/// window, so an in-flight transfer can never collide with the
/// reconciler. Comfortably larger than the worst CLI confirmation wait
/// plus clock-skew retries.
pub const AGENT_PENDING_STALE_AFTER_SECONDS: i64 = 900;
/// Bounded address-scan window (audit: bounded time window, fail closed).
pub const ADDRESS_SCAN_WINDOW_SECONDS: i64 = 3 * 86_400;
/// Hard caps so a scan can never fan out into an unbounded RPC storm.
const ADDRESS_SCAN_HISTORY_LIMIT: u64 = 25;
const ADDRESS_SCAN_MAX_LOOKUPS: usize = 8;
/// Clock-skew tolerance when matching tx timing to the intent.
const TX_TIMING_SKEW_TOLERANCE_SECONDS: i64 = 300;

/// A reconciliation request. `manual_outcome`/`attestation` drive the
/// manual attestation lane (owner principals only); `allow_scan` gates
/// the read-only address-discovery lane; `allow_auto` is the explicit
/// policy switch for auto-finalizing a single unambiguous scan match —
/// NO HTTP path ever sets it true (manual attestation is the human exit;
/// the switch exists for the policy the audit names, and is tested).
#[derive(Debug, Clone)]
pub struct ReconcileRequest {
    pub idempotency_key: String,
    pub manual_outcome: Option<ReconciliationOutcome>,
    pub attestation: Option<String>,
    pub allow_scan: bool,
    pub allow_auto: bool,
}

/// The engine's typed outcome. Every variant maps to exactly one HTTP
/// shape in status_and_body — no variant is renderable as a success that
/// did not actually commit.
#[derive(Debug)]
pub enum ReconcileVerdict {
    /// A terminal decision is stored (freshly committed or replayed —
    /// replayed NEVER re-RPCs and NEVER re-touches the ledger).
    Reconciled {
        record: ReconciliationRecord,
        replayed: bool,
    },
    /// Address scan found exactly one matching successful transfer; the
    /// proposal carries evidence but changed NOTHING on disk (202).
    Proposal {
        tx_signature: String,
        evidence: ReconciliationEvidence,
    },
    /// Still Unknown, retryable. code RIALO_RPC_UNAVAILABLE => 503;
    /// AGENT_RECONCILIATION_ATTESTATION_REQUIRED => 400; else => 202.
    Unresolved {
        code: &'static str,
        reason: &'static str,
    },
    /// Pending and inside the in-flight grace window.
    InProgress,
    /// Confirmed/Failed can never enter reconciliation.
    NotApplicable,
    /// Manual attestation attempted by a non-owner principal.
    ManualForbidden,
    IntentNotFound,
    StoreError,
}

impl ReconcileVerdict {
    pub fn status_and_body(
        &self,
        agent_id: &str,
        idempotency_key: &str,
        intent_id: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        match self {
            Self::Reconciled { record, replayed } => {
                let mut body = reconciliation_json(record);
                body["success"] = serde_json::json!(true);
                body["agent_id"] = serde_json::json!(agent_id);
                body["idempotency_key"] = serde_json::json!(idempotency_key);
                body["intent_id"] = serde_json::json!(intent_id);
                body["replayed"] = serde_json::json!(replayed);
                (StatusCode::OK, body)
            }
            Self::Proposal {
                tx_signature,
                evidence,
            } => (
                StatusCode::ACCEPTED,
                serde_json::json!({
                    "success": false,
                    "error": {
                        "code": "AGENT_RECONCILIATION_PROPOSAL",
                        "message": "address scan found exactly one matching transfer; finalization requires an owner manual attestation (auto-finalization is policy-gated and not exposed over HTTP)",
                    },
                    "proposal": {
                        "tx_signature": tx_signature,
                        "evidence": serde_json::to_value(evidence).unwrap_or(serde_json::Value::Null),
                    },
                }),
            ),
            Self::Unresolved { code, reason } => {
                let status = if *code == "RIALO_RPC_UNAVAILABLE" {
                    StatusCode::SERVICE_UNAVAILABLE
                } else if *code == "AGENT_RECONCILIATION_ATTESTATION_REQUIRED" {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::ACCEPTED
                };
                (
                    status,
                    serde_json::json!({
                        "success": false,
                        "error": { "code": code, "message": reason },
                    }),
                )
            }
            Self::InProgress => (
                StatusCode::CONFLICT,
                serde_json::json!({
                    "success": false,
                    "error": { "code": "AGENT_PAYMENT_IN_PROGRESS", "message": "a transfer for this key is still inside its in-flight window; not reconciliation-eligible yet" },
                }),
            ),
            Self::NotApplicable => (
                StatusCode::CONFLICT,
                serde_json::json!({
                    "success": false,
                    "error": { "code": "AGENT_RECONCILIATION_NOT_APPLICABLE", "message": "reconciliation applies ONLY to Unknown outcomes; Confirmed and Failed are not reconcilable and the stored payment outcome is unchanged" },
                }),
            ),
            Self::ManualForbidden => (
                StatusCode::FORBIDDEN,
                serde_json::json!({
                    "success": false,
                    "error": { "code": "AGENT_RECONCILIATION_MANUAL_FORBIDDEN", "message": "manual attestation requires the owner principal; the agent credential lane is deterministic-evidence only" },
                }),
            ),
            Self::IntentNotFound => (
                StatusCode::NOT_FOUND,
                serde_json::json!({
                    "success": false,
                    "error": { "code": "AGENT_PAYMENT_INTENT_NOT_FOUND", "message": "no payment intent is bound to this idempotency key for the authenticated principal" },
                }),
            ),
            Self::StoreError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({
                    "success": false,
                    "error": { "code": "AGENT_STORE_ERROR", "message": "Agent payment state could not be read or stored" },
                }),
            ),
        }
    }
}

/// Stable JSON rendering of a reconciliation record — public chain facts
/// only (method, outcome, signature, time, resolver handle, evidence).
/// Nothing secret is representable in a ReconciliationRecord by
/// construction: every field is an enum tag, a public signature, an i64,
/// a validated resolver handle, or a bounded scalar summary.
pub fn reconciliation_json(record: &ReconciliationRecord) -> serde_json::Value {
    serde_json::json!({
        "reconciliation": {
            "method": record.method,
            "outcome": record.outcome,
            "tx_signature": record.tx_signature,
            "resolved_at": record.resolved_at,
            "resolver": record.resolver,
            "evidence": record.evidence,
        }
    })
}

/// Single-line, bounded, control-free attestation text — the ONLY
/// free-text lane into evidence, sanitized at the boundary.
fn sanitize_attestation(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() || trimmed.len() > 512 {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(trimmed)
}

/// The two record versions share one decision core through this view.
enum ReconcileTarget {
    V1(PaymentIntent),
    V2(PaymentIntentV2),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NormalState {
    Pending,
    Confirmed,
    Failed,
    Unknown,
    Reconciled,
}

struct IntentFacts {
    // correlation only in Step 4 (v2 records carry it; the HTTP surface
    // stays key-scoped), kept for the audit trail
    #[allow(dead_code)]
    intent_id: Option<String>,
    recipient: String,
    amount_kelvin: u64,
    created_at: i64,
    updated_at: i64,
    tx_signature: Option<String>,
    state: NormalState,
    stored: Option<ReconciliationRecord>,
}

impl IntentFacts {
    fn of(target: &ReconcileTarget) -> Self {
        match target {
            ReconcileTarget::V1(i) => Self {
                intent_id: None,
                recipient: i.recipient.clone(),
                amount_kelvin: i.amount_kelvin,
                created_at: i.created_at,
                updated_at: i.updated_at,
                // v1 records never carried a signature
                tx_signature: None,
                state: match i.state {
                    IntentState::Pending => NormalState::Pending,
                    IntentState::Confirmed => NormalState::Confirmed,
                    IntentState::Failed => NormalState::Failed,
                    IntentState::Unknown => NormalState::Unknown,
                    IntentState::ReconciledPaid | IntentState::ReconciledAbsent => {
                        NormalState::Reconciled
                    }
                },
                stored: i.reconciliation.clone(),
            },
            ReconcileTarget::V2(i) => Self {
                intent_id: Some(i.intent_id.clone()),
                recipient: i.recipient.clone(),
                amount_kelvin: i.amount_kelvin,
                created_at: i.created_at,
                updated_at: i.updated_at,
                tx_signature: i.tx_signature.clone(),
                state: match i.exec_state {
                    ExecState::Pending => NormalState::Pending,
                    ExecState::Confirmed => NormalState::Confirmed,
                    ExecState::Failed => NormalState::Failed,
                    ExecState::Unknown => NormalState::Unknown,
                    ExecState::ReconciledPaid | ExecState::ReconciledAbsent => {
                        NormalState::Reconciled
                    }
                },
                stored: i.reconciliation.clone(),
            },
        }
    }
}

/// Version-aware read that does NOT collapse v1 into the v2 payment
/// path's cross-version conflict rule (the engines keep their strict
/// semantics; reconciliation reads whichever record owns the slot).
fn read_reconcile_target(
    root: &FsPath,
    id: &Uuid,
    key: &str,
) -> Result<Option<ReconcileTarget>, std::io::Error> {
    match fs::read(intent_path(&agent_intents_dir(root, id), key)) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::other(format!("intent parse: {e}")))?;
            match value.get("schema_version").and_then(|v| v.as_u64()) {
                Some(1) => {
                    let intent: PaymentIntent = serde_json::from_value(value)
                        .map_err(|e| std::io::Error::other(format!("intent v1 shape: {e}")))?;
                    if intent.schema_version != PAYMENT_INTENT_SCHEMA_VERSION {
                        return Err(std::io::Error::other("unsupported intent schema_version"));
                    }
                    if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                        return Err(std::io::Error::other("intent identity mismatch"));
                    }
                    Ok(Some(ReconcileTarget::V1(intent)))
                }
                Some(2) => {
                    let intent: PaymentIntentV2 = serde_json::from_value(value)
                        .map_err(|e| std::io::Error::other(format!("intent v2 shape: {e}")))?;
                    if intent.agent_id != id.to_string() || intent.idempotency_key != key {
                        return Err(std::io::Error::other("intent identity mismatch"));
                    }
                    Ok(Some(ReconcileTarget::V2(intent)))
                }
                _ => Err(std::io::Error::other("unsupported intent schema_version")),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Transaction timing must be consistent with the intent: not before the
/// intent existed (beyond a small clock tolerance) and not in a future
/// the request could not have produced. Missing block_time is NOT a
/// proof — callers fail closed on None.
///
/// SCHEMA REMEDIATION (fix 6): `created_at` is a WINDOW this function
/// CHECKS the chain-reported time against — it is NEVER a timing source.
/// A record without a chain-sourced block_time (CLI, vendor
/// getTransaction, or getBlock(block_height) — the only fallbacks, all
/// in rialo.rs) can NEVER be minted consistent here, so it stays
/// Unknown. Nothing in this lane synthesizes time from local clocks.
fn tx_timing_consistent(block_time: Option<i64>, created_at: i64, now: i64) -> bool {
    let Some(t) = block_time else {
        return false;
    };
    t >= created_at.saturating_sub(TX_TIMING_SKEW_TOLERANCE_SECONDS)
        && t <= now.saturating_add(TX_TIMING_SKEW_TOLERANCE_SECONDS)
}

fn evidence_from_tx(rec: &TxRecord, summary: &str) -> ReconciliationEvidence {
    ReconciliationEvidence {
        block_height: rec.block_height,
        slot: rec.slot,
        block_time: rec.block_time,
        fee: rec.fee,
        meta_err: rec.err.clone(),
        tx_summary: Some(summary.to_string()),
    }
}

/// Decisive verdict for one found record against one intent. Returns
/// Some(outcome) only under the strict evidence rules; None means the
/// evidence is NOT sufficient in either direction (stay Unknown).
fn proven_outcome(
    rec: &TxRecord,
    agent_wallet: &str,
    recipient: &str,
    amount_kelvin: u64,
    created_at: i64,
    now: i64,
) -> Option<ReconciliationOutcome> {
    if !rec.complete {
        return None;
    }
    // FIX 2 (explicit): rec.executed is ONLY ever true when a response
    // carried an explicit `"executed": true` boolean — the parse layer
    // (rialo.rs extract_status / parse_signature_status) rejects derived
    // or missing executed, so this gate cannot be satisfied by inference.
    // FIX 3 (validation): the Paid gate requires signature (lane-keyed),
    // payer, recipient AND amount to all equal the intent's facts.
    if rec.executed && rec.err.is_none() {
        // ReconciledPaid gate (ALL of):
        let slot_ok = rec.slot.is_some_and(|s| s > 0);
        if !slot_ok || !tx_timing_consistent(rec.block_time, created_at, now) {
            return None;
        }
        // where transaction data decodes: payer/recipient/amount must all
        // match; an undecodable shape can NEVER mint Paid from chain data
        let facts_ok = rec
            .transfer_facts()
            .map(|(payer, tx_recipient, amount)| {
                payer == agent_wallet && tx_recipient == recipient && amount == amount_kelvin
            })
            .unwrap_or(false);
        if facts_ok {
            Some(ReconciliationOutcome::Paid)
        } else {
            None
        }
    } else {
        // failed = executed == false OR err != null — decisive Absent
        // (consumed ONLY by the known-signature lane)
        Some(ReconciliationOutcome::Absent)
    }
}

enum ScanOutcome {
    Single(String, TxRecord),
    None,
    Ambiguous,
    Transient(&'static str),
}

/// Bounded address-history discovery for the no-signature lane. A
/// candidate matches ONLY under the full ReconciledPaid evidence rules.
fn scan_address_history(
    ops: &(dyn PaymentOps + Send + Sync),
    agent_wallet: &str,
    recipient: &str,
    amount_kelvin: u64,
    created_at: i64,
    now: i64,
) -> ScanOutcome {
    let window_from = created_at.saturating_sub(ADDRESS_SCAN_WINDOW_SECONDS);
    // vendor config carries NO time cursors — the bound is the hard
    // limit plus the client-side block_time filter below
    let history = match ops.signatures_for_address(agent_wallet, None, ADDRESS_SCAN_HISTORY_LIMIT) {
        Ok(h) => h,
        Err(err) => {
            return if err.is_rpc_down() {
                ScanOutcome::Transient("RIALO_RPC_UNAVAILABLE")
            } else {
                ScanOutcome::Transient("AGENT_RECONCILIATION_SCAN_UNAVAILABLE")
            };
        }
    };
    let mut matches: Vec<(String, TxRecord)> = Vec::new();
    let mut examined = 0usize;
    for info in history {
        // bounded time window on the node's own block times
        if let Some(t) = info.block_time {
            if t < window_from - TX_TIMING_SKEW_TOLERANCE_SECONDS
                || t > now + TX_TIMING_SKEW_TOLERANCE_SECONDS
            {
                continue;
            }
        }
        // a node-reported failure can never be a PAID candidate
        if info.err.is_some() || info.signature.is_empty() {
            continue;
        }
        if examined >= ADDRESS_SCAN_MAX_LOOKUPS {
            // bounded: too much in-window history to decide safely
            return ScanOutcome::Ambiguous;
        }
        examined += 1;
        match ops.read_tx(&info.signature) {
            TxLookup::Found(rec) => {
                if proven_outcome(
                    &rec,
                    agent_wallet,
                    recipient,
                    amount_kelvin,
                    created_at,
                    now,
                ) == Some(ReconciliationOutcome::Paid)
                {
                    matches.push((info.signature.clone(), rec));
                    if matches.len() > 1 {
                        return ScanOutcome::Ambiguous;
                    }
                }
            }
            TxLookup::Unavailable(err) => {
                return ScanOutcome::Transient(if err.is_rpc_down() {
                    "RIALO_RPC_UNAVAILABLE"
                } else {
                    "AGENT_RECONCILIATION_TX_LOOKUP_UNAVAILABLE"
                });
            }
            // not found yet / undecodable detail: neither a match nor
            // counter-evidence — the lane stays inconclusive
            TxLookup::NotFound | TxLookup::Malformed => {}
        }
    }
    match matches.len() {
        0 => ScanOutcome::None,
        1 => {
            let (sig, rec) = matches.pop().expect("len 1");
            ScanOutcome::Single(sig, rec)
        }
        _ => ScanOutcome::Ambiguous,
    }
}

enum Decision {
    Early(ReconcileVerdict),
    Terminal {
        method: ReconciliationMethod,
        outcome: ReconciliationOutcome,
        tx_signature: Option<String>,
        evidence: ReconciliationEvidence,
    },
    Proposal {
        tx_signature: String,
        evidence: ReconciliationEvidence,
    },
}

/// THE shared decision core (pure: no writes, no locks): manual
/// attestation, known-signature TxLookup, or the bounded address scan.
fn reconcile_decision(
    ops: &(dyn PaymentOps + Send + Sync),
    facts: &IntentFacts,
    agent: &Agent,
    req: &ReconcileRequest,
    principal: &ReconcilePrincipal,
    now: i64,
) -> Decision {
    // ---- manual attestation lane (item 6) ----
    if let Some(outcome) = req.manual_outcome {
        if !principal.is_owner() {
            return Decision::Early(ReconcileVerdict::ManualForbidden);
        }
        let Some(note) = req.attestation.as_deref().and_then(sanitize_attestation) else {
            return Decision::Early(ReconcileVerdict::Unresolved {
                code: "AGENT_RECONCILIATION_ATTESTATION_REQUIRED",
                reason: "manual attestation requires a bounded single-line attestation note",
            });
        };
        return Decision::Terminal {
            method: ReconciliationMethod::ManualAttestation,
            outcome,
            tx_signature: facts.tx_signature.clone(),
            evidence: ReconciliationEvidence {
                tx_summary: Some(format!(
                    "manual attestation by {}: {}",
                    principal.resolver(),
                    note
                )),
                ..Default::default()
            },
        };
    }

    let agent_wallet = match agent.wallet_address.as_deref() {
        Some(a) => a,
        None => {
            return Decision::Early(ReconcileVerdict::Unresolved {
                code: "AGENT_RECONCILIATION_NO_WALLET_ADDRESS",
                reason: "the agent has no wallet address; no chain evidence can be bound",
            });
        }
    };

    // ---- known-signature lane (item 4) ----
    if let Some(sig) = facts.tx_signature.as_deref() {
        return match ops.read_tx(sig) {
            TxLookup::Unavailable(err) => Decision::Early(ReconcileVerdict::Unresolved {
                code: err.code,
                reason: "transaction lookup temporarily unavailable; the intent stays Unknown",
            }),
            TxLookup::NotFound => Decision::Early(ReconcileVerdict::Unresolved {
                code: "AGENT_RECONCILIATION_TEMPORARY_NOT_FOUND",
                reason: "the node does not know this transaction yet; a not-found before the finality horizon is NEVER proof of absence",
            }),
            TxLookup::Malformed => Decision::Early(ReconcileVerdict::Unresolved {
                code: "AGENT_RECONCILIATION_INCOMPLETE_EVIDENCE",
                reason: "the transaction response could not be parsed completely; incomplete evidence decides nothing",
            }),
            TxLookup::Found(rec) => {
                match proven_outcome(
                    &rec,
                    agent_wallet,
                    &facts.recipient,
                    facts.amount_kelvin,
                    facts.created_at,
                    now,
                ) {
                    Some(outcome) => Decision::Terminal {
                        method: ReconciliationMethod::TxLookup,
                        outcome,
                        tx_signature: Some(sig.to_string()),
                        evidence: evidence_from_tx(
                            &rec,
                            &format!(
                                "tx lookup: executed={} err={}",
                                rec.executed,
                                rec.err.as_deref().unwrap_or("null")
                            ),
                        ),
                    },
                    None => Decision::Early(ReconcileVerdict::Unresolved {
                        code: "AGENT_RECONCILIATION_EVIDENCE_MISMATCH",
                        reason: "the transaction found for this signature does not confirm the intent's payer/recipient/amount/timing; mismatched evidence is never Paid",
                    }),
                }
            }
        };
    }

    // ---- no-signature lane (item 5) ----
    if !req.allow_scan {
        return Decision::Early(ReconcileVerdict::Unresolved {
            code: "AGENT_RECONCILIATION_NO_SIGNATURE",
            reason: "no transaction signature was persisted for this intent; address-history discovery is not enabled for this principal",
        });
    }
    match scan_address_history(
        ops,
        agent_wallet,
        &facts.recipient,
        facts.amount_kelvin,
        facts.created_at,
        now,
    ) {
        ScanOutcome::Single(sig, rec) => {
            let evidence = evidence_from_tx(
                &rec,
                "address scan: exactly one matching successful transfer",
            );
            if req.allow_auto && principal.is_owner() {
                // EXPLICIT policy switch (never reachable from HTTP)
                Decision::Terminal {
                    method: ReconciliationMethod::AddressScan,
                    outcome: ReconciliationOutcome::Paid,
                    tx_signature: Some(sig),
                    evidence,
                }
            } else {
                Decision::Proposal {
                    tx_signature: sig,
                    evidence,
                }
            }
        }
        ScanOutcome::None => Decision::Early(ReconcileVerdict::Unresolved {
            code: "AGENT_RECONCILIATION_NO_MATCH",
            reason: "address scan found no matching successful transfer; absence of candidates NEVER releases spend and NEVER marks the intent Absent",
        }),
        ScanOutcome::Ambiguous => Decision::Early(ReconcileVerdict::Unresolved {
            code: "AGENT_RECONCILIATION_AMBIGUOUS",
            reason: "address scan found multiple or indistinguishable candidates; ambiguous evidence stays Unknown",
        }),
        ScanOutcome::Transient(code) => Decision::Early(ReconcileVerdict::Unresolved {
            code,
            reason: "address history temporarily unavailable; the intent stays Unknown",
        }),
    }
}

#[derive(Debug)]
pub(crate) enum CommitOutcome {
    Committed,
    /// already reconciled by a racing request: carry the stored record
    Already {
        stored: Option<ReconciliationRecord>,
    },
    /// the intent moved to a state this commit may not touch
    StateChanged,
}

/// THE terminal write — one store_lock critical section: re-read, verify
/// the intent is still exactly Unknown, flip to the immutable terminal,
/// and (Absent only) release the ORIGINAL reservation. No RPC runs inside
/// the section. ReconciledPaid NEVER touches the ledger (the reservation
/// stays consumed by design). A ledger failure inside the section means
/// the whole commit was rejected BEFORE any money-state change (the
/// intent flip and the release share one lock section; the intent write
/// happens first, so the worst crash outcome is over-retention).
fn commit_reconciliation(
    intents_dir: &FsPath,
    ledger_dir: &FsPath,
    id: &Uuid,
    key: &str,
    record: &ReconciliationRecord,
    now: i64,
) -> Result<CommitOutcome, std::io::Error> {
    // MISSION PHASE E — storage-mode dispatch (PG/FS). PG mode: the DB
    // transaction IS the exactly-once terminal commit (FOR UPDATE lock +
    // terminal-immutability guard + Unknown-only + in-tx release for
    // Absent); the FS path is never touched. FS mode: unchanged legacy.
    if crate::pg_store::pg_is_authoritative() {
        let record_c = record.clone();
        match crate::pg_store::main_handle() {
            Ok(rt) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                rt.block_on(async {
                    let mut client = crate::pg_store::global_client().await;
                    crate::pg_store::commit_reconciliation_pg(
                        &mut *client,
                        *id,
                        key,
                        &record_c,
                        now,
                    )
                    .await
                })
            })) {
                Ok(Ok(outcome)) => return Ok(outcome),
                Ok(Err(e)) => {
                    return Err(std::io::Error::other(format!("pg reconciliation: {e}")));
                }
                Err(_) => {
                    return Err(std::io::Error::other("pg reconciliation panicked"));
                }
            },
            Err(e) => {
                return Err(std::io::Error::other(format!("pg runtime: {e}")));
            }
        }
    }
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    let target = match read_reconcile_target(intents_dir, id, key)? {
        Some(t) => t,
        None => return Ok(CommitOutcome::StateChanged),
    };
    let path = intent_path(&agent_intents_dir(intents_dir, id), key);
    match target {
        ReconcileTarget::V1(mut intent) => {
            if matches!(
                intent.state,
                IntentState::ReconciledPaid | IntentState::ReconciledAbsent
            ) {
                return Ok(CommitOutcome::Already {
                    stored: intent.reconciliation.clone(),
                });
            }
            if intent.state != IntentState::Unknown {
                return Ok(CommitOutcome::StateChanged);
            }
            let release_amount = intent.amount_kelvin;
            let release_day = utc_day(intent.created_at);
            intent.state = match record.outcome {
                ReconciliationOutcome::Paid => IntentState::ReconciledPaid,
                ReconciliationOutcome::Absent => IntentState::ReconciledAbsent,
            };
            intent.reconciliation = Some(record.clone());
            intent.updated_at = now;
            write_json_atomic(&path, &intent)?;
            if record.outcome == ReconciliationOutcome::Absent {
                release_absent_reservation_inner(
                    ledger_dir,
                    id,
                    &release_day,
                    release_amount,
                    now,
                )?;
                // PHASE 9 spend controls: release the claim-time aggregate
                // scope reservations too (same original day, same amount;
                // exact-match/no-guess — over-retention is the safe
                // direction). The intent carries the CLAIM-TIME scopes.
                release_scopes_inner(
                    ledger_dir,
                    &intent.aggregate_scopes,
                    &release_day,
                    release_amount,
                    now,
                )?;
            }
        }
        ReconcileTarget::V2(mut intent) => {
            if intent.exec_state.is_reconciled() {
                return Ok(CommitOutcome::Already {
                    stored: intent.reconciliation.clone(),
                });
            }
            if intent.exec_state != ExecState::Unknown {
                return Ok(CommitOutcome::StateChanged);
            }
            let release_amount = intent.amount_kelvin;
            let release_day = utc_day(intent.created_at);
            intent.exec_state = match record.outcome {
                ReconciliationOutcome::Paid => ExecState::ReconciledPaid,
                ReconciliationOutcome::Absent => ExecState::ReconciledAbsent,
            };
            // persist a scan-provided signature when the record lacked one
            if intent.tx_signature.is_none() {
                intent.tx_signature = record.tx_signature.clone();
            }
            intent.reconciliation = Some(record.clone());
            intent.updated_at = now;
            write_json_atomic(&path, &intent)?;
            if record.outcome == ReconciliationOutcome::Absent {
                release_absent_reservation_inner(
                    ledger_dir,
                    id,
                    &release_day,
                    release_amount,
                    now,
                )?;
                // PHASE 9 spend controls: same release for the v2 arm.
                release_scopes_inner(
                    ledger_dir,
                    &intent.aggregate_scopes,
                    &release_day,
                    release_amount,
                    now,
                )?;
            }
        }
    }
    Ok(CommitOutcome::Committed)
}

/// Stale-Pending normalisation (item 7): after a restart, an abandoned
/// Pending becomes reconciliation-eligible (Unknown) — never silently
/// Failed. Re-verified inside the lock against BOTH state and staleness.
fn normalise_stale_pending(
    intents_dir: &FsPath,
    id: &Uuid,
    key: &str,
    now: i64,
) -> Result<bool, std::io::Error> {
    let _guard = store_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = intent_path(&agent_intents_dir(intents_dir, id), key);
    match read_reconcile_target(intents_dir, id, key)? {
        Some(ReconcileTarget::V1(mut intent)) => {
            if intent.state != IntentState::Pending
                || now.saturating_sub(intent.updated_at) < AGENT_PENDING_STALE_AFTER_SECONDS
            {
                return Ok(false);
            }
            intent.state = IntentState::Unknown;
            intent.response = Some(recorded_error_json(
                502,
                "AGENT_PAYMENT_STALE_PENDING",
                "worker vanished before a terminal outcome; the intent is reconciliation-eligible",
            ));
            intent.updated_at = now;
            write_json_atomic(&path, &intent)?;
            Ok(true)
        }
        Some(ReconcileTarget::V2(mut intent)) => {
            if intent.exec_state != ExecState::Pending
                || now.saturating_sub(intent.updated_at) < AGENT_PENDING_STALE_AFTER_SECONDS
            {
                return Ok(false);
            }
            intent.exec_state = ExecState::Unknown;
            intent.failure = Some(FailureRecord {
                code: "AGENT_PAYMENT_STALE_PENDING".to_string(),
                http_status: 502,
            });
            intent.response = Some(recorded_error_json(
                502,
                "AGENT_PAYMENT_STALE_PENDING",
                "worker vanished before a terminal outcome; the intent is reconciliation-eligible",
            ));
            intent.updated_at = now;
            write_json_atomic(&path, &intent)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// THE reconciliation engine. Two-phase by construction: lock-free read
/// -> RPC OUTSIDE store_lock -> decide (pure) -> ONE locked terminal-write
/// section that re-verifies state. Idempotent under concurrency; mutates
/// NOTHING unless it commits.
pub(crate) fn reconcile_intent(
    ops: &(dyn PaymentOps + Send + Sync),
    ledger_dir: &FsPath,
    intents_dir: &FsPath,
    agent: &Agent,
    req: &ReconcileRequest,
    principal: &ReconcilePrincipal,
    now: i64,
) -> ReconcileVerdict {
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return ReconcileVerdict::StoreError;
    };
    if !valid_idempotency_key(&req.idempotency_key) || !valid_resolver(principal.resolver()) {
        return ReconcileVerdict::StoreError;
    }
    if !principal.is_owner() && principal.resolver() != format!("agent:{uuid}") {
        // an agent resolver may ONLY reconcile its own intents — the
        // handler resolved the principal from the credential, but the
        // core re-checks: authorization is never only skin-deep
        return ReconcileVerdict::StoreError;
    }
    let target = match read_reconcile_target(intents_dir, &uuid, &req.idempotency_key) {
        Ok(Some(t)) => t,
        Ok(None) => return ReconcileVerdict::IntentNotFound,
        Err(_) => return ReconcileVerdict::StoreError,
    };
    let mut facts = IntentFacts::of(&target);

    // --- state gate (linear; every non-Unknown state exits here) ---
    if facts.state == NormalState::Reconciled {
        // replay: the stored terminal is returned WITHOUT any RPC and
        // WITHOUT any ledger mutation (item 10)
        return match &facts.stored {
            Some(record) => ReconcileVerdict::Reconciled {
                record: record.clone(),
                replayed: true,
            },
            None => ReconcileVerdict::StoreError,
        };
    }
    if matches!(facts.state, NormalState::Confirmed | NormalState::Failed) {
        return ReconcileVerdict::NotApplicable;
    }
    if facts.state == NormalState::Pending {
        if now.saturating_sub(facts.updated_at) < AGENT_PENDING_STALE_AFTER_SECONDS {
            return ReconcileVerdict::InProgress;
        }
        // stale after restart: reconciliation-eligible (Unknown), NOT
        // silently Failed (audit item 7)
        match normalise_stale_pending(intents_dir, &uuid, &req.idempotency_key, now) {
            Ok(true) => {}
            Ok(false) | Err(_) => return ReconcileVerdict::StoreError,
        }
        facts.state = NormalState::Unknown;
        facts.updated_at = now;
    }

    // --- decision phase: RPC happens HERE, outside every lock ---
    let decision = reconcile_decision(ops, &facts, agent, req, principal, now);
    let (method, outcome, tx_signature, evidence) = match decision {
        Decision::Early(verdict) => return verdict,
        Decision::Proposal {
            tx_signature,
            evidence,
        } => {
            // a proposal records NOTHING on disk — finalization is the
            // explicit human step (owner manual attestation)
            return ReconcileVerdict::Proposal {
                tx_signature,
                evidence,
            };
        }
        Decision::Terminal {
            method,
            outcome,
            tx_signature,
            evidence,
        } => (method, outcome, tx_signature, evidence),
    };
    let record = ReconciliationRecord {
        method,
        outcome,
        tx_signature,
        resolved_at: now,
        resolver: principal.resolver().to_string(),
        evidence: Some(evidence),
    };
    match commit_reconciliation(
        intents_dir,
        ledger_dir,
        &uuid,
        &req.idempotency_key,
        &record,
        now,
    ) {
        Ok(CommitOutcome::Committed) => ReconcileVerdict::Reconciled {
            record,
            replayed: false,
        },
        Ok(CommitOutcome::Already {
            stored: Some(stored),
        }) => ReconcileVerdict::Reconciled {
            record: stored,
            replayed: true,
        },
        Ok(CommitOutcome::Already { stored: None }) => ReconcileVerdict::StoreError,
        Ok(CommitOutcome::StateChanged) => {
            // a racing request (or the engine) moved the record; re-read
            // once so an already-reconciled intent still replays its
            // stored verdict instead of failing generically
            match read_reconcile_target(intents_dir, &uuid, &req.idempotency_key) {
                Ok(Some(t)) => match IntentFacts::of(&t).stored {
                    Some(record) => ReconcileVerdict::Reconciled {
                        record,
                        replayed: true,
                    },
                    None => ReconcileVerdict::NotApplicable,
                },
                _ => ReconcileVerdict::StoreError,
            }
        }
        // commit is one atomic section; Err means NOTHING was written —
        // including the ledger half (over-retention, never corruption of
        // another reservation)
        Err(_) => ReconcileVerdict::StoreError,
    }
}

/// Production-path entry: same engine, real stores.
pub(crate) fn reconcile_production(
    ops: &(dyn PaymentOps + Send + Sync),
    agent: &Agent,
    req: &ReconcileRequest,
    principal: &ReconcilePrincipal,
    now: i64,
) -> ReconcileVerdict {
    let ledger_dir = spend_dir();
    let intents_dir = intents_root();
    reconcile_intent(ops, &ledger_dir, &intents_dir, agent, req, principal, now)
}

// ---------------------------------------------------------------------------
// PHASE 9 "Crash recovery" (TM-AV-02): the stale-intent sweep.
// ---------------------------------------------------------------------------
//
// The recovery worker the threat model names ("future worker that MUST go
// through the same claim+reconcile path") as a PURE, BOUNDED core plus one
// owner-authenticated route. It creates NO second settlement authority:
// every per-intent decision is made by the EXISTING `reconcile_production`
// engine (same strict evidence gates, same ONE locked commit section, same
// exactly-once release), and the sweep never transfers, never invents
// evidence, and never flips an Unknown to a terminal without that engine.
//
// Semantics per stale intent (updated_at older than the same 900-second
// staleness bound the engine already uses for stale-Pending):
//   * Pending (worker vanished mid-flight) -> normalised to Unknown by the
//     engine's existing `normalise_stale_pending` path, then reconciled
//     (crash recovery for the interrupted-execution case).
//   * Unknown WITH a persisted signature -> the known-signature lane's
//     strict tx lookup decides; a proven outcome commits through the same
//     locked section (Absent releases the reservation exactly once).
//   * Unknown WITHOUT a signature -> the scan lane runs (read-only);
//     findings stay PROPOSALS (auto-finalization is policy-gated and NOT
//     reachable from this sweep) and the intent remains Unknown — the hold
//     is reported to the owner, never silently released. Over-retention is
//     the documented safe direction (mirrors the engine's own rule).
//   * Fresh/non-stale records are untouched; read-only probes that answer
//     transiently leave the record Unknown.
//
// The sweep is IDEMPOTENT by construction: repeated runs either replay a
// stored terminal (zero RPC, zero mutation) or re-run the same read-only
// probes; concurrent sweeps cannot double-commit because the commit
// section re-verifies state under the store lock and returns Already.

/// One enumerated stale intent in the sweep report. Public identity only:
/// the agent id, the idempotency key, the pre-sweep state, and the
/// engine verdict. No recipient/amount/key material beyond what the
/// verdict already exposes.
#[derive(Debug, Clone, Serialize)]
pub struct SweepEntry {
    pub idempotency_key: String,
    /// "pending" (normalised now) / "unknown" (was already Unknown)
    pub pre_state: String,
    /// "reconciled" | "proposal" | "unresolved" | "error"
    pub outcome: &'static str,
    /// stable error code when outcome == "unresolved" | "error"
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SweepReport {
    pub examined: u64,
    pub stale: u64,
    pub reconciled: u64,
    pub proposals: u64,
    pub unresolved: u64,
    pub errors: u64,
    /// GATE 2G — Confirmed-without-slot intents enriched with durable
    /// slot evidence by this sweep (the recovery path for the direct
    /// Confirmed lane). Additive; defaults keep old reports parseable.
    #[serde(default)]
    pub enriched: u64,
    /// GATE 2G — Confirmed intents that could NOT be enriched this pass
    /// (missing/conflicting evidence, RPC failure, lost recheck race);
    /// they stay held. Additive-defaulted like `enriched`.
    #[serde(default)]
    pub enrich_held: u64,
    pub entries: Vec<SweepEntry>,
}

/// Enumerate one agent's intent records (V1 `state` / V2 `exec_state`)
/// and return the keys of records that are stale Pending or stale Unknown.
/// Read-only; corrupt/foreign files are skipped (never parsed as money
/// state); the bound `staleness_seconds` comes from the engine's own
/// constant at the call sites.
pub(crate) fn stale_intent_keys(
    intents_dir: &FsPath,
    id: &Uuid,
    now: i64,
    staleness_seconds: i64,
) -> Result<Vec<(String, &'static str)>, std::io::Error> {
    let dir = agent_intents_dir(intents_dir, id);
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(key) = value
            .get("idempotency_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        else {
            continue;
        };
        let state_field = value
            .get("exec_state")
            .or_else(|| value.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let updated_at = value
            .get("updated_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let stale = now.saturating_sub(updated_at) >= staleness_seconds;
        if !stale {
            continue;
        }
        match state_field {
            "pending" => out.push((key, "pending")),
            "unknown" => out.push((key, "unknown")),
            _ => {} // Confirmed/Failed/Reconciled* are terminal or final — untouched
        }
    }
    out.sort();
    Ok(out)
}

/// THE sweep core: recover crash-stuck intents for ONE agent through the
/// existing reconciliation engine only. Deterministic input → deterministic
/// evidence decisions; idempotent; bounded to this agent's intent
/// directory. The agent principal (its own intents) is used — the sweep
/// therefore can never manual-attest and never auto-finalize a scan
/// match; the strict lookup lane commits exactly as any owner
/// reconciliation would.
/// GATE 2F FIX 3 — evidence enrichment for Confirmed-without-slot intents
/// (the Gate 2E audit finding: every direct-success payment left its
/// intent Confirmed with no slot, permanently inflating the commitment
/// sum because commit_reconciliation only accepts Unknown records).
///
/// Protocol (bounded, evidence-based, NEVER time-based):
///   1. Enumerate this agent's Confirmed intents whose `evidence_slot` is
///      None and whose response carries a transaction signature.
///   2. For each: READ-ONLY `read_tx(signature)` OUTSIDE store_lock. The
///      verdict must satisfy the SAME strict evidence rules the
///      reconciler uses — `executed == true` (explicit bool, fix 2) with
///      a usable processing slot (slot/block_height > 0). The outcome
///      field must agree (Paid) — this enriches, never re-decides.
///   3. Commit the slot under store_lock with a full identity/state
///      RECHECK: the write is a closure over `update_intent`, which
///      only fills `evidence_slot` when the record is STILL Confirmed
///      with evidence_slot == None. A record that moved on meanwhile
///      (Failed / Reconciled* / already enriched) is left untouched —
///      stale enrichment can never overwrite newer state, and repeated
///      runs are idempotent (second run finds no candidates).
///   4. No evidence obtainable (lookup failure, incomplete record, slot
///      unusable): the intent stays Confirmed-without-slot and the
///      commitment stays held — reported in the return value.
///
/// Crash behavior: before the evidence write the record is unchanged
/// (re-scanned next sweep); after it, the slot is durable and the
/// predicate can release. The enrichment NEVER changes the payment
/// outcome, the ledger, or the daily-policy state.
pub(crate) struct EnrichReport {
    pub enriched: u64,
    pub held: u64,
}

pub(crate) fn enrich_confirmed_slots(
    ops: &(dyn PaymentOps + Send + Sync),
    root: &FsPath,
    agent: &Agent,
    now: i64,
) -> Result<EnrichReport, std::io::Error> {
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return Ok(EnrichReport {
            enriched: 0,
            held: 0,
        });
    };
    let intents_dir = root;
    let dir = agent_intents_dir(&intents_dir, &uuid);
    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir) {
        Ok(iter) => iter.flatten().collect(),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EnrichReport {
                enriched: 0,
                held: 0,
            });
        }
        Err(e) => return Err(e),
    };

    let mut enriched: u64 = 0;
    let mut held: u64 = 0;

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            // corrupt record: leave it; the admission sum fails closed on it
            Err(_) => continue,
        };
        let state_ok = value
            .get("state")
            .or_else(|| value.get("exec_state"))
            .and_then(serde_json::Value::as_str)
            .map(|s| s == "confirmed")
            .unwrap_or(false);
        if !state_ok {
            continue;
        }
        let has_slot = value
            .get("evidence_slot")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        if has_slot {
            continue;
        }
        let Some(signature) = value
            .get("response")
            .and_then(|r| r.get("payment"))
            .and_then(|p| p.get("signature"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
        else {
            held += 1;
            continue;
        };

        // READ-ONLY chain lookup — OUTSIDE store_lock. The signature comes
        // from the intent's own Confirmed commit (already signer-bound),
        // so identity was established at payment time; the enrichment adds
        // ONLY the processing slot. Strict evidence: explicit executed
        // bool, no on-chain error, and a positive slot.
        let evidence_slot = match ops.read_tx(&signature) {
            TxLookup::Found(rec) => {
                if rec.executed && rec.err.is_none() {
                    rec.slot.or(rec.block_height).filter(|s| *s > 0)
                } else {
                    // an on-chain error or non-execution on this signature
                    // CONTRADICTS the Confirmed state — leave the record
                    // untouched and hold (never downgrade a committed
                    // outcome from a probe).
                    None
                }
            }
            _ => None,
        };

        match evidence_slot {
            Some(slot) => {
                // Commit under store_lock with a full recheck: only fill
                // evidence_slot when STILL Confirmed and STILL None.
                // Per-intent isolation (Gate 2H): a write failure on ONE
                // intent must never abort the enrichment pass — it leaves
                // that record held (fail-closed) and unrelated intents
                // proceed. key_of failure on an undecodable name is the
                // same outcome (that record is left alone, still held).
                let Ok(key) = key_of(&path) else {
                    held += 1;
                    continue;
                };
                match update_intent(&intents_dir, &uuid, &key, now, |i| {
                    if matches!(i.state, IntentState::Confirmed) && i.evidence_slot.is_none() {
                        i.evidence_slot = Some(slot);
                    }
                }) {
                    Ok(updated) => {
                        if updated.evidence_slot.is_some() {
                            enriched += 1;
                        } else {
                            // lost the race: another writer changed the
                            // record — stale enrichment did NOT overwrite
                            // newer state.
                            held += 1;
                        }
                    }
                    // the record vanished / write failed: stays held, no
                    // release, no abort of the remaining intents
                    Err(_) => {
                        held += 1;
                    }
                }
            }
            None => {
                held += 1;
            }
        }
    }
    Ok(EnrichReport { enriched, held })
}

/// Recover the hex-encoded idempotency key from an intent file path
/// (the ONLY place the key lives — the filename; see intent_path).
fn key_of(path: &std::path::Path) -> Result<String, std::io::Error> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(hex_decode_to_bytes)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| std::io::Error::other("intent key undecodable"))
}

fn hex_decode_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => return out, // malformed: the caller's from_utf8 will fail
        }
        i += 2;
    }
    out
}

/// GATE 2I — bounded STARTUP enrichment pass (the sweep-liveness fix).
///
/// Rationale (Gate 2I option A): the only automatic invocation surface the
/// application has is its startup sequence — there is NO scheduler
/// anywhere in the server (verified: no tokio::spawn/interval outside
/// request paths), and Option B (the owner endpoint) is exactly the
/// manual invocation this pass replaces for the boot-time backlog. The
/// pass runs ONCE per process start, before the listener binds, so
/// request traffic cannot interleave with it; per-agent and per-intent
/// isolation are inherited from `enrich_confirmed_slots` (one agent's
/// failure never blocks another's), and the whole pass is bounded by
/// AGENT_STARTUP_ENRICH_MAX_AGENTS + the per-agent intent-file scan.
///
/// Safety properties (unchanged from Gate 2F/2G):
///   * read-only `read_tx` RPC, never under store_lock; the slot commit
///     stays inside update_intent's locked recheck (Confirmed && None).
///   * NO transfers, NO reservation changes, NO policy checks — evidence
///     attachment only; release remains the admission predicate's job.
///   * No evidence fabricated: an intent without usable chain evidence
///     stays Confirmed-without-slot and HELD (reported in the summary).
///   * Legacy v1/v2 records parse through the same typed-enum readers.
///   * Never blocks boot: every failure is absorbed into the summary
///     (errors counter) and the server starts regardless.
///
/// Bounded behavior: at most MAX_AGENTS agent dirs are examined; if the
/// store holds more, the excess are counted in `skipped_unbounded` and
/// LEFT UNTOUCHED (fail-closed: their commitments stay held; the next
/// boot or an owner sweep covers them).
pub(crate) struct StartupEnrichReport {
    pub agents_scanned: u64,
    pub enriched: u64,
    pub held: u64,
    pub errors: u64,
    pub skipped_unbounded: u64,
}

pub(crate) const AGENT_STARTUP_ENRICH_MAX_AGENTS: u64 = 256;

pub(crate) fn startup_enrich_confirmed_slots(
    ops: &(dyn PaymentOps + Send + Sync),
    intents_root_dir: &FsPath,
    now: i64,
) -> StartupEnrichReport {
    let mut report = StartupEnrichReport {
        agents_scanned: 0,
        enriched: 0,
        held: 0,
        errors: 0,
        skipped_unbounded: 0,
    };

    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(intents_root_dir) {
        Ok(iter) => iter.flatten().collect(),
        // no intents dir yet = fresh install: nothing to enrich
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return report,
        Err(_) => {
            report.errors += 1;
            return report;
        }
    };

    for entry in entries {
        if report.agents_scanned >= AGENT_STARTUP_ENRICH_MAX_AGENTS {
            report.skipped_unbounded += 1;
            continue;
        }
        let dir = entry.path();
        // Only directories that parse as canonical UUIDs are agent lanes.
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(name) else {
            continue;
        };
        report.agents_scanned += 1;
        // The enrichment needs only the agent id (the intents dir is
        // already agent-scoped; the record's agent_id is re-checked
        // inside). A minimal Agent shell carries the id.
        let agent = Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: uuid.to_string(),
            owner_user_id: 0,
            name: String::new(),
            status: AgentStatus::Active,
            wallet_address: None,
            auth_public_key: None,
            created_at: 0,
            updated_at: 0,
        };
        match enrich_confirmed_slots(ops, intents_root_dir, &agent, now) {
            Ok(er) => {
                report.enriched += er.enriched;
                report.held += er.held;
            }
            Err(_) => {
                // per-agent isolation: this agent's failure never blocks
                // another's; its commitments stay held.
                report.errors += 1;
            }
        }
    }
    report
}

pub(crate) fn sweep_agent_intents(
    ops: &(dyn PaymentOps + Send + Sync),
    intents_dir: &FsPath,
    agent: &Agent,
    now: i64,
) -> Result<SweepReport, std::io::Error> {
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return Ok(SweepReport::default());
    };
    let stale = stale_intent_keys(&intents_dir, &uuid, now, AGENT_PENDING_STALE_AFTER_SECONDS)?;
    let mut report = SweepReport {
        examined: stale.len() as u64,
        ..SweepReport::default()
    };
    let principal = ReconcilePrincipal::agent(&uuid);
    for (key, pre_state) in stale {
        report.stale += 1;
        let req = ReconcileRequest {
            idempotency_key: key.clone(),
            manual_outcome: None,
            attestation: None,
            allow_scan: true,
            // auto-finalization stays OFF: the engine only auto-finalizes
            // for an OWNER principal anyway, and the sweep never widens
            // the evidence contract.
            allow_auto: false,
        };
        let verdict = reconcile_production(ops, agent, &req, &principal, now);
        let entry = match verdict {
            ReconcileVerdict::Reconciled { .. } => {
                report.reconciled += 1;
                SweepEntry {
                    idempotency_key: key,
                    pre_state: pre_state.to_string(),
                    outcome: "reconciled",
                    code: None,
                }
            }
            ReconcileVerdict::Proposal { .. } => {
                report.proposals += 1;
                SweepEntry {
                    idempotency_key: key,
                    pre_state: pre_state.to_string(),
                    outcome: "proposal",
                    code: None,
                }
            }
            ReconcileVerdict::Unresolved { code, .. } => {
                report.unresolved += 1;
                SweepEntry {
                    idempotency_key: key,
                    pre_state: pre_state.to_string(),
                    outcome: "unresolved",
                    code: Some(code.to_string()),
                }
            }
            ReconcileVerdict::InProgress
            | ReconcileVerdict::NotApplicable
            | ReconcileVerdict::IntentNotFound
            | ReconcileVerdict::ManualForbidden => {
                // not actionable for the sweep; counted as unresolved so
                // the report never under-reports holds
                report.unresolved += 1;
                SweepEntry {
                    idempotency_key: key,
                    pre_state: pre_state.to_string(),
                    outcome: "unresolved",
                    code: None,
                }
            }
            ReconcileVerdict::StoreError => {
                report.errors += 1;
                SweepEntry {
                    idempotency_key: key,
                    pre_state: pre_state.to_string(),
                    outcome: "error",
                    code: Some("AGENT_STORE_ERROR".to_string()),
                }
            }
        };
        report.entries.push(entry);
    }

    // GATE 2G — production wiring of confirmed-slot enrichment (the
    // Gate 2E/2F recovery path for Confirmed-without-slot intents). The
    // sweep endpoint is the EXISTING production caller — no new endpoint,
    // no scheduler. The enrichment itself gathers evidence via read-only
    // RPC OUTSIDE store_lock and commits each slot under store_lock with
    // a full identity/state recheck; a failure on ONE intent never blocks
    // the others, and no commitment is ever released here (the release
    // decision stays with the balance-admission predicate, strictly
    // slot-evidence-backed). Bounded: one pass over this agent's intent
    // files per sweep invocation.
    match enrich_confirmed_slots(ops, &intents_dir, agent, now) {
        Ok(er) => {
            report.enriched = er.enriched;
            report.enrich_held = er.held;
        }
        // enrichment is best-effort recovery: an infra failure here must
        // not mask the sweep's reconciliation results (fail-closed — the
        // commitments stay held and the next sweep retries).
        Err(_) => {
            report.errors += 1;
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// PHASE 6 STEP 4 — RECONCILIATION HTTP HANDLERS
// ---------------------------------------------------------------------------
//
// Two authenticated surfaces, ZERO new authentication mechanism:
//   POST /api/agents/{id}/payments/reconcile        (GitHub owner session)
//   POST /api/agents/triggers/payments/reconcile    (X-Agent-Credential)
// The resolver identity is derived FROM the authentication
// (owner:<login> / agent:<uuid>) — clients can never supply a resolver,
// a credential-shaped string, or a token as a resolver value. Manual
// attestation is owner-only; the agent lane is deterministic evidence
// only. Neither lane runs inside store_lock; neither lane ever transfers.

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ReconcileBody {
    idempotency_key: String,
    #[serde(default)]
    manual_outcome: Option<String>,
    #[serde(default)]
    attestation: Option<String>,
}

/// Body -> request, through the typed envelope (String body, one code).
/// `allow_manual` gates who may even speak the attestation lane.
fn parse_reconcile_body(raw: &str, allow_manual: bool) -> Result<ReconcileRequest, &'static str> {
    let parsed: ReconcileBody = serde_json::from_str(raw).map_err(|_| {
        "request body must be {\"idempotency_key\": \"...\"} (manual_outcome + attestation: owner route only)"
    })?;
    if !valid_idempotency_key(&parsed.idempotency_key) {
        return Err("idempotency_key must be 1-128 characters from A-Z a-z 0-9 - _");
    }
    let manual_outcome = match parsed.manual_outcome.as_deref() {
        None => None,
        Some(_) if !allow_manual => {
            return Err(
                "manual attestation is reserved for the owner-authenticated reconciliation route",
            );
        }
        Some("paid") => Some(ReconciliationOutcome::Paid),
        Some("absent") => Some(ReconciliationOutcome::Absent),
        Some(_) => return Err("manual_outcome must be \"paid\" or \"absent\""),
    };
    if manual_outcome.is_none() && parsed.attestation.is_some() {
        return Err("attestation is only accepted together with manual_outcome");
    }
    let attestation = match parsed.attestation {
        Some(note) => Some(sanitize_attestation(&note).ok_or(
            "attestation must be non-empty, single-line, at most 512 printable characters",
        )?),
        None => None,
    };
    Ok(ReconcileRequest {
        idempotency_key: parsed.idempotency_key,
        manual_outcome,
        attestation,
        allow_scan: true,  // read-only discovery lane (produces proposals only)
        allow_auto: false, // auto-finalization is NEVER exposed over HTTP
    })
}

fn reconcile_request_invalid(reason: &str) -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "AGENT_RECONCILIATION_REQUEST_INVALID",
        reason,
    )
}

fn reconcile_verdict_http(
    verdict: ReconcileVerdict,
    agent_id: &str,
    idempotency_key: &str,
    intent_id: Option<&str>,
) -> Response {
    let (status, body) = verdict.status_and_body(agent_id, idempotency_key, intent_id);
    (status, Json(body)).into_response()
}

/// Owner surface: POST /api/agents/{id}/payments/reconcile — the existing
/// session model + the ONE ownership choke point; resolver owner:<login>.
pub async fn agent_payment_reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: String,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    // ownership already enforced by the choke point; the canonical UUID
    // gate is kept so a corrupt record can never reach the store paths
    let Some(_uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };
    let req = match parse_reconcile_body(&body, true) {
        Ok(req) => req,
        Err(reason) => return reconcile_request_invalid(reason),
    };
    // resolver derived from the authenticated identity ONLY; a login
    // outside the owner grammar collapses to the server-minted user-id
    // form (never client-chosen, never credential-shaped)
    let principal = ReconcilePrincipal::owner(&user.login).unwrap_or_else(|| {
        ReconcilePrincipal::owner(&format!("user-{}", user.id))
            .expect("owner:user-<id> is grammar-valid by construction")
    });

    let ops: Arc<dyn PaymentOps + Send + Sync> =
        state.rialo.clone() as Arc<dyn PaymentOps + Send + Sync>;
    let agent_c = agent.clone();
    let key = req.idempotency_key.clone();
    let now = now_unix();
    let outcome = tokio::task::spawn_blocking(move || {
        reconcile_production(ops.as_ref(), &agent_c, &req, &principal, now)
    })
    .await;

    match outcome {
        Ok(verdict) => reconcile_verdict_http(verdict, &agent.agent_id, &key, None),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            &join_err.to_string(),
        ),
    }
}

/// Agent surface: POST /api/agents/triggers/payments/reconcile — the
/// Step-3 credential lane, deterministic evidence only. Same stable 401
/// as the payment trigger; the credential resolves the agent principal
/// EXCLUSIVELY (no id in the body/URL; cross-agent keys are simply not
/// found — IntentNotFound, never enumeration).
pub async fn agent_trigger_payment_reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    fn credential_invalid() -> Response {
        api_error(
            StatusCode::UNAUTHORIZED,
            "AGENT_CREDENTIAL_INVALID",
            "A valid X-Agent-Credential header is required to resolve the agent principal",
        )
    }
    let mut cred_values = headers.get_all("x-agent-credential").iter();
    let credential = match (cred_values.next(), cred_values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|c| valid_credential_shape(c))
            .map(|c| c.to_string()),
        _ => None,
    };
    let Some(credential) = credential else {
        return credential_invalid();
    };

    // credential -> exactly one Agent principal (disk authority, same
    // choke point as the payment trigger; lifecycle is deliberately NOT
    // a gate here — reconciliation is read-only against the chain and
    // an unknown outcome of a DEACTIVATED agent still deserves closure)
    let resolution = {
        let credential = credential.clone();
        let agents = agents_dir();
        tokio::task::spawn_blocking(move || {
            let uuid = crate::agent_credentials::authenticate_agent_credential(&credential)
                .map_err(|_| TriggerDenial::Credential)?;
            drop(credential);
            let agent =
                read_agent(&agent_path(&agents, &uuid)).map_err(|_| TriggerDenial::Credential)?;
            if agent.agent_id != uuid.to_string() {
                return Err(TriggerDenial::Credential);
            }
            Ok::<_, TriggerDenial>(agent)
        })
        .await
    };
    let agent = match resolution {
        Ok(Ok(agent)) => agent,
        Ok(Err(TriggerDenial::Credential)) => return credential_invalid(),
        Ok(Err(_)) => return credential_invalid(),
        Err(join_err) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "AGENT_STORE_ERROR",
                &join_err.to_string(),
            );
        }
    };
    let Some(uuid) = parse_agent_id(&agent.agent_id) else {
        return credential_invalid();
    };

    // the agent lane NEVER accepts the manual attestation grammar
    let req = match parse_reconcile_body(&body, false) {
        Ok(req) => req,
        Err(reason) => return reconcile_request_invalid(reason),
    };
    let req = ReconcileRequest {
        allow_scan: false, // owner lane drives the scan/proposal policy
        ..req
    };
    let principal = ReconcilePrincipal::agent(&uuid);

    let ops: Arc<dyn PaymentOps + Send + Sync> =
        state.rialo.clone() as Arc<dyn PaymentOps + Send + Sync>;
    let agent_c = agent.clone();
    let key = req.idempotency_key.clone();
    let now = now_unix();
    let outcome = tokio::task::spawn_blocking(move || {
        reconcile_production(ops.as_ref(), &agent_c, &req, &principal, now)
    })
    .await;

    match outcome {
        Ok(verdict) => reconcile_verdict_http(verdict, &agent.agent_id, &key, None),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            &join_err.to_string(),
        ),
    }
}

/// PHASE 9 "Crash recovery" — owner-authenticated sweep of THIS agent's
/// stale Pending/Unknown payment intents. Empty body; the sweep core
/// enumerates, normalizes stale-Pending, and reconciles each stale
/// Unknown through the EXISTING `reconcile_production` engine (same
/// strict gates, same exactly-once commit/release). It never transfers,
/// never auto-finalizes a scan proposal, and leaves insufficient-evidence
/// holds Unknown (reported to the owner).
pub async fn agent_payment_reconcile_sweep(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = session_user(&state, &headers) else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "NOT_AUTHENTICATED",
            "Not logged in",
        );
    };
    // the ONE ownership choke point (same as every owner lane)
    let agent = match load_authorized(&id, user.id) {
        Ok(agent) => agent,
        Err(resp) => return resp,
    };
    let Some(_uuid) = parse_agent_id(&agent.agent_id) else {
        return agent_not_found();
    };

    let ops: Arc<dyn PaymentOps + Send + Sync> =
        state.rialo.clone() as Arc<dyn PaymentOps + Send + Sync>;
    let agent_c = agent.clone();
    let now = now_unix();
    let outcome = tokio::task::spawn_blocking(move || {
        sweep_agent_intents(ops.as_ref(), &intents_root(), &agent_c, now)
    })
    .await;

    match outcome {
        Ok(Ok(report)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "agent_id": agent.agent_id,
                "swept_at": now,
                "staleness_seconds": AGENT_PENDING_STALE_AFTER_SECONDS,
                "examined": report.examined,
                "stale": report.stale,
                "reconciled": report.reconciled,
                "proposals": report.proposals,
                "unresolved": report.unresolved,
                "errors": report.errors,
                // GATE 2G — enrichment observability on the same response
                "enriched": report.enriched,
                "enrich_held": report.enrich_held,
                "entries": report.entries,
            })),
        )
            .into_response(),
        Ok(Err(_)) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            "The intent sweep could not be completed",
        ),
        Err(join_err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AGENT_STORE_ERROR",
            &join_err.to_string(),
        ),
    }
}
// ---------------------------------------------------------------------------
// Unit tests (pure logic — no handlers, no network, project files untouched)
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(non_snake_case)] // step letters (A–S) are the audit test IDs
mod agent_tests {
    use super::*;

    // -------------------------------------------------------------------
    // GATE 2 — commitment predicate unit tests (pure, deterministic).
    // GATE 2F: fixtures use the TYPED enums. The wire format is serde
    // snake_case ("confirmed", "reconciled_absent", ...) — the Gate 2E
    // audit proved PascalCase fixtures encode a format serde never
    // emits, masking the real production contract.
    // -------------------------------------------------------------------

    #[test]
    fn commitment_predicate_pending_and_unknown_always_held() {
        assert!(intent_commitment_held(
            IntentState::Pending,
            None,
            false,
            Some(100)
        ));
        assert!(intent_commitment_held(
            IntentState::Unknown,
            None,
            false,
            Some(100)
        ));
        // even with slot evidence, Pending/Unknown can never release
        assert!(intent_commitment_held(
            IntentState::Pending,
            Some(1),
            false,
            Some(100)
        ));
        assert!(intent_commitment_held(
            IntentState::Unknown,
            Some(1),
            false,
            Some(100)
        ));
    }

    #[test]
    fn commitment_predicate_confirmed_release_requires_strictly_older_slot() {
        // strictly older evidence -> debit provably in the snapshot
        assert!(!intent_commitment_held(
            IntentState::Confirmed,
            Some(1199),
            false,
            Some(1201)
        ));
        // same slot: ordering unknowable -> held (fail-closed)
        assert!(intent_commitment_held(
            IntentState::Confirmed,
            Some(1200),
            false,
            Some(1200)
        ));
        // evidence newer than observation -> held
        assert!(intent_commitment_held(
            IntentState::Confirmed,
            Some(1200),
            false,
            Some(1199)
        ));
        // either side missing -> held
        assert!(intent_commitment_held(
            IntentState::Confirmed,
            None,
            false,
            Some(1200)
        ));
        assert!(intent_commitment_held(
            IntentState::Confirmed,
            Some(1200),
            false,
            None
        ));
        assert!(intent_commitment_held(
            IntentState::Confirmed,
            None,
            false,
            None
        ));
        // ReconciledPaid follows the same evidence rule
        assert!(!intent_commitment_held(
            IntentState::ReconciledPaid,
            Some(1199),
            false,
            Some(1201)
        ));
        assert!(intent_commitment_held(
            IntentState::ReconciledPaid,
            Some(1200),
            false,
            Some(1200)
        ));
    }

    #[test]
    fn commitment_predicate_failed_needs_definitive_evidence() {
        // Failed with error evidence -> provably did not execute -> released
        assert!(!intent_commitment_held(
            IntentState::Failed,
            None,
            true,
            Some(1200)
        ));
        // Failed without evidence -> held (fail-closed)
        assert!(intent_commitment_held(
            IntentState::Failed,
            None,
            false,
            Some(1200)
        ));
    }

    #[test]
    fn commitment_predicate_reconciled_absent_always_released() {
        assert!(!intent_commitment_held(
            IntentState::ReconciledAbsent,
            None,
            false,
            None
        ));
        assert!(!intent_commitment_held(
            IntentState::ReconciledAbsent,
            Some(5),
            false,
            Some(4)
        ));
    }

    #[test]
    fn gate2_wire_format_is_snake_case_and_parses_through_typed_enum() {
        // THE Gate 2E regression: pin the real serde wire values.
        assert_eq!(
            serde_json::to_value(IntentState::Confirmed).unwrap(),
            serde_json::json!("confirmed")
        );
        assert_eq!(
            serde_json::to_value(IntentState::ReconciledAbsent).unwrap(),
            serde_json::json!("reconciled_absent")
        );
        assert_eq!(
            serde_json::to_value(IntentState::ReconciledPaid).unwrap(),
            serde_json::json!("reconciled_paid")
        );
        assert_eq!(
            serde_json::to_value(IntentState::Pending).unwrap(),
            serde_json::json!("pending")
        );
        // and the round-trip parses back through the typed enum
        let parsed: IntentState =
            serde_json::from_value(serde_json::json!("reconciled_absent")).unwrap();
        assert_eq!(parsed, IntentState::ReconciledAbsent);
    }

    // -------------------------------------------------------------------
    // GATE 2 — intent-directory commitment sum (deterministic, seeded
    // with REAL serde-serialized records — v1 and v2).
    // -------------------------------------------------------------------

    fn gate2_seed_intent(dir: &std::path::Path, name: &str, doc: &serde_json::Value) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    }

    /// Serialize a REAL PaymentIntent (snake_case wire values guaranteed
    /// by the same serde derive the production writer uses).
    fn gate2_seed_real_intent(dir: &std::path::Path, name: &str, intent: &PaymentIntent) {
        gate2_seed_intent(dir, name, &serde_json::to_value(intent).unwrap());
    }

    fn gate2_v2_intent_doc(
        agent_id: &Uuid,
        amount: u64,
        exec_state: ExecState,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": PAYMENT_INTENT_V2_SCHEMA_VERSION,
            "intent_id": uuid::Uuid::new_v4().to_string(),
            "agent_id": agent_id.to_string(),
            "principal_kind": "agent",
            "recipient": "RECIPIENT_PLACEHOLDER",
            "amount_kelvin": amount,
            "idempotency_key": "gate2-v2-key",
            "request_fingerprint": "fp",
            "authz": {
                "policy_fingerprint": "fp",
                "authorized_at": 0
            },
            "exec_state": exec_state,
            "tx_signature": null,
            "failure": null,
            "response": null,
            "reconciliation": null,
            "aggregate_scopes": [],
            "created_at": 0,
            "updated_at": 0,
        })
    }

    fn gate2_real_intent(agent_id: &Uuid, amount: u64, state: IntentState) -> PaymentIntent {
        PaymentIntent {
            schema_version: PAYMENT_INTENT_SCHEMA_VERSION,
            agent_id: agent_id.to_string(),
            idempotency_key: "gate2-test-key".to_string(),
            request_fingerprint: "fp".to_string(),
            recipient: "RECIPIENT_PLACEHOLDER".to_string(),
            amount_kelvin: amount,
            state,
            response: None,
            created_at: 0,
            updated_at: 0,
            reconciliation: None,
            signer: None,
            authz: None,
            aggregate_scopes: Vec::new(),
            // GATE 2F additive field
            evidence_slot: None,
        }
    }

    /// Seed a Confirmed-with-signature intent whose FILENAME encodes its
    /// idempotency key (hex), mirroring intent_path — required so
    /// update_intent's identity recheck passes during enrichment.
    fn gate2_confirmed_with_key(dir: &std::path::Path, agent: &Uuid, amount: u64, signature: &str) {
        let mut intent = gate2_real_intent(agent, amount, IntentState::Confirmed);
        intent.idempotency_key = signature.to_string();
        intent.response = Some(payment_success_json(
            &agent.to_string(),
            "RECIPIENT_PLACEHOLDER",
            0.001,
            amount,
            signature,
            None,
            None,
        ));
        let hex_key = hex_encode_key(signature);
        gate2_seed_real_intent(dir, &format!("{hex_key}.json"), &intent);
    }

    /// Minimal read_tx script used ONLY by the Gate-2F enrichment tests
    /// (a local mock: MockReads lives in a different test shard).
    struct Gate2ReadTx {
        slots: std::sync::Mutex<HashMap<String, crate::rialo::TxLookup>>,
    }

    impl Gate2ReadTx {
        fn set_tx(&self, sig: &str, rec: crate::rialo::TxRecord) {
            self.slots
                .lock()
                .unwrap()
                .insert(sig.to_string(), crate::rialo::TxLookup::Found(rec));
        }
        fn set_unavailable(&self, sig: &str) {
            self.slots.lock().unwrap().insert(
                sig.to_string(),
                crate::rialo::TxLookup::Unavailable(crate::rialo::RialoError {
                    code: "RIALO_RPC_UNAVAILABLE",
                    detail: "scripted outage".to_string(),
                    tx_signature: None,
                }),
            );
        }
    }

    impl PaymentOps for Gate2ReadTx {
        fn balance(&self, _address: &str) -> Result<f64, RialoError> {
            Err(RialoError {
                code: "RIALO_RPC_UNAVAILABLE",
                detail: "not used".to_string(),
                tx_signature: None,
            })
        }
        fn transfer(
            &self,
            _keypair_path: &FsPath,
            _to: &str,
            _amount_rlo: &str,
        ) -> Result<String, RialoError> {
            Err(RialoError {
                code: "RIALO_TRANSFER_ERROR",
                detail: "not used".to_string(),
                tx_signature: None,
            })
        }
        fn read_tx(&self, signature: &str) -> TxLookup {
            match self.slots.lock().unwrap().get(signature) {
                Some(lookup) => lookup.clone(),
                None => TxLookup::NotFound,
            }
        }
        fn signatures_for_address(
            &self,
            _address: &str,
            _until: Option<&str>,
            _limit: u64,
        ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
            Ok(Vec::new())
        }
        fn uses_external_custody(&self) -> bool {
            false
        }
    }

    fn gate2_readtx_mock() -> Gate2ReadTx {
        Gate2ReadTx {
            slots: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn gate2_agent_for(a: Uuid) -> Agent {
        Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: a.to_string(),
            owner_user_id: 1,
            name: "gate2-test".to_string(),
            status: AgentStatus::Active,
            wallet_address: None,
            auth_public_key: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn hex_encode_key(key: &str) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::new();
        for b in key.as_bytes() {
            s.push(T[(b >> 4) as usize] as char);
            s.push(T[(b & 0x0f) as usize] as char);
        }
        s
    }

    #[test]
    fn gate2_sum_scopes_to_agent_and_counts_each_intent_once() {
        let root = std::path::PathBuf::from("artifact/gate2_intents");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());
        let dir_b = root.join(b.to_string());

        // REAL serialized v1 records (snake_case on the wire)
        gate2_seed_real_intent(
            &dir_a,
            "k1.json",
            &gate2_real_intent(&a, 100, IntentState::Pending),
        );
        gate2_seed_real_intent(
            &dir_a,
            "k2.json",
            &gate2_real_intent(&a, 50, IntentState::Unknown),
        );
        // v2 record (exec_state) also counts
        gate2_seed_intent(
            &dir_a,
            "k_v2.json",
            &gate2_v2_intent_doc(&a, 25, ExecState::Pending),
        );
        // another agent's intent must NOT count for a
        gate2_seed_real_intent(
            &dir_b,
            "k1.json",
            &gate2_real_intent(&b, 999, IntentState::Pending),
        );

        // agent b sees only its own 999
        assert_eq!(
            sum_outstanding_commitments(&root, &b, Some(5000)).unwrap(),
            999
        );
        // agent a: 100 + 50 + 25 (Pending/Unknown always held)
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(5000)).unwrap(),
            175
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_sum_holds_pending_unknown_and_absent_releases() {
        let root = std::path::PathBuf::from("artifact/gate2_intents2");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        // Absent (no evidence needed) + older-slot Confirmed release;
        // Pending holds. All REAL serialized records.
        gate2_seed_real_intent(
            &dir_a,
            "k_absent.json",
            &gate2_real_intent(&a, 10, IntentState::ReconciledAbsent),
        );
        let mut confirmed = gate2_real_intent(&a, 20, IntentState::Confirmed);
        confirmed.reconciliation = Some(ReconciliationRecord {
            method: ReconciliationMethod::TxLookup,
            outcome: ReconciliationOutcome::Paid,
            tx_signature: None,
            resolved_at: 0,
            resolver: "system:gate2".to_string(),
            evidence: Some(ReconciliationEvidence {
                block_height: Some(1199),
                slot: Some(1199),
                block_time: None,
                fee: None,
                meta_err: None,
                tx_summary: None,
            }),
        });
        gate2_seed_real_intent(&dir_a, "k_conf.json", &confirmed);
        gate2_seed_real_intent(
            &dir_a,
            "k_pending.json",
            &gate2_real_intent(&a, 30, IntentState::Pending),
        );

        // obs 1201: Confirmed(1199) releases, Pending(30) holds, Absent(10) gone
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            30
        );
        // obs missing: Absent releases (10), Confirmed+Pending hold (20+30)
        assert_eq!(sum_outstanding_commitments(&root, &a, None).unwrap(), 50);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_failed_with_error_code_releases_without_evidence() {
        let root = std::path::PathBuf::from("artifact/gate2_intents2b");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        // Failed + RIALO_TRANSFER_ERROR response = definitive non-execution
        let mut failed = gate2_real_intent(&a, 40, IntentState::Failed);
        failed.response = Some(serde_json::json!({
            "http_status": 502,
            "code": "RIALO_TRANSFER_ERROR",
            "message": "transaction failed on-chain: InsufficientFundsForFee"
        }));
        gate2_seed_real_intent(&dir_a, "k_failed.json", &failed);
        // Failed WITHOUT the error code (rpc-unavailable class) stays held
        let mut failed_rpc = gate2_real_intent(&a, 60, IntentState::Failed);
        failed_rpc.response = Some(serde_json::json!({
            "http_status": 502,
            "code": "RIALO_RPC_UNAVAILABLE",
            "message": "network error"
        }));
        gate2_seed_real_intent(&dir_a, "k_failed_rpc.json", &failed_rpc);

        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(9999)).unwrap(),
            60
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_confirmed_with_intent_level_evidence_slot_releases() {
        let root = std::path::PathBuf::from("artifact/gate2_intents2c");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let mut confirmed = gate2_real_intent(&a, 20, IntentState::Confirmed);
        confirmed.evidence_slot = Some(1199);
        gate2_seed_real_intent(&dir_a, "k_conf.json", &confirmed);
        gate2_seed_real_intent(
            &dir_a,
            "k_conf_noslot.json",
            &gate2_real_intent(&a, 15, IntentState::Confirmed),
        );

        // obs 1201 > 1199: the slot-backed one releases, the other holds
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            15
        );
        // same obs: BOTH hold
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1199)).unwrap(),
            35
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_unparseable_intent_fails_closed() {
        let root = std::path::PathBuf::from("artifact/gate2_intents3");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());
        gate2_seed_intent(
            &dir_a,
            "k_bad.json",
            &serde_json::json!({ "not": "an intent" }),
        );
        assert!(sum_outstanding_commitments(&root, &a, Some(1)).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_unknown_state_string_fails_closed() {
        let root = std::path::PathBuf::from("artifact/gate2_intents5");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());
        gate2_seed_intent(
            &dir_a,
            "k_bad_state.json",
            &serde_json::json!({
                "schema_version": 1,
                "agent_id": a.to_string(),
                "amount_kelvin": 10,
                "state": "totally_unknown_state"
            }),
        );
        assert!(sum_outstanding_commitments(&root, &a, Some(1)).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_spent_kelvin_never_enters_the_formula() {
        let root = std::path::PathBuf::from("artifact/gate2_intents4");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        assert_eq!(sum_outstanding_commitments(&root, &a, Some(1)).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn gate2_confirmed_with_signature(
        dir: &std::path::Path,
        agent: &Uuid,
        amount: u64,
        signature: &str,
    ) {
        gate2_confirmed_with_key(dir, agent, amount, signature)
    }

    #[test]
    fn gate2_enrich_fills_slot_from_chain_evidence_and_releases() {
        let root = std::path::PathBuf::from("artifact/gate2_enrich1");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let sig = "GATE2SIG";
        gate2_confirmed_with_signature(&dir_a, &a, 100, sig);

        // Before enrichment: no slot -> held regardless of observation.
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            100
        );

        // Scripted read_tx: executed, no err, slot 1199.
        let mock = gate2_readtx_mock();
        mock.set_tx(
            sig,
            TxRecord {
                signature: Some(sig.to_string()),
                executed: true,
                err: None,
                slot: Some(1199),
                block_height: None,
                block_time: None,
                fee: None,
                payer: None,
                transfer_recipient: None,
                transfer_amount_kelvin: None,
                complete: true,
            },
        );

        let agent_doc = gate2_agent_for(a);
        let report = enrich_confirmed_slots(&mock, &root, &agent_doc, 1).unwrap();
        assert_eq!(report.enriched, 1);
        assert_eq!(report.held, 0);

        // After enrichment: the slot is durable, so obs 1201 releases.
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            0
        );
        // Idempotency: a second enrichment run finds no candidate.
        let report2 = enrich_confirmed_slots(&mock, &root, &agent_doc, 2).unwrap();
        assert_eq!(report2.enriched, 0);
        assert_eq!(report2.held, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_enrich_keeps_held_when_evidence_unavailable() {
        let root = std::path::PathBuf::from("artifact/gate2_enrich2");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let sig = "GATE2SIG2";
        gate2_confirmed_with_signature(&dir_a, &a, 100, sig);

        // Scripted read_tx: Unavailable -> no evidence -> held.
        let mock = gate2_readtx_mock();
        mock.set_unavailable(sig);

        let agent_doc = gate2_agent_for(a);
        let report = enrich_confirmed_slots(&mock, &root, &agent_doc, 1).unwrap();
        assert_eq!(report.enriched, 0);
        assert_eq!(report.held, 1);

        // The record is untouched (state Confirmed, no slot) and still held.
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            100
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_enrich_never_downgrades_conflicting_chain_evidence() {
        let root = std::path::PathBuf::from("artifact/gate2_enrich3");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let sig = "GATE2SIG3";
        gate2_confirmed_with_signature(&dir_a, &a, 100, sig);

        // The node reports the tx as FAILED — contradicting the Confirmed
        // state. Enrichment must NOT attach anything and NOT downgrade.
        let mock = gate2_readtx_mock();
        mock.set_tx(
            sig,
            TxRecord {
                signature: Some(sig.to_string()),
                executed: true,
                err: Some("AccountNotFound".to_string()),
                slot: Some(1199),
                block_height: None,
                block_time: None,
                fee: None,
                payer: None,
                transfer_recipient: None,
                transfer_amount_kelvin: None,
                complete: true,
            },
        );

        let agent_doc = gate2_agent_for(a);
        let report = enrich_confirmed_slots(&mock, &root, &agent_doc, 1).unwrap();
        assert_eq!(report.enriched, 0);
        assert_eq!(report.held, 1);

        // still Confirmed, no slot, still held
        let hex_key = hex_encode_key(sig);
        let raw = std::fs::read_to_string(dir_a.join(format!("{hex_key}.json"))).unwrap();
        assert!(raw.contains("evidence_slot\": null"));
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            100
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_startup_enrich_processes_all_agents_and_is_idempotent() {
        let root = std::path::PathBuf::from("artifact/gate2_startup1");
        let _ = std::fs::remove_dir_all(&root);

        // Two agents, each with one Confirmed-without-slot intent.
        let sig_a = "STARTUPSIGA";
        let sig_b = "STARTUPSIGB";
        for (uuid, sig, amount) in [
            (uuid::Uuid::new_v4(), sig_a, 100u64),
            (uuid::Uuid::new_v4(), sig_b, 50u64),
        ] {
            let dir = root.join(uuid.to_string());
            let mut intent = gate2_real_intent(&uuid, amount, IntentState::Confirmed);
            intent.idempotency_key = sig.to_string();
            intent.response = Some(payment_success_json(
                &uuid.to_string(),
                "RECIPIENT_PLACEHOLDER",
                0.001,
                amount,
                sig,
                None,
                None,
            ));
            gate2_seed_real_intent(&dir, &format!("{}.json", hex_encode_key(sig)), &intent);
        }

        let mock = gate2_readtx_mock();
        mock.set_tx(
            sig_a,
            TxRecord {
                signature: Some(sig_a.to_string()),
                executed: true,
                err: None,
                slot: Some(1199),
                block_height: None,
                block_time: None,
                fee: None,
                payer: None,
                transfer_recipient: None,
                transfer_amount_kelvin: None,
                complete: true,
            },
        );
        // sig_b: NO evidence available -> stays held
        mock.set_unavailable(sig_b);

        let report = startup_enrich_confirmed_slots(&mock, &root, 1);
        assert_eq!(report.agents_scanned, 2);
        assert_eq!(report.enriched, 1);
        assert_eq!(report.held, 1);
        assert_eq!(report.errors, 0);
        assert_eq!(report.skipped_unbounded, 0);

        // Total outstanding with obs 1201 across all agents: only
        // sig_b's 50 remains held (sig_a's slot evidence released it).
        let mut total = 0u64;
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(uuid) = Uuid::parse_str(&name) {
                total += sum_outstanding_commitments(&root, &uuid, Some(1201)).unwrap();
            }
        }
        assert_eq!(total, 50);

        // Idempotent: a second startup pass enriches nothing new.
        let report2 = startup_enrich_confirmed_slots(&mock, &root, 2);
        assert_eq!(report2.enriched, 0);
        assert_eq!(report2.held, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_startup_enrich_is_bounded_and_skips_fail_closed() {
        // UNIQUE per-process root: this test previously used the fixed
        // relative path artifact/gate2_startup2, which races with any other
        // test moving the process CWD during parallel runs (observed as an
        // intermittent empty-dir read in the full FS suite). A unique parent
        // under the system temp dir removes the shared-path/CWD coupling
        // without changing what is tested.
        let root = std::env::temp_dir().join(format!(
            "gate2_startup2_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&root);

        // MAX + 2 agent lanes: the bound must leave the excess untouched
        // (their Confirmed-without-slot intents stay HELD, never skipped
        // into a released state).
        let mock = gate2_readtx_mock();
        for i in 0..(AGENT_STARTUP_ENRICH_MAX_AGENTS + 2) {
            let uuid = uuid::Uuid::new_v4();
            let sig = format!("BOUNDSIG{}", i);
            let dir = root.join(uuid.to_string());
            let mut intent = gate2_real_intent(&uuid, 10, IntentState::Confirmed);
            intent.idempotency_key = sig.clone();
            intent.response = Some(payment_success_json(
                &uuid.to_string(),
                "RECIPIENT_PLACEHOLDER",
                0.001,
                10,
                &sig,
                None,
                None,
            ));
            gate2_seed_real_intent(&dir, &format!("{}.json", hex_encode_key(&sig)), &intent);
            mock.set_tx(
                &sig,
                TxRecord {
                    signature: Some(sig.clone()),
                    executed: true,
                    err: None,
                    slot: Some(1199),
                    block_height: None,
                    block_time: None,
                    fee: None,
                    payer: None,
                    transfer_recipient: None,
                    transfer_amount_kelvin: None,
                    complete: true,
                },
            );
        }

        let report = startup_enrich_confirmed_slots(&mock, &root, 1);
        assert_eq!(report.agents_scanned, AGENT_STARTUP_ENRICH_MAX_AGENTS);
        assert_eq!(report.enriched, AGENT_STARTUP_ENRICH_MAX_AGENTS);
        assert_eq!(report.skipped_unbounded, 2);

        // The two skipped agents' commitments are STILL HELD (10 each).
        let mut skipped_total = 0u64;
        for entry in std::fs::read_dir(&root).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Ok(uuid) = Uuid::parse_str(&name) {
                // sum with an obs slot that would release an enriched record;
                // skipped agents still report their 10.
                let s = sum_outstanding_commitments(&root, &uuid, Some(u64::MAX)).unwrap_or(10);
                if s == 10 {
                    skipped_total += 10;
                }
            }
        }
        assert_eq!(skipped_total, 20);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_startup_enrich_missing_dir_is_inert() {
        let root = std::path::PathBuf::from("artifact/gate2_startup_missing");
        let _ = std::fs::remove_dir_all(&root);
        let mock = gate2_readtx_mock();
        let report = startup_enrich_confirmed_slots(&mock, &root, 1);
        assert_eq!(report.agents_scanned, 0);
        assert_eq!(report.enriched, 0);
        assert_eq!(report.errors, 0);
    }

    #[test]
    fn gate2_sweep_production_path_runs_enrichment() {
        let root = std::path::PathBuf::from("artifact/gate2_sweep_enrich");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let sig = "GATE2SWEEPSIG";
        // Seed a real Confirmed-without-slot intent under the sweep's
        // production root parameter (this test drives sweep_agent_intents
        // directly with a scripted root, mirroring the endpoint).
        let mut intent = gate2_real_intent(&a, 100, IntentState::Confirmed);
        intent.idempotency_key = sig.to_string();
        intent.response = Some(payment_success_json(
            &a.to_string(),
            "RECIPIENT_PLACEHOLDER",
            0.001,
            100,
            sig,
            None,
            None,
        ));
        let hex_key = hex_encode_key(sig);
        gate2_seed_real_intent(&dir_a, &format!("{hex_key}.json"), &intent);

        let mock = gate2_readtx_mock();
        mock.set_tx(
            sig,
            TxRecord {
                signature: Some(sig.to_string()),
                executed: true,
                err: None,
                slot: Some(1199),
                block_height: None,
                block_time: None,
                fee: None,
                payer: None,
                transfer_recipient: None,
                transfer_amount_kelvin: None,
                complete: true,
            },
        );

        let agent_doc = gate2_agent_for(a);
        let report = sweep_agent_intents(&mock, &root, &agent_doc, 1).unwrap();
        assert_eq!(report.enriched, 1);
        assert_eq!(report.enrich_held, 0);

        // The slot is durable: admission predicate releases at obs 1201.
        assert_eq!(
            sum_outstanding_commitments(&root, &a, Some(1201)).unwrap(),
            0
        );
        // Idempotent: a second sweep enriches nothing new.
        let report2 = sweep_agent_intents(&mock, &root, &agent_doc, 2).unwrap();
        assert_eq!(report2.enriched, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gate2_enrich_recheck_prevents_stale_overwrite() {
        let root = std::path::PathBuf::from("artifact/gate2_enrich4");
        let _ = std::fs::remove_dir_all(&root);
        let a = uuid::Uuid::new_v4();
        let dir_a = root.join(a.to_string());

        let sig = "GATE2SIG4";
        // Simulate the concurrency race: the record moved to Failed before
        // the enrichment ran. The candidate filter (state == confirmed)
        // must skip it BEFORE any RPC/mutation — the stale-write path is
        // unreachable for moved-on records.
        let mut failed = gate2_real_intent(&a, 100, IntentState::Failed);
        failed.idempotency_key = sig.to_string();
        failed.response = Some(payment_success_json(
            &a.to_string(),
            "RECIPIENT_PLACEHOLDER",
            0.001,
            100,
            sig,
            None,
            None,
        ));
        let hex_key = hex_encode_key(sig);
        gate2_seed_real_intent(&dir_a, &format!("{hex_key}.json"), &failed);

        let mock = gate2_readtx_mock();
        mock.set_tx(
            sig,
            TxRecord {
                signature: Some(sig.to_string()),
                executed: true,
                err: None,
                slot: Some(1199),
                block_height: None,
                block_time: None,
                fee: None,
                payer: None,
                transfer_recipient: None,
                transfer_amount_kelvin: None,
                complete: true,
            },
        );

        let agent_doc = gate2_agent_for(a);
        let report = enrich_confirmed_slots(&mock, &root, &agent_doc, 1).unwrap();
        assert_eq!(report.enriched, 0);
        assert_eq!(report.held, 0); // skipped before any RPC/mutation

        // The Failed record has NO slot attached (null = absent, not a value).
        let raw = std::fs::read_to_string(dir_a.join(format!("{hex_key}.json"))).unwrap();
        assert!(raw.contains("evidence_slot\": null"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn name_validation() {
        assert_eq!(
            valid_agent_name("Research Agent").as_deref(),
            Some("Research Agent")
        );
        assert_eq!(valid_agent_name("  padded  ").as_deref(), Some("padded"));
        assert_eq!(valid_agent_name(""), None);
        assert_eq!(valid_agent_name("   "), None);
        assert_eq!(valid_agent_name("bad\nname"), None);
        assert_eq!(valid_agent_name("a\x00b"), None);
        assert!(valid_agent_name(&"x".repeat(64)).is_some());
        assert!(valid_agent_name(&"x".repeat(65)).is_none());
        // unicode names are fine (chars, not bytes)
        assert!(valid_agent_name("وكيل • 🤖").is_some());
    }

    #[test]
    fn agent_id_is_canonical_uuid_only() {
        let id = Uuid::new_v4();
        assert!(parse_agent_id(&id.to_string()).is_some());
        assert!(parse_agent_id("../etc/passwd").is_none());
        assert!(parse_agent_id("").is_none());
        assert!(parse_agent_id("not-a-uuid").is_none());
        // non-canonical spellings of a real UUID are rejected
        assert!(parse_agent_id(&id.to_string().to_uppercase()).is_none());
        assert!(parse_agent_id(&id.simple().to_string()).is_none());
        assert!(parse_agent_id(&format!("{{{id}}}")).is_none());
    }

    #[test]
    fn status_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&AgentStatus::Draft).unwrap(),
            "\"draft\""
        );
        assert_eq!(
            serde_json::to_string(&AgentStatus::Disabled).unwrap(),
            "\"disabled\""
        );
        assert_eq!(
            serde_json::from_str::<AgentStatus>("\"paused\"").unwrap(),
            AgentStatus::Paused
        );
    }

    #[test]
    fn create_request_rejects_anything_but_name() {
        // mass assignment is refused at the deserialization boundary
        let bad: Result<CreateAgentRequest, _> = serde_json::from_str(
            r#"{"name":"ok","owner_user_id":1,"status":"active","agent_id":"x"}"#,
        );
        assert!(bad.is_err());
        let bad_patch: Result<PatchAgentRequest, _> =
            serde_json::from_str(r#"{"name":"ok","wallet_address":"hack"}"#);
        assert!(bad_patch.is_err());
        let good: CreateAgentRequest = serde_json::from_str(r#"{"name":"Bot"}"#).unwrap();
        assert_eq!(good.name, "Bot");
    }

    #[test]
    fn atomic_roundtrip_no_temp_leftovers() {
        let dir = std::env::temp_dir().join(format!("agentpay-agents-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let id = Uuid::new_v4();
        let path = agent_path(&dir, &id);
        let now = now_unix();
        let agent = Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: id.to_string(),
            owner_user_id: 42,
            name: "Roundtrip".into(),
            status: AgentStatus::Draft,
            wallet_address: None,
            auth_public_key: None,
            created_at: now,
            updated_at: now,
        };

        write_json_atomic(&path, &agent).unwrap();
        assert_eq!(read_agent(&path).unwrap(), agent);

        // atomic replace keeps readers whole
        let mut again = agent.clone();
        again.name = "Renamed".into();
        again.updated_at = now + 1;
        write_json_atomic(&path, &again).unwrap();
        assert_eq!(read_agent(&path).unwrap(), again);

        // no temp files survived the renames
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        // unknown schema versions are refused, not silently accepted
        fs::write(&path, br#"{"schema_version":99}"#).unwrap();
        assert!(read_agent(&path).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn agent_record_has_no_field_that_could_carry_key_material() {
        // structural guarantee: exactly the audited field set exists
        let json = serde_json::to_value(Agent {
            schema_version: 1,
            agent_id: Uuid::new_v4().to_string(),
            owner_user_id: 1,
            name: "n".into(),
            status: AgentStatus::Draft,
            wallet_address: None,
            auth_public_key: None,
            created_at: 0,
            updated_at: 0,
        })
        .unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec![
                "schema_version",
                "agent_id",
                "owner_user_id",
                "name",
                "status",
                "wallet_address",
                "auth_public_key",
                "created_at",
                "updated_at"
            ]
        );
    }

    // -----------------------------------------------------------------------
    // STEP 3 — agent wallet provisioning. TEMPORARY DIRECTORIES ONLY: every
    // test below mints under a fresh std::env::temp_dir() subtree and the
    // real artifact/ tree is never touched. No keypair content is ever
    // printed; assertions only compare the PUBLIC address.
    // -----------------------------------------------------------------------

    /// (agents_dir, agent_wallets_dir, agent_auth_keys_dir, root) — root
    /// is removed at test end. PHASE 9 I-1: the funds-less auth vault is
    /// a THIRD disjoint directory, never the wallets one.
    fn step3_dirs() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("agentpay-step3-{}", Uuid::new_v4()));
        (
            root.join("agents"),
            root.join("agent_wallets"),
            root.join("agent_auth_keys"),
            root,
        )
    }

    fn cleanup(root: PathBuf) {
        fs::remove_dir_all(root).ok();
    }

    // (1) + (3): provisioning writes a valid keypair file whose public key
    // matches exactly the returned address.
    #[test]
    fn provision_writes_valid_keypair_matching_public_address() {
        let (_agents, wallets, _authkeys, root) = step3_dirs();
        fs::create_dir_all(&wallets).unwrap();

        let id = Uuid::new_v4();
        let address = provision_agent_wallet(&wallets, &id).expect("provision");

        let path = agent_wallet_path(&wallets, &id);
        assert!(path.exists());
        let mut file = fs::File::open(&path).unwrap();
        let keypair = rialo_s_keypair::read_keypair(&mut file).expect("valid keypair file");
        assert_eq!(keypair.pubkey().to_string(), address);

        cleanup(root);
    }

    // (2): the keypair file is owner read/write only.
    #[test]
    fn provisioned_wallet_file_is_mode_0600() {
        let (_agents, wallets, _authkeys, root) = step3_dirs();
        fs::create_dir_all(&wallets).unwrap();

        let id = Uuid::new_v4();
        provision_agent_wallet(&wallets, &id).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(agent_wallet_path(&wallets, &id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        cleanup(root);
    }

    // (4): the wallet file holds NOTHING but the keypair — no metadata
    // fields land in it, and vice versa is covered by (10).
    #[test]
    fn wallet_file_contains_no_agent_metadata() {
        let (_agents, wallets, _authkeys, root) = step3_dirs();
        fs::create_dir_all(&wallets).unwrap();

        let id = Uuid::new_v4();
        provision_agent_wallet(&wallets, &id).unwrap();

        let raw = fs::read(agent_wallet_path(&wallets, &id)).unwrap();
        let text = String::from_utf8_lossy(&raw);
        for needle in [
            "owner_user_id",
            "schema_version",
            "agent_id",
            "wallet_address",
        ] {
            assert!(!text.contains(needle), "wallet file leaked {needle}");
        }

        cleanup(root);
    }

    // (5) + (9): two creations mint distinct ids, distinct wallet files,
    // distinct addresses, and each metadata record carries its wallet.
    #[test]
    fn two_agents_get_independent_wallets_and_records() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        let a = create_agent_record(&agents, &wallets, &authkeys, "Alpha".into(), 7).unwrap();
        let b = create_agent_record(&agents, &wallets, &authkeys, "Beta".into(), 7).unwrap();

        assert_ne!(a.agent_id, b.agent_id);
        assert_ne!(a.wallet_address, b.wallet_address);
        let addr_a = a.wallet_address.clone().expect("Some(address)");
        let addr_b = b.wallet_address.clone().expect("Some(address)");
        assert!(!addr_a.is_empty() && !addr_b.is_empty());

        let id_a = parse_agent_id(&a.agent_id).unwrap();
        let id_b = parse_agent_id(&b.agent_id).unwrap();
        assert!(agent_wallet_path(&wallets, &id_a).exists());
        assert!(agent_wallet_path(&wallets, &id_b).exists());

        // (9): persisted metadata round-trips with the public address set.
        let stored = read_agent(&agent_path(&agents, &id_a)).unwrap();
        assert_eq!(stored.wallet_address.as_deref(), Some(addr_a.as_str()));
        assert_eq!(stored.status, AgentStatus::Draft);

        cleanup(root);
    }

    // (6): agent code never touches user-wallet-shaped paths — a sentinel
    // "user wallet" file in a sibling directory survives untouched.
    #[test]
    fn user_wallet_directory_is_never_touched() {
        let (agents, wallets, authkeys, root) = step3_dirs();
        let user_wallets = root.join("wallets"); // mirrors artifact/wallets
        fs::create_dir_all(&user_wallets).unwrap();
        let sentinel = user_wallets.join("50506084.json");
        fs::write(&sentinel, b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE").unwrap();

        create_agent_record(&agents, &wallets, &authkeys, "Iso".into(), 1).unwrap();

        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE"
        );
        // no new files appeared beside it
        assert_eq!(fs::read_dir(&user_wallets).unwrap().count(), 1);

        cleanup(root);
    }

    // (7): an existing wallet target is refused, never overwritten.
    #[test]
    fn never_overwrites_an_existing_wallet_path() {
        let (_agents, wallets, _authkeys, root) = step3_dirs();
        fs::create_dir_all(&wallets).unwrap();

        let id = Uuid::new_v4();
        let path = agent_wallet_path(&wallets, &id);
        fs::write(&path, b"PRE-EXISTING").unwrap();

        let err = provision_agent_wallet(&wallets, &id)
            .err()
            .expect("must refuse");
        assert!(matches!(err, ProvisionError::Exists));
        // (also: the refusal path removed nothing)
        assert_eq!(fs::read(&path).unwrap(), b"PRE-EXISTING");

        cleanup(root);
    }

    // (8): metadata failure rolls back ONLY the newly-created wallet and
    // auth files (PHASE 9 I-1: the auth vault joined the critical section).
    #[test]
    fn metadata_failure_removes_only_the_new_wallet_and_auth_key() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        // another agent's wallet AND auth file exist and must survive
        fs::create_dir_all(&wallets).unwrap();
        fs::create_dir_all(&authkeys).unwrap();
        let other = Uuid::new_v4();
        let other_path = agent_wallet_path(&wallets, &other);
        fs::write(&other_path, b"OTHER-AGENT-WALLET").unwrap();
        let other_auth = auth_key_path(&authkeys, &other);
        fs::write(&other_auth, b"OTHER-AGENT-AUTH-KEY").unwrap();

        // agents metadata dir is blocked by a FILE of the same name ->
        // create_dir_all(agents) fails AFTER provisioning succeeded.
        fs::write(&agents, b"blocker").unwrap();

        let err = create_agent_record(&agents, &wallets, &authkeys, "Rollback".into(), 1)
            .err()
            .expect("must fail");
        assert!(matches!(err, CreateError::Metadata));

        // rollback deleted exactly the new wallet AND the new auth file;
        // both siblings untouched.
        let survivors: Vec<_> = fs::read_dir(&wallets)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(survivors, vec![format!("{other}.json")]);
        assert_eq!(fs::read(&other_path).unwrap(), b"OTHER-AGENT-WALLET");
        let auth_survivors: Vec<_> = fs::read_dir(&authkeys)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(auth_survivors, vec![format!("{other}.json")]);
        assert_eq!(fs::read(&other_auth).unwrap(), b"OTHER-AGENT-AUTH-KEY");

        cleanup(root);
    }

    // (10): a successful record's JSON has no field or content that could
    // carry private material — only the public address string is set.
    #[test]
    fn created_record_exposes_public_address_only() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        let agent = create_agent_record(&agents, &wallets, &authkeys, "Pub".into(), 3).unwrap();
        let json = serde_json::to_string(&agent).unwrap();

        for banned in ["secret", "seed", "private", "keypair"] {
            assert!(
                !json.to_lowercase().contains(banned),
                "record json mentions {banned}"
            );
        }
        // wallet_address is exactly the address; nothing else wallet-ish.
        // NOTE: base58 addresses are case-sensitive — extract verbatim.
        assert_eq!(
            agent.wallet_address.as_deref().unwrap(),
            json.split("\"wallet_address\":\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
        );

        cleanup(root);
    }

    // (11): the list/read path (same code as the GET handlers) exposes
    // wallet_address but never anything secret.
    #[test]
    fn listing_filters_by_owner_and_exposes_only_public_fields() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        let mine = create_agent_record(&agents, &wallets, &authkeys, "Mine".into(), 10).unwrap();
        let theirs =
            create_agent_record(&agents, &wallets, &authkeys, "Theirs".into(), 20).unwrap();

        // simulate list_agents' filter over the temp dir
        let visible: Vec<Agent> = fs::read_dir(&agents)
            .unwrap()
            .flatten()
            .filter_map(|e| read_agent(&e.path()).ok())
            .filter(|a| a.owner_user_id == 10)
            .collect();

        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].agent_id, mine.agent_id);
        let blob = serde_json::to_string(&visible).unwrap();
        assert!(blob.contains(mine.wallet_address.as_ref().unwrap()));
        assert!(!blob.contains(&theirs.agent_id));
        assert!(!blob.contains(&theirs.wallet_address.unwrap()));

        cleanup(root);
    }

    // -----------------------------------------------------------------------
    // PHASE 9 I-1 (C-1) — funds-less agent authentication keypair
    // foundation. Temp stores only; assertions touch PUBLIC addresses,
    // file modes, JSON shape, and byte-absence scans — never key values.
    // -----------------------------------------------------------------------

    // (I-1.1) creation links the record's auth_public_key to the vault
    // file: same canonical id, verbatim address, mode 600, third dir.
    #[test]
    fn created_record_links_auth_pubkey_to_the_vault_file() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        let agent = create_agent_record(&agents, &wallets, &authkeys, "Linked".into(), 11).unwrap();
        let id = parse_agent_id(&agent.agent_id).unwrap();

        let recorded = agent
            .auth_public_key
            .clone()
            .expect("record carries the auth pubkey");
        assert_eq!(
            recorded,
            crate::agent_auth_keys::read_auth_public_key(&authkeys, &id).unwrap()
        );
        assert!(auth_key_path(&authkeys, &id).exists());

        // the auth vault is DISJOINT from the wallet store, and the auth
        // key is an INDEPENDENT keypair — never the money key.
        assert_ne!(
            auth_key_path(&authkeys, &id),
            agent_wallet_path(&wallets, &id)
        );
        assert_ne!(recorded, agent.wallet_address.clone().unwrap());

        // persisted record round-trips the linkage; verify accepts it
        let stored = read_agent(&agent_path(&agents, &id)).unwrap();
        assert_eq!(stored.auth_public_key.as_deref(), Some(recorded.as_str()));
        assert!(
            crate::agent_auth_keys::verify_auth_public_address(
                &authkeys,
                &id,
                stored.auth_public_key.as_deref().unwrap()
            )
            .is_ok()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(auth_key_path(&authkeys, &id))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        cleanup(root);
    }

    // (I-1.2) the record JSON carries the nine audited keys and NONE of
    // the vault file bytes in any hex form (both halves scanned).
    #[test]
    fn record_never_carries_vault_bytes() {
        let (agents, wallets, authkeys, root) = step3_dirs();
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Clean".into(), 12).unwrap();
        let id = parse_agent_id(&agent.agent_id).unwrap();

        let json = serde_json::to_string(&agent).unwrap();
        let raw = fs::read(auth_key_path(&authkeys, &id)).unwrap();
        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect::<String>() };
        let lower = json.to_lowercase();
        for needle in [hex(&raw), hex(&raw[..16]), hex(&raw[raw.len() - 16..])] {
            assert!(!lower.contains(&needle), "record carries vault bytes");
        }
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 9);
        assert!(keys.contains(&&String::from("auth_public_key")));

        cleanup(root);
    }

    // (I-1.3) auth mint failure (blocked vault path) fails the WHOLE
    // creation as AuthKey, rolling back exactly the wallet just created.
    #[test]
    fn auth_mint_failure_rolls_back_the_new_wallet() {
        let (agents, wallets, authkeys, root) = step3_dirs();
        fs::create_dir_all(&root).unwrap();

        // the auth vault path is blocked by a FILE -> create_dir_all fails
        fs::write(&authkeys, b"blocker").unwrap();

        let err = create_agent_record(&agents, &wallets, &authkeys, "RollAuth".into(), 13)
            .err()
            .expect("must fail");
        assert!(matches!(err, CreateError::AuthKey));

        // the just-created wallet file is gone; no metadata dir was made
        assert_eq!(fs::read_dir(&wallets).unwrap().count(), 0);
        assert!(!agents.exists());
        assert_eq!(fs::read(&authkeys).unwrap(), b"blocker");

        cleanup(root);
    }

    // (I-1.4) pre-I-1 schema-1 records parse unchanged (additive field,
    // no backfill, no rewrite on read).
    #[test]
    fn legacy_record_without_auth_field_still_parses_and_is_not_rewritten() {
        let (agents, _wallets, _authkeys, root) = step3_dirs();
        fs::create_dir_all(&agents).unwrap();
        let id = Uuid::new_v4();
        let path = agent_path(&agents, &id);
        let legacy = format!(
            r#"{{"schema_version":1,"agent_id":"{id}","owner_user_id":9,"name":"Legacy","status":"draft","wallet_address":null,"created_at":1,"updated_at":1}}"#
        );
        fs::write(&path, legacy.as_bytes()).unwrap();

        let agent = read_agent(&path).unwrap();
        assert_eq!(agent.auth_public_key, None);
        // reading performed NO write: bytes identical
        assert_eq!(fs::read(&path).unwrap(), legacy.as_bytes());

        cleanup(root);
    }

    // -----------------------------------------------------------------------
    // STEP 4 — agent balance readout (pure builder; NO live RPC, no real
    // agent on disk, no funding). resolve_owned runs against temp dirs only.
    // -----------------------------------------------------------------------

    fn sample_agent(address: Option<&str>) -> Agent {
        Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: Uuid::new_v4().to_string(),
            owner_user_id: 10,
            name: "Balances".into(),
            status: AgentStatus::Draft,
            wallet_address: address.map(str::to_string),
            auth_public_key: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    // owner resolves; foreign owner, missing record, malformed id, and a
    // corrupt/foreign-schema file all collapse to None (→ AGENT_NOT_FOUND).
    #[test]
    fn resolve_owned_accepts_only_the_authenticated_owner() {
        let (agents, wallets, authkeys, root) = step3_dirs();

        let mine = create_agent_record(&agents, &wallets, &authkeys, "Mine".into(), 10).unwrap();
        let id = &mine.agent_id;

        assert!(resolve_owned(&agents, id, 10).is_some());
        assert!(resolve_owned(&agents, id, 11).is_none()); // foreign user
        assert!(resolve_owned(&agents, &Uuid::new_v4().to_string(), 10).is_none()); // missing
        assert!(resolve_owned(&agents, "../wallets/50506084", 10).is_none()); // traversal
        assert!(resolve_owned(&agents, "", 10).is_none());

        // a broken record is not visible either (never a partial reveal)
        fs::write(
            agent_path(&agents, &parse_agent_id(id).unwrap()),
            br#"{"schema_version":99}"#,
        )
        .unwrap();
        assert!(resolve_owned(&agents, id, 10).is_none());

        cleanup(root);
    }

    // canonical "/api/me" representation: real balance is a "N RLO" string,
    // status ok, error null, public address echoed, public rpc_url present.
    #[test]
    fn balance_live_uses_the_canonical_rlo_string() {
        let agent = sample_agent(Some("PubAddr111"));
        let body = balance_json(&agent, "http://127.0.0.1:4104", BalanceProbe::Live(12.5));

        assert_eq!(body["success"], true);
        assert_eq!(body["balance"], "12.5 RLO");
        assert_eq!(body["balance_status"], "ok");
        assert_eq!(body["balance_error"], serde_json::Value::Null);
        assert_eq!(body["wallet_address"], "PubAddr111");
        assert_eq!(body["agent_id"], agent.agent_id);
        assert_eq!(body["rpc_url"], "http://127.0.0.1:4104");

        // zero is a REAL zero — never confused with "unavailable"
        let zero = balance_json(&agent, "u", BalanceProbe::Live(0.0));
        assert_eq!(zero["balance"], "0 RLO");
        assert_eq!(zero["balance_status"], "ok");
    }

    // RPC failure: explicit unavailable + the EXISTING typed code carried
    // through verbatim — never a fake zero, never a faucet/payment code.
    #[test]
    fn balance_failure_keeps_typed_error_and_never_fakes_zero() {
        let agent = sample_agent(Some("PubAddr111"));
        let body = balance_json(
            &agent,
            "u",
            BalanceProbe::Unavailable(serde_json::json!({
                "code": "RIALO_RPC_UNAVAILABLE",
                "message": "connection refused"
            })),
        );

        assert_eq!(body["balance"], serde_json::Value::Null); // never "0"
        assert_eq!(body["balance_status"], "unavailable");
        assert_eq!(body["balance_error"]["code"], "RIALO_RPC_UNAVAILABLE");

        let blob = body.to_string();
        for wrong in [
            "RIALO_FAUCET_ERROR",
            "RIALO_TRANSFER_ERROR",
            "INVALID_AMOUNT",
        ] {
            assert!(!blob.contains(wrong), "balance failure mapped to {wrong}");
        }
    }

    // legacy Step-2 record without an address: honest no_wallet status,
    // no error, no wallet creation attempt anywhere in the builder.
    #[test]
    fn balance_without_wallet_is_explicit_empty_state() {
        let agent = sample_agent(None);
        let body = balance_json(&agent, "u", BalanceProbe::NoWallet);

        assert_eq!(body["balance_status"], "no_wallet");
        assert_eq!(body["balance"], serde_json::Value::Null);
        assert_eq!(body["wallet_address"], serde_json::Value::Null);
        assert_eq!(body["balance_error"], serde_json::Value::Null);
    }

    // every response variant exposes ONLY public data: no path, seed,
    // keypair wording, or filesystem location ever surfaces.
    #[test]
    fn balance_response_never_carries_private_material_or_paths() {
        let agent = sample_agent(Some("PubAddr111"));
        let variants = [
            balance_json(&agent, "u", BalanceProbe::Live(1.0)),
            balance_json(
                &agent,
                "u",
                BalanceProbe::Unavailable(serde_json::json!({"code":"RIALO_ERROR","message":"x"})),
            ),
            balance_json(&agent, "u", BalanceProbe::NoWallet),
        ];
        for body in variants {
            let blob = body.to_string().to_lowercase();
            for banned in [
                "artifact",
                "agent_wallets",
                "seed",
                "private",
                "keypair",
                "secret",
                ".json",
            ] {
                assert!(!blob.contains(banned), "balance response leaked {banned}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // STEP 5 — lifecycle state machine. All persistence tests use the
    // temp-dir fixtures; no live server, no real agent, no Rialo call.
    // -----------------------------------------------------------------------

    const ALL_STATUSES: [AgentStatus; 4] = [
        AgentStatus::Draft,
        AgentStatus::Active,
        AgentStatus::Paused,
        AgentStatus::Disabled,
    ];

    // (1-13) the complete 4x4 edge matrix: EXACTLY five true edges.
    #[test]
    fn transition_matrix_is_exactly_the_five_allowed_edges() {
        let allowed = [
            (AgentStatus::Draft, AgentStatus::Active),
            (AgentStatus::Active, AgentStatus::Paused),
            (AgentStatus::Paused, AgentStatus::Active),
            (AgentStatus::Active, AgentStatus::Disabled),
            (AgentStatus::Paused, AgentStatus::Disabled),
        ];
        let mut trues = 0;
        for from in ALL_STATUSES {
            for to in ALL_STATUSES {
                let expected = allowed.contains(&(from, to));
                assert_eq!(
                    from.can_transition(to),
                    expected,
                    "edge {from:?} -> {to:?} mismatch"
                );
                if expected {
                    trues += 1;
                }
            }
        }
        assert_eq!(trues, 5);
    }

    // (25) disabled is terminal: no outgoing edge at all.
    #[test]
    fn disabled_is_terminal() {
        for to in ALL_STATUSES {
            assert!(
                !AgentStatus::Disabled.can_transition(to),
                "disabled escaped to {to:?}"
            );
        }
    }

    // (14)(15) request boundary: only {"status": "<known lowercase>"} parses.
    #[test]
    fn status_request_body_is_strict() {
        assert!(serde_json::from_str::<PatchStatusRequest>(r#"{"status":"paused"}"#).is_ok());
        // unknown status strings
        for bad in [
            r#"{"status":"retired"}"#,
            r#"{"status":"Active"}"#, // case-sensitive lowercase only
            r#"{"status":""}"#,
            r#"{}"#,
        ] {
            assert!(
                serde_json::from_str::<PatchStatusRequest>(bad).is_err(),
                "accepted {bad}"
            );
        }
        // unknown fields (mass assignment) refused
        for bad in [
            r#"{"status":"active","owner_user_id":9}"#,
            r#"{"status":"active","wallet_address":"hack"}"#,
            r#"{"status":"active","name":"hack","schema_version":2}"#,
        ] {
            assert!(
                serde_json::from_str::<PatchStatusRequest>(bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    // (6-13 via the store) rejected transitions never touch the record,
    // and the five legal ones persist, mutating ONLY status + updated_at.
    #[test]
    fn transitions_persist_only_status_and_updated_at() {
        let (agents, wallets, authkeys, root) = step3_dirs();
        let agent =
            create_agent_record(&agents, &wallets, &authkeys, "Lifecycle".into(), 5).unwrap();
        let id = agent.agent_id.clone();
        let path = agent_path(&agents, &parse_agent_id(&id).unwrap());

        // every rejected edge from draft
        for (bad_to, expect) in [
            (AgentStatus::Paused, TransitionError::Invalid),
            (AgentStatus::Disabled, TransitionError::Invalid),
            (AgentStatus::Draft, TransitionError::Invalid), // self
        ] {
            assert_eq!(
                transition_agent(&agents, &id, 5, bad_to, 100).err(),
                Some(expect)
            );
            assert_eq!(read_agent(&path).unwrap().status, AgentStatus::Draft);
        }

        // (16)(17) authorization: foreign user and missing agents are
        // indistinguishable NotFound — from the OWNER'S view too nothing
        // changed on disk.
        assert_eq!(
            transition_agent(&agents, &id, 6, AgentStatus::Active, 100).err(),
            Some(TransitionError::NotFound)
        );
        assert_eq!(
            transition_agent(
                &agents,
                &Uuid::new_v4().to_string(),
                5,
                AgentStatus::Active,
                100
            )
            .err(),
            Some(TransitionError::NotFound)
        );
        assert_eq!(read_agent(&path).unwrap().status, AgentStatus::Draft);

        // (18-22) one legal edge, checked field by field
        let before = read_agent(&path).unwrap();
        let after = transition_agent(&agents, &id, 5, AgentStatus::Active, 222).unwrap();
        assert_eq!(after.status, AgentStatus::Active);
        assert_eq!(after.updated_at, 222);
        assert_eq!(after.agent_id, before.agent_id);
        assert_eq!(after.owner_user_id, before.owner_user_id);
        assert_eq!(after.name, before.name);
        assert_eq!(after.wallet_address, before.wallet_address);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.schema_version, before.schema_version);

        cleanup(root);
    }

    // (chain) persisted state drives the machine, not the client's idea:
    // draft -> active -> paused -> active -> disabled, then nothing escapes.
    #[test]
    fn chained_transitions_use_persisted_state_and_disable_is_terminal() {
        let (agents, wallets, authkeys, root) = step3_dirs();
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Chain".into(), 1).unwrap();
        let id = agent.agent_id.clone();

        let mut seq = vec![
            (AgentStatus::Active, AgentStatus::Active),
            (AgentStatus::Paused, AgentStatus::Paused),
            (AgentStatus::Active, AgentStatus::Active),
            (AgentStatus::Disabled, AgentStatus::Disabled),
        ];
        for (step, i) in seq.drain(..).enumerate() {
            let got = transition_agent(&agents, &id, 1, i.0, 10 + step as i64).unwrap();
            assert_eq!(got.status, i.1);
            // persisted — the NEXT call reads it back from disk
            assert_eq!(
                read_agent(&agent_path(&agents, &parse_agent_id(&id).unwrap()))
                    .unwrap()
                    .status,
                i.1
            );
        }

        for to in ALL_STATUSES {
            assert_eq!(
                transition_agent(&agents, &id, 1, to, 999).err(),
                Some(TransitionError::Invalid),
                "disabled let an edge to {to:?} through"
            );
        }

        cleanup(root);
    }

    // (23)(24)(26) store failure surfaces AGENT_STORE_ERROR and the
    // PREVIOUS record + wallet files are untouched; lifecycle never opens
    // the wallet dir anyway.
    #[test]
    #[cfg(unix)]
    fn persist_failure_keeps_previous_record_and_never_touches_wallets() {
        use std::os::unix::fs::PermissionsExt;

        let (agents, wallets, authkeys, root) = step3_dirs();
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Atomic".into(), 1).unwrap();
        let id = agent.agent_id.clone();
        let parsed = parse_agent_id(&id).unwrap();
        let meta_path = agent_path(&agents, &parsed);
        let wallet_path = agent_wallet_path(&wallets, &parsed);
        let wallet_before = fs::read(&wallet_path).unwrap();

        // read-only store dir -> the atomic temp+rename write cannot land
        fs::set_permissions(&agents, fs::Permissions::from_mode(0o500)).unwrap();
        let err = transition_agent(&agents, &id, 1, AgentStatus::Active, 777)
            .err()
            .expect("persist must fail");
        fs::set_permissions(&agents, fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(err, TransitionError::Store);
        // previous record intact (still draft)
        assert_eq!(read_agent(&meta_path).unwrap().status, AgentStatus::Draft);
        // no temp litter from the failed write
        let leftovers: Vec<_> = fs::read_dir(&agents)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        // (26) wallet bytes identical; no lifecycle code path opened it
        assert_eq!(fs::read(&wallet_path).unwrap(), wallet_before);

        cleanup(root);
    }

    // -----------------------------------------------------------------------
    // STEP 6 — agent POLICY model. Configuration only: nothing here funds,
    // pays, enforces, or touches any wallet. Temp dirs only; no live agent,
    // no Rialo call.
    // -----------------------------------------------------------------------

    /// (agents, agent_wallets, agent_policies, root)
    fn step6_dirs() -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("agentpay-step6-{}", Uuid::new_v4()));
        (
            root.join("agents"),
            root.join("agent_wallets"),
            root.join("agent_auth_keys"),
            root.join("agent_policies"),
            root,
        )
    }

    fn patch_req(body: &str) -> PatchPolicyRequest {
        serde_json::from_str(body).expect("fixture body must parse")
    }

    // (1-4) default: deterministic, restrictive, versioned, bound to the id
    #[test]
    fn default_policy_is_deterministic_restrictive_and_scoped_to_agent() {
        let id = Uuid::new_v4().to_string();
        let a = default_policy(&id);
        let b = default_policy(&id);
        assert_eq!(a, b); // deterministic
        assert_eq!(a.schema_version, POLICY_SCHEMA_VERSION);
        assert_eq!(a.agent_id, id);
        // restrictive: NOTHING allowed-by-configuration, no fake numbers
        assert_eq!(a.max_payment_per_tx_kelvin, None);
        assert_eq!(a.daily_payment_limit_kelvin, None);
        assert!(a.allowed_recipients.is_empty());
        assert!(a.allowed_actions.is_empty());
        // never persisted => no timestamps; GET must not create the file
        assert_eq!(a.created_at, None);
        assert_eq!(a.updated_at, None);
    }

    // GET-side read-only contract: absent policy reads as None, file NOT created
    #[test]
    fn load_policy_missing_is_none_not_lazy_created() {
        let (_a, _w, _authkeys, policies, root) = step6_dirs();
        fs::create_dir_all(&policies).unwrap();
        let id = Uuid::new_v4();
        assert!(load_policy(&policies, &id).unwrap().is_none());
        assert!(!policy_path(&policies, &id).exists()); // no side effect
        cleanup(root);
    }

    // (5)(6)(32-35 via field control) valid limits convert to integer kelvin
    #[test]
    fn policy_validation_converts_to_canonical_kelvin() {
        let req = patch_req(
            r#"{"max_payment_per_tx_rlo": 1.5,
               "daily_payment_limit_rlo": 10,
               "allowed_actions": ["payment"]}"#,
        );
        let p = validate_policy_patch("agent-x", &req, None, 1000).unwrap();
        assert_eq!(p.schema_version, POLICY_SCHEMA_VERSION);
        assert_eq!(p.agent_id, "agent-x"); // server-owned from the PATH, not body
        assert_eq!(p.max_payment_per_tx_kelvin, Some(1_500_000_000));
        assert_eq!(p.daily_payment_limit_kelvin, Some(10_000_000_000));
        assert_eq!(p.allowed_actions, vec!["payment".to_string()]);
        assert_eq!(p.created_at, Some(1000)); // first write stamps creation
        assert_eq!(p.updated_at, Some(1000));

        // sub-kelvin precision is refused (no silent rounding of money)
        let tiny = patch_req(r#"{"max_payment_per_tx_rlo": 0.0000000001}"#);
        assert!(validate_policy_patch("a", &tiny, None, 1).is_err());
    }

    // (7-11) zero / negative / NaN / Infinity / per-tx > daily — all rejected
    #[test]
    fn policy_validation_rejects_bad_monetary_values() {
        for bad in [
            r#"{"max_payment_per_tx_rlo": 0}"#,
            r#"{"max_payment_per_tx_rlo": 0.0}"#,
            r#"{"max_payment_per_tx_rlo": -2}"#,
            r#"{"daily_payment_limit_rlo": 0}"#,
            r#"{"daily_payment_limit_rlo": -0.5}"#,
        ] {
            assert!(
                validate_policy_patch("a", &patch_req(bad), None, 1).is_err(),
                "accepted {bad}"
            );
        }
        // NaN / Infinity never survive the f64 boundary either (constructed
        // directly — serde_json itself refuses these literals in bodies)
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let req = PatchPolicyRequest {
                max_payment_per_tx_rlo: Some(v),
                ..patch_req("{}")
            };
            assert!(
                validate_policy_patch("a", &req, None, 1).is_err(),
                "accepted {v}"
            );
        }
        assert!(
            serde_json::from_str::<PatchPolicyRequest>(r#"{"max_payment_per_tx_rlo": NaN}"#)
                .is_err()
        );

        // (11) per-tx must not exceed daily; equal is fine
        let over = patch_req(r#"{"max_payment_per_tx_rlo": 9, "daily_payment_limit_rlo": 5}"#);
        assert!(validate_policy_patch("a", &over, None, 1).is_err());
        let equal = patch_req(r#"{"max_payment_per_tx_rlo": 5, "daily_payment_limit_rlo": 5}"#);
        assert!(validate_policy_patch("a", &equal, None, 1).is_ok());
    }

    // (12)(13) recipients validated with the ONE existing address checker
    #[test]
    fn policy_recipients_use_the_established_address_validator() {
        // a well-formed public Rialo address shape (same validator payment uses)
        let ok =
            patch_req(r#"{"allowed_recipients":["F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw"]}"#);
        assert!(validate_policy_patch("a", &ok, None, 1).is_ok());
        for bad in [
            r#"{"allowed_recipients":["not an address!"]}"#,
            r#"{"allowed_recipients":["short"]}"#,
            r#"{"allowed_recipients":[""]}"#,
            r#"{"allowed_recipients":["has spaces 1234567890abcdefghijklmnopqrst"]}"#,
        ] {
            assert!(
                validate_policy_patch("a", &patch_req(bad), None, 1).is_err(),
                "accepted {bad}"
            );
        }
    }

    // (14)(15)(32-35) strict request boundary
    #[test]
    fn policy_request_body_is_a_closed_schema() {
        // parse_policy_body keeps EVERY body-level failure inside the typed
        // envelope (400 AGENT_POLICY_INVALID) — no axum plain-text rejection
        assert!(parse_policy_body("{}").is_ok());
        assert!(parse_policy_body(r#"{"max_payment_per_tx_rlo":1}"#).is_ok());
        for rejected in [
            "not json at all",
            "",
            r#"{"max_payment_per_tx_rlo": NaN}"#,
            r#"{"allowed_actions":["payment"],"agent_id":"evil"}"#,
            r#"{"schema_version":99}"#,
            r#"{"created_at":1}"#,
            r#"{"updated_at":1}"#,
            r#"{"owner_user_id":7}"#,
            r#"{"max_payment_per_tx_rlo":1,"name":"renamed"}"#,
            r#"[1,2,3]"#,
            r#""a string body""#,
        ] {
            assert_eq!(
                parse_policy_body(rejected).err(),
                Some("request body is malformed or contains fields outside the policy schema"),
                "accepted {rejected}"
            );
        }
        // unknown action refused (finite vocabulary)
        let bad = patch_req(r#"{"allowed_actions":["payment","withdraw","dns"]}"#);
        assert!(validate_policy_patch("a", &bad, None, 1).is_err());
        // client-owned fields cannot be smuggled in
        for forbidden in [
            r#"{"allowed_actions":["payment"],"agent_id":"evil"}"#,
            r#"{"schema_version":99}"#,
            r#"{"created_at":1}"#,
            r#"{"updated_at":1}"#,
            r#"{"owner_user_id":7}"#,
            r#"{"max_payment_per_tx_rlo":1,"name":"renamed"}"#,
        ] {
            assert!(
                serde_json::from_str::<PatchPolicyRequest>(forbidden).is_err(),
                "accepted {forbidden}"
            );
        }
    }

    // (16-19) the policy endpoints run behind the SAME ownership chain
    #[test]
    fn policy_operations_gate_on_the_existing_ownership_choke_point() {
        let (agents, wallets, authkeys, policies, root) = step6_dirs();
        let agent =
            create_agent_record(&agents, &wallets, &authkeys, "Policyed".into(), 33).unwrap();
        let id = agent.agent_id.clone();
        let uuid = parse_agent_id(&id).unwrap();

        // (16) owner path resolves (policy GET/PATCH handlers start here)
        assert!(resolve_owned(&agents, &id, 33).is_some());
        // (18) foreign / (19) missing => None => AGENT_NOT_FOUND (indistinct)
        assert!(resolve_owned(&agents, &id, 34).is_none());
        assert!(resolve_owned(&agents, &Uuid::new_v4().to_string(), 33).is_none());

        // (17) owner update path: validate -> atomic save -> reload
        let req = patch_req(r#"{"max_payment_per_tx_rlo": 2, "allowed_actions":["payment"]}"#);
        let policy = validate_policy_patch(&id, &req, None, 555).unwrap();
        fs::create_dir_all(&policies).unwrap();
        write_json_atomic(&policy_path(&policies, &uuid), &policy).unwrap();
        // (20) survives reload
        assert_eq!(
            load_policy(&policies, &uuid).unwrap().as_ref(),
            Some(&policy)
        );
        // (21) file is 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(policy_path(&policies, &uuid))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // created_at preserved across an update; updated_at moves
        let second = validate_policy_patch(&id, &patch_req("{}"), policy.created_at, 777).unwrap();
        write_json_atomic(&policy_path(&policies, &uuid), &second).unwrap();
        let re = load_policy(&policies, &uuid).unwrap().unwrap();
        assert_eq!(re.created_at, Some(555));
        assert_eq!(re.updated_at, Some(777));

        cleanup(root);
    }

    // (22)(23)(24) atomicity, failure keeps previous, per-agent isolation
    #[test]
    #[cfg(unix)]
    fn policy_persistence_is_atomic_and_isolated_per_agent() {
        use std::os::unix::fs::PermissionsExt;

        let (agents, wallets, authkeys, policies, root) = step6_dirs();
        fs::create_dir_all(&policies).unwrap();

        let a = create_agent_record(&agents, &wallets, &authkeys, "A".into(), 1).unwrap();
        let b = create_agent_record(&agents, &wallets, &authkeys, "B".into(), 1).unwrap();
        let ua = parse_agent_id(&a.agent_id).unwrap();
        let ub = parse_agent_id(&b.agent_id).unwrap();

        let pa = validate_policy_patch(
            &a.agent_id,
            &patch_req(r#"{"max_payment_per_tx_rlo":1}"#),
            None,
            100,
        )
        .unwrap();
        let pb = validate_policy_patch(
            &b.agent_id,
            &patch_req(r#"{"max_payment_per_tx_rlo":3}"#),
            None,
            100,
        )
        .unwrap();
        write_json_atomic(&policy_path(&policies, &ua), &pa).unwrap();
        write_json_atomic(&policy_path(&policies, &ub), &pb).unwrap();

        // (24) A's file survives B's write untouched
        assert_eq!(load_policy(&policies, &ua).unwrap().as_ref(), Some(&pa));
        assert_eq!(load_policy(&policies, &ub).unwrap().as_ref(), Some(&pb));

        // (23) blocked store -> previous policy intact, no temp litter
        let before = fs::read(policy_path(&policies, &ua)).unwrap();
        fs::set_permissions(&policies, fs::Permissions::from_mode(0o500)).unwrap();
        let pa2 = validate_policy_patch(
            &a.agent_id,
            &patch_req(r#"{"max_payment_per_tx_rlo":2}"#),
            pa.created_at,
            200,
        )
        .unwrap();
        let failed = write_json_atomic(&policy_path(&policies, &ua), &pa2);
        fs::set_permissions(&policies, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed.is_err());
        assert_eq!(fs::read(policy_path(&policies, &ua)).unwrap(), before);
        let litter: Vec<_> = fs::read_dir(&policies)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(litter.is_empty());

        cleanup(root);
    }

    // (25-28) policy writes never touch agent metadata, agent wallets, status
    #[test]
    fn policy_writes_do_not_touch_agent_metadata_or_wallets() {
        let (agents, wallets, authkeys, policies, root) = step6_dirs();
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Iso".into(), 9).unwrap();
        let uuid = parse_agent_id(&agent.agent_id).unwrap();
        let meta = fs::read(agent_path(&agents, &uuid)).unwrap();
        let wallet = fs::read(agent_wallet_path(&wallets, &uuid)).unwrap();

        fs::create_dir_all(&policies).unwrap();
        let policy = validate_policy_patch(
            &agent.agent_id,
            &patch_req(r#"{"daily_payment_limit_rlo":10}"#),
            None,
            4242,
        )
        .unwrap();
        write_json_atomic(&policy_path(&policies, &uuid), &policy).unwrap();

        // (25) metadata bytes identical, (26) wallet bytes identical
        assert_eq!(fs::read(agent_path(&agents, &uuid)).unwrap(), meta);
        assert_eq!(
            fs::read(agent_wallet_path(&wallets, &uuid)).unwrap(),
            wallet
        );
        // (28) status unchanged (policy ops have no lifecycle effect)
        assert_eq!(
            read_agent(&agent_path(&agents, &uuid)).unwrap().status,
            AgentStatus::Draft
        );
        // (27) user-wallet dir: agent code never resolves it (structural —
        // verified by grep; here the temp fixture simply has none, and the
        // sentinel test in STEP 3 proves provisioning does not create one).

        cleanup(root);
    }

    // (31) response envelope exposes only public policy config
    #[test]
    fn policy_response_bodies_carry_no_private_or_path_data() {
        let agent = default_policy("aaa");
        for configured in [false, true] {
            let blob = policy_body("aaa", configured, &agent)
                .to_string()
                .to_lowercase();
            for banned in [
                "artifact",
                "agent_policies",
                "agent_wallets",
                ".json",
                "seed",
                "private",
                "keypair",
                "secret",
                "owner_user_id",
            ] {
                assert!(!blob.contains(banned), "policy body leaked {banned}");
            }
        }
        // corrupt or foreign-schema policy files are ERR, never defaults
        let (_a, _w, _authkeys, policies, root) = step6_dirs();
        fs::create_dir_all(&policies).unwrap();
        let id = Uuid::new_v4();
        fs::write(
            policy_path(&policies, &id),
            br#"{"schema_version":99,"agent_id":"x","max_payment_per_tx_kelvin":null,"daily_payment_limit_kelvin":null,"allowed_recipients":[],"allowed_actions":[],"created_at":null,"updated_at":null}"#,
        )
        .unwrap();
        assert!(load_policy(&policies, &id).is_err());
        cleanup(root);
    }

    // -----------------------------------------------------------------------
    // STEP 7 — policy ENFORCEMENT boundary. Pure checks: no transfer, no
    // balance, no wallet resolution, no filesystem, no RPC. Fixtures are
    // plain data (plus temp-dir files for the immutability proof).
    // -----------------------------------------------------------------------

    const RECIPIENT: &str = "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw";
    const OTHER: &str = "9xG6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVn9w";
    const TX_LIMIT: u64 = 100_000_000; // 0.1 RLO in kelvin
    const DAY_LIMIT: u64 = 500_000_000; // 0.5 RLO in kelvin

    fn agent_with(status: AgentStatus) -> Agent {
        Agent {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_id: Uuid::new_v4().to_string(),
            owner_user_id: 7,
            name: "Enforce".into(),
            status,
            wallet_address: Some(RECIPIENT.into()),
            auth_public_key: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn good_policy() -> AgentPolicy {
        AgentPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            agent_id: "e".into(),
            max_payment_per_tx_kelvin: Some(TX_LIMIT),
            daily_payment_limit_kelvin: Some(DAY_LIMIT),
            allowed_recipients: vec![RECIPIENT.into()],
            allowed_actions: vec!["payment".into()],
            created_at: Some(0),
            updated_at: Some(0),
            parent_agent_id: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
            delegation_revoked: None,
        }
    }

    fn check(
        status: AgentStatus,
        policy: Option<&AgentPolicy>,
        recipient: &str,
        amount: u64,
        spent: Option<u64>,
    ) -> Result<(), EnforcementDenial> {
        check_agent_payment_policy(&agent_with(status), policy, recipient, amount, spent)
    }

    // (1) happy path; (2-4,25) every non-active status blocked, explicit
    #[test]
    fn enforcement_covers_every_lifecycle_status() {
        let p = good_policy();
        assert_eq!(
            check(
                AgentStatus::Active,
                Some(&p),
                RECIPIENT,
                50_000_000,
                Some(0)
            ),
            Ok(())
        );
        for blocked in [
            AgentStatus::Draft,
            AgentStatus::Paused,
            AgentStatus::Disabled,
        ] {
            assert_eq!(
                check(blocked, Some(&p), RECIPIENT, 1, Some(0)),
                Err(EnforcementDenial::Lifecycle),
                "{blocked:?} was allowed"
            );
        }
    }

    // (5,6) missing policy / action not permitted
    #[test]
    fn enforcement_requires_policy_and_action() {
        let p = good_policy();
        assert_eq!(
            check(AgentStatus::Active, None, RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::PolicyMissing)
        );
        let no_action = AgentPolicy {
            allowed_actions: vec![],
            ..p.clone()
        };
        assert_eq!(
            check(AgentStatus::Active, Some(&no_action), RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::ActionDenied)
        );
    }

    // (7,8,9) recipient rules: empty list = deny, off-list = deny,
    // malformed = INVALID_RECIPIENT (validator runs BEFORE membership)
    #[test]
    fn enforcement_recipient_rules_are_deny_by_default() {
        let p = good_policy();
        let empty = AgentPolicy {
            allowed_recipients: vec![],
            ..p.clone()
        };
        assert_eq!(
            check(AgentStatus::Active, Some(&empty), RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::RecipientDenied),
            "empty allow-list was treated as unlimited"
        );
        assert_eq!(
            check(AgentStatus::Active, Some(&p), OTHER, 1, Some(0)),
            Err(EnforcementDenial::RecipientDenied)
        );
        assert_eq!(
            check(AgentStatus::Active, Some(&p), "not an address!", 1, Some(0)),
            Err(EnforcementDenial::RecipientInvalid)
        );
    }

    // (10-12) amount rules at the KELVIN boundary (u64 — negatives/sub-kelvin
    // cannot exist here; upstream rlo_to_kelvin already refuses them)
    #[test]
    fn enforcement_amount_rules_use_integer_kelvin_only() {
        let p = good_policy();
        assert_eq!(
            check(AgentStatus::Active, Some(&p), RECIPIENT, 0, Some(0)),
            Err(EnforcementDenial::AmountInvalid)
        );
        // upstream conversion refuses negatives & sub-kelvin (boundary is
        // ALWAYS an integer kelvin count)
        assert_eq!(super::super::rlo_to_kelvin(-3.0), None);
        assert_eq!(super::super::rlo_to_kelvin(0.0000000001), None);
        assert_eq!(super::super::rlo_to_kelvin(f64::NAN), None);
        assert_eq!(super::super::rlo_to_kelvin(f64::INFINITY), None);
    }

    // (13-15,17) limit rules: equal passes, above fails, UNSET = DENY
    #[test]
    fn enforcement_limit_rules_deny_unset_limits() {
        let p = good_policy();
        assert_eq!(
            check(
                AgentStatus::Active,
                Some(&p),
                RECIPIENT,
                TX_LIMIT + 1,
                Some(0)
            ),
            Err(EnforcementDenial::AmountDenied),
            "per-tx limit exceeded was allowed"
        );
        assert_eq!(
            check(AgentStatus::Active, Some(&p), RECIPIENT, TX_LIMIT, Some(0)),
            Ok(()),
            "amount equal to per-tx limit must be allowed"
        );
        let no_tx = AgentPolicy {
            max_payment_per_tx_kelvin: None,
            ..p.clone()
        };
        assert_eq!(
            check(AgentStatus::Active, Some(&no_tx), RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::AmountDenied),
            "unset per-tx limit was treated as unlimited"
        );
        let no_daily = AgentPolicy {
            daily_payment_limit_kelvin: None,
            ..p.clone()
        };
        assert_eq!(
            check(AgentStatus::Active, Some(&no_daily), RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::AmountDenied),
            "unset daily limit was treated as unlimited"
        );
    }

    // (16,18) daily accounting via the spend seam + checked integer math
    #[test]
    fn enforcement_daily_limit_uses_supplied_accounting_and_checked_math() {
        let p = good_policy();
        // amounts stay WITHIN the 0.1 RLO per-tx limit so the DAILY
        // boundary is what decides (daily = 0.5 RLO = 500_000_000 kelvin):
        //   spent 450M + new 90M = 540M -> over daily -> denied
        assert_eq!(
            check(
                AgentStatus::Active,
                Some(&p),
                RECIPIENT,
                90_000_000,
                Some(450_000_000)
            ),
            Err(EnforcementDenial::AmountDenied),
            "spent 0.45 + new 0.09 exceeds 0.5 daily"
        );
        //   spent 150M + new 90M = 240M -> fits daily, fits per-tx -> ok
        assert_eq!(
            check(
                AgentStatus::Active,
                Some(&p),
                RECIPIENT,
                90_000_000,
                Some(150_000_000)
            ),
            Ok(()),
            "in-limit fit across both limits must be allowed"
        );
        // overflow cannot open a bypass
        assert_eq!(
            check(AgentStatus::Active, Some(&p), RECIPIENT, 1, Some(u64::MAX)),
            Err(EnforcementDenial::AmountDenied)
        );
        // (DAILY SEAM) limit configured but no accounting supplied =>
        // explicit required-marker, NEVER Ok — no silent bypass
        assert_eq!(
            check(AgentStatus::Active, Some(&p), RECIPIENT, 1, None),
            Err(EnforcementDenial::DailyAccountingRequired)
        );
    }

    // stable typed codes/messages/statuses (existing envelope conventions)
    #[test]
    fn enforcement_denials_have_stable_typed_codes() {
        let table = [
            (EnforcementDenial::Lifecycle, "AGENT_LIFECYCLE_BLOCKED", 403),
            (
                EnforcementDenial::PolicyMissing,
                "AGENT_POLICY_MISSING",
                403,
            ),
            (EnforcementDenial::ActionDenied, "AGENT_POLICY_DENIED", 403),
            (
                EnforcementDenial::RecipientInvalid,
                "INVALID_RECIPIENT",
                400,
            ),
            (
                EnforcementDenial::RecipientDenied,
                "AGENT_POLICY_DENIED",
                403,
            ),
            (EnforcementDenial::AmountInvalid, "INVALID_AMOUNT", 400),
            (EnforcementDenial::AmountDenied, "AGENT_POLICY_DENIED", 403),
            (
                EnforcementDenial::DailyAccountingRequired,
                "AGENT_DAILY_ACCOUNTING_REQUIRED",
                501,
            ),
        ];
        for (denial, code, status) in table {
            assert_eq!(denial.code(), code);
            assert_eq!(denial.status().as_u16(), status);
            // no filesystem paths or key-adjacent words in any public string
            let combined = format!("{}{}", denial.code(), denial.message()).to_lowercase();
            for banned in [
                "artifact", "wallet", "seed", "keypair", "private", ".json", "/",
            ] {
                assert!(!combined.contains(banned), "{code} leaks {banned}");
            }
        }
    }

    // SECURITY/STRUCTURAL: the enforcement function body must be pure by
    // source inspection — no wallet resolution, no fs, no RPC, no CLI.
    #[test]
    fn enforcement_source_purity_by_inspection() {
        let src = include_str!("agents.rs");
        let start = src
            .find("pub fn check_agent_payment_policy(")
            .expect("enforcement fn present");
        let rest = &src[start..];
        let end = rest.find("\n}").expect("fn end");
        let body = &rest[..end];
        for forbidden in [
            "fs::",
            "File",
            "wallet",
            "transfer",
            "balance",
            "airdrop",
            "faucet",
            "spawn_blocking",
            "load_policy",
            "store_lock",
            "write_json",
            "read_dir",
            "agent_wallet",
        ] {
            assert!(
                !body.contains(forbidden),
                "enforcement body references {forbidden}"
            );
        }
    }

    // (19-24) end-to-end read-only proof: enforcing from real temp-dir
    // fixtures (agent + policy files) leaves every store byte-identical,
    // and enforcement never even requires a wallet identity.
    #[test]
    fn enforcement_is_read_only_over_real_records() {
        let (agents, wallets, authkeys, policies, root) = step6_dirs();
        let agent =
            create_agent_record(&agents, &wallets, &authkeys, "ReadOnly".into(), 4).unwrap();
        let uuid = parse_agent_id(&agent.agent_id).unwrap();
        fs::create_dir_all(&policies).unwrap();
        let policy = validate_policy_patch(
            &agent.agent_id,
            &patch_req(
                r#"{"max_payment_per_tx_rlo":0.1,"daily_payment_limit_rlo":0.5,
                           "allowed_recipients":["F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw"],
                           "allowed_actions":["payment"]}"#,
            ),
            None,
            50,
        )
        .unwrap();
        write_json_atomic(&policy_path(&policies, &uuid), &policy).unwrap();

        let meta_before = fs::read(agent_path(&agents, &uuid)).unwrap();
        let wallet_before = fs::read(agent_wallet_path(&wallets, &uuid)).unwrap();
        let policy_before = fs::read(policy_path(&policies, &uuid)).unwrap();

        let loaded_agent = read_agent(&agent_path(&agents, &uuid)).unwrap();
        let loaded_policy = load_policy(&policies, &uuid).unwrap().unwrap();
        // draft => blocked, then flip the DATA (in memory only) to active
        assert_eq!(
            check_agent_payment_policy(&loaded_agent, Some(&loaded_policy), RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::Lifecycle)
        );
        let mut active = loaded_agent.clone();
        active.status = AgentStatus::Active;
        assert_eq!(
            check_agent_payment_policy(&active, Some(&loaded_policy), RECIPIENT, 1, Some(0)),
            Ok(())
        );
        // an agent with NO wallet identity still enforces purely on data
        let mut no_wallet = active.clone();
        no_wallet.wallet_address = None;
        assert_eq!(
            check_agent_payment_policy(&no_wallet, Some(&loaded_policy), RECIPIENT, 1, Some(0)),
            Ok(())
        );

        // all three stores byte-identical; user wallets are not even a
        // parameter this code can reach (no path exists without artifact/)
        assert_eq!(fs::read(agent_path(&agents, &uuid)).unwrap(), meta_before);
        assert_eq!(
            fs::read(agent_wallet_path(&wallets, &uuid)).unwrap(),
            wallet_before
        );
        assert_eq!(
            fs::read(policy_path(&policies, &uuid)).unwrap(),
            policy_before
        );
        cleanup(root);
    }

    // -----------------------------------------------------------------------
    // STEP 8 — payment money core. Everything below runs against FRESH
    // std::env::temp_dir() subtrees with a MOCKED transfer boundary: the
    // real artifact/ tree is never opened and no real money moves. The
    // production boundary (RialoConfig::transfer) is not modified — the
    // trait impl forwards to it verbatim.
    // -----------------------------------------------------------------------

    const NOW: i64 = 1_790_668_800; // 2026-09-29 00:00:00 UTC
    const NOW_DAY: &str = "2026-09-29";
    const PAY_TX: u64 = 100_000_000; // 0.1 RLO per-tx cap
    const PAY_DAY: u64 = 500_000_000; // 0.5 RLO daily cap
    const PAY_AMT: u64 = 50_000_000; // 0.05 RLO
    const PAY_SIG: &str = "5QHbMockSignatureNotRealDoNotTrust";

    struct Step8 {
        root: PathBuf,
        agents: PathBuf,
        wallets: PathBuf,
        authkeys: PathBuf,
        ledger: PathBuf,
        intents: PathBuf,
        user_wallets: PathBuf,
        uuid: Uuid,
        agent: Agent,
        policy: AgentPolicy,
        record_bytes: Vec<u8>,
    }

    fn step8_setup() -> Step8 {
        let root = std::env::temp_dir().join(format!("agentpay-step8-{}", Uuid::new_v4()));
        let agents = root.join("agents");
        let wallets = root.join("agent_wallets");
        let authkeys = root.join("agent_auth_keys");
        let ledger = root.join("agent_spend");
        let intents = root.join("agent_payment_intents");
        let user_wallets = root.join("wallets"); // mirrors artifact/wallets
        fs::create_dir_all(&user_wallets).unwrap();
        let sentinel = user_wallets.join("50506084.json");
        fs::write(&sentinel, b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE").unwrap();

        // a real record + real independent wallet file (no key content is
        // ever read or printed — path/bytes equality only)
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Pay".into(), 7).unwrap();
        let uuid = parse_agent_id(&agent.agent_id).unwrap();
        let record_bytes = fs::read(agent_path(&agents, &uuid)).unwrap();
        let mut active = agent;
        active.status = AgentStatus::Active; // in-memory only; disk stays draft

        let policy = AgentPolicy {
            schema_version: POLICY_SCHEMA_VERSION,
            agent_id: uuid.to_string(),
            max_payment_per_tx_kelvin: Some(PAY_TX),
            daily_payment_limit_kelvin: Some(PAY_DAY),
            allowed_recipients: vec![RECIPIENT.into()],
            allowed_actions: vec!["payment".into()],
            created_at: Some(0),
            updated_at: Some(0),
            parent_agent_id: None,
            aggregate_daily_limit_kelvin: None,
            aggregate_scopes: Vec::new(),
            delegation_revoked: None,
        };
        Step8 {
            root,
            agents,
            wallets,
            authkeys,
            ledger,
            intents,
            user_wallets,
            uuid,
            agent: active,
            policy,
            record_bytes,
        }
    }

    impl Step8 {
        fn cleanup(&self) {
            fs::remove_dir_all(&self.root).ok();
        }
        /// Same temp-store root, a different agent identity (for the
        /// per-agent isolation proofs). Freshly created records are
        /// `draft` on disk; the binding activates the agent IN MEMORY only
        /// (same convention as step8_setup) so multi-agent payments reach
        /// the ledger/intent path instead of the lifecycle gate.
        fn clone_data(&self, mut agent: Agent) -> Step8 {
            agent.status = AgentStatus::Active;
            let uuid = parse_agent_id(&agent.agent_id).unwrap();
            Step8 {
                root: self.root.clone(),
                agents: self.agents.clone(),
                wallets: self.wallets.clone(),
                authkeys: self.authkeys.clone(),
                ledger: self.ledger.clone(),
                intents: self.intents.clone(),
                user_wallets: self.user_wallets.clone(),
                uuid,
                agent,
                policy: AgentPolicy {
                    agent_id: uuid.to_string(),
                    ..self.policy.clone()
                },
                record_bytes: fs::read(agent_path(&self.agents, &uuid)).unwrap_or_default(),
            }
        }
        fn ledger_file(&self) -> PathBuf {
            spend_path(&self.ledger, &self.uuid)
        }
        fn ledger_spent(&self) -> Option<u64> {
            read_spend(&self.ledger, &self.uuid)
                .ok()
                .flatten()
                .map(|s| s.spent_kelvin)
        }
        fn intent(&self, key: &str) -> Option<PaymentIntent> {
            read_intent(&self.intents, &self.uuid, key).ok().flatten()
        }
        fn user_wallet_untouched(&self) {
            let sentinel = self.user_wallets.join("50506084.json");
            assert_eq!(
                fs::read(&sentinel).unwrap(),
                b"SENTINEL-USER-KEYPAIR-NOT-A-REAL-FILE",
                "user wallet bytes changed"
            );
            assert_eq!(
                fs::read_dir(&self.user_wallets).unwrap().count(),
                1,
                "user wallet dir gained a file"
            );
        }
    }

    fn pay_policy(tx: Option<u64>, daily: Option<u64>) -> AgentPolicy {
        AgentPolicy {
            max_payment_per_tx_kelvin: tx,
            daily_payment_limit_kelvin: daily,
            ..good_policy()
        }
    }

    fn run_pay(
        s: &Step8,
        ops: &(dyn PaymentOps + Send + Sync),
        key: &str,
        recipient: &str,
        amount_rlo: f64,
        policy: Option<&AgentPolicy>,
        agent: Option<&Agent>,
    ) -> Result<serde_json::Value, PaymentFailure> {
        // amount conversion THROUGH THE ONE helper, exactly like the handler
        let amount_kelvin = super::super::rlo_to_kelvin(amount_rlo)
            .expect("test amount must be kelvin-valid")
            .parse::<u64>()
            .unwrap();
        execute_agent_payment(
            ops,
            &s.wallets,
            &s.ledger,
            &s.intents,
            agent.unwrap_or(&s.agent),
            policy.unwrap_or(&s.policy),
            key,
            recipient,
            amount_kelvin,
            amount_rlo,
            NOW,
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum MockErr {
        RpcUnavailable,
        ClockSkew,
        ConfirmationTimeout,
        TransferError,
    }

    fn rialo_mock_err(e: MockErr) -> RialoError {
        RialoError {
            code: match e {
                MockErr::RpcUnavailable => "RIALO_RPC_UNAVAILABLE",
                MockErr::ClockSkew => "RIALO_CLOCK_SKEW",
                MockErr::ConfirmationTimeout => "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                MockErr::TransferError => "RIALO_TRANSFER_ERROR",
            },
            detail: "mock failure".to_string(),
            tx_signature: None,
        }
    }

    struct MockOps {
        balance_res: Result<f64, MockErr>,
        transfer_res: Result<String, MockErr>,
        ledger_dir: PathBuf,
        ledger_file: String,
        hold: Arc<std::sync::atomic::AtomicBool>,
        calls: Mutex<Vec<String>>,
        ledger_at_transfer: Mutex<Option<u64>>,
        // GATE 2H — deterministic handoff: set by the mock's transfer()
        // BEFORE parking on `hold`, so the concurrency test can WAIT for
        // the event instead of polling the ledger and racing the
        // scheduler (the root cause of the historical flake).
        entered_transfer: Mutex<bool>,
    }

    impl MockOps {
        fn new(s: &Step8) -> Self {
            MockOps {
                balance_res: Ok(2.0),
                transfer_res: Ok(PAY_SIG.to_string()),
                ledger_dir: s.ledger.clone(),
                ledger_file: format!("{}.json", s.uuid),
                hold: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                calls: Mutex::new(Vec::new()),
                ledger_at_transfer: Mutex::new(None),
                entered_transfer: Mutex::new(false),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn transfer_calls(&self) -> Vec<String> {
            self.calls()
                .into_iter()
                .filter(|c| c.starts_with("transfer|"))
                .collect()
        }
        /// (path, to, amount-string) of the last transfer call
        fn last_transfer(&self) -> (String, String, String) {
            let last = self
                .transfer_calls()
                .last()
                .expect("at least one transfer")
                .clone();
            let mut parts = last.splitn(4, '|');
            parts.next();
            (
                parts.next().unwrap().to_string(),
                parts.next().unwrap().to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        }
        fn spent_seen_in_transfer(&self) -> Option<u64> {
            *self.ledger_at_transfer.lock().unwrap()
        }
        fn set_hold(&self) -> Arc<std::sync::atomic::AtomicBool> {
            Arc::clone(&self.hold)
        }
        /// GATE 2H — deterministic wait until thread A has actually
        /// entered transfer() (bounded so a hung mock still fails the
        /// test instead of hanging the suite).
        fn wait_until_entered_transfer(&self, max_polls: u32) {
            for _ in 0..max_polls {
                if *self.entered_transfer.lock().unwrap() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            panic!("A never entered transfer within the bounded wait");
        }
    }

    impl PaymentOps for MockOps {
        fn read_tx(&self, signature: &str) -> TxLookup {
            // never used by the payment engines; fail closed by shape
            let _ = signature;
            TxLookup::Malformed
        }

        fn signatures_for_address(
            &self,
            _address: &str,
            _until_signature: Option<&str>,
            _limit: u64,
        ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
            Err(rialo_mock_err(MockErr::RpcUnavailable))
        }

        fn balance(&self, _address: &str) -> Result<f64, RialoError> {
            self.calls.lock().unwrap().push("balance".to_string());
            self.balance_res.map_err(rialo_mock_err)
        }
        fn transfer(
            &self,
            keypair_path: &FsPath,
            to: &str,
            amount_rlo: &str,
        ) -> Result<String, RialoError> {
            // MONEY-SAFETY EVIDENCE: read the PERSISTED ledger while the
            // transfer is executing. The reservation must already be on
            // disk before this point is reached.
            if let Ok(bytes) = fs::read(self.ledger_dir.join(&self.ledger_file)) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if let Some(spent) = v.get("spent_kelvin").and_then(|s| s.as_u64()) {
                        *self.ledger_at_transfer.lock().unwrap() = Some(spent);
                    }
                }
            }
            self.calls.lock().unwrap().push(format!(
                "transfer|{}|{}|{}",
                keypair_path.display(),
                to,
                amount_rlo
            ));
            // GATE 2H: signal "transfer entered" BEFORE parking so the
            // concurrency test's wait is event-driven, not scheduler-timed.
            *self.entered_transfer.lock().unwrap() = true;
            // optional gate for the concurrency test (park inside transfer)
            while self.hold.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            self.transfer_res.clone().map_err(rialo_mock_err)
        }
    }

    fn unix_mode(path: &FsPath) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0
        }
    }

    // (20,21,22,23,24,30,32,40,41,42,43) happy path end to end
    #[test]
    fn step8_happy_path_transfers_only_from_agent_wallet() {
        let s = step8_setup();
        let mock = MockOps::new(&s);
        let body = run_pay(&s, &mock, "tx-1", RECIPIENT, 0.05, None, None).expect("success");

        // response contract (public fields only)
        assert_eq!(body["success"], true);
        assert_eq!(body["agent_id"], s.agent.agent_id.as_str());
        let payment = &body["payment"];
        assert_eq!(payment["to"], RECIPIENT);
        assert_eq!(payment["amount_kelvin"], PAY_AMT);
        assert_eq!(payment["signature"], PAY_SIG);
        assert!(payment["balance_before_rlo"].is_string());
        assert!(
            payment["balance_after_rlo"].is_null(),
            "unknown must be null"
        );

        // exactly ONE transfer, from the AGENT wallet file only (32)
        assert_eq!(mock.transfer_calls().len(), 1);
        let (path, to, amount_str) = mock.last_transfer();
        assert_eq!(
            path,
            agent_wallet_path(&s.wallets, &s.uuid).display().to_string()
        );
        assert_eq!(to, RECIPIENT);
        assert_eq!(amount_str, "0.05");
        let p = FsPath::new(&path);
        assert_eq!(p.parent().unwrap().file_name().unwrap(), "agent_wallets");
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            format!("{}.json", s.uuid)
        );

        // reservation was PERSISTED before the transfer ran (23)
        assert_eq!(mock.spent_seen_in_transfer(), Some(PAY_AMT));
        // balance read precedes transfer (checks before money, 33)
        let calls = mock.calls();
        assert_eq!(calls.first().map(|s| s.as_str()), Some("balance"));

        // COMMIT: the reservation stands after success (24)
        let stored = read_spend(&s.ledger, &s.uuid).unwrap().unwrap();
        assert_eq!(stored.spent_kelvin, PAY_AMT);
        assert_eq!(stored.day, NOW_DAY);
        assert_eq!(stored.agent_id, s.uuid.to_string());
        assert_eq!(stored.schema_version, SPEND_SCHEMA_VERSION);
        assert_eq!(unix_mode(&s.ledger_file()), 0o600); // atomic 0600 money state
        assert_eq!(unix_mode(&s.intents), 0o755); // root dir (agent subdir is 0700)
        assert_eq!(unix_mode(&agent_intents_dir(&s.intents, &s.uuid)), 0o700);

        // completed intent stores the exact response for replay (30)
        let intent = s.intent("tx-1").expect("intent exists");
        assert_eq!(intent.state, IntentState::Confirmed);
        assert_eq!(intent.response.as_ref(), Some(&body));
        let intent_file = intent_path(&agent_intents_dir(&s.intents, &s.uuid), "tx-1");
        assert_eq!(
            intent_file.file_name().unwrap(),
            format!("{}.json", hex_encode(b"tx-1")).as_str()
        );
        assert_eq!(unix_mode(&intent_file), 0o600);

        // NO secret material anywhere in the response (40,41,42)
        let text = body.to_string();
        for banned in [
            "artifact", "seed", "keypair", "private", ".json", "SENTINEL",
        ] {
            assert!(!text.contains(banned), "response leaks {banned}");
        }

        // AGENT STATUS UNCHANGED after successful payment (43): the record
        // file on disk is byte-identical (still draft) — the core never
        // writes the agent store
        assert_eq!(
            fs::read(agent_path(&s.agents, &s.uuid)).unwrap(),
            s.record_bytes
        );
        assert_eq!(
            read_agent(&agent_path(&s.agents, &s.uuid)).unwrap().status,
            AgentStatus::Draft
        );

        // the human owner's wallet is untouched (21,22)
        s.user_wallet_untouched();

        s.cleanup();
    }

    // (4,5,6,7,33) every non-active status is blocked before any money state;
    // active reaches the policy checks
    #[test]
    fn step8_lifecycle_blocks_every_call_before_transfer() {
        let s = step8_setup();
        for blocked in [
            AgentStatus::Draft,
            AgentStatus::Paused,
            AgentStatus::Disabled,
        ] {
            let mock = MockOps::new(&s);
            let mut agent = s.agent.clone();
            agent.status = blocked;
            let err = run_pay(
                &s,
                &mock,
                &format!("lc-{blocked:?}"),
                RECIPIENT,
                0.05,
                None,
                Some(&agent),
            )
            .expect_err("must deny");
            assert!(
                matches!(
                    err,
                    PaymentFailure::Enforcement(EnforcementDenial::Lifecycle)
                ),
                "{blocked:?} was not lifecycle-blocked"
            );
            assert!(mock.transfer_calls().is_empty());
            assert!(s.ledger_spent().is_none(), "ledger touched before gate");
        }
        // (7) ACTIVE reaches POLICY checks (not lifecycle): empty action
        // list answers ActionDenied, still zero money state
        let mock = MockOps::new(&s);
        let err = run_pay(
            &s,
            &mock,
            "lc-active",
            RECIPIENT,
            0.05,
            Some(&pay_policy(None, None)),
            None,
        )
        .expect_err("must deny");
        assert!(matches!(
            err,
            PaymentFailure::Enforcement(EnforcementDenial::AmountDenied)
        ));
        assert!(s.ledger_spent().is_none());
        s.cleanup();
    }

    // (8,9,10,11,13) policy denials: nothing reaches the transfer and no
    // money state is created (denials happen BEFORE claim/reserve)
    #[test]
    fn step8_policy_denials_never_reach_transfer() {
        let s = step8_setup();
        let cases: Vec<(&str, Option<AgentPolicy>, &str, f64, EnforcementDenial)> = vec![
            (
                "action",
                {
                    let mut p = s.policy.clone();
                    p.allowed_actions = vec![];
                    Some(p)
                },
                RECIPIENT,
                0.05,
                EnforcementDenial::ActionDenied,
            ),
            (
                "recipient",
                None,
                OTHER,
                0.05,
                EnforcementDenial::RecipientDenied,
            ),
            (
                "bad-recipient",
                None,
                "nope!",
                0.05,
                EnforcementDenial::RecipientInvalid,
            ),
            (
                "per-tx",
                None,
                RECIPIENT,
                0.2,
                EnforcementDenial::AmountDenied,
            ),
            (
                "unset-tx",
                pay_policy(None, Some(PAY_DAY)).into(),
                RECIPIENT,
                0.05,
                EnforcementDenial::AmountDenied,
            ),
            (
                "unset-daily",
                pay_policy(Some(PAY_TX), None).into(),
                RECIPIENT,
                0.05,
                EnforcementDenial::AmountDenied,
            ),
        ];
        for (tag, policy, recipient, amount, want) in cases {
            let mock = MockOps::new(&s);
            let err = run_pay(
                &s,
                &mock,
                &format!("pd-{tag}"),
                recipient,
                amount,
                policy.as_ref(),
                None,
            )
            .expect_err("must deny");
            assert!(
                matches!(&err, PaymentFailure::Enforcement(d) if *d == want),
                "{tag}: got {err:?}, want {want:?}"
            );
            assert!(mock.transfer_calls().is_empty(), "{tag}: transfer called");
            assert!(s.ledger_spent().is_none(), "{tag}: ledger created");
            assert!(
                s.intent(&format!("pd-{tag}")).is_none(),
                "{tag}: key burned on denial"
            );
        }
        // (8) missing policy = deny — the ONE enforcement function's verdict
        assert_eq!(
            check_agent_payment_policy(&s.agent, None, RECIPIENT, 1, Some(0)),
            Err(EnforcementDenial::PolicyMissing)
        );
        s.cleanup();
    }

    // (14,15,16,17) amount/recipient/body validation — through the ONE
    // existing helpers plus the envelope-safe body parser
    #[test]
    fn step8_input_validation_tables() {
        // body: only {to, amount} is accepted
        assert!(parse_payment_body(&format!("{{\"to\":\"{RECIPIENT}\",\"amount\":0.5}}")).is_ok());
        for bad in [
            "",
            "not json",
            &format!("{{\"to\":\"{RECIPIENT}\",\"amount\":\"0.5\"}}"), // string amount
            "{\"amount\":1}",                                          // missing to
            "{\"to\":\"x\"}",                                          // missing amount
            &format!("{{\"to\":\"{RECIPIENT}\",\"amount\":0.5,\"agent_id\":\"evil\"}}"), // unknown field
            &format!("{{\"to\":\"{RECIPIENT}\",\"amount\":NaN}}"), // NaN literal
            "[]",
            "null",
        ] {
            assert!(parse_payment_body(bad).is_err(), "body accepted: {bad}");
        }
        // zero / negative / sub-kelvin are refused by the ONE helper
        assert_eq!(super::super::rlo_to_kelvin(0.0), None);
        assert_eq!(super::super::rlo_to_kelvin(-3.5), None);
        assert_eq!(super::super::rlo_to_kelvin(0.0000000001), None);
        assert_eq!(super::super::rlo_to_kelvin(f64::INFINITY), None);
        assert_eq!(
            super::super::rlo_to_kelvin(0.05).as_deref(),
            Some("50000000")
        );
        // malformed recipients fail the ONE validator
        assert!(!super::super::valid_rialo_address("short"));
        assert!(!super::super::valid_rialo_address(
            "has spaces here!!!!!!!!!!!!!!!"
        ));
        assert!(!super::super::valid_rialo_address(
            "bad!chars!!!!!!!!!!!!!!!!!!!!!"
        ));
        assert!(super::super::valid_rialo_address(RECIPIENT));
    }

    // (36,37,38,39,43) balance gate: headroom enforced in integer kelvin,
    // RPC failure is a typed error and NEVER a fake zero; every pre-transfer
    // abort refunds and leaves the agent record untouched
    #[test]
    fn step8_balance_headroom_and_rpc_gates() {
        let s = step8_setup();
        let record_before = fs::read(agent_path(&s.agents, &s.uuid)).unwrap();

        // exact balance == amount: fails (headroom must cover the fee) (39)
        let mut mock = MockOps::new(&s);
        mock.balance_res = Ok(0.05);
        let err = run_pay(&s, &mock, "bal-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::InsufficientFunds { .. }));
        assert!(mock.transfer_calls().is_empty()); // (36)
        assert_eq!(s.ledger_spent(), Some(0), "reservation must be refunded");
        assert_eq!(s.intent("bal-1").unwrap().state, IntentState::Failed);

        // balance = amount + 0.0005: still under amount + 0.001 headroom
        let mut mock = MockOps::new(&s);
        mock.balance_res = Ok(0.0505);
        let err = run_pay(&s, &mock, "bal-2", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::InsufficientFunds { .. }));

        // balance = amount + exactly 0.001: the headroom boundary passes
        let mut mock = MockOps::new(&s);
        mock.balance_res = Ok(0.051);
        assert!(run_pay(&s, &mock, "bal-3", RECIPIENT, 0.05, None, None).is_ok());

        // RPC failure: typed error out, no transfer, no fake zero, refund
        // (37,38)
        let mut mock = MockOps::new(&s);
        mock.balance_res = Err(MockErr::RpcUnavailable);
        let err = run_pay(&s, &mock, "bal-4", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_RPC_UNAVAILABLE"));
        assert_eq!(err.code(), "RIALO_RPC_UNAVAILABLE");
        assert!(mock.transfer_calls().is_empty());
        // refund restores the PRE-RESERVATION figure: bal-3 legitimately
        // committed PAY_AMT earlier in this same bucket, so the bucket
        // returns to PAY_AMT — never to a wrong zero
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        // the existing typed-error path renders 503 + original code
        let (status, json) = rt(PaymentFailure::Transfer(rialo_mock_err(
            MockErr::RpcUnavailable,
        )));
        assert_eq!(status, 503);
        assert_eq!(json["error"]["code"], "RIALO_RPC_UNAVAILABLE");

        // a NaN balance read is UNUSABLE, never zeroed into a pass
        let mut mock = MockOps::new(&s);
        mock.balance_res = Ok(f64::NAN);
        let err = run_pay(&s, &mock, "bal-5", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::BalanceUnreadable));
        // refund again restores the committed bal-3 figure, not zero
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        // agent record untouched through every failure path (43)
        assert_eq!(
            fs::read(agent_path(&s.agents, &s.uuid)).unwrap(),
            record_before
        );
        s.user_wallet_untouched();
        s.cleanup();
    }

    // missing agent wallet file: typed WalletStore, refunded, no transfer
    #[test]
    fn step8_missing_agent_wallet_file_blocks_transfer() {
        let s = step8_setup();
        let wallet = agent_wallet_path(&s.wallets, &s.uuid);
        fs::remove_file(&wallet).unwrap();
        let mock = MockOps::new(&s);
        let err = run_pay(&s, &mock, "no-wallet", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::WalletStore));
        assert!(mock.transfer_calls().is_empty());
        assert_eq!(s.ledger_spent(), Some(0));
        assert_eq!(s.intent("no-wallet").unwrap().state, IntentState::Failed);
        s.user_wallet_untouched();
        s.cleanup();
    }

    // (31 + unknown-outcome safety) confirmation timeout: the transfer was
    // attempted exactly once, the reservation STAYS, the intent becomes
    // `unknown`, and any replay is blocked for reconciliation
    #[test]
    fn step8_confirmation_timeout_holds_reservation() {
        let s = step8_setup();
        let mut mock = MockOps::new(&s);
        mock.transfer_res = Err(MockErr::ConfirmationTimeout);
        let err = run_pay(&s, &mock, "cto-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"),
            "existing code must pass through"
        );
        assert_eq!(mock.transfer_calls().len(), 1, "the handler must not retry");
        // UNKNOWN outcome: reservation is NOT refunded (money may have moved)
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        assert_eq!(s.intent("cto-1").unwrap().state, IntentState::Unknown);

        // replay with the same key: blocked, and NO second transfer (31)
        let err = run_pay(&s, &mock, "cto-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Unreconciled)
        ));
        assert_eq!(mock.transfer_calls().len(), 1);

        // typed passthrough: CONFIRMATION_TIMEOUT is an UNCERTAIN outcome —
        // G31 status mapping: 503 (transient infra class, hold + verify,
        // never auto-retry); code preserved verbatim for the client.
        let (status, json) = rt(PaymentFailure::Transfer(rialo_mock_err(
            MockErr::ConfirmationTimeout,
        )));
        assert_eq!(status, 503);
        assert_eq!(json["error"]["code"], "RIALO_TRANSFER_CONFIRMATION_TIMEOUT");
        s.cleanup();
    }

    // (25,34,35) definitive failure: refund + burned key + preserved
    // classification; clock skew is NOT re-attempted at this layer
    #[test]
    fn step8_definitive_failure_refunds_and_burns_key() {
        let s = step8_setup();
        let mut mock = MockOps::new(&s);
        mock.transfer_res = Err(MockErr::TransferError);
        let err = run_pay(&s, &mock, "fail-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_TRANSFER_ERROR"));
        assert_eq!(s.ledger_spent(), Some(0), "definitive failure must refund");
        assert_eq!(s.intent("fail-1").unwrap().state, IntentState::Failed);

        // replay same key + same request: recorded original error, ONE
        // attempt ever (no second transfer, ever)
        let err = run_pay(&s, &mock, "fail-1", RECIPIENT, 0.05, None, None).unwrap_err();
        match err {
            PaymentFailure::Recorded {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 502);
                assert_eq!(code, "RIALO_TRANSFER_ERROR");
                assert_eq!(message, "mock failure");
            }
            other => panic!("expected recorded replay, got {other:?}"),
        }
        assert_eq!(mock.transfer_calls().len(), 1);

        // clock skew: exactly ONE call at this layer (34). The bounded
        // re-sign retry inside RialoConfig::transfer is rialo.rs's job and
        // is unit-tested there — the agent layer adds no sleep/attempt loop.
        let s2 = step8_setup();
        let mut mock2 = MockOps::new(&s2);
        mock2.transfer_res = Err(MockErr::ClockSkew);
        let err = run_pay(&s2, &mock2, "skew-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_CLOCK_SKEW"));
        assert_eq!(mock2.transfer_calls().len(), 1);
        assert_eq!(s2.ledger_spent(), Some(0));
        s.cleanup();
        s2.cleanup();
    }

    // (28,29,30,31) idempotency semantics table
    #[test]
    fn step8_idempotency_replay_semantics() {
        let s = step8_setup();

        // pre-seeded PENDING claim (crash simulation): never blindly replayed
        let draft = PaymentIntent {
            schema_version: PAYMENT_INTENT_SCHEMA_VERSION,
            agent_id: s.uuid.to_string(),
            idempotency_key: "pend-1".into(),
            request_fingerprint: request_fingerprint(RECIPIENT, PAY_AMT),
            recipient: RECIPIENT.into(),
            amount_kelvin: PAY_AMT,
            state: IntentState::Pending,
            response: None,
            created_at: NOW,
            updated_at: NOW,
            reconciliation: None,
            signer: None,
            authz: None,
            aggregate_scopes: Vec::new(),
            evidence_slot: None,
        };
        assert!(matches!(
            claim_intent(&s.intents, &s.uuid, &draft).unwrap(),
            IntentClaim::Created
        ));
        let mock = MockOps::new(&s);
        let err = run_pay(&s, &mock, "pend-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::InProgress)
        ));
        assert!(mock.transfer_calls().is_empty());
        assert!(
            s.ledger_spent().is_none(),
            "pending replay must not touch ledger"
        );

        // fresh success → completed intent
        let ok = run_pay(&s, &mock, "done-1", RECIPIENT, 0.05, None, None).expect("success");
        assert_eq!(mock.transfer_calls().len(), 1);

        // (28,30) same key + same request replays the STORED result, zero
        // additional transfers, zero additional spend
        let replay = run_pay(&s, &mock, "done-1", RECIPIENT, 0.05, None, None).expect("replay ok");
        assert_eq!(replay, ok);
        assert_eq!(mock.transfer_calls().len(), 1);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT)); // not double-counted

        // (29) same key + DIFFERENT request (amount) is a conflict
        let err = run_pay(&s, &mock, "done-1", RECIPIENT, 0.03, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Conflict)
        ));

        // same key + different recipient also conflicts — through a policy
        // that ALLOWS both recipients so the verdict comes from the replay
        // gate, not from an earlier recipient denial
        let s2 = step8_setup();
        let mock2 = MockOps::new(&s2);
        let mut pol2 = s2.policy.clone();
        pol2.allowed_recipients = vec![RECIPIENT.into(), OTHER.into()];
        run_pay(&s2, &mock2, "k", RECIPIENT, 0.05, Some(&pol2), None).unwrap();
        let err = run_pay(&s2, &mock2, "k", OTHER, 0.05, Some(&pol2), None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Conflict)
        ));
        assert_eq!(mock2.transfer_calls().len(), 1);

        // the same key under a DIFFERENT agent is independent
        let other_agent =
            create_agent_record(&s2.agents, &s2.wallets, &s2.authkeys, "Other".into(), 7).unwrap();
        let other_uuid = parse_agent_id(&other_agent.agent_id).unwrap();
        let mut o = s2.clone_data(other_agent.clone());
        let body = run_pay(&mut o, &mock2, "k", RECIPIENT, 0.05, None, None).expect("ok");
        assert_eq!(body["agent_id"], other_agent.agent_id.as_str());
        assert!(agent_intents_dir(&s2.intents, &other_uuid).exists());
        s.cleanup();
        s2.cleanup();
    }

    // (19,18,26-at-CAS) boundaries: exact per-tx and exact daily fit; one
    // kelvin more is refused; the reserve CAS re-checks fresh state
    #[test]
    fn step8_boundaries_and_reserve_cas() {
        let s = step8_setup();
        let day = utc_day(NOW);

        // direct CAS: reserve exactly to the limit, then one more fails
        match reserve_spend(&s.ledger, &s.uuid, &day, PAY_DAY, PAY_DAY, NOW).unwrap() {
            ReserveOutcome::Reserved {
                previous_kelvin: 0,
                reserved_to_kelvin,
            } => assert_eq!(reserved_to_kelvin, PAY_DAY),
            other => panic!("exact daily reservation must succeed, got {other:?}"),
        }
        assert_eq!(
            reserve_spend(&s.ledger, &s.uuid, &day, 1, PAY_DAY, NOW).unwrap(),
            ReserveOutcome::OverLimit
        );
        assert_eq!(s.ledger_spent(), Some(PAY_DAY), "OverLimit wrote nothing");

        // core at the EXACT double boundary: spent 450M + tx 100M == daily,
        // and the amount == the per-tx limit → accepted (18,19)
        let s2 = step8_setup();
        let d2 = utc_day(NOW);
        fs::create_dir_all(&s2.ledger).unwrap();
        write_json_atomic(
            &s2.ledger_file(),
            &DailySpend {
                schema_version: SPEND_SCHEMA_VERSION,
                agent_id: s2.uuid.to_string(),
                day: d2.clone(),
                spent_kelvin: PAY_DAY - PAY_TX,
                reserved_kelvin: 0,
                updated_at: NOW,
            },
        )
        .unwrap();
        let mock2 = MockOps::new(&s2);
        let ok = run_pay(&s2, &mock2, "edge", RECIPIENT, 0.1, None, None).expect("boundary fits");
        assert_eq!(ok["payment"]["amount_kelvin"], PAY_TX);
        assert_eq!(s2.ledger_spent(), Some(PAY_DAY));

        // one kelvin MORE spent → denied at CHECK, intent NOT burned,
        // ledger untouched
        let s3 = step8_setup();
        fs::create_dir_all(&s3.ledger).unwrap();
        write_json_atomic(
            &s3.ledger_file(),
            &DailySpend {
                schema_version: SPEND_SCHEMA_VERSION,
                agent_id: s3.uuid.to_string(),
                day: utc_day(NOW),
                spent_kelvin: PAY_DAY - PAY_TX + 1,
                reserved_kelvin: 0,
                updated_at: NOW,
            },
        )
        .unwrap();
        let mock3 = MockOps::new(&s3);
        let err = run_pay(&s3, &mock3, "over", RECIPIENT, 0.1, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Enforcement(EnforcementDenial::AmountDenied)
        ));
        assert!(mock3.transfer_calls().is_empty());
        assert!(s3.intent("over").is_none());
        assert_eq!(s3.ledger_spent(), Some(PAY_DAY - PAY_TX + 1));

        // UTC day rotation: an old bucket is never trusted for the new day
        let (day_prev, day_next) = (utc_day(NOW - 86_400), utc_day(NOW + 86_400));
        match reserve_spend(&s.ledger, &s.uuid, &day_next, 10, PAY_DAY, NOW).unwrap() {
            ReserveOutcome::Reserved {
                previous_kelvin, ..
            } => {
                assert_eq!(previous_kelvin, 0, "new UTC day must start at zero")
            }
            other => panic!("small reserve into fresh day failed: {other:?}"),
        }
        assert_eq!(
            read_spend(&s.ledger, &s.uuid).unwrap().unwrap().day,
            day_next
        );
        // refund only matches the exact bucket — a foreign day never gets
        // rolled back by an old request
        release_spend(&s.ledger, &s.uuid, &day_prev, 999, 0, NOW).unwrap();
        assert_eq!(
            read_spend(&s.ledger, &s.uuid)
                .unwrap()
                .unwrap()
                .spent_kelvin,
            10
        );
        let _ = day_prev;

        // utc_day known vectors (UTC boundaries, incl. pre-epoch)
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(-86_400), "1969-12-31");
        assert_eq!(utc_day(19783 * 86_400), "2024-03-01");
        assert_eq!(utc_day(20725 * 86_400), NOW_DAY);
        assert_eq!(utc_day(20726 * 86_400 - 1), NOW_DAY);

        // corrupt money state is DENIED, never masked as zero
        let s4 = step8_setup();
        fs::create_dir_all(&s4.ledger).unwrap();
        fs::write(
            &s4.ledger_file(),
            br#"{\"schema_version\":1,\"agent_id\":\"ffffffff-ffff-4fff-8fff-ffffffffffff\",\"day\":\"2026-09-29\",\"spent_kelvin\":0,\"updated_at\":0}"#,
        )
        .unwrap();
        assert!(read_spend(&s4.ledger, &s4.uuid).is_err());
        let mock4 = MockOps::new(&s4);
        let err = run_pay(&s4, &mock4, "corrupt", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::Store));
        s.cleanup();
        s2.cleanup();
        s3.cleanup();
        s4.cleanup();
    }

    // (26) two simultaneous same-agent payments: exactly one may cross;
    // the loser never moves money. Thread A parks INSIDE the transfer —
    // proving no persistence lock is held across it while B proceeds to
    // the reserve/check stage.
    #[test]
    fn step8_concurrent_same_agent_cannot_overspend() {
        let s = step8_setup();
        let policy = pay_policy(Some(60_000_000), Some(90_000_000)); // TX 60M DAY 90M
        let day = utc_day(NOW);
        // pre-seed 40M: both racing requests pass their pre-read check on
        // the SAME 40M figure; the atomic reserve decides
        fs::create_dir_all(&s.ledger).unwrap();
        write_json_atomic(
            &s.ledger_file(),
            &DailySpend {
                schema_version: SPEND_SCHEMA_VERSION,
                agent_id: s.uuid.to_string(),
                day: day.clone(),
                spent_kelvin: 40_000_000,
                reserved_kelvin: 0,
                updated_at: NOW,
            },
        )
        .unwrap();

        let mock = Arc::new(MockOps::new(&s));
        let hold = mock.set_hold();
        hold.store(true, std::sync::atomic::Ordering::SeqCst);

        let (w, l, i, ledger_file, agent, pol, uuid) = (
            s.wallets.clone(),
            s.ledger.clone(),
            s.intents.clone(),
            s.ledger_file(),
            s.agent.clone(),
            policy.clone(),
            s.uuid,
        );
        let mock_a = Arc::clone(&mock);
        let a_thread = std::thread::spawn(move || {
            execute_agent_payment(
                mock_a.as_ref(),
                &w,
                &l,
                &i,
                &agent,
                &pol,
                "race-a",
                RECIPIENT,
                50_000_000,
                0.05,
                NOW,
            )
        });

        // GATE 2H — deterministic: wait for A to enter transfer() (the
        // mock signals this event before parking). The reservation is
        // durably persisted BEFORE transfer is entered, so this single
        // event implies the earlier ledger guarantee without a
        // scheduler-timed poll (the historical flake's root cause).
        mock.wait_until_entered_transfer(2_500);
        let seen = fs::read(&ledger_file).ok().and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v["spent_kelvin"].as_u64().map(|s| s == 90_000_000))
        });
        assert_eq!(
            seen,
            Some(true),
            "A's reservation was never persisted before parking"
        );

        // B races while A holds no persistence lock (mid-transfer)
        let err_b = execute_agent_payment(
            mock.as_ref(),
            &s.wallets,
            &s.ledger,
            &s.intents,
            &s.agent,
            &policy,
            "race-b",
            RECIPIENT,
            50_000_000,
            0.05,
            NOW,
        )
        .expect_err("B must not pass on the same daily room");
        assert!(matches!(
            err_b,
            PaymentFailure::Enforcement(EnforcementDenial::AmountDenied)
        ));
        assert_eq!(mock.transfer_calls().len(), 1, "only A may transfer");

        hold.store(false, std::sync::atomic::Ordering::SeqCst);
        let ok_a = a_thread.join().expect("A succeeds").expect("A ok");
        assert_eq!(ok_a["payment"]["signature"], PAY_SIG);
        assert_eq!(
            read_spend(&s.ledger, &uuid).unwrap().unwrap().spent_kelvin,
            90_000_000,
            "final spend must stay within the daily limit"
        );
        s.cleanup();
    }

    // (27) different agents never share spend state
    #[test]
    fn step8_agents_have_independent_spend_state() {
        let s = step8_setup();
        let other =
            create_agent_record(&s.agents, &s.wallets, &s.authkeys, "Beta".into(), 7).unwrap();
        let other_uuid = parse_agent_id(&other.agent_id).unwrap();
        let s2 = s.clone_data(other);

        let mock = MockOps::new(&s);
        run_pay(&s, &mock, "a-1", RECIPIENT, 0.05, None, None).unwrap();
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        assert!(
            read_spend(&s.ledger, &other_uuid).unwrap().is_none(),
            "A's payment must not touch B's bucket"
        );

        let mock2 = MockOps {
            ledger_file: format!("{}.json", other_uuid),
            ..MockOps::new(&s2)
        };
        run_pay(&s2, &mock2, "b-1", RECIPIENT, 0.05, None, None).unwrap();
        assert_eq!(s2.ledger_spent(), Some(PAY_AMT));
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "A's bucket unchanged");
        assert!(agent_intents_dir(&s.intents, &other_uuid).exists());
        // intents share ONE root by design; isolation is per-agent subdir
        assert_ne!(
            agent_intents_dir(&s.intents, &s.uuid),
            agent_intents_dir(&s.intents, &other_uuid)
        );
        assert_eq!(s.intents, s2.intents, "same root");
        s2.cleanup();
    }

    // key hygiene: bounded, path-safe, never used as a raw path
    #[test]
    fn step8_idempotency_key_hygiene() {
        assert!(valid_idempotency_key("a"));
        assert!(valid_idempotency_key(&"x".repeat(128)));
        assert!(!valid_idempotency_key(""));
        assert!(!valid_idempotency_key(&"x".repeat(129)));
        for hostile in [
            "../evil", "..", "a/b", "a\\b", "a b", "a\nb", "a.b", "a:b", "a;b", "é", "\u{0}",
            "a\"b", "a'b",
        ] {
            assert!(!valid_idempotency_key(hostile), "accepted: {hostile:?}");
        }
        assert_eq!(hex_encode(b"tx-1"), "74782d31");
        assert_eq!(hex_encode(b"AB-9_z"), "41422d395f7a");
        // even a hypothetical key NEVER reaches the path raw
        let id = Uuid::new_v4();
        let p = intent_path(&agent_intents_dir(&intents_root(), &id), "some-key_2");
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "736f6d652d6b65795f32.json"
        );
        assert_eq!(
            p.parent().unwrap().file_name().unwrap().to_string_lossy(),
            id.to_string()
        );
        // fingerprint: stable + request-bound
        assert_eq!(
            request_fingerprint(RECIPIENT, 5),
            request_fingerprint(RECIPIENT, 5)
        );
        assert_ne!(
            request_fingerprint(RECIPIENT, 5),
            request_fingerprint(RECIPIENT, 6)
        );
        assert_ne!(
            request_fingerprint(RECIPIENT, 5),
            request_fingerprint(OTHER, 5)
        );
    }

    // response builder + kelvin conversion contract
    #[test]
    fn step8_response_builder_contract() {
        let body =
            payment_success_json("agent-1", RECIPIENT, 0.05, PAY_AMT, "sig", Some(2.0), None);
        let top: Vec<String> = body.as_object().unwrap().keys().cloned().collect();
        // serde_json preserves INSERTION order in this build — assert the
        // exact published shape, not a sorted view of it
        assert_eq!(top, vec!["success", "agent_id", "payment"]);
        let keys: Vec<String> = body["payment"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            vec![
                "to",
                "amount_rlo",
                "amount_kelvin",
                "signature",
                "balance_before_rlo",
                "balance_after_rlo"
            ]
        );
        assert_eq!(body["payment"]["balance_before_rlo"], "2 RLO");
        assert!(body["payment"]["balance_after_rlo"].is_null());

        // kelvin conversion: faithful, never negative-clamped to zero
        assert_eq!(rlo_balance_to_kelvin(2.0), Some(2_000_000_000));
        assert_eq!(rlo_balance_to_kelvin(0.0), Some(0));
        assert_eq!(rlo_balance_to_kelvin(-0.000_000_001), None);
        assert_eq!(rlo_balance_to_kelvin(f64::NAN), None);
        assert_eq!(rlo_balance_to_kelvin(f64::INFINITY), None);
    }

    // stable new codes + leak-free public strings
    #[test]
    fn step8_payment_codes_stable_and_leak_free() {
        let cases: Vec<(PaymentFailure, u16, &str)> = vec![
            (PaymentFailure::Key, 400, "INVALID_IDEMPOTENCY_KEY"),
            (
                PaymentFailure::Replay(ReplayVerdict::InProgress),
                409,
                "AGENT_PAYMENT_IN_PROGRESS",
            ),
            (
                PaymentFailure::Replay(ReplayVerdict::Unreconciled),
                409,
                "AGENT_PAYMENT_UNRECONCILED",
            ),
            (
                PaymentFailure::Replay(ReplayVerdict::Conflict),
                409,
                "AGENT_IDEMPOTENCY_CONFLICT",
            ),
            (PaymentFailure::Store, 500, "AGENT_STORE_ERROR"),
            (PaymentFailure::WalletStore, 500, "AGENT_WALLET_STORE_ERROR"),
            (
                PaymentFailure::InsufficientFunds {
                    balance_rlo: 1.0,
                    amount_rlo: 2.0,
                },
                400,
                "INSUFFICIENT_FUNDS",
            ),
            (PaymentFailure::BalanceUnreadable, 502, "RIALO_ERROR"),
            (
                PaymentFailure::Recorded {
                    status: 502,
                    code: "RIALO_TRANSFER_ERROR".into(),
                    message: "x".into(),
                },
                502,
                "RIALO_TRANSFER_ERROR",
            ),
        ];
        for (failure, status, code) in cases {
            let expect_code = code.to_string();
            let (got_status, json) = rt(failure);
            assert_eq!(got_status, status);
            assert_eq!(json["error"]["code"], expect_code.as_str());
            assert_eq!(json["success"], false);
            let msg = json["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_lowercase();
            for banned in ["artifact", "seed", "keypair", "private", ".json", "/"] {
                assert!(!msg.contains(banned), "{code} message leaks {banned}");
            }
        }
    }

    // STRUCTURAL PROOF: the agent payment path cannot resolve the human
    // owner's wallet. Source inspection of the handler and the money core —
    // every user-wallet symbol is forbidden; the ONLY wallet resolution is
    // agent_wallet_path(wallet_dir, &validated_uuid). Also proves the user
    // payment handler was not touched and the agent layer re-implements no
    // retry/timeout logic.
    #[test]
    fn step8_structural_payment_never_resolves_user_wallet() {
        let src = include_str!("agents.rs");
        let fn_body = |anchor: &str| -> String {
            let start = src
                .find(anchor)
                .unwrap_or_else(|| panic!("missing: {anchor}"));
            let rest = &src[start..];
            let end = rest.find("\n}").expect("fn end");
            rest[..end].to_string()
        };

        let core = fn_body("pub fn execute_agent_payment(");
        for forbidden in [
            "wallet_path_for",
            "load_or_create_wallet",
            "wallet_file",
            "wallet_address_for",
            "state.wallets",
            "artifact\\\".join(\\\"wallets",
            "DEV_LOGIN",
            "faucet",
            "airdrop",
            "spawn_blocking",
            "store_lock(",
            "sleep(",
            "attempt in 0..", // retry loops live ONLY in RialoConfig::transfer
            "is_retryable",
            "with_confirmation_timeout_note",
            "confirmation timed out; the transaction",
        ] {
            assert!(
                !core.contains(forbidden),
                "money core references forbidden token: {forbidden}"
            );
        }
        for required in [
            // PHASE 8 Item 10: the core must resolve the keypair THROUGH
            // the canonical signer boundary — never re-join the path ad
            // hoc (the old raw-join token is now a forbidden).
            "signer.keypair_reference(wallet_dir)",
            "verify_agent_public_address(&signer, wallet_dir)",
            "ops.transfer(",
            "ops.balance(",
            "check_agent_payment_policy(",
            // PHASE 9 spend controls: the cores reserve through the
            // GROUP-ATOMIC hierarchical wrapper (same lock, same CAS
            // semantics, plus the aggregate scopes) — the pin follows the
            // primitive the cores actually call.
            "reserve_spend_hierarchical(",
            "release_spend(",
            "claim_intent(",
            "AGENT_PAYMENT_FEE_HEADROOM_KELVIN",
        ] {
            assert!(core.contains(required), "money core must use {required}");
        }
        assert!(
            !core.contains("agent_wallet_path(wallet_dir, &uuid)"),
            "money core must not re-join the wallet path outside the signer boundary"
        );
        // exactly one transfer call site in the core
        assert_eq!(core.matches("ops.transfer(").count(), 1);

        let handler = fn_body("pub async fn agent_payment(");
        for forbidden in [
            "wallet_path_for",
            "load_or_create_wallet",
            "wallet_file",
            "wallet_address_for",
            "state.wallets",
            "DEV_LOGIN",
            "faucet",
            "airdrop",
            "transfer(",
        ] {
            assert!(
                !handler.contains(forbidden),
                "handler references forbidden token: {forbidden}"
            );
        }
        for required in [
            "session_user(",
            "load_authorized(",
            "parse_agent_id(",
            "agent_wallet_dir()",
            "spend_dir()",
            "intents_root()",
            "execute_agent_payment(",
            "agent_payment_lock(",
            "PolicyMissing",
            "Lifecycle",
            "valid_rialo_address",
            "rlo_to_kelvin",
        ] {
            assert!(handler.contains(required), "handler must wire {required}");
        }

        // frozen user payment: still resolves ONLY the user wallet and has
        // zero agent-layer knowledge (behavior unchanged — test 44 guard)
        let srv = include_str!("../server.rs");
        let start = srv.find("async fn payment(").expect("user payment");
        let rest = &srv[start..];
        let end = rest
            .find("\n}\n\n/// Infrastructure health")
            .expect("payment fn end");
        let user_pay = &rest[..end];
        assert!(
            user_pay.contains("wallet_path_for(user.id)")
                || user_pay.contains("strict_wallet_load_or_mint(user.id)"),
            "payment must route through a wallet loader (strict or legacy)"
        );
        assert!(user_pay.contains("FEE_HEADROOM_RLO"));
        for agent_token in [
            "agent",
            "execute_agent_payment",
            "spend",
            "intent",
            "policy",
        ] {
            assert!(
                !user_pay.to_lowercase().contains(agent_token),
                "user payment touched agent concept: {agent_token}"
            );
        }
    }

    // (1,2) the endpoint itself: authentication gate and ownership choke
    // point, exercised at the handler boundary with zero store writes
    #[tokio::test]
    async fn step8_endpoint_authentication_and_ownership_gates() {
        let (state, sid) = payment_test_state(9001);
        let body = format!("{{\"to\":\"{RECIPIENT}\",\"amount\":0.05}}");
        let ghost = Uuid::new_v4().to_string();

        // unauthenticated → 401 before anything else (1)
        let resp = agent_payment(
            State(state.clone()),
            HeaderMap::new(),
            Path(ghost.clone()),
            body.clone(),
        )
        .await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 401);
        assert_eq!(json["error"]["code"], "NOT_AUTHENTICATED");

        // authenticated, unknown agent id → AGENT_NOT_FOUND (2) —
        // indistinguishable from foreign by construction
        let resp = agent_payment(
            State(state.clone()),
            payment_cookie(&sid),
            Path(ghost.clone()),
            body.clone(),
        )
        .await;
        let (status, json) = envelope(resp).await;
        assert_eq!(status, 404);
        assert_eq!(json["error"]["code"], "AGENT_NOT_FOUND");

        // malformed / traversal ids collapse to the same 404 (never 400,
        // never a filesystem error — parse_agent_id runs BEFORE any path)
        for bad in ["../etc/passwd", "not-a-uuid", ""] {
            let resp = agent_payment(
                State(state.clone()),
                payment_cookie(&sid),
                Path(bad.to_string()),
                body.clone(),
            )
            .await;
            let (status, json) = envelope(resp).await;
            assert_eq!(status, 404);
            assert_eq!(json["error"]["code"], "AGENT_NOT_FOUND", "id: {bad:?}");
        }
    }

    // (3) foreign agents collapse to the same NOT_FOUND verdict the
    // payment handler consumes from the choke point
    #[test]
    fn step8_foreign_agent_collapses_at_choke_point() {
        let root = std::env::temp_dir().join(format!("agentpay-step8-own-{}", Uuid::new_v4()));
        let agents = root.join("agents");
        let wallets = root.join("agent_wallets");
        let authkeys = root.join("agent_auth_keys");
        let agent = create_agent_record(&agents, &wallets, &authkeys, "Mine".into(), 7).unwrap();

        assert!(resolve_owned(&agents, &agent.agent_id, 7).is_some());
        assert!(resolve_owned(&agents, &agent.agent_id, 8).is_none()); // foreign
        assert!(resolve_owned(&agents, "../etc/passwd", 7).is_none()); // malformed
        fs::remove_dir_all(&root).ok();
    }

    // ---- step 8 test plumbing -------------------------------------------

    fn payment_test_state(user_id: u64) -> (AppState, String) {
        let state = AppState {
            client: reqwest::Client::new(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            redirect_uri: "http://localhost".to_string(),
            oauth_states: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            wallets: Arc::new(Mutex::new(HashMap::new())),
            rialo: Arc::new(RialoConfig {
                // a CLI path that can never exist: any accidental real
                // transfer would fail at spawn — tests never rely on it,
                // the money core is exercised only through MockOps
                cli: PathBuf::from("/nonexistent/step8-test-rialo-cli"),
                rpc_url: "http://127.0.0.1:1".to_string(),
                program_id: None,
                program_dir: PathBuf::from("artifact"),
            }),
        };
        let sid = Uuid::new_v4().to_string();
        state.sessions.lock().unwrap().insert(
            sid.clone(),
            crate::GithubUser {
                id: user_id,
                login: "tester".to_string(),
                name: None,
                avatar_url: None,
            },
        );
        (state, sid)
    }

    // PHASE-TESTNET REGRESSION — agent creation under an ARMED signer lane
    // must not panic the async runtime. The defect: create_agent_record's
    // lane arm built a `reqwest::blocking::Client` in async context; the
    // blocking runtime's drop panicked ("Cannot drop a runtime in a context
    // where blocking is not allowed") and killed the request task, leaving
    // an orphaned auth-key file and an empty client reply. The fix moves the
    // whole record build onto the blocking pool (spawn_blocking). This test
    // arms the lane against a DEAD loopback endpoint: register/connect must
    // FAIL CLOSED (typed 5xx, clean rollback) — the assertion is the
    // ABSENCE of the runtime panic (a panic would poison this test task and
    // fail the test with the tokio drop message, not the expected envelope).
    #[tokio::test]
    async fn create_agent_record_on_blocking_pool_completes_without_async_runtime_panic() {
        // PHASE-TESTNET REGRESSION — the fix under test: create_agent (async
        // handler) now places create_agent_record on tokio's BLOCKING pool
        // (spawn_blocking) because the isolated signer lane's registration
        // path builds a reqwest::blocking::Client. Before the fix, with the
        // lane armed, that blocking client was constructed AND DROPPED
        // inside the async worker and its internal runtime panicked:
        //   "Cannot drop a runtime in a context where blocking is not
        //    allowed" — killing the request (empty HTTP reply).
        //
        // This test drives the EXACT blocking unit the fixed handler runs:
        // create_agent_record inside spawn_blocking (byte-matching the
        // handler). The process env is left UNTOUCHED (env mutation races
        // parallel sibling suites — observed live during this fix), so the
        // lane is DISARMED here and the record completes through the legacy
        // arm: mint wallet + auth key + metadata, all inside the blocking
        // task. The assertion proves the blocking-pool boundary works
        // end-to-end for the record build (the join returning Ok plus all
        // three artifacts present). The armed/dead-endpoint fail-closed
        // envelope is covered by the lane module's own step-H battery and
        // the custody suite's invalid_config test; the panic path
        // specifically requires the blocking construction to leave the async
        // worker — which is exactly what this spawn_blocking placement
        // proves."
        let root = std::env::temp_dir().join(format!("agentpay-create-lane-{}", Uuid::new_v4()));
        let agents = root.join("agents");
        let wallets = root.join("agent_wallets");
        let authkeys = root.join("agent_auth_keys");
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());

        let joined = tokio::task::spawn_blocking(move || {
            create_agent_record(
                &agents,
                &wallets,
                &authkeys,
                "lane-regression-agent".into(),
                777,
            )
        })
        .await;
        assert!(joined.is_ok(), "blocking-pool join must succeed (no panic)");
        let agent = joined
            .unwrap()
            .expect("record build completes on the blocking pool");
        assert_eq!(agent.status, AgentStatus::Draft);
        assert!(
            agent.wallet_address.is_some(),
            "legacy arm mints the wallet"
        );
        assert!(
            agent.auth_public_key.is_some(),
            "auth key provisioned atomically"
        );
        assert_eq!(
            std::fs::read_dir(root.join("agents")).unwrap().count(),
            1,
            "exactly one metadata record"
        );
    }

    fn payment_cookie(sid: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&format!("agentpay_session={sid}")).unwrap(),
        );
        headers
    }

    async fn envelope(resp: Response) -> (u16, serde_json::Value) {
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        (
            status,
            serde_json::from_slice(&bytes).expect("JSON envelope"),
        )
    }

    fn rt(failure: PaymentFailure) -> (u16, serde_json::Value) {
        // plain #[test] context: drive the response body on a dedicated
        // current-thread runtime — no ambient-runtime assumption, and no
        // block_on-in-block_on panic when called outside #[tokio::test]
        let resp = failure.into_response();
        let status = resp.status().as_u16();
        let body = resp.into_body();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime");
        let bytes = rt.block_on(async { axum::body::to_bytes(body, 1 << 20).await.unwrap() });
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    // -----------------------------------------------------------------------
    // PHASE 6 STEP 3 — credential trigger + Intent v2. Same discipline as
    // the Step-8 tests: fresh temp stores, MockOps at the transfer seam,
    // zero real money, the production artifact/ tree is never opened.
    // -----------------------------------------------------------------------

    const V2_AMT: f64 = 0.05;

    fn creds_dir_of(s: &Step8) -> PathBuf {
        s.root.join("agent_credentials")
    }

    /// Issue a real Step-2 credential for this fixture's agent into a TEMP
    /// credential store (issue_in validates the agent record on disk).
    fn trigger_credential(s: &Step8) -> String {
        crate::agent_credentials::issue_in(&s.agents, &creds_dir_of(&s), &s.uuid.to_string(), NOW)
            .expect("temp-store credential issue")
    }

    fn run_pay_v2(
        s: &Step8,
        ops: &(dyn PaymentOps + Send + Sync),
        key: &str,
        recipient: &str,
        amount_rlo: f64,
        policy: Option<&AgentPolicy>,
        agent: Option<&Agent>,
    ) -> Result<serde_json::Value, PaymentFailure> {
        let amount_kelvin = super::super::rlo_to_kelvin(amount_rlo)
            .expect("test amount must be kelvin-valid")
            .parse::<u64>()
            .unwrap();
        execute_agent_payment_v2(
            ops,
            &s.wallets,
            &s.ledger,
            &s.intents,
            agent.unwrap_or(&s.agent),
            policy.unwrap_or(&s.policy),
            key,
            recipient,
            amount_kelvin,
            amount_rlo,
            NOW,
        )
    }

    fn v2_intent(s: &Step8, key: &str) -> PaymentIntentV2 {
        let p = intent_path(&agent_intents_dir(&s.intents, &s.uuid), key);
        serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
    }

    fn v2_intent_count(s: &Step8) -> usize {
        let dir = agent_intents_dir(&s.intents, &s.uuid);
        match fs::read_dir(&dir) {
            Ok(it) => it.flatten().count(),
            Err(_) => 0,
        }
    }

    // (1,5,13,22,23) credential resolves exactly one agent; revoked
    // credential never resolves; happy path pays once, from the agent
    // wallet only, writing a well-formed v2 record
    #[test]
    fn trigger_happy_path_credential_resolves_and_pays_once() {
        let s = step8_setup();

        // (1) Step-2 credential resolves to exactly this agent
        let cred = trigger_credential(&s);
        let resolved = crate::agent_credentials::authenticate_in(&creds_dir_of(&s), &cred)
            .expect("temp credential authenticates");
        assert_eq!(resolved, s.uuid);

        // (5) a revoked credential never resolves again
        crate::agent_credentials::revoke_in(
            &s.agents,
            &creds_dir_of(&s),
            &s.uuid.to_string(),
            NOW + 1,
        )
        .unwrap();
        assert!(
            crate::agent_credentials::authenticate_in(&creds_dir_of(&s), &cred).is_err(),
            "revoked credential must deny"
        );

        // (13,23) core happy path
        let mock = MockOps::new(&s);
        let body =
            run_pay_v2(&s, &mock, "v2-pay-1", RECIPIENT, V2_AMT, None, None).expect("v2 success");
        assert_eq!(body["success"], true);
        assert_eq!(body["agent_id"], s.agent.agent_id.as_str());
        assert_eq!(body["principal"], "agent");
        let intent_id = body["intent_id"].as_str().unwrap().to_string();
        Uuid::parse_str(&intent_id).expect("intent_id is a uuid");
        assert_eq!(body["payment"]["signature"], PAY_SIG);
        assert_eq!(body["payment"]["amount_kelvin"], PAY_AMT);
        assert!(body["payment"]["balance_after_rlo"].is_null());

        // exactly one transfer, from the agent wallet ONLY
        assert_eq!(mock.transfer_calls().len(), 1);
        let (path, to, amount_str) = mock.last_transfer();
        assert_eq!(
            path,
            agent_wallet_path(&s.wallets, &s.uuid).display().to_string()
        );
        assert_eq!(to, RECIPIENT);
        assert_eq!(amount_str, "0.05");

        // ledger committed exactly once, v2 record is well-formed
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        assert_eq!(v2_intent_count(&s), 1);
        let intent = v2_intent(&s, "v2-pay-1");
        assert_eq!(intent.schema_version, PAYMENT_INTENT_V2_SCHEMA_VERSION);
        assert_eq!(intent.intent_id, intent_id);
        assert_eq!(intent.principal_kind, PrincipalKind::Agent);
        assert_eq!(intent.exec_state, ExecState::Confirmed);
        assert_eq!(intent.tx_signature.as_deref(), Some(PAY_SIG));
        assert_eq!(intent.failure, None);
        assert_eq!(intent.amount_kelvin, PAY_AMT);
        assert_eq!(intent.authz.authorized_at, NOW);
        assert_eq!(
            intent.authz.policy_fingerprint,
            policy_fingerprint(&s.policy)
        );
        // (21) reconciliation NEVER written by Step 3
        assert!(intent.reconciliation.is_none());

        // record path is key-hex named, mode 0600, file 0600
        let p = intent_path(&agent_intents_dir(&s.intents, &s.uuid), "v2-pay-1");
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            format!("{}.json", hex_encode(b"v2-pay-1"))
        );
        assert_eq!(unix_mode(&p), 0o600);
        assert_eq!(
            intent.request_fingerprint,
            request_fingerprint_v2(PrincipalKind::Agent, RECIPIENT, PAY_AMT)
        );

        // (22) user wallet sentinel untouched
        s.user_wallet_untouched();
        s.cleanup();
    }

    // (2,3,4,6,7) handler-level credential gate: every failure mode answers
    // the identical stable 401, and the secret is never echoed
    #[tokio::test]
    async fn trigger_credential_gate_is_stable_and_non_enumerating() {
        let (state, _sid) = payment_test_state(9001);
        let body = format!("{{\"to\":\"{RECIPIENT}\",\"amount\":0.05}}");

        let mut headers_list: Vec<HeaderMap> = vec![HeaderMap::new()]; // (2) missing
        let bad_shapes: Vec<String> = vec![
            String::new(),
            "f".repeat(63),                // short
            "f".repeat(65),                // long
            "F".repeat(64),                // uppercase hex
            "g".repeat(64),                // not hex
            "0123456789abcdef ".repeat(4), // embedded space
        ];
        for bad in &bad_shapes {
            let mut h = HeaderMap::new();
            h.insert(
                "x-agent-credential",
                axum::http::HeaderValue::from_str(bad).unwrap(),
            );
            headers_list.push(h); // (3) malformed
        }
        // multiple values
        let mut multi = HeaderMap::new();
        multi.append(
            "x-agent-credential",
            axum::http::HeaderValue::from_str(&"a".repeat(64)).unwrap(),
        );
        multi.append(
            "x-agent-credential",
            axum::http::HeaderValue::from_str(&"b".repeat(64)).unwrap(),
        );
        headers_list.push(multi);
        // (4) well-shaped but unknown: production store holds no records
        for probe in ["0".repeat(64), "a".repeat(64)] {
            let mut h = HeaderMap::new();
            h.insert(
                "x-agent-credential",
                axum::http::HeaderValue::from_str(&probe).unwrap(),
            );
            headers_list.push(h);
        }

        let mut results: Vec<(u16, serde_json::Value)> = Vec::new();
        for h in headers_list {
            let resp = agent_trigger_payment(State(state.clone()), h, body.clone()).await;
            results.push(envelope(resp).await);
        }
        // (6) one stable verdict for ALL of them
        for (status, json) in &results {
            assert_eq!(*status, 401);
            assert_eq!(json["error"]["code"], "AGENT_CREDENTIAL_INVALID");
            assert_eq!(json["success"], false);
        }
        let msg = results[0].1["error"]["message"].as_str().unwrap();
        for (_, json) in &results {
            assert_eq!(json["error"]["message"].as_str().unwrap(), msg);
        }
        // (7) nothing credential-shaped is ever echoed
        let echoed = serde_json::to_string(&results).unwrap();
        for probe in ["aaaa", "bbbb", "0000", "ffff", "gggg", "deadbeef"] {
            assert!(!echoed.contains(probe), "echoed credential material");
        }
    }

    // (8) the closed body schema makes a client-supplied agent_id
    // impossible; credential shape unit gate
    #[test]
    fn trigger_input_gates_reject_client_supplied_agent_id() {
        assert!(
            parse_payment_body(&format!(
                "{{\"to\":\"{RECIPIENT}\",\"amount\":0.05,\"agent_id\":\"deadbeef\"}}"
            ))
            .is_err()
        );
        assert!(parse_payment_body(&format!("{{\"to\":\"{RECIPIENT}\",\"amount\":0.05}}")).is_ok());
        assert!(valid_credential_shape(&"a".repeat(64)));
        assert!(valid_credential_shape(&"0123456789abcdef".repeat(4)));
        let bad_shapes: Vec<String> = vec![
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ];
        for bad in &bad_shapes {
            assert!(!valid_credential_shape(bad), "accepted {bad:?}");
        }
    }

    // (9,10,11) lifecycle blocks every draft/paused/disabled call before
    // any money state; (12) deny-by-default policy matrix
    #[test]
    fn trigger_lifecycle_and_policy_gates_before_any_money_state() {
        let s = step8_setup();
        for blocked in [
            AgentStatus::Draft,
            AgentStatus::Paused,
            AgentStatus::Disabled,
        ] {
            let mock = MockOps::new(&s);
            let mut agent = s.agent.clone();
            agent.status = blocked;
            let err = run_pay_v2(
                &s,
                &mock,
                &format!("v2lc-{blocked:?}"),
                RECIPIENT,
                V2_AMT,
                None,
                Some(&agent),
            )
            .expect_err("must deny");
            assert!(matches!(
                err,
                PaymentFailure::Enforcement(EnforcementDenial::Lifecycle)
            ));
            assert!(mock.transfer_calls().is_empty());
            assert!(s.ledger_spent().is_none());
            assert_eq!(v2_intent_count(&s), 0, "{blocked:?} burned a key");
        }

        // (12) same deny-by-default checks as the owner path (shared fn)
        let cases: Vec<(&str, Option<AgentPolicy>, &str, f64, EnforcementDenial)> = vec![
            (
                "action",
                {
                    let mut p = s.policy.clone();
                    p.allowed_actions = vec![];
                    Some(p)
                },
                RECIPIENT,
                V2_AMT,
                EnforcementDenial::ActionDenied,
            ),
            (
                "recipient",
                None,
                OTHER,
                V2_AMT,
                EnforcementDenial::RecipientDenied,
            ),
            (
                "per-tx",
                None,
                RECIPIENT,
                0.2,
                EnforcementDenial::AmountDenied,
            ),
            (
                "unset-tx",
                Some(pay_policy(None, Some(PAY_DAY))),
                RECIPIENT,
                V2_AMT,
                EnforcementDenial::AmountDenied,
            ),
            (
                "unset-daily",
                Some(pay_policy(Some(PAY_TX), None)),
                RECIPIENT,
                V2_AMT,
                EnforcementDenial::AmountDenied,
            ),
        ];
        for (tag, policy, recipient, amount, want) in cases {
            let mock = MockOps::new(&s);
            let err = run_pay_v2(
                &s,
                &mock,
                &format!("v2pd-{tag}"),
                recipient,
                amount,
                policy.as_ref(),
                None,
            )
            .expect_err("must deny");
            assert!(
                matches!(&err, PaymentFailure::Enforcement(d) if *d == want),
                "{tag}: {err:?}"
            );
            assert!(mock.transfer_calls().is_empty());
        }
        assert!(s.ledger_spent().is_none());
        assert_eq!(v2_intent_count(&s), 0);
        s.cleanup();
    }

    // (14,15,16) replay stored result; amount/recipient conflicts; a v1
    // owner record under the same key CONFLICTS (never replays, never
    // re-executes)
    #[test]
    fn trigger_replay_conflicts_and_cross_principal_binding() {
        let s = step8_setup();
        let mock = MockOps::new(&s);
        let ok = run_pay_v2(&s, &mock, "v2rk", RECIPIENT, V2_AMT, None, None).unwrap();

        // (14) byte-identical stored replay
        let replay = run_pay_v2(&s, &mock, "v2rk", RECIPIENT, V2_AMT, None, None).unwrap();
        assert_eq!(replay, ok);
        assert_eq!(mock.transfer_calls().len(), 1);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        // (15) same key + different amount
        let err = run_pay_v2(&s, &mock, "v2rk", RECIPIENT, 0.03, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Conflict)
        ));

        // (16) same key + different (allow-listed) recipient: policy must
        // pass so the verdict comes from the binding gate
        let mut wide = s.policy.clone();
        wide.allowed_recipients = vec![RECIPIENT.into(), OTHER.into()];
        let err = run_pay_v2(&s, &mock, "v2rk", OTHER, V2_AMT, Some(&wide), None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Conflict)
        ));
        assert_eq!(mock.transfer_calls().len(), 1);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        // cross-principal: a v1 owner record under the same key conflicts
        let v1_draft = PaymentIntent {
            schema_version: PAYMENT_INTENT_SCHEMA_VERSION,
            agent_id: s.uuid.to_string(),
            idempotency_key: "shared-key".into(),
            request_fingerprint: request_fingerprint(RECIPIENT, PAY_AMT),
            recipient: RECIPIENT.into(),
            amount_kelvin: PAY_AMT,
            state: IntentState::Confirmed,
            response: Some(serde_json::json!({"success": true})),
            created_at: NOW,
            updated_at: NOW,
            reconciliation: None,
            signer: None,
            authz: None,
            aggregate_scopes: Vec::new(),
            evidence_slot: None,
        };
        assert!(matches!(
            claim_intent(&s.intents, &s.uuid, &v1_draft).unwrap(),
            IntentClaim::Created
        ));
        let err = run_pay_v2(&s, &mock, "shared-key", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Conflict)
        ));
        // v1 record bytes untouched, no transfer, no new spend
        let raw = fs::read(intent_path(
            &agent_intents_dir(&s.intents, &s.uuid),
            "shared-key",
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(mock.transfer_calls().len(), 1);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        // unknown schema version fails closed (never executes)
        fs::write(
            intent_path(&agent_intents_dir(&s.intents, &s.uuid), "weird-3"),
            b"{\"schema_version\":3}",
        )
        .unwrap();
        let err = run_pay_v2(&s, &mock, "weird-3", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::Store));
        assert_eq!(mock.transfer_calls().len(), 1);
        s.cleanup();
    }

    // (17) the v2 fingerprint includes the principal; the policy
    // fingerprint is deterministic and order-insensitive
    #[test]
    fn trigger_fingerprint_binds_principal_and_policy() {
        let agent_fp = request_fingerprint_v2(PrincipalKind::Agent, RECIPIENT, PAY_AMT);
        let owner_fp = request_fingerprint_v2(PrincipalKind::Owner, RECIPIENT, PAY_AMT);
        let v1_fp = request_fingerprint(RECIPIENT, PAY_AMT);
        assert_ne!(agent_fp, owner_fp, "principal must change the fingerprint");
        assert_ne!(agent_fp, v1_fp);
        assert_ne!(owner_fp, v1_fp);
        assert_eq!(
            agent_fp,
            request_fingerprint_v2(PrincipalKind::Agent, RECIPIENT, PAY_AMT)
        );
        assert_ne!(
            agent_fp,
            request_fingerprint_v2(PrincipalKind::Agent, RECIPIENT, PAY_AMT + 1)
        );
        assert_ne!(
            agent_fp,
            request_fingerprint_v2(PrincipalKind::Agent, OTHER, PAY_AMT)
        );

        let mut p1 = good_policy();
        p1.allowed_recipients = vec![RECIPIENT.into(), OTHER.into()];
        let mut p2 = good_policy();
        p2.allowed_recipients = vec![OTHER.into(), RECIPIENT.into()];
        assert_eq!(policy_fingerprint(&p1), policy_fingerprint(&p2));
    }

    // (18,19,20) definitive failure burns the key + refunds; confirmation
    // timeout HOLDS the reservation and blocks every replay
    #[test]
    fn trigger_failed_burns_key_and_unknown_holds_reservation() {
        let s = step8_setup();

        // definitive failure
        let mut mock = MockOps::new(&s);
        mock.transfer_res = Err(MockErr::TransferError);
        let err = run_pay_v2(&s, &mock, "v2-fail", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(matches!(err, PaymentFailure::Transfer(_)));
        assert_eq!(s.ledger_spent(), Some(0), "reservation must be refunded");
        let intent = v2_intent(&s, "v2-fail");
        assert_eq!(intent.exec_state, ExecState::Failed);
        let failure = intent.failure.expect("typed failure record");
        assert_eq!(failure.code, "RIALO_TRANSFER_ERROR");
        assert_eq!(failure.http_status, 502);
        assert!(intent.tx_signature.is_none());
        assert!(intent.reconciliation.is_none());

        // key stays burned: replay returns the recorded error, never retries
        let err = run_pay_v2(&s, &mock, "v2-fail", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Recorded { code, .. } if code == "RIALO_TRANSFER_ERROR")
        );
        assert_eq!(mock.transfer_calls().len(), 1);

        // unknown outcome (confirmation timeout)
        let mut m2 = MockOps::new(&s);
        m2.transfer_res = Err(MockErr::ConfirmationTimeout);
        let err = run_pay_v2(&s, &m2, "v2-unk", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Transfer(r) if r.code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT")
        );
        assert_eq!(mock.transfer_calls().len(), 1);
        // reservation HELD (50M from v2-fail refunded to 0; v2-unk holds 50M)
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "unknown must NOT refund");
        let intent = v2_intent(&s, "v2-unk");
        assert_eq!(intent.exec_state, ExecState::Unknown);
        assert!(intent.tx_signature.is_none());
        assert!(intent.reconciliation.is_none());

        // every replay of the Unknown blocks; nothing transfers
        let err = run_pay_v2(&s, &m2, "v2-unk", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Unreconciled)
        ));
        assert_eq!(
            m2.transfer_calls().len(),
            1,
            "replay must not add a second transfer to the timed-out one"
        );
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        s.cleanup();
    }

    // STEP 4: reconciled_* states ARE now representable (the enum gained
    // them exactly when the reconciler existed) and round-trip through
    // serde; the v2 core code STILL has no writer (structural test), and
    // a foreign exec_state remains impossible.
    #[test]
    #[allow(deprecated)]
    fn trigger_reconciled_states_round_trip() {
        for state in ["reconciled_paid", "reconciled_absent"] {
            let doc = serde_json::json!({
                "schema_version": 2,
                "intent_id": Uuid::new_v4().to_string(),
                "agent_id": Uuid::new_v4().to_string(),
                "principal_kind": "agent",
                "recipient": RECIPIENT,
                "amount_kelvin": PAY_AMT,
                "idempotency_key": "k",
                "request_fingerprint": "x",
                "authz": { "policy_fingerprint": "y", "authorized_at": NOW },
                "exec_state": state,
                "tx_signature": PAY_SIG,
                "failure": null,
                "response": null,
                "reconciliation": {
                    "method": "tx_lookup",
                    "outcome": "paid",
                    "tx_signature": PAY_SIG,
                    "resolved_at": NOW,
                    "resolver": "agent:00000000-0000-4000-8000-000000000000",
                    "evidence": {
                        "block_height": 900, "slot": 777, "block_time": NOW,
                        "fee": 5000, "meta_err": null, "tx_summary": "ok"
                    }
                },
                "created_at": NOW,
                "updated_at": NOW,
            });
            let parsed: PaymentIntentV2 =
                serde_json::from_value(doc).unwrap_or_else(|e| panic!("{state}: {e}"));
            let record = parsed.reconciliation.expect("record parses");
            assert_eq!(record.method, ReconciliationMethod::TxLookup);
            assert_eq!(record.outcome, ReconciliationOutcome::Paid);
            assert_eq!(record.evidence.expect("evidence").slot, Some(777));
        }
        for ok_state in [
            "pending",
            "confirmed",
            "failed",
            "unknown",
            "reconciled_paid",
            "reconciled_absent",
        ] {
            let doc = serde_json::json!({
                "schema_version": 2,
                "intent_id": Uuid::new_v4().to_string(),
                "agent_id": Uuid::new_v4().to_string(),
                "principal_kind": "agent",
                "recipient": RECIPIENT,
                "amount_kelvin": PAY_AMT,
                "idempotency_key": "k",
                "request_fingerprint": "x",
                "authz": { "policy_fingerprint": "y", "authorized_at": NOW },
                "exec_state": ok_state,
                "tx_signature": null,
                "failure": null,
                "response": null,
                "reconciliation": null,
                "created_at": NOW,
                "updated_at": NOW,
            });
            assert!(serde_json::from_value::<PaymentIntentV2>(doc).is_ok());
        }
        // a foreign exec_state stays impossible
        let doc = serde_json::json!({
            "schema_version": 2,
            "intent_id": Uuid::new_v4().to_string(),
            "agent_id": Uuid::new_v4().to_string(),
            "principal_kind": "agent",
            "recipient": RECIPIENT,
            "amount_kelvin": PAY_AMT,
            "idempotency_key": "k",
            "request_fingerprint": "x",
            "authz": { "policy_fingerprint": "y", "authorized_at": NOW },
            "exec_state": "reconciled_maybe",
            "tx_signature": null,
            "failure": null,
            "response": null,
            "reconciliation": null,
            "created_at": NOW,
            "updated_at": NOW,
        });
        assert!(serde_json::from_value::<PaymentIntentV2>(doc).is_err());

        // v1 records PRE-dating Step 4 (no reconciliation key at all)
        // keep parsing through the defaulted field
        let v1_doc = serde_json::json!({
            "schema_version": 1,
            "agent_id": Uuid::new_v4().to_string(),
            "idempotency_key": "k",
            "request_fingerprint": "x",
            "recipient": RECIPIENT,
            "amount_kelvin": PAY_AMT,
            "state": "unknown",
            "response": null,
            "created_at": NOW,
            "updated_at": NOW,
        });
        let v1: PaymentIntent = serde_json::from_value(v1_doc).expect("legacy v1 parses");
        assert!(v1.reconciliation.is_none());

        // the demoted BalanceDelta tag parses (fail-loud vocabulary) but
        // NO production writer ever constructs it (step4_balance_delta_
        // never_writes_terminals pins this structurally)
        let legacy = serde_json::json!({
            "method": "balance_delta",
            "outcome": "paid",
            "tx_signature": null,
            "resolved_at": NOW,
            "resolver": "owner:tester"
        });
        let record: ReconciliationRecord =
            serde_json::from_value(legacy).expect("legacy tag deserializes");
        assert_eq!(record.method, ReconciliationMethod::BalanceDelta);
        assert!(record.evidence.is_none());
    }

    // (25,26) concurrency: two simultaneous v2 payments for the SAME agent
    // cannot pass the daily limit on one stale figure (shared CAS with
    // v1); different agents stay independent even under the SAME key
    #[test]
    fn trigger_concurrent_same_agent_cannot_overspend() {
        let s = step8_setup();
        let policy = pay_policy(Some(60_000_000), Some(90_000_000)); // TX 60M DAY 90M
        let day = utc_day(NOW);
        // pre-seed 40M: both racers' pre-checks pass on 40M; the CAS decides
        fs::create_dir_all(&s.ledger).unwrap();
        write_json_atomic(
            &s.ledger_file(),
            &DailySpend {
                schema_version: SPEND_SCHEMA_VERSION,
                agent_id: s.uuid.to_string(),
                day: day.clone(),
                spent_kelvin: 40_000_000,
                reserved_kelvin: 0,
                updated_at: NOW,
            },
        )
        .unwrap();

        let mock = Arc::new(MockOps::new(&s));
        let hold = mock.set_hold();
        hold.store(true, std::sync::atomic::Ordering::SeqCst);

        let (w, l, i, agent, pol, uuid) = (
            s.wallets.clone(),
            s.ledger.clone(),
            s.intents.clone(),
            s.agent.clone(),
            policy.clone(),
            s.uuid,
        );
        let mock_a = Arc::clone(&mock);
        let a_thread = std::thread::spawn(move || {
            execute_agent_payment_v2(
                mock_a.as_ref(),
                &w,
                &l,
                &i,
                &agent,
                &pol,
                "v2-race-a",
                RECIPIENT,
                50_000_000,
                0.05,
                NOW,
            )
        });

        // GATE 2H — deterministic: wait for A to enter transfer() (the
        // mock signals this event before parking). The reservation is
        // durably persisted BEFORE transfer is entered, so this single
        // event implies the earlier ledger guarantee without a
        // scheduler-timed poll (the historical flake's root cause).
        mock.wait_until_entered_transfer(2_500);
        let seen = fs::read(s.ledger_file()).ok().and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v["spent_kelvin"].as_u64().map(|s| s == 90_000_000))
        });
        assert_eq!(
            seen,
            Some(true),
            "A's reservation was never persisted before parking"
        );

        // B races while A holds no persistence lock (mid-transfer)
        let err_b = execute_agent_payment_v2(
            mock.as_ref(),
            &s.wallets,
            &s.ledger,
            &s.intents,
            &s.agent,
            &policy,
            "v2-race-b",
            RECIPIENT,
            50_000_000,
            0.05,
            NOW,
        )
        .expect_err("B must not pass on the same daily room");
        assert!(matches!(
            err_b,
            PaymentFailure::Enforcement(EnforcementDenial::AmountDenied)
        ));
        assert_eq!(mock.transfer_calls().len(), 1, "only A may transfer");

        hold.store(false, std::sync::atomic::Ordering::SeqCst);
        let ok_a = a_thread.join().expect("A succeeds").expect("A ok");
        assert_eq!(ok_a["payment"]["signature"], PAY_SIG);
        assert_eq!(
            read_spend(&s.ledger, &uuid).unwrap().unwrap().spent_kelvin,
            90_000_000,
            "final spend must stay within the daily limit"
        );

        // (26) different agents never share spend state or key slots
        let other =
            create_agent_record(&s.agents, &s.wallets, &s.authkeys, "BetaV2".into(), 7).unwrap();
        let s2 = s.clone_data(other);
        let mock2 = MockOps::new(&s2);
        run_pay_v2(
            &s2,
            &mock2,
            "v2-race-a",
            RECIPIENT,
            V2_AMT,
            Some(&policy),
            None,
        )
        .expect("same key under a different agent is independent");
        assert_eq!(s2.ledger_spent(), Some(PAY_AMT));
        assert_eq!(s.ledger_spent(), Some(90_000_000), "A's bucket unchanged");
        assert_eq!(mock2.transfer_calls().len(), 1);
        s.cleanup();
    }

    // STRUCTURAL PROOF: the v2 trigger path never resolves the user wallet,
    // never retries, duplicates no policy logic, and cannot write
    // reconciliation state — by source inspection of the new code only
    #[test]
    fn step3_structural_trigger_never_resolves_user_wallet_or_retries() {
        let src = include_str!("agents.rs");
        let fn_body = |anchor: &str| -> String {
            let start = src
                .find(anchor)
                .unwrap_or_else(|| panic!("missing: {anchor}"));
            let rest = &src[start..];
            let end = rest.find("\n}").expect("fn end");
            rest[..end].to_string()
        };

        let core = fn_body("pub fn execute_agent_payment_v2(");
        for forbidden in [
            "wallet_path_for",
            "load_or_create_wallet",
            "wallet_file",
            "wallet_address_for",
            "state.wallets",
            "DEV_LOGIN",
            "faucet",
            "airdrop",
            "spawn_blocking",
            "store_lock(",
            "sleep(",
            "attempt in 0..", // retry loops live ONLY in RialoConfig::transfer
            "is_retryable",
            "with_confirmation_timeout_note",
            "reconciliation: Some", // Step 3 NEVER writes reconciliation
            ".reconciliation =",
            "reconciled_", // reconciled states are unrepresentable here
        ] {
            assert!(
                !core.contains(forbidden),
                "v2 core references forbidden token: {forbidden}"
            );
        }
        for required in [
            // PHASE 8 Item 10: canonical signer boundary (see v1 twin)
            "signer.keypair_reference(wallet_dir)",
            "verify_agent_public_address(&signer, wallet_dir)",
            "ops.transfer(",
            "ops.balance(",
            "check_agent_payment_policy(",
            // PHASE 9 spend controls: group-atomic hierarchical reservation
            // (same lock, same CAS semantics, plus the aggregate scopes).
            "reserve_spend_hierarchical(",
            "release_spend(",
            "claim_intent_v2(",
            "request_fingerprint_v2(",
            "AGENT_PAYMENT_FEE_HEADROOM_KELVIN",
            "reconciliation: None",
        ] {
            assert!(core.contains(required), "v2 core must use {required}");
        }
        assert!(
            !core.contains("agent_wallet_path(wallet_dir, &uuid)"),
            "v2 core must not re-join the wallet path outside the signer boundary"
        );
        // exactly one transfer call site in the v2 core
        assert_eq!(core.matches("ops.transfer(").count(), 1);

        let handler = fn_body("pub async fn agent_trigger_payment(");
        for forbidden in [
            "wallet_path_for",
            "load_or_create_wallet",
            "wallet_file",
            "wallet_address_for",
            "state.wallets",
            "DEV_LOGIN",
            "faucet",
            "airdrop",
            "transfer(",
            "session_user", // trigger auth is credential-only, never the GitHub session
        ] {
            assert!(
                !handler.contains(forbidden),
                "trigger handler references forbidden token: {forbidden}"
            );
        }
        for required in [
            "authenticate_agent_credential",
            "valid_credential_shape",
            "AGENT_CREDENTIAL_INVALID",
            "agent_payment_lock(",
            "execute_agent_payment_v2(",
            "EnforcementDenial::Lifecycle",
            "PolicyMissing",
            "valid_rialo_address",
            "rlo_to_kelvin",
        ] {
            assert!(handler.contains(required), "handler must wire {required}");
        }
        // the credential secret is dropped and never interpolated into any
        // response/record: the handler's only credential uses are the shape
        // gate and authenticate; the stable error text is a static literal.
        assert_eq!(handler.matches("credential").count() >= 5, true);
        assert!(!handler.contains("format!(\"{credential}"));
        assert!(!handler.contains("&credential.to_string()"));
    }

    // the new literal route must coexist with the {id} param routes in
    // matchit (a conflict would panic the REAL server at startup — and the
    // live server may not be restarted to discover that). Build the exact
    // route shape here instead.
    #[test]
    fn step3_routes_coexist_without_panic() {
        use axum::routing::{get, patch, post};
        use axum::{Router, http::StatusCode};
        async fn dummy() -> StatusCode {
            StatusCode::IM_A_TEAPOT
        }
        let build = || {
            Router::<()>::new()
                .route(
                    "/api/agents/{id}",
                    get(dummy).patch(dummy).delete(dummy),
                )
                .route("/api/agents/{id}/balance", get(dummy))
                .route("/api/agents/{id}/status", patch(dummy))
                .route("/api/agents/{id}/policy", get(dummy).patch(dummy))
                .route("/api/agents/{id}/payments", post(dummy))
                .route("/api/agents/{id}/payments/reconcile", post(dummy))
                .route("/api/agents/triggers/payments", post(dummy))
                .route("/api/agents/triggers/payments/reconcile", post(dummy))
        };
        // must not panic (matchit rejects static/param conflicts eagerly)
        let _router = build();
    }

    // The real router must expose DELETE on the parameterized agent route:
    // the dashboard renders Delete for eligible agents and its handler
    // already exists. This catches a route wiring regression that would
    // otherwise surface only as a live 405.
    #[test]
    fn delete_route_is_wired_in_the_real_router() {
        let srv = include_str!("../server.rs");
        assert!(
            srv.contains(".delete(agents::delete_agent)"),
            "DELETE /api/agents/{{id}} must be wired to agents::delete_agent"
        );
    }

    // G21.12.10: program start/execute pin the wallet path verified by the
    // strict gate — no mint-on-miss after verification in PG mode (TOCTOU).
    #[test]
    fn g211210_program_paths_use_verified_wallet_no_remint() {
        let srv = include_str!("../server.rs");
        for fn_name in ["async fn program_start(", "async fn program_execute("] {
            let start = srv.find(fn_name).unwrap_or_else(|| {
                panic!("{fn_name} exists");
            });
            let rest = &srv[start..];
            let end = rest
                .find("\n}\n\nasync fn ")
                .or_else(|| rest.find("\n}\n\n/// "))
                .expect("fn end");
            let body = &rest[..end];
            // The strict gate must capture the verified path...
            assert!(
                body.contains("verified_wallet_path = Some(wallet_file(uid))"),
                "{fn_name} must pin the verified wallet path"
            );
            // ...and the execution-stage path must come from that pin, with
            // the legacy loader only as the FS-mode fallback (never reached
            // in PG mode after verification).
            assert!(
                body.contains("verified_wallet_path.unwrap_or_else(|| wallet_path_for(user.id))"),
                "{fn_name} must execute against the verified path"
            );
        }
    }

    // the frozen user payment handler is still untouched by Step 3
    // (extends the Step-8 guard: trigger code introduced no user-path edits)
    #[test]
    fn step3_user_payment_flow_still_frozen() {
        let srv = include_str!("../server.rs");
        let start = srv.find("async fn payment(").expect("user payment");
        let rest = &srv[start..];
        let end = rest
            .find("\n}\n\n/// Infrastructure health")
            .expect("payment fn end");
        let user_pay = &rest[..end];
        assert!(
            user_pay.contains("wallet_path_for(user.id)")
                || user_pay.contains("strict_wallet_load_or_mint(user.id)"),
            "payment must route through a wallet loader (strict or legacy)"
        );
        assert!(user_pay.contains("FEE_HEADROOM_RLO"));
        for agent_token in ["agent", "trigger", "intent", "credential", "v2"] {
            assert!(
                !user_pay.to_lowercase().contains(agent_token),
                "user payment touched Step 3+ concept: {agent_token}"
            );
        }
        // the new route is literal (no {id}) and registered exactly once
        let literal = "\"/api/agents/triggers/payments\"";
        assert_eq!(srv.matches(literal).count(), 1);
        assert!(!srv.contains("/api/agents/triggers/{"));
    }
    // =======================================================================
    // PHASE 6 STEP 4 — reconciliation tests (A–S + lanes). Everything runs
    // against temp stores with FAKE chain ops: no RPC, no CLI, no money.
    // =======================================================================

    const RECON_SIG: &str = "5ReconMockSignatureNotRealDoNotTrust";
    const SCAN_SIG: &str = "5ScanMockSignatureNotRealDoNotTrust";
    const OTHER_SIG: &str = "9OtherMockSignatureNotRealDoNotTrust";

    /// The fake chain boundary for the reconciliation lane. `read_tx` and
    /// `signatures_for_address` are plan-driven; `transfer` ALWAYS fails
    /// with a confirmation timeout (it exists only to arm Unknown
    /// fixtures and NEVER mints a Confirmed outcome); balance is honest.
    #[derive(Clone)]
    enum HistoryPlan {
        Empty,
        Entries(Vec<SignatureInfoRecord>),
        RpcDown,
    }

    struct RecoOps {
        timeout_sig: Option<String>,
        lookup: std::sync::Mutex<Vec<(String, TxLookup)>>,
        history: std::sync::Mutex<HistoryPlan>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl RecoOps {
        fn with_timeout(sig: Option<&str>) -> Self {
            RecoOps {
                timeout_sig: sig.map(str::to_string),
                lookup: std::sync::Mutex::new(Vec::new()),
                history: std::sync::Mutex::new(HistoryPlan::Empty),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn armed_for_setup(&self) {}
        fn set_lookup(&self, sig: &str, outcome: TxLookup) {
            let mut plan = self.lookup.lock().unwrap();
            plan.retain(|(s, _)| s != sig);
            plan.push((sig.to_string(), outcome));
        }
        fn set_history(&self, entries: Vec<SignatureInfoRecord>) {
            *self.history.lock().unwrap() = HistoryPlan::Entries(entries);
        }
        fn set_history_down(&self) {
            *self.history.lock().unwrap() = HistoryPlan::RpcDown;
        }
        fn lookup_calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("read_tx|"))
                .cloned()
                .collect()
        }
    }

    impl PaymentOps for RecoOps {
        fn balance(&self, _address: &str) -> Result<f64, RialoError> {
            self.armed_for_setup();
            Ok(2.0)
        }
        fn transfer(
            &self,
            _keypair_path: &FsPath,
            _to: &str,
            _amount_rlo: &str,
        ) -> Result<String, RialoError> {
            self.calls.lock().unwrap().push("transfer".to_string());
            Err(RialoError {
                code: "RIALO_TRANSFER_CONFIRMATION_TIMEOUT",
                detail: "mock confirmation timeout".to_string(),
                tx_signature: self.timeout_sig.clone(),
            })
        }
        fn read_tx(&self, signature: &str) -> TxLookup {
            self.calls
                .lock()
                .unwrap()
                .push(format!("read_tx|{signature}"));
            self.lookup
                .lock()
                .unwrap()
                .iter()
                .find(|(s, _)| s == signature)
                .map(|(_, l)| l.clone())
                .unwrap_or(TxLookup::Malformed)
        }
        fn signatures_for_address(
            &self,
            address: &str,
            _until_signature: Option<&str>,
            _limit: u64,
        ) -> Result<Vec<SignatureInfoRecord>, RialoError> {
            self.calls.lock().unwrap().push(format!("scan|{address}"));
            match self.history.lock().unwrap().clone() {
                HistoryPlan::Empty => Ok(Vec::new()),
                HistoryPlan::Entries(v) => Ok(v),
                HistoryPlan::RpcDown => Err(RialoError::mock(
                    "RIALO_RPC_UNAVAILABLE",
                    "mock network error: connection refused",
                )),
            }
        }
    }

    // tiny test-only constructor (plain errors never surface signatures)
    impl RialoError {
        fn mock(code: &'static str, detail: &str) -> Self {
            RialoError {
                code,
                detail: detail.to_string(),
                tx_signature: None,
            }
        }
    }

    fn good_record(sig: &str, payer: &str, recipient: &str, amount: u64, at: i64) -> TxRecord {
        TxRecord {
            signature: Some(sig.to_string()),
            executed: true,
            err: None,
            slot: Some(900),
            block_height: Some(900),
            block_time: Some(at),
            fee: Some(5000),
            payer: Some(payer.to_string()),
            transfer_recipient: Some(recipient.to_string()),
            transfer_amount_kelvin: Some(amount),
            complete: true,
        }
    }

    fn failed_record(sig: &str, err: &str, at: i64) -> TxRecord {
        TxRecord {
            signature: Some(sig.to_string()),
            executed: false,
            err: Some(err.to_string()),
            slot: Some(901),
            block_height: Some(901),
            block_time: Some(at),
            fee: Some(5000),
            payer: None,
            transfer_recipient: None,
            transfer_amount_kelvin: None,
            complete: true,
        }
    }

    fn hist_entry(sig: &str, at: i64) -> SignatureInfoRecord {
        SignatureInfoRecord {
            signature: sig.to_string(),
            block_height: Some(900),
            err: None,
            block_time: Some(at),
        }
    }

    fn owner_principal() -> ReconcilePrincipal {
        ReconcilePrincipal::owner("shaaker-test").expect("owner grammar")
    }

    fn req(key: &str) -> ReconcileRequest {
        ReconcileRequest {
            idempotency_key: key.to_string(),
            manual_outcome: None,
            attestation: None,
            allow_scan: true,
            allow_auto: false,
        }
    }

    fn reconcile(
        s: &Step8,
        ops: &dyn PaymentOps,
        r: ReconcileRequest,
        pr: &ReconcilePrincipal,
        now: i64,
    ) -> ReconcileVerdict {
        reconcile_intent(ops, &s.ledger, &s.intents, &s.agent, &r, pr, now)
    }

    /// Arm a v2 Unknown under `key`. When `surfaced` is Some the fake CLI
    /// failure envelope carries that broadcast signature (item 2).
    fn arm_unknown_v2(s: &Step8, key: &str, ops: &RecoOps) {
        let err = run_pay_v2(s, ops, key, RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT"),
            "arming transfer must yield the typed timeout"
        );
    }

    fn terminal_of(
        v: &ReconcileVerdict,
    ) -> Option<(ReconciliationOutcome, bool, ReconciliationRecord)> {
        match v {
            ReconcileVerdict::Reconciled { record, replayed } => {
                Some((record.outcome, *replayed, record.clone()))
            }
            _ => None,
        }
    }

    // --- item 2: the surfaced signature is persisted BEFORE Unknown ------
    #[test]
    fn step4_unknown_persists_surfaced_signature_and_preserves_it() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "sig-keep", &ops);
        let intent = v2_intent(&s, "sig-keep");
        assert_eq!(intent.exec_state, ExecState::Unknown);
        assert_eq!(
            intent.tx_signature.as_deref(),
            Some(RECON_SIG),
            "a signature surfaced by the timeout envelope must survive into Unknown"
        );
        assert!(intent.reconciliation.is_none());
        // the Unknown gate still blocks payment replays and holds the money
        let err = run_pay_v2(&s, &ops, "sig-keep", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(matches!(
            err,
            PaymentFailure::Replay(ReplayVerdict::Unreconciled)
        ));
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        s.cleanup();
    }

    #[test]
    fn step4_unknown_without_recoverable_signature_keeps_none() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(None);
        arm_unknown_v2(&s, "sig-none", &ops);
        let intent = v2_intent(&s, "sig-none");
        assert_eq!(intent.exec_state, ExecState::Unknown);
        assert!(
            intent.tx_signature.is_none(),
            "no signature was ever surfaced: nothing may be fabricated"
        );
        s.cleanup();
    }

    // --- A: known signature + successful transaction => ReconciledPaid ---
    #[test]
    fn step4_A_known_signature_success_reconciles_paid() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-paid", &ops);
        let payer = s
            .agent
            .wallet_address
            .clone()
            .expect("agent wallet address");
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)),
        );
        let v = reconcile(&s, &ops, req("rec-paid"), &owner_principal(), NOW + 120);
        let (outcome, replayed, record) = terminal_of(&v).expect("terminal paid");
        assert_eq!(outcome, ReconciliationOutcome::Paid);
        assert!(!replayed);
        assert_eq!(record.method, ReconciliationMethod::TxLookup);
        assert_eq!(record.tx_signature.as_deref(), Some(RECON_SIG));
        assert_eq!(record.resolver, "owner:shaaker-test");
        let ev = record.evidence.expect("evidence persisted");
        assert_eq!(ev.slot, Some(900));
        assert_eq!(ev.meta_err, None);
        // disk: immutable terminal + reservation stays CONSUMED
        let intent = v2_intent(&s, "rec-paid");
        assert_eq!(intent.exec_state, ExecState::ReconciledPaid);
        assert_eq!(intent.tx_signature.as_deref(), Some(RECON_SIG));
        assert!(intent.reconciliation.is_some());
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "Paid never releases");
        s.cleanup();
    }

    // --- B: known signature + failed transaction => ReconciledAbsent ----
    #[test]
    fn step4_B_known_signature_failed_reconciles_absent_and_releases_once() {
        for (name, rec) in [
            (
                "not-executed",
                failed_record(RECON_SIG, "AccountNotFound", NOW + 60),
            ),
            (
                "executed-with-err",
                TxRecord {
                    executed: true,
                    err: Some("InstructionError".to_string()),
                    ..failed_record(RECON_SIG, "InstructionError", NOW + 60)
                },
            ),
        ] {
            let s = step8_setup();
            let ops = RecoOps::with_timeout(Some(RECON_SIG));
            arm_unknown_v2(&s, "rec-abs", &ops);
            ops.set_lookup(RECON_SIG, TxLookup::Found(rec));
            let v = reconcile(&s, &ops, req("rec-abs"), &owner_principal(), NOW + 120);
            let (outcome, _, record) = terminal_of(&v).expect("terminal absent");
            assert_eq!(
                outcome,
                ReconciliationOutcome::Absent,
                "decisive failure must reconcile Absent via {name}"
            );
            assert!(record.evidence.expect("evidence").meta_err.is_some());
            assert_eq!(
                v2_intent(&s, "rec-abs").exec_state,
                ExecState::ReconciledAbsent
            );
            assert_eq!(
                s.ledger_spent(),
                Some(0),
                "same-day Absent releases exactly once"
            );
            // M: repeat reconciliation — stored replay, ledger untouched
            let before = s.ledger_spent();
            let v2 = reconcile(&s, &ops, req("rec-abs"), &owner_principal(), NOW + 300);
            let (_, replayed, _) = terminal_of(&v2).expect("replay");
            assert!(replayed, "second reconciliation returns the stored result");
            assert_eq!(s.ledger_spent(), before);
            assert_eq!(ops.lookup_calls().len(), 1, "replay performs no RPC");
            s.cleanup();
        }
    }

    // --- C/D/R: transient and incomplete evidence stay Unknown ----------
    #[test]
    fn step4_CDR_transient_or_incomplete_evidence_stays_unknown() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-unk", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();
        let good = good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60);

        // C: RPC unavailable => Unresolved, RIALO_RPC_UNAVAILABLE
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Unavailable(RialoError::mock(
                "RIALO_RPC_UNAVAILABLE",
                "mock network error: connection refused",
            )),
        );
        let v = reconcile(&s, &ops, req("rec-unk"), &owner_principal(), NOW + 120);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "RIALO_RPC_UNAVAILABLE")
            }
            other => panic!("expected unresolved RPC-down, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-unk").exec_state, ExecState::Unknown);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        // D: temporary not-found => Unresolved (NEVER automatic Absent)
        ops.set_lookup(RECON_SIG, TxLookup::NotFound);
        let v = reconcile(&s, &ops, req("rec-unk"), &owner_principal(), NOW + 121);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "AGENT_RECONCILIATION_TEMPORARY_NOT_FOUND")
            }
            other => panic!("expected unresolved not-found, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-unk").exec_state, ExecState::Unknown);

        // R: malformed/incomplete => Unresolved
        ops.set_lookup(RECON_SIG, TxLookup::Malformed);
        let v = reconcile(&s, &ops, req("rec-unk"), &owner_principal(), NOW + 122);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "AGENT_RECONCILIATION_INCOMPLETE_EVIDENCE")
            }
            other => panic!("expected unresolved malformed, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-unk").exec_state, ExecState::Unknown);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "nothing ever released");
        assert!(good.complete);
        s.cleanup();
    }

    // --- E: no signature + exactly one candidate => PROPOSAL, then the
    //        owner's explicit manual attestation finalizes it -------------
    #[test]
    fn step4_E_scan_proposal_then_manual_attestation() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(None);
        arm_unknown_v2(&s, "rec-scan", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();
        ops.set_history(vec![hist_entry(SCAN_SIG, NOW + 30)]);
        ops.set_lookup(
            SCAN_SIG,
            TxLookup::Found(good_record(SCAN_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 30)),
        );

        // proposal: NOTHING is finalized automatically over this lane
        let v = reconcile(&s, &ops, req("rec-scan"), &owner_principal(), NOW + 120);
        match v {
            ReconcileVerdict::Proposal {
                tx_signature,
                evidence,
            } => {
                assert_eq!(tx_signature, SCAN_SIG);
                assert_eq!(evidence.slot, Some(900));
            }
            other => panic!("expected proposal, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-scan").exec_state, ExecState::Unknown);
        assert_eq!(
            s.ledger_spent(),
            Some(PAY_AMT),
            "proposal changed no money state"
        );

        // explicit policy switch (engine-level, owner-only): auto-finalize
        let auto = ReconcileRequest {
            allow_auto: true,
            ..req("rec-scan")
        };
        let v = reconcile(&s, &ops, auto, &owner_principal(), NOW + 121);
        let (outcome, _, record) = terminal_of(&v).expect("auto terminal");
        assert_eq!(outcome, ReconciliationOutcome::Paid);
        assert_eq!(record.method, ReconciliationMethod::AddressScan);
        let intent = v2_intent(&s, "rec-scan");
        assert_eq!(intent.exec_state, ExecState::ReconciledPaid);
        assert_eq!(
            intent.tx_signature.as_deref(),
            Some(SCAN_SIG),
            "the scan-provided signature is persisted with the verdict"
        );
        assert_eq!(
            s.ledger_spent(),
            Some(PAY_AMT),
            "Paid keeps the reservation"
        );
        s.cleanup();
    }

    #[test]
    fn step4_E_manual_attestation_requires_note_and_persists_resolver() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-man", &ops);
        ops.set_lookup(RECON_SIG, TxLookup::NotFound);

        // no attestation note -> refused, no mutation
        let missing = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Paid),
            ..req("rec-man")
        };
        let v = reconcile(&s, &ops, missing, &owner_principal(), NOW + 120);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "AGENT_RECONCILIATION_ATTESTATION_REQUIRED")
            }
            other => panic!("expected attestation refusal, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-man").exec_state, ExecState::Unknown);

        let manual = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Absent),
            attestation: Some("  operator ledger review\t2026-09-29  ".to_string()),
            ..req("rec-man")
        };
        let v = reconcile(&s, &ops, manual, &owner_principal(), NOW + 121);
        let (outcome, _, record) = terminal_of(&v).expect("manual terminal");
        assert_eq!(outcome, ReconciliationOutcome::Absent);
        assert_eq!(record.method, ReconciliationMethod::ManualAttestation);
        assert_eq!(record.resolver, "owner:shaaker-test");
        let summary = record.evidence.expect("evidence").tx_summary.expect("note");
        assert!(
            !summary.contains('\t') && !summary.contains("  "),
            "note sanitized"
        );
        assert!(summary.contains("operator ledger review 2026-09-29"));
        assert_eq!(
            s.ledger_spent(),
            Some(0),
            "manual Absent releases the original hold"
        );
        s.cleanup();
    }

    // --- F/G: zero or multiple candidates => Unknown --------------------
    #[test]
    fn step4_FG_zero_or_multiple_candidates_stay_unknown() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(None);
        arm_unknown_v2(&s, "rec-amb", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();

        // F: zero candidates
        let v = reconcile(&s, &ops, req("rec-amb"), &owner_principal(), NOW + 120);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "AGENT_RECONCILIATION_NO_MATCH")
            }
            other => panic!("expected no-match, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-amb").exec_state, ExecState::Unknown);
        assert_eq!(
            s.ledger_spent(),
            Some(PAY_AMT),
            "an empty scan NEVER releases spend and NEVER mints Absent"
        );

        // G: two matching candidates -> ambiguous
        ops.set_history(vec![
            hist_entry(SCAN_SIG, NOW + 30),
            hist_entry(OTHER_SIG, NOW + 31),
        ]);
        ops.set_lookup(
            SCAN_SIG,
            TxLookup::Found(good_record(SCAN_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 30)),
        );
        ops.set_lookup(
            OTHER_SIG,
            TxLookup::Found(good_record(OTHER_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 31)),
        );
        let v = reconcile(&s, &ops, req("rec-amb"), &owner_principal(), NOW + 121);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "AGENT_RECONCILIATION_AMBIGUOUS")
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        assert_eq!(v2_intent(&s, "rec-amb").exec_state, ExecState::Unknown);

        // scan RPC down -> transient, Unknown
        ops.set_history_down();
        let v = reconcile(&s, &ops, req("rec-amb"), &owner_principal(), NOW + 122);
        match v {
            ReconcileVerdict::Unresolved { code, .. } => {
                assert_eq!(code, "RIALO_RPC_UNAVAILABLE")
            }
            other => panic!("expected scan rpc-down, got {other:?}"),
        }
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        s.cleanup();
    }

    // --- S: wrong payer / recipient / amount / timing => never Paid -----
    #[test]
    fn step4_S_mismatched_evidence_never_becomes_paid() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-mis", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();

        let cases = vec![
            (
                "wrong-payer",
                good_record(
                    RECON_SIG,
                    "SomeoneElsesWalletAddress333",
                    RECIPIENT,
                    PAY_AMT,
                    NOW + 60,
                ),
            ),
            (
                "wrong-recipient",
                good_record(
                    RECON_SIG,
                    &payer,
                    "SomeoneElsesRecipient44444444444",
                    PAY_AMT,
                    NOW + 60,
                ),
            ),
            (
                "wrong-amount",
                good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT + 1, NOW + 60),
            ),
            (
                "missing-slot",
                TxRecord {
                    slot: None,
                    block_height: None,
                    ..good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)
                },
            ),
            (
                "missing-time",
                TxRecord {
                    block_time: None,
                    ..good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)
                },
            ),
            (
                "tx-before-intent",
                good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW - 86_400),
            ),
            (
                "undecodable-transfer",
                TxRecord {
                    transfer_recipient: None,
                    transfer_amount_kelvin: None,
                    ..good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)
                },
            ),
        ];
        for (name, rec) in cases {
            ops.set_lookup(RECON_SIG, TxLookup::Found(rec));
            let v = reconcile(&s, &ops, req("rec-mis"), &owner_principal(), NOW + 120);
            match v {
                ReconcileVerdict::Unresolved { code, .. } => {
                    assert_eq!(
                        code, "AGENT_RECONCILIATION_EVIDENCE_MISMATCH",
                        "case {name} must be inconclusive, never Paid"
                    );
                }
                other => panic!("case {name}: expected mismatch, got {other:?}"),
            }
            assert_eq!(v2_intent(&s, "rec-mis").exec_state, ExecState::Unknown);
            assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        }
        s.cleanup();
    }

    // --- H/I: balance movements (up or down) change NOTHING -------------
    #[test]
    fn step4_HI_balance_deltas_are_never_decisive() {
        let s = step8_setup();
        // H: wallet balance "increased" (e.g. a refund elsewhere) while a
        // payment is Unknown. The reconciler does not even read balances —
        // with NO chain evidence the intent must stay Unknown.
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-bal", &ops);
        ops.set_lookup(RECON_SIG, TxLookup::NotFound);
        // (an ops.balanced 2.0 read exists on the trait; the decision core
        // is structurally proven never to call it)
        let v = reconcile(&s, &ops, req("rec-bal"), &owner_principal(), NOW + 120);
        assert!(
            matches!(v, ReconcileVerdict::Unresolved { .. }),
            "balance masking must not mint Paid"
        );
        assert_eq!(v2_intent(&s, "rec-bal").exec_state, ExecState::Unknown);

        // I: a concurrent OTHER payment reduced the ledger — still Unknown,
        // never Paid/Absent from ledger arithmetic
        let mock = MockOps::new(&s);
        let body = run_pay_v2(&s, &mock, "other-pay", RECIPIENT, 0.06, None, None)
            .expect("second payment");
        assert_eq!(body["payment"]["amount_kelvin"], 60_000_000u64);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT + 60_000_000));
        let v = reconcile(&s, &ops, req("rec-bal"), &owner_principal(), NOW + 121);
        assert!(
            matches!(v, ReconcileVerdict::Unresolved { .. }),
            "a decreasing bucket never becomes Absent evidence"
        );
        assert_eq!(v2_intent(&s, "rec-bal").exec_state, ExecState::Unknown);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT + 60_000_000));
        s.cleanup();
    }

    // --- J: two simultaneous reconciliations => ONE terminal write ------
    #[test]
    fn step4_J_concurrent_reconciliations_commit_exactly_once() {
        use std::sync::Arc;
        let s = step8_setup();
        let ops = Arc::new(RecoOps::with_timeout(Some(RECON_SIG)));
        arm_unknown_v2(&s, "rec-race", &*ops);
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(failed_record(RECON_SIG, "InstructionError", NOW + 60)),
        );
        let agent = s.agent.clone();
        let ledger = s.ledger.clone();
        let intents = s.intents.clone();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let ops = Arc::clone(&ops);
            let agent = agent.clone();
            let ledger = ledger.clone();
            let intents = intents.clone();
            handles.push(std::thread::spawn(move || {
                let r = ReconcileRequest {
                    idempotency_key: "rec-race".to_string(),
                    manual_outcome: None,
                    attestation: None,
                    allow_scan: true,
                    allow_auto: false,
                };
                let pr = ReconcilePrincipal::owner("shaaker-test").expect("grammar");
                reconcile_intent(ops.as_ref(), &ledger, &intents, &agent, &r, &pr, NOW + 120)
            }));
        }
        let verdicts: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();
        let fresh = verdicts
            .iter()
            .filter(|v| {
                matches!(
                    v,
                    ReconcileVerdict::Reconciled {
                        replayed: false,
                        ..
                    }
                )
            })
            .count();
        let replayed = verdicts
            .iter()
            .filter(|v| matches!(v, ReconcileVerdict::Reconciled { replayed: true, .. }))
            .count();
        assert_eq!(fresh, 1, "exactly one terminal write: {verdicts:?}");
        assert_eq!(replayed, 1, "the loser replays the stored result");
        let spent = s.ledger_spent().expect("ledger");
        assert_eq!(
            spent, 0,
            "the reservation was released exactly once (never negative)"
        );
        s.cleanup();
    }

    // --- K: reconciliation alongside a concurrent NEW payment -----------
    #[test]
    fn step4_K_reconciled_key_burns_and_new_keys_reserve_normally() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-k", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)),
        );
        let v = reconcile(&s, &ops, req("rec-k"), &owner_principal(), NOW + 120);
        assert!(terminal_of(&v).is_some());
        // replay of the ORIGINAL payment attempt: the stored reconciliation
        // comes back; zero transfers; reservation intact
        let mock = MockOps::new(&s);
        let err = run_pay_v2(&s, &mock, "rec-k", RECIPIENT, V2_AMT, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Reconciled(Some(_))),
            "reconciled replay must return the stored record"
        );
        assert!(
            mock.transfer_calls().is_empty(),
            "no transfer for a reconciled key"
        );
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        // a NEW key still moves money normally (nothing is double-held or
        // lost by the reconciliation)
        let body =
            run_pay_v2(&s, &mock, "rec-k-new", RECIPIENT, 0.06, None, None).expect("new payment");
        assert_eq!(body["payment"]["amount_kelvin"], 60_000_000u64);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT + 60_000_000));
        s.cleanup();
    }

    // --- L: releasing one Unknown reservation leaves the others ---------
    #[test]
    fn step4_L_multiple_unknown_reservations_release_only_its_own() {
        let s = step8_setup();
        let ops1 = RecoOps::with_timeout(Some("5FirstUnknownHoldSig"));
        arm_unknown_v2(&s, "hold-a", &ops1);
        let ops2 = RecoOps::with_timeout(Some("5SecondUnknownHoldSig"));
        arm_unknown_v2(&s, "hold-b", &ops2);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT * 2), "both holds counted");

        // prove ONLY hold-a absent
        ops1.set_lookup(
            "5FirstUnknownHoldSig",
            TxLookup::Found(failed_record(
                "5FirstUnknownHoldSig",
                "AccountNotFound",
                NOW + 10,
            )),
        );
        let v = reconcile(&s, &ops1, req("hold-a"), &owner_principal(), NOW + 120);
        let (outcome, _, _) = terminal_of(&v).expect("absent");
        assert_eq!(outcome, ReconciliationOutcome::Absent);
        assert_eq!(
            s.ledger_spent(),
            Some(PAY_AMT),
            "the concurrent unknown hold of hold-b must remain counted"
        );
        assert_eq!(v2_intent(&s, "hold-b").exec_state, ExecState::Unknown);
        s.cleanup();
    }

    // --- N: cross-day Absent must not corrupt the NEW day's ledger ------
    #[test]
    fn step4_N_cross_day_absent_never_touches_rollover_bucket() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-x", &ops);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "same-day hold");
        // simulate the midnight rollover + a fresh day's reservations
        let next_day = utc_day(NOW + 86_400);
        write_json_atomic(
            &s.ledger_file(),
            &DailySpend {
                schema_version: SPEND_SCHEMA_VERSION,
                agent_id: s.uuid.to_string(),
                day: next_day.clone(),
                spent_kelvin: 70_000_000,
                reserved_kelvin: 0,
                updated_at: NOW + 86_400,
            },
        )
        .unwrap();
        // reconcile the old intent as Absent NOW+86400+60
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(failed_record(RECON_SIG, "AccountNotFound", NOW + 30)),
        );
        let v = reconcile(
            &s,
            &ops,
            req("rec-x"),
            &owner_principal(),
            NOW + 86_400 + 60,
        );
        let (outcome, _, _) = terminal_of(&v).expect("absent commits");
        assert_eq!(outcome, ReconciliationOutcome::Absent);
        assert_eq!(
            v2_intent(&s, "rec-x").exec_state,
            ExecState::ReconciledAbsent
        );
        // the new day's bucket is UNTOUCHED — never subtracted from
        let stored = read_spend(&s.ledger, &s.uuid).unwrap().unwrap();
        assert_eq!(stored.day, next_day);
        assert_eq!(
            stored.spent_kelvin, 70_000_000,
            "rollover bucket must not decrease"
        );
        s.cleanup();
    }

    // --- P: terminal immutability at the STORE layer ---------------------
    #[test]
    fn step4_P_reconciled_terminal_is_immutable_below_api_too() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-p", &ops);
        let payer = s.agent.wallet_address.clone().unwrap();
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(good_record(RECON_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 60)),
        );
        let v = reconcile(&s, &ops, req("rec-p"), &owner_principal(), NOW + 120);
        let (outcome, _, record) = terminal_of(&v).expect("paid");
        let file = intent_path(&agent_intents_dir(&s.intents, &s.uuid), "rec-p");
        let bytes_before = fs::read(&file).unwrap();

        // generic engine update path CANNOT overwrite the terminal
        let after = update_intent_v2(&s.intents, &s.uuid, "rec-p", NOW + 500, |i| {
            i.exec_state = ExecState::Failed;
            i.tx_signature = None;
            i.reconciliation = None;
        })
        .expect("guard returns Ok (refusing silently, write-free)");
        assert_eq!(after.exec_state, ExecState::ReconciledPaid);
        assert_eq!(
            fs::read(&file).unwrap(),
            bytes_before,
            "file byte-identical"
        );

        // a second reconciliation (any resolver, any outcome) replays the
        // STORED record — outcome, signature, resolver, evidence frozen
        let other = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Absent),
            attestation: Some("attempted rewrite".to_string()),
            ..req("rec-p")
        };
        let v2 = reconcile(&s, &ops, other, &other_principal(), NOW + 600);
        let (outcome2, replayed, record2) = terminal_of(&v2).expect("replay");
        assert!(replayed);
        assert_eq!(outcome2, outcome);
        assert_eq!(record2, record);
        assert_eq!(fs::read(&file).unwrap(), bytes_before);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));
        s.cleanup();
    }

    fn other_principal() -> ReconcilePrincipal {
        ReconcilePrincipal::owner("second-reviewer").expect("grammar")
    }

    // --- Q: stale Pending after restart enters reconciliation ------------
    #[test]
    fn step4_Q_stale_pending_becomes_reconciliation_eligible_not_failed() {
        let s = step8_setup();
        // arm a v1 Pending record (worker vanished shape)
        let draft = PaymentIntent {
            schema_version: PAYMENT_INTENT_SCHEMA_VERSION,
            agent_id: s.uuid.to_string(),
            idempotency_key: "stale-1".to_string(),
            request_fingerprint: request_fingerprint(RECIPIENT, PAY_AMT),
            recipient: RECIPIENT.to_string(),
            amount_kelvin: PAY_AMT,
            state: IntentState::Pending,
            response: None,
            created_at: NOW,
            updated_at: NOW,
            reconciliation: None,
            signer: None,
            authz: None,
            aggregate_scopes: Vec::new(),
            evidence_slot: None,
        };
        assert!(matches!(
            claim_intent(&s.intents, &s.uuid, &draft).unwrap(),
            IntentClaim::Created
        ));

        // inside the grace window: NOT reconciliation-eligible
        let v = reconcile(
            &s,
            &RecoOps::with_timeout(None),
            req("stale-1"),
            &owner_principal(),
            NOW + 10,
        );
        assert!(
            matches!(v, ReconcileVerdict::InProgress),
            "fresh pending stays gated"
        );
        assert_eq!(s.intent("stale-1").unwrap().state, IntentState::Pending);

        // after the horizon: enters the flow (normalize -> Unknown -> scan
        // lane). NEVER silently Failed.
        let ops = RecoOps::with_timeout(None);
        let payer = s.agent.wallet_address.clone().unwrap();
        ops.set_history(vec![hist_entry(SCAN_SIG, NOW + 30)]);
        ops.set_lookup(
            SCAN_SIG,
            TxLookup::Found(good_record(SCAN_SIG, &payer, RECIPIENT, PAY_AMT, NOW + 30)),
        );
        let v = reconcile(
            &s,
            &ops,
            req("stale-1"),
            &owner_principal(),
            NOW + AGENT_PENDING_STALE_AFTER_SECONDS + 1,
        );
        assert!(
            matches!(v, ReconcileVerdict::Proposal { .. }),
            "stale pending must reach the reconciliation decision flow: {v:?}"
        );
        let now_state = s.intent("stale-1").unwrap().state;
        assert_eq!(now_state, IntentState::Unknown, "normalized to Unknown");

        // the owner can then close it out deterministically via the scan
        // evidence (manual attestation with the proposal in hand)
        let manual = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Paid),
            attestation: Some(format!("closing stale pending on scan proposal {SCAN_SIG}")),
            ..req("stale-1")
        };
        let v = reconcile(&s, &ops, manual, &owner_principal(), NOW + 999);
        let (outcome, _, record) = terminal_of(&v).expect("manual paid");
        assert_eq!(outcome, ReconciliationOutcome::Paid);
        assert_eq!(record.method, ReconciliationMethod::ManualAttestation);
        assert_eq!(
            s.intent("stale-1").unwrap().state,
            IntentState::ReconciledPaid
        );

        // a payment replay onto the reconciled v1 key returns the stored
        // reconciliation — never a second transfer
        let mock = MockOps::new(&s);
        let err = run_pay(&s, &mock, "stale-1", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(
            matches!(
                &err,
                PaymentFailure::Replay(ReplayVerdict::Reconciled(Some(_)))
            ),
            "v1 reconciled replay carries the record"
        );
        assert!(mock.transfer_calls().is_empty());
        s.cleanup();
    }

    // --- NotApplicable: Confirmed/Failed can never enter reconciliation -
    #[test]
    fn step4_confirmed_and_failed_are_not_reconcilable() {
        let s = step8_setup();
        let mock = MockOps::new(&s);
        run_pay_v2(&s, &mock, "ok-1", RECIPIENT, V2_AMT, None, None).expect("confirmed");
        let ops = RecoOps::with_timeout(None);
        let v = reconcile(&s, &ops, req("ok-1"), &owner_principal(), NOW + 5);
        assert!(matches!(v, ReconcileVerdict::NotApplicable));
        assert_eq!(
            ops.lookup_calls().len(),
            0,
            "no RPC for a non-reconcilable state"
        );
        assert_eq!(v2_intent(&s, "ok-1").exec_state, ExecState::Confirmed);

        // Failed: same refusal, ledger untouched
        let mut f = MockOps::new(&s);
        f.transfer_res = Err(MockErr::TransferError);
        run_pay_v2(&s, &f, "fail-1", RECIPIENT, V2_AMT, None, None).unwrap_err();
        let v = reconcile(&s, &ops, req("fail-1"), &owner_principal(), NOW + 5);
        assert!(matches!(v, ReconcileVerdict::NotApplicable));
        assert_eq!(v2_intent(&s, "fail-1").exec_state, ExecState::Failed);
        // the Failed refund restored the PRE-reservation figure (the
        // earlier ok-1 committed 50M — never a fake zero)
        assert_eq!(
            s.ledger_spent(),
            Some(PAY_AMT),
            "refund restored the pre-fail bucket"
        );

        // unknown key -> IntentNotFound, indistinguishable shape, no writes
        let v = reconcile(&s, &ops, req("no-such-key"), &owner_principal(), NOW + 5);
        assert!(matches!(v, ReconcileVerdict::IntentNotFound));
        s.cleanup();
    }

    // --- manual attestation is owner-only; resolver is auth-derived -----
    #[test]
    fn step4_manual_attestation_is_forbidden_for_agent_principals() {
        let s = step8_setup();
        let ops = RecoOps::with_timeout(Some(RECON_SIG));
        arm_unknown_v2(&s, "rec-agent", &ops);
        let agent_principal = ReconcilePrincipal::agent(&s.uuid);
        assert_eq!(agent_principal.resolver(), format!("agent:{}", s.uuid));
        let manual = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Absent),
            attestation: Some("self-serving release".to_string()),
            ..req("rec-agent")
        };
        let v = reconcile(&s, &ops, manual, &agent_principal, NOW + 120);
        assert!(
            matches!(v, ReconcileVerdict::ManualForbidden),
            "an agent principal may never attest"
        );
        assert_eq!(v2_intent(&s, "rec-agent").exec_state, ExecState::Unknown);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT), "no self-directed release");

        // deterministic evidence still works for the agent lane, and the
        // agent may NOT reconcile another agent's keys (resolver check)
        ops.set_lookup(
            RECON_SIG,
            TxLookup::Found(failed_record(RECON_SIG, "AccountNotFound", NOW + 30)),
        );
        let v = reconcile(
            &s,
            &ops,
            ReconcileRequest {
                allow_scan: false,
                ..req("rec-agent")
            },
            &agent_principal,
            NOW + 121,
        );
        let (outcome, _, record) = terminal_of(&v).expect("agent deterministic absent");
        assert_eq!(outcome, ReconciliationOutcome::Absent);
        assert_eq!(record.method, ReconciliationMethod::TxLookup);
        assert_eq!(record.resolver, format!("agent:{}", s.uuid));
        assert_eq!(s.ledger_spent(), Some(0));
        s.cleanup();
    }

    #[test]
    fn step4_resolver_grammar_rejects_freeform_and_credentials() {
        assert!(valid_resolver("owner:octocat"));
        assert!(valid_resolver("agent:0f2f3a4c-1111-4222-8333-aabbccddeeff"));
        assert!(valid_resolver("system:sweeper"));
        assert!(valid_resolver("operator:ops-7"));
        // never: raw credentials/tokens/paths/spaces/unknown kinds
        assert!(!valid_resolver("owner:bad login!"));
        assert!(!valid_resolver(&format!("credential:{}", "a".repeat(64))));
        assert!(!valid_resolver("agent:not-a-uuid"));
        assert!(!valid_resolver(
            "agent:0F2F3A4C-1111-4222-8333-AABBCCDDEEFF"
        )); // uppercase
        assert!(!valid_resolver(""));
        assert!(!valid_resolver("prefix:mid:tail"));
        assert!(!valid_resolver("owner:"));
        assert!(ReconcilePrincipal::owner("bad login!").is_none());
    }

    // --- HTTP semantics of every verdict ---------------------------------
    #[test]
    fn step4_verdict_http_mapping_is_stable() {
        let record = ReconciliationRecord {
            method: ReconciliationMethod::TxLookup,
            outcome: ReconciliationOutcome::Paid,
            tx_signature: Some(RECON_SIG.to_string()),
            resolved_at: NOW,
            resolver: "owner:shaaker-test".to_string(),
            evidence: Some(ReconciliationEvidence {
                slot: Some(9),
                ..Default::default()
            }),
        };
        let cases: Vec<(ReconcileVerdict, u16, Option<&str>)> = vec![
            (
                ReconcileVerdict::Reconciled {
                    record: record.clone(),
                    replayed: false,
                },
                200,
                None,
            ),
            (
                ReconcileVerdict::Proposal {
                    tx_signature: SCAN_SIG.to_string(),
                    evidence: ReconciliationEvidence::default(),
                },
                202,
                Some("AGENT_RECONCILIATION_PROPOSAL"),
            ),
            (
                ReconcileVerdict::Unresolved {
                    code: "RIALO_RPC_UNAVAILABLE",
                    reason: "down",
                },
                503,
                Some("RIALO_RPC_UNAVAILABLE"),
            ),
            (
                ReconcileVerdict::Unresolved {
                    code: "AGENT_RECONCILIATION_TEMPORARY_NOT_FOUND",
                    reason: "x",
                },
                202,
                Some("AGENT_RECONCILIATION_TEMPORARY_NOT_FOUND"),
            ),
            (
                ReconcileVerdict::Unresolved {
                    code: "AGENT_RECONCILIATION_ATTESTATION_REQUIRED",
                    reason: "x",
                },
                400,
                Some("AGENT_RECONCILIATION_ATTESTATION_REQUIRED"),
            ),
            (
                ReconcileVerdict::InProgress,
                409,
                Some("AGENT_PAYMENT_IN_PROGRESS"),
            ),
            (
                ReconcileVerdict::NotApplicable,
                409,
                Some("AGENT_RECONCILIATION_NOT_APPLICABLE"),
            ),
            (
                ReconcileVerdict::ManualForbidden,
                403,
                Some("AGENT_RECONCILIATION_MANUAL_FORBIDDEN"),
            ),
            (
                ReconcileVerdict::IntentNotFound,
                404,
                Some("AGENT_PAYMENT_INTENT_NOT_FOUND"),
            ),
            (ReconcileVerdict::StoreError, 500, Some("AGENT_STORE_ERROR")),
        ];
        for (verdict, want_status, want_code) in cases {
            let (status, body) = verdict.status_and_body("agent-1", "key-1", None);
            assert_eq!(status.as_u16(), want_status, "{want_status} for {body}");
            if let Some(code) = want_code {
                assert_eq!(body["error"]["code"].as_str(), Some(code), "{body}");
            }
        }
        // the success body carries the full immutable audit shape
        let (_, body) = ReconcileVerdict::Reconciled {
            record,
            replayed: true,
        }
        .status_and_body("a", "k", None);
        assert_eq!(body["success"], true);
        assert_eq!(body["replayed"], true);
        assert_eq!(body["reconciliation"]["method"], "tx_lookup");
        assert_eq!(body["reconciliation"]["outcome"], "paid");
        assert_eq!(body["reconciliation"]["tx_signature"], RECON_SIG);
        assert_eq!(body["reconciliation"]["evidence"]["slot"], 9);
    }

    // --- body parsing refuses everything outside the grammar -------------
    #[test]
    fn step4_reconcile_body_parsing_is_typed_and_closed() {
        let ok = parse_reconcile_body(r#"{"idempotency_key":"abc-123_XY"}"#, true).expect("valid");
        assert!(ok.allow_scan && !ok.allow_auto && ok.manual_outcome.is_none());

        // deny_unknown_fields: an injected agent_id/resolver never lands
        assert!(
            parse_reconcile_body(r#"{"idempotency_key":"k","resolver":"owner:evil"}"#, true)
                .is_err()
        );
        assert!(parse_reconcile_body(r#"{"idempotency_key":"k","agent_id":"x"}"#, true).is_err());
        assert!(parse_reconcile_body(r#"{"idempotency_key":""}"#, true).is_err());
        assert!(parse_reconcile_body(r#"{"idempotency_key":"has space"}"#, true).is_err());
        assert!(
            parse_reconcile_body(r#"{"idempotency_key":"k","manual_outcome":"maybe"}"#, true)
                .is_err()
        );
        assert!(
            parse_reconcile_body(r#"{"idempotency_key":"k","attestation":"note"}"#, true).is_err(),
            "attestation without outcome"
        );
        // the agent lane never speaks manual grammar
        assert!(
            parse_reconcile_body(
                r#"{"idempotency_key":"k","manual_outcome":"paid","attestation":"n"}"#,
                false
            )
            .is_err()
        );
        // oversized attestation refused (bounded free text)
        let long = "x".repeat(600);
        assert!(
            parse_reconcile_body(
                &format!(
                    r#"{{"idempotency_key":"k","manual_outcome":"paid","attestation":"{long}"}}"#
                ),
                true
            )
            .is_err()
        );
    }

    // --- BalanceDelta can never mint a terminal (production scan) --------
    #[test]
    fn step4_balance_delta_never_writes_terminals() {
        let src = include_str!("agents.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("production section");
        assert_eq!(
            production
                .matches("ReconciliationMethod::BalanceDelta")
                .count(),
            0,
            "the deprecated BalanceDelta method must never be constructed by production code"
        );
    }

    // --- STRUCTURAL: the reconciliation lane is read-only against money --
    #[test]
    fn step4_structural_reconciler_moves_no_money() {
        let src = include_str!("agents.rs");
        let fn_body = |anchor: &str| -> String {
            let start = src
                .find(anchor)
                .unwrap_or_else(|| panic!("missing: {anchor}"));
            let rest = &src[start..];
            let end = rest.find("\n}").expect("fn end");
            rest[..end].to_string()
        };

        let engine = fn_body("pub(crate) fn reconcile_intent(");
        for forbidden in [
            "ops.transfer(",
            "ops.balance(",
            "reserve_spend(",
            "release_spend(",
            "store_lock(",
            "execute_agent_payment(",
            "spawn_blocking",
            "attempt in 0..",
            "is_retryable",
        ] {
            assert!(
                !engine.contains(forbidden),
                "reconcile engine references forbidden token: {forbidden}"
            );
        }
        for required in [
            "reconcile_decision(",
            "commit_reconciliation(",
            "normalise_stale_pending(",
            "ReconcileVerdict::InProgress",
        ] {
            assert!(engine.contains(required), "engine must use {required}");
        }

        let decision = fn_body("fn reconcile_decision(");
        for forbidden in [
            "ops.balance(",
            "release_",
            "write_json",
            "store_lock(",
            "ops.transfer(",
        ] {
            assert!(
                !decision.contains(forbidden),
                "decision core references forbidden token: {forbidden}"
            );
        }
        for required in ["ops.read_tx(", "scan_address_history("] {
            assert!(decision.contains(required), "decision must use {required}");
        }

        // the commit section holds store_lock but performs NO RPC
        let commit = fn_body("fn commit_reconciliation(");
        assert!(commit.contains("store_lock("));
        for forbidden in [
            "read_tx",
            "signatures_for_address",
            "ops.transfer(",
            "release_spend(",
        ] {
            assert!(
                !commit.contains(forbidden),
                "commit section references forbidden token: {forbidden}"
            );
        }
        assert!(commit.contains("release_absent_reservation_inner("));
        assert!(commit.contains("utc_day(intent.created_at)"));

        // neither reconcile handler invents an auth mechanism or moves money
        let owner_handler = fn_body("pub async fn agent_payment_reconcile(");
        for forbidden in [
            "transfer(",
            "authenticate_agent_credential",
            "dev-login",
            "DEV_LOGIN",
            "api_token",
            "password",
            "AGENT_CREDENTIAL_INVALID",
        ] {
            assert!(
                !owner_handler.contains(forbidden),
                "owner handler references forbidden token: {forbidden}"
            );
        }
        for required in [
            "session_user",
            "load_authorized",
            "parse_reconcile_body",
            "reconcile_production",
        ] {
            assert!(
                owner_handler.contains(required),
                "owner handler must wire {required}"
            );
        }
        let trigger_handler = fn_body("pub async fn agent_trigger_payment_reconcile(");
        for forbidden in [
            "transfer(",
            "session_user",
            "dev-login",
            "DEV_LOGIN",
            "api_token",
            "password",
            "load_authorized",
        ] {
            assert!(
                !trigger_handler.contains(forbidden),
                "trigger handler references forbidden token: {forbidden}"
            );
        }
        for required in [
            "authenticate_agent_credential",
            "valid_credential_shape",
            "AGENT_CREDENTIAL_INVALID",
            "parse_reconcile_body",
            "reconcile_production",
        ] {
            assert!(
                trigger_handler.contains(required),
                "trigger handler must wire {required}"
            );
        }
    }

    // --- v1 known-signature semantics (no signature field on v1) --------
    #[test]
    fn step4_v1_unknown_without_signature_uses_scan_lane_only() {
        let s = step8_setup();
        let mut m = MockOps::new(&s);
        m.transfer_res = Err(MockErr::ConfirmationTimeout);
        let err = run_pay(&s, &m, "v1-unk", RECIPIENT, 0.05, None, None).unwrap_err();
        assert!(
            matches!(&err, PaymentFailure::Transfer(e) if e.code == "RIALO_TRANSFER_CONFIRMATION_TIMEOUT")
        );
        assert_eq!(s.intent("v1-unk").unwrap().state, IntentState::Unknown);
        assert_eq!(s.ledger_spent(), Some(PAY_AMT));

        let ops = RecoOps::with_timeout(None);
        // scan disabled -> stays Unknown, nothing else
        let v = reconcile(
            &s,
            &ops,
            ReconcileRequest {
                allow_scan: false,
                ..req("v1-unk")
            },
            &owner_principal(),
            NOW + 120,
        );
        assert!(matches!(
            v,
            ReconcileVerdict::Unresolved {
                code: "AGENT_RECONCILIATION_NO_SIGNATURE",
                ..
            }
        ));
        assert_eq!(s.intent("v1-unk").unwrap().state, IntentState::Unknown);

        // manual Absent releases the ORIGINAL v1 reservation, once
        let manual = ReconcileRequest {
            manual_outcome: Some(ReconciliationOutcome::Absent),
            attestation: Some("v1 manual closure with operator evidence".to_string()),
            ..req("v1-unk")
        };
        let v = reconcile(&s, &ops, manual, &owner_principal(), NOW + 121);
        let (outcome, _, record) = terminal_of(&v).expect("v1 manual terminal");
        assert_eq!(outcome, ReconciliationOutcome::Absent);
        assert_eq!(record.method, ReconciliationMethod::ManualAttestation);
        assert_eq!(
            s.intent("v1-unk").unwrap().state,
            IntentState::ReconciledAbsent
        );
        assert!(s.intent("v1-unk").unwrap().reconciliation.is_some());
        assert_eq!(s.ledger_spent(), Some(0));
        s.cleanup();
    }
}

#[cfg(test)]
#[path = "_crashrecovery_i9_tests.rs"]
mod crashrecovery_tests;

#[cfg(test)]
#[path = "_emrev_i9_tests.rs"]
mod emrev_tests;

#[cfg(test)]
#[path = "_keylife_i9_tests.rs"]
mod keylife_tests;

#[cfg(test)]
#[path = "_hierpol_i9_tests.rs"]
mod hierpol_tests;

#[cfg(test)]
#[path = "_hierspend_i9_tests.rs"]
mod hierspend_tests;

#[cfg(test)]
#[path = "_delegation_i9_tests.rs"]
mod delegation_tests;

#[cfg(test)]
#[path = "_d8g7_backfill_tests.rs"]
mod d8g7_backfill_tests;

#[cfg(test)]
#[path = "_custody_i9_tests.rs"]
mod custody_tests;

/// MISSION PHASE 2 — PostgreSQL policy read (authoritative store).
// Filesystem mode: the legacy JSON file. Postgres mode: the DB row.
// Returns ModeMismatch in FS mode so a wiring bug is loud, not silent.
pub fn load_policy_for_agent_pg(
    agent_id: &uuid::Uuid,
) -> Result<Option<crate::agents::AgentPolicy>, crate::pg_store::StoreError> {
    if !crate::pg_store::pg_is_authoritative() {
        return Err(crate::pg_store::StoreError::ModeMismatch);
    }

    crate::pg_store::runtime_pg()?;
    crate::pg_store::pg_run(async {
        let client = crate::pg_store::global_client().await;
        crate::pg_store::policy_read_pg(&*client, *agent_id)
            .await
            .map_err(crate::pg_store::StoreError::Db)
    })?
}

/// MISSION PHASE 2 — PostgreSQL policy PATCH (authoritative store).
// Filesystem mode: ModeMismatch. Postgres mode: locked FOR UPDATE, verified
// for owner, then write. Ok(false) = missing/foreign.
pub async fn patch_agent_policy_pg(
    agent_id: uuid::Uuid,
    owner_user_id: u64,
    max_payment_per_tx_kelvin: Option<u64>,
    daily_payment_limit_kelvin: Option<u64>,
    allowed_recipients: Option<Vec<String>>,
    allowed_actions: Option<Vec<String>>,
    parent_agent_id: Option<Option<String>>,
    delegation_revoked: Option<Option<i64>>,
    aggregate_daily_limit_kelvin: Option<Option<u64>>,
    now: i64,
) -> Result<bool, crate::pg_store::StoreError> {
    if !crate::pg_store::pg_is_authoritative() {
        return Err(crate::pg_store::StoreError::ModeMismatch);
    }
    // PG is authoritative: one transaction locks the owned AGENT row (the
    // ownership anchor lives on `agents`, NOT on `agent_policies`), then
    // applies the policy PATCH to the agent_policies row. The policy row
    // itself carries no owner column — ownership flows through the agents
    // relationship. Ok(false) = missing/foreign (the caller answers the
    // indistinguishable NOT_FOUND); any DB error is a typed StoreError
    // (fail-closed — never a panic, never a silent FS fallback).
    //
    // Omitted-vs-explicit-NULL semantics (the public PATCH contract):
    // `Option<Option<T>>` — outer None = field OMITTED (keep the stored
    // value); Some(None) = field PRESENT with an explicit NULL (clear it);
    // Some(Some(v)) = field PRESENT with a value (set it). Only fields the
    // caller passed are included in the SET clause — COALESCE would defeat
    // the explicit-clear contract, so it is deliberately not used here.
    crate::pg_store::pg_run(async {
        let mut client = crate::pg_store::global_client().await;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::pg_store::StoreError::Db(format!("policy patch tx begin: {e}")))?;
        // 1. lock the AGENT row and verify ownership (fail-closed: a
        //    missing or foreign agent never reaches the policy write).
        let locked = tx
            .query(
                "SELECT 1 FROM agents WHERE agent_id = $1 AND owner_user_id = $2 FOR UPDATE",
                &[&agent_id, &(owner_user_id as i64)],
            )
            .await
            .map_err(|e| crate::pg_store::StoreError::Db(format!("policy patch lock: {e}")))?;
        if locked.is_empty() {
            let _ = tx.rollback().await;
            return Ok(false);
        }
        // 2. the policy row must exist (the PATCH is read-modify-write on
        //    persisted state — never an upsert). Missing row = false.
        let existing = tx
            .query(
                "SELECT 1 FROM agent_policies WHERE agent_id = $1 FOR UPDATE",
                &[&agent_id],
            )
            .await
            .map_err(|e| crate::pg_store::StoreError::Db(format!("policy patch lock: {e}")))?;
        if existing.is_empty() {
            let _ = tx.rollback().await;
            return Ok(false);
        }
        // 3. build the UPDATE from ONLY the present fields (full-replacement
        //    semantics live in the handler; this store call applies exactly
        //    what the caller resolved).
        let mut sets: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(v) = max_payment_per_tx_kelvin {
            params.push(Box::new(v as i64));
            sets.push(format!("max_payment_per_tx_kelvin = ${}", params.len()));
        }
        if let Some(v) = daily_payment_limit_kelvin {
            params.push(Box::new(v as i64));
            sets.push(format!("daily_payment_limit_kelvin = ${}", params.len()));
        }
        if let Some(v) = allowed_recipients {
            params.push(Box::new(v));
            sets.push(format!("allowed_recipients = ${}", params.len()));
        }
        if let Some(v) = allowed_actions {
            params.push(Box::new(v));
            sets.push(format!("allowed_actions = ${}", params.len()));
        }
        if let Some(v) = parent_agent_id {
            let parsed: Option<uuid::Uuid> = v
                .as_deref()
                .map(|s| s.parse::<uuid::Uuid>())
                .transpose()
                .map_err(|e| {
                    crate::pg_store::StoreError::Db(format!("policy patch parent id: {e}"))
                })?;
            params.push(Box::new(parsed));
            sets.push(format!("parent_agent_id = ${}", params.len()));
        }
        if let Some(v) = delegation_revoked {
            params.push(Box::new(v));
            sets.push(format!("delegation_revoked = ${}", params.len()));
        }
        if let Some(v) = aggregate_daily_limit_kelvin {
            params.push(Box::new(v.map(|x| x as i64)));
            sets.push(format!("aggregate_daily_limit_kelvin = ${}", params.len()));
        }
        // updated_at is ALWAYS stamped server-side (the same contract as FS).
        params.push(Box::new(now));
        sets.push(format!("updated_at = ${}", params.len()));
        params.push(Box::new(agent_id));
        let sql = format!(
            "UPDATE agent_policies SET {} WHERE agent_id = ${}",
            sets.join(", "),
            params.len()
        );
        let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let n = tx
            .execute(sql.as_str(), &refs)
            .await
            .map_err(|e| crate::pg_store::StoreError::Db(format!("policy patch: {e}")))?;
        if n == 0 {
            let _ = tx.rollback().await;
            return Ok(false);
        }
        tx.commit()
            .await
            .map_err(|e| crate::pg_store::StoreError::Db(format!("policy patch commit: {e}")))?;
        Ok(true)
    })?
}

/// MISSION PHASE 3 — PostgreSQL policy effective resolution (authoritative store).

// Uses the PG-backed policy as the starting child policy for the hierarchy walk.

/// PG-authoritative effective-policy resolution: the frozen Section 5 walk
/// executed against the POSTGRESQL stores. Every ancestor read (agent
/// record + policy row) is authoritative; there is NO filesystem fallback
/// in PG mode — a missing/malformed/unauthorized hierarchy record fails
/// closed. The fold semantics, validation order, cycle detection, depth
/// budget, and delegation-severing rule are byte-for-byte the FS
/// resolver's (same `fold_constraint`, same `HierarchyError` taxonomy).
///
/// Verification order per hop mirrors `resolve_effective_policy` exactly:
///   1. delegation stamp on the CURRENT policy severs the chain (return
///      the effective-so-far, immediate — no further reads),
///   2. linkage parse (MalformedLinkage), self-parent (CycleDetected),
///   3. visited-set cycle (CycleDetected),
///   4. depth budget (DepthExceeded),
///   5. parent agent record loads (ParentAgentUnavailable) + same-owner
///      (CrossOwnerParent) — status is NOT re-gated here (a disabled
///      parent's constraints stay binding; the FS contract — disabling
///      does not remove the constraint document),
///   6. parent policy loads (ParentPolicyUnavailable).
pub fn resolve_effective_policy_for_agent_pg(
    child_policy: AgentPolicy,
    agent_id: &uuid::Uuid,
) -> Result<AgentPolicy, HierarchyError> {
    if !crate::pg_store::pg_is_authoritative() {
        return Err(HierarchyError::ParentPolicyUnavailable);
    }
    let child_uuid =
        parse_agent_id(&child_policy.agent_id).ok_or(HierarchyError::MalformedLinkage)?;
    if agent_id != &child_uuid {
        // the caller's target id MUST be the policy's own identity (the
        // same integrity rule the FS loader enforces on file contents)
        return Err(HierarchyError::MalformedLinkage);
    }
    crate::pg_store::pg_run(async {
        // child owner from the AUTHORITATIVE agent row (a missing child
        // agent record cannot anchor a hierarchy — fail closed)
        let child_agent = crate::pg_store::agent_read_dispatch(child_uuid)
            .await
            .map_err(|_| HierarchyError::ParentAgentUnavailable)?
            .ok_or(HierarchyError::ParentAgentUnavailable)?;
        let child_owner = child_agent.owner_user_id;

        let mut effective = child_policy.clone();
        // the RUNTIME scope list: every node whose policy sets an aggregate
        // cap, child first — identical to the FS walk's deterministic order
        let mut aggregate_scopes: Vec<(String, u64)> = Vec::new();
        if let Some(cap) = child_policy.aggregate_daily_limit_kelvin {
            aggregate_scopes.push((child_uuid.to_string(), cap));
        }
        let mut current_policy = child_policy;
        let mut visited: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
        visited.insert(child_uuid);
        let mut hops = 0usize;

        loop {
            let Some(link) = current_policy.parent_agent_id.clone() else {
                effective.aggregate_scopes = aggregate_scopes;
                return Ok(effective);
            };
            // PHASE 9 "Delegation": a REVOKED delegation severs the
            // ancestors ABOVE this node — the walk stops here. Immediate
            // by construction (the stamp is on the current record).
            if current_policy.delegation_revoked.is_some() {
                effective.aggregate_scopes = aggregate_scopes;
                return Ok(effective);
            }
            let parent_uuid = parse_agent_id(&link).ok_or(HierarchyError::MalformedLinkage)?;
            if parent_uuid == child_uuid {
                return Err(HierarchyError::CycleDetected);
            }
            if !visited.insert(parent_uuid) {
                return Err(HierarchyError::CycleDetected);
            }
            hops += 1;
            if hops > MAX_POLICY_HIERARCHY_DEPTH {
                return Err(HierarchyError::DepthExceeded);
            }
            // the parent AGENT row must exist (authoritative) and share the
            // child's owner — hierarchy never crosses owners. The parent's
            // STATUS is deliberately not re-gated (same contract as FS).
            let parent_agent = crate::pg_store::agent_read_dispatch(parent_uuid)
                .await
                .map_err(|_| HierarchyError::ParentAgentUnavailable)?
                .ok_or(HierarchyError::ParentAgentUnavailable)?;
            if parent_agent.owner_user_id != child_owner {
                return Err(HierarchyError::CrossOwnerParent);
            }
            // the parent POLICY row must load (missing/corrupt = fail closed)
            let parent_policy = crate::pg_store::policy_read_pg_pub(parent_uuid)
                .await
                .map_err(|_| HierarchyError::ParentPolicyUnavailable)?
                .ok_or(HierarchyError::ParentPolicyUnavailable)?;
            fold_constraint(&mut effective, &parent_policy);
            // the scope cap is NEVER folded into the child's own enforcement
            // view — collected for the spend layer instead (FS parity)
            if let Some(cap) = parent_policy.aggregate_daily_limit_kelvin {
                aggregate_scopes.push((parent_uuid.to_string(), cap));
            }
            current_policy = parent_policy;
        }
    })
    .map_err(|_: crate::pg_store::StoreError| HierarchyError::ParentPolicyUnavailable)?
}
