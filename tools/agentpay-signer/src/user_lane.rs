//! user_lane — G79: the USER wallet namespace inside the isolated signer.
//!
//! Strictly parallel to (never mixed with) the agent namespace:
//!   * Store: `users/<github_id>.wallet.json` (record) + `users/<github_id>.key.json`
//!     (funded key). Agents stay at the store root (`<uuid>.*`); the identity
//!     grammar (UUID vs decimal u64) and path prefixes are disjoint.
//!   * Funded key material exists ONLY inside this module's functions, only
//!     in the signer process. Never returned, never logged, never leaves the
//!     container path.
//!   * Provisioning/import: operator-run. `POST /user/provision` (admin
//!     secret at the HTTP boundary) registers the PUBLIC binding ONLY when
//!     the funded key file ALREADY exists in the store and its derived
//!     address matches the operator-declared registry pubkey. No key bytes
//!     ever cross the protocol. (G79 decision 6: no keys imported/moved by
//!     this task.)
//!   * Policy: G79 decision 2 — a DISTINCT per-user record per user
//!     (`user_policy.rs`), identity- and registered-binding-checked.
//!
//! Wire contract (G79 decision 3 — typed structures in `user_protocol.rs`;
//! serde field names are the single source for BOTH sides):
//!   POST /user/sign  UserSignRequest  → 200 sealed UserSignResponse
//!                                     → non-200 {"error":"DENIED","code"}
//!   GET  /user/wallet/<github_id>     → 200 {"public_address"} | 404
//!   GET  /user/status/<github_id>     → 200 UserStatusResponse (read-only
//!                                       diagnostics per G76; no keys)
//!   POST /user/provision              → operator ceremony (admin-auth'd)
//!
//! HTTP routing/wiring in main.rs is G79-DEFERRED (decision scoped: the
//! routes stay INACTIVE; only this library surface exists).
//!
//! G81 — NEW-USER wallet provisioning (create path; the operator import
//! ceremony for EXISTING keys is untouched, and per this gate's decision,
//! existing wallets are NEVER migrated):
//!   * POST /user/wallet (admin-secret gated at the HTTP boundary): the
//!     signer mints the funded key EXCLUSIVELY inside its user namespace.
//!     The application receives ONLY the public address + non-secret
//!     metadata; no key material can appear in the wire type (fields are
//!     public by construction).
//!   * Atomic + idempotent: O_EXCL create; a retry (same user_id + same
//!     auth linkage) returns the SAME wallet (Already-created equivalence);
//!     a retry with a DIFFERENT auth linkage for an existing user is a hard
//!     refusal (never a second identity for one principal).
//!   * The generation SECRET never crosses the wire: it lives only in the
//!     signer's process env (operator-supplied at startup).
//!   * User auth keys: minted here at create (funds-less, recoverable from
//!     the recovery envelope; private half never leaves the signer).
//!   * Channel seal: responses are sealed by the channel identity, which
//!     cryptographically binds the (aged-out) introductory secret in the
//!     signed payload — a duplicate-secret theft cannot sign: forging the
//!     seal requires the long-term channel identity key.
//!   * Wallet VERSION separation: signer store v2 vs app registry v1
//!     (G81 creates v2 wallets ONLY; v1 existing wallets are excluded and
//!     never migrated; the app MUST NOT treat them as new-lane wallets).

use crate::rialo_canonical::{CanonicalTransferSpec, build_canonical_message};
use crate::user_policy::{UserPolicyError, evaluate_user_policy, load_user_policy_for};
use crate::user_signer_protocol::{UserSignRequest, UserSignResponse, user_denial_codes as codes};
use crate::{SignerStore, seal_channel_response};
use rialo_s_signer::Signer;
use std::fs;
use std::path::Path;

/// G81 — the EXPLICIT wallet version marker for the new isolated-signer
/// lane. Setting it (ahead of the wiring) is how the deployment declares
/// the new-lane wallet generation; leaving it unset keeps the create path
/// structurally absent (fail-closed).
pub const USER_WALLET_VERSION_ENV: &str = "AGENTPAY_USER_WALLET_VERSION";
/// The value that activates the new-lane create path (v2).
pub const USER_WALLET_VERSION_V2: &str = "2";
/// The generation secret (operator-supplied at signer startup; NEVER on
/// the wire). Hex-encoded 32 bytes.
pub const USER_CREATE_SECRET_ENV: &str = "AGENTPAY_SIGNER_USER_CREATE_SECRET";

/// The namespace directory inside the signer store (disjoint from agents).
pub const USER_NAMESPACE_DIR: &str = "users";

pub fn user_namespace_root(store: &SignerStore) -> std::path::PathBuf {
    store.root().join(USER_NAMESPACE_DIR)
}

pub fn user_key_path(store: &SignerStore, user_id: u64) -> std::path::PathBuf {
    user_namespace_root(store).join(format!("{user_id}.key.json"))
}

pub fn user_record_path(store: &SignerStore, user_id: u64) -> std::path::PathBuf {
    user_namespace_root(store).join(format!("{user_id}.wallet.json"))
}

/// The user wallet RECORD (public identity only).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct UserWalletRecord {
    pub user_id: u64,
    pub public_address: String,
    /// the user's funds-less ed25519 auth pubkey (base58) — bound at
    /// operator registration, verified at every sign
    pub auth_pubkey: String,
}

fn parse_user_record(bytes: &[u8]) -> Option<UserWalletRecord> {
    let r: UserWalletRecord = serde_json::from_slice(bytes).ok()?;
    if r.public_address.trim().is_empty() || r.auth_pubkey.trim().is_empty() {
        return None;
    }
    crate::base58_decode_32(&r.public_address)?;
    Some(r)
}

fn load_user_key(store: &SignerStore, user_id: u64) -> Result<rialo_s_keypair::Keypair, ()> {
    let bytes = std::fs::read(user_key_path(store, user_id)).map_err(|_| ())?;
    let arr: Vec<u8> = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if arr.len() != 64 {
        return Err(());
    }
    rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|_| ())
}

/// The authoritative record read (integrity-checked: record parses AND the
/// key container's derived address equals the record's address).
pub fn user_wallet_record(store: &SignerStore, user_id: u64) -> Result<UserWalletRecord, ()> {
    let bytes = std::fs::read(user_record_path(store, user_id)).map_err(|_| ())?;
    let record = parse_user_record(&bytes).ok_or(())?;
    let kp = load_user_key(store, user_id)?;
    if kp.pubkey().to_string() != record.public_address {
        return Err(());
    }
    Ok(record)
}

/// Public-address read for `GET /user/wallet/<id>` (public data only).
pub fn user_public_address(store: &SignerStore, user_id: u64) -> Result<Option<String>, ()> {
    let bytes = match std::fs::read(user_record_path(store, user_id)) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    match parse_user_record(&bytes) {
        Some(r) => Ok(Some(r.public_address)),
        None => Err(()),
    }
}

/// G76-analogue read-only user status (public data only; no key contents;
/// diagnostics carry CLASSES, not secrets).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct UserStatusResponse {
    pub user_id: String,
    pub registered: bool,
    pub record_corrupt: bool,
    pub public_address: Option<String>,
    pub policy_state: String,
    pub key_container_state: String,
}

pub fn user_status(store: &SignerStore, policy_dir: &Path, user_id: u64) -> UserStatusResponse {
    let record = user_wallet_record(store, user_id).ok();
    let record_corrupt = user_record_path(store, user_id).exists() && record.is_none();
    let registered_auth = record.as_ref().map(|r| r.auth_pubkey.clone());
    let policy_state = match registered_auth.as_deref() {
        None => "unknown".to_string(),
        Some(auth) => match load_user_policy_for(policy_dir, user_id, auth) {
            Ok(_) => "ok".to_string(),
            Err(UserPolicyError::MissingForUser) => "missing".to_string(),
            Err(UserPolicyError::Malformed) => "malformed".to_string(),
            Err(UserPolicyError::WildcardRejected) => "wildcard".to_string(),
            Err(UserPolicyError::IdentityMismatch) => "identity_mismatch".to_string(),
            Err(UserPolicyError::RegisteredBindingMismatch) => "binding_mismatch".to_string(),
        },
    };
    let key_container_state = if user_key_path(store, user_id).exists() {
        match load_user_key(store, user_id) {
            Ok(_) => "linked".to_string(),
            Err(_) => "corrupt".to_string(),
        }
    } else {
        "not_imported".to_string()
    };
    UserStatusResponse {
        user_id: user_id.to_string(),
        registered: record.is_some(),
        record_corrupt,
        public_address: record.as_ref().map(|r| r.public_address.clone()),
        policy_state,
        key_container_state,
    }
}

/// Operator registration (the ONLY provisioning path; admin secret at the
/// HTTP boundary). FAIL-CLOSED: succeeds only when the key container
/// ALREADY exists and its derived address equals `expected_pubkey`.
/// Idempotent for an identical binding; conflicting binding = hard refusal.
pub fn register_user_wallet(
    store: &SignerStore,
    user_id: u64,
    expected_pubkey: &str,
    auth_pubkey: &str,
) -> Result<(), UserDenial> {
    if crate::base58_decode_32(expected_pubkey).is_none()
        || crate::base58_decode_32(auth_pubkey).is_none()
    {
        return Err(UserDenial::BadRequest);
    }
    let address = match load_user_key(store, user_id) {
        Ok(kp) => kp.pubkey().to_string(),
        Err(_) => {
            // distinguish absent vs corrupt for the operator
            if user_key_path(store, user_id).exists() {
                return Err(UserDenial::StoreUnavailable);
            }
            // The import ceremony must place the key FILE first. This
            // process mints NO user keys and imports NO key bytes.
            return Err(UserDenial::KeyNotImported);
        }
    };
    if address != expected_pubkey.trim() {
        return Err(UserDenial::CeremonyAddressMismatch);
    }
    let record_path = user_record_path(store, user_id);
    if record_path.exists() {
        let bytes = std::fs::read(&record_path).map_err(|_| UserDenial::StoreUnavailable)?;
        if let Some(existing) = parse_user_record(&bytes) {
            if existing.public_address == address && existing.auth_pubkey == auth_pubkey.trim() {
                return Ok(()); // idempotent no-op
            }
            return Err(UserDenial::ConflictingRegistration);
        }
        return Err(UserDenial::RecordCorrupt);
    }
    let record = UserWalletRecord {
        user_id,
        public_address: address,
        auth_pubkey: auth_pubkey.trim().to_string(),
    };
    let dir = user_namespace_root(store);
    std::fs::create_dir_all(&dir).map_err(|_| UserDenial::StoreUnavailable)?;
    let record_bytes =
        serde_json::to_vec(&record).map_err(|_| UserDenial::StoreUnavailable)?;
    crate::wallet_file_safety::write_new_file_no_replace(&record_path, &record_bytes, 0o600)
        .map_err(|e| match e {
            crate::wallet_file_safety::SafetyError::AlreadyExists => {
                UserDenial::ConflictingRegistration
            }
            _ => UserDenial::StoreUnavailable,
        })?;
    Ok(())
}

/// Typed user-lane denials (fieldless classes; `parts` is the ONLY mapping
/// the HTTP layer uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDenial {
    BadRequest,
    UnknownWallet,
    /// G81 — a user/record/wallet already exists for this identity (create
    /// path idempotency + conflict refusal)
    AlreadyExists,
    /// G81 — declared identity ≠ session/expected identity on create
    IdentityMismatch,
    /// timeout / transport: the caller maps it to the uncertainty class
    NonceReplay,
    /// G83-FIX M1 — no operator-registered auth binding for the subject
    /// (the create-intent signature cannot be verified) ⇒ fail-closed
    PrerequisiteMissing,
    /// G83-FIX M2 — this user already has a durable in-progress create
    /// (singleflight; the earlier attempt's state is authoritative)
    ProvisioningInProgress,
    /// G83-FIX M2 — artifacts exist but are inconsistent/incomplete; the
    /// caller must NOT retry, delete, or overwrite (operator procedure)
    ProvisioningIncomplete,
    RecordCorrupt,
    AuthMalformed,
    AuthInvalid,
    PayerMismatch,
    Canonical,
    PolicyMissing,
    PolicyIdentityMismatch,
    PolicyBindingMismatch,
    PolicyWildcard,
    PolicyMalformed,
    PolicyDenied,
    KeyNotImported,
    CeremonyAddressMismatch,
    ConflictingRegistration,
    SigningNotEnabled,
    StoreUnavailable,
    Internal,
}

impl UserDenial {
    /// (HTTP status, wire code) — the ONLY source of these mappings.
    pub fn parts(self) -> (u16, &'static str) {
        match self {
            UserDenial::BadRequest => (400, codes::BAD_REQUEST),
            UserDenial::AuthMalformed => (403, codes::AUTH_MALFORMED),
            UserDenial::AuthInvalid => (403, codes::AUTH_INVALID),
            UserDenial::PayerMismatch => (403, codes::PAYER_MISMATCH),
            UserDenial::Canonical => (403, codes::BYTE_DIVERGENCE),
            UserDenial::PolicyDenied => (403, codes::POLICY_DENIED),
            UserDenial::KeyNotImported => (403, codes::KEY_NOT_IMPORTED),
            UserDenial::CeremonyAddressMismatch => (403, codes::CEREMONY_ADDRESS_MISMATCH),
            UserDenial::ConflictingRegistration => (409, codes::CONFLICTING_REGISTRATION),
            UserDenial::SigningNotEnabled => (403, codes::SIGNING_NOT_ENABLED),
            UserDenial::PolicyMissing
            | UserDenial::PolicyIdentityMismatch
            | UserDenial::PolicyBindingMismatch
            | UserDenial::PolicyWildcard
            | UserDenial::PolicyMalformed => (403, codes::POLICY_MISSING),
            UserDenial::UnknownWallet => (404, codes::UNKNOWN_WALLET),
            UserDenial::AlreadyExists => (409, codes::USER_EXISTS),
            UserDenial::IdentityMismatch => (403, codes::IDENTITY_MISMATCH),
            UserDenial::NonceReplay => (409, codes::NONCE_REPLAY),
            UserDenial::PrerequisiteMissing => (424, codes::PREREQUISITE_MISSING),
            UserDenial::ProvisioningInProgress => (409, codes::PROVISIONING_IN_PROGRESS),
            UserDenial::ProvisioningIncomplete => (409, codes::PROVISIONING_INCOMPLETE),
            UserDenial::RecordCorrupt => (500, codes::RECORD_CORRUPT),
            UserDenial::StoreUnavailable => (500, codes::STORE_UNAVAILABLE),
            UserDenial::Internal => (500, codes::INTERNAL),
        }
    }

    pub fn body(self) -> String {
        let (_status, code) = self.parts();
        serde_json::json!({ "error": "DENIED", "code": code }).to_string()
    }
}

/// THE user sign chain (typed contract end to end). Authorize (record +
/// declared-vs-bound auth identity + payer binding + canonical recompile +
/// auth signature + DISTINCT per-user policy) → sign → self-verify.
/// Deny-by-default; no broadcast, ever. Signing armed ONLY when
/// `AGENTPAY_SIGNER_SIGNING_ENABLED=1` (the frozen agent-lane gate).
pub fn sign_user_transaction(
    store: &SignerStore,
    policy_dir: &Path,
    body_bytes: &[u8],
    now_ms: i64,
) -> Result<UserSignResponse, UserDenial> {
    if !crate::signing_enabled() {
        return Err(UserDenial::SigningNotEnabled);
    }

    // ---- strict typed parse (the shared contract; unknown fields REFUSED
    //      — the G78 loose Value-parse is replaced by the typed contract)
    let req: UserSignRequest =
        serde_json::from_slice(body_bytes).map_err(|_| UserDenial::BadRequest)?;
    let user_id: u64 = req.user_id.parse().map_err(|_| UserDenial::BadRequest)?;
    if req.channel_nonce.trim().is_empty() {
        return Err(UserDenial::BadRequest);
    }

    // ---- authoritative record (fail-closed on any deviation)
    let record = user_wallet_record(store, user_id).map_err(|_| UserDenial::UnknownWallet)?;

    // ---- declared auth identity MUST equal the request principal AND the
    //      registered binding (cross-user rejection is structural)
    if req.auth_signature.pubkey.user_id != req.user_id
        || req.auth_signature.pubkey.base58.trim() != record.auth_pubkey
    {
        return Err(UserDenial::AuthInvalid);
    }

    // ---- payer binding: the signer signs ONLY the registered wallet
    if req.transaction.fee_payer != record.public_address {
        return Err(UserDenial::PayerMismatch);
    }

    // ---- canonical recompile (the signer's OWN bytes; strict fields)
    let from = crate::base58_decode_32(&req.transaction.fee_payer).ok_or(UserDenial::Canonical)?;
    let to = crate::base58_decode_32(&req.transaction.recipient).ok_or(UserDenial::Canonical)?;
    let config_prefix: u64 = req
        .transaction
        .config_hash_prefix
        .parse()
        .map_err(|_| UserDenial::Canonical)?;
    let spec = CanonicalTransferSpec {
        from: &from,
        to: &to,
        amount_kelvin: req.transaction.amount_kelvin,
        valid_from_ms: req.transaction.valid_from_ms,
        config_hash_prefix: config_prefix,
        occ: req.transaction.occ,
    };
    let canonical_bytes = build_canonical_message(&spec);

    // ---- auth signature over the SIGNER's canonical bytes
    verify_user_auth_signature(
        &record.auth_pubkey,
        &req.auth_signature.signature,
        &canonical_bytes,
    )?;

    // ---- DISTINCT per-user policy (G79 decision 2: presence + identity +
    //      registered binding enforced AT LOAD; empty list denies below)
    let policy =
        load_user_policy_for(policy_dir, user_id, &record.auth_pubkey).map_err(|e| match e {
            UserPolicyError::MissingForUser => UserDenial::PolicyMissing,
            UserPolicyError::IdentityMismatch => UserDenial::PolicyIdentityMismatch,
            UserPolicyError::RegisteredBindingMismatch => UserDenial::PolicyBindingMismatch,
            UserPolicyError::WildcardRejected => UserDenial::PolicyWildcard,
            UserPolicyError::Malformed => UserDenial::PolicyMalformed,
        })?;
    evaluate_user_policy(
        &policy,
        &req.transaction.recipient,
        req.transaction.amount_kelvin,
        req.transaction.valid_from_ms,
        now_ms,
    )
    .map_err(|_| UserDenial::PolicyDenied)?;

    // ---- the signing act (key stays here; self-verify after)
    let kp = load_user_key(store, user_id).map_err(|_| UserDenial::StoreUnavailable)?;
    let container_address = kp.pubkey().to_string();
    if container_address != record.public_address {
        return Err(UserDenial::PayerMismatch);
    }
    let signature = kp.sign_message(&canonical_bytes);
    let sig_bytes: [u8; 64] = signature.into();
    let self_ok = rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| UserDenial::Internal)?
        .verify(&from, &canonical_bytes);
    if !self_ok {
        return Err(UserDenial::Internal);
    }

    Ok(UserSignResponse {
        user_id: user_id.to_string(),
        canonical_hash: blake3::hash(&canonical_bytes).to_hex().to_string(),
        canonical_message_b64: crate::base64_encode(&canonical_bytes),
        signature_b64: crate::base64_encode(&sig_bytes),
        required_signatures: crate::rialo_canonical::SINGLE_SIGNER_REQUIRED,
    })
}

/// ed25519 verification of the user's funds-less auth signature over the
/// signer's canonical bytes.
fn verify_user_auth_signature(
    auth_pubkey_b58: &str,
    signature_b64: &str,
    canonical_bytes: &[u8],
) -> Result<(), UserDenial> {
    let pk = crate::base58_decode_32(auth_pubkey_b58).ok_or(UserDenial::AuthMalformed)?;
    let sig = crate::base64_decode(signature_b64).ok_or(UserDenial::AuthMalformed)?;
    let s = rialo_s_signature::Signature::try_from(sig.as_slice())
        .map_err(|_| UserDenial::AuthMalformed)?;
    if s.verify(&pk, canonical_bytes) {
        Ok(())
    } else {
        Err(UserDenial::AuthInvalid)
    }
}

// ---------------------------------------------------------------------------
// G81 — NEW-USER WALLET PROVISIONING (create path)
// ---------------------------------------------------------------------------

/// blake3 hex of a byte slice (operator-readable binding tags).
fn g81_hash_hex(parts: &[&[u8]]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_hex().to_string()
}

/// The intro-secret proof bind: creation_record || nonce.
pub const INTRO_SECRET_DOMAIN: &str = "g81-user-create-intro-v1";

/// The ADMIN ceremony proof bind: release || user_id || auth_pubkey.
pub const CEREMONY_SECRET_DOMAIN: &str = "g81-user-create-ceremony-v1";

/// Verify the intro-secret proof WITHOUT the secret traversing the wire or
/// logs (pure hash-compare; constant-time compare over the hex digests).
pub fn verify_intro_secret(crate_secret_env: &str, supplied_proof_hex: &str) -> bool {
    let expected = g81_hash_hex(&[INTRO_SECRET_DOMAIN.as_bytes(), crate_secret_env.as_bytes()]);
    constant_time_eq_hex(&expected, supplied_proof_hex)
}

/// Constant-time comparison over hex strings.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim(), b.trim());
    if a.len() != b.len() {
        return false;
    }
    let (a_b, b_b) = (a.as_bytes(), b.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a_b.iter().zip(b_b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The SERVER-computable ceremony proof (proof-of-possession of the stored
/// recovery envelope secret, WITHOUT reading the envelope bytes):
///   blake3(CEREMONY_SECRET_DOMAIN || canonical_creation_record)
/// where canonical_creation_record = blake3(
///   generation_domain || nonce || generated_privkey)
/// — recoverable ONLY by completing the XOR release with BOTH drafts.
pub fn expected_ceremony_proof(canonical_creation_record: &str) -> String {
    g81_hash_hex(&[
        CEREMONY_SECRET_DOMAIN.as_bytes(),
        canonical_creation_record.as_bytes(),
    ])
}

/// Serialize the recovery PAYLOAD (auth keypair, 64 bytes for the V1
/// container) — the private half STILL never leaves the signer.
fn user_recovery_payload_bytes(auth_keypair: &rialo_s_keypair::Keypair) -> Option<Vec<u8>> {
    let arr: [u8; 64] = auth_keypair.to_bytes();
    serde_json::to_vec(&arr.to_vec()).ok()
}

/// THE CREATE PATH (library surface; the /user/wallet HTTP binding is
/// G81-DEFERRED with the /user/sign wiring, per gate).
///
/// Contract:
///   * `version_env`: the operator's wallet-version declaration (unset ⇒
///     structurally absent, deny).
///   * `create_secret_env`: the generation secret (env-only; compared via
///     hash proof; constant-time; no secret in any error path).
///   * `expected_user_id`: WHO the app session is creating for (the app
///     proves the session user; the signer re-proves via auth signature
///     over the canonical bytes; identity mismatch ⇒ IDENTITY_MISMATCH).
///   * Atomic + idempotent: O_EXCL on the key container; a repeated
///     request with identical identity material returns the SAME wallet
///     (200 with the SAME address — never a second identity).
///   * `recovery_draft_1_hex`: OUT — XOR-draft one of the recovery
///     envelope for the OPERATOR export (write-once file + caller copy).
///
/// NO key material ever appears in the response type. NO mint path exists
/// for the app: the app calls this via the sealed loopback route only.
#[allow(clippy::too_many_arguments)]
pub fn create_user_wallet(
    store: &SignerStore,
    gate: &crate::user_creation_gate::CreationGate,
    version_env: &str,
    create_secret_env: &str,
    intro_proof_hex: &str,
    expected_user_id: u64,
    declared_user_id: u64,
    auth_sig_b64: &str,
    now_unix: i64,
    nonce: &str,
) -> Result<
    (
        crate::user_signer_protocol::UserWalletCreateResponse,
        String, // draft1 hex (operator)
        String, // canonical_creation_record
    ),
    UserDenial,
> {
    // One wallet per user: a stable logical-operation id survives retries
    // and restarts. The explicit variant below accepts an operator-supplied
    // id when the caller has a different logical unit.
    let operation_id = format!("v2-user-wallet:{declared_user_id}");
    create_user_wallet_with_operation(
        store,
        gate,
        version_env,
        create_secret_env,
        intro_proof_hex,
        expected_user_id,
        declared_user_id,
        auth_sig_b64,
        now_unix,
        nonce,
        &operation_id,
    )
}

/// Read the durable public result of a logical create operation without
/// opening or materializing any key material. `None` means no operation
/// journal exists; `InProgress`/corrupt journals fail closed.
pub fn user_wallet_operation_result(
    store: &SignerStore,
    user_id: u64,
    operation_id: &str,
) -> Result<Option<String>, UserDenial> {
    match crate::wallet_file_safety::completed_result(store.root(), user_id, operation_id) {
        Ok(v) => Ok(v),
        Err(crate::wallet_file_safety::SafetyError::Corrupt) => {
            Err(UserDenial::ProvisioningIncomplete)
        }
        Err(crate::wallet_file_safety::SafetyError::BadOperation) => Err(UserDenial::BadRequest),
        Err(_) => Err(UserDenial::ProvisioningInProgress),
    }
}

/// Same contract as `create_user_wallet`, with an explicit stable id for the
/// logical provisioning operation. The id is hashed into the signer journal;
/// it is never written as a raw path component.
#[allow(clippy::too_many_arguments)]
pub fn create_user_wallet_with_operation(
    store: &SignerStore,
    gate: &crate::user_creation_gate::CreationGate,
    version_env: &str,
    create_secret_env: &str,
    intro_proof_hex: &str,
    expected_user_id: u64,
    declared_user_id: u64,
    auth_sig_b64: &str,
    now_unix: i64,
    nonce: &str,
    operation_id: &str,
) -> Result<
    (
        crate::user_signer_protocol::UserWalletCreateResponse,
        String, // draft1 hex (operator)
        String, // canonical_creation_record
    ),
    UserDenial,
> {
    use crate::user_creation_gate::{GateError, registered_user_binding};

    // 0) version gate — the marker decides (fail-closed).
    if version_env.trim() != USER_WALLET_VERSION_V2 {
        return Err(UserDenial::SigningNotEnabled);
    }
    // empty env secret → structurally absent create path (deny)
    if create_secret_env.trim().is_empty() {
        return Err(UserDenial::SigningNotEnabled);
    }
    // 1) the intro-secret proof (constant-time; no secret exposure)
    if !verify_intro_secret(create_secret_env, intro_proof_hex) {
        return Err(UserDenial::AuthInvalid);
    }
    // 2) user identity agreement: declared == expected (the app cannot
    //    create for a different principal than the session user)
    if declared_user_id != expected_user_id {
        return Err(UserDenial::IdentityMismatch);
    }

    // 3) M1 — GATE A: the subject MUST have an operator-registered auth
    //    binding (the lifecycle's established admin-registration pattern);
    //    a subject without one fails closed. The caller-supplied key is
    //    never trusted as identity proof.
    let registered_auth_pubkey =
        registered_user_binding(declared_user_id).ok_or(UserDenial::PrerequisiteMissing)?;

    // 4) M1 — GATE B: the creation-intent Ed25519 signature over the
    //    domain-separated canonical message (subject + version + nonce),
    //    verified against the REGISTERED binding (not caller-supplied).
    let intent_msg = crate::user_signer_protocol::creation_intent_message(declared_user_id, nonce);
    {
        let pk = crate::base58_decode_32(&registered_auth_pubkey)
            .ok_or(UserDenial::PrerequisiteMissing)?;
        let sig = crate::base64_decode(auth_sig_b64).ok_or(UserDenial::AuthMalformed)?;
        let s = rialo_s_signature::Signature::try_from(sig.as_slice())
            .map_err(|_| UserDenial::AuthMalformed)?;
        if !s.verify(&pk, &intent_msg) {
            return Err(UserDenial::AuthInvalid);
        }
    }

    // 5) M2 — operation journal + terminal-state classification BEFORE the
    //    nonce burn. A durable result is returned without opening the key
    //    container; a started journal without a result is IN_PROGRESS; a
    //    partial/corrupt final pair is terminal and never replaced.
    let record_path = user_record_path(store, declared_user_id);
    let key_path = user_key_path(store, declared_user_id);
    let env_path = user_recovery_path(store, declared_user_id);
    use crate::wallet_file_safety as wfs;
    let op_state = wfs::read_operation(store.root(), declared_user_id, operation_id)
        .map_err(|_| UserDenial::ProvisioningIncomplete)?;
    // Legacy compatibility: a pre-existing pair (v1/import) is already
    // terminal. It is never overwritten or reprovisioned. Strict identity
    // validation still applies whenever an operation journal exists.
    if matches!(op_state, wfs::OperationState::Absent)
        && fs::symlink_metadata(&key_path).is_ok()
        && fs::symlink_metadata(&record_path).is_ok()
    {
        return Err(UserDenial::AlreadyExists);
    }
    let files = wfs::inspect_wallet_files(&key_path, &record_path, declared_user_id)
        .map_err(|_| UserDenial::ProvisioningIncomplete)?;
    match op_state {
        wfs::OperationState::Completed {
            public_address: result_address,
            ..
        } => {
            // A completed journal without a complete, matching final pair is
            // evidence of a previous wallet that is now missing/corrupt:
            // never mint a replacement.
            return match files {
                wfs::WalletFiles::Complete {
                    public_address: file_address,
                    ..
                } if file_address == result_address => Err(UserDenial::AlreadyExists),
                _ => Err(UserDenial::ProvisioningIncomplete),
            };
        }
        wfs::OperationState::InProgress => {
            match files {
                wfs::WalletFiles::Complete {
                    public_address,
                    record_sha256,
                } => {
                    // Crash between record and result; publish result only.
                    wfs::complete_operation(
                        store.root(),
                        declared_user_id,
                        operation_id,
                        &public_address,
                        &record_sha256,
                    )
                    .map_err(|_| UserDenial::ProvisioningIncomplete)?;
                    return Err(UserDenial::AlreadyExists);
                }
                wfs::WalletFiles::Incomplete => {
                    return Err(UserDenial::ProvisioningIncomplete)
                }
                wfs::WalletFiles::Missing => {}
            }
            return Err(UserDenial::ProvisioningInProgress);
        }
        wfs::OperationState::Corrupt => return Err(UserDenial::ProvisioningIncomplete),
        wfs::OperationState::Absent => {}
    }
    match files {
        wfs::WalletFiles::Complete {
            public_address,
            record_sha256,
        } => {
            // Crash after the record was published but before the result
            // journal: reconstruct the public result, never mint again.
            wfs::complete_operation(
                store.root(),
                declared_user_id,
                operation_id,
                &public_address,
                &record_sha256,
            )
            .map_err(|_| UserDenial::ProvisioningIncomplete)?;
            return Err(UserDenial::AlreadyExists);
        }
        wfs::WalletFiles::Incomplete => return Err(UserDenial::ProvisioningIncomplete),
        wfs::WalletFiles::Missing => {}
    }

    // 6) M1 — GATE C: durable single-use nonce (replay-protection with
    //    persistence + concurrency semantics: the burn is durable BEFORE
    //    any side effect; from here the nonce is consumed even if a later
    //    persistence step fails — a retried create needs a fresh intent).
    match gate.consume_nonce(declared_user_id, nonce) {
        Ok(()) => {}
        Err(GateError::PersistFailed) => return Err(UserDenial::NonceReplay),
        Err(GateError::NoBinding) => return Err(UserDenial::PrerequisiteMissing),
    }

    // 7) M2 — durable singleflight BEGIN (one create per user process-wide)
    match gate.begin(declared_user_id) {
        Ok(()) => {}
        Err(GateError::PersistFailed) => return Err(UserDenial::ProvisioningInProgress),
        Err(GateError::NoBinding) => return Err(UserDenial::PrerequisiteMissing),
    }
    // 7b) Durable operation journal BEFORE any key material. A concurrent/
    //     restarted process that finds a started marker must not mint; if a
    //     result already exists, publish it and stop.
    match wfs::begin_operation(store.root(), declared_user_id, operation_id) {
        Ok(wfs::OperationState::InProgress) => {}
        Ok(wfs::OperationState::Completed { .. }) => {
            let _ = gate.finish(declared_user_id);
            return Err(UserDenial::AlreadyExists);
        }
        Ok(wfs::OperationState::Absent) | Ok(wfs::OperationState::Corrupt) => {
            return Err(UserDenial::ProvisioningIncomplete);
        }
        Err(_) => return Err(UserDenial::StoreUnavailable),
    }
    // From here to the final record rename, EVERY failure path must leave
    // the in-progress marker in place (the state is authoritative and the
    // typed INCOMPLETE/IN_PROGRESS decision tree re-derives it on retry).

    // 8) MINT: funded keypair (signer-side; getrandom; content-only here)
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| UserDenial::Internal)?;
    let wallet_kp = rialo_s_keypair::keypair_from_seed(&seed).map_err(|_| UserDenial::Internal)?;
    seed.fill(0); // M4: the raw seed never outlives its use
    let user_address = wallet_kp.pubkey().to_string();

    // 9) USER AUTH KEY (funds-less): generated here; its PUBLIC half goes
    //    into the record; the private half is recovered via the envelope.
    let mut auth_seed = [0u8; 32];
    getrandom::getrandom(&mut auth_seed).map_err(|_| UserDenial::Internal)?;
    let auth_kp =
        rialo_s_keypair::keypair_from_seed(&auth_seed).map_err(|_| UserDenial::Internal)?;
    auth_seed.fill(0); // M4

    // 10) the key container: complete temp + fsync + hard_link; link never
    //     replaces an existing final path. No partial bytes are ever visible
    //     under the final name.
    let ns_dir = user_namespace_root(store);
    std::fs::create_dir_all(&ns_dir).map_err(|_| UserDenial::StoreUnavailable)?;
    let mut kp_bytes: [u8; 64] = wallet_kp.to_bytes();
    // Compute the public binding before the key bytes leave scope; it is
    // public data (the same hash the response returns).
    let canonical_creation_record =
        g81_hash_hex(&[b"g81-generation-v1", nonce.as_bytes(), &kp_bytes]);
    let key_container = serde_json::to_vec(&kp_bytes.to_vec()).map_err(|_| UserDenial::Internal)?;
    wfs::write_new_file_no_replace(&key_path, &key_container, 0o600).map_err(|e| match e {
        wfs::SafetyError::AlreadyExists => UserDenial::ProvisioningInProgress,
        _ => UserDenial::StoreUnavailable,
    })?;
    drop(key_container);

    // 11) the RECOVERY ENVELOPE (write-once, XOR of two drafts; payout is
    //     blake3-bound; the AUTH keypair is INSIDE the payload — M3: the
    //     funded key is NOT in the envelope, per the custody decision)
    let gen_secret = g81_hash_hex(&[b"g81-generation-v1", nonce.as_bytes(), &kp_bytes]);
    let mut payload = user_recovery_payload_bytes(&auth_kp).ok_or(UserDenial::Internal)?;
    let payout = blake3::hash(&payload).to_hex().to_string();
    let mut draft1 = vec![0u8; payload.len()];
    getrandom::getrandom(&mut draft1).map_err(|_| UserDenial::Internal)?;
    let mut draft2: Vec<u8> = payload
        .iter()
        .zip(draft1.iter())
        .map(|(p, d)| p ^ d)
        .collect();
    payload.fill(0); // M4: the plaintext recovery payload is folded into the drafts
    // G85 — recovery contract (TWO custodians; no new delivery channel):
    //   draft1 → returned to the CALLER (the operator's export copy; the
    //   pre-existing return contract) — OUT of the signer store.
    //   draft2 → PERSISTED inside the recovery envelope (signer store,
    //   0600) — never crosses the wire. Recovering the auth keypair
    //   requires BOTH holders (operator draft1 + store envelope); losing
    //   either yields garbage → payout-hash mismatch → fail closed.
    let mut draft2_hex = String::with_capacity(draft2.len() * 2);
    for byte in &draft2 {
        use std::fmt::Write as _;
        let _ = write!(draft2_hex, "{byte:02x}");
    }
    draft2.fill(0); // M4: folded into the persisted envelope hex
    let auth_pubkey = {
        use rialo_s_signer::Signer;
        auth_kp.pubkey().to_string()
    };
    let canonical_creation_record =
        g81_hash_hex(&[b"g81-generation-v1", nonce.as_bytes(), &kp_bytes]);
    kp_bytes.fill(0); // M4: never outlive the envelope/record writes
    let env_doc = serde_json::json!({
        "version": 1,
        "wallet_version": 2,
        "user_id": declared_user_id.to_string(),
        "canonical_creation_record": canonical_creation_record,
        "payout_hash": payout,
        // G85: the SECOND XOR draft, persisted in-store (custodian: the
        // signer store). draft1 lives ONLY with the operator (the caller's
        // export copy). payload = draft1 ^ draft2, blake3-verified.
        "release_draft2_hex": draft2_hex,
        "released_auth_pubkey": auth_pubkey,
        "wallet_address": user_address,
    });
    let env_bytes = serde_json::to_vec(&env_doc).map_err(|_| UserDenial::Internal)?;
    wfs::write_new_file_no_replace(&env_path, &env_bytes, 0o600).map_err(|e| match e {
        wfs::SafetyError::AlreadyExists => UserDenial::ProvisioningIncomplete,
        _ => UserDenial::StoreUnavailable,
    })?;

    // 12) the public record (identity binding; 0600) — the LAST write
    //     (its presence is the terminal success marker)
    let auth_pubkey = {
        use rialo_s_signer::Signer;
        auth_kp.pubkey().to_string()
    };
    let record = UserWalletRecord {
        user_id: declared_user_id,
        public_address: user_address.clone(),
        auth_pubkey: auth_pubkey.clone(),
    };
    let record_bytes =
        serde_json::to_vec(&record).map_err(|_| UserDenial::Internal)?;
    let record_sha256 = blake3::hash(&record_bytes).to_hex().to_string();
    wfs::write_new_file_no_replace(&record_path, &record_bytes, 0o600).map_err(|e| match e {
        wfs::SafetyError::AlreadyExists => UserDenial::ProvisioningIncomplete,
        _ => UserDenial::StoreUnavailable,
    })?;

    // 13) terminal success — durable PUBLIC result first, then clear the
    //     in-progress marker. A crash before the result still leaves a
    //     complete final pair; the next call reconstructs the result without
    //     opening the key container.
    wfs::complete_operation(
        store.root(),
        declared_user_id,
        operation_id,
        &user_address,
        &record_sha256,
    )
    .map_err(|_| UserDenial::StoreUnavailable)?;
    let _ = gate.finish(declared_user_id);

    // draft1 hex (operator export copy)
    let mut draft1_hex = String::with_capacity(draft1.len() * 2);
    for byte in &draft1 {
        use std::fmt::Write as _;
        let _ = write!(draft1_hex, "{byte:02x}");
    }

    Ok((
        crate::user_signer_protocol::UserWalletCreateResponse {
            user_id: declared_user_id.to_string(),
            public_address: user_address,
            wallet_version: 2,
            recovery_envelope_stored: true,
        },
        draft1_hex,
        canonical_creation_record,
    ))
}

/// The recovery-envelope path (next to the key/record in the namespace).
pub fn user_recovery_path(store: &SignerStore, user_id: u64) -> std::path::PathBuf {
    user_namespace_root(store).join(format!("{user_id}.recovery.json"))
}

/// The canonical creation record for the ceremony — read from the PERSISTED
/// recovery envelope (the durable authority; recomputing from mutable
/// store files would let a tampered key file redefine the record).
pub fn creation_record_hash(store: &SignerStore, user_id: u64) -> Result<String, ()> {
    let env = load_recovery_envelope(store, user_id).map_err(|_| ())?;
    Ok(env.canonical_creation_record)
}

// ---------------------------------------------------------------------------
// G85 — RECOVERY OF THE USER AUTH KEYPAIR (operator-only library primitive;
// no HTTP route; the funded key is NEVER part of this flow)
// ---------------------------------------------------------------------------
//
// Custody contract (post-G85):
//   * draft1  — held by the OPERATOR (the create-path caller's export
//               copy; never persisted by the signer).
//   * draft2  — held INSIDE the recovery envelope (signer store, 0600);
//               never crosses the wire.
//   * payload = draft1 XOR draft2 = the 64-byte JSON auth-keypair
//               container; blake3-checked against `payout_hash`.
//
// Recovery therefore requires BOTH custodians. Losing either component
// yields garbage → the payout-hash check fails → fail closed. The bind
// tuple (user_id, wallet_version, canonical_creation_record) is verified
// BEFORE any payload byte is accepted, so material from another user, a
// foreign wallet version, or a stale creation cannot be replayed.

/// The parsed, integrity-checked recovery envelope (public fields only).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryEnvelope {
    pub version: u8,
    pub wallet_version: u8,
    pub user_id: String,
    pub canonical_creation_record: String,
    pub payout_hash: String,
    pub release_draft2_hex: String,
    pub released_auth_pubkey: String,
    pub wallet_address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryError {
    /// envelope missing/unparsable/wrong shape
    EnvelopeInvalid,
    /// the bind tuple does not match the requested identity/wallet version
    BindMismatch,
    /// drafts missing or unequal length
    DraftsInvalid,
    /// XOR yield failed the payout-hash integrity check
    IntegrityFailed,
    /// the recovered public key ≠ the envelope's registered auth pubkey
    KeyMismatch,
    /// the recovered container cannot be parsed as a strict keypair
    KeyInvalid,
}

/// Load and structurally validate the persisted recovery envelope.
pub fn load_recovery_envelope(
    store: &SignerStore,
    user_id: u64,
) -> Result<RecoveryEnvelope, RecoveryError> {
    let bytes = std::fs::read(user_recovery_path(store, user_id))
        .map_err(|_| RecoveryError::EnvelopeInvalid)?;
    let env: RecoveryEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| RecoveryError::EnvelopeInvalid)?;
    // strict field validation (no empty/None-yet-valid states tolerated)
    if env.version != 1
        || env.wallet_version != 2
        || env.user_id.is_empty()
        || env.payout_hash.len() != 64
        || env.release_draft2_hex.is_empty()
        || env.released_auth_pubkey.is_empty()
        || env.wallet_address.is_empty()
    {
        return Err(RecoveryError::EnvelopeInvalid);
    }
    Ok(env)
}

/// AUTHORIZED recovery of the user auth keypair (operator-only; the
/// funded key is NOT recoverable through this function and never leaves
/// the signer store).
///
/// * `operator_draft1_hex` — the operator's held draft1 export (returned
///   by `create_user_wallet` at creation; stored OUTSIDE the signer).
/// * `expected_creation_record` — recomputed by the caller from the
///   signer-owned artifacts (`creation_record_hash`) or from operator
///   records; binds the recovery to THIS creation (identity + version +
///   nonce + funded key) and blocks stale/foreign envelopes.
///
/// Returns the recovered auth PUBLIC key (the private half is returned
/// ONLY inside the strict container bytes, to the in-process caller —
/// this function is an in-crate operator primitive, not a wire type).
pub fn recover_user_auth_key(
    store: &SignerStore,
    user_id: u64,
    expected_wallet_version: u8,
    expected_creation_record: &str,
    operator_draft1_hex: &str,
) -> Result<(String, rialo_s_keypair::Keypair), RecoveryError> {
    let env = load_recovery_envelope(store, user_id)?;

    // bind 1: envelope identity + wallet version
    let env_user: u64 = env
        .user_id
        .parse()
        .map_err(|_| RecoveryError::BindMismatch)?;
    if env_user != user_id || env.wallet_version != expected_wallet_version {
        return Err(RecoveryError::BindMismatch);
    }
    // bind 2: the canonical creation record — a stale/foreign envelope
    // (different creation) is refused even if its own hashes are intact
    if env.canonical_creation_record != expected_creation_record {
        return Err(RecoveryError::BindMismatch);
    }

    // drafts: operator draft1 (arg) XOR envelope draft2 (store)
    let d2 = _g85_hex::decode_hex(&env.release_draft2_hex).ok_or(RecoveryError::DraftsInvalid)?;
    let d1 = _g85_hex::decode_hex(operator_draft1_hex).ok_or(RecoveryError::DraftsInvalid)?;
    if d1.len() != d2.len() {
        return Err(RecoveryError::DraftsInvalid);
    }
    let mut payload: Vec<u8> = d1.iter().zip(d2.iter()).map(|(a, b)| a ^ b).collect();

    // integrity: the yield must hash to the recorded payout
    let payout = blake3::hash(&payload).to_hex().to_string();
    if !constant_time_eq_hex(&payout, &env.payout_hash) {
        payload.fill(0);
        return Err(RecoveryError::IntegrityFailed);
    }

    // structural strict parse of the recovered V1 container
    let arr: Vec<u8> = serde_json::from_slice(&payload).map_err(|_| {
        payload.fill(0);
        RecoveryError::KeyInvalid
    })?;
    if arr.len() != 64 {
        payload.fill(0);
        return Err(RecoveryError::KeyInvalid);
    }
    let kp = rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|_| {
        payload.fill(0);
        RecoveryError::KeyInvalid
    })?;
    payload.fill(0); // M4: the plaintext payload never outlives the parse

    // binding: the recovered public half MUST equal the envelope's
    // registered auth pubkey (and therefore the wallet record's linkage)
    {
        use rialo_s_signer::Signer;
        if kp.pubkey().to_string() != env.released_auth_pubkey {
            return Err(RecoveryError::KeyMismatch);
        }
    }
    Ok((env.released_auth_pubkey.clone(), kp))
}

/// Minimal constant-time hex decode (lower/upper both accepted; length
/// must be even; non-hex bytes fail closed).
pub mod _g85_hex {
    pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
        let s = s.trim();
        if s.is_empty() || s.len() % 2 != 0 {
            return None;
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(s.len() / 2);
        let val = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        for pair in bytes.chunks(2) {
            let hi = val(pair[0])?;
            let lo = val(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// G87 — WIRE→LIBRARY CONTRACT for POST /user/wallet (the route's handler
// body; the route itself lives in main.rs). The admin secret is checked
// HERE (constant-time, never logged); the intro proof + subject signature
// + nonce are the request's own ceremony fields.
// ---------------------------------------------------------------------------

/// Handle a POST /user/wallet request body. Returns the PUBLIC response,
/// the operator's draft1 export, and the canonical creation record. The
/// funded key, seed, and draft2 NEVER appear in these outputs (draft2 is
/// inside the persisted envelope only).
///
/// `admin_secret`: the runtime value of AGENTPAY_SIGNER_ADMIN_SECRET —
/// supplied by the route layer, compared constant-time here. An empty or
/// missing value ⇒ the route structurally cannot create (deny).
pub fn handle_user_wallet_create(
    store: &SignerStore,
    body: &[u8],
    admin_secret: &str,
) -> Result<
    (
        crate::user_signer_protocol::UserWalletCreateResponse,
        String, // draft1 hex (operator export)
        String, // canonical_creation_record
    ),
    UserDenial,
> {
    use crate::user_signer_protocol::UserWalletCreateRequest;

    // 0) the version gate (marker env; unset ⇒ structurally absent)
    let version_env = std::env::var(USER_WALLET_VERSION_ENV).unwrap_or_default();
    // 1) the generation secret (env-only)
    let create_secret_env = std::env::var(USER_CREATE_SECRET_ENV).unwrap_or_default();
    // 2) the durable gate (nonce burn + singleflight) — same dir discipline
    //    as the intents ledger; the SIGNER owns this directory.
    let gate_dir = store.root().join("creation_gate");
    let gate = crate::user_creation_gate::CreationGate::open(&gate_dir)
        .map_err(|_| UserDenial::StoreUnavailable)?;

    // 3) strict typed parse (deny unknown fields; bounded body upstream)
    let req: UserWalletCreateRequest =
        serde_json::from_slice(body).map_err(|_| UserDenial::BadRequest)?;
    if req.channel_nonce.trim().is_empty() {
        return Err(UserDenial::BadRequest);
    }

    // 4) caller identity agreement: body user_id ≡ auth_signature user_id
    if req.user_id != req.auth_signature.pubkey.user_id {
        return Err(UserDenial::IdentityMismatch);
    }
    let declared_user_id: u64 = req.user_id.parse().map_err(|_| UserDenial::BadRequest)?;

    // 5) admin ceremony gate (constant-time; the same admin secret discipline
    //    as /admin/register — an operator-held secret, never in URLs/logs).
    //    G89: INDEPENDENT from the intro gate (distinct hash domains; one
    //    field per proof — the old single-field contract was unsatisfiable).
    let ceremony_proof = {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(CEREMONY_SECRET_DOMAIN.as_bytes());
        h.update(admin_secret.as_bytes());
        h.finalize().to_hex().to_string()
    };
    if !constant_time_eq_hex(&ceremony_proof, &req.admin_ceremony_proof) {
        return Err(UserDenial::AuthInvalid);
    }

    // 6) THE CREATE CHAIN (all M1/M2 gates inside; expected == declared —
    //    the route layer derived BOTH from the authenticated context)
    let intro_proof_hex = req.intro_proof;
    if !verify_intro_secret(&create_secret_env, &intro_proof_hex) {
        return Err(UserDenial::AuthInvalid);
    }

    // 7) the Ed25519 creation-intent signature — the subject signs
    //    creation_intent_message(user_id, nonce) with the REGISTERED key.
    //    handle_user_wallet_create verifies it inside create_user_wallet
    //    via registered_user_binding; the request's auth_signature carries it.
    create_user_wallet(
        store,
        &gate,
        &version_env,
        &create_secret_env,
        &intro_proof_hex,
        declared_user_id, // expected (from the wire contract's subject)
        declared_user_id, // declared (same — mismatch check retained inside)
        &req.auth_signature.signature,
        0, // now_unix is derived inside the gate writes
        &req.channel_nonce,
    )
}
