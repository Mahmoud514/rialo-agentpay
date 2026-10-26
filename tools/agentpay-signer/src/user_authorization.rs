//! G108 — D1 identity-proof and D8 operator-authorization primitives.
//!
//! This module is deliberately **not wired** into any route or lifecycle
//! mutation. It provides:
//!   * a fail-closed identity-verification adapter boundary (D1),
//!   * canonical, domain-separated enrollment possession proofs (D1),
//!   * Ed25519 operator authorizations over a versioned payload (D8),
//!   * a provisioned operator trust-store boundary (D8),
//!   * an atomic replay-store boundary and a fail-closed audit-sink boundary.
//!
//! The only implementations shipped here are **deny-all** adapters. Real
//! identity providers, provisioned operator keys, durable replay state and
//! durable audit storage must be supplied by an approved deployment step.
//! Until then every verification attempt fails closed: no enrollment, rotation
//! or revocation can be authorized through this module.
//!
//! Invariants:
//!   * no private key material is accepted, stored, logged or returned;
//!   * error values are fieldless (no keys, signatures, evidence or nonces);
//!   * replay/trust/audit unavailability is a denial, never a bypass;
//!   * canonical bytes are length-prefixed and domain-separated.

use std::collections::HashSet;

use base64::Engine as _;
use rialo_s_signature::Signature;
use serde::Serialize;

const AUTHZ_DOMAIN: &[u8] = b"AGENTPAY-OPERATOR-AUTH-v1\x00";
const ENROLL_DOMAIN: &[u8] = b"AGENTPAY-USER-ENROLL-v1\x00";
const ROTATE_DOMAIN: &[u8] = b"AGENTPAY-USER-ROTATE-v1\x00";
const KEY_FP_DOMAIN: &[u8] = b"AGENTPAY-AUTH-KEY-FP-v1\x00";

/// Supported authorization/enrollment schema version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Supported policy version (threshold semantics).
pub const POLICY_VERSION_ONE: u16 = 1;
/// A single-person approval policy.
pub const THRESHOLD_ONE: u8 = 1;
/// A two-person approval policy (distinct operator keys required).
pub const THRESHOLD_TWO: u8 = 2;
/// Maximum accepted authorization lifetime, seconds.
pub const MAX_AUTHZ_LIFETIME_SECS: u64 = 600;
/// Maximum accepted clock skew for `issued_at`, seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
/// Maximum operator approvals accepted in one payload.
pub const MAX_OPERATORS: usize = 8;

/// Fieldless authorization failure. Never carries key/signature material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzError {
    Malformed,
    UnsupportedVersion,
    PolicyMismatch,
    NotYetValid,
    Expired,
    InsufficientApprovals,
    DuplicateOperator,
    UnknownOperator,
    RevokedOperator,
    InvalidSignature,
    Replay,
    StoreUnavailable,
    AuditUnavailable,
    UnauthorizedOperation,
}

/// Fieldless enrollment failure. Never carries key/signature material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    Malformed,
    UnsupportedVersion,
    NotYetValid,
    Expired,
    IdentityUnavailable,
    IdentityInvalid,
    IdentityMismatch,
    KeyMismatch,
    InvalidPossessionProof,
    Replay,
    StoreUnavailable,
}

/// Identity-provider adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    Unavailable,
    Invalid,
    Expired,
    Mismatch,
}

/// Trust-store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStoreError {
    Unavailable,
}

/// Replay-store failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    Replay,
    Unavailable,
}

/// Audit-sink failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    Unavailable,
}

/// D1 — the operation a user is authorizing (also used by D8 payloads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOperation {
    Enroll,
    Rotate,
    Revoke,
    Migrate,
}

impl LifecycleOperation {
    fn code(self) -> u8 {
        match self {
            Self::Enroll => 1,
            Self::Rotate => 2,
            Self::Revoke => 3,
            Self::Migrate => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enroll => "enroll",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
            Self::Migrate => "migrate",
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

struct CanonicalWriter {
    out: Vec<u8>,
}

impl CanonicalWriter {
    fn new(domain: &[u8]) -> Self {
        Self {
            out: domain.to_vec(),
        }
    }

    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_be_bytes());
    }

    fn bytes(&mut self, b: &[u8]) -> Result<(), ()> {
        if b.len() > u32::MAX as usize {
            return Err(());
        }
        self.u32(b.len() as u32);
        self.out.extend_from_slice(b);
        Ok(())
    }

    fn string(&mut self, s: &str) -> Result<(), ()> {
        self.bytes(s.as_bytes())
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control())
}

fn valid_fingerprint(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, ()> {
    if s.is_empty() || s.len() > 4096 {
        return Err(());
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ())
}

/// Decode a 32-byte Ed25519 public key from standard base64.
pub fn decode_auth_pubkey(pubkey_b64: &str) -> Result<[u8; 32], AuthzError> {
    let bytes = decode_b64(pubkey_b64).map_err(|_| AuthzError::Malformed)?;
    bytes.try_into().map_err(|_| AuthzError::Malformed)
}

/// Domain-separated fingerprint of a 32-byte authentication public key.
pub fn auth_key_fingerprint(pubkey: &[u8]) -> Result<String, AuthzError> {
    if pubkey.len() != 32 {
        return Err(AuthzError::Malformed);
    }
    let mut h = blake3::Hasher::new();
    h.update(KEY_FP_DOMAIN);
    h.update(pubkey);
    Ok(h.finalize().to_hex().to_string())
}

// ---------------------------------------------------------------------------
// D8 — operator authorization payload
// ---------------------------------------------------------------------------

/// Versioned, canonical operator authorization payload.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationPayload {
    pub version: u16,
    pub policy_version: u16,
    pub request_id: String,
    pub nonce: String,
    pub operation: LifecycleOperation,
    pub user_id: u64,
    pub generation: u64,
    pub current_key_fingerprint: String,
    pub new_key_fingerprint: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub threshold: u8,
    pub operator_ids: Vec<String>,
}

impl AuthorizationPayload {
    fn validate(&self) -> Result<(), AuthzError> {
        if self.version != PROTOCOL_VERSION || self.policy_version != POLICY_VERSION_ONE {
            return Err(AuthzError::UnsupportedVersion);
        }
        if !valid_id(&self.request_id) || !valid_id(&self.nonce) {
            return Err(AuthzError::Malformed);
        }
        if self.user_id == 0 || self.generation == 0 {
            return Err(AuthzError::Malformed);
        }
        if self.threshold != THRESHOLD_ONE && self.threshold != THRESHOLD_TWO {
            return Err(AuthzError::PolicyMismatch);
        }
        if self.operator_ids.is_empty()
            || self.operator_ids.len() > MAX_OPERATORS
            || self.threshold as usize > self.operator_ids.len()
        {
            return Err(AuthzError::InsufficientApprovals);
        }
        let mut sorted = self.operator_ids.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != self.operator_ids {
            return Err(AuthzError::DuplicateOperator);
        }
        let mut seen = HashSet::new();
        for id in &self.operator_ids {
            if !valid_id(id) || !seen.insert(id.as_str()) {
                return Err(AuthzError::DuplicateOperator);
            }
        }
        match self.operation {
            LifecycleOperation::Enroll | LifecycleOperation::Migrate => {
                if self.generation != 1
                    || !self.current_key_fingerprint.is_empty()
                    || !valid_fingerprint(&self.new_key_fingerprint)
                {
                    return Err(AuthzError::Malformed);
                }
            }
            LifecycleOperation::Rotate => {
                if self.generation < 2
                    || !valid_fingerprint(&self.current_key_fingerprint)
                    || !valid_fingerprint(&self.new_key_fingerprint)
                    || self.current_key_fingerprint == self.new_key_fingerprint
                {
                    return Err(AuthzError::Malformed);
                }
            }
            LifecycleOperation::Revoke => {
                if !valid_fingerprint(&self.current_key_fingerprint) {
                    return Err(AuthzError::Malformed);
                }
                if !self.new_key_fingerprint.is_empty() {
                    return Err(AuthzError::Malformed);
                }
            }
        }
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(AuthzError::Malformed);
        }
        if self.expires_at - self.issued_at > MAX_AUTHZ_LIFETIME_SECS {
            return Err(AuthzError::PolicyMismatch);
        }
        Ok(())
    }

    /// Canonical, domain-separated bytes every operator signs.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthzError> {
        self.validate()?;
        let mut w = CanonicalWriter::new(AUTHZ_DOMAIN);
        w.u16(self.version);
        w.u16(self.policy_version);
        w.string(&self.request_id)
            .map_err(|_| AuthzError::Malformed)?;
        w.string(&self.nonce).map_err(|_| AuthzError::Malformed)?;
        w.u8(self.operation.code());
        w.u64(self.user_id);
        w.u64(self.generation);
        w.string(&self.current_key_fingerprint)
            .map_err(|_| AuthzError::Malformed)?;
        w.string(&self.new_key_fingerprint)
            .map_err(|_| AuthzError::Malformed)?;
        w.u64(self.issued_at);
        w.u64(self.expires_at);
        w.u8(self.threshold);
        w.u16(self.operator_ids.len() as u16);
        for id in &self.operator_ids {
            w.string(id).map_err(|_| AuthzError::Malformed)?;
        }
        Ok(w.finish())
    }
}

/// One operator's Ed25519 signature over an authorization payload.
#[derive(Clone, PartialEq, Eq)]
pub struct OperatorSignature {
    pub operator_id: String,
    pub signature_b64: String,
}

/// A provisioned operator identity. `active=false` is a revoked key.
#[derive(Clone, PartialEq, Eq)]
pub struct OperatorRecord {
    pub operator_id: String,
    pub role: String,
    pub public_key_b64: String,
    pub active: bool,
    pub allowed_operations: Vec<LifecycleOperation>,
}

impl OperatorRecord {
    pub fn operator(operator_id: impl Into<String>, public_key_b64: impl Into<String>) -> Self {
        Self {
            operator_id: operator_id.into(),
            role: "operator".to_string(),
            public_key_b64: public_key_b64.into(),
            active: true,
            allowed_operations: vec![
                LifecycleOperation::Enroll,
                LifecycleOperation::Rotate,
                LifecycleOperation::Revoke,
            ],
        }
    }

    pub fn admin(operator_id: impl Into<String>, public_key_b64: impl Into<String>) -> Self {
        Self {
            operator_id: operator_id.into(),
            role: "admin".to_string(),
            public_key_b64: public_key_b64.into(),
            active: true,
            allowed_operations: vec![
                LifecycleOperation::Enroll,
                LifecycleOperation::Rotate,
                LifecycleOperation::Revoke,
            ],
        }
    }

    pub fn with_operations(mut self, operations: Vec<LifecycleOperation>) -> Self {
        self.allowed_operations = operations;
        self
    }

    pub fn revoked(mut self) -> Self {
        self.active = false;
        self
    }

    fn allows(&self, operation: LifecycleOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }
}

/// D8 trust-store boundary. Implementations must be explicitly provisioned.
pub trait OperatorTrustStore {
    fn lookup(&self, operator_id: &str) -> Result<Option<OperatorRecord>, TrustStoreError>;
}

impl<T: OperatorTrustStore + ?Sized> OperatorTrustStore for &T {
    fn lookup(&self, operator_id: &str) -> Result<Option<OperatorRecord>, TrustStoreError> {
        (**self).lookup(operator_id)
    }
}

/// Default-deny trust store: no operator is ever known.
pub struct DenyAllTrustStore;

impl OperatorTrustStore for DenyAllTrustStore {
    fn lookup(&self, _operator_id: &str) -> Result<Option<OperatorRecord>, TrustStoreError> {
        Err(TrustStoreError::Unavailable)
    }
}

/// Scope for replay uniqueness: a request id/nonce is unique per user and
/// operation. This prevents cross-user or cross-operation collisions while
/// still rejecting reuse within the same lifecycle scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayScope {
    pub user_id: u64,
    pub operation: LifecycleOperation,
}

/// Atomic replay boundary. Implementations must reject a reused request id
/// **or** nonce within the same `ReplayScope`, and must be durable before the
/// lifecycle mutation commits.
pub trait ReplayStore {
    fn consume(
        &self,
        scope: ReplayScope,
        request_id: &str,
        nonce: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), ReplayError>;
}

impl<T: ReplayStore + ?Sized> ReplayStore for &T {
    fn consume(
        &self,
        scope: ReplayScope,
        request_id: &str,
        nonce: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), ReplayError> {
        (**self).consume(scope, request_id, nonce, now, expires_at)
    }
}

/// Default-deny replay store: no request can be consumed.
pub struct DenyAllReplayStore;

impl ReplayStore for DenyAllReplayStore {
    fn consume(
        &self,
        _scope: ReplayScope,
        _request_id: &str,
        _nonce: &str,
        _now: u64,
        _expires_at: u64,
    ) -> Result<(), ReplayError> {
        Err(ReplayError::Unavailable)
    }
}

/// Successful D8 authorization. Contains only public identifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationOutcome {
    pub request_id: String,
    pub policy_version: u16,
    pub approved_by: Vec<String>,
    pub approved_key_fingerprints: Vec<String>,
}

/// D8 verifier. It is a pure check: it never mutates wallet state.
pub struct AuthorizationVerifier<S: OperatorTrustStore, R: ReplayStore> {
    store: S,
    replay: R,
}

impl<S: OperatorTrustStore, R: ReplayStore> AuthorizationVerifier<S, R> {
    pub fn new(store: S, replay: R) -> Self {
        Self { store, replay }
    }

    pub fn verify(
        &self,
        payload: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        now: u64,
    ) -> Result<AuthorizationOutcome, AuthzError> {
        let canonical = payload.canonical_bytes()?;

        if payload.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(AuthzError::NotYetValid);
        }
        if now >= payload.expires_at {
            return Err(AuthzError::Expired);
        }
        if signatures.len() < payload.threshold as usize {
            return Err(AuthzError::InsufficientApprovals);
        }

        let mut seen_ids = HashSet::new();
        let mut seen_keys = HashSet::new();
        let mut approved = Vec::new();
        let mut approved_fingerprints = Vec::new();

        for sig in signatures {
            if !valid_id(&sig.operator_id) || !seen_ids.insert(sig.operator_id.as_str()) {
                return Err(AuthzError::DuplicateOperator);
            }
            if !payload.operator_ids.iter().any(|id| id == &sig.operator_id) {
                return Err(AuthzError::UnknownOperator);
            }
            let record = self
                .store
                .lookup(&sig.operator_id)
                .map_err(|_| AuthzError::StoreUnavailable)?
                .ok_or(AuthzError::UnknownOperator)?;
            if record.operator_id != sig.operator_id {
                return Err(AuthzError::UnknownOperator);
            }
            if !record.active {
                return Err(AuthzError::RevokedOperator);
            }
            if record.role != "operator" && record.role != "admin" {
                return Err(AuthzError::PolicyMismatch);
            }
            if !record.allows(payload.operation) {
                return Err(AuthzError::UnauthorizedOperation);
            }
            let pubkey = decode_b64(&record.public_key_b64).map_err(|_| AuthzError::Malformed)?;
            if pubkey.len() != 32 {
                return Err(AuthzError::Malformed);
            }
            if !seen_keys.insert(pubkey.clone()) {
                return Err(AuthzError::DuplicateOperator);
            }
            approved_fingerprints
                .push(auth_key_fingerprint(&pubkey).map_err(|_| AuthzError::Malformed)?);
            let sig_bytes = decode_b64(&sig.signature_b64).map_err(|_| AuthzError::Malformed)?;
            let signature =
                Signature::try_from(sig_bytes.as_slice()).map_err(|_| AuthzError::Malformed)?;
            if !signature.verify(&pubkey, &canonical) {
                return Err(AuthzError::InvalidSignature);
            }
            approved.push(sig.operator_id.clone());
        }

        if payload.threshold == THRESHOLD_TWO && seen_keys.len() < 2 {
            return Err(AuthzError::InsufficientApprovals);
        }

        // Replay is consumed only after every cryptographic check succeeded.
        self.replay
            .consume(
                ReplayScope {
                    user_id: payload.user_id,
                    operation: payload.operation,
                },
                &payload.request_id,
                &payload.nonce,
                now,
                payload.expires_at,
            )
            .map_err(|e| match e {
                ReplayError::Replay => AuthzError::Replay,
                ReplayError::Unavailable => AuthzError::StoreUnavailable,
            })?;

        approved.sort();
        approved_fingerprints.sort();
        Ok(AuthorizationOutcome {
            request_id: payload.request_id.clone(),
            policy_version: payload.policy_version,
            approved_by: approved,
            approved_key_fingerprints: approved_fingerprints,
        })
    }
}

// ---------------------------------------------------------------------------
// G109 — coherent authorization + audit pipeline (NOT WIRED)
// ---------------------------------------------------------------------------

/// Fieldless lifecycle-authorization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleAuthorizationError {
    Authorization(AuthzError),
    AuditUnavailable,
}

/// A narrow, non-mutating integration point: verify D8 authorization, consume
/// replay, then persist a redacted audit event. It does not create, rotate or
/// revoke any wallet state and is not called by any route. A sensitive
/// lifecycle mutation must abort when this returns `AuditUnavailable`.
pub struct LifecycleAuthorizer<S: OperatorTrustStore, R: ReplayStore, A: AuditSink> {
    verifier: AuthorizationVerifier<S, R>,
    audit: A,
}

impl<S: OperatorTrustStore, R: ReplayStore, A: AuditSink> LifecycleAuthorizer<S, R, A> {
    pub fn new(store: S, replay: R, audit: A) -> Self {
        Self {
            verifier: AuthorizationVerifier::new(store, replay),
            audit,
        }
    }

    pub fn authorize(
        &self,
        payload: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        now: u64,
    ) -> Result<AuthorizationOutcome, LifecycleAuthorizationError> {
        let outcome = self
            .verifier
            .verify(payload, signatures, now)
            .map_err(LifecycleAuthorizationError::Authorization)?;
        let event = AuditEvent {
            kind: "lifecycle_authorization",
            outcome: "allowed",
            policy_version: payload.policy_version,
            request_id: outcome.request_id.clone(),
            user_id: payload.user_id,
            generation: payload.generation,
            operation: payload.operation.as_str(),
            approved_by: outcome.approved_by.clone(),
            operator_key_fingerprints: outcome.approved_key_fingerprints.clone(),
            at: now,
        };
        self.audit
            .record(&event)
            .map_err(|_| LifecycleAuthorizationError::AuditUnavailable)?;
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------
// D1 — identity adapter + enrollment proof of possession
// ---------------------------------------------------------------------------

/// Opaque identity assertion produced by the configured adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    pub provider: String,
    pub subject: String,
    pub evidence_b64: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

/// Identity returned by a *successful* adapter verification.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub user_id: u64,
    pub provider: String,
    pub subject: String,
}

/// D1 identity-verification adapter boundary. The default is deny-all.
pub trait IdentityProvider {
    fn verify(
        &self,
        assertion: &IdentityAssertion,
        expected_user_id: u64,
        now: u64,
    ) -> Result<VerifiedIdentity, IdentityError>;
}

impl<T: IdentityProvider + ?Sized> IdentityProvider for &T {
    fn verify(
        &self,
        assertion: &IdentityAssertion,
        expected_user_id: u64,
        now: u64,
    ) -> Result<VerifiedIdentity, IdentityError> {
        (**self).verify(assertion, expected_user_id, now)
    }
}

/// Default-deny identity adapter: no identity provider is connected.
pub struct DenyAllIdentityProvider;

impl IdentityProvider for DenyAllIdentityProvider {
    fn verify(
        &self,
        _assertion: &IdentityAssertion,
        _expected_user_id: u64,
        _now: u64,
    ) -> Result<VerifiedIdentity, IdentityError> {
        Err(IdentityError::Unavailable)
    }
}

/// D1 enrollment request. The possession proof covers only public values.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub version: u16,
    pub user_id: u64,
    pub auth_pubkey_b64: String,
    pub key_fingerprint: String,
    pub request_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub identity: IdentityAssertion,
    pub possession_signature_b64: String,
}

impl EnrollmentRequest {
    fn validate(&self) -> Result<[u8; 32], EnrollmentError> {
        if self.version != PROTOCOL_VERSION {
            return Err(EnrollmentError::UnsupportedVersion);
        }
        if self.user_id == 0
            || !valid_id(&self.request_id)
            || !valid_id(&self.nonce)
            || !valid_fingerprint(&self.key_fingerprint)
            || !valid_id(&self.identity.provider)
            || !valid_id(&self.identity.subject)
        {
            return Err(EnrollmentError::Malformed);
        }
        if self.identity.evidence_b64.is_empty() {
            return Err(EnrollmentError::Malformed);
        }
        let pubkey =
            decode_auth_pubkey(&self.auth_pubkey_b64).map_err(|_| EnrollmentError::Malformed)?;
        let expected = auth_key_fingerprint(&pubkey).map_err(|_| EnrollmentError::Malformed)?;
        if expected != self.key_fingerprint {
            return Err(EnrollmentError::KeyMismatch);
        }
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(EnrollmentError::Malformed);
        }
        if self.expires_at - self.issued_at > MAX_AUTHZ_LIFETIME_SECS {
            return Err(EnrollmentError::Malformed);
        }
        Ok(pubkey)
    }

    /// Canonical bytes the user's authentication key signs for enrollment.
    pub fn possession_bytes(&self) -> Result<Vec<u8>, EnrollmentError> {
        self.possession_bytes_for(LifecycleOperation::Enroll)
    }

    /// Canonical possession bytes for a lifecycle operation. Enrollment and
    /// rotation use different domains; revocation requires no possession proof.
    pub fn possession_bytes_for(
        &self,
        operation: LifecycleOperation,
    ) -> Result<Vec<u8>, EnrollmentError> {
        self.validate()?;
        let domain = match operation {
            LifecycleOperation::Enroll => ENROLL_DOMAIN,
            LifecycleOperation::Rotate => ROTATE_DOMAIN,
            LifecycleOperation::Revoke | LifecycleOperation::Migrate => {
                return Err(EnrollmentError::Malformed);
            }
        };
        let mut w = CanonicalWriter::new(domain);
        w.u16(self.version);
        w.u64(self.user_id);
        w.string(&self.auth_pubkey_b64)
            .map_err(|_| EnrollmentError::Malformed)?;
        w.string(&self.key_fingerprint)
            .map_err(|_| EnrollmentError::Malformed)?;
        w.string(&self.request_id)
            .map_err(|_| EnrollmentError::Malformed)?;
        w.string(&self.nonce)
            .map_err(|_| EnrollmentError::Malformed)?;
        w.u64(self.issued_at);
        w.u64(self.expires_at);
        w.string(&self.identity.provider)
            .map_err(|_| EnrollmentError::Malformed)?;
        w.string(&self.identity.subject)
            .map_err(|_| EnrollmentError::Malformed)?;
        Ok(w.finish())
    }
}

/// Successful D1 verification. No private material is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnrollment {
    pub user_id: u64,
    pub auth_pubkey_b64: String,
    pub key_fingerprint: String,
    pub identity_provider: String,
    pub identity_subject: String,
    pub generation: u64,
}

/// D1 verifier. It is a pure check: it never creates wallet state.
pub struct EnrollmentVerifier<I: IdentityProvider, R: ReplayStore> {
    identity: I,
    replay: R,
}

impl<I: IdentityProvider, R: ReplayStore> EnrollmentVerifier<I, R> {
    pub fn new(identity: I, replay: R) -> Self {
        Self { identity, replay }
    }

    pub fn verify(
        &self,
        req: &EnrollmentRequest,
        now: u64,
    ) -> Result<VerifiedEnrollment, EnrollmentError> {
        self.verify_for_operation(req, now, LifecycleOperation::Enroll)
    }

    /// Verify identity + possession for an enrollment or rotation proof.
    /// Replay is scoped to the actual operation so an enrollment proof id
    /// cannot collide with an operator authorization id in the same scope.
    pub fn verify_for_operation(
        &self,
        req: &EnrollmentRequest,
        now: u64,
        operation: LifecycleOperation,
    ) -> Result<VerifiedEnrollment, EnrollmentError> {
        if matches!(
            operation,
            LifecycleOperation::Revoke | LifecycleOperation::Migrate
        ) {
            return Err(EnrollmentError::Malformed);
        }
        let pubkey = req.validate()?;
        if req.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(EnrollmentError::NotYetValid);
        }
        if now >= req.expires_at {
            return Err(EnrollmentError::Expired);
        }
        if req.identity.nonce != req.nonce {
            return Err(EnrollmentError::Malformed);
        }
        if req.identity.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || now >= req.identity.expires_at
        {
            return Err(EnrollmentError::IdentityInvalid);
        }

        let verified = self
            .identity
            .verify(&req.identity, req.user_id, now)
            .map_err(|e| match e {
                IdentityError::Unavailable => EnrollmentError::IdentityUnavailable,
                IdentityError::Mismatch => EnrollmentError::IdentityMismatch,
                IdentityError::Invalid | IdentityError::Expired => EnrollmentError::IdentityInvalid,
            })?;
        if verified.user_id != req.user_id || verified.provider != req.identity.provider {
            return Err(EnrollmentError::IdentityMismatch);
        }
        if verified.subject.is_empty() || verified.subject != req.identity.subject {
            return Err(EnrollmentError::IdentityMismatch);
        }

        let canonical = req.possession_bytes_for(operation)?;
        let sig_bytes =
            decode_b64(&req.possession_signature_b64).map_err(|_| EnrollmentError::Malformed)?;
        let signature =
            Signature::try_from(sig_bytes.as_slice()).map_err(|_| EnrollmentError::Malformed)?;
        if !signature.verify(&pubkey, &canonical) {
            return Err(EnrollmentError::InvalidPossessionProof);
        }

        self.replay
            .consume(
                ReplayScope {
                    user_id: req.user_id,
                    operation,
                },
                &req.request_id,
                &req.nonce,
                now,
                req.expires_at,
            )
            .map_err(|e| match e {
                ReplayError::Replay => EnrollmentError::Replay,
                ReplayError::Unavailable => EnrollmentError::StoreUnavailable,
            })?;

        Ok(VerifiedEnrollment {
            user_id: verified.user_id,
            auth_pubkey_b64: req.auth_pubkey_b64.clone(),
            key_fingerprint: req.key_fingerprint.clone(),
            identity_provider: verified.provider,
            identity_subject: verified.subject,
            generation: 1,
        })
    }
}

// ---------------------------------------------------------------------------
// D10 — audit boundary (redacted, fail-closed)
// ---------------------------------------------------------------------------

/// Redacted lifecycle audit event. No keys, signatures or evidence.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub outcome: &'static str,
    pub policy_version: u16,
    pub request_id: String,
    pub user_id: u64,
    pub generation: u64,
    pub operation: &'static str,
    pub approved_by: Vec<String>,
    pub operator_key_fingerprints: Vec<String>,
    pub at: u64,
}

/// Durable audit boundary. A sensitive mutation must abort if this fails.
pub trait AuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

impl<T: AuditSink + ?Sized> AuditSink for &T {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        (**self).record(event)
    }
}

/// Default-deny audit sink: no durable audit storage is configured.
pub struct DenyAllAuditSink;

impl AuditSink for DenyAllAuditSink {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::Unavailable)
    }
}
