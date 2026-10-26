//! G111 — lifecycle coordinator for synthetic, testable user-wallet operations.
//!
//! It composes the existing primitives rather than duplicating crypto:
//! D1 `EnrollmentVerifier` (identity + possession), D8 `LifecycleAuthorizer`
//! (operator approval + replay + pre-mutation audit), and the durable
//! `UserBindingRegistry`.
//!
//! Safety / partial-failure semantics:
//! 1. Shape and generation checks run before any replay is consumed.
//! 2. D1 proof replay is consumed first. If D8 then fails, the proof id is
//!    burned and no state is mutated; the caller must use fresh ids.
//! 3. D8 replay is consumed and a redacted authorization audit event is
//!    persisted before the registry mutation. If the registry write fails, no
//!    binding changes; the audit records an authorized-but-not-applied attempt.
//! 4. The registry write is one atomic record containing the mutation's
//!    redacted audit metadata. Success is returned only after that write.
//! 5. There is no second external audit write after mutation. The registry
//!    record is the authoritative applied-mutation audit; `FileAuditSink`
//!    records the authorization step and is not transactionally coupled to the
//!    registry file.
//!
//! This is deliberately not a production route. It requires a real identity
//! adapter and provisioned operator trust store to succeed; the shipped
//! defaults deny.

use crate::user_authorization::{
    AuditSink, AuthorizationOutcome, AuthorizationPayload, EnrollmentError, EnrollmentRequest,
    EnrollmentVerifier, IdentityProvider, LifecycleAuthorizationError, LifecycleAuthorizer,
    LifecycleOperation, OperatorSignature, OperatorTrustStore, ReplayStore,
};
use crate::user_binding_registry::{
    MutationContext, RegistryError, UserBinding, UserBindingRegistry,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    /// Request fields do not agree (user, operation, generation, key ids, or
    /// proof/authorization request ids are not distinct).
    RequestMismatch,
    Enrollment(EnrollmentError),
    Authorization(LifecycleAuthorizationError),
    Registry(RegistryError),
}

pub struct LifecycleCoordinator<I, S, R, A> {
    identity: I,
    trust: S,
    replay: R,
    audit: A,
    registry: UserBindingRegistry,
}

impl<I, S, R, A> LifecycleCoordinator<I, S, R, A>
where
    I: IdentityProvider,
    S: OperatorTrustStore,
    R: ReplayStore,
    A: AuditSink,
{
    pub fn new(identity: I, trust: S, replay: R, audit: A, registry: UserBindingRegistry) -> Self {
        Self {
            identity,
            trust,
            replay,
            audit,
            registry,
        }
    }

    pub fn status(&self, user_id: u64) -> Result<Option<UserBinding>, LifecycleError> {
        self.registry.get(user_id).map_err(LifecycleError::Registry)
    }

    pub fn signing_allowed(
        &self,
        user_id: u64,
        key_fingerprint: &str,
    ) -> Result<bool, LifecycleError> {
        self.registry
            .signing_allowed(user_id, key_fingerprint)
            .map_err(LifecycleError::Registry)
    }

    /// Initial enrollment: identity + new-key possession + operator approval.
    pub fn enroll(
        &self,
        proof: &EnrollmentRequest,
        authorization: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        now: u64,
    ) -> Result<UserBinding, LifecycleError> {
        self.validate_shape(proof, authorization, LifecycleOperation::Enroll, 1, now)?;

        let verified = EnrollmentVerifier::new(&self.identity, &self.replay)
            .verify(proof, now)
            .map_err(LifecycleError::Enrollment)?;
        if verified.key_fingerprint != authorization.new_key_fingerprint {
            return Err(LifecycleError::RequestMismatch);
        }

        let outcome = LifecycleAuthorizer::new(&self.trust, &self.replay, &self.audit)
            .authorize(authorization, signatures, now)
            .map_err(LifecycleError::Authorization)?;
        let ctx = context(authorization, &outcome, now);
        self.registry
            .enroll(verified.user_id, &verified.auth_pubkey_b64, &ctx)
            .map_err(LifecycleError::Registry)
    }

    /// Authorized rotation: identity + NEW-key possession + operator approval,
    /// with an expected generation and expected current fingerprint.
    pub fn rotate(
        &self,
        proof: &EnrollmentRequest,
        authorization: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        expected_generation: u64,
        now: u64,
    ) -> Result<UserBinding, LifecycleError> {
        self.validate_shape(
            proof,
            authorization,
            LifecycleOperation::Rotate,
            expected_generation
                .checked_add(1)
                .ok_or(LifecycleError::RequestMismatch)?,
            now,
        )?;

        let existing = self
            .registry
            .get(authorization.user_id)
            .map_err(LifecycleError::Registry)?
            .ok_or(LifecycleError::Registry(RegistryError::NotFound))?;
        if existing.status == crate::user_binding_registry::BindingStatus::Revoked {
            return Err(LifecycleError::Registry(RegistryError::Revoked));
        }
        if existing.generation != expected_generation {
            return Err(LifecycleError::Registry(RegistryError::GenerationMismatch));
        }
        if existing.key_fingerprint != authorization.current_key_fingerprint {
            return Err(LifecycleError::Registry(RegistryError::KeyMismatch));
        }
        if proof.key_fingerprint != authorization.new_key_fingerprint {
            return Err(LifecycleError::RequestMismatch);
        }

        let verified = EnrollmentVerifier::new(&self.identity, &self.replay)
            .verify_for_operation(proof, now, LifecycleOperation::Rotate)
            .map_err(LifecycleError::Enrollment)?;

        let outcome = LifecycleAuthorizer::new(&self.trust, &self.replay, &self.audit)
            .authorize(authorization, signatures, now)
            .map_err(LifecycleError::Authorization)?;
        let ctx = context(authorization, &outcome, now);
        self.registry
            .rotate_checked(
                authorization.user_id,
                expected_generation,
                &authorization.current_key_fingerprint,
                &verified.auth_pubkey_b64,
                &ctx,
            )
            .map_err(LifecycleError::Registry)
    }

    /// Authorized revocation: operator approval only; no user possession proof.
    pub fn revoke(
        &self,
        authorization: &AuthorizationPayload,
        signatures: &[OperatorSignature],
        now: u64,
    ) -> Result<UserBinding, LifecycleError> {
        if authorization.operation != LifecycleOperation::Revoke
            || authorization.user_id == 0
            || authorization.generation == 0
            || now == 0
        {
            return Err(LifecycleError::RequestMismatch);
        }

        let existing = self
            .registry
            .get(authorization.user_id)
            .map_err(LifecycleError::Registry)?
            .ok_or(LifecycleError::Registry(RegistryError::NotFound))?;
        if existing.status == crate::user_binding_registry::BindingStatus::Revoked {
            return Err(LifecycleError::Registry(RegistryError::AlreadyRevoked));
        }
        if existing.generation != authorization.generation {
            return Err(LifecycleError::Registry(RegistryError::GenerationMismatch));
        }
        if existing.key_fingerprint != authorization.current_key_fingerprint {
            return Err(LifecycleError::Registry(RegistryError::KeyMismatch));
        }

        let outcome = LifecycleAuthorizer::new(&self.trust, &self.replay, &self.audit)
            .authorize(authorization, signatures, now)
            .map_err(LifecycleError::Authorization)?;
        let ctx = context(authorization, &outcome, now);
        self.registry
            .revoke_checked(
                authorization.user_id,
                authorization.generation,
                &authorization.current_key_fingerprint,
                &ctx,
            )
            .map_err(LifecycleError::Registry)
    }

    fn validate_shape(
        &self,
        proof: &EnrollmentRequest,
        authorization: &AuthorizationPayload,
        operation: LifecycleOperation,
        expected_generation: u64,
        now: u64,
    ) -> Result<(), LifecycleError> {
        if authorization.operation != operation
            || authorization.user_id != proof.user_id
            || authorization.generation != expected_generation
            || proof.key_fingerprint != authorization.new_key_fingerprint
            || now == 0
        {
            return Err(LifecycleError::RequestMismatch);
        }
        if proof.request_id == authorization.request_id || proof.nonce == authorization.nonce {
            return Err(LifecycleError::RequestMismatch);
        }
        Ok(())
    }
}

fn context<'a>(
    authorization: &'a AuthorizationPayload,
    outcome: &'a AuthorizationOutcome,
    at: u64,
) -> MutationContext<'a> {
    MutationContext {
        request_id: &authorization.request_id,
        operator_ids: &outcome.approved_by,
        operator_key_fingerprints: &outcome.approved_key_fingerprints,
        at,
    }
}
