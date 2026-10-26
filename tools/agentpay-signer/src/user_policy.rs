//! user_policy — G79: DISTINCT per-user policy records (the signer's
//! SECOND, independent gate). Replaces the G78 anonymous single-document
//! policy per the G79 decision 2.
//!
//! RECORD FORMAT (one file PER USER, signed by the OPERATOR's ceremony):
//!   {
//!     "user_id":           <u64 — the authenticated principal governed>,
//!     "auth_pubkey":       "<base58 — MUST equal the signer's registered
//!                           user record auth linkage>",
//!     "max_per_tx_kelvin": <u64>,
//!     "recipients":        ["<base58>", …]
//!   }
//!
//! IDENTITY/INTEGRITY ENFORCEMENT (why a swapped/copy-pasted record cannot
//! grant anything): a record is accepted ONLY when
//!   (a) record.user_id == the authenticated request user_id (the file NAME
//!       is not trusted — the identity inside must match), AND
//!   (b) record.auth_pubkey == the signer's REGISTERED user record auth
//!       linkage (copying user A's policy for user B fails closed), AND
//!   (c) the file lives in the signer's own policy directory
//!       (AGENTPAY_SIGNER_USER_POLICY_DIR/<user_id>.policy.json — the
//!       signer NEVER reads the app store; the operator provisions them).
//! NOTE (honest limitation): (a)+(b) bind the record to the registered
//! identity chain; a copy-forge of BOTH the record AND the registered
//! linkage would require signer-store write access, which is the signer's
//! own trust boundary. Ed25519-signing of policy files by the operator is
//! a documented FUTURE hardening (needs an operator key ceremony decision,
//! per G79's stop rule on unresolved custody decisions).
//! Any mismatch/absence/malformed content ⇒ typed denial (fail-closed).
//! Empty recipients ⇒ deny every request; "*" ⇒ load rejection.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserPolicyRecord {
    /// explicit authenticated identity — must equal the requesting principal
    pub user_id: u64,
    /// must equal the signer's registered user record auth linkage
    pub auth_pubkey: String,
    /// per-transaction cap in integer kelvin (REQUIRED; no default = deny)
    pub max_per_tx_kelvin: u64,
    /// recipients allowed for THIS user (base58). EMPTY ⇒ DENY; "*" ⇒
    /// rejected at load (never interpreted as unrestricted).
    pub recipients: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserPolicyError {
    /// no file for this user — deny (fail-closed; never a shared default)
    MissingForUser,
    /// unparsable / wrong shape
    Malformed,
    /// "*" present — rejected at load (never interpreted)
    WildcardRejected,
    /// record.user_id != the authenticated user_id
    IdentityMismatch,
    /// record.auth_pubkey != the registered user's auth linkage
    RegisteredBindingMismatch,
}

/// Load and fully validate the per-user policy record.
///
/// `registered_auth_pubkey` comes from the signer's OWN registered user
/// record (`users/<user_id>.wallet.json`) — the caller (user_lane) has
/// already integrity-checked that record against the key container.
pub fn load_user_policy_for(
    policy_dir: &std::path::Path,
    user_id: u64,
    registered_auth_pubkey: &str,
) -> Result<UserPolicyRecord, UserPolicyError> {
    let path = policy_dir.join(format!("{user_id}.policy.json"));
    let raw = std::fs::read(&path).map_err(|_| UserPolicyError::MissingForUser)?;
    let record: UserPolicyRecord =
        serde_json::from_slice(&raw).map_err(|_| UserPolicyError::Malformed)?;
    // (a) explicit identity enforcement — the former `_user_id` is now a
    //     REAL check: the record must govern THIS authenticated principal.
    if record.user_id != user_id {
        return Err(UserPolicyError::IdentityMismatch);
    }
    // (b) the registered-binding check
    if record.auth_pubkey.trim() != registered_auth_pubkey.trim() {
        return Err(UserPolicyError::RegisteredBindingMismatch);
    }
    // (c) wildcard is never interpreted
    if record.recipients.iter().any(|r| r.trim() == "*") {
        return Err(UserPolicyError::WildcardRejected);
    }
    Ok(record)
}

/// Structured policy-refusal reasons (distinct classes for operator
/// diagnosability; mapped to typed denial bodies by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserDenialReason {
    EmptyRecipients,
    OverCap,
    RecipientNotAllowed,
    ValidFromWindow,
}

/// Evaluate the loaded per-user record. Empty recipients ⇒ deny; per-tx
/// cap; exact recipient match; validFrom window (±120_000 ms, the
/// agent-lane tolerance).
pub fn evaluate_user_policy(
    record: &UserPolicyRecord,
    recipient: &str,
    amount_kelvin: u64,
    valid_from_ms: i64,
    now_ms: i64,
) -> Result<(), UserDenialReason> {
    if record.recipients.is_empty() {
        return Err(UserDenialReason::EmptyRecipients);
    }
    if amount_kelvin > record.max_per_tx_kelvin {
        return Err(UserDenialReason::OverCap);
    }
    if !record
        .recipients
        .iter()
        .any(|r| r.trim() == recipient.trim())
    {
        return Err(UserDenialReason::RecipientNotAllowed);
    }
    const TOLERANCE_MS: i64 = 120_000;
    let delta = valid_from_ms - now_ms;
    if !(-TOLERANCE_MS..=TOLERANCE_MS).contains(&delta) {
        return Err(UserDenialReason::ValidFromWindow);
    }
    Ok(())
}

#[cfg(test)]
mod g79_policy_tests {
    use super::*;

    const AUTH: &str = "Auth1111111111111111111111111111111111111111";
    const RCPT: &str = "Rcpt1111111111111111111111111111111111111111";

    fn record(user_id: u64, auth: &str, recipients: &[&str], cap: u64) -> UserPolicyRecord {
        UserPolicyRecord {
            user_id,
            auth_pubkey: auth.to_string(),
            max_per_tx_kelvin: cap,
            recipients: recipients.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn write_policy(dir: &std::path::Path, user_id: u64, rec: &UserPolicyRecord) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(format!("{user_id}.policy.json")),
            serde_json::to_vec(rec).unwrap(),
        )
        .unwrap();
    }

    struct DirGuard(std::path::PathBuf);
    impl DirGuard {
        fn new(tag: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "g79pol-{tag}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            )))
        }
    }
    impl Drop for DirGuard {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn empty_recipients_denies() {
        let r = record(1, AUTH, &[], 1000);
        assert_eq!(
            evaluate_user_policy(&r, RCPT, 1, 0, 0),
            Err(UserDenialReason::EmptyRecipients)
        );
    }

    #[test]
    fn over_cap_denies() {
        let r = record(1, AUTH, &[RCPT], 5);
        assert_eq!(
            evaluate_user_policy(&r, RCPT, 6, 0, 0),
            Err(UserDenialReason::OverCap)
        );
    }

    #[test]
    fn non_allowlisted_recipient_denies() {
        let r = record(1, AUTH, &[RCPT], 5);
        assert_eq!(
            evaluate_user_policy(&r, "Other1111111111111111111111111111111111111111", 1, 0, 0),
            Err(UserDenialReason::RecipientNotAllowed)
        );
    }

    #[test]
    fn valid_from_window_enforced() {
        let r = record(1, AUTH, &[RCPT], 5);
        assert_eq!(
            evaluate_user_policy(&r, RCPT, 1, -200_000, 0),
            Err(UserDenialReason::ValidFromWindow)
        );
        assert!(evaluate_user_policy(&r, RCPT, 1, 0, 0).is_ok());
        assert!(evaluate_user_policy(&r, RCPT, 1, 120_000, 0).is_ok());
        assert_eq!(
            evaluate_user_policy(&r, RCPT, 1, 120_001, 0),
            Err(UserDenialReason::ValidFromWindow)
        );
    }

    #[test]
    fn identity_mismatch_denies_at_load() {
        let dir = DirGuard::new("idmm");
        write_policy(&dir.0, 1, &record(2, AUTH, &[RCPT], 5));
        assert_eq!(
            load_user_policy_for(&dir.0, 1, AUTH).unwrap_err(),
            UserPolicyError::IdentityMismatch
        );
    }

    #[test]
    fn registered_binding_mismatch_denies_at_load() {
        let dir = DirGuard::new("bindmm");
        write_policy(
            &dir.0,
            1,
            &record(1, "WrongAuth1111111111111111111111111111111111", &[RCPT], 5),
        );
        assert_eq!(
            load_user_policy_for(&dir.0, 1, AUTH).unwrap_err(),
            UserPolicyError::RegisteredBindingMismatch
        );
    }

    #[test]
    fn missing_user_policy_denies() {
        let dir = DirGuard::new("missing");
        assert_eq!(
            load_user_policy_for(&dir.0, 42, AUTH).unwrap_err(),
            UserPolicyError::MissingForUser
        );
    }

    #[test]
    fn malformed_policy_denies() {
        let dir = DirGuard::new("malformed");
        std::fs::create_dir_all(&dir.0).unwrap();
        std::fs::write(dir.0.join("1.policy.json"), b"{not json").unwrap();
        assert_eq!(
            load_user_policy_for(&dir.0, 1, AUTH).unwrap_err(),
            UserPolicyError::Malformed
        );
    }

    #[test]
    fn wildcard_policy_rejected_at_load() {
        let dir = DirGuard::new("wildcard");
        write_policy(&dir.0, 1, &record(1, AUTH, &["*"], 5));
        assert_eq!(
            load_user_policy_for(&dir.0, 1, AUTH).unwrap_err(),
            UserPolicyError::WildcardRejected
        );
    }
}
