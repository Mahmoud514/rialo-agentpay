//! user_signer_protocol — G79 decision 3: SHARED, strongly-typed wire
//! structures for the app→signer user protocol, authored ONCE in the server
//! tree and compiled into BOTH crates via `#[path]` (the established
//! rialo_canonical zero-drift discipline). No coincidentally-matching JSON:
//! serde field names are the single source; drift is a compile error.
//!
//! Signer crate: `#[path] pub mod user_signer_protocol;` (compiled+tested
//! offline on rustc 1.91). Server crate: the same declaration arrives with
//! the DEFERRED wiring gate (server compile requires rustc ≥ 1.94; CI = 1.99).

use serde::{Deserialize, Serialize};

/// The semantic transaction (identical field set to the frozen agent wire;
/// the user protocol owns its type — the agent lane is untouched).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSemanticTransaction {
    pub fee_payer: String,
    pub recipient: String,
    pub amount_kelvin: u64,
    pub valid_from_ms: i64,
    /// decimal-string u64 (the documented wire form; quoted to survive >2^53)
    pub config_hash_prefix: String,
    #[serde(default)]
    pub occ: bool,
}

/// The user auth-identity reference (typed; not a loose JSON pointer shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAuthRef {
    /// decimal-string github id
    pub user_id: String,
    /// base58 funds-less auth pubkey
    pub base58: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAuthEnvelope {
    pub pubkey: UserAuthRef,
    /// base64 ed25519 over the canonical bytes (signer recompiled)
    pub signature: String,
}

/// POST /user/sign request body (the ONLY shape accepted; unknown fields
/// are REFUSED at the signer — deny-by-default).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSignRequest {
    /// decimal-string github id (the users/ namespace principal)
    pub user_id: String,
    pub transaction: UserSemanticTransaction,
    pub auth_signature: UserAuthEnvelope,
    /// fresh per-request nonce; bound into the sealed response
    pub channel_nonce: String,
}

/// 200 response (sealed by the signer's channel key before transport). The
/// adapter verifies the seal FIRST, then consumes these typed fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSignResponse {
    /// decimal-string user id echo — binds the response to the principal
    pub user_id: String,
    /// blake3 hex of the signer's canonical message
    pub canonical_hash: String,
    pub canonical_message_b64: String,
    pub signature_b64: String,
    /// the frozen single-signer shape (must equal SINGLE_SIGNER_REQUIRED)
    pub required_signatures: u8,
}

/// Typed signer refusal body on non-200.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserSignDenial {
    pub error: String,
    pub code: String,
}

/// Read-only status response (the G76-analogue diagnostic; public data only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserStatusResponse {
    pub user_id: String,
    pub registered: bool,
    pub record_corrupt: bool,
    pub public_address: Option<String>,
    pub policy_state: String,
    pub key_container_state: String,
}

/// The canonical denial codes (single source for BOTH sides).
pub mod user_denial_codes {
    pub const BAD_REQUEST: &str = "USER_BAD_REQUEST";
    pub const UNKNOWN_WALLET: &str = "USER_UNKNOWN_WALLET";
    pub const AUTH_INVALID: &str = "USER_AUTH_INVALID";
    pub const AUTH_MALFORMED: &str = "USER_AUTH_MALFORMED";
    pub const POLICY_DENIED: &str = "USER_POLICY_DENIED";
    pub const POLICY_MISSING: &str = "USER_POLICY_MISSING";
    pub const POLICY_IDENTITY_MISMATCH: &str = "USER_POLICY_IDENTITY_MISMATCH";
    pub const POLICY_BINDING_MISMATCH: &str = "USER_POLICY_BINDING_MISMATCH";
    pub const PAYER_MISMATCH: &str = "USER_PAYER_MISMATCH";
    pub const BYTE_DIVERGENCE: &str = "USER_BYTE_DIVERGENCE";
    pub const RECORD_CORRUPT: &str = "USER_RECORD_CORRUPT";
    pub const STORE_UNAVAILABLE: &str = "USER_STORE_UNAVAILABLE";
    pub const KEY_NOT_IMPORTED: &str = "USER_KEY_NOT_IMPORTED";
    pub const CEREMONY_ADDRESS_MISMATCH: &str = "USER_CEREMONY_ADDRESS_MISMATCH";
    pub const CONFLICTING_REGISTRATION: &str = "USER_CONFLICTING_REGISTRATION";
    pub const SIGNING_NOT_ENABLED: &str = "USER_SIGNING_NOT_ENABLED";
    pub const INTENT_REPLAY: &str = "USER_INTENT_REPLAY";
    pub const INTENT_CONFLICT: &str = "USER_INTENT_CONFLICT";
    pub const INTENT_HOLD: &str = "USER_INTENT_HOLD";
    /// G81 — new-wallet provisioning (create path; separate from the
    /// operator import ceremony, which never mints keys)
    pub const USER_EXISTS: &str = "USER_EXISTS";
    pub const IDENTITY_MISMATCH: &str = "USER_IDENTITY_MISMATCH";
    pub const RELEASE_UNKNOWN: &str = "USER_RELEASE_UNKNOWN";
    /// G83-FIX — create-path security states
    pub const PREREQUISITE_MISSING: &str = "USER_PREREQUISITE_MISSING";
    pub const NONCE_REPLAY: &str = "USER_NONCE_REPLAY";
    pub const PROVISIONING_IN_PROGRESS: &str = "USER_PROVISIONING_IN_PROGRESS";
    pub const PROVISIONING_INCOMPLETE: &str = "USER_PROVISIONING_INCOMPLETE";
    pub const INTERNAL: &str = "USER_INTERNAL";
}

/// G83-FIX M1 — domain-separated canonical creation-intent message. The
/// subject signs EXACTLY these bytes with their (operator-registered)
/// funds-less auth key; the signer verifies against the REGISTERED binding
/// (never against a caller-supplied key alone).
///   msg = "g81-create-intent-v2" || b"2" || user_id(u64 LE) || nonce
pub const CREATE_INTENT_DOMAIN: &str = "g81-create-intent-v2";

/// The canonical creation-intent bytes for a create request.
pub fn creation_intent_message(user_id: u64, nonce: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(CREATE_INTENT_DOMAIN.as_bytes());
    m.extend_from_slice(b"2");
    m.extend_from_slice(&user_id.to_le_bytes());
    m.extend_from_slice(nonce.as_bytes());
    m
}

/// G81 — POST /user/wallet request (admin-secret-gated route; the ONLY
/// new-wallet creation path; the signer mints the key EXCLUSIVELY inside
/// its user namespace and returns ONLY public data).
///
/// G89 FIX — the request carries TWO independent proofs:
///   * `admin_ceremony_proof` = blake3(CEREMONY_SECRET_DOMAIN || signer's
///     AGENTPAY_SIGNER_ADMIN_SECRET) — proves the operator ceremony at the
///     HTTP boundary;
///   * `intro_proof` = blake3(INTRO_SECRET_DOMAIN || signer's
///     AGENTPAY_SIGNER_USER_CREATE_SECRET) — the generation-secret gate.
/// The previous single `ceremony_secret` field was required to equal both
/// digests at once, which no operator secret pair can satisfy (different
/// hash domains); no wire caller ever exercised it (library tests call
/// `create_user_wallet` directly).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserWalletCreateRequest {
    /// subject identity: must equal auth_signature.pubkey.user_id
    pub user_id: String,
    /// fresh per-request nonce; bound into the sealed response
    pub channel_nonce: String,
    /// blake3(CEREMONY_DOMAIN || admin secret) — operator ceremony proof
    pub admin_ceremony_proof: String,
    /// blake3(INTRO_DOMAIN || generation secret) — intro proof
    pub intro_proof: String,
    /// the request authenticator (funds-less; proves the subject)
    pub auth_signature: UserAuthEnvelope,
}

/// 200 sealed response (public data ONLY — no key material can exist in
/// this type by construction).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserWalletCreateResponse {
    /// decimal-string user id (echo)
    pub user_id: String,
    /// the new wallet's public address (the ONLY secret-adjacent output)
    pub public_address: String,
    /// state marker v2 (G81: the explicit new-lane wallet version)
    pub wallet_version: u8,
    /// the recovery-envelope ciphertext is held by the OPERATOR export,
    /// never in this response; only its presence flag crosses the wire
    pub recovery_envelope_stored: bool,
}

#[cfg(test)]
mod g79_protocol_tests {
    use super::*;

    fn sample_request() -> UserSignRequest {
        UserSignRequest {
            user_id: "50506318".into(),
            transaction: UserSemanticTransaction {
                fee_payer: "From1111111111111111111111111111111111111111".into(),
                recipient: "To111111111111111111111111111111111111111111".into(),
                amount_kelvin: 7,
                valid_from_ms: 1,
                config_hash_prefix: "42".into(),
                occ: false,
            },
            auth_signature: UserAuthEnvelope {
                pubkey: UserAuthRef {
                    user_id: "50506318".into(),
                    base58: "Auth1111111111111111111111111111111111111111".into(),
                },
                signature: "c2ln".into(),
            },
            channel_nonce: "bm9uY2U=".into(),
        }
    }

    #[test]
    fn request_roundtrip_field_names_pinned() {
        let req = sample_request();
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["user_id"], "50506318");
        assert_eq!(
            json["transaction"]["fee_payer"],
            "From1111111111111111111111111111111111111111"
        );
        assert_eq!(json["transaction"]["amount_kelvin"], 7);
        assert_eq!(json["transaction"]["config_hash_prefix"], "42");
        assert_eq!(
            json["auth_signature"]["pubkey"]["base58"],
            "Auth1111111111111111111111111111111111111111"
        );
        assert_eq!(json["channel_nonce"], "bm9uY2U=");
        let back: UserSignRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn request_unknown_field_refused() {
        let mut json = serde_json::to_value(sample_request()).unwrap();
        json["surprise"] = serde_json::json!(1);
        let parsed: Result<UserSignRequest, _> = serde_json::from_value(json);
        assert!(parsed.is_err(), "unknown fields must be refused");
    }

    #[test]
    fn response_roundtrip_and_user_echo_pinned() {
        let resp = UserSignResponse {
            user_id: "50506318".into(),
            canonical_hash: "ab".repeat(32),
            canonical_message_b64: "bQ==".into(),
            signature_b64: "c2ln".into(),
            required_signatures: 1,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user_id"], "50506318");
        assert_eq!(json["required_signatures"], 1);
        let back: UserSignResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn denial_body_shape_pinned() {
        let d = UserSignDenial {
            error: "DENIED".into(),
            code: user_denial_codes::AUTH_INVALID.to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["error"], "DENIED");
        assert_eq!(json["code"], "USER_AUTH_INVALID");
    }
}
