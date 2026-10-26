#[cfg(test)]
mod g89_probe {
    use crate::user_signer_protocol::UserWalletCreateRequest;
    /// Mirror EXACTLY the E2E http_post body (create_body output) and parse.
    #[test]
    fn probe_parse_exact_e2e_body() {
        // replicate create_body's serde_json semantics for the SAME input
        let v = serde_json::json!({
            "user_id": "77410099u64".to_string().trim_end_matches("u64"),
            "channel_nonce": "g89-e2e-create-n1",
            "admin_ceremony_proof": "be00d81aaefaecdc5ad1dccedf85b66f548b6200f3e695367388dd67c2bb075a",
            "intro_proof": "54755185f81b5dbfe6443e83755feabfc7cec3e0937e634f43ee30041545096b",
            "auth_signature": {
                "pubkey": { "user_id": "77410099", "base58": "" },
                "signature": "c2ln",
            },
        });
        let body = v.to_string();
        let r: Result<UserWalletCreateRequest, _> = serde_json::from_str(&body);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
        // raw base64 signature from the E2E (intent_sig): valid base64?
        use crate::base64_decode;
        let sig = crate::base64_encode(&[7u8; 64]);
        assert!(base64_decode(&sig).is_some());
    }
}
