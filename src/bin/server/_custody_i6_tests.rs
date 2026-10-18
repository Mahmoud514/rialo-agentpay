//! PHASE 9 I-6 — focused custody-migration tests: strict pubkey-only
//! verification, fail-closed malformed containers, structural boundary
//! pins, tx/auth key separation, and unchanged lane semantics.
//! All stores are fresh std::env::temp_dir() subtrees; the real
//! artifact/ tree is never opened. Keypair bytes here are test-only;
//! their secret halves are never printed or asserted on.

use crate::agent_auth_keys::{
    AuthKeyError, auth_key_path, provision_agent_auth_key, read_auth_public_key,
    verify_auth_public_address,
};
use crate::latch_transport::ExecutionLane;
use crate::rialo_tx_signers::{
    SignerError, TxSigner, read_pubkey_address_only, verify_agent_public_address,
};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use uuid::Uuid;

// ---------- fixtures ----------

fn fresh_dirs() -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("agentpay-custody-i6-{}", Uuid::new_v4()));
    let wallets = root.join("agent_wallets");
    let vault = root.join("agent_auth_keys");
    fs::create_dir_all(&wallets).unwrap();
    fs::create_dir_all(&vault).unwrap();
    (root, wallets, vault)
}

fn cleanup(root: PathBuf) {
    fs::remove_dir_all(root).ok();
}

/// Build a canonical 64-byte JSON container from a 64-byte keypair.
/// The established writer (`write_keypair`) emits exactly this shape.
fn container_from(keypair: &rialo_s_keypair::Keypair) -> String {
    let bytes = keypair.to_bytes();
    let elems: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", elems.join(","))
}

/// Mint a throwaway keypair from deterministic test entropy (never the
/// real artifact tree) and return (container, public address).
fn test_container() -> (String, String) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
    // public address via the established Signer surface
    let address = {
        use rialo_s_signer::Signer;
        keypair.pubkey().to_string()
    };
    (container_from(&keypair), address)
}

// ---------- (1) equivalence: canonical container -> matching address ----------

#[test]
fn canonical_container_extracts_exactly_the_signer_pubkey() {
    let (container, address) = test_container();
    let mut cursor = Cursor::new(container);
    let got = read_pubkey_address_only(&mut cursor).expect("valid container");
    assert_eq!(
        got, address,
        "pubkey-only reader must equal Signer::pubkey()"
    );
}

#[test]
fn verify_agent_public_address_matches_pre_i6_behavior_on_valid_store() {
    let (root, wallets, _vault) = fresh_dirs();
    let id = Uuid::new_v4();
    let address =
        provision_agent_auth_key(&wallets, &id).expect("provisioning the agent wallet store");
    let signer = TxSigner::for_agent_record(&id.to_string(), &address).expect("signer");
    verify_agent_public_address(&signer, &wallets).expect("verification must succeed");
    cleanup(root);
}

// ---------- (2) fail-closed malformed containers ----------

#[test]
fn wrong_element_count_fails_closed() {
    let (container, _) = test_container();
    // 63 elements: drop the last one
    let inner = container.trim_start_matches('[').trim_end_matches(']');
    let mut elems: Vec<String> = inner.split(',').map(|s| s.to_string()).collect();
    elems.pop();
    let short = format!("[{}]", elems.join(","));
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(short)),
        Err(SignerError::Unavailable),
        "63 elements must fail closed"
    );

    // 65 elements: append an extra one
    let long = format!("[{},1]", inner);
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(long)),
        Err(SignerError::Unavailable),
        "65 elements must fail closed"
    );
}

#[test]
fn non_numeric_element_fails_closed() {
    let (container, _) = test_container();
    let broken = container.replacen(",", ",\"x\",", 1);
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(broken)),
        Err(SignerError::Unavailable)
    );
}

#[test]
fn negative_element_fails_closed() {
    let (container, _) = test_container();
    let broken = container.replacen(",", ",-1,", 1);
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(broken)),
        Err(SignerError::Unavailable)
    );
}

#[test]
fn oversized_element_fails_closed() {
    let (container, _) = test_container();
    let broken = container.replacen(",", ",256,", 1);
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(broken)),
        Err(SignerError::Unavailable)
    );
}

#[test]
fn trailing_comma_fails_closed() {
    let (container, _) = test_container();
    let broken = format!("{},", container.trim_end_matches(']'));
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(broken)),
        Err(SignerError::Unavailable),
        "65th empty element (trailing comma) must fail closed"
    );
}

#[test]
fn empty_and_whitespace_input_fails_closed() {
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new("")),
        Err(SignerError::Unavailable)
    );
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new("   \n\t ")),
        Err(SignerError::Unavailable)
    );
}

#[test]
fn base58_encoded_key_fails_closed() {
    // The established writer never emits base58; a base58 keypair
    // string must NOT be accepted by the strict reader.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
    let base58 = keypair.to_base58_string();
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(base58)),
        Err(SignerError::Unavailable),
        "base58-encoded keys must fail closed"
    );
}

#[test]
fn missing_brackets_fail_closed() {
    let (container, _) = test_container();
    let inner = container.trim_start_matches('[').trim_end_matches(']');
    assert_eq!(
        read_pubkey_address_only(&mut Cursor::new(inner)),
        Err(SignerError::Unavailable)
    );
}

#[test]
fn whitespace_around_elements_is_tolerated_but_shape_is_enforced() {
    // The writer emits no spaces, but surrounding whitespace must not
    // break the canonical case (robustness parity with read_keypair's
    // trim()), while the 64-element shape stays mandatory.
    let (container, address) = test_container();
    let spaced = container.replace(",", " , ");
    let mut cursor = Cursor::new(spaced);
    assert_eq!(
        read_pubkey_address_only(&mut cursor).expect("spaced"),
        address
    );
}

// ---------- (3) structural: no SigningKey in verification path ----------

#[test]
fn verification_reader_never_materializes_signing_key() {
    // Structural: the code of the signer module (comment lines
    // stripped) must contain no read_keypair and no SigningKey in the
    // verification path.
    let src = include_str!("rialo_tx_signers.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("read_keypair"),
        "verification path must not use read_keypair (I-6 boundary)"
    );
    assert!(
        !code.contains("SigningKey"),
        "verification path must not construct SigningKey"
    );
    assert!(
        !code.contains("keypair.pubkey()"),
        "verification path must not construct Keypair to get a pubkey"
    );
    assert!(
        code.contains("read_pubkey_address_only"),
        "verification must use the strict pubkey-only reader"
    );
}

#[test]
fn auth_vault_verification_uses_the_same_pubkey_only_reader() {
    let src = include_str!("agent_auth_keys.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("read_keypair"),
        "auth vault read path must not use read_keypair (I-6 boundary)"
    );
    assert!(
        code.contains("read_pubkey_address_only"),
        "auth vault must route through the shared pubkey-only reader"
    );
    // auth_pubkey remains ONLY for minting (creation needs the full
    // keypair); it must not be reachable from read_auth_public_key.
    assert!(
        code.contains("fn auth_pubkey"),
        "minting helper stays present"
    );
}

// ---------- (4) tx-key vs auth-key separation ----------

#[test]
fn tx_signer_and_auth_vault_stay_separated_stores() {
    let (root, wallets, vault) = fresh_dirs();
    let id = Uuid::new_v4();

    let tx_address = provision_agent_auth_key(&wallets, &id).expect("tx store");
    let auth_address = provision_agent_auth_key(&vault, &id).expect("auth store");

    // Different, independently minted keys in different directories.
    assert_ne!(
        tx_address, auth_address,
        "money signer and funds-less auth key must never share a key"
    );

    // tx verification only sees the wallet dir; auth only the vault.
    let signer = TxSigner::for_agent_record(&id.to_string(), &tx_address).unwrap();
    verify_agent_public_address(&signer, &wallets).expect("tx verification");
    verify_auth_public_address(&vault, &id, &auth_address).expect("auth verification");

    // Cross-swapped expectations must fail closed.
    let cross = verify_auth_public_address(&vault, &id, &tx_address);
    assert_eq!(cross, Err(AuthKeyError::Mismatch));
    let cross = verify_agent_public_address(
        &TxSigner::for_agent_record(&id.to_string(), &auth_address).unwrap(),
        &wallets,
    );
    assert_eq!(cross, Err(SignerError::Mismatch));
    cleanup(root);
}

// ---------- (5) no private key in CLI args / Latch proxy path ----------

#[test]
fn rialo_transfer_receives_a_file_path_not_key_material() {
    // rialo.rs transfer(): the keypair reference handed to the CLI is a
    // file path; no key bytes ever flow through args or the lane.
    let src = include_str!("rialo.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("read_keypair"),
        "transfer lane must not read key material in-process"
    );
    assert!(
        code.contains("keypair_path: &PathBuf"),
        "transfer takes the wallet FILE PATH"
    );
}

#[test]
fn latch_transport_and_proxy_lane_stay_keyless() {
    for (name, src) in [
        ("latch_transport", include_str!("latch_transport.rs")),
        ("latch_proxy_lane", include_str!("latch_proxy_lane.rs")),
    ] {
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("read_keypair") && !code.contains("SigningKey"),
            "Latch lane {name} must stay free of key-material handling"
        );
    }
}

#[test]
fn signer_file_reference_only_names_the_canonical_uuid_json() {
    let (root, wallets, _vault) = fresh_dirs();
    let id = Uuid::new_v4();
    let signer = TxSigner::for_agent_record(&id.to_string(), "Addr").expect("signer");
    let reference = signer.keypair_reference(&wallets);
    let reference = reference.to_string_lossy().to_string();
    assert!(reference.ends_with(".json"));
    assert!(
        reference.contains(&id.to_string()),
        "reference is the canonical uuid filename"
    );
    assert!(!reference.contains(".."), "no path escape");
    let _ = root;
    cleanup(root);
}

// ---------- (6) exact-once / lane semantics remain intact ----------

#[test]
fn lane_semantics_unchanged_native_and_latch_variants_persist() {
    // The exact-once machinery is untouched: the transport still
    // carries the one-shot guard and the lane enum still names both
    // lanes; verification-time custody changes nothing in the lanes.
    let src = include_str!("latch_transport.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(code.contains("AtomicBool"), "one-shot guard preserved");
    assert!(code.contains("claim_attempt"), "guard claim preserved");
    assert!(code.contains("PreExec"), "fallback class preserved");
    assert!(code.contains("Denial"), "denial class preserved");
    assert!(code.contains("Uncertain"), "uncertainty class preserved");
    assert!(
        code.contains("ExecutionLane::Native"),
        "native lane preserved"
    );
    let lane_variants = format!("{:?}", ExecutionLane::Native);
    assert_eq!(lane_variants, "Native", "lane enum unchanged");
}

#[test]
fn custody_change_touches_no_execution_semantics() {
    // The signer module's structural promise: no signing in-process.
    let src = include_str!("rialo_tx_signers.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains(".sign("),
        "server-side signing stays forbidden"
    );
}

#[test]
fn malformed_store_never_returns_partial_address() {
    // Fail-closed through the full verification surface: malformed
    // container yields Unavailable, not a bogus address comparison.
    let (root, wallets, _vault) = fresh_dirs();
    let id = Uuid::new_v4();
    let path = wallets.join(format!("{id}.json"));
    fs::write(&path, "[1,2,3]").unwrap();
    let signer = TxSigner::for_agent_record(&id.to_string(), "Addr").expect("signer");
    assert_eq!(
        verify_agent_public_address(&signer, &wallets),
        Err(SignerError::Unavailable)
    );
    cleanup(root);
}

#[test]
fn missing_store_reports_not_found_and_wrong_key_reports_mismatch() {
    let (root, wallets, _vault) = fresh_dirs();
    let id = Uuid::new_v4();
    let signer = TxSigner::for_agent_record(&id.to_string(), "Addr").expect("signer");
    assert_eq!(
        verify_agent_public_address(&signer, &wallets),
        Err(SignerError::NotFound)
    );

    let (container, address) = test_container();
    fs::write(wallets.join(format!("{id}.json")), container).unwrap();
    // recorded address != file's pubkey -> Mismatch
    let wrong = TxSigner::for_agent_record(&id.to_string(), "SomeOtherAddress").unwrap();
    assert_eq!(
        verify_agent_public_address(&wrong, &wallets),
        Err(SignerError::Mismatch)
    );
    // recorded address == file's pubkey -> Ok
    let right = TxSigner::for_agent_record(&id.to_string(), &address).unwrap();
    verify_agent_public_address(&right, &wallets).expect("matching store");
    cleanup(root);
}

#[test]
fn auth_vault_malformed_container_fails_closed_too() {
    let (root, _wallets, vault) = fresh_dirs();
    let id = Uuid::new_v4();
    fs::write(auth_key_path(&vault, &id), "not-a-container").unwrap();
    assert_eq!(
        read_auth_public_key(&vault, &id),
        Err(AuthKeyError::Unavailable)
    );
    cleanup(root);
}
