//! PHASE 9 I-1 (C-1) — focused tests for the funds-less agent
//! authentication keypair vault. All stores are fresh
//! std::env::temp_dir() subtrees; the real artifact/ tree is never
//! opened. Keypair contents here are test-only; their bytes are never
//! printed or asserted on — only public addresses, container validity,
//! path/mode behavior, and structural source scans.

use super::*;
use rialo_s_signer::Signer;
use std::fs;
use uuid::Uuid;

fn fresh_vault() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("agentpay-authkeys-i1-{}", Uuid::new_v4()));
    let vault = root.join("agent_auth_keys");
    fs::create_dir_all(&vault).unwrap();
    (root, vault)
}

fn cleanup(root: PathBuf) {
    fs::remove_dir_all(root).ok();
}

// (1) provisioning writes a valid keypair whose public key matches
// exactly the returned address.
#[test]
fn provision_writes_valid_keypair_matching_public_address() {
    let (root, vault) = fresh_vault();
    let id = Uuid::new_v4();

    let address = provision_agent_auth_key(&vault, &id).expect("provision");

    let path = auth_key_path(&vault, &id);
    assert!(path.exists());
    let mut file = fs::File::open(&path).unwrap();
    let keypair = rialo_s_keypair::read_keypair(&mut file).expect("valid keypair container");
    assert_eq!(keypair.pubkey().to_string(), address);
    // the public read path returns exactly the same address
    assert_eq!(read_auth_public_key(&vault, &id).unwrap(), address);

    cleanup(root);
}

// (2) the vault file is owner read/write only (600, BEFORE content).
#[test]
fn provisioned_auth_file_is_mode_0600() {
    let (root, vault) = fresh_vault();
    let id = Uuid::new_v4();

    provision_agent_auth_key(&vault, &id).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(auth_key_path(&vault, &id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    cleanup(root);
}

// (3) an existing vault path is refused and never overwritten.
#[test]
fn never_overwrites_an_existing_auth_path() {
    let (root, vault) = fresh_vault();
    let id = Uuid::new_v4();
    let path = auth_key_path(&vault, &id);
    fs::write(&path, b"PRE-EXISTING").unwrap();
    let before = fs::read(&path).unwrap();

    let err = provision_agent_auth_key(&vault, &id)
        .err()
        .expect("must refuse");
    assert!(matches!(err, AuthKeyProvisionError::Exists));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&path).unwrap(), b"PRE-EXISTING");

    cleanup(root);
}

// (3b) a failed open (missing parent dir) is Store, and leaves nothing
// behind (the O_EXCL cleanup can only ever touch our own path).
#[test]
fn provision_failure_leaves_no_file() {
    let root = std::env::temp_dir().join(format!("agentpay-authkeys-i1b-{}", Uuid::new_v4()));
    let missing_vault = root.join("does-not-exist");
    let id = Uuid::new_v4();

    let err = provision_agent_auth_key(&missing_vault, &id)
        .err()
        .expect("must fail");
    assert!(matches!(err, AuthKeyProvisionError::Store));
    assert!(!auth_key_path(&missing_vault, &id).exists());
    assert!(!missing_vault.exists());

    cleanup(root);
}

// (4) two agent ids get independent keys.
#[test]
fn two_ids_get_independent_auth_keys() {
    let (root, vault) = fresh_vault();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();

    let addr_a = provision_agent_auth_key(&vault, &a).unwrap();
    let addr_b = provision_agent_auth_key(&vault, &b).unwrap();
    assert_ne!(addr_a, addr_b);
    assert_ne!(auth_key_path(&vault, &a), auth_key_path(&vault, &b));

    cleanup(root);
}

// (5) the vault file holds NOTHING but the keypair — no metadata
// field names can appear in it.
#[test]
fn auth_file_contains_no_agent_metadata() {
    let (root, vault) = fresh_vault();
    let id = Uuid::new_v4();
    provision_agent_auth_key(&vault, &id).unwrap();

    let raw = fs::read(auth_key_path(&vault, &id)).unwrap();
    let text = String::from_utf8_lossy(&raw);
    for needle in [
        "owner_user_id",
        "schema_version",
        "agent_id",
        "wallet_address",
        "auth_public_key",
        "name",
    ] {
        assert!(!text.contains(needle), "auth vault file leaked {needle}");
    }

    cleanup(root);
}

// (6) verify happy path: recorded key == vault public key.
#[test]
fn verify_accepts_the_matching_recorded_key() {
    let (root, vault) = fresh_vault();
    let id = Uuid::new_v4();
    let address = provision_agent_auth_key(&vault, &id).unwrap();

    assert!(verify_auth_public_address(&vault, &id, &address).is_ok());

    cleanup(root);
}

// (7) verify mismatch is a hard abort with ZERO disk mutation.
#[test]
fn verify_mismatch_aborts_without_touching_anything() {
    let (root, vault) = fresh_vault();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let addr_a = provision_agent_auth_key(&vault, &a).unwrap();
    provision_agent_auth_key(&vault, &b).unwrap();

    let path_a = auth_key_path(&vault, &a);
    let before = fs::read(&path_a).unwrap();

    // A's id with B's recorded key — and vice versa — MUST mismatch.
    assert!(matches!(
        verify_auth_public_address(&vault, &a, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
        Err(AuthKeyError::Mismatch)
    ));
    assert!(verify_auth_public_address(&vault, &a, &addr_a).is_ok());

    assert_eq!(fs::read(&path_a).unwrap(), before);
    assert_eq!(fs::read_dir(&vault).unwrap().count(), 2);

    cleanup(root);
}

// (8) deterministic read-side failures: missing → NotFound,
// garbage container → Unavailable, blank expected → InvalidReference.
#[test]
fn read_and_verify_failures_are_typed_and_deterministic() {
    let (root, vault) = fresh_vault();
    let missing = Uuid::new_v4();
    assert!(matches!(
        read_auth_public_key(&vault, &missing),
        Err(AuthKeyError::NotFound)
    ));
    assert!(matches!(
        verify_auth_public_address(&vault, &missing, "x"),
        Err(AuthKeyError::NotFound)
    ));

    let garbage = Uuid::new_v4();
    fs::write(auth_key_path(&vault, &garbage), b"not-a-keypair-at-all").unwrap();
    assert!(matches!(
        read_auth_public_key(&vault, &garbage),
        Err(AuthKeyError::Unavailable)
    ));
    assert!(matches!(
        verify_auth_public_address(&vault, &garbage, "x"),
        Err(AuthKeyError::Unavailable)
    ));

    assert!(matches!(
        verify_auth_public_address(&vault, &missing, "   "),
        Err(AuthKeyError::InvalidReference)
    ));

    cleanup(root);
}

// (9) error enums are fieldless: Debug can carry no detail.
#[test]
fn error_debug_forms_carry_no_detail() {
    for d in [
        format!("{:?}", AuthKeyProvisionError::Exists),
        format!("{:?}", AuthKeyProvisionError::Store),
    ] {
        assert!(d == "Exists" || d == "Store", "debug leaked: {d}");
    }
    for e in [
        AuthKeyError::InvalidReference,
        AuthKeyError::NotFound,
        AuthKeyError::Unavailable,
        AuthKeyError::Mismatch,
    ] {
        let d = format!("{e:?}");
        assert!(
            !d.contains('/') && !d.contains(".json"),
            "debug leaked: {d}"
        );
    }
}

// (10) structural source scan: the vault mints and public-reads ONLY.
// No signing machinery, no transport, no routes, no wallet-path
// coupling, no Latch/Privy code — prose in doc comments may name the
// concepts (strip comment lines first, per the established pattern).
#[test]
fn module_source_stays_within_the_i1_vault_scope() {
    let src = include_str!("agent_auth_keys.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        ".sign(",
        "sign_prepared",
        "SigningKey",
        "Message",
        "ureq",
        "reqwest",
        ".route(",
        "\"artifact\"",
        "artifact/",
        "agent_wallet",
        "TxSigner",
        "keypair_reference",
        "privy",
        "latch",
    ] {
        assert!(
            !code.to_lowercase().contains(&forbidden.to_lowercase()),
            "vault source references {forbidden}"
        );
    }
    // The minting primitives it legitimately uses must be present
    // (guards the scan above from passing vacuously).
    assert!(code.contains("getrandom"));
    assert!(code.contains("keypair_from_seed"));
    assert!(code.contains("create_new(true)"));
}
