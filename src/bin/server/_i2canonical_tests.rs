//! PHASE 9 I-2 — canonical builder byte-identity spike tests.
//!
//! FIXTURE PROVENANCE: every hex vector below was emitted by the REAL
//! Rialo SDK serializer — rialo-s-message 0.18.1 `legacy::Message::serialize()`
//! (bincode 1.3) and rialo-s-transaction 0.18.1 via `bincode::serialize`,
//! plus rialo-s-system-interface 0.18.1 `instruction::transfer` — from a
//! throwaway offline generator (crates.io 0.18.1 sources, `cargo run
//! --offline`), deterministic inputs only (fixed [0x11;32]/[0x22;32]/
//! [0x33;32] public keys, explicit valid_from — the SDK's clock-reading
//! `Message::new` was NOT used). Generator self-check `H_repeat_equal=yes`.
//! The keypair behind G_tx_signed is a funds-less TEST-ONLY vector (seed
//! pattern lives in the throwaway generator only); the repo embeds public
//! signature/pubkey bytes solely. These fixtures pin bytes, not claims:
//! LATCH byte identity (G-15/D14 live-enclave recompile) remains
//! UNRESOLVED and no test here asserts it.

use super::*;
use crate::rialo_canonical::{
    CanonicalTransferSpec, DecodeError, SYSTEM_PROGRAM_ID, build_canonical_message,
    canonical_signing_bytes, decode_canonical_message, decode_transaction_envelope,
    unsigned_transaction_envelope,
};

const FROM: [u8; 32] = [0x11; 32];
const TO: [u8; 32] = [0x22; 32];
const TO2: [u8; 32] = [0x33; 32];
const VF: i64 = 1_760_000_000_000;
const CHP: u64 = 0x0123_4567_89ab_cdef;
const K_SIGNER: [u8; 32] = [
    0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
    0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
];

fn spec<'a>(
    from: &'a [u8; 32],
    to: &'a [u8; 32],
    amt: u64,
    vf: i64,
    chp: u64,
    occ: bool,
) -> CanonicalTransferSpec<'a> {
    CanonicalTransferSpec {
        from,
        to,
        amount_kelvin: amt,
        valid_from_ms: vf,
        config_hash_prefix: chp,
        occ,
    }
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// fixture table (name, expected hex, builder inputs; multi/envelope rows
/// marked decoder-only)
fn fixtures() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "A_basic",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c0200000000ca9a3b00000000",
        ),
        (
            "B_amount_b0",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c020000000000000000000000",
        ),
        (
            "B_amount_b1",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c020000000100000000000000",
        ),
        (
            "B_amount_b255",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c02000000ff00000000000000",
        ),
        (
            "B_amount_b256",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c020000000001000000000000",
        ),
        (
            "B_amount_b65535",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c02000000ffff000000000000",
        ),
        (
            "B_amount_bmax",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c02000000ffffffffffffffff",
        ),
        (
            "C_recip_to2",
            "0100010311111111111111111111111111111111111111111111111111111111111111113333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c0200000000ca9a3b00000000",
        ),
        (
            "C_recip_from_self",
            "010001021111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001010200000c0200000000ca9a3b00000000",
        ),
        (
            "E_vf_zero",
            "010001031111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000000000000000000000efcdab89674523010001020200010c0200000000ca9a3b00000000",
        ),
        (
            "E_vf_max",
            "01000103111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000ffffffffffffff7fefcdab89674523010001020200010c0200000000ca9a3b00000000",
        ),
        (
            "E_vf_neg",
            "01000103111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffefcdab89674523010001020200010c0200000000ca9a3b00000000",
        ),
        (
            "E_chp_zero",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc89901000000000000000000000001020200010c0200000000ca9a3b00000000",
        ),
        (
            "E_occ_true",
            "0100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010101020200010c0200000000ca9a3b00000000",
        ),
    ]
}
fn builder_for(name: &str) -> Option<Vec<u8>> {
    let s = match name {
        "A_basic" => spec(&FROM, &TO, 1_000_000_000, VF, CHP, false),
        "B_amount_b0" => spec(&FROM, &TO, 0, VF, CHP, false),
        "B_amount_b1" => spec(&FROM, &TO, 1, VF, CHP, false),
        "B_amount_b255" => spec(&FROM, &TO, 255, VF, CHP, false),
        "B_amount_b256" => spec(&FROM, &TO, 256, VF, CHP, false),
        "B_amount_b65535" => spec(&FROM, &TO, 65_535, VF, CHP, false),
        "B_amount_bmax" => spec(&FROM, &TO, u64::MAX, VF, CHP, false),
        "C_recip_to2" => spec(&FROM, &TO2, 1_000_000_000, VF, CHP, false),
        "C_recip_from_self" => spec(&FROM, &FROM, 1_000_000_000, VF, CHP, false),
        "E_vf_zero" => spec(&FROM, &TO, 1_000_000_000, 0, CHP, false),
        "E_vf_max" => spec(&FROM, &TO, 1_000_000_000, i64::MAX, CHP, false),
        "E_vf_neg" => spec(&FROM, &TO, 1_000_000_000, -1, CHP, false),
        "E_chp_zero" => spec(&FROM, &TO, 1_000_000_000, VF, 0, false),
        "E_occ_true" => spec(&FROM, &TO, 1_000_000_000, VF, CHP, true),
        _ => return None,
    };
    Some(build_canonical_message(&s))
}

// A/B/C/E: byte identity of the builder against real-SDK fixtures
#[test]
fn builder_matches_sdk_serializer_fixtures() {
    for (name, hex) in fixtures() {
        let built = builder_for(name).unwrap_or_else(|| panic!("no builder case for {name}"));
        assert_eq!(hx(&built), hex, "BYTE MISMATCH in {name}");
    }
}

// G5: equivalent intents through different code paths — signing-bytes
// alias, envelope message section, and decoder round-trip must all agree
// with the same canonical message bytes.
#[test]
fn equivalent_paths_agree() {
    let sp = spec(&FROM, &TO, 1_000_000_000, VF, CHP, false);
    let msg = build_canonical_message(&sp);
    assert_eq!(canonical_signing_bytes(&sp), msg);
    let env = unsigned_transaction_envelope(&sp);
    assert_eq!(&env[65..], &msg[..]);
    let (sigs, decoded) = decode_transaction_envelope(&env).unwrap();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0], vec![0u8; 64], "new_unsigned pre-fills zeros");
    let rt = CanonicalTransferSpec {
        from: &decoded.account_keys[0],
        to: &decoded.account_keys[1],
        amount_kelvin: u64::from_le_bytes(decoded.instructions[0].data[4..12].try_into().unwrap()),
        valid_from_ms: decoded.valid_from_ms,
        config_hash_prefix: decoded.config_hash_prefix,
        occ: decoded.occ,
    };
    assert_eq!(
        build_canonical_message(&rt),
        msg,
        "decode->build round-trip"
    );
    assert_eq!(decoded.account_keys[2], SYSTEM_PROGRAM_ID);
    assert_eq!(decoded.instructions[0].data[..4], [2, 0, 0, 0]);
}

// F: repeat determinism
#[test]
fn repeated_serialization_is_byte_identical() {
    let sp = spec(&FROM, &TO, 42, VF, CHP, true);
    let a = build_canonical_message(&sp);
    let b = build_canonical_message(&sp);
    assert_eq!(a, b);
    // and across an independently reconstructed equal spec
    let sp2 = spec(&[0x11; 32], &[0x22; 32], 42, VF, CHP, true);
    assert_eq!(a, build_canonical_message(&sp2));
}

// semantic difference ⇒ byte difference (injective over the fixture set)
#[test]
fn distinct_intents_have_distinct_bytes() {
    let mut all: Vec<String> = fixtures().iter().map(|(_, h)| (*h).to_string()).collect();
    all.push("01000104111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010002030200010c020000000700000000000000030200020c020000000900000000000000".to_string());
    all.sort();
    let n = all.len();
    all.dedup();
    assert_eq!(
        all.len(),
        n,
        "two different intents collided on identical bytes"
    );
}

// transaction envelope fixtures
#[test]
fn unsigned_envelope_matches_sdk_fixture() {
    let sp = spec(&FROM, &TO, 1_000_000_000, VF, CHP, false);
    assert_eq!(
        hx(&unsigned_transaction_envelope(&sp)),
        "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c0200000000ca9a3b00000000"
    );
}

// signed fixture: the message SECTION must equal the builder output for
// the same public inputs; the signature bytes are opaque public data
#[test]
fn signed_envelope_message_section_is_builder_identical() {
    let signed = "01069e2eed6ddd8bf808207b9ac78347c4c394dca4fa8e13110f75e4746226b9c1a22a83ada019e3fce49fcb8cd3199a1ab999398f4356af5c2f9e21c3e762190e01000103ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c2222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010001020200010c020000002a00000000000000";
    let env = unsigned_transaction_envelope(&spec(&K_SIGNER, &TO, 42, VF, CHP, false));
    assert_eq!(
        env[65..].to_vec(),
        bytes_of(signed)[65..],
        "message section mismatch"
    );
    let (_, msg) = decode_transaction_envelope(&bytes_of(signed)).unwrap();
    assert_eq!(msg.account_keys[0], K_SIGNER);
    assert_eq!(msg.instructions[0].data[4..12], 42u64.to_le_bytes());
}

fn bytes_of(hexstr: &str) -> Vec<u8> {
    (0..hexstr.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexstr[i..i + 2], 16).unwrap())
        .collect()
}

// decoder handles the reference multi-instruction fixture the builder
// deliberately does NOT emit (documented scope)
#[test]
fn decoder_parses_multi_instruction_reference() {
    let d = decode_canonical_message(&bytes_of("01000104111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000000c02cc899010000efcdab89674523010002030200010c020000000700000000000000030200020c020000000900000000000000")).unwrap();
    assert_eq!(d.account_keys.len(), 4);
    assert_eq!(d.instructions.len(), 2);
    assert_eq!(d.instructions[0].accounts, vec![0, 1]);
    assert_eq!(d.instructions[1].accounts, vec![0, 2]);
    assert_eq!(d.instructions[1].program_id_index, 3);
    assert_eq!(
        u64::from_le_bytes(d.instructions[1].data[4..12].try_into().unwrap()),
        9
    );
}

// strictness: garbage/truncation NEVER guesses
#[test]
fn decoder_rejects_malformed_input() {
    let good = build_canonical_message(&spec(&FROM, &TO, 7, VF, CHP, false));
    for cut in [0usize, 1, 3, 5, 100, 116, 118, 133] {
        assert!(
            decode_canonical_message(&good[..cut]).is_err(),
            "truncation at {cut} decoded anyway"
        );
    }
    assert!(decode_canonical_message(&[0u8; 40]).is_err());
    let mut bad_bool = good.clone();
    bad_bool[116] = 2;
    assert!(matches!(
        decode_canonical_message(&bad_bool),
        Err(DecodeError::InvalidBool)
    ));
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        decode_canonical_message(&trailing),
        Err(DecodeError::TrailingBytes)
    ));
    // overlong zero length (0x80 0x00) is rejected, never accepted
    let mut overlong = good.clone();
    overlong[3] = 0x80;
    overlong.insert(4, 0x00);
    assert!(decode_canonical_message(&overlong).is_err());
}

// short-vec encoder golden behavior (source-pinned from rialo-s-short-vec)
#[test]
fn short_vec_encoding_matches_canonical_form() {
    let mut v = Vec::new();
    short_vec_len(0, &mut v);
    assert_eq!(v, vec![0x00]);
    v.clear();
    short_vec_len(127, &mut v);
    assert_eq!(v, vec![0x7f]);
    v.clear();
    short_vec_len(128, &mut v);
    assert_eq!(v, vec![0x80, 0x01]);
    v.clear();
    short_vec_len(u16::MAX, &mut v);
    assert_eq!(v, vec![0xff, 0xff, 0x03]);
}

// purity scan of the module itself (no fs/net/secrets/floats/wire claims)
#[test]
fn canonical_module_is_pure_and_secretless() {
    let src = include_str!("rialo_canonical.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!") && !l.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "File::",
        "read_keypair",
        "write_keypair",
        "keypair_from_seed",
        "getrandom",
        "artifact/",
        "ureq",
        "reqwest",
        ".route(",
        "lat_",
        "onlatch",
        "/proxy/",
        ".sign(",
        "SigningKey",
        "f32",
        "f64",
        "SystemTime",
        "Instant::now",
        "privy",
    ] {
        assert!(
            !code.to_lowercase().contains(&forbidden.to_lowercase()),
            "canonical builder references {forbidden}"
        );
    }
    // guard against vacuous passing
    assert!(code.contains("build_canonical_message"));
    assert!(code.contains("to_le_bytes"));
}

// isolation: nothing in production paths may reference the spike builder
#[test]
fn spike_is_isolated_from_production_payment_paths() {
    // include_str! requires literals — expand one per production file
    assert!(
        !include_str!("agents.rs").contains("rialo_canonical"),
        "agents.rs wired"
    );
    assert!(
        !include_str!("rialo.rs").contains("rialo_canonical"),
        "rialo.rs wired"
    );
    assert!(
        !include_str!("activity.rs").contains("rialo_canonical"),
        "activity.rs wired"
    );
    assert!(
        !include_str!("stats.rs").contains("rialo_canonical"),
        "stats.rs wired"
    );
    assert!(
        !include_str!("verify.rs").contains("rialo_canonical"),
        "verify.rs wired"
    );
    // the fixtures themselves carry no private material: assert none of
    // the test-key seed appears anywhere in the builder outputs
    let built = hx(&build_canonical_message(&spec(
        &FROM, &TO, 1, VF, CHP, false,
    )));
    assert!(!built.contains("0707070707070707"));
}

// sanity on the two documented constants (fixture-verified once more here)
#[test]
fn pinned_constants_are_fixture_consistent() {
    let msg = build_canonical_message(&spec(&FROM, &TO, 1, VF, CHP, false));
    assert_eq!(msg.len(), 135);
    assert_eq!(&msg[msg.len() - 12..msg.len() - 8], &[2u8, 0, 0, 0][..]);
    assert_eq!(msg[3], 3); // three keys
    assert_eq!(&msg[4 + 64..4 + 96], &SYSTEM_PROGRAM_ID);
}
