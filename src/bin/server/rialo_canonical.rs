//! rialo_canonical — PHASE 9 I-2: the canonical transaction builder and
//! byte-identity evidence surface for the future Latch signing/delegation
//! lane. SPIKE SCOPE ONLY (R2/I-0 §3, I-2 line): pure semantic-intent →
//! canonical-bytes compilation plus a strict decoder. NOTHING in the
//! production payment path calls this module (structural-pinned by tests);
//! the native lane (rialo CLI custody) is unchanged and remains
//! authoritative. It also is NOT the Latch lane: the Latch-side "live byte
//! identity" (G-15/D14, enclave-recompile agreement) is UNRESOLVED — the
//! proof here is byte identity against the real Rialo SDK serializer
//! (rialo-s-message/rialo-s-transaction 0.18.1, offline vectors), not
//! against a live enclave.
//!
//! LAYER MAP (I-2 §6 boundary):
//!   1. AgentPay semantic intent      — `CanonicalTransferSpec` (this module)
//!   2. canonical transaction repr.   — the legacy Message field tuple
//!   3. canonical transaction bytes   — `build_canonical_message` (PROVEN
//!      byte-identical to the SDK's `Message::serialize()` = bincode of the
//!      real rialo-s-message 0.18.1 struct, per the embedded fixtures)
//!   4. Latch semantic JSON schema    — UNRESOLVED (G-2 wire schema; never
//!      guessed; nothing in this module emits a "Latch payload")
//!   5. Latch signing bytes           — UNRESOLVED until the live-enclave
//!      recompile spike (G-15/D14); 3 is NOT claimed equal to 5.
//!
//! WIRE FACTS — all established by EVIDENCE, none assumed:
//!   * layout/order: rialo-s-message-0.18.1 `legacy::Message` field order
//!     (header, account_keys short-vec, valid_from i64, config_hash_prefix
//!     u64, occ bool, instructions short-vec of CompiledInstruction
//!     {program_id_index u8, accounts short-vec, data short-vec});
//!     integers little-endian fixed-width (bincode default, verified
//!     against fixture bytes); keys are raw 32 bytes, no length prefix.
//!   * length prefixes: 7-bit-group compact u16 (continuation bit 0x80),
//!     per rialo-s-short-vec-0.18.1 `ShortU16::serialize` (read, not
//!     remembered).
//!   * system transfer instruction data: u32-le discriminator 2 + u64-le
//!     kelvin amount — independently pinned in-repo by the reconciliation
//!     decoder (`system_transfer_amount`, rialo.rs) AND by fixtures here.
//!   * system program id: 32 zero bytes (pinned by fixture A_basic key 3).
//!   * account ordering/dedup: fee payer first, then instruction accounts
//!     in order with dedup, program last as the read-only unsigned key;
//!     header [1, 0, 1] for one transfer; verified for the single-transfer
//!     and self-transfer shapes by fixtures (multi-ix fixtures exist for
//!     the decoder only — this builder is intentionally single-transfer,
//!     the one shape the AgentPay lane needs).
//!   * transaction envelope: short-vec signature count + 64-byte
//!     signatures + message (rialo-s-transaction `Transaction` field
//!     order); `new_unsigned` pre-fills `num_required_signatures` ZERO
//!     signatures (behavior pinned by the G_tx_unsigned fixture — the
//!     prefix is 0x01 + 64 zero bytes, NOT an empty list).
//!   * valid_from unit: unix MILLISECONDS (`Message::new` uses
//!     as_millis; documented, and it is a caller-supplied field here).
//!   * signing/hash boundary (G6): the SDK signs the message bytes
//!     (`Transaction::sign` → `sign_message(message_bytes)`); the
//!     blake3(b"solana-tx-message-v1" || bytes) digest is the SDK's
//!     message-hash step and is NOT implemented here (no blake3
//!     dependency exists in this build; adding one is out of scope and
//!     unnecessary for byte identity of 3).
//!
//! Determinism contract: pure functions, no clock, no randomness, no
//! locale, no map iteration, integer-only (no floats anywhere), std-only.
//! Secrets: this module never reads key material and never emits any —
//! it operates on PUBLIC 32-byte key arrays only (test-pinned by scans).

#![allow(dead_code)] // deliberate: an I-2 SPIKE is unwired by design (the
// native lane is unchanged, the Latch lane is a future item); consumed by
// tests today. Same precedent as src/agent_credentials.rs pre-wiring.

use serde::Serialize;

/// System program id: 32 zero bytes — pinned by SDK fixture A_basic
/// (generated from `rialo_s_system_interface`, not assumed).
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// System-transfer instruction discriminator (u32 = 2, serialized
/// little-endian). Pinned twice: by the in-repo reconciliation decoder
/// (`system_transfer_amount`) and by every I-2 fixture.
pub const SYSTEM_TRANSFER_DISCRIMINATOR: u32 = 2;

/// Transfer instruction data is fixed-shape: 4-byte discriminator +
/// 8-byte little-endian kelvin amount.
pub const TRANSFER_DATA_LEN: usize = 12;

/// Number of required signatures for a single-sender transfer.
pub const SINGLE_SIGNER_REQUIRED: u8 = 1;

/// 1. Semantic transaction intent (AgentPay side). All public material:
/// 32-byte PUBLIC key arrays and integers — the module has no access to,
/// and no need for, any secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalTransferSpec<'a> {
    /// fee payer + transfer source (public key bytes)
    pub from: &'a [u8; 32],
    /// transfer destination (public key bytes; may equal `from`)
    pub to: &'a [u8; 32],
    /// integer kelvin only (matches the app's canonical money type;
    /// the SDK's SystemInstruction::Transfer carries u64 kelvins)
    pub amount_kelvin: u64,
    /// unix milliseconds, caller-supplied (the SDK's `Message::new`
    /// default clock source is explicitly NOT used — the spike is
    /// deterministic; Q5 clock ownership stays deferred)
    pub valid_from_ms: i64,
    pub config_hash_prefix: u64,
    pub occ: bool,
}

/// 2./3. Canonical message bytes: deterministic legacy-Message encoding
/// per the wire facts in the module doc. Pure Vec<u8> — no serializer
/// behind this that could drift.
pub fn build_canonical_message(spec: &CanonicalTransferSpec<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    // header: required signer (payer), 0 readonly signed, 1 readonly
    // unsigned (the system program) — single-transfer shape.
    out.push(SINGLE_SIGNER_REQUIRED);
    out.push(0);
    out.push(1);
    // account_keys: fee payer first; destination next unless it
    // dedups with the payer; system program last.
    let self_transfer = spec.from == spec.to;
    let key_count: u16 = if self_transfer { 2 } else { 3 };
    short_vec_len(key_count, &mut out);
    out.extend_from_slice(spec.from);
    if !self_transfer {
        out.extend_from_slice(spec.to);
    }
    out.extend_from_slice(&SYSTEM_PROGRAM_ID);
    // valid_from i64 LE, config_hash_prefix u64 LE, occ bool byte
    out.extend_from_slice(&spec.valid_from_ms.to_le_bytes());
    out.extend_from_slice(&spec.config_hash_prefix.to_le_bytes());
    out.push(u8::from(spec.occ));
    // instructions: exactly one
    short_vec_len(1, &mut out);
    let program_id_index: u8 = key_count as u8 - 1;
    out.push(program_id_index);
    short_vec_len(2, &mut out); // accounts: [from_index, to_index]
    out.push(0);
    out.push(if self_transfer { 0 } else { 1 });
    let mut data = [0u8; TRANSFER_DATA_LEN];
    data[..4].copy_from_slice(&SYSTEM_TRANSFER_DISCRIMINATOR.to_le_bytes());
    data[4..].copy_from_slice(&spec.amount_kelvin.to_le_bytes());
    short_vec_len(TRANSFER_DATA_LEN as u16, &mut out);
    out.extend_from_slice(&data);
    out
}

/// The hash/signature BOUNDARY view (G6): these are the exact bytes the
/// SDK signs for the fee-payer (Transaction::sign → sign_message over
/// the serialized message). Naming it `signing_bytes` documents the
/// boundary; this module never signs anything.
pub fn canonical_signing_bytes(spec: &CanonicalTransferSpec<'_>) -> Vec<u8> {
    build_canonical_message(spec)
}

/// 3. (envelope) Transaction-level bytes with the signature slots
/// pre-filled as zeros — mirrors the SDK `Transaction::new_unsigned`
/// behavior pinned by the G_tx_unsigned fixture: short-vec count =
/// num_required_signatures, each slot 64 zero bytes, then the message.
/// A real signer fills the slots OUTSIDE this module (signing stays
/// where it is: CLI today, enclave lane only after G-15 closes).
pub fn unsigned_transaction_envelope(spec: &CanonicalTransferSpec<'_>) -> Vec<u8> {
    let message = build_canonical_message(spec);
    let mut out = Vec::new();
    short_vec_len(u16::from(SINGLE_SIGNER_REQUIRED), &mut out);
    out.extend_from_slice(&[0u8; 64]);
    out.extend_from_slice(&message);
    out
}

// ---------------------------------------------------------------------------
// strict decoder (evidence tool: round-trips the builder and parses SDK
// fixtures, including multi-instruction ones the builder does not emit)
// ---------------------------------------------------------------------------

/// Decoded canonical message — public, integer fields only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedMessage {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<[u8; 32]>,
    pub valid_from_ms: i64,
    pub config_hash_prefix: u64,
    pub occ: bool,
    pub instructions: Vec<DecodedInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecodedInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Failure of a strict decode. Every arm means "this is NOT provably a
/// canonical message" — the decoder NEVER guesses (same discipline as
/// `system_transfer_amount`, which returns None for any other shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    LengthOverflow,
    ShortVecTruncated,
    /// trailing unconsumed bytes after the last declared field
    TrailingBytes,
    /// a length prefix used a non-canonical (overlong) encoding
    NonCanonicalLength,
    /// bool field other than 0/1 — never guessed
    InvalidBool,
}

/// 7-bit-group compact u16 decoder (the inverse of `short_vec_len`,
/// mirroring rialo-s-short-vec semantics).
fn short_vec_read_len(bytes: &[u8], at: &mut usize) -> Result<usize, DecodeError> {
    let start = *at;
    let mut val: u32 = 0;
    for shift in (0..21).step_by(7) {
        let b = *bytes.get(*at).ok_or(DecodeError::ShortVecTruncated)?;
        *at += 1;
        val |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            if val > u16::MAX as u32 {
                return Err(DecodeError::LengthOverflow);
            }
            // strictness: only the CANONICAL encoding round-trips.
            // Re-encode and require byte-for-byte equality — overlong
            // forms (e.g. 0x80 0x00 for 0) are rejected, never guessed.
            let mut re = Vec::new();
            short_vec_len(val as u16, &mut re);
            if re[..] != bytes[start..*at] {
                return Err(DecodeError::NonCanonicalLength);
            }
            return Ok(val as usize);
        }
    }
    Err(DecodeError::LengthOverflow)
}

/// Decode the message portion (starting at offset 0 of the message
/// bytes). Envelope-level caller: strip the signature section first
/// (`decode_transaction_envelope`).
pub fn decode_canonical_message(bytes: &[u8]) -> Result<DecodedMessage, DecodeError> {
    let mut at = 0usize;
    let take = |n: usize, at: &mut usize| -> Result<&[u8], DecodeError> {
        let end = *at + n;
        let s = bytes.get(*at..end).ok_or(DecodeError::Truncated)?;
        *at = end;
        Ok(s)
    };
    let header = take(3, &mut at)?;
    let num_keys = short_vec_read_len(bytes, &mut at)?;
    let mut account_keys = Vec::with_capacity(num_keys.min(64));
    for _ in 0..num_keys {
        let k: &[u8; 32] = take(32, &mut at)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        account_keys.push(*k);
    }
    let valid_from_ms = i64::from_le_bytes(take(8, &mut at)?.try_into().unwrap());
    let config_hash_prefix = u64::from_le_bytes(take(8, &mut at)?.try_into().unwrap());
    let occ_byte = take(1, &mut at)?[0];
    if occ_byte > 1 {
        return Err(DecodeError::InvalidBool); // bool must be 0/1 — never guess
    }
    let ix_count = short_vec_read_len(bytes, &mut at)?;
    let mut instructions = Vec::with_capacity(ix_count.min(64));
    for _ in 0..ix_count {
        let program_id_index = take(1, &mut at)?[0];
        let acct_len = short_vec_read_len(bytes, &mut at)?;
        let accounts: Vec<u8> = take(acct_len, &mut at)?.to_vec();
        let data_len = short_vec_read_len(bytes, &mut at)?;
        let data: Vec<u8> = take(data_len, &mut at)?.to_vec();
        instructions.push(DecodedInstruction {
            program_id_index,
            accounts,
            data,
        });
    }
    if at != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(DecodedMessage {
        num_required_signatures: header[0],
        num_readonly_signed: header[1],
        num_readonly_unsigned: header[2],
        account_keys,
        valid_from_ms,
        config_hash_prefix,
        occ: occ_byte == 1,
        instructions,
    })
}

/// Decode a full transaction envelope: signature section + message.
/// Signature BYTES are returned opaquely (public data; never interpreted
/// — verifying them would need ed25519 machinery this spike does not add).
pub fn decode_transaction_envelope(
    bytes: &[u8],
) -> Result<(Vec<Vec<u8>>, DecodedMessage), DecodeError> {
    let mut at = 0usize;
    let count = short_vec_read_len(bytes, &mut at)?;
    let mut signatures = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        let s: &[u8] = bytes.get(at..at + 64).ok_or(DecodeError::Truncated)?;
        at += 64;
        signatures.push(s.to_vec());
    }
    let msg = decode_canonical_message(&bytes[at..])?;
    Ok((signatures, msg))
}

/// Append a compact-u16 short-vec length prefix. Exactly the
/// `ShortU16::serialize` loop from rialo-s-short-vec-0.18.1 (read from
/// source; continuation bit 0x80 on all but the last group).
pub fn short_vec_len(len: u16, out: &mut Vec<u8>) {
    let mut rem_val = len;
    loop {
        let mut elem = (rem_val & 0x7f) as u8;
        rem_val >>= 7;
        if rem_val == 0 {
            out.push(elem);
            break;
        } else {
            elem |= 0x80;
            out.push(elem);
        }
    }
}

#[cfg(test)]
#[path = "_i2canonical_tests.rs"]
mod i2_tests;
