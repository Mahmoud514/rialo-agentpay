//! rialo_tx_signers — PHASE 8 Item 10: the canonical transaction-signer
//! boundary for Rialo transaction signing.
//!
//! Ground truth this module models (verified against the existing code,
//! not planned): signing itself is performed EXTERNALLY by the `rialo`
//! CLI (`RialoConfig::transfer` in rialo.rs) — the server never produces
//! a signature in-process. What the server DOES have to be canonical is
//! the answer to "which keypair reference is allowed to sign THIS
//! authorized payment". Before this module that answer was implicit
//! folklore: a bare `agent_wallet_path(dir, uuid)` join inside each money
//! core. This module makes it a named boundary:
//!
//!   * [`TxSigner`] is the canonical signer identity. It is deliberately
//!     NOT the agent identity, NOT the credential identity
//!     (`agent_credentials` authenticates principals; it never signs),
//!     NOT the owner identity, NOT a policy object. A signer is exactly
//!     one of two wallet-backed kinds and carries NO key material — only
//!     a canonical id and (for agents) the PUBLIC address that the wallet
//!     file provably belongs to.
//!   * [`TxSigner::keypair_reference`] is the ONLY sanctioned way to turn
//!     a signer into the keypair FILE REFERENCE handed to the CLI.
//!     Directories are always caller-supplied (the money cores receive
//!     `wallet_dir` exactly as before), so this module never hard-codes
//!     `artifact/...` and the structural anti-pattern tests keep passing.
//!   * [`verify_agent_public_address`] is the deterministic hard check
//!     linking signer ↔ keypair file: it reads the file's PUBLIC key
//!     only — via [`read_pubkey_address_only`], a strict pubkey-only
//!     reader that parses the canonical 64-byte JSON container and
//!     materializes NO private key half (no `SigningKey`, no `Keypair`)
//!     in the verification path (PHASE 9 I-6) — and compares against
//!     the record's address. Outcomes are explicit
//!     ([`SignerError`]); there is no fallback signer anywhere in this
//!     module.
//!   * [`SignerRecord`] is the minimal persisted linkage attached to a
//!     payment intent at the Confirmed commit — kind + public address.
//!     It answers "who/what signer was selected for the transaction that
//!     this record's response carries the signature of". No secrets, no
//!     paths, speculative fields refused.
//!
//! What this module is NOT (later items, deliberately absent): no HSM /
//! TEE boundary (Item 13), no private-key isolation mechanism (Item 14),
//! no new signing abstraction or Latch integration (separate architecture
//! item), no key rotation. It also does NOT weaken anything: the policy /
//! lifecycle / limits gates run BEFORE any signer resolution in both
//! money cores, and the signer boundary never re-orders them.

use serde::{Deserialize, Serialize};
use std::path::{Path as FsPath, PathBuf};
use uuid::Uuid;

use super::agents::parse_agent_id;

/// The canonical signer of a Rialo transaction. Two kinds exist because
/// exactly two wallet stores do: human wallets (`artifact/wallets/`,
/// keyed by GitHub user id — FROZEN surface, referenced here by identity
/// only) and agent wallets (`artifact/agent_wallets/`, one independently
/// minted keypair per agent id). Variants can never be conflated: the
/// reference filename formula differs and resolution in a money core
/// structurally accepts only the Agent kind.
#[derive(Clone, PartialEq, Eq)]
pub enum TxSigner {
    /// The human owner's persisted wallet (identity: GitHub user id).
    /// Displayed address lives with the wallet cache in server.rs; this
    /// identity form exists so signer/user identities can be told apart
    /// in code and tests — it is NOT usable inside the agent money cores.
    /// The frozen user-lane handlers do not construct it (out of Item 10
    /// scope); the canonical boundary still has to NAME both signer
    /// kinds, so this variant is exercised by the focused test shard and
    /// consumed by later items that rewire the user lane.
    #[allow(dead_code)]
    User { user_id: u64 },
    /// An agent's own independently keyed wallet (identity: canonical
    /// lowercase UUIDv4 + the PUBLIC address recorded for it).
    Agent {
        agent_id: Uuid,
        /// public key address only — never key material
        address: String,
    },
}

impl std::fmt::Debug for TxSigner {
    /// Manual Debug: public identity fields only. There is nothing else
    /// on the type to leak, and this keeps the shape stable if fields
    /// are ever added.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxSigner::User { user_id } => f
                .debug_struct("TxSigner::User")
                .field("kind", &"user_wallet")
                .field("user_id", user_id)
                .finish(),
            TxSigner::Agent { agent_id, address } => f
                .debug_struct("TxSigner::Agent")
                .field("kind", &"agent_wallet")
                .field("agent_id", agent_id)
                .field("address", address)
                .finish(),
        }
    }
}

/// Deterministic, fieldless signer-boundary failures. No variant ever
/// carries path bytes beyond what the caller already owns, and no
/// variant implies a retry against a different signer: an error here is
/// terminal for the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
    /// The identity/address could not form a canonical signer (non
    /// canonical UUID, empty/blank public address). Nothing was touched
    /// on disk.
    InvalidReference,
    /// The signer's keypair reference does not exist in the supplied
    /// wallet directory.
    NotFound,
    /// The reference exists but is not a usable regular file, or its
    /// keypair container cannot be parsed by the established reader.
    Unavailable,
    /// The keypair at the reference does not belong to this signer's
    /// recorded public identity. The operation MUST abort — switching
    /// wallets or signing with the unverified key would be a fallback.
    Mismatch,
}

/// Minimal persisted linkage written onto a payment intent at the
/// Confirmed commit: the canonical signer that produced the signature
/// inside the same record's response. `address` is public key material —
/// the wallet address — never any secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignerRecord {
    /// "agent_wallet" today; user-lane records are not written because
    /// the user lane mints no intents (frozen design).
    pub kind: String,
    /// public address of the signing wallet (None only if a future kind
    /// has no addressable signer; agent records always carry it)
    #[serde(default)]
    pub address: Option<String>,
}

impl TxSigner {
    /// Canonical agent signer from an agent record's (id, public address)
    /// pair. The id must pass the SAME canonical gate the storage choke
    /// point uses (lowercase UUIDv4, no braces/urn/case games); the
    /// address must be non-blank. Any failure is `InvalidReference` and
    /// is raised before any path is even composed.
    pub fn for_agent_record(agent_id: &str, address: &str) -> Result<Self, SignerError> {
        let id = parse_agent_id(agent_id).ok_or(SignerError::InvalidReference)?;
        if address.trim().is_empty() {
            return Err(SignerError::InvalidReference);
        }
        Ok(TxSigner::Agent {
            agent_id: id,
            address: address.to_string(),
        })
    }

    /// The human-owner signer identity (user lane). Kept here so every
    /// signer of a Rialo transaction in this system has a canonical
    /// named form; the frozen user-wallet handlers remain the only code
    /// that resolves it to a file.
    #[allow(dead_code)] // see the User variant's note (non-test builds)
    pub fn for_user(user_id: u64) -> Self {
        TxSigner::User { user_id }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            TxSigner::User { .. } => "user_wallet",
            TxSigner::Agent { .. } => "agent_wallet",
        }
    }

    /// The signer's public identity as an address string, when the kind
    /// has one. Agent signers always do (guaranteed non-blank by the
    /// constructor).
    pub fn public_address(&self) -> Option<&str> {
        match self {
            TxSigner::Agent { address, .. } => Some(address),
            TxSigner::User { .. } => None,
        }
    }

    /// THE sanctioned identity → keypair-file reference map. Purely
    /// nominal: joins `<dir>/<id>.json` from the canonical id components
    /// (the exact on-disk layout the CLI already consumes). The directory
    /// is ALWAYS supplied by the caller (the money cores pass their
    /// `wallet_dir`); this function never resolves one itself, so the
    /// structural "never touches artifact paths" guarantees of callers
    /// are unchanged.
    pub fn keypair_reference(&self, wallets_dir: &FsPath) -> PathBuf {
        match self {
            TxSigner::User { user_id } => wallets_dir.join(format!("{user_id}.json")),
            TxSigner::Agent { agent_id, .. } => wallets_dir.join(format!("{agent_id}.json")),
        }
    }

    /// The persisted linkage form (see [`SignerRecord`]).
    pub fn record(&self) -> SignerRecord {
        SignerRecord {
            kind: self.kind().to_string(),
            address: self.public_address().map(|a| a.to_string()),
        }
    }
}

/// Strict pubkey-only verification reader (PHASE 9 I-6):
///
/// * Parses ONLY the canonical 64-byte JSON array container that
///   `rialo_s_keypair::write_keypair` produces (the established writer
///   everywhere in this codebase — server.rs, agent_auth_keys.rs and
///   the CLI fixture pattern all write this exact format).
/// * Accepts exactly 64 elements, each a non-negative integer 0..=255,
///   separated by single commas with optional surrounding whitespace.
/// * Returns ONLY the base58 address of the public half
///   (`bytes[32..64]`). The secret half is copied into a fixed buffer
///   for container-shape validation and then zeroed; NO signing key is
///   ever constructed (`ed25519_dalek::SigningKey` is never named in
///   this module's code — pinned by the structural tests).
/// * Every deviation is a hard `Unavailable`: base58-encoded keys,
///   wrong element counts, non-numeric/negative/>255 elements, and
///   trailing commas all fail closed.
///
/// This deliberately does NOT reuse `rialo_s_keypair::read_keypair`,
/// which materializes the full `Keypair` (secret included) just to
/// expose the public half. The CLI remains the ONLY component that
/// turns the file into a signer (unchanged custody boundary).
pub(crate) fn read_pubkey_address_only<R: std::io::Read>(
    reader: &mut R,
) -> Result<String, SignerError> {
    use rialo_s_pubkey::Pubkey;

    let mut buffer = String::new();
    reader
        .read_to_string(&mut buffer)
        .map_err(|_| SignerError::Unavailable)?;
    let trimmed = buffer.trim();

    // Canonical container only: `[n,n,...,n]` with 64 decimal u8
    // elements. The established writer never emits base58 or empty
    // arrays, so accepting them here would silently widen the parse
    // surface; failing closed is the I-6 contract.
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(SignerError::Unavailable)?;

    let mut private_half = [0u8; 32];
    let mut public = [0u8; 32];
    let result = (|| {
        for (idx, element) in inner.split(',').enumerate() {
            let element = element.trim();
            // `parse::<u8>()` already rejects signs, fractions and
            // >255 values; an empty element (trailing/double comma)
            // fails the same way.
            let byte: u8 = element.parse().map_err(|_| SignerError::Unavailable)?;
            if idx < 32 {
                private_half[idx] = byte;
            } else if idx < 64 {
                public[idx - 32] = byte;
            } else {
                return Err(SignerError::Unavailable); // >64 elements
            }
        }
        // Exactly 64 elements: the loop above saw 64 when the index
        // reached 63; anything else (including 0) is malformed.
        if inner.is_empty() || !inner.contains(',') || inner.split(',').count() != 64 {
            return Err(SignerError::Unavailable);
        }
        Ok(())
    })();
    // The private half is never used beyond shape validation; zeroize
    // it so no transient copy survives this call.
    private_half.fill(0);
    result?;

    // Address-derivation only: Pubkey::from the public half, rendered
    // exactly like `Signer::pubkey()` (base58 Display). The address is
    // public identity material.
    let Ok(address) = Pubkey::try_from(&public[..]) else {
        return Err(SignerError::Unavailable);
    };
    Ok(address.to_string())
}

/// Hard, deterministic signer ↔ keypair-file verification:
///
/// * non-Agent signer asking for an agent check → `Mismatch`
///   (defensive: the money cores only ever construct Agent signers)
/// * missing file → `NotFound`
/// * path is not a regular file / open failure → `Unavailable`
/// * unparseable keypair container → `Unavailable`
/// * file's pubkey ≠ signer's recorded public address → `Mismatch`
///
/// Only the PUBLIC key leaves the file into the comparison
/// ([`read_pubkey_address_only`]); no signing key is ever constructed
/// and nothing is logged, returned, or persisted beyond the public
/// address (PHASE 9 I-6 custody boundary).
pub fn verify_agent_public_address(
    signer: &TxSigner,
    wallets_dir: &FsPath,
) -> Result<(), SignerError> {
    let TxSigner::Agent { address, .. } = signer else {
        return Err(SignerError::Mismatch);
    };
    let path = signer.keypair_reference(wallets_dir);
    match std::fs::File::open(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(SignerError::NotFound),
        Err(_) => return Err(SignerError::Unavailable),
        Ok(mut file) => {
            let pubkey_only = read_pubkey_address_only(&mut file)?;
            if pubkey_only != *address {
                return Err(SignerError::Mismatch);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "_signers10_tests.rs"]
mod tests10;

#[cfg(test)]
#[path = "_custody_i6_tests.rs"]
mod custody_i6_tests;
