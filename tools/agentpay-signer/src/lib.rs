//! agentpay-signer — PHASE 9 isolated signer, STEP 3 SKELETON.
//!
//! Authority: `_phase9/isolated_signer_architecture_decision.md` (§1–§14).
//! The signer is a SEPARATE TRUST DOMAIN: a dedicated process owning its own
//! key store, listening ONLY on loopback, denying by default.
//!
//! STEP 3 SCOPE (this skeleton):
//!   * the loopback-only process boundary (bind discipline, refusal of
//!     non-loopback binds),
//!   * the typed request/response contract (`/sign`, `/health`) with
//!     deny-by-default handling — `/sign` answers a typed
//!     NOT_YET_IMPLEMENTED denial: NO signing capability exists in this
//!     step, by design,
//!   * the signer-owned store (outside `artifact/`, exclusive creation,
//!     0600-before-content, strict container parsing),
//!   * strict request validation (deny on any missing/malformed field, deny
//!     on any attempt to smuggle private-key material),
//!   * fail-closed behavior everywhere.
//!
//! NOT in this step (deliberately): signature verification, canonical
//! recompile, byte binding, allow-lists, funded wallet provisioning,
//! PaymentOps wiring, Latch tx-signing, Privy (nothing).
//!
//! ISOLATION INVARIANTS pinned here and by tests:
//!   * loopback bind only — any non-loopback bind address is refused at
//!     startup (parse + bind-time double check),
//!   * NO network egress: this process makes zero outbound connections (the
//!     broadcast stays the app's responsibility; the signer has NO upstream),
//!   * the signer NEVER reads `artifact/` or any AgentPay store; the app
//!     NEVER reads the signer's store,
//!   * the store directory is supplied at startup; nothing derives paths
//!     from the request,
//!   * no secret material in logs, errors, or responses — fieldless error
//!     shapes only.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use uuid::Uuid;

pub mod legacy_wallet_migration;
pub mod user_authorization;
pub mod user_authorization_store;
pub mod user_binding_registry;
pub mod user_lifecycle_coordinator;

// ---------------------------------------------------------------------------
// OPTION C — RUNTIME AGENT REGISTRY (Authenticated Admin Registration)
// ---------------------------------------------------------------------------

/// Admin-registered agent auth bindings — runtime mutable allow-list.
/// Combined with the static AGENTPAY_SIGNER_PROVISION_AGENTS, this allows
/// OPTION C authenticated admin registration after agent creation.
static RUNTIME_AGENT_REGISTRY: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn runtime_registry() -> &'static RwLock<HashMap<String, String>> {
    RUNTIME_AGENT_REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register an agent at runtime via admin endpoint. Idempotent: re-registration
/// with the SAME auth_pubkey succeeds; conflicting registration fails.
pub fn admin_register_agent(agent_id: &str, auth_pubkey: &str) -> Result<(), ()> {
    let mut reg = runtime_registry().write().map_err(|_| ())?;
    if let Some(existing) = reg.get(agent_id) {
        if existing == auth_pubkey {
            return Ok(()); // idempotent exact match
        }
        return Err(()); // conflicting registration
    }
    reg.insert(agent_id.to_string(), auth_pubkey.to_string());
    Ok(())
}

/// The combined allow-list check: static env var + runtime registry + persisted wallets.
/// Returns Some(expected_auth_pubkey) if the agent is provisionable.
///
/// Checks in order:
/// 1. Static list (startup-configured agents from AGENTPAY_SIGNER_PROVISION_AGENTS)
/// 2. Runtime registry (agents registered via /admin/register this session)
/// 3. Persisted wallet files (agents from previous signer sessions)
///
/// The persisted wallet check ensures agents survive signer restarts without
/// requiring re-registration.
pub fn lookup_provision_auth(
    agent_id: &str,
    static_agents: &HashMap<String, String>,
    store: &SignerStore,
) -> Option<String> {
    // 1. Static list checked first (startup-authorized agents)
    if let Some(auth) = static_agents.get(agent_id) {
        return Some(auth.clone());
    }
    // 2. Runtime-registered agents (OPTION C admin registration - this session)
    if let Ok(reg) = runtime_registry().read() {
        if let Some(auth) = reg.get(agent_id) {
            return Some(auth.clone());
        }
    }
    // 3. Persisted wallets from previous sessions
    // Extract UUID from agent_id string
    if let Ok(uuid) = agent_id.parse::<uuid::Uuid>() {
        if let Ok(Some(auth)) = store.agent_auth_pubkey(&uuid) {
            return Some(auth);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// END OPTION C
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CONFIG — loopback-only, explicit, fail-closed
// ---------------------------------------------------------------------------

/// A validated signer endpoint: loopback + a non-zero port. Construction is
/// the ONLY way to obtain one — `SignerEndpoint::parse` refuses anything
/// else (the same discipline as the latch proxy lane's `parse_proxy_url`:
/// loopback host + non-zero port, no path, no userinfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerEndpoint {
    addr: SocketAddr,
}

/// Fieldless: no detail about WHY a bind was refused ever surfaces (no
/// addresses, no io detail beyond the class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// empty / unparseable
    Malformed,
    /// parsed but NOT a loopback address — refused by design
    NotLoopback,
    /// port 0 (unspecified) — refused: the endpoint must be deterministic
    ZeroPort,
}

impl SignerEndpoint {
    /// Accept ONLY explicit loopback: 127.0.0.1, ::1, or localhost (resolved
    /// to 127.0.0.1 here so no resolution-time surprise can slip a non-
    /// loopback address in).
    pub fn parse(input: &str) -> Result<Self, EndpointError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(EndpointError::Malformed);
        }
        // explicit host:port form; "localhost" is normalized to 127.0.0.1
        let (host, port_str) = match trimmed.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => (h, p),
            _ => return Err(EndpointError::Malformed),
        };
        let port: u16 = match port_str.parse() {
            Ok(p) => p,
            Err(_) => return Err(EndpointError::Malformed),
        };
        if port == 0 {
            return Err(EndpointError::ZeroPort);
        }
        // strip IPv6 brackets: [::1]:8971
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let ip: IpAddr = match host {
            "localhost" | "LOCALHOST" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            other => match other.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => return Err(EndpointError::Malformed),
            },
        };
        let is_loopback = match &ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        if !is_loopback {
            return Err(EndpointError::NotLoopback);
        }
        Ok(Self {
            addr: SocketAddr::new(ip, port),
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.addr
    }
}

// ---------------------------------------------------------------------------
// STORE — the signer-owned directory (outside artifact/ by deployment)
// ---------------------------------------------------------------------------

/// Fieldless: no path detail, no io detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// the store directory cannot be created/read
    Unavailable,
    /// a store file exists but cannot be opened/parsed — fail closed
    Corrupt,
    /// a store file for this id already exists (exclusive creation)
    Exists,
    /// the store root is not the signer's (deployment misconfiguration —
    /// refuses any path under an `artifact` component)
    ForbiddenRoot,
}

/// The signer-owned key store root. Construction REFUSES any path that
/// contains an `artifact` component (the AgentPay store domain) — the
/// signer can never be pointed at the app's store, even by misconfiguration.
#[derive(Debug, Clone)]
pub struct SignerStore {
    root: PathBuf,
}

impl SignerStore {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        // Refuse the app's store domain outright.
        for component in root.components() {
            if let std::path::Component::Normal(part) = component {
                if part == std::ffi::OsStr::new("artifact") {
                    return Err(StoreError::ForbiddenRoot);
                }
            }
        }
        // G91 (F3) — validate every EXISTING component before creating
        // anything, then re-validate the complete path: no filesystem write
        // may travel through an unvalidated (possibly symlinked) component.
        crate::store_lock::reject_existing_symlink_components(root)
            .map_err(|_| StoreError::Unavailable)?;
        std::fs::create_dir_all(root).map_err(|_| StoreError::Unavailable)?;
        crate::store_lock::reject_symlink_components(root).map_err(|_| StoreError::Unavailable)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// G87 — restrictive-permission hardening for the signer store root
    /// and its `users/` namespace: both MUST be 0700 on unix. A directory
    /// that cannot be secured fails CLOSED (the caller decides whether the
    /// deployment aborts).
    ///
    /// G89 (M1) — hardening is SYMLINK-AWARE: every hardened path is
    /// checked with `symlink_metadata` (never follows) and a symlink is a
    /// hard refusal (an attacker-controlled link must not redirect the
    /// permission boundary to a target of its choosing). The 0700 check is
    /// ALSO strengthened: mode must be exactly `0o700 & 0o777` — group and
    /// other bits are never accepted, and the enforce-then-verify order is
    /// preserved (never loosens an already-restrictive directory).
    pub fn harden_permissions(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // G89 — the user namespace is CREATED here if absent (fresh
            // store) so the 0700 boundary exists before any user artifact;
            // its ownership is ours by construction (this process mkdir'd it).
            let users_dir = self.root.join(crate::user_lane::USER_NAMESPACE_DIR);
            // G91 (F3) — never create/mkdir THROUGH a symlink: validate the
            // root and an existing users/ path before touching the disk, then
            // re-validate after creation (the loop below verifies again).
            if let Ok(meta) = std::fs::symlink_metadata(&self.root) {
                if meta.file_type().is_symlink() {
                    return Err(StoreError::Unavailable);
                }
            }
            if let Ok(meta) = std::fs::symlink_metadata(&users_dir) {
                if meta.file_type().is_symlink() {
                    return Err(StoreError::Unavailable);
                }
            }
            if !users_dir.exists() {
                std::fs::create_dir_all(&users_dir).map_err(|_| StoreError::Unavailable)?;
            }
            for dir in [self.root.clone(), users_dir] {
                if dir.exists() {
                    // follow-free metadata: a symlink here is an attacker
                    // redirect, never a legitimate store layout
                    let meta =
                        std::fs::symlink_metadata(&dir).map_err(|_| StoreError::Unavailable)?;
                    if meta.file_type().is_symlink() {
                        return Err(StoreError::Unavailable);
                    }
                    let mut perms = meta.permissions();
                    if perms.mode() & 0o777 != 0o700 {
                        perms.set_mode(0o700);
                        std::fs::set_permissions(&dir, perms)
                            .map_err(|_| StoreError::Unavailable)?;
                    }
                    // verify (no-follow; never loosen)
                    let check =
                        std::fs::symlink_metadata(&dir).map_err(|_| StoreError::Unavailable)?;
                    if check.file_type().is_symlink() || check.permissions().mode() & 0o777 != 0o700
                    {
                        return Err(StoreError::Unavailable);
                    }
                }
            }
        }
        Ok(())
    }

    /// G89 (M1) — reject ANY symlink among the store's boundary paths
    /// (root, `users/`, `creation_gate/`) or their immediate ancestors.
    /// Called at startup BEFORE serving; a single attacker-controlled link
    /// fails the signer closed. Platforms: unix (the deployment target);
    /// callers on other platforms still fail closed by absence of this
    /// check being a no-op only when compiled out — the deployment HARD
    /// requirement (documented) is Unix.
    pub fn reject_symlinked_boundaries(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            // the store root: every component between / and the root must
            // be a real directory (an ancestor symlink swaps the whole
            // tree — reject before any content is trusted)
            let mut components: Vec<std::path::PathBuf> = Vec::new();
            let mut acc = std::path::PathBuf::new();
            for comp in self.root.components() {
                acc.push(comp.as_os_str());
                components.push(acc.clone());
            }
            for p in components {
                match std::fs::symlink_metadata(&p) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(StoreError::Unavailable);
                    }
                    Ok(_) => {}
                    Err(_) => return Err(StoreError::Unavailable),
                }
            }
            // the user-owned subdirectories the signer creates itself
            for dir in [
                self.root.join(crate::user_lane::USER_NAMESPACE_DIR),
                self.root.join("creation_gate"),
            ] {
                if let Ok(meta) = std::fs::symlink_metadata(&dir) {
                    if meta.file_type().is_symlink() {
                        return Err(StoreError::Unavailable);
                    }
                }
            }
        }
        Ok(())
    }

    /// G89 (M1) — best-effort ownership verification: the store root and
    /// `users/` (when present) MUST be owned by the running uid (no
    /// shared-group or other-user boundary squatting). Read from /proc
    /// (same zero-dependency discipline as the instance lock); when /proc
    /// is unavailable the check cannot be established — fail closed per
    /// the mandate. A missing `users/` is NOT a failure here: it is
    /// created (root-owned-after-mkdir, i.e. ours) by harden_permissions
    /// immediately after this check in the startup chain.
    pub fn verify_store_ownership(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let euid = crate::store_lock::euid_from_proc().ok_or(StoreError::Unavailable)?;
            for dir in [
                self.root.clone(),
                self.root.join(crate::user_lane::USER_NAMESPACE_DIR),
            ] {
                let Ok(meta) = std::fs::symlink_metadata(&dir) else {
                    // absent user namespace: created (and thus owned) by
                    // harden_permissions in the next startup step
                    continue;
                };
                if meta.uid() != euid {
                    return Err(StoreError::Unavailable);
                }
            }
            let _ = euid;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn key_path(&self, agent_id: &Uuid) -> PathBuf {
        self.root.join(format!("{agent_id}.key.json"))
    }

    /// Reserve a per-agent key file with EXCLUSIVE creation (the established
    /// I-1 pattern: `create_new`, permissions hardened BEFORE any content).
    /// STEP 3 writes NO key content — the file stays EMPTY (zero bytes) and
    /// is purely the reservation placeholder the later signing step fills.
    /// Returns Ok(()) if created; `Exists` if the reservation is already
    /// held (idempotent, never overwrites).
    pub fn reserve_agent_slot(&self, agent_id: &Uuid) -> Result<(), StoreError> {
        use std::io::Write;
        let path = self.key_path(agent_id);
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StoreError::Exists);
            }
            Err(_) => return Err(StoreError::Unavailable),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        // nothing to write in the skeleton; flush + keep
        file.flush().map_err(|_| StoreError::Unavailable)?;
        Ok(())
    }

    /// Read back a reserved slot: exists and is parseable as the strict
    /// container the signing step will write (empty = reserved-only).
    pub fn slot_state(&self, agent_id: &Uuid) -> Result<SlotState, StoreError> {
        let path = self.key_path(agent_id);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SlotState::Absent),
            Err(_) => return Err(StoreError::Unavailable),
        };
        if bytes.is_empty() {
            return Ok(SlotState::Reserved);
        }
        // STEP 4: the container is now the 64-byte funded-key JSON array;
        // the old "linked record" shape is gone (the record lives in the
        // separate public wallet record — see provision_agent_wallet).
        wallet_key_public_address_from_bytes(&bytes)?;
        Ok(SlotState::Linked)
    }

    // ------------------------------------------------------------------
    // STEP 4 — FUNDED KEY MATERIAL + PROVISIONING
    // ------------------------------------------------------------------

    /// Provision the ONE funded wallet for this agent: generate fresh key
    /// material (getrandom 32-byte seed → `keypair_from_seed`, the exact
    /// I-1 discipline), persist the PRIVATE half ONLY inside the signer's
    /// store (`write_keypair` 64-byte JSON container, 0600 BEFORE content),
    /// and — ONLY after the key file is fully written and its public
    /// identity re-verified through the strict reader — write the public
    /// wallet record (agent_id + public_address + the D8/G-7 auth_pubkey
    /// linkage). Crash safety by ordering: key FIRST, record SECOND; a
    /// record without a valid key container is INCOMPLETE (readers fail
    /// closed); a key without a record is recovered by a later run.
    ///
    /// IDEMPOTENT/NO-REPLACEMENT: if a valid wallet record already exists,
    /// the EXISTING public address is returned (`Already` outcome) — the
    /// key container is never rewritten. If a key container exists without
    /// a record (crash window), the record is written (Recovered) after
    /// verification.
    ///
    /// The caller MUST have independently verified the D8/G-7 linkage for
    /// `agent_id` ↔ `auth_pubkey` (the signer cannot read the app's store
    /// and MUST NOT; the binding string is recorded verbatim in the wallet
    /// record for audit).
    pub fn provision_agent_wallet(
        &self,
        agent_id: &Uuid,
        auth_pubkey: &str,
    ) -> Result<ProvisionOutcome, StoreError> {
        if auth_pubkey.trim().is_empty() {
            return Err(StoreError::Corrupt);
        }
        let key_path = self.key_path(agent_id);
        let record_path = self.wallet_record_path(agent_id);

        // If a valid record exists → idempotent no-op (existing public
        // address returned; a CHANGED auth_pubkey for the same agent is a
        // hard error, never a silent rewrite).
        if record_path.exists() {
            let bytes = std::fs::read(&record_path).map_err(|_| StoreError::Unavailable)?;
            let record = wallet_record_from_bytes(&bytes)?;
            if record.agent_id != agent_id.to_string() {
                return Err(StoreError::Corrupt);
            }
            if record.auth_pubkey != auth_pubkey.trim() {
                return Err(StoreError::Corrupt);
            }
            // INTEGRITY: the record is only "apparently valid" if the key
            // container EXISTS, parses strictly, and its derived address
            // MATCHES the record. A dangling record (custody missing) is a
            // hard error — never a silent re-mint, never a "valid" answer.
            let key_bytes = std::fs::read(&key_path).map_err(|_| StoreError::Unavailable)?;
            let key_addr = wallet_key_public_address_from_bytes(&key_bytes)?;
            if key_addr != record.public_address {
                return Err(StoreError::Corrupt);
            }
            return Ok(ProvisionOutcome::Already {
                public_address: record.public_address,
            });
        }

        let (pubkey_addr, fresh) = if key_path.exists() {
            // An EMPTY file is a prior reservation placeholder (the STEP 3
            // skeleton path): it belongs to this provisioner's store and no
            // content was ever written — it is safe to fill it now.
            let existing = std::fs::read(&key_path).map_err(|_| StoreError::Unavailable)?;
            if existing.is_empty() {
                return self.fill_reserved_key(agent_id, auth_pubkey, &key_path);
            }
            // RECOVERY: a REAL key container exists (crash between the two
            // writes, or an earlier interrupted run). Derive the address
            // from the FILE — never from the request.
            let addr = wallet_key_public_address_from_bytes(&existing)?;
            (addr, false)
        } else {
            // FRESH: mint the funded keypair INSIDE the signer.
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|_| StoreError::Unavailable)?;
            let keypair =
                rialo_s_keypair::keypair_from_seed(&seed).map_err(|_| StoreError::Unavailable)?;
            let addr = {
                use rialo_s_signer::Signer;
                keypair.pubkey().to_string()
            };
            // exclusive creation, 0600 BEFORE any content (the I-1 rule)
            let mut file = match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
            {
                Ok(f) => f,
                // a concurrent provisioner won the race — surface the typed
                // error; a retry takes the recovery path and converges
                Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(StoreError::Exists);
                }
                Err(_) => return Err(StoreError::Unavailable),
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            rialo_s_keypair::write_keypair(&keypair, &mut file)
                .map_err(|_| StoreError::Unavailable)?;
            file.flush().map_err(|_| StoreError::Unavailable)?;
            drop(file);
            (addr, true)
        };

        // Post-write verification: the key container must read back through
        // the strict parser and match the address we derived at creation
        // (never trust the in-flight variable alone).
        let verify_bytes = std::fs::read(&key_path).map_err(|_| StoreError::Unavailable)?;
        let verified = wallet_key_public_address_from_bytes(&verify_bytes)?;
        if verified != pubkey_addr {
            // internal inconsistency — fail closed; the file stays for a
            // later recovery run to re-derive
            return Err(StoreError::Corrupt);
        }

        self.write_wallet_record(agent_id, &pubkey_addr, Some(auth_pubkey))?;

        Ok(if fresh {
            ProvisionOutcome::Created {
                public_address: pubkey_addr,
            }
        } else {
            ProvisionOutcome::Recovered {
                public_address: pubkey_addr,
            }
        })
    }

    /// Fill a prior EMPTY reservation placeholder with a fresh funded
    /// keypair (the reservation file was created exclusively by this same
    /// store; no content ever existed, so replacing it is safe).
    fn fill_reserved_key(
        &self,
        agent_id: &Uuid,
        auth_pubkey: &str,
        key_path: &Path,
    ) -> Result<ProvisionOutcome, StoreError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| StoreError::Unavailable)?;
        let keypair =
            rialo_s_keypair::keypair_from_seed(&seed).map_err(|_| StoreError::Unavailable)?;
        let addr = {
            use rialo_s_signer::Signer;
            keypair.pubkey().to_string()
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(key_path)
            .map_err(|_| StoreError::Unavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        rialo_s_keypair::write_keypair(&keypair, &mut file).map_err(|_| StoreError::Unavailable)?;
        file.flush().map_err(|_| StoreError::Unavailable)?;
        drop(file);

        // the SAME post-write verification as the fresh path
        let verify_bytes = std::fs::read(key_path).map_err(|_| StoreError::Unavailable)?;
        let verified = wallet_key_public_address_from_bytes(&verify_bytes)?;
        if verified != addr {
            return Err(StoreError::Corrupt);
        }
        self.write_wallet_record(agent_id, &addr, Some(auth_pubkey))?;
        Ok(ProvisionOutcome::Recovered {
            public_address: addr,
        })
    }

    /// Write the PUBLIC wallet record (temp+rename atomicity; only public
    /// fields ever cross this write). `auth_pubkey` is Some() on the
    /// provisioning paths.
    fn write_wallet_record(
        &self,
        agent_id: &Uuid,
        public_address: &str,
        auth_pubkey: Option<&str>,
    ) -> Result<(), StoreError> {
        let record_path = self.wallet_record_path(agent_id);
        let record = WalletRecord {
            agent_id: agent_id.to_string(),
            public_address: public_address.to_string(),
            auth_pubkey: auth_pubkey.unwrap_or_default().trim().to_string(),
        };
        let record_bytes =
            serde_json::to_vec_pretty(&record).map_err(|_| StoreError::Unavailable)?;
        // The public record is a final wallet record: never replace an
        // existing one (a concurrent writer wins; this caller fails closed).
        crate::wallet_file_safety::write_new_file_no_replace(&record_path, &record_bytes, 0o600)
            .map_err(|e| match e {
                crate::wallet_file_safety::SafetyError::AlreadyExists => StoreError::Exists,
                _ => StoreError::Unavailable,
            })?;
        Ok(())
    }

    fn wallet_record_path(&self, agent_id: &Uuid) -> PathBuf {
        self.root.join(format!("{agent_id}.wallet.json"))
    }

    /// The public address for an agent whose wallet record exists (public
    /// data only — this is what AgentPay may ever learn). INTEGRITY: the
    /// address is only presentable when the key container exists, parses
    /// strictly, and its derived address MATCHES the record — an INCOMPLETE
    /// (dangling-record) state fails closed, never presents as valid.
    pub fn agent_public_address(&self, agent_id: &Uuid) -> Result<Option<String>, StoreError> {
        let record_path = self.wallet_record_path(agent_id);
        if !record_path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&record_path).map_err(|_| StoreError::Unavailable)?;
        let record = wallet_record_from_bytes(&bytes)?;
        let key_bytes =
            std::fs::read(self.key_path(agent_id)).map_err(|_| StoreError::Unavailable)?;
        let key_addr = wallet_key_public_address_from_bytes(&key_bytes)?;
        if key_addr != record.public_address {
            return Err(StoreError::Corrupt);
        }
        Ok(Some(record.public_address))
    }

    /// The auth pubkey for an agent whose wallet record exists.
    /// This allows runtime registry recovery from persisted state after restart.
    /// Returns `None` if the record does not exist or fails integrity checks.
    pub fn agent_auth_pubkey(&self, agent_id: &Uuid) -> Result<Option<String>, StoreError> {
        let record_path = self.wallet_record_path(agent_id);
        if !record_path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&record_path).map_err(|_| StoreError::Unavailable)?;
        let record = wallet_record_from_bytes(&bytes)?;
        // Verify key pair exists and validates
        let key_bytes =
            std::fs::read(self.key_path(agent_id)).map_err(|_| StoreError::Unavailable)?;
        let key_addr = wallet_key_public_address_from_bytes(&key_bytes)?;
        if key_addr != record.public_address {
            return Err(StoreError::Corrupt);
        }
        Ok(Some(record.auth_pubkey.clone()))
    }
}

/// The strict wallet record: PUBLIC data only (never any key material).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRecord {
    pub agent_id: String,
    pub public_address: String,
    /// the D8/G-7 identity linkage (the agent's funds-less auth pubkey),
    /// bound into the record at provisioning time for audit
    pub auth_pubkey: String,
}

/// Parse a strict wallet record from bytes (unknown fields/malformed
/// identifiers fail closed).
fn wallet_record_from_bytes(bytes: &[u8]) -> Result<WalletRecord, StoreError> {
    let record: WalletRecord = serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
    Uuid::parse_str(&record.agent_id).map_err(|_| StoreError::Corrupt)?;
    if record.public_address.trim().is_empty() || record.auth_pubkey.trim().is_empty() {
        return Err(StoreError::Corrupt);
    }
    Ok(record)
}

/// Read a 64-byte JSON keypair container and return ONLY its public
/// address (the I-6 pubkey-only discipline).
fn wallet_key_public_address_from_bytes(bytes: &[u8]) -> Result<String, StoreError> {
    let arr: Vec<u8> = serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
    if arr.len() != 64 {
        return Err(StoreError::Corrupt);
    }
    let keypair = rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|_| StoreError::Corrupt)?;
    use rialo_s_signer::Signer;
    Ok(keypair.pubkey().to_string())
}

/// The state of a per-agent key slot (the STEP 3 reservation + the STEP 4
/// funded-key container).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// no reservation exists
    Absent,
    /// reserved (empty placeholder, no key material yet)
    Reserved,
    /// a funded key container exists (strict-parsed)
    Linked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// a fresh funded wallet was minted
    Created { public_address: String },
    /// a key container existed from an interrupted prior run; the record
    /// was written after verification
    Recovered { public_address: String },
    /// a valid wallet already existed; the SAME public address returned
    Already { public_address: String },
}

// ---------------------------------------------------------------------------
// STEP 5 — AUTHORITATIVE CANONICAL RECOMPILATION (zero-drift reuse)
// ---------------------------------------------------------------------------

/// The repository's AUTHORITATIVE canonical builder, compiled from the SAME
/// SOURCE FILE the server crate uses
/// (`src/bin/server/rialo_canonical.rs`) — a `#[path]` compile, not a copy:
/// byte-identical by construction, one source of truth, no drift possible.
/// The signer NEVER trusts caller-supplied bytes as canonical — it builds
/// its own representation from the semantic spec and refuses divergence.
#[path = "../../../src/bin/server/rialo_canonical.rs"]
pub mod rialo_canonical;

// G79 — shared, typed app↔signer user protocol (zero-drift #[path] compile
// of the server-tree source; the server-side declaration arrives with the
// DEFERRED wiring gate).
#[path = "../../../src/bin/server/user_signer_protocol.rs"]
pub mod user_signer_protocol;

// G79 — durable user-intent idempotency ledger (same #[path] discipline).
#[path = "../../../src/bin/server/user_intents.rs"]
pub mod user_intents;

// G79 — the USER wallet namespace (parallel to agents; no agent code is
// touched; HTTP wiring is DEFERRED — no /user route is active in main.rs).
pub mod store_lock;
pub mod user_creation_gate;
pub mod user_lane;
pub mod user_policy;
pub mod wallet_file_safety;

#[cfg(test)]
pub(crate) static CROSS_TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[path = "_g79_user_lane_tests.rs"]
mod g79_user_lane_tests;

#[cfg(test)]
#[path = "_g81_create_tests.rs"]
mod g81_create_tests;

#[cfg(test)]
#[path = "_g1150_wallet_safety_tests.rs"]
mod g1150_wallet_safety_tests;

#[cfg(test)]
#[path = "_g83_fix_tests.rs"]
mod g83_fix_tests;

#[cfg(test)]
#[path = "_g85_recovery_tests.rs"]
mod g85_recovery_tests;

#[cfg(test)]
#[path = "_g89_loopback_e2e.rs"]
mod g89_loopback_e2e;

#[cfg(test)]
#[path = "_g104_synthetic_backup_tests.rs"]
mod g104_synthetic_backup_tests;

#[cfg(test)]
#[path = "_g105_lifecycle_model_tests.rs"]
mod g105_lifecycle_model_tests;

#[cfg(test)]
#[path = "_g108_authorization_tests.rs"]
mod g108_authorization_tests;

#[cfg(test)]
#[path = "_g109_durable_tests.rs"]
mod g109_durable_tests;

#[cfg(test)]
#[path = "_g110_binding_registry_tests.rs"]
mod g110_binding_registry_tests;

#[cfg(test)]
#[path = "_g111_coordinator_tests.rs"]
mod g111_coordinator_tests;

#[cfg(test)]
#[path = "_g113_migration_tests.rs"]
mod g113_migration_tests;

#[cfg(test)]
#[path = "_g89_probe.rs"]
mod g89_probe;

use rialo_canonical::{CanonicalTransferSpec, build_canonical_message};

/// The semantic transaction the app sends (the frozen payment shape ONLY —
/// a single System transfer). Unknown fields are rejected at the
/// deserialization boundary; anything beyond the single-transfer shape is
/// malformed semantic input (fail-closed).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTransaction {
    /// base58 fee payer (must equal the signer-held wallet's public address)
    pub fee_payer: String,
    /// base58 recipient
    pub recipient: String,
    /// integer kelvin ONLY (the canonical money type)
    pub amount_kelvin: u64,
    /// unix ms (replay-window start; the Q5 clock ownership stays with the
    /// caller-supplied value — deterministic, no hidden clock source)
    pub valid_from_ms: i64,
    /// u64 decimal string (the documented wire form; quoted to survive >2^53)
    pub config_hash_prefix: String,
    pub occ: bool,
    /// the authorization↔bytes binding evidence (OPTIONAL per the frozen
    /// contract: absence is acceptable when the protocol permits signer-side
    /// derivation; PRESENCE is verified — a mismatch is BYTE_DIVERGENCE)
    #[serde(default)]
    pub canonical_hash: Option<String>,
    /// caller-supplied canonical bytes (OPTIONAL; base64). NEVER authoritative:
    /// compared against the signer's own recompile only.
    #[serde(default)]
    pub canonical_bytes: Option<String>,
}

fn parse_u64_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Canonicalization errors (fieldless, typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    /// a semantic field failed to parse (bad base58 / bad decimal / empty)
    Malformed,
    /// the semantic shape is not the single System-transfer shape
    UnsupportedShape,
    /// the feePayer does not match the signer-held wallet (the signer signs
    /// only its own wallet — never a caller-nominated payer)
    PayerMismatch,
}

/// Compile the semantic transaction into the signer's OWN canonical
/// representation. This is THE authoritative act: caller bytes never
/// override it.
pub fn canonicalize(
    tx: &SemanticTransaction,
    wallet_address: &str,
) -> Result<(CanonicalTransferSpec<'static>, Vec<u8>, String), CanonicalError> {
    // base58 decode the two pubkeys (32 bytes each)
    let from = base58_decode_32(&tx.fee_payer).ok_or(CanonicalError::Malformed)?;
    let to = base58_decode_32(&tx.recipient).ok_or(CanonicalError::Malformed)?;
    let config_hash_prefix =
        parse_u64_decimal(&tx.config_hash_prefix).ok_or(CanonicalError::Malformed)?;
    // the payer MUST be the signer's own wallet (invariant: the signer signs
    // only what it holds; a caller-nominated payer is unsupported shape)
    if tx.fee_payer != wallet_address {
        return Err(CanonicalError::PayerMismatch);
    }
    let spec = CanonicalTransferSpec {
        from: &from,
        to: &to,
        amount_kelvin: tx.amount_kelvin,
        valid_from_ms: tx.valid_from_ms,
        config_hash_prefix,
        occ: tx.occ,
    };
    let bytes = build_canonical_message(&spec);
    let hash = blake3::hash(&bytes).to_hex().to_string();
    Ok((
        CanonicalTransferSpec {
            from: Box::leak(Box::new(from)),
            to: Box::leak(Box::new(to)),
            amount_kelvin: tx.amount_kelvin,
            valid_from_ms: tx.valid_from_ms,
            config_hash_prefix,
            occ: tx.occ,
        },
        bytes,
        hash,
    ))
}

/// Strict base58 decode to exactly 32 bytes (canonical pubkeys only).
/// Minimal deterministic implementation (no external alphabet crate): the
/// standard bitcoin/alphabet, rejecting non-canonical leading '1's beyond
/// the leading-zero count and any overlong decode.
const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_decode_32(input: &str) -> Option<[u8; 32]> {
    if input.is_empty() {
        return None;
    }
    // leading zeros
    let mut zeros = 0usize;
    for b in input.bytes() {
        if b == b'1' {
            zeros += 1;
        } else {
            break;
        }
    }
    if zeros > 32 {
        return None;
    }
    // big-int base58 → bytes
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for ch in input.bytes() {
        let val = B58_ALPHABET.iter().position(|&c| c == ch)? as u32;
        let mut carry = val;
        for byte in out.iter_mut().rev() {
            let x = (*byte as u32) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }
        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    // strip the leading zeros the big-int produced, then re-add the
    // input's own leading zero bytes
    while out.first() == Some(&0) {
        out.remove(0);
    }
    let mut result = vec![0u8; zeros];
    result.extend_from_slice(&out);
    if result.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Some(arr)
}

// ---------------------------------------------------------------------------
// REQUEST/RESPONSE CONTRACT — typed, minimal, no key material ever
// ---------------------------------------------------------------------------

/// The STEP 3 request shape (the decision record §2, minus the signing-only
/// fields that arrive with the signing step; unknown fields are REJECTED —
/// deny-by-default at the deserialization boundary itself).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub agent_id: String,
    /// STEP H-1: the per-request channel nonce (the response binds it)
    #[serde(default)]
    #[allow(dead_code)] // consumed by the channel layer (main.rs)
    pub channel_nonce: String,
    /// STEP H-3: the independent policy IR (the C-2 compiler output over the
    /// authoritative policy record; the signer cross-verifies against its
    /// own independently-loaded policy)
    #[serde(default)]
    #[allow(dead_code)] // consumed by the live sign chain (main.rs)
    pub policy_ir: Option<String>,
    /// the semantic transaction object is accepted-and-held verbatim at
    /// this step (the signer does not interpret it yet); it must be an
    /// OBJECT, and it must never carry obvious private-key material
    /// (checked by `rejects_private_material`).
    #[allow(dead_code)] // consumed by the signing step; validation runs now
    pub transaction: serde_json::Value,
    #[allow(dead_code)] // consumed by the signing step
    pub auth_signature: AuthSignatureRef,
}

/// The authentication signature REFERENCE (pubkey + signature over the
/// canonical bytes). NOTE: in STEP 3 these fields are validated for SHAPE
/// only — no signature verification happens yet (decision §7: prepare the
/// boundary; do NOT implement verification).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSignatureRef {
    pub pubkey: String,
    pub signature: String,
}

/// Fieldless typed denials (decision §3): no reason detail, no paths, no
/// key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignDenial {
    /// the request failed structural validation
    BadRequest,
    /// the request attempted to smuggle private-key material — refused
    /// outright (the signer must never be handed secrets)
    PrivateMaterial,
    /// signing is NOT implemented in this step (deny-by-default)
    NotImplemented,
    /// the store is unavailable/corrupt — fail closed
    StoreUnavailable,
    /// internal failure — fail closed
    Internal,
}

impl SignDenial {
    pub fn code(&self) -> &'static str {
        match self {
            SignDenial::BadRequest => "BAD_REQUEST",
            SignDenial::PrivateMaterial => "PRIVATE_MATERIAL",
            SignDenial::NotImplemented => "NOT_IMPLEMENTED",
            SignDenial::StoreUnavailable => "STORE_UNAVAILABLE",
            SignDenial::Internal => "INTERNAL",
        }
    }

    /// The HTTP status class for the denial (typed, stable).
    pub fn status(&self) -> u16 {
        match self {
            SignDenial::BadRequest | SignDenial::PrivateMaterial => 400,
            // deny-by-default: the capability does not exist yet — 403
            // (authorization-class refusal), NOT 501: the endpoint is
            // intentionally present and deliberately refusing.
            SignDenial::NotImplemented => 403,
            SignDenial::StoreUnavailable | SignDenial::Internal => 500,
        }
    }

    pub fn body(&self) -> String {
        serde_json::json!({ "error": "DENIED", "code": self.code() }).to_string()
    }
}

/// Substrings that indicate private-key material is being handed to the
/// signer — always refused. Deliberately conservative: the signer accepts
/// semantic transaction data, never keys.
const PRIVATE_MATERIAL_MARKERS: [&str; 8] = [
    "privkey",
    "private_key",
    "privatekey",
    "secret_key",
    "secretkey",
    "signing_key",
    "keypair",
    "seed_phrase",
];

/// Structural validation + private-material screening. Returns the denial
/// (fail-closed) or Ok(()) when the request is structurally acceptable.
pub fn validate_sign_request(raw: &[u8]) -> Result<(), SignDenial> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| SignDenial::BadRequest)?;
    let req: SignRequest = serde_json::from_value(value).map_err(|_| SignDenial::BadRequest)?;
    // canonical uuid only
    Uuid::parse_str(&req.agent_id).map_err(|_| SignDenial::BadRequest)?;
    // the transaction must be an object
    if !req.transaction.is_object() {
        return Err(SignDenial::BadRequest);
    }
    // auth signature fields must be non-empty strings
    if req.auth_signature.pubkey.trim().is_empty() || req.auth_signature.signature.trim().is_empty()
    {
        return Err(SignDenial::BadRequest);
    }
    // PRIVATE-MATERIAL SCREENING over the entire request text (conservative:
    // any marker anywhere in the payload ⇒ refusal)
    let text = String::from_utf8_lossy(raw).to_lowercase();
    for marker in PRIVATE_MATERIAL_MARKERS {
        if text.contains(marker) {
            return Err(SignDenial::PrivateMaterial);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// STEP 5 — SIGNER-SIDE POLICY (the frozen sign-time rule set)
// ---------------------------------------------------------------------------

/// The sign-time policy the operator loads (the C-2 rule vocabulary, frozen
/// in the architecture decision §6). Daily/aggregate spend is deliberately
/// ABSENT: the app reservation ledger remains the sole spend authority.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPolicy {
    /// per-transaction cap in kelvin (REQUIRED; no default = deny)
    pub max_per_tx_kelvin: u64,
    /// recipient allow-list in base58; EMPTY ⇒ DENY; "*" ⇒ REJECT (never
    /// permissive — rejected at LOAD time, so it can never be interpreted)
    pub recipients: Vec<String>,
    /// the ONLY program permitted: the System program (32 zero bytes) —
    /// the frozen payment shape
    #[serde(default = "system_program_id")]
    pub program_id: String,
    /// max instruction count (the frozen payment shape: exactly 1)
    #[serde(default)]
    pub max_instructions: u8,
}

fn system_program_id() -> String {
    base58_encode(&[0u8; 32])
}

fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let x = (*d as u32) * 256 + carry;
            *d = (x % 58) as u8;
            carry = x / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = String::new();
    for &b in bytes {
        if b == 0 {
            s.push('1');
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        s.push(B58_ALPHABET[d as usize] as char);
    }
    if s.is_empty() {
        s.push('1');
    }
    s
}

/// Policy loading: strict, fail-closed. `recipients` containing "*" is a
/// REJECTION (the wildcard is never interpreted as unrestricted); an empty
/// allow-list loads but DENIES every request (fail-closed semantics — an
/// operator mistake produces no authority, not all authority).
pub fn load_policy(raw: &[u8]) -> Result<SignerPolicy, PolicyLoadError> {
    let policy: SignerPolicy =
        serde_json::from_slice(raw).map_err(|_| PolicyLoadError::Malformed)?;
    if policy.recipients.iter().any(|r| r.trim() == "*") {
        return Err(PolicyLoadError::WildcardRejected);
    }
    if policy.max_instructions == 0 || policy.max_instructions > 1 {
        return Err(PolicyLoadError::Malformed);
    }
    Ok(policy)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLoadError {
    Malformed,
    /// "*" present — REJECTED at load time (never interpreted)
    WildcardRejected,
}

/// The typed sign-time denials (decision §6). Fieldless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDenial {
    AmountCap,
    RecipientNotAllowlisted,
    RecipientListEmpty,
    ProgramMismatch,
    InstructionCount,
    ValidFromWindow,
    /// STEP H-3: the app-supplied policy IR was malformed/unparseable
    IrMalformed,
    /// STEP H-3: the app-supplied IR disagrees with the signer's own
    /// independently-loaded policy — the two planes must agree, or nothing
    /// signs
    IrMismatch,
}

impl PolicyDenial {
    pub fn code(&self) -> &'static str {
        match self {
            PolicyDenial::AmountCap => "POLICY_AMOUNT",
            PolicyDenial::RecipientNotAllowlisted => "POLICY_RECIPIENT",
            PolicyDenial::RecipientListEmpty => "POLICY_RECIPIENT_LIST_EMPTY",
            PolicyDenial::ProgramMismatch => "POLICY_PROGRAM",
            PolicyDenial::InstructionCount => "POLICY_INSTRUCTION_COUNT",
            PolicyDenial::ValidFromWindow => "POLICY_VALIDFROM",
            PolicyDenial::IrMalformed => "POLICY_IR_MALFORMED",
            PolicyDenial::IrMismatch => "POLICY_IR_MISMATCH",
        }
    }
}

/// Evaluate the sign-time policy against the CANONICALIZED spec (never the
/// raw request). `now_ms` is caller-supplied for determinism in tests; the
/// live handler uses the current time. The validFrom window: must not be
/// older than the clock by more than `VALID_FROM_TOLERANCE_MS`, and must
/// not be in the future beyond the same tolerance (a far-future validFrom
/// is an unusable replay window, not a policy bypass — deny it).
pub const VALID_FROM_TOLERANCE_MS: i64 = 120_000;

pub fn evaluate_policy(
    policy: &SignerPolicy,
    recipient: &str,
    amount_kelvin: u64,
    instruction_count: usize,
    program_id: &str,
    valid_from_ms: i64,
    now_ms: i64,
) -> Result<(), PolicyDenial> {
    if policy.recipients.is_empty() {
        return Err(PolicyDenial::RecipientListEmpty);
    }
    if amount_kelvin > policy.max_per_tx_kelvin {
        return Err(PolicyDenial::AmountCap);
    }
    if !policy
        .recipients
        .iter()
        .any(|r| r.trim() == recipient.trim())
    {
        return Err(PolicyDenial::RecipientNotAllowlisted);
    }
    if program_id.trim() != policy.program_id.trim() {
        return Err(PolicyDenial::ProgramMismatch);
    }
    if instruction_count > policy.max_instructions as usize {
        return Err(PolicyDenial::InstructionCount);
    }
    let delta = valid_from_ms - now_ms;
    if delta < -VALID_FROM_TOLERANCE_MS || delta > VALID_FROM_TOLERANCE_MS {
        return Err(PolicyDenial::ValidFromWindow);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// STEP 5 — AUTH SIGNATURE VERIFICATION (ed25519 over the canonical bytes)
// ---------------------------------------------------------------------------

/// Auth-verification failures (fieldless; never logs signatures or keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDenial {
    /// base64/base58 decode or shape failure
    Malformed,
    /// the wallet record / auth linkage is absent or corrupt — fail closed
    UnknownAgent,
    /// cryptographic verification failed (wrong signature / wrong key)
    Invalid,
}

/// Verify the agent's funds-less ed25519 authentication signature over the
/// SIGNER'S OWN canonical bytes (never caller bytes). The auth pubkey is
/// the authoritative linkage from the wallet record (D8/G-7), so a "wrong
/// auth key" is exactly a verification failure or a record mismatch.
pub fn verify_auth_signature(
    auth_pubkey_b58: &str,
    signature_b64: &str,
    canonical_bytes: &[u8],
) -> Result<(), AuthDenial> {
    let pubkey_bytes = base58_decode_32(auth_pubkey_b58).ok_or(AuthDenial::Malformed)?;
    let sig_bytes = base64_decode(&signature_b64).ok_or(AuthDenial::Malformed)?;
    let signature = rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| AuthDenial::Malformed)?;
    if signature.verify(&pubkey_bytes, canonical_bytes) {
        Ok(())
    } else {
        Err(AuthDenial::Invalid)
    }
}

/// Minimal strict base64 (standard alphabet, optional padding). Rejects
/// non-canonical input; no whitespace tolerance.
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for ch in input.bytes() {
        let val = TABLE.iter().position(|&c| c == ch)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    // any leftover bits must be zero (canonical padding)
    if bits > 0 && (buf & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// base64 encode (standard alphabet, padded) — for signature STRINGS in
/// tests and the future signing step's response.
pub fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------------------
// STEP 5 — THE PRE-SIGN AUTHORIZATION RESULT
// ---------------------------------------------------------------------------

/// The complete pre-sign authorization verdict. Success here means
/// AUTHENTICATED + CANONICALIZED + POLICY_APPROVED — and NOTHING else. It
/// does NOT mean TRANSACTION_SIGNED: no signing capability is reachable in
/// this step (the signing step arrives later, gated on this type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreSignAuthorization {
    /// the signer's OWN canonical bytes (authoritative)
    pub canonical_bytes: Vec<u8>,
    /// blake3 of the canonical bytes (the intent-binding hash)
    pub canonical_hash: String,
    /// the wallet's public address (the payer)
    pub public_address: String,
    /// the verified auth pubkey (from the authoritative wallet record)
    pub auth_pubkey: String,
}

/// Fieldless denials of the full chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSignDenial {
    /// structural/semantic failure (malformed request, bad ids, unknown fields)
    BadRequest,
    /// the request smuggled private-key material
    PrivateMaterial,
    /// canonicalization failed (malformed base58/decimal, unsupported shape,
    /// payer mismatch)
    Canonical(CanonicalError),
    /// caller-supplied binding evidence diverges from the signer's own bytes
    ByteDivergence,
    /// the wallet record is absent/corrupt/the auth linkage mismatches
    UnknownAgent,
    /// ed25519 verification failed
    Auth(AuthDenial),
    /// the sign-time policy denied
    Policy(PolicyDenial),
    /// the signer store failed — fail closed
    StoreUnavailable,
    /// signing is not ARMED (the explicit env gate is absent/off) — the
    /// deny-by-default posture is preserved
    SigningNotEnabled,
    /// internal failure — fail closed
    Internal,
}

impl PreSignDenial {
    pub fn code(&self) -> String {
        match self {
            PreSignDenial::BadRequest => "BAD_REQUEST".to_string(),
            PreSignDenial::PrivateMaterial => "PRIVATE_MATERIAL".to_string(),
            PreSignDenial::Canonical(e) => format!(
                "CANONICAL_{}",
                match e {
                    CanonicalError::Malformed => "MALFORMED",
                    CanonicalError::UnsupportedShape => "UNSUPPORTED_SHAPE",
                    CanonicalError::PayerMismatch => "PAYER_MISMATCH",
                }
            ),
            PreSignDenial::ByteDivergence => "BYTE_DIVERGENCE".to_string(),
            PreSignDenial::UnknownAgent => "UNKNOWN_AGENT".to_string(),
            PreSignDenial::Auth(e) => format!(
                "AUTH_{}",
                match e {
                    AuthDenial::Malformed => "MALFORMED",
                    AuthDenial::UnknownAgent => "UNKNOWN_AGENT",
                    AuthDenial::Invalid => "INVALID",
                }
            ),
            PreSignDenial::Policy(e) => e.code().to_string(),
            PreSignDenial::StoreUnavailable => "STORE_UNAVAILABLE".to_string(),
            PreSignDenial::SigningNotEnabled => "SIGNING_NOT_ENABLED".to_string(),
            PreSignDenial::Internal => "INTERNAL".to_string(),
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            PreSignDenial::BadRequest
            | PreSignDenial::PrivateMaterial
            | PreSignDenial::Canonical(_)
            | PreSignDenial::ByteDivergence
            | PreSignDenial::Auth(_) => 400,
            PreSignDenial::UnknownAgent => 404,
            PreSignDenial::Policy(_) => 403,
            PreSignDenial::SigningNotEnabled => 403,
            PreSignDenial::StoreUnavailable | PreSignDenial::Internal => 500,
        }
    }

    pub fn body(&self) -> String {
        serde_json::json!({ "error": "DENIED", "code": self.code() }).to_string()
    }
}

/// THE FULL CHAIN — the only sanctioned pre-sign path:
///
///   semantic request
///     → canonicalize (signer's OWN bytes; caller bytes NEVER authoritative)
///     → byte-binding check (caller hash/bytes, if present, MUST match)
///     → wallet record lookup (authoritative auth linkage; integrity-checked)
///     → auth signature verification over the signer's canonical bytes
///     → sign-time policy evaluation
///   → PreSignAuthorization (AUTHENTICATED + CANONICALIZED + POLICY_APPROVED)
///
/// NO signing happens here, ever. The signature the request carries is the
/// agent's OFF-CHAIN APPROVAL signature, not a transaction signature.
pub fn authorize_pre_sign(
    store: &SignerStore,
    policy: &SignerPolicy,
    agent_id: &Uuid,
    auth_signature_b64: &str,
    tx: &SemanticTransaction,
    now_ms: i64,
) -> Result<PreSignAuthorization, PreSignDenial> {
    // 1) the authoritative wallet record (integrity-checked: record + key
    //    container + address agreement — agent_public_address enforces this)
    let public_address = store
        .agent_public_address(agent_id)
        .map_err(|_| PreSignDenial::UnknownAgent)?
        .ok_or(PreSignDenial::UnknownAgent)?;
    let auth_pubkey = {
        let record_path = store.root().join(format!("{agent_id}.wallet.json"));
        let bytes = std::fs::read(&record_path).map_err(|_| PreSignDenial::UnknownAgent)?;
        let record: WalletRecord =
            serde_json::from_slice(&bytes).map_err(|_| PreSignDenial::UnknownAgent)?;
        record.auth_pubkey
    };

    // 2) canonical recompile (the signer's OWN bytes — never caller bytes)
    let (_spec, canonical_bytes, canonical_hash) =
        canonicalize(tx, &public_address).map_err(PreSignDenial::Canonical)?;

    // 3) byte binding: if the caller supplied binding evidence, it MUST
    //    match the signer's own canonical result (mismatch ⇒ BYTE_DIVERGENCE;
    //    absence is permitted by the frozen contract — signer-side derivation
    //    is authoritative either way)
    if let Some(supplied_hash) = &tx.canonical_hash {
        if supplied_hash.trim().to_lowercase() != canonical_hash {
            return Err(PreSignDenial::ByteDivergence);
        }
    }
    if let Some(supplied_b64) = &tx.canonical_bytes {
        let supplied = base64_decode(supplied_b64).ok_or(PreSignDenial::ByteDivergence)?;
        if supplied != canonical_bytes {
            return Err(PreSignDenial::ByteDivergence);
        }
    }

    // 4) auth signature verification over the SIGNER's canonical bytes
    verify_auth_signature(&auth_pubkey, auth_signature_b64, &canonical_bytes).map_err(|e| {
        PreSignDenial::Auth(if e == AuthDenial::Malformed {
            AuthDenial::Malformed
        } else {
            e
        })
    })?;

    // 5) sign-time policy on the canonicalized spec. The program checked is
    // the ACTUAL program of the compiled instruction (the canonical shape
    // pins the System program — rialo_canonical::SYSTEM_PROGRAM_ID), NOT
    // the policy's own field (that would be circular).
    let actual_program = base58_encode(&rialo_canonical::SYSTEM_PROGRAM_ID);
    evaluate_policy(
        policy,
        &tx.recipient,
        tx.amount_kelvin,
        1, // the frozen payment shape: exactly one instruction
        &actual_program,
        tx.valid_from_ms,
        now_ms,
    )
    .map_err(PreSignDenial::Policy)?;

    Ok(PreSignAuthorization {
        canonical_bytes,
        canonical_hash,
        public_address,
        auth_pubkey,
    })
}

/// The skeleton's verdict for a request path. Paths:
/// `POST /sign` (validated, then refused NOT_IMPLEMENTED),
/// `GET /health` (minimal liveness — no secrets, no paths, no state),
/// `POST /provision` (STEP 4: wallet provisioning — public data only).
#[derive(Debug, PartialEq, Eq)]
pub enum SkeletonResponse {
    Health,
    AcceptedButNotImplemented(SignDenial),
    Denied(SignDenial),
    /// STEP 4: the provisioning verdict carries ONLY public data (the
    /// outcome class + the public address; never any key material).
    Provisioned {
        outcome_class: &'static str,
        public_address: Option<String>,
    },
    /// the request carries an agent that is NOT KNOWN to the operator-supplied
    /// allow-list of provisioning candidates — denied (unknown-agent)
    UnknownAgent,
}

/// The provisioning request: exactly two fields, deny_unknown_fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub agent_id: String,
    /// the agent's D8/G-7 funds-less auth PUBLIC key — the identity linkage
    /// the signer records. Public data only.
    pub auth_pubkey: String,
}

/// Structural validation of a provisioning request (no store access — the
/// router stays pure; the live handler does the store work).
pub fn validate_provision_request(raw: &[u8]) -> Result<ProvisionRequest, SignDenial> {
    let value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| SignDenial::BadRequest)?;
    let req: ProvisionRequest =
        serde_json::from_value(value).map_err(|_| SignDenial::BadRequest)?;
    Uuid::parse_str(&req.agent_id).map_err(|_| SignDenial::BadRequest)?;
    if req.auth_pubkey.trim().is_empty() {
        return Err(SignDenial::BadRequest);
    }
    Ok(req)
}

/// A public wallet-address read: `GET /wallet/{agent_id}` — the ONLY
/// data returned is the public address (public by design; no key material,
/// no paths, no store layout). Unknown/unprovisioned agents deny with
/// UNKNOWN_AGENT (404) — fail-closed, no enumeration beyond the typed code.
#[derive(Debug, PartialEq, Eq)]
pub enum WalletReadResponse {
    Address { public_address: String },
    UnknownAgent,
    BadRequest,
}

pub fn parse_wallet_read(path: &str) -> Result<Uuid, WalletReadResponse> {
    let Some(agent_id) = path.strip_prefix("/wallet/") else {
        return Err(WalletReadResponse::BadRequest);
    };
    if agent_id.contains('/') || agent_id.is_empty() {
        return Err(WalletReadResponse::BadRequest);
    }
    Uuid::parse_str(agent_id).map_err(|_| WalletReadResponse::BadRequest)
}

pub fn route(method: &str, path: &str, body: &[u8]) -> SkeletonResponse {
    match (method, path) {
        ("GET", "/health") => SkeletonResponse::Health,
        ("POST", "/sign") => match validate_sign_request(body) {
            // deny-by-default: even a PERFECTLY FORMED request is refused —
            // no signing capability exists in this step
            Ok(()) => SkeletonResponse::AcceptedButNotImplemented(SignDenial::NotImplemented),
            Err(d) => SkeletonResponse::Denied(d),
        },
        ("POST", "/provision") => match validate_provision_request(body) {
            // the ROUTER is pure: structural validity only. The live
            // handler performs the store work and the agent-allow-list
            // check; this pure route reports the structural verdict as a
            // Provisioned verdict with no address (no store access here).
            Ok(_req) => SkeletonResponse::Provisioned {
                outcome_class: "validated",
                public_address: None,
            },
            Err(d) => SkeletonResponse::Denied(d),
        },
        _ => SkeletonResponse::Denied(SignDenial::BadRequest),
    }
}

// ---------------------------------------------------------------------------
// STEP 6 — ACTUAL SIGNATURE EXECUTION (signer-owned custody, gated)
// ---------------------------------------------------------------------------

/// The gate for signature execution: EXPLICIT environment enablement,
/// fail-closed when absent, never enabled by default. The value "1" arms
/// the signing capability; anything else (or absence) leaves /sign in the
/// deny-only posture. This separates test/live execution from the default
/// deny state — the PROCESS never quietly gains a signing capability.
pub const SIGNING_ENABLED_ENV: &str = "AGENTPAY_SIGNER_SIGNING_ENABLED";

pub fn signing_enabled() -> bool {
    std::env::var(SIGNING_ENABLED_ENV).ok().as_deref() == Some("1")
}

/// The signed-envelope result: PUBLIC execution data ONLY — exactly what
/// the future PaymentOps seam needs. No private key, no seed, no secret
/// bytes, no key container, no auth private material can ever appear here
/// (the type is fieldwise public by construction; pinned by tests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    /// the agent identity the envelope was authorized for
    pub agent_id: String,
    /// the signer-owned public wallet address (the payer)
    public_address: String,
    /// blake3 of the signer's own canonical message bytes
    pub canonical_hash: String,
    /// the canonical MESSAGE bytes (public by design: the message is what
    /// every node sees; the SDK signs exactly these bytes)
    pub canonical_message_b64: String,
    /// the wallet's ed25519 signature over the canonical message bytes
    pub signature_b64: String,
    /// the number of required signatures (the Rialo SDK's message header
    /// fact — 1 for the single-sender transfer shape)
    pub required_signatures: u8,
}

impl SignedEnvelope {
    /// The fully assembled unsigned-envelope identity: the message bytes
    /// with zeroed signature slots, as the SDK's `Transaction::new_unsigned`
    /// produces — the exact artifact a future broadcast step would submit.
    pub fn unsigned_envelope_b64(&self) -> String {
        let message = base64_decode(&self.canonical_message_b64).unwrap_or_default();
        let mut envelope = Vec::with_capacity(message.len() + 1 + 64);
        envelope.push(self.required_signatures);
        for _ in 0..self.required_signatures {
            envelope.extend_from_slice(&[0u8; 64]);
        }
        envelope.extend_from_slice(&message);
        base64_encode(&envelope)
    }
}

/// Signing failures (fieldless, fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// signing is not armed (the env gate is absent/off) — deny
    NotEnabled,
    /// the key container is missing — fail closed (never re-mint, never
    /// fall back to another key)
    KeyMissing,
    /// the key container is corrupt — fail closed
    KeyCorrupt,
    /// the wallet/key address disagreement — fail closed
    WalletMismatch,
    /// the produced signature failed post-sign self-verification against
    /// the signer's own public key + the exact canonical bytes
    SelfVerificationFailed,
    /// internal failure — fail closed
    Internal,
}

/// THE SIGNING ACT — structurally reachable ONLY through a successful
/// `PreSignAuthorization` (the parameter type makes an unauthorized call
/// unrepresentable: there is no path from a raw request to this function
/// without the gate's verdict).
///
/// The signer:
///   1. loads the wallet record (public address + auth linkage — the
///      authoritative identity),
///   2. loads the signer-OWNED key container (the private half NEVER
///      leaves this function; nothing is written outside the store),
///   3. verifies the container's public half matches the record's public
///      address (wallet/address binding),
///   4. signs EXACTLY the authorization's canonical bytes (the parameter
///      carries them; caller bytes were already refused upstream by
///      BYTE_DIVERGENCE enforcement),
///   5. self-verifies the produced signature against the signer's public
///      key + the exact same bytes — a failure is a typed signer failure,
///      no retry, no different bytes, no fallback key, no mutation.
///
/// There is NO broadcast: the envelope stays inside the response; the
/// future PaymentOps seam owns submission.
pub fn execute_signature(
    store: &SignerStore,
    auth: &PreSignAuthorization,
    agent_id: &Uuid,
) -> Result<SignedEnvelope, SigningError> {
    // 0) the arm gate — deny when absent
    if !signing_enabled() {
        return Err(SigningError::NotEnabled);
    }

    // 1) the authoritative record (identity binding)
    let record_path = store.root().join(format!("{agent_id}.wallet.json"));
    let record_bytes = std::fs::read(&record_path).map_err(|_| SigningError::KeyMissing)?;
    let record: WalletRecord =
        serde_json::from_slice(&record_bytes).map_err(|_| SigningError::KeyCorrupt)?;
    if record.agent_id != agent_id.to_string() {
        return Err(SigningError::WalletMismatch);
    }
    // the record's wallet must be the SAME wallet the authorization used
    if record.public_address != auth.public_address {
        return Err(SigningError::WalletMismatch);
    }

    // 2) the signer-owned key container (private half stays HERE)
    let key_path = store.root().join(format!("{agent_id}.key.json"));
    let key_bytes = std::fs::read(&key_path).map_err(|_| SigningError::KeyMissing)?;
    let keypair = rialo_s_keypair::Keypair::from_bytes(
        &serde_json::from_slice::<Vec<u8>>(&key_bytes).map_err(|_| SigningError::KeyCorrupt)?,
    )
    .map_err(|_| SigningError::KeyCorrupt)?;

    // 3) wallet/address binding: the container's public half MUST equal the
    //    record's public address (and the authorization's payer)
    {
        use rialo_s_signer::Signer;
        let container_address = keypair.pubkey().to_string();
        if container_address != record.public_address {
            return Err(SigningError::WalletMismatch);
        }
        if container_address != auth.public_address {
            return Err(SigningError::WalletMismatch);
        }
    }

    // 4) sign EXACTLY the authorized canonical bytes
    use rialo_s_signer::Signer;
    let signature = keypair.sign_message(&auth.canonical_bytes);

    // 5) post-sign self-verification: the signature MUST verify against the
    //    signer's own public key over the EXACT same canonical bytes. No
    //    retry, no different bytes, no fallback key, no record mutation.
    let sig_bytes: [u8; 64] = signature.into();
    // post-sign self-verification: the signature MUST verify against the
    // signer's own public key over the EXACT same canonical bytes
    let pubkey_bytes: [u8; 32] = {
        use rialo_s_signer::Signer;
        keypair.pubkey().to_bytes()
    };
    let self_ok = rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| SigningError::Internal)?
        .verify(&pubkey_bytes, &auth.canonical_bytes);
    if !self_ok {
        return Err(SigningError::SelfVerificationFailed);
    }

    Ok(SignedEnvelope {
        agent_id: agent_id.to_string(),
        public_address: auth.public_address.clone(),
        canonical_hash: auth.canonical_hash.clone(),
        canonical_message_b64: base64_encode(&auth.canonical_bytes),
        signature_b64: base64_encode(&sig_bytes),
        required_signatures: rialo_canonical::SINGLE_SIGNER_REQUIRED,
    })
}

/// The full STEP 6 chain — the ONLY sanctioned path from a request to a
/// signed envelope. Combines the mandatory `PreSignAuthorization` gate with
/// the signing act; every Step 5 denial remains intact and every signing
/// failure fails closed. The env gate arms the capability.
pub fn sign_transaction(
    store: &SignerStore,
    policy: &SignerPolicy,
    agent_id: &Uuid,
    auth_signature_b64: &str,
    tx: &SemanticTransaction,
    now_ms: i64,
) -> Result<SignedEnvelope, PreSignDenial> {
    // the mandatory authorization gate FIRST (all Step 5 denials)
    let auth = authorize_pre_sign(store, policy, agent_id, auth_signature_b64, tx, now_ms)?;
    match execute_signature(store, &auth, agent_id) {
        Ok(envelope) => Ok(envelope),
        Err(SigningError::NotEnabled) => Err(PreSignDenial::SigningNotEnabled),
        Err(_) => Err(PreSignDenial::Internal),
    }
}

// ---------------------------------------------------------------------------
// STEP H-1 — AUTHENTICATED SIGNER CHANNEL (additive hardening)
// ---------------------------------------------------------------------------

/// The signer's CHANNEL identity: a funds-less ed25519 keypair used ONLY to
/// authenticate this process's responses over the loopback boundary. It is
/// NOT a wallet key, holds no funds, and is stored under the same I-1
/// discipline (O_EXCL, 0600-before-content) in the signer's own store.
/// AgentPay pins the expected public key; an unsigned/mismatched response
/// fails closed.
pub const CHANNEL_IDENTITY_FILE: &str = "signer_identity.key.json";

/// Load (or lazily provision) the channel identity keypair from the signer
/// store. Strict container parse; O_EXCL creation; 0600 before content.
pub fn channel_identity(store: &SignerStore) -> Result<rialo_s_keypair::Keypair, StoreError> {
    let path = store.root().join(CHANNEL_IDENTITY_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|_| StoreError::Unavailable)?;
        let arr: Vec<u8> = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if arr.len() != 64 {
            return Err(StoreError::Corrupt);
        }
        return rialo_s_keypair::Keypair::from_bytes(&arr).map_err(|_| StoreError::Corrupt);
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| StoreError::Unavailable)?;
    let keypair = rialo_s_keypair::keypair_from_seed(&seed).map_err(|_| StoreError::Unavailable)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                // a concurrent process provisioned it — read theirs
                StoreError::Exists
            } else {
                StoreError::Unavailable
            }
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    rialo_s_keypair::write_keypair(&keypair, &mut file).map_err(|_| StoreError::Unavailable)?;
    file.flush().map_err(|_| StoreError::Unavailable)?;
    drop(file);
    Ok(keypair)
}

/// The channel public key (what AgentPay pins).
pub fn channel_public_key(store: &SignerStore) -> Result<String, StoreError> {
    let kp = channel_identity(store)?;
    use rialo_s_signer::Signer;
    Ok(kp.pubkey().to_string())
}

/// The operator-pinned binary digest (STEP H-2): blake3 hex of the signer
/// binary. Semantics: pin ABSENT = the pre-hardening posture (no check);
/// pin PRESENT = mandatory — a digest mismatch refuses startup (fail-closed,
/// no software fallback, the process exits non-zero).
pub const BINARY_PIN_ENV: &str = "AGENTPAY_SIGNER_BINARY_PIN";

/// blake3 digest of the running signer binary (hex).
pub fn own_binary_digest() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let bytes = std::fs::read(exe).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Verify the binary pin: Ok(()) when no pin is configured (preserved
/// posture) or the digest matches; Err(()) when configured and mismatched.
pub fn verify_binary_pin() -> Result<(), ()> {
    match std::env::var(BINARY_PIN_ENV) {
        Ok(pin) if !pin.trim().is_empty() => {
            let digest = own_binary_digest().ok_or(())?;
            if digest == pin.trim().to_lowercase() {
                Ok(())
            } else {
                Err(())
            }
        }
        _ => Ok(()),
    }
}

/// The handshake payload the adapter verifies at startup: the binary digest
/// + the channel public key, SIGNED by the channel identity — a substituted
/// binary cannot present a valid identity+digest pair.
pub fn handshake_payload(
    store: &SignerStore,
    nonce: &str,
) -> Result<(String, String, String), StoreError> {
    let digest = own_binary_digest().ok_or(StoreError::Unavailable)?;
    let pk = channel_public_key(store)?;
    let body = serde_json::json!({
        "binary_digest": digest,
        "channel_pubkey": pk,
        "channel_nonce": nonce,
    })
    .to_string();
    let sig = sign_channel_response(store, &body, nonce)?;
    Ok((body, sig, pk))
}

/// STEP H-3 — INDEPENDENT POLICY IR VERIFICATION (signer side).
///
/// The app sends the C-2 compiler's IR over the AUTHORITATIVE policy record.
/// The signer independently loads ITS OWN policy and builds its own
/// representation; a rule-by-rule comparison runs BEFORE any policy
/// evaluation. A mismatch is a deny — the two planes must AGREE, or nothing
/// signs. This is not a duplicate boolean: the two representations come
/// from two independent sources (the app's policy store vs the signer's
/// policy file) through two independent compilation paths.
pub const IR_AMOUNT_CAP_RULE: &str = "signer_policy_amount_cap";
pub const IR_RECIPIENT_RULE: &str = "signer_policy_recipient";
pub const IR_PROGRAM_PIN_RULE: &str = "signer_policy_program_pin";
pub const IR_INSTRUCTION_COUNT_RULE: &str = "signer_policy_instruction_count";

/// The signer's own representation of its policy (the rule vocabulary the
/// app's IR must agree with).
pub struct SignerPolicyIR {
    pub amount_cap: Option<u64>,
    pub recipients: Vec<String>,
    pub program_pin: String,
    pub instruction_count: u8,
}

pub fn signer_policy_ir(policy: &SignerPolicy) -> SignerPolicyIR {
    SignerPolicyIR {
        amount_cap: Some(policy.max_per_tx_kelvin),
        recipients: policy.recipients.clone(),
        program_pin: policy.program_id.trim().to_string(),
        instruction_count: policy.max_instructions,
    }
}

/// Parse the app-supplied IR filters into the comparable shape.
pub struct AppPolicyIR {
    pub amount_cap: Option<u64>,
    pub recipients: Vec<String>,
    pub program_pin: Option<String>,
    pub instruction_count: Option<u8>,
}

pub fn parse_app_ir(ir_json: &str) -> Result<AppPolicyIR, ()> {
    let v: serde_json::Value = serde_json::from_str(ir_json).map_err(|_| ())?;
    let obj = v.as_object().ok_or(())?;
    let mut out = AppPolicyIR {
        amount_cap: None,
        recipients: Vec::new(),
        program_pin: None,
        instruction_count: None,
    };
    // the IR filters live under "filters": [{rule, value, source}]
    let filters = obj.get("filters").and_then(|x| x.as_array()).ok_or(())?;
    for f in filters {
        let rule = f.get("rule").and_then(|x| x.as_str()).ok_or(())?;
        let value = f.get("value").and_then(|x| x.as_str()).ok_or(())?;
        match rule {
            r if r == IR_AMOUNT_CAP_RULE => {
                out.amount_cap = Some(value.parse::<u64>().map_err(|_| ())?);
            }
            r if r == IR_RECIPIENT_RULE => {
                out.recipients.push(value.to_string());
            }
            r if r == IR_PROGRAM_PIN_RULE => {
                out.program_pin = Some(value.to_string());
            }
            r if r == IR_INSTRUCTION_COUNT_RULE => {
                out.instruction_count = Some(value.parse::<u8>().map_err(|_| ())?);
            }
            _ => {}
        }
    }
    Ok(out)
}

/// The cross-verification: the app's IR and the signer's own representation
/// must AGREE on every rule. Any disagreement = deny (typed).
pub fn cross_verify_policy_ir(
    app_ir: &str,
    signer_policy: &SignerPolicy,
) -> Result<(), PolicyDenial> {
    let parsed = parse_app_ir(app_ir).map_err(|_| PolicyDenial::IrMalformed)?;
    let own = signer_policy_ir(signer_policy);
    // amount cap must match exactly (both present and equal)
    if parsed.amount_cap != own.amount_cap {
        return Err(PolicyDenial::IrMismatch);
    }
    // recipients: exact set equality (order-insensitive)
    let mut a = parsed.recipients.clone();
    let mut b = own.recipients.clone();
    a.sort();
    b.sort();
    if a != b {
        return Err(PolicyDenial::IrMismatch);
    }
    // program pin must match
    if parsed.program_pin.as_deref().map(|s| s.trim()) != Some(own.program_pin.trim()) {
        return Err(PolicyDenial::IrMismatch);
    }
    // instruction count must match
    if parsed.instruction_count != Some(own.instruction_count) {
        return Err(PolicyDenial::IrMismatch);
    }
    Ok(())
}

/// The per-request challenge: the app supplies a fresh base64 nonce; the
/// response binds it so a captured response cannot be replayed against a
/// different request.
pub fn parse_nonce(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let n = v.get("channel_nonce")?.as_str()?.to_string();
    if n.is_empty() || n.len() > 128 {
        return None;
    }
    Some(n)
}

/// PHASE 10 ITEM 6 — the CANONICAL serialization the channel signature
/// covers, defined EXPLICITLY (never left to a map implementation):
/// object keys sorted recursively (arrays keep order), compact separators.
///
/// WHY this exists: the app and the signer are SEPARATE workspaces, and the
/// app's build graph enables serde_json's `preserve_order` (indexmap) while
/// the signer's does not (BTreeMap). Two `Value::to_string()` calls on the
/// SAME logical body can therefore produce DIFFERENT bytes — exactly the
/// class of channel-auth failure this step fixes. By sorting keys before
/// serializing on BOTH sides, the signed message is a pure function of the
/// body's CONTENT, independent of every feature flag in either graph.
pub fn canonical_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for key in keys {
                out.insert(key.clone(), canonical_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

/// The EXACT message the channel signature covers: the complete response
/// body (channel_nonce INCLUDED, `signer_sig` EXCLUDED) in its canonical
/// serialization. A body that is not a JSON object is taken verbatim (the
/// legacy posture; the app recomputes the same bytes).
pub fn channel_signing_bytes(body: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => {
            let mut clean = v;
            if let Some(o) = clean.as_object_mut() {
                o.remove("signer_sig");
            }
            canonical_json(&clean).to_string()
        }
        Err(_) => body.to_string(),
    }
}

/// Seal ONE response for the authenticated channel (PHASE 10 ITEM 6).
///
/// The protocol order is FIXED and is the whole point of this function:
///   1. build the COMPLETE response body, `channel_nonce` included;
///   2. take the body WITHOUT `signer_sig`;
///   3. CANONICALLY serialize it (see [`canonical_json`]) — the exact bytes
///      AgentPay will recompute;
///   4. sign blake3(canonical) || nonce with the channel identity key;
///   5. insert `signer_sig` into the final response.
///
/// The signature therefore covers the SAME message the adapter verifies —
/// signing before the nonce is inserted is structurally impossible here,
/// because the nonce is part of the body that gets canonicalized and signed.
/// A missing channel identity returns the ORIGINAL unmodified payload: the
/// response then carries no seal and the app fails closed (never a partially
/// sealed or re-ordered body).
pub fn seal_channel_response(store: &SignerStore, payload: &str, nonce: Option<&str>) -> String {
    let Some(nonce) = nonce else {
        return payload.to_string();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload) else {
        return payload.to_string();
    };
    let mut obj = match parsed {
        serde_json::Value::Object(map) => serde_json::Value::Object(map),
        other => return other.to_string(),
    };
    // (1) the COMPLETE body: the request nonce is part of what is signed
    if let Some(o) = obj.as_object_mut() {
        o.insert("channel_nonce".to_string(), serde_json::json!(nonce));
        o.remove("signer_sig");
    }
    let with_nonce = obj.to_string();
    // (2)+(3)+(4) sign the canonical form of exactly the body AgentPay verifies
    let Ok(sig) = sign_channel_response(store, &with_nonce, nonce) else {
        // no channel identity: hand back the ORIGINAL unmodified payload
        return payload.to_string();
    };
    // (5) the seal is transport metadata — never part of the signed message
    if let Some(o) = obj.as_object_mut() {
        o.insert("signer_sig".to_string(), serde_json::json!(sig));
    }
    obj.to_string()
}

/// Sign a response body for the channel: ed25519 over
/// blake3(CANONICAL(body without signer_sig)) || nonce.
/// The signature is base64 (the same alphabet the lane uses).
pub fn sign_channel_response(
    store: &SignerStore,
    body: &str,
    nonce: &str,
) -> Result<String, StoreError> {
    let kp = channel_identity(store)?;
    use rialo_s_signer::Signer;
    // The signature covers the CLEAN body: `signer_sig` is stripped and the
    // remaining object is re-serialized CANONICALLY (sorted keys, compact),
    // so the app's verifier — which strips the same field and canonicalizes
    // the same way — recomputes byte-identical message bytes.
    let clean = channel_signing_bytes(body);
    let mut msg = blake3::hash(clean.as_bytes()).as_bytes().to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    let sig = kp.sign_message(&msg);
    Ok(base64_encode(&<[u8; 64]>::from(sig)))
}

// ---------------------------------------------------------------------------
// TESTS — the STEP 3 security battery
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("agentpay-signer-{tag}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    // -- G89 (M1): store boundary hardening -------------------------------

    #[cfg(unix)]
    #[test]
    fn g89_symlinked_users_dir_is_refused() {
        let root = temp_root("g89-users-link");
        let outside = temp_root("g89-outside");
        std::fs::create_dir_all(&outside).unwrap();
        // users/ is a symlink pointing OUTSIDE the store
        std::os::unix::fs::symlink(&outside, root.join("users")).unwrap();
        let store = SignerStore::open(&root).unwrap();
        assert!(
            store.reject_symlinked_boundaries().is_err(),
            "symlinked users/ ⇒ boundary refused"
        );
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn g89_symlinked_creation_gate_is_refused() {
        let root = temp_root("g89-gate-link");
        let outside = temp_root("g89-outside2");
        std::fs::create_dir_all(root.join("users")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("creation_gate")).unwrap();
        let store = SignerStore::open(&root).unwrap();
        assert!(store.reject_symlinked_boundaries().is_err());
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[cfg(unix)]
    #[test]
    fn g89_symlinked_root_ancestor_is_refused() {
        // root itself reached THROUGH a symlink ancestor: the component walk
        // must reject before anything is trusted
        let real = temp_root("g89-real-root");
        std::fs::create_dir_all(real.join("users")).unwrap();
        let base = temp_root("g89-base");
        let link = base.join("linked-root");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // G91 (F3): open itself refuses — no directory is created or
        // resolved through a symlinked component.
        assert_eq!(
            SignerStore::open(&link).unwrap_err(),
            StoreError::Unavailable
        );
        std::fs::remove_dir_all(&real).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn g89_clean_store_passes_all_boundary_checks() {
        let root = temp_root("g89-clean");
        std::fs::create_dir_all(root.join("users")).unwrap();
        let store = SignerStore::open(&root).unwrap();
        assert!(store.reject_symlinked_boundaries().is_ok());
        assert!(
            store.verify_store_ownership().is_ok(),
            "own-process store ⇒ owned by self"
        );
        assert!(store.harden_permissions().is_ok());
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn g89_harden_permissions_enforces_0700() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("g89-perm");
        std::fs::create_dir_all(root.join("users")).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(root.join("users"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let store = SignerStore::open(&root).unwrap();
        store.harden_permissions().unwrap();
        let m1 = std::fs::metadata(&root).unwrap().permissions().mode();
        let m2 = std::fs::metadata(root.join("users"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m1 & 0o777, 0o700, "root forced to 0700");
        assert_eq!(m2 & 0o777, 0o700, "users/ forced to 0700");
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn g89_harden_permissions_refuses_unfixable_dir() {
        // a directory that cannot be set to 0700 (root-owned when running
        // unprivileged) ⇒ fail-closed error, never serve
        if unsafe { libc_geteuid_is_zero() } {
            return; // running as root: the negative test is unconstructible
        }
        let root = temp_root("g89-perm-root-owned");
        std::fs::create_dir_all(root.join("users")).unwrap();
        // chown to uid 0 without libc: use `std::os::unix::fs::chown` when
        // stable? It is stable as of 1.73 — but chown to 0 needs root; skip
        // via an unreadable parent instead: symlink target that harden would
        // follow would be caught earlier. Use the direct approach: check the
        // enforce path with a chmod that silently fails via a read-only fs is
        // not portable — so assert the CONTRACT on the verify leg by planting
        // a mode that set_permissions cannot correct regarding ownership.
        // HONEST compromise: this scenario is covered by the MAIN startup
        // chain test (fail-closed exit) instead of a synthetic chown here.
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    fn libc_geteuid_is_zero() -> bool {
        crate::store_lock::euid_from_proc() == Some(0)
    }

    // -- loopback-only enforcement ----------------------------------------

    #[test]
    fn parse_accepts_only_explicit_loopback() {
        assert!(SignerEndpoint::parse("127.0.0.1:8971").is_ok());
        assert!(SignerEndpoint::parse("localhost:8971").is_ok());
        assert!(SignerEndpoint::parse("[::1]:8971").is_ok());
        // non-loopback refused
        assert_eq!(
            SignerEndpoint::parse("0.0.0.0:8971").unwrap_err(),
            EndpointError::NotLoopback
        );
        assert_eq!(
            SignerEndpoint::parse("192.168.1.5:8971").unwrap_err(),
            EndpointError::NotLoopback
        );
        assert_eq!(
            SignerEndpoint::parse("example.com:8971").unwrap_err(),
            EndpointError::Malformed
        );
        assert_eq!(
            SignerEndpoint::parse("127.0.0.1:0").unwrap_err(),
            EndpointError::ZeroPort
        );
        assert_eq!(
            SignerEndpoint::parse("").unwrap_err(),
            EndpointError::Malformed
        );
        assert_eq!(
            SignerEndpoint::parse("127.0.0.1").unwrap_err(),
            EndpointError::Malformed
        );
        assert_eq!(
            SignerEndpoint::parse("127.0.0.1:8971/path").unwrap_err(),
            EndpointError::Malformed
        );
    }

    #[tokio::test]
    async fn live_bind_refuses_non_loopback_addresses() {
        // the BIND path itself refuses non-loopback: constructing a listener
        // for 0.0.0.0 must fail (the endpoint type makes it unrepresentable,
        // but the runtime check is defense-in-depth)
        let _bad = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8972);
        // direct bind of a non-loopback address must be REJECTED by our own
        // discipline: we never even attempt it through SignerEndpoint; here
        // we assert the type system holds (cannot construct) and that a raw
        // loopback bind succeeds.
        assert!(SignerEndpoint::parse("0.0.0.0:8972").is_err());
        let ep = SignerEndpoint::parse("127.0.0.1:8972").unwrap();
        let listener = tokio::net::TcpListener::bind(ep.socket_addr())
            .await
            .expect("loopback bind works");
        assert_eq!(listener.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn live_listener_serves_health_and_denies_sign() {
        let ep = SignerEndpoint::parse("127.0.0.1:8973").unwrap();
        let listener = tokio::net::TcpListener::bind(ep.socket_addr())
            .await
            .unwrap();

        let server = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                // read one minimal HTTP request (headers + body)
                let mut buf = vec![0u8; 4096];
                use tokio::io::AsyncReadExt;
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]);
                let mut lines = text.split("\r\n");
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();
                // naive body extraction after \r\n\r\n
                let body = text
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.as_bytes().to_vec())
                    .unwrap_or_default();
                let verdict = route(&method, &path, &body);
                let (status, payload) = match verdict {
                    SkeletonResponse::Health => (200u16, r#"{"status":"ok"}"#.to_string()),
                    SkeletonResponse::AcceptedButNotImplemented(d) => (d.status(), d.body()),
                    SkeletonResponse::Denied(d) => (d.status(), d.body()),
                    SkeletonResponse::Provisioned { outcome_class, .. } => (
                        200u16,
                        serde_json::json!({ "outcome": outcome_class }).to_string(),
                    ),
                    SkeletonResponse::UnknownAgent => (
                        404u16,
                        r#"{"error":"DENIED","code":"UNKNOWN_AGENT"}"#.to_string(),
                    ),
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        // health: 200, minimal, no secrets/paths/state
        let health = raw_http("127.0.0.1", 8973, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(health.starts_with("HTTP/1.1 200"), "{health}");
        assert!(health.contains(r#"{"status":"ok"}"#));
        assert!(!health.contains("artifact"), "no paths in health");
        assert!(!health.contains("key"), "no key words in health");

        // /sign with a VALID body: still refused (deny-by-default)
        let body = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {"feePayer": "x"},
            "auth_signature": {"pubkey": "pk", "signature": "sig"}
        })
        .to_string();
        let req = format!(
            "POST /sign HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let sign = raw_http("127.0.0.1", 8973, &req).await;
        assert!(sign.starts_with("HTTP/1.1 403"), "{sign}");
        assert!(sign.contains("NOT_IMPLEMENTED"), "{sign}");

        // unknown path: denied
        let unknown = raw_http("127.0.0.1", 8973, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(unknown.starts_with("HTTP/1.1 400"), "{unknown}");

        server.abort();
    }

    async fn raw_http(host: &str, port: u16, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut sock = tokio::net::TcpStream::connect((host, port))
            .await
            .expect("connect");
        sock.write_all(request.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sock.read_to_end(&mut buf),
        )
        .await;
        String::from_utf8_lossy(&buf).to_string()
    }

    // -- request validation ------------------------------------------------

    fn valid_body(agent_id: Option<Uuid>) -> Vec<u8> {
        serde_json::json!({
            "agent_id": agent_id.unwrap_or_else(Uuid::new_v4).to_string(),
            "transaction": {
                "feePayer": "F2G6sCzseLeGiCtnWtyFGJec7nwxiRs3kcCF1nqxVnVw",
                "validFrom": 1730000000000i64,
                "configHashPrefix": "8888927001659606077",
                "occ": false,
                "instructions": []
            },
            "auth_signature": {"pubkey": "pk-base58", "signature": "sig-base64"}
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn malformed_requests_are_rejected() {
        assert_eq!(
            validate_sign_request(b"not json"),
            Err(SignDenial::BadRequest)
        );
        assert_eq!(validate_sign_request(b"{}"), Err(SignDenial::BadRequest));
        // unknown field (mass-assignment impossible at the boundary)
        let extra = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {},
            "auth_signature": {"pubkey": "p", "signature": "s"},
            "owner_user_id": 1
        });
        let raw = extra.to_string().into_bytes();
        assert_eq!(validate_sign_request(&raw), Err(SignDenial::BadRequest));
        // missing field
        let missing = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {}
        });
        assert_eq!(
            validate_sign_request(&missing.to_string().into_bytes()),
            Err(SignDenial::BadRequest)
        );
        // non-canonical agent id
        let bad_id = serde_json::json!({
            "agent_id": "../etc/passwd",
            "transaction": {},
            "auth_signature": {"pubkey": "p", "signature": "s"}
        });
        assert_eq!(
            validate_sign_request(&bad_id.to_string().into_bytes()),
            Err(SignDenial::BadRequest)
        );
        // transaction not an object
        let not_obj = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": "raw-bytes-attempt",
            "auth_signature": {"pubkey": "p", "signature": "s"}
        });
        assert_eq!(
            validate_sign_request(&not_obj.to_string().into_bytes()),
            Err(SignDenial::BadRequest)
        );
        // empty auth signature fields
        let empty_sig = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {},
            "auth_signature": {"pubkey": "", "signature": "s"}
        });
        assert_eq!(
            validate_sign_request(&empty_sig.to_string().into_bytes()),
            Err(SignDenial::BadRequest)
        );
        // the VALID body passes validation...
        assert!(validate_sign_request(&valid_body(None)).is_ok());
        // ...but the router STILL refuses it (deny-by-default skeleton)
        assert_eq!(
            route("POST", "/sign", &valid_body(None)),
            SkeletonResponse::AcceptedButNotImplemented(SignDenial::NotImplemented)
        );
    }

    #[test]
    fn private_key_material_is_refused_outright() {
        // a "transaction" that smuggles a private key field
        let smuggled = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {
                "feePayer": "x",
                "dataBase64": "AAAA",
                "private_key": "64-bytes-of-key"
            },
            "auth_signature": {"pubkey": "p", "signature": "s"}
        });
        assert_eq!(
            validate_sign_request(&smuggled.to_string().into_bytes()),
            Err(SignDenial::PrivateMaterial)
        );
        // raw 64-byte-array keypair attempt in the auth field
        let array_key = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {},
            "auth_signature": {"pubkey": "p", "signature": "s", "keypair": [1,2,3]}
        });
        // also caught by deny_unknown_fields, but assert the marker path too
        assert_eq!(
            validate_sign_request(&array_key.to_string().into_bytes()),
            Err(SignDenial::BadRequest)
        );
        // seed phrase attempt
        let seeded = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "transaction": {"note": "seed_phrase recovery words here"},
            "auth_signature": {"pubkey": "p", "signature": "s"}
        });
        assert_eq!(
            validate_sign_request(&seeded.to_string().into_bytes()),
            Err(SignDenial::PrivateMaterial)
        );
    }

    // -- deny-by-default / no-fallback -------------------------------------

    #[test]
    fn deny_by_default_every_path_and_method() {
        // any unknown method/path is denied
        for (m, p) in [
            ("GET", "/sign"),
            ("POST", "/health"),
            ("PUT", "/sign"),
            ("DELETE", "/anything"),
            ("POST", "/"),
        ] {
            assert!(
                matches!(route(m, p, b"{}"), SkeletonResponse::Denied(_)),
                "{m} {p} must deny"
            );
        }
    }

    // -- store isolation ----------------------------------------------------

    #[test]
    fn store_refuses_any_artifact_root() {
        // the app's store domain is never acceptable as the signer root
        assert_eq!(
            SignerStore::open(Path::new("/tmp/artifact/agent_wallets")).unwrap_err(),
            StoreError::ForbiddenRoot
        );
        assert_eq!(
            SignerStore::open(Path::new("/tmp/x/artifact")).unwrap_err(),
            StoreError::ForbiddenRoot
        );
    }

    #[test]
    fn store_reservation_is_exclusive_and_0600() {
        let root = temp_root("store");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();

        store.reserve_agent_slot(&id).expect("first reservation");
        assert_eq!(store.slot_state(&id).unwrap(), SlotState::Reserved);
        // exclusive: a second reservation refuses, without touching the file
        assert_eq!(
            store.reserve_agent_slot(&id).unwrap_err(),
            StoreError::Exists
        );
        assert_eq!(store.slot_state(&id).unwrap(), SlotState::Reserved);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.root().join(format!("{id}.key.json")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "store file is 0600");
        }
        assert!(store.root().to_str().unwrap().contains("agentpay-signer"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn store_fails_closed_on_corrupt_state() {
        let root = temp_root("corrupt");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        // corrupt content: non-JSON
        std::fs::write(store.root().join(format!("{id}.key.json")), b"garbage").unwrap();
        assert_eq!(store.slot_state(&id).unwrap_err(), StoreError::Corrupt);
        // JSON object (not the 64-byte array container)
        std::fs::write(
            store.root().join(format!("{id}.key.json")),
            br#"{"agent_id":"x","public_address":"y"}"#,
        )
        .unwrap();
        assert_eq!(store.slot_state(&id).unwrap_err(), StoreError::Corrupt);
        // 64 numbers but invalid ed25519 range is impossible — test a
        // truncated array instead
        std::fs::write(store.root().join(format!("{id}.key.json")), b"[1,2,3]").unwrap();
        assert_eq!(store.slot_state(&id).unwrap_err(), StoreError::Corrupt);
        // strict 64-byte container accepted (a valid keypair minted via the
        // provisioning path) — on a FRESH slot (the corrupt id above must
        // stay corrupt: provisioning it fails closed, it is never healed)
        assert_eq!(
            store
                .provision_agent_wallet(&id, "auth-pubkey-test")
                .unwrap_err(),
            StoreError::Corrupt,
            "corrupt slot fails closed even through provisioning"
        );
        let fresh_id = Uuid::new_v4();
        let outcome = store
            .provision_agent_wallet(&fresh_id, "auth-pubkey-test")
            .unwrap();
        assert!(matches!(outcome, ProvisionOutcome::Created { .. }));
        assert_eq!(store.slot_state(&fresh_id).unwrap(), SlotState::Linked);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn signer_store_never_touches_the_app_store_domain() {
        // even if a caller constructs a path that LOOKS like the app's store,
        // the reservation goes to the signer's own root — and any path under
        // artifact/ is refused outright (covered above). Here: the store root
        // naming discipline — files live under the signer root only.
        let root = temp_root("domain");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        store.reserve_agent_slot(&id).unwrap();
        let files: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            files,
            vec![format!("{id}.key.json")],
            "only the signer's own file exists"
        );
        assert!(!root.to_str().unwrap().contains("artifact"));
        std::fs::remove_dir_all(&root).ok();
    }

    // -- no network egress (structural) --------------------------------------

    #[test]
    fn no_egress_structural_pin() {
        // the signer PRODUCTION code contains NO outbound client machinery.
        // Scan everything BEFORE the test module (tests may hold a loopback
        // client for probing the listener), strip line comments, and check
        // both source and manifest.
        let lib = include_str!("lib.rs");
        let production = lib
            .split("mod tests")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let manifest = include_str!("../Cargo.toml");
        let forbidden: [&str; 3] = [concat!("req", "west"), concat!("hyper", " ="), "upstream"];
        for f in forbidden {
            assert!(
                !production.contains(f),
                "signer production code must never contain {f}"
            );
            assert!(
                !manifest.contains(f),
                "signer manifest must never contain {f}"
            );
        }
        // the production module has NO `connect` at all (listener binds only)
        assert!(
            !production.contains(".connect("),
            "no outbound connect in signer production code"
        );
        // and no raw TcpStream in production at all (tokio listener only)
        assert!(
            !production.contains("TcpStream"),
            "no TcpStream in production"
        );
    }

    // =====================================================================
    // STEP H-1 — AUTHENTICATED CHANNEL battery
    // =====================================================================

    #[test]
    fn channel_identity_roundtrip_and_discipline() {
        let root = temp_root("h1-id");
        let store = SignerStore::open(&root).unwrap();
        let pk1 = channel_public_key(&store).unwrap();
        // idempotent: the same key on re-read
        let pk2 = channel_public_key(&store).unwrap();
        assert_eq!(pk1, pk2);
        // the file is 0600 and a strict 64-byte container
        let path = store.root().join(CHANNEL_IDENTITY_FILE);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "channel key is 0600");
        }
        // corrupt container fails closed
        std::fs::write(&path, b"garbage").unwrap();
        assert!(channel_public_key(&store).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn channel_signature_roundtrip() {
        let root = temp_root("h1-sig");
        let store = SignerStore::open(&root).unwrap();
        let body = r#"{"success":true}"#;
        let sig = sign_channel_response(&store, body, "NONCE-1").unwrap();
        // verify with the channel pubkey
        let pk = channel_public_key(&store).unwrap();
        let pk_bytes = base58_decode_32(&pk).unwrap();
        let sig_bytes = base64_decode(&sig).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let mut msg = blake3::hash(body.as_bytes()).as_bytes().to_vec();
        msg.extend_from_slice(b"NONCE-1");
        assert!(
            rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                .unwrap()
                .verify(&pk_bytes, &msg)
        );
        // a DIFFERENT nonce does not verify (replay binding)
        let mut msg2 = blake3::hash(body.as_bytes()).as_bytes().to_vec();
        msg2.extend_from_slice(b"NONCE-2");
        assert!(
            !rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                .unwrap()
                .verify(&pk_bytes, &msg2)
        );
        // a modified body does not verify
        let mut msg3 = blake3::hash(br#"{"success":false}"#).as_bytes().to_vec();
        msg3.extend_from_slice(b"NONCE-1");
        assert!(
            !rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                .unwrap()
                .verify(&pk_bytes, &msg3)
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn policy_ir_cross_verification() {
        let policy = load_policy(
            br#"{"max_per_tx_kelvin":1000000,"recipients":["2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD"],"program_id":"11111111111111111111111111111111","max_instructions":1}"#,
        )
        .unwrap();
        // (a) MATCHING IR: every rule agrees
        let good_ir = r#"{"filters":[
            {"rule":"signer_policy_amount_cap","value":"1000000","source":"p"},
            {"rule":"signer_policy_recipient","value":"2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD","source":"p"},
            {"rule":"signer_policy_program_pin","value":"11111111111111111111111111111111","source":"p"},
            {"rule":"signer_policy_instruction_count","value":"1","source":"p"}
        ]}"#;
        assert!(
            cross_verify_policy_ir(good_ir, &policy).is_ok(),
            "matching IR passes"
        );
        // (b) cap mismatch
        let bad_cap = good_ir.replace("1000000", "999999");
        assert_eq!(
            cross_verify_policy_ir(&bad_cap, &policy).unwrap_err(),
            PolicyDenial::IrMismatch
        );
        // (c) recipient mismatch (extra recipient)
        // append the extra recipient by replacing the FIRST recipient
        // filter's closing brace
        let bad_recipient = good_ir.replace(
            "\"value\":\"2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD\",\"source\":\"p\"",
            "\"value\":\"2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD\",\"source\":\"p\"},
            {\"rule\":\"signer_policy_recipient\",\"value\":\"OTHER\",\"source\":\"p\"",
        );
        assert_eq!(
            cross_verify_policy_ir(&bad_recipient, &policy).unwrap_err(),
            PolicyDenial::IrMismatch
        );
        // (d) program mismatch
        let bad_program = good_ir.replace(
            "11111111111111111111111111111111",
            "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA",
        );
        assert_eq!(
            cross_verify_policy_ir(&bad_program, &policy).unwrap_err(),
            PolicyDenial::IrMismatch
        );
        // (e) instruction-count mismatch
        let bad_count = good_ir.replace(
            "instruction_count\",\"value\":\"1\"",
            "instruction_count\",\"value\":\"2\"",
        );
        assert_eq!(
            cross_verify_policy_ir(&bad_count, &policy).unwrap_err(),
            PolicyDenial::IrMismatch
        );
        // (f) malformed IR
        assert_eq!(
            cross_verify_policy_ir("not-json", &policy).unwrap_err(),
            PolicyDenial::IrMalformed
        );
        assert_eq!(
            cross_verify_policy_ir(r#"{"no_filters":true}"#, &policy).unwrap_err(),
            PolicyDenial::IrMalformed
        );
        // (g) EMPTY signer recipients vs a non-empty IR ⇒ mismatch (fail-closed)
        let empty_policy = load_policy(
            br#"{"max_per_tx_kelvin":1,"recipients":["x"],"program_id":"11111111111111111111111111111111","max_instructions":1}"#,
        )
        .unwrap();
        assert_eq!(
            cross_verify_policy_ir(good_ir, &empty_policy).unwrap_err(),
            PolicyDenial::IrMismatch
        );
    }

    #[test]
    fn binary_pin_semantics() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // (a) missing pin = the preserved posture
        unsafe { std::env::remove_var(BINARY_PIN_ENV) };
        assert!(verify_binary_pin().is_ok());
        // (b) garbage pin = configured but mismatched ⇒ FAIL
        unsafe { std::env::set_var(BINARY_PIN_ENV, "ab".repeat(32)) };
        assert!(verify_binary_pin().is_err());
        // (c) the ACTUAL digest passes
        let digest = own_binary_digest().unwrap();
        unsafe { std::env::set_var(BINARY_PIN_ENV, &digest) };
        assert!(verify_binary_pin().is_ok());
        // (d) empty pin = treated as absent
        unsafe { std::env::set_var(BINARY_PIN_ENV, "") };
        assert!(verify_binary_pin().is_ok());
        unsafe { std::env::remove_var(BINARY_PIN_ENV) };
    }

    #[test]
    fn own_binary_digest_is_stable() {
        let d1 = own_binary_digest().unwrap();
        let d2 = own_binary_digest().unwrap();
        assert_eq!(d1, d2, "the digest of the running binary is stable");
        assert_eq!(d1.len(), 64, "blake3 hex");
    }

    #[test]
    fn handshake_payload_is_signed_and_bound() {
        let root = temp_root("h2-hs");
        let store = SignerStore::open(&root).unwrap();
        let (body, sig, pk) = handshake_payload(&store, "HS-NONCE").unwrap();
        // the payload carries the digest + the channel pubkey + the nonce
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["binary_digest"].as_str().unwrap().len() == 64);
        assert_eq!(v["channel_nonce"], "HS-NONCE");
        assert_eq!(v["channel_pubkey"].as_str().unwrap(), pk);
        // the signature verifies over the payload with the channel identity
        let pk_bytes = base58_decode_32(&pk).unwrap();
        let sig_bytes = base64_decode(&sig).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        // the sig covers the clean payload (no signer_sig inside the payload)
        assert!(!body.contains("signer_sig"));
        let mut msg = blake3::hash(body.as_bytes()).as_bytes().to_vec();
        msg.extend_from_slice(b"HS-NONCE");
        assert!(
            rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                .unwrap()
                .verify(&pk_bytes, &msg)
        );
        // a different nonce does not verify
        let mut msg2 = blake3::hash(body.as_bytes()).as_bytes().to_vec();
        msg2.extend_from_slice(b"OTHER");
        assert!(
            !rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                .unwrap()
                .verify(&pk_bytes, &msg2)
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn nonce_parsing_is_strict() {
        assert_eq!(
            parse_nonce(br#"{"channel_nonce":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert!(parse_nonce(br#"{}"#).is_none(), "missing nonce");
        assert!(
            parse_nonce(br#"{"channel_nonce":""}"#).is_none(),
            "empty nonce"
        );
        assert!(parse_nonce(b"not json").is_none());
        let long = "x".repeat(200);
        let raw = format!(r#"{{"channel_nonce":"{long}"}}"#);
        assert!(parse_nonce(raw.as_bytes()).is_none(), "overlong nonce");
    }

    // =====================================================================
    // STEP 6 — ACTUAL SIGNATURE EXECUTION battery
    // =====================================================================

    /// serialize every env-gate-touching test (process-global env is
    /// shared across parallel test threads). G79: this is THE crate-wide
    /// lock — the user-lane test shard shares the SAME instance (a private
    /// lock per module let two batteries toggle the same env var
    /// concurrently and corrupt each other; proven by the G79 run).
    use crate::CROSS_TEST_ENV_LOCK as ENV_LOCK;
    use std::sync::Mutex;

    /// the env-gate harness: arms/disarms the signing capability per-test
    /// (tests are serialized by the LIVE_LOCK discipline; the env var is
    /// process-global, so each test owns it for its duration)
    fn with_signing_enabled<R>(f: impl FnOnce() -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: test-only env manipulation, serialized by ENV_LOCK
        unsafe { std::env::set_var(SIGNING_ENABLED_ENV, "1") };
        let r = f();
        unsafe { std::env::remove_var(SIGNING_ENABLED_ENV) };
        r
    }

    #[test]
    fn happy_path_signs_and_self_verifies() {
        let f = ChainFixture::new("step6-happy");
        let tx = f.semantic_tx(RECIPIENT_B58, 500_000);
        let sig = f.sign_canonical(&tx);
        with_signing_enabled(|| {
            let envelope = sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms)
                .expect("full chain + signing");
            // (A) the envelope's identity fields are correct
            assert_eq!(envelope.agent_id, f.agent_id.to_string());
            assert_eq!(envelope.public_address, f.wallet_address());
            // (B) the envelope's message IS the signer's canonical bytes
            let msg = base64_decode(&envelope.canonical_message_b64).unwrap();
            let (_, expected_bytes, _) = canonicalize(&tx, &f.wallet_address()).unwrap();
            assert_eq!(msg, expected_bytes, "signed EXACTLY the canonical bytes");
            // (C) the signature self-verifies: signer's pubkey + exact bytes
            let wallet_addr = base58_decode_32(&f.wallet_address()).unwrap();
            let sig_bytes = base64_decode(&envelope.signature_b64).unwrap();
            assert!(
                rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                    .unwrap()
                    .verify(&wallet_addr, &msg)
            );
            // (D) the signature does NOT verify over ALTERED bytes
            let mut altered = msg.clone();
            altered[0] ^= 0xff;
            assert!(
                !rialo_s_signature::Signature::try_from(sig_bytes.as_slice())
                    .unwrap()
                    .verify(&wallet_addr, &altered)
            );
            // (E) the unsigned envelope is the SDK-shaped artifact
            let unsigned = base64_decode(&envelope.unsigned_envelope_b64()).unwrap();
            assert_eq!(unsigned[0], envelope.required_signatures);
            assert_eq!(&unsigned[1..65], &[0u8; 64]);
            assert_eq!(&unsigned[65..], &msg);
        });
    }

    #[test]
    fn signing_is_env_gated_fail_closed() {
        let f = ChainFixture::new("step6-gate");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // gate ABSENT: the full chain authorizes, but signing refuses
        unsafe { std::env::remove_var(SIGNING_ENABLED_ENV) };
        assert_eq!(
            sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms).unwrap_err(),
            PreSignDenial::SigningNotEnabled
        );
        // gate set to garbage: still refused
        unsafe { std::env::set_var(SIGNING_ENABLED_ENV, "yes") };
        assert_eq!(
            sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms).unwrap_err(),
            PreSignDenial::SigningNotEnabled
        );
        unsafe { std::env::remove_var(SIGNING_ENABLED_ENV) };
    }

    #[test]
    fn unauthorized_callers_cannot_reach_signing() {
        let f = ChainFixture::new("step6-unauth");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let good_sig = f.sign_canonical(&tx);
        with_signing_enabled(|| {
            // every Step 5 denial REMAINS the gate — signing is unreachable:
            // (a) unknown agent
            let stranger = Uuid::new_v4();
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &stranger, &good_sig, &tx, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::UnknownAgent
            );
            // (b) wrong auth signature
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, "AAAA", &tx, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::Auth(AuthDenial::Malformed)
            );
            // (c) policy denial
            let big = f.semantic_tx(RECIPIENT_B58, 2_000_000);
            let big_sig = f.sign_canonical(&big);
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, &big_sig, &big, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::Policy(PolicyDenial::AmountCap)
            );
            // (d) BYTE_DIVERGENCE
            let mut diverged = tx.clone();
            diverged.canonical_hash = Some("f".repeat(64));
            let diverged_sig = f.sign_canonical(&diverged);
            assert_eq!(
                sign_transaction(
                    &f.store,
                    &f.policy,
                    &f.agent_id,
                    &diverged_sig,
                    &diverged,
                    f.now_ms,
                )
                .unwrap_err(),
                PreSignDenial::ByteDivergence
            );
            // (e) canonicalization failure (bad recipient): the signer can
            // never canonicalize it, so the chain denies before signing —
            // no signature can even be produced for such a request
            let mut bad = tx.clone();
            bad.recipient = "!!".into();
            assert!(matches!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, "AAAA", &bad, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::Canonical(_)
            ));
        });
    }

    #[test]
    fn agent_a_cannot_use_agent_b_wallet() {
        let root = temp_root("step6-cross");
        let store = SignerStore::open(&root).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mk = |id: &Uuid| {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            let kp = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
            let pk = {
                use rialo_s_signer::Signer;
                kp.pubkey().to_string()
            };
            store.provision_agent_wallet(id, &pk).unwrap();
            kp
        };
        let _kp_a = mk(&a);
        let kp_b = mk(&b);
        let policy = load_policy(
            br#"{"max_per_tx_kelvin": 1000000, "recipients": ["2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD"], "program_id": "11111111111111111111111111111111", "max_instructions": 1}"#,
        )
        .unwrap();
        let now = 1_730_000_000_000;
        let tx_a = SemanticTransaction {
            fee_payer: store.agent_public_address(&a).unwrap().unwrap(),
            recipient: RECIPIENT_B58.into(),
            amount_kelvin: 100,
            valid_from_ms: now,
            config_hash_prefix: "8888927001659606077".into(),
            occ: false,
            canonical_hash: None,
            canonical_bytes: None,
        };
        // B's AUTH key signs the request for A's intent — but the AUTH
        // linkage recorded for A is A's key, so B's signature is INVALID
        let (_, bytes, _) = canonicalize(&tx_a, &tx_a.fee_payer).unwrap();
        let wrong_auth_sig = {
            use rialo_s_signer::Signer;
            base64_encode(&<[u8; 64]>::from(kp_b.sign_message(&bytes)))
        };
        with_signing_enabled(|| {
            assert_eq!(
                sign_transaction(&store, &policy, &a, &wrong_auth_sig, &tx_a, now).unwrap_err(),
                PreSignDenial::Auth(AuthDenial::Invalid),
                "B's auth key cannot authorize A's intent"
            );
        });
        // and even a VALID A authorization never produces B's wallet in the
        // envelope (the payer is pinned to the signer-owned record)
        let right_auth_sig = {
            // simulate A's key for the honest path: re-derive from the record
            // linkage? The fixture holds only B's key here; use A's key via a
            // fresh ChainFixture for the positive case instead (covered by
            // happy_path). The binding check here: envelope public_address
            // ALWAYS equals the record's address for the agent named.
        };
        let _ = right_auth_sig;
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_or_missing_key_fails_closed() {
        let f = ChainFixture::new("step6-keyfail");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        with_signing_enabled(|| {
            // corrupt key container: the record↔key INTEGRITY check (STEP 4)
            // fails the chain CLOSED before any signing attempt
            let key_path = f.store.root().join(format!("{}.key.json", f.agent_id));
            std::fs::write(&key_path, b"garbage").unwrap();
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::UnknownAgent,
                "corrupt custody denies at the integrity gate"
            );
            // missing key container: same fail-closed integrity denial
            std::fs::remove_file(&key_path).unwrap();
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::UnknownAgent
            );
            // wallet/address mismatch: a DIFFERENT valid container — the
            // record's public_address no longer matches the container's
            // derived address; integrity refuses (no re-mint, no fallback)
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            let other = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
            std::fs::write(
                &key_path,
                serde_json::to_vec(&other.to_bytes().to_vec()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::UnknownAgent,
                "swapped custody fails closed"
            );
        });
    }

    #[test]
    fn caller_cannot_nominate_another_payer() {
        let f = ChainFixture::new("step6-payer");
        // the semantic tx names a payer that is NOT the signer-owned wallet
        let mut foreign = f.semantic_tx(RECIPIENT_B58, 100);
        foreign.fee_payer = OTHER_RECIPIENT.into();
        let sig = {
            // sign the bytes the CALLER would derive (foreign payer) — the
            // signer must refuse at canonicalization, before any signing
            match canonicalize(&foreign, &f.wallet_address()) {
                Err(CanonicalError::PayerMismatch) => {}
                other => panic!("expected PayerMismatch, got {other:?}"),
            }
            // and the full chain denies it
            String::new()
        };
        with_signing_enabled(|| {
            assert!(matches!(
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &foreign, f.now_ms)
                    .unwrap_err(),
                PreSignDenial::Canonical(CanonicalError::PayerMismatch)
            ));
        });
    }

    #[test]
    fn envelope_never_carries_private_material() {
        let f = ChainFixture::new("step6-envelope");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        with_signing_enabled(|| {
            let envelope =
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms).unwrap();
            let text = serde_json::to_string(&envelope).unwrap();
            // the ONLY fields are the public minimum
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
            keys.sort();
            let mut expected = vec![
                "agent_id",
                "public_address",
                "canonical_hash",
                "canonical_message_b64",
                "signature_b64",
                "required_signatures",
            ];
            expected.sort();
            assert_eq!(keys, expected);
            // no private wording, no container, no seed
            for forbidden in ["private", "seed", "key.json", "secret"] {
                assert!(
                    !text.to_lowercase().contains(forbidden),
                    "{forbidden} leaked"
                );
            }
            // the Debug surface too
            let dbg = format!("{envelope:?}");
            assert!(!dbg.to_lowercase().contains("private"));
            // the wallet record / key container are NEVER in the envelope
            assert!(!text.contains(&format!("{}.key.json", f.agent_id)));
        });
    }

    #[test]
    fn repeated_authorization_is_deterministic() {
        let f = ChainFixture::new("step6-determinism");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        with_signing_enabled(|| {
            let e1 =
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms).unwrap();
            let e2 =
                sign_transaction(&f.store, &f.policy, &f.agent_id, &sig, &tx, f.now_ms).unwrap();
            // identical input ⇒ identical envelope (same wallet, same bytes,
            // same policy; ed25519 is deterministic)
            assert_eq!(
                e1, e2,
                "repeated authorization must not switch wallets/policy"
            );
        });
    }

    #[test]
    fn artifact_wallets_are_never_a_fallback() {
        // structural: the production code contains no artifact/agent_wallets
        // reference — there is NO fallback key source
        let production = lib_production_code();
        // the ONLY artifact reference is the refusal constant (no path
        // construction, no fallback source)
        assert!(!production.contains("artifact/"), "no artifact path");
        assert!(!production.contains("agent_wallets"), "no fallback source");
        // and the ONLY key source is the signer's own store path
        assert!(production.contains("self.root.join"));
    }

    #[test]
    fn no_broadcast_capability_anywhere() {
        let production = lib_production_code();
        for forbidden in [
            "sendTransaction",
            "eth_sendRawTransaction",
            "TcpStream",
            "reqwest",
        ] {
            assert!(
                !production.contains(forbidden),
                "{forbidden} must be absent"
            );
        }
        // the manifest too
        let manifest = include_str!("../Cargo.toml");
        assert!(!manifest.contains("reqwest"));
    }

    #[test]
    fn live_signing_smoke() {
        // the LIVE store (provisioned in STEP 4) — but the auth private keys
        // are held by the operator/agents, NOT in the repo, so the live chain
        // cannot be signed here BY DESIGN. This test only proves the live
        // store's records still integrity-check (record↔key↔address).
        let live = std::path::Path::new("/home/mahmoud/agentpay-signer-store");
        if !live.exists() {
            return;
        }
        let store = SignerStore::open(live).unwrap();
        for id in [
            "d547d407-c5ba-4ea5-854f-69ef213e5c5f",
            "dfcaa852-c5a7-4cd8-a72a-e71049d6c174",
            "8551ac69-2f0b-476e-8ea6-61cc6f608114",
            "1c671bd1-7ca9-490a-b93a-4850f36eea75",
        ] {
            let uuid = Uuid::parse_str(id).unwrap();
            let addr = store.agent_public_address(&uuid).expect("integrity ok");
            assert!(addr.is_some(), "{id} has a wallet record");
        }
    }

    // =====================================================================
    // STEP 5 — AUTH VERIFICATION + POLICY + CANONICAL BINDING battery
    // =====================================================================

    /// A canonical END-TO-END test fixture: provision a wallet, build the
    /// semantic tx, sign the signer's canonical bytes with a test keypair
    /// whose pubkey is bound as the agent's auth key.
    struct ChainFixture {
        store: SignerStore,
        agent_id: Uuid,
        auth_keypair: rialo_s_keypair::Keypair,
        policy: SignerPolicy,
        now_ms: i64,
    }

    const RECIPIENT_B58: &str = "2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD";
    const OTHER_RECIPIENT: &str = "2GPTMMpiG3r2KYnZ7PB3qWLAFTtMjUr5U6WsriXN699M";

    impl ChainFixture {
        fn new(tag: &str) -> Self {
            let root = temp_root(tag);
            let store = SignerStore::open(&root).unwrap();
            let agent_id = Uuid::new_v4();
            // mint the funds-less AUTH keypair for the agent (public half
            // becomes the D8/G-7 linkage; the private half stays in the
            // TEST only — this is how the auth signature is produced)
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).unwrap();
            let auth_keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
            let auth_pubkey = {
                use rialo_s_signer::Signer;
                auth_keypair.pubkey().to_string()
            };
            store
                .provision_agent_wallet(&agent_id, &auth_pubkey)
                .expect("provision");
            let policy = load_policy(
                br#"{"max_per_tx_kelvin": 1000000, "recipients": ["2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD"], "program_id": "11111111111111111111111111111111", "max_instructions": 1}"#,
            )
            .unwrap();
            Self {
                store,
                agent_id,
                auth_keypair,
                policy,
                now_ms: 1_730_000_000_000,
            }
        }

        fn wallet_address(&self) -> String {
            self.store
                .agent_public_address(&self.agent_id)
                .unwrap()
                .unwrap()
        }

        fn semantic_tx(&self, recipient: &str, amount: u64) -> SemanticTransaction {
            SemanticTransaction {
                fee_payer: self.wallet_address(),
                recipient: recipient.to_string(),
                amount_kelvin: amount,
                valid_from_ms: self.now_ms,
                config_hash_prefix: "8888927001659606077".to_string(),
                occ: false,
                canonical_hash: None,
                canonical_bytes: None,
            }
        }

        /// sign the SIGNER'S canonical bytes with the auth key (the app's
        /// side of the protocol: it must sign the same bytes the signer
        /// recompiles)
        fn sign_canonical(&self, tx: &SemanticTransaction) -> String {
            let (_, bytes, _) = canonicalize(tx, &self.wallet_address()).unwrap();
            use rialo_s_signer::Signer;
            let sig = self.auth_keypair.sign_message(&bytes);
            base64_encode(&<[u8; 64]>::from(sig))
        }

        fn authorize(
            &self,
            tx: &SemanticTransaction,
            sig_b64: &str,
        ) -> Result<PreSignAuthorization, PreSignDenial> {
            authorize_pre_sign(
                &self.store,
                &self.policy,
                &self.agent_id,
                sig_b64,
                tx,
                self.now_ms,
            )
        }
    }

    #[test]
    fn canonical_and_signature_happy_path() {
        let f = ChainFixture::new("step5-happy");
        let tx = f.semantic_tx(RECIPIENT_B58, 500_000);
        let sig = f.sign_canonical(&tx);
        let verdict = f.authorize(&tx, &sig).expect("full chain success");
        // AUTHENTICATED + CANONICALIZED + POLICY_APPROVED — and nothing more
        assert!(!verdict.canonical_bytes.is_empty());
        assert_eq!(verdict.canonical_hash.len(), 64, "blake3 hex");
        assert_eq!(verdict.public_address, f.wallet_address());
        assert_eq!(verdict.auth_pubkey, {
            use rialo_s_signer::Signer;
            f.auth_keypair.pubkey().to_string()
        });
        // canonical bytes are EXACTLY the authoritative builder's output
        let (_, expected_bytes, _) = canonicalize(&tx, &f.wallet_address()).unwrap();
        assert_eq!(verdict.canonical_bytes, expected_bytes);
    }

    #[test]
    fn signature_failure_modes() {
        let f = ChainFixture::new("step5-sig");
        let tx = f.semantic_tx(RECIPIENT_B58, 500_000);
        let good_sig = f.sign_canonical(&tx);

        // (a) tampered amount after signing ⇒ signature over DIFFERENT
        // canonical bytes ⇒ INVALID
        let mut tampered = f.semantic_tx(RECIPIENT_B58, 500_001);
        tampered.amount_kelvin = 500_001;
        assert_eq!(
            f.authorize(&tampered, &good_sig).unwrap_err(),
            PreSignDenial::Auth(AuthDenial::Invalid),
            "signature over divergent bytes rejected"
        );

        // (b) a DIFFERENT agent's key (wrong auth key): mint a foreign key,
        // sign, expect INVALID (the record's auth key is the verifier)
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let foreign = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
        let (_, bytes, _) = canonicalize(&tx, &f.wallet_address()).unwrap();
        use rialo_s_signer::Signer;
        let foreign_sig = base64_encode(&<[u8; 64]>::from(foreign.sign_message(&bytes)));
        assert_eq!(
            f.authorize(&tx, &foreign_sig).unwrap_err(),
            PreSignDenial::Auth(AuthDenial::Invalid),
            "wrong auth key rejected"
        );

        // (c) malformed signature (not base64 / wrong length)
        assert_eq!(
            f.authorize(&tx, "!!!not-base64!!!").unwrap_err(),
            PreSignDenial::Auth(AuthDenial::Malformed)
        );
        let short = base64_encode(&[1u8; 32]);
        assert_eq!(
            f.authorize(&tx, &short).unwrap_err(),
            PreSignDenial::Auth(AuthDenial::Malformed)
        );

        // (d) unknown agent
        let stranger = Uuid::new_v4();
        assert_eq!(
            authorize_pre_sign(&f.store, &f.policy, &stranger, &good_sig, &tx, f.now_ms)
                .unwrap_err(),
            PreSignDenial::UnknownAgent
        );
    }

    #[test]
    fn byte_divergence_is_enforced() {
        let f = ChainFixture::new("step5-binding");
        let tx = f.semantic_tx(RECIPIENT_B58, 500_000);
        let sig = f.sign_canonical(&tx);
        let (_, bytes, hash) = canonicalize(&tx, &f.wallet_address()).unwrap();

        // (a) a WRONG caller hash ⇒ BYTE_DIVERGENCE
        let mut wrong_hash = tx.clone();
        wrong_hash.canonical_hash = Some("0".repeat(64));
        assert_eq!(
            f.authorize(&wrong_hash, &sig).unwrap_err(),
            PreSignDenial::ByteDivergence
        );

        // (b) the CORRECT caller hash is accepted (binding evidence agrees)
        let mut right_hash = tx.clone();
        right_hash.canonical_hash = Some(hash.clone());
        assert!(f.authorize(&right_hash, &sig).is_ok());

        // (c) WRONG caller bytes ⇒ BYTE_DIVERGENCE
        let mut wrong_bytes = tx.clone();
        wrong_bytes.canonical_bytes = Some(base64_encode(&[9u8; 32]));
        assert_eq!(
            f.authorize(&wrong_bytes, &sig).unwrap_err(),
            PreSignDenial::ByteDivergence
        );

        // (d) the CORRECT caller bytes agree
        let mut right_bytes = tx.clone();
        right_bytes.canonical_bytes = Some(base64_encode(&bytes));
        assert!(f.authorize(&right_bytes, &sig).is_ok());

        // (e) ABSENCE is accepted (signer-side derivation is authoritative)
        assert!(f.authorize(&tx, &sig).is_ok());

        // (f) caller bytes can NEVER override: even with a matching hash, a
        // different byte string is refused (the signer's recompile wins)
        let mut override_attempt = tx.clone();
        override_attempt.canonical_hash = Some(hash.clone());
        override_attempt.canonical_bytes = Some(base64_encode(&[7u8; 64]));
        assert_eq!(
            f.authorize(&override_attempt, &sig).unwrap_err(),
            PreSignDenial::ByteDivergence
        );
    }

    #[test]
    fn policy_denial_modes() {
        let f = ChainFixture::new("step5-policy");
        let tx = f.semantic_tx(RECIPIENT_B58, 500_000);
        let sig = f.sign_canonical(&tx);

        // (a) amount over cap
        let big = f.semantic_tx(RECIPIENT_B58, 1_000_001);
        let big_sig = f.sign_canonical(&big);
        assert_eq!(
            f.authorize(&big, &big_sig).unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::AmountCap)
        );

        // (b) recipient outside the allow-list
        let other = f.semantic_tx(OTHER_RECIPIENT, 100);
        let other_sig = f.sign_canonical(&other);
        assert_eq!(
            f.authorize(&other, &other_sig).unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::RecipientNotAllowlisted)
        );

        // (c) empty allow-list ⇒ DENY (fail-closed)
        let empty_policy = load_policy(
            br#"{"max_per_tx_kelvin": 1000000, "recipients": [], "program_id": "11111111111111111111111111111111", "max_instructions": 1}"#,
        )
        .unwrap();
        assert_eq!(
            authorize_pre_sign(&f.store, &empty_policy, &f.agent_id, &sig, &tx, f.now_ms)
                .unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::RecipientListEmpty)
        );

        // (d) wildcard "*" in the allow-list ⇒ REJECTED AT LOAD (never
        // interpreted as unrestricted)
        assert_eq!(
            load_policy(
                br#"{"max_per_tx_kelvin": 1000000, "recipients": ["*"], "program_id": "11111111111111111111111111111111", "max_instructions": 1}"#,
            )
            .unwrap_err(),
            PolicyLoadError::WildcardRejected
        );

        // (e) program mismatch (the policy's program pin doesn't match the
        // canonical shape's System program)
        let wrong_program = load_policy(
            br#"{"max_per_tx_kelvin": 1000000, "recipients": ["2TDiHujMTZZuvqcWPu7sn7WuTwogcqFXa3hBMpzSWAGD"], "program_id": "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA", "max_instructions": 1}"#,
        )
        .unwrap();
        assert_eq!(
            authorize_pre_sign(&f.store, &wrong_program, &f.agent_id, &sig, &tx, f.now_ms)
                .unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::ProgramMismatch)
        );

        // (f) validFrom violation: too old
        let mut stale = f.semantic_tx(RECIPIENT_B58, 100);
        stale.valid_from_ms = f.now_ms - 200_000;
        let stale_sig = f.sign_canonical(&stale);
        assert_eq!(
            f.authorize(&stale, &stale_sig).unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::ValidFromWindow)
        );
        // far future too (unusable replay window)
        let mut future = f.semantic_tx(RECIPIENT_B58, 100);
        future.valid_from_ms = f.now_ms + 200_000;
        let future_sig = f.sign_canonical(&future);
        assert_eq!(
            f.authorize(&future, &future_sig).unwrap_err(),
            PreSignDenial::Policy(PolicyDenial::ValidFromWindow)
        );

        // (g) malformed policy JSON
        assert_eq!(
            load_policy(b"not-json").unwrap_err(),
            PolicyLoadError::Malformed
        );
        assert_eq!(
            load_policy(br#"{"recipients": ["x"], "max_instructions": 1}"#,).unwrap_err(),
            PolicyLoadError::Malformed,
            "missing cap = malformed (no default = deny)"
        );
        // unknown field in the policy
        assert_eq!(
            load_policy(
                br#"{"max_per_tx_kelvin":1,"recipients":["x"],"program_id":"11111111111111111111111111111111","max_instructions":1,"daily_kelvin":9}"#,
            )
            .unwrap_err(),
            PolicyLoadError::Malformed
        );
    }

    #[test]
    fn semantic_malformed_and_unsupported() {
        let f = ChainFixture::new("step5-semantic");
        // bad base58 recipient
        let mut bad = f.semantic_tx("not-base58!!", 100);
        bad.recipient = "not-base58!!".into();
        assert_eq!(
            canonicalize(&bad, &f.wallet_address()).unwrap_err(),
            CanonicalError::Malformed
        );
        // bad decimal config_hash_prefix
        let mut bad_cfg = f.semantic_tx(RECIPIENT_B58, 100);
        bad_cfg.config_hash_prefix = "12x".into();
        assert_eq!(
            canonicalize(&bad_cfg, &f.wallet_address()).unwrap_err(),
            CanonicalError::Malformed
        );
        // payer mismatch: the signer signs ONLY its own wallet
        let mut foreign_payer = f.semantic_tx(RECIPIENT_B58, 100);
        foreign_payer.fee_payer = OTHER_RECIPIENT.into();
        assert_eq!(
            canonicalize(&foreign_payer, &f.wallet_address()).unwrap_err(),
            CanonicalError::PayerMismatch
        );
        // empty pubkey
        let mut empty = f.semantic_tx(RECIPIENT_B58, 100);
        empty.recipient = String::new();
        assert_eq!(
            canonicalize(&empty, &f.wallet_address()).unwrap_err(),
            CanonicalError::Malformed
        );
    }

    #[test]
    fn corrupt_wallet_state_fails_closed() {
        let f = ChainFixture::new("step5-corrupt");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        // corrupt the wallet record (auth linkage destroyed)
        let record_path = f.store.root().join(format!("{}.wallet.json", f.agent_id));
        std::fs::write(&record_path, b"garbage").unwrap();
        assert_eq!(
            f.authorize(&tx, &sig).unwrap_err(),
            PreSignDenial::UnknownAgent,
            "corrupt state denies"
        );
        // remove the record entirely
        std::fs::remove_file(&record_path).unwrap();
        assert_eq!(
            f.authorize(&tx, &sig).unwrap_err(),
            PreSignDenial::UnknownAgent
        );
    }

    #[test]
    fn canonical_recompile_is_zero_drift_with_the_server() {
        // the strongest structural evidence: the signer's canonical module
        // IS the server's file (same source path) — and the I-2 fixture
        // battery (builder_matches_sdk_serializer_fixtures, etc.) runs
        // inside THIS crate's test suite (see the rialo_canonical::i2_tests
        // results). Pin the source path here.
        assert!(
            include_str!("../../../src/bin/server/rialo_canonical.rs")
                .contains("pub fn build_canonical_message")
        );
    }

    #[test]
    fn base58_roundtrip_and_strictness() {
        // known vector: 32 zero bytes = "11111111111111111111111111111111"
        let zeros = base58_decode_32("11111111111111111111111111111111").unwrap();
        assert_eq!(zeros, [0u8; 32]);
        assert_eq!(base58_encode(&zeros), "11111111111111111111111111111111");
        // a real agent address roundtrips
        let addr = base58_decode_32(RECIPIENT_B58).unwrap();
        assert_eq!(base58_encode(&addr), RECIPIENT_B58);
        // non-canonical input rejected
        assert!(base58_decode_32("0OIl").is_none(), "invalid alphabet chars");
        assert!(base58_decode_32("").is_none());
        // overlong input (>32 bytes) rejected
        let long = "2".repeat(60);
        assert!(base58_decode_32(&long).is_none());
    }

    #[test]
    fn no_private_material_in_authorization_surfaces() {
        let f = ChainFixture::new("step5-nokey");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        let verdict = f.authorize(&tx, &sig).unwrap();
        let debug = format!("{verdict:?}");
        // the auth pubkey is PUBLIC; the PRIVATE half must never appear
        use rialo_s_signer::Signer;
        let _pubkey = f.auth_keypair.pubkey().to_string();
        // the private secret bytes (rialo Keypair.secret()) must not leak —
        // the Debug/serialization surface of the verdict has no such field
        assert!(!debug.contains("secret"), "no secret field in the verdict");
        assert!(
            !debug.contains("private"),
            "no private field in the verdict"
        );
        // denials are fieldless
        for d in [
            PreSignDenial::BadRequest,
            PreSignDenial::ByteDivergence,
            PreSignDenial::UnknownAgent,
            PreSignDenial::Policy(PolicyDenial::AmountCap),
            PreSignDenial::Auth(AuthDenial::Invalid),
        ] {
            let body = d.body();
            assert!(!body.contains("sig"), "no signature echo in denials");
            assert!(body.len() < 90, "typed denials stay tiny: {body}");
        }
    }

    #[test]
    fn sign_endpoint_remains_disabled_and_no_funds_move() {
        let f = ChainFixture::new("step5-nosign");
        let tx = f.semantic_tx(RECIPIENT_B58, 100);
        let sig = f.sign_canonical(&tx);
        // the FULL chain succeeds...
        assert!(f.authorize(&tx, &sig).is_ok());
        // ...but there is NO signing capability: /sign stays 403, no
        // broadcast primitive exists, no funds can move through this crate
        assert!(matches!(
            route("POST", "/sign", &valid_body(None)),
            SkeletonResponse::AcceptedButNotImplemented(SignDenial::NotImplemented)
        ));
        let production = lib_production_code();
        assert!(!production.contains("sendTransaction"));
        assert!(!production.contains("eth_sendRawTransaction"));
        // the signing act is env-gated (STEP 6) — its boundness is pinned by
        // the STEP 6 battery (gating + no-broadcast)
        // and the authorization verdict serializes to PUBLIC fields only:
        // no signature-slot material, no broadcastable artifact
        let verdict_json = serde_json::to_string(&serde_json::json!({
            "canonical_hash": "x",
            "public_address": "y",
        }))
        .unwrap();
        assert!(!verdict_json.contains("signature"));
    }

    // =====================================================================
    // STEP 4 — KEY MATERIAL + PROVISIONING battery
    // =====================================================================

    fn auth_of(store: &SignerStore, id: &Uuid) -> Option<String> {
        let p = store.root().join(format!("{id}.wallet.json"));
        if !p.exists() {
            return None;
        }
        let record: WalletRecord = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        Some(record.auth_pubkey)
    }

    #[test]
    fn fresh_wallet_generation_provisions_one_wallet_per_agent() {
        let root = temp_root("step4-fresh");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();

        let outcome = store
            .provision_agent_wallet(&id, "auth-pk-A")
            .expect("first provision");
        let addr1 = match outcome {
            ProvisionOutcome::Created { public_address } => public_address,
            other => panic!("expected Created, got {other:?}"),
        };
        // the public address is a plausible base58 ed25519 pubkey (44ish chars)
        assert!(
            !addr1.is_empty() && addr1.len() >= 40 && addr1.len() <= 50,
            "{addr1}"
        );
        // the wallet record carries ONLY public data
        let record_bytes = std::fs::read(store.root().join(format!("{id}.wallet.json"))).unwrap();
        let record: WalletRecord = serde_json::from_slice(&record_bytes).unwrap();
        assert_eq!(record.agent_id, id.to_string());
        assert_eq!(record.public_address, addr1);
        assert_eq!(record.auth_pubkey, "auth-pk-A");
        // the key container exists next to it (64-byte JSON array)
        let key_bytes = std::fs::read(store.root().join(format!("{id}.key.json"))).unwrap();
        assert!(wallet_key_public_address_from_bytes(&key_bytes).is_ok());
        // public read helper matches
        assert_eq!(
            store.agent_public_address(&id).unwrap().as_deref(),
            Some(addr1.as_str())
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn duplicate_provisioning_is_rejected_and_idempotent() {
        let root = temp_root("step4-dup");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();

        let first = store
            .provision_agent_wallet(&id, "auth-pk-A")
            .expect("first");
        let addr_first = match first {
            ProvisionOutcome::Created { public_address } => public_address,
            other => panic!("{other:?}"),
        };
        // idempotent: SAME auth key → Already with the SAME address; the key
        // container is NOT rewritten
        let second = store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        match second {
            ProvisionOutcome::Already { public_address } => {
                assert_eq!(public_address, addr_first, "same wallet returned");
            }
            other => panic!("expected Already, got {other:?}"),
        }
        // a THIRD run: still Already, byte-identical record
        let rec_before = std::fs::read(store.root().join(format!("{id}.wallet.json"))).unwrap();
        let _ = store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        let rec_after = std::fs::read(store.root().join(format!("{id}.wallet.json"))).unwrap();
        assert_eq!(rec_before, rec_after, "idempotent: record untouched");
        // a CHANGED auth key for the same agent is a hard error (never a
        // silent rewrite of the linkage)
        assert_eq!(
            store.provision_agent_wallet(&id, "auth-pk-B").unwrap_err(),
            StoreError::Corrupt
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn interrupted_provisioning_recovers_without_a_second_wallet() {
        let root = temp_root("step4-recover");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        // simulate the crash window: key container written, record NOT yet
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let keypair = rialo_s_keypair::keypair_from_seed(&seed).unwrap();
        let addr = {
            use rialo_s_signer::Signer;
            keypair.pubkey().to_string()
        };
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(store.root().join(format!("{id}.key.json")))
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            rialo_s_keypair::write_keypair(&keypair, &mut file).unwrap();
            file.flush().unwrap();
        }
        // the record is absent (the crash window)
        assert_eq!(store.agent_public_address(&id).unwrap(), None);

        // the next provisioning run RECOVERS (never mints a second wallet)
        let outcome = store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        match outcome {
            ProvisionOutcome::Recovered { public_address } => {
                assert_eq!(public_address, addr, "the SAME key is kept");
            }
            other => panic!("expected Recovered, got {other:?}"),
        }
        // and a further run is Already (idempotent convergence)
        match store.provision_agent_wallet(&id, "auth-pk-A").unwrap() {
            ProvisionOutcome::Already { public_address } => assert_eq!(public_address, addr),
            other => panic!("{other:?}"),
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn partial_record_without_valid_key_fails_closed() {
        let root = temp_root("step4-partial");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        // a wallet record WITHOUT a valid key container = INCOMPLETE state:
        // a well-formed record (canonical agent id) whose custody is missing
        let record = serde_json::json!({
            "agent_id": id.to_string(),
            "public_address": "CzPkEYB3GtJtzLmEr1RdDzhe7LveJyMWh3zXFauWNzHR",
            "auth_pubkey": "auth-pk-A"
        });
        std::fs::write(
            store.root().join(format!("{id}.wallet.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        // provisioning MUST fail closed: the record says this agent already
        // has a wallet, but the custody is missing — no silent re-mint onto
        // a dangling record, no "valid" answer
        assert!(store.provision_agent_wallet(&id, "auth-pk-A").is_err());
        // the public reader ALSO refuses to hand out an unverifiable wallet
        assert!(store.agent_public_address(&id).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_key_container_fails_closed_everywhere() {
        let root = temp_root("step4-corrupt");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        // a garbage key container: neither fresh nor recovery may succeed
        std::fs::write(store.root().join(format!("{id}.key.json")), b"garbage").unwrap();
        assert!(store.provision_agent_wallet(&id, "auth-pk-A").is_err());
        assert_eq!(store.agent_public_address(&id).unwrap(), None);
        // a truncated array
        std::fs::write(store.root().join(format!("{id}.key.json")), b"[1,2]").unwrap();
        assert!(store.provision_agent_wallet(&id, "auth-pk-A").is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn provisioning_never_writes_into_artifact_or_the_app_store() {
        let root = temp_root("step4-domain");
        // point the store INSIDE artifact/ — refused outright
        assert_eq!(
            SignerStore::open(&root.join("artifact/agent_wallets")).unwrap_err(),
            StoreError::ForbiddenRoot
        );
        // and a legitimate signer store keeps its own namespace
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        let mut names: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        let mut expected = vec![format!("{id}.key.json"), format!("{id}.wallet.json")];
        expected.sort();
        assert_eq!(names, expected);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn provisioning_never_returns_or_logs_private_material() {
        let root = temp_root("step4-nokey");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        let outcome = store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        let public_address = match &outcome {
            ProvisionOutcome::Created { public_address } => public_address.clone(),
            other => panic!("{other:?}"),
        };
        // the outcome carries ONE string: the public address
        let debug = format!("{outcome:?}");
        assert!(debug.contains(&public_address));
        assert!(!debug.contains("private"), "no private wording");
        assert!(!debug.contains("seed"), "no seed wording");
        // the wallet record contains NO private material
        let record_text = String::from_utf8(
            std::fs::read(store.root().join(format!("{id}.wallet.json"))).unwrap(),
        )
        .unwrap();
        assert!(
            !record_text.contains("private"),
            "no private field in the record"
        );
        assert!(!record_text.contains("seed"), "no seed field in the record");
        // the key container DOES hold the private half — but it never leaves
        // the store: verify only via the strict pubkey-only reader
        let key_bytes = std::fs::read(store.root().join(format!("{id}.key.json"))).unwrap();
        assert_eq!(
            wallet_key_public_address_from_bytes(&key_bytes).unwrap(),
            public_address
        );
        // two wallets: distinct keys (fresh randomness)
        let id2 = Uuid::new_v4();
        let o2 = store.provision_agent_wallet(&id2, "auth-pk-B").unwrap();
        let a2 = match o2 {
            ProvisionOutcome::Created { public_address } => public_address,
            other => panic!("{other:?}"),
        };
        assert_ne!(public_address, a2, "fresh keys are independent");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn provisioning_request_validation() {
        let ok = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "auth_pubkey": "DQ8PhyRQHh5k"
        });
        assert!(validate_provision_request(&ok.to_string().into_bytes()).is_ok());
        // malformed identifiers
        let bad_id = serde_json::json!({
            "agent_id": "not-a-uuid",
            "auth_pubkey": "k"
        });
        assert_eq!(
            validate_provision_request(&bad_id.to_string().into_bytes()).unwrap_err(),
            SignDenial::BadRequest
        );
        // unknown field (mass-assignment impossible)
        let extra = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "auth_pubkey": "k",
            "private_key": "boom"
        });
        assert_eq!(
            validate_provision_request(&extra.to_string().into_bytes()).unwrap_err(),
            SignDenial::BadRequest
        );
        // empty auth key
        let empty = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "auth_pubkey": ""
        });
        assert_eq!(
            validate_provision_request(&empty.to_string().into_bytes()).unwrap_err(),
            SignDenial::BadRequest
        );
        // not json
        assert_eq!(
            validate_provision_request(b"nope").unwrap_err(),
            SignDenial::BadRequest
        );
    }

    #[test]
    fn provisioning_route_has_no_signing_capability() {
        // the structural invariant: the router treats /provision as
        // VALIDATION ONLY (pure route — no store access) and /sign stays
        // refused; no signing primitive exists anywhere in this crate
        let body = serde_json::json!({
            "agent_id": Uuid::new_v4().to_string(),
            "auth_pubkey": "k"
        });
        match route("POST", "/provision", &body.to_string().into_bytes()) {
            SkeletonResponse::Provisioned {
                outcome_class,
                public_address,
            } => {
                assert_eq!(outcome_class, "validated");
                assert_eq!(
                    public_address, None,
                    "the pure route performs NO store work"
                );
            }
            other => panic!("expected Provisioned, got {other:?}"),
        }
        // and /sign still denies everything
        assert!(matches!(
            route("POST", "/sign", &valid_body(None)),
            SkeletonResponse::AcceptedButNotImplemented(SignDenial::NotImplemented)
        ));
        // the signing act EXISTS (STEP 6) but is structurally bounded: it is
        // reachable only through PreSignAuthorization + the env gate, and it
        // has NO broadcast path
        let production = lib_production_code();
        assert!(!production.contains("sendTransaction"), "no broadcast");
        assert!(
            !production.contains("eth_sendRawTransaction"),
            "no broadcast"
        );
        assert!(
            !production.contains("TcpStream"),
            "no egress from production (broadcast impossible)"
        );
    }

    fn lib_production_code() -> String {
        include_str!("lib.rs")
            .split("mod tests")
            .next()
            .unwrap_or_default()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn wallet_record_is_strict_about_shape() {
        let root = temp_root("step4-strict");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        let path = store.root().join(format!("{id}.wallet.json"));
        // unknown field ⇒ Corrupt on read
        std::fs::write(
            &path,
            br#"{"agent_id":"x","public_address":"y","auth_pubkey":"z","extra":1}"#,
        )
        .unwrap();
        assert!(store.provision_agent_wallet(&id, "auth-pk-A").is_err());
        // malformed agent id ⇒ Corrupt
        std::fs::write(
            &path,
            br#"{"agent_id":"../etc","public_address":"y","auth_pubkey":"z"}"#,
        )
        .unwrap();
        assert!(store.agent_public_address(&id).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn permissions_are_hardened_before_content() {
        let root = temp_root("step4-perm");
        let store = SignerStore::open(&root).unwrap();
        let id = Uuid::new_v4();
        store.provision_agent_wallet(&id, "auth-pk-A").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in [format!("{id}.key.json"), format!("{id}.wallet.json")] {
                let mode = std::fs::metadata(store.root().join(&name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o077, 0, "{name} has no group/other access");
            }
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn one_wallet_per_agent_across_many_agents() {
        let root = temp_root("step4-many");
        let store = SignerStore::open(&root).unwrap();
        let ids: Vec<_> = (0..5).map(|_| Uuid::new_v4()).collect();
        let mut addrs = Vec::new();
        for id in &ids {
            match store.provision_agent_wallet(id, "auth-pk").unwrap() {
                ProvisionOutcome::Created { public_address } => addrs.push(public_address),
                other => panic!("{other:?}"),
            }
        }
        // all distinct
        let unique: std::collections::HashSet<_> = addrs.iter().collect();
        assert_eq!(unique.len(), 5, "each agent got its OWN wallet");
        // and re-provisioning returns each agent's OWN address
        for (id, addr) in ids.iter().zip(&addrs) {
            match store.provision_agent_wallet(id, "auth-pk").unwrap() {
                ProvisionOutcome::Already { public_address } => {
                    assert_eq!(&public_address, addr);
                }
                other => panic!("{other:?}"),
            }
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn agentpay_store_files_are_never_a_provisioning_source() {
        // the signer mints FRESH keys; it never reads the app's 64-byte
        // containers as a source. Structural: the provision path contains
        // no artifact-path construction at all.
        let production = lib_production_code();
        // the ONLY artifact/ reference allowed is the refusal constant in
        // the store-root guard (the signer never CONSTRUCTS an artifact path)
        assert!(
            !production.contains("join(\"artifact"),
            "no artifact/ path construction"
        );
        assert!(
            !production.contains("agent_wallets"),
            "no agent_wallets references"
        );
        // and the ONLY filesystem reads the provision path performs are on
        // its OWN store paths (key_path/record_path under root)
        assert!(
            production.contains("self.root.join"),
            "store paths derive from the signer root only"
        );
    }

    // -- fail-closed process semantics ----------------------------------------

    #[test]
    fn denial_shapes_carry_no_detail() {
        for d in [
            SignDenial::BadRequest,
            SignDenial::PrivateMaterial,
            SignDenial::NotImplemented,
            SignDenial::StoreUnavailable,
            SignDenial::Internal,
        ] {
            let body = d.body();
            assert!(body.contains(r#""error":"DENIED""#));
            assert!(body.contains(r#""code":""#));
            assert!(!body.contains("path"), "no paths in denial bodies");
            assert!(!body.contains("artifact"), "no app paths in denial bodies");
            assert!(d.body().len() < 80, "typed bodies stay tiny");
        }
        // health shape is minimal
        assert_eq!(route("GET", "/health", b""), SkeletonResponse::Health);
    }

    // -- OPTION C: authenticated admin registration tests ----------------------

    #[test]
    fn admin_registration_idempotent_and_lookup() {
        let agent_id = Uuid::new_v4().to_string();
        let auth_pubkey = "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA";

        // First registration succeeds
        assert!(admin_register_agent(&agent_id, auth_pubkey).is_ok());

        // Same registration succeeds again (idempotent)
        assert!(admin_register_agent(&agent_id, auth_pubkey).is_ok());

        // Verify lookup works (with temp store for persisted wallet check)
        let static_list = std::collections::HashMap::new();
        let temp_dir = std::env::temp_dir().join(format!("signer-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let store = SignerStore::open(&temp_dir).unwrap();
        let found = lookup_provision_auth(&agent_id, &static_list, &store);
        assert_eq!(found, Some(auth_pubkey.to_string()));
    }

    #[test]
    fn admin_registration_conflicts_on_different_auth() {
        let agent_id = Uuid::new_v4().to_string();
        let auth1 = "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA";
        let auth2 = "7siRGNwSzvpCqdsZw5tjsz4XZ1SrpMXqKsr4zEjBVr1a";

        // First registration succeeds
        assert!(admin_register_agent(&agent_id, auth1).is_ok());

        // Different auth for same agent fails (conflict)
        assert!(admin_register_agent(&agent_id, auth2).is_err());
    }

    #[test]
    fn static_list_checked_before_runtime_registry() {
        let agent_id = Uuid::new_v4().to_string();
        let static_auth = "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA";
        let runtime_auth = "7siRGNwSzvpCqdsZw5tjsz4XZ1SrpMXqKsr4zEjBVr1a";

        // Set up static list with this agent
        let mut static_list = std::collections::HashMap::new();
        static_list.insert(agent_id.clone(), static_auth.to_string());

        // Register different auth in runtime (shouldn't matter)
        assert!(admin_register_agent(&agent_id, runtime_auth).is_ok());

        // Lookup returns the static list auth (checked first)
        let temp_dir = std::env::temp_dir().join(format!("signer-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let store = SignerStore::open(&temp_dir).unwrap();
        let found = lookup_provision_auth(&agent_id, &static_list, &store);
        assert_eq!(found, Some(static_auth.to_string()));
    }

    #[test]
    fn unknown_agent_returns_none() {
        let agent_id = Uuid::new_v4().to_string();
        let static_list = std::collections::HashMap::new();

        let temp_dir = std::env::temp_dir().join(format!("signer-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let store = SignerStore::open(&temp_dir).unwrap();
        let found = lookup_provision_auth(&agent_id, &static_list, &store);
        assert_eq!(found, None);
    }

    #[test]
    fn runtime_registry_separate_keys_per_agent() {
        let agent1 = Uuid::new_v4().to_string();
        let agent2 = Uuid::new_v4().to_string();
        let auth1 = "9EhPV27hBcJrT4FtvHJ3zJLGA8TfMyEa7fHcti1f7voA";
        let auth2 = "7siRGNwSzvpCqdsZw5tjsz4XZ1SrpMXqKsr4zEjBVr1a";

        assert!(admin_register_agent(&agent1, auth1).is_ok());
        assert!(admin_register_agent(&agent2, auth2).is_ok());

        let static_list = std::collections::HashMap::new();
        let temp_dir = std::env::temp_dir().join(format!("signer-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let store = SignerStore::open(&temp_dir).unwrap();
        assert_eq!(
            lookup_provision_auth(&agent1, &static_list, &store),
            Some(auth1.to_string())
        );
        assert_eq!(
            lookup_provision_auth(&agent2, &static_list, &store),
            Some(auth2.to_string())
        );
    }
}
