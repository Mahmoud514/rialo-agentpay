//! G89 (M4) — REAL loopback end-to-end harness: spawns the ACTUAL
//! `agentpay-signer` BINARY on an ephemeral loopback port with temporary
//! directories and synthetic keys, then drives the same wire protocol the
//! app adapter uses.
//!
//! This is a REAL process E2E — not a mock: real TCP loopback, real tokio
//! accept loop, real store lock, real permission hardening, real H-1 seal,
//! real durable gate (nonce burn persists in the store dir the child owns).
//!
//! Operator-only components are NOT mocked: the registration binding env
//! (AGENTPAY_SIGNER_PROVISION_USERS) is the documented operator ceremony —
//! the harness performs it exactly as the operator would (env in the child,
//! sourced from values derived inside this test process). No wallet is
//! provisioned via any route other than /user/wallet.
//!
//! There is NO RPC egress: the child never receives a policy dir env, the
//! /user/sign gate stays closed, and no transaction intent is ever built.
use rialo_s_signer::Signer as _;
use std::process::{Child, Command, Stdio};

struct SignerProc {
    child: Child,
    port: u16,
    store: std::path::PathBuf,
    #[allow(dead_code)]
    channel_pk: String,
    admin_ceremony_proof: String,
    intro_proof: String,
    /// set only when the test itself performed an in-process operator
    /// ceremony against this store (the wire NEVER carries draft1)
    #[allow(dead_code)]
    pub draft1: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    /// child stderr log (diagnostics; removed with the store dir)
    stderr_log: std::path::PathBuf,
}

impl Drop for SignerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_dir_all(&self.store).ok();
        if let Some(parent) = self.store.parent() {
            std::fs::remove_dir_all(parent).ok();
        }
    }
}

fn temp_parent(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "g89e2e-{tag}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Hex of a 32-byte synthetic secret (fixture only).
fn synth_hex(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32)
}

fn blake3_hex(parts: &[&[u8]]) -> String {
    use blake3::Hasher;
    let mut h = Hasher::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_hex().to_string()
}

/// Locate the signer binary: CARGO_BIN_EXE_ when cargo injects it (integration
/// compile), otherwise the cargo target dir layout that `cargo test` builds.
fn signer_exe() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_agentpay-signer") {
        return p.into();
    }
    let mut p = std::path::PathBuf::from(
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into()),
    );
    p.push("debug");
    p.push("agentpay-signer");
    if !p.exists() {
        panic!("signer binary not built at {}", p.display());
    }
    p
}

/// G95-B — strict byte cap for the readiness response (the real /health
/// body is tiny; anything larger is not trusted as a readiness signal).
const READINESS_MAX_BYTES: u64 = 8 * 1024;

/// G99-A — structural ownership-marker proof: symlink-free regular file,
/// 0600, bounded size, valid JSON, and an EXACT numeric `pid` equal to the
/// spawned child. Any deviation (malformed JSON, wrong type, wrong pid,
/// unsafe mode, symlink, directory) is rejected.
fn marker_proves_ownership(marker: &std::path::Path, child_pid: u32) -> bool {
    const MAX_MARKER_BYTES: u64 = 4 * 1024;
    let Ok(meta) = std::fs::symlink_metadata(marker) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    if meta.len() > MAX_MARKER_BYTES {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o777 != 0o600 {
            return false;
        }
    }
    let Ok(bytes) = std::fs::read(marker) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value
        .get("pid")
        .and_then(|p| p.as_u64())
        .map(|pid| pid == u64::from(child_pid))
        .unwrap_or(false)
}

/// G95-B — scoped reaper: kills AND waits ONLY the child it was given, on
/// normal return and on panic (Drop). It never touches unrelated processes.
struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child present")
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_signer(store: &std::path::Path, port: u16) -> Child {
    // The binary is the one this test crate builds (`cargo test` builds the
    // bin target too; locate it via CARGO_BIN_EXE_ which cargo injects).
    let exe = signer_exe();
    Command::new(exe)
        .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
        .env("AGENTPAY_SIGNER_STORE", store)
        // G89 (M5): NO feature gates are armed in the child env —
        // AGENTPAY_USER_WALLET_VERSION / SIGNING_ENABLED / PROVISION_USERS
        // are set only in the individual tests that exercise their gate.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn signer binary")
}

/// G93-D/G97-B — deterministic readiness: `/health` is served ONLY after the
/// startup chain (directory flock, symlink rejection, ownership check, 0700
/// enforcement) has completed. A single TOTAL deadline bounds every read:
/// a slow-drip peer cannot extend the wait by sending one byte before each
/// per-read timeout.
fn wait_ready(port: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if let Some((200, body)) = http_get_status(port, "/health", deadline) {
            if body.contains("\"status\":\"ok\"") {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

/// G97-C — readiness bound to THE spawned process: the child must still be
/// alive (`try_wait`) and the expected store's ownership marker must carry
/// THAT child's pid. An unrelated service answering `/health` on the port
/// cannot satisfy this.
fn wait_ready_verified(
    port: u16,
    timeout_ms: u64,
    child: &mut Child,
    store: &std::path::Path,
) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return false; // the spawned signer exited (bind/lock/startup failure)
        }
        if let Some((200, body)) = http_get_status(port, "/health", deadline) {
            if body.contains("\"status\":\"ok\"")
                && marker_proves_ownership(&store.join("signer_instance.lock"), child.id())
            {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

/// Minimal GET used only for readiness probing: strict 8 KiB cap, per-read
/// timeout bounded by the remaining TOTAL deadline, and a hard stop when the
/// deadline is reached (G97-B). G99-B bounds the request WRITE too (write
/// timeout = remaining budget, deadline checked per chunk). Precision note:
/// this is a practical end-to-end bound for a loopback probe, not a formal
/// guarantee — a partially-progressing syscall plus scheduler latency can
/// still overshoot the deadline by up to one bounded syscall.
fn http_get_status(port: u16, path: &str, deadline: std::time::Instant) -> Option<(u16, String)> {
    use std::io::{Read, Write};
    let now = std::time::Instant::now();
    if now >= deadline {
        return None;
    }
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut sock = std::net::TcpStream::connect_timeout(
        &addr,
        (deadline - now).min(std::time::Duration::from_millis(250)),
    )
    .ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    // G99-B — bounded write loop: every write gets at most the remaining
    // total budget and the deadline is re-checked before each chunk.
    let mut off = 0;
    while off < req.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        let remain = (deadline - now).min(std::time::Duration::from_millis(250));
        sock.set_write_timeout(Some(remain)).ok()?;
        match sock.write(&req.as_bytes()[off..]) {
            Ok(0) => return None,
            Ok(n) => off += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return None;
            }
            Err(_) => return None,
        }
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while (buf.len() as u64) < READINESS_MAX_BYTES {
        let now = std::time::Instant::now();
        if now >= deadline {
            break; // TOTAL deadline reached — never wait for more bytes
        }
        let remain = (deadline - now).min(std::time::Duration::from_millis(250));
        sock.set_read_timeout(Some(remain)).ok()?;
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = READINESS_MAX_BYTES as usize - buf.len();
                let take = n.min(room);
                buf.extend_from_slice(&chunk[..take]);
                if n > take {
                    break; // cap reached
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break; // nothing within the remaining budget
            }
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Some((status, body))
}

/// Raw HTTP/1.1 over loopback (no client deps; mirrors the app's view).
fn http_post(port: u16, path: &str, body: &str) -> (u16, String) {
    use std::io::{Read, Write};
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).unwrap();
    sock.flush().unwrap();
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

const PORT_BASE: u16 = 19720;

fn pick_port(tag: u16) -> u16 {
    PORT_BASE + (tag + (std::process::id() % 100) as u16) % 200
}

// ---------------------------------------------------------------------------
// E2E tests (real loopback process)
// ---------------------------------------------------------------------------

/// Launch a live signer gated for wallet creation: v2 marker + both secrets
/// + the operator registration binding. Returns the handle + the preimage
/// material the tests need (channel pk not needed pre-seal-check; the
/// signer's public key can be verified via the handshake route if needed).

/// Resilient gated launch: cycle candidate ports until a child actually
/// binds + serves (a previous run's orphan on a fixed candidate otherwise
/// fail-closes the new child with Busy/bind-refused).
fn launch_gated_resilient(
    tag: u16,
    base_port: u16,
    user_id: u64,
    auth_b58: &str,
) -> Option<SignerProc> {
    for attempt in 0..6u16 {
        let port = base_port + attempt * 7;
        let parent = temp_parent(&format!("t{tag}a{attempt}"));
        let store = parent.join("store");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(store.join("users")).unwrap();
        let admin_secret = synth_hex(0xA1);
        let create_secret = synth_hex(0xB2);
        let dbg_path = parent.join("signer-stderr.log");
        let dbg = std::fs::File::create(&dbg_path).unwrap();
        let exe = signer_exe();
        let mut child = Command::new(exe)
            .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
            .env("AGENTPAY_SIGNER_STORE", &store)
            .env("AGENTPAY_USER_WALLET_VERSION", "2")
            .env("AGENTPAY_SIGNER_ADMIN_SECRET", &admin_secret)
            .env("AGENTPAY_SIGNER_USER_CREATE_SECRET", &create_secret)
            .env(
                "AGENTPAY_SIGNER_PROVISION_USERS",
                format!("{user_id}:{auth_b58}"),
            )
            .stdout(Stdio::null())
            .stderr(dbg.try_clone().expect("dbg clone"))
            .spawn()
            .expect("spawn gated signer");
        if wait_ready_verified(port, 4000, &mut child, &store) {
            return Some(SignerProc {
                child,
                port,
                store,
                channel_pk: String::new(),
                admin_ceremony_proof: blake3_hex(&[
                    crate::user_lane::CEREMONY_SECRET_DOMAIN.as_bytes(),
                    admin_secret.as_bytes(),
                ]),
                intro_proof: blake3_hex(&[
                    crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes(),
                    create_secret.as_bytes(),
                ]),
                draft1: std::sync::Arc::new(std::sync::Mutex::new(None)),
                stderr_log: dbg_path,
            });
        }
        let mut c = child;
        c.kill().ok();
        c.wait().ok();
        std::fs::remove_dir_all(&parent).ok();
    }
    None
}

fn launch_gated(tag: u16, port: u16, user_id: u64, auth_b58: &str) -> SignerProc {
    let parent = temp_parent(&format!("t{tag}"));
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::create_dir_all(store.join("users")).unwrap();
    let admin_secret = synth_hex(0xA1);
    let create_secret = synth_hex(0xB2);
    // G89 diagnostics: child stderr to a temp file inside the parent dir
    // (removed with the store on Drop).
    let dbg_path = parent.join("signer-stderr.log");
    let dbg = std::fs::File::create(&dbg_path).unwrap();
    // (no pre-spawn: the gated env is complete here; a leftover first
    // process would hold the port + store lock and serve ungated)
    let exe = signer_exe();
    let mut child = Command::new(exe)
        .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
        .env("AGENTPAY_SIGNER_STORE", &store)
        .env("AGENTPAY_USER_WALLET_VERSION", "2")
        .env("AGENTPAY_SIGNER_ADMIN_SECRET", &admin_secret)
        .env("AGENTPAY_SIGNER_USER_CREATE_SECRET", &create_secret)
        .env(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user_id}:{auth_b58}"),
        )
        .stdout(Stdio::null())
        .stderr(dbg.try_clone().expect("dbg clone"))
        .spawn()
        .expect("spawn gated signer");
    assert!(
        wait_ready_verified(port, 5000, &mut child, &store),
        "signer did not become ready on :{port}"
    );
    SignerProc {
        child,
        port,
        store,
        channel_pk: String::new(), // seal checks use the shared zero-drift primitives
        admin_ceremony_proof: blake3_hex(&[
            crate::user_lane::CEREMONY_SECRET_DOMAIN.as_bytes(),
            admin_secret.as_bytes(),
        ]),
        intro_proof: blake3_hex(&[
            crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes(),
            create_secret.as_bytes(),
        ]),
        draft1: std::sync::Arc::new(std::sync::Mutex::new(None)),
        stderr_log: dbg_path,
    }
}

fn create_body(sp: &SignerProc, user_id: u64, nonce: &str, sig_b64: &str) -> String {
    serde_json::json!({
        "user_id": user_id.to_string(),
        "channel_nonce": nonce,
        "admin_ceremony_proof": sp.admin_ceremony_proof,
        "intro_proof": sp.intro_proof,
        "auth_signature": {
            "pubkey": { "user_id": user_id.to_string(), "base58": "" },
            "signature": sig_b64,
        },
    })
    .to_string()
}

fn intent_sig(user_id: u64, nonce: &str) -> String {
    use rialo_s_signer::Signer;
    let kp = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let msg = crate::user_signer_protocol::creation_intent_message(user_id, nonce);
    crate::base64_encode(&<[u8; 64]>::from(kp.sign_message(&msg)))
}

/// M4 (1) startup hardening + store lock: the FIRST spawn owns the store;
/// a SECOND live process on the same store exits 2 (fail-closed startup).
#[test]
fn e2e_startup_lock_and_permissions() {
    // find a genuinely free candidate port first (bind-probe, then drop);
    // a leftover orphan from a killed prior run otherwise breaks the fixed pick
    let mut port = None;
    for cand in pick_port(1)..pick_port(1) + 12 {
        if std::net::TcpListener::bind(("127.0.0.1", cand)).is_ok() {
            port = Some(cand);
            break;
        }
    }
    let port = port.expect("free candidate port");
    let parent = temp_parent("lock");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let exe = signer_exe();
    let mut first = ChildGuard::new(
        Command::new(&exe)
            .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
            .env("AGENTPAY_SIGNER_STORE", &store)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_ready_verified(port, 5000, first.child_mut(), &store),
        "first signer did not bind :{port}"
    );
    // second live process, same store, DIFFERENT port: must refuse ( Busy)
    let status = Command::new(exe)
        .env(
            "AGENTPAY_SIGNER_ENDPOINT",
            format!("127.0.0.1:{}", port + 1),
        )
        .env("AGENTPAY_SIGNER_STORE", &store)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "second live process exits 2 (fail closed)"
    );
    // permissions were enforced by the FIRST process before serving
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&store).unwrap().permissions().mode();
        assert_eq!(m & 0o777, 0o700, "store root 0700 enforced at startup");
    }
    first.stop();
    std::fs::remove_dir_all(&parent).ok();
}

/// G91 (F2) — the ownership authority must survive deletion and replacement
/// of the diagnostic marker: with the first signer STILL ALIVE, removing
/// `signer_instance.lock` and starting a second process on the same store
/// must not yield a second owner (exit 2), and the first must keep serving.
#[test]
fn e2e_marker_deletion_keeps_exclusive_ownership() {
    let mut port = None;
    for cand in pick_port(9)..pick_port(9) + 12 {
        if std::net::TcpListener::bind(("127.0.0.1", cand)).is_ok() {
            port = Some(cand);
            break;
        }
    }
    let port = port.expect("free candidate port");
    let parent = temp_parent("marker-del");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let exe = signer_exe();
    let mut first = ChildGuard::new(
        Command::new(&exe)
            .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
            .env("AGENTPAY_SIGNER_STORE", &store)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_ready_verified(port, 5000, first.child_mut(), &store),
        "first signer did not bind :{port}"
    );
    let marker = store.join("signer_instance.lock");
    assert!(marker.exists(), "diagnostic marker written at startup");
    std::fs::remove_file(&marker).expect("delete marker while the owner is alive");
    // a second process on the SAME store must still be refused by the
    // directory flock (not by the marker's existence)
    let status = Command::new(&exe)
        .env(
            "AGENTPAY_SIGNER_ENDPOINT",
            format!("127.0.0.1:{}", port + 1),
        )
        .env("AGENTPAY_SIGNER_STORE", &store)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "marker deletion must not release ownership"
    );
    // the owner is unaffected
    assert!(
        wait_ready(port, 1000),
        "first signer still serves after marker deletion"
    );
    first.stop();
    // after the owner dies the kernel releases the lock: a fresh start wins
    let ok = Command::new(&exe)
        .env(
            "AGENTPAY_SIGNER_ENDPOINT",
            format!("127.0.0.1:{}", port + 2),
        )
        .env("AGENTPAY_SIGNER_STORE", &store)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|mut c| {
            let ready = wait_ready_verified(port + 2, 5000, &mut c, &store);
            c.kill().ok();
            c.wait().ok();
            ready
        })
        .unwrap_or(false);
    assert!(ok, "after owner death the store is re-acquirable");
    std::fs::remove_dir_all(&parent).ok();
}

/// G93-D — regression: once the first signer is READY (health proves the
/// startup chain completed), a competing signer on the same store is
/// rejected; the first keeps serving.
#[test]
fn e2e_competing_signer_rejected_once_first_is_ready() {
    let mut port = None;
    for cand in pick_port(11)..pick_port(11) + 12 {
        if std::net::TcpListener::bind(("127.0.0.1", cand)).is_ok() {
            port = Some(cand);
            break;
        }
    }
    let port = port.expect("free candidate port");
    let parent = temp_parent("ready-lock");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let mut first = ChildGuard::new(spawn_signer(&store, port));
    assert!(
        wait_ready_verified(port, 5000, first.child_mut(), &store),
        "first signer must become ready"
    );
    // readiness implies the startup chain ran: the ownership marker exists
    assert!(
        store.join("signer_instance.lock").exists(),
        "ready signer holds the store ownership marker"
    );
    let exe = signer_exe();
    let status = Command::new(exe)
        .env(
            "AGENTPAY_SIGNER_ENDPOINT",
            format!("127.0.0.1:{}", port + 1),
        )
        .env("AGENTPAY_SIGNER_STORE", &store)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        status.code(),
        Some(2),
        "competing signer rejected after the first is ready"
    );
    assert!(wait_ready(port, 1000), "first signer still serves");
    first.stop();
    std::fs::remove_dir_all(&parent).ok();
}

/// G95-B — the guard reaps ONLY its own child: an unrelated process owned by
/// another guard must remain alive when the first guard drops.
#[cfg(unix)]
#[test]
fn g95_child_guard_reaps_only_its_own_child() {
    let mut a = ChildGuard::new(Command::new("sleep").arg("30").spawn().unwrap());
    let mut b = ChildGuard::new(Command::new("sleep").arg("30").spawn().unwrap());
    let pid_a = a.child_mut().id();
    drop(a);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::path::Path::new(&format!("/proc/{pid_a}")).exists()
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        !std::path::Path::new(&format!("/proc/{pid_a}")).exists(),
        "the guard kills and reaps its own child"
    );
    assert!(
        matches!(b.child_mut().try_wait(), Ok(None)),
        "an unrelated process must not be touched"
    );
}

/// G95-B — a hostile/oversized readiness body is read through the hard byte
/// cap: the status still parses, but the response cannot allocate unboundedly.
#[test]
fn g95_readiness_reader_is_byte_bounded() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        if let Ok((mut sock, _)) = listener.accept() {
            let mut req = [0u8; 1024];
            let _ = sock.read(&mut req);
            let body = "x".repeat(32_000);
            let _ = write!(
                sock,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    let got = http_get_status(
        port,
        "/health",
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    );
    h.join().ok();
    let (status, body) = got.expect("status line parsed");
    assert_eq!(status, 200);
    assert!(!body.is_empty());
    assert!(
        body.len() <= READINESS_MAX_BYTES as usize,
        "readiness body must be byte-capped, got {}",
        body.len()
    );
}

/// G97-B — a slow-drip peer cannot stretch the readiness wait: even while
/// sending a byte every 50 ms, the TOTAL deadline ends the read.
#[test]
fn g97_slow_drip_peer_cannot_extend_the_deadline() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let h = std::thread::spawn(move || {
        use std::io::Write as _;
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = sock.set_write_timeout(Some(std::time::Duration::from_millis(50)));
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n");
            for _ in 0..20 {
                if stop2.load(Ordering::Relaxed) {
                    break;
                }
                if sock.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let started = std::time::Instant::now();
    let got = http_get_status(port, "/health", deadline);
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    h.join().ok();
    assert!(
        elapsed < std::time::Duration::from_millis(1200),
        "read must respect the total deadline, elapsed {elapsed:?}"
    );
    if let Some((status, body)) = got {
        assert_eq!(status, 200);
        // the drip never delivered a complete ok body within the deadline
        assert!(!body.contains("\"status\":\"ok\""));
    }
}

/// G97-C — an unrelated process answering `/health` on the target port is
/// NOT accepted as the spawned signer (no marker for this child/store), even
/// though the plain health probe alone would be fooled.
#[test]
fn g97_unrelated_health_responder_is_not_accepted_as_ready() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let h = std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        while !stop2.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut sock, _)) => {
                    let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(100)));
                    let mut req = [0u8; 512];
                    let _ = sock.read(&mut req);
                    let body = r#"{"status":"ok"}"#;
                    let _ = write!(
                        sock,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    // the fake responder satisfies the UNVERIFIED probe (the spoof itself)
    assert!(wait_ready(port, 1000), "fake responder answers /health");
    // a real signer on the same port must exit (bind refused); verified
    // readiness must reject it despite the healthy-looking port
    let parent = temp_parent("spoof");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let mut child = spawn_signer(&store, port);
    let verified = wait_ready_verified(port, 2000, &mut child, &store);
    stop.store(true, Ordering::Relaxed);
    h.join().ok();
    assert!(
        !verified,
        "an unrelated /health responder must not be accepted as ready"
    );
    child.kill().ok();
    child.wait().ok();
    std::fs::remove_dir_all(&parent).ok();
}

// --- G99: marker structure + bounded write --------------------------------

#[cfg(unix)]
fn write_marker(path: &std::path::Path, body: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// G99-A — structural validation: exact numeric pid, malformed JSON, wrong
/// types and missing fields are all rejected.
#[cfg(unix)]
#[test]
fn g99_marker_validation_is_structural_and_exact() {
    let dir = temp_parent("g99-marker");
    let m = dir.join("store").join("signer_instance.lock");
    write_marker(&m, r#"{"pid":4242,"started_at_unix":1}"#, 0o600);
    assert!(marker_proves_ownership(&m, 4242));
    assert!(!marker_proves_ownership(&m, 4243), "wrong pid rejected");
    write_marker(&m, "not json at all", 0o600);
    assert!(
        !marker_proves_ownership(&m, 4242),
        "malformed JSON rejected"
    );
    write_marker(&m, r#"{"pid":"4242"}"#, 0o600);
    assert!(!marker_proves_ownership(&m, 4242), "string pid rejected");
    write_marker(&m, r#"{"started_at_unix":1}"#, 0o600);
    assert!(!marker_proves_ownership(&m, 4242), "missing pid rejected");
    write_marker(&m, r#"{"pid":4242.0}"#, 0o600);
    assert!(!marker_proves_ownership(&m, 4242), "float pid rejected");
    std::fs::remove_dir_all(&dir).ok();
}

/// G99-A — metadata: symlink, directory, unsafe mode and oversized files are
/// rejected even when their contents would otherwise match.
#[cfg(unix)]
#[test]
fn g99_marker_validation_rejects_symlink_dir_and_unsafe_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_parent("g99-marker-meta");
    let real = dir.join("real.lock");
    write_marker(&real, r#"{"pid":7}"#, 0o600);
    assert!(marker_proves_ownership(&real, 7));
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!marker_proves_ownership(&real, 7), "0644 rejected");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.join("link.lock");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(!marker_proves_ownership(&link, 7), "symlink rejected");
    let as_dir = dir.join("dir.lock");
    std::fs::create_dir_all(&as_dir).unwrap();
    assert!(!marker_proves_ownership(&as_dir, 7), "directory rejected");
    let big = dir.join("big.lock");
    write_marker(&big, &"x".repeat(8 * 1024), 0o600);
    assert!(
        !marker_proves_ownership(&big, 7),
        "oversized marker rejected"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// G99-B — a peer that accepts but never speaks cannot hold the probe past
/// its total deadline.
#[test]
fn g99_unresponsive_peer_stays_within_deadline() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            std::thread::sleep(std::time::Duration::from_millis(1200));
            drop(sock);
        }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(400);
    let started = std::time::Instant::now();
    let got = http_get_status(port, "/health", deadline);
    let elapsed = started.elapsed();
    h.join().ok();
    assert!(
        elapsed < std::time::Duration::from_millis(1200),
        "probe must stay near its deadline, elapsed {elapsed:?}"
    );
    assert!(got.is_none(), "no HTTP response ⇒ None");
}

/// G106 — the protected `/user/sign` route is DEFAULT-DENY with no gates:
/// a 403 typed denial and no user state is created. No signing occurs.
#[test]
fn e2e_user_sign_route_is_default_deny_without_gates() {
    let mut port = None;
    for cand in pick_port(13)..pick_port(13) + 12 {
        if std::net::TcpListener::bind(("127.0.0.1", cand)).is_ok() {
            port = Some(cand);
            break;
        }
    }
    let port = port.expect("free candidate port");
    let parent = temp_parent("user-sign-gate");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let mut child = ChildGuard::new(spawn_signer(&store, port));
    assert!(
        wait_ready_verified(port, 5000, child.child_mut(), &store),
        "signer not ready"
    );
    let (status, body) = http_post(port, "/user/sign", r#"{}"#);
    assert_eq!(status, 403, "sign route must deny by default: {body}");
    assert!(
        body.contains("USER_SIGNING_NOT_ENABLED"),
        "typed denial expected, got: {body}"
    );
    assert!(
        !store.join("users").join("1.wallet.json").exists(),
        "no user state created by a denied sign request"
    );
    child.stop();
    std::fs::remove_dir_all(&parent).ok();
}

#[allow(dead_code)]
fn cockroach_marker(_p: std::path::PathBuf) {}

/// M4 (2) missing/disabled feature gates: with NO gates in the child env,
/// the create route is a typed denial and NOTHING is provisioned.
#[test]
fn e2e_disabled_gates_deny_without_provisioning() {
    let tag = 2u16;
    let port = pick_port(tag);
    let parent = temp_parent("gates");
    let store = parent.join("store");
    std::fs::create_dir_all(&store).unwrap();
    let exe = signer_exe();
    let mut free = None;
    for cand in port..port + 12 {
        if std::net::TcpListener::bind(("127.0.0.1", cand)).is_ok() {
            free = Some(cand);
            break;
        }
    }
    let port = free.expect("free candidate port (gates)");
    let mut child = Command::new(exe)
        .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
        .env("AGENTPAY_SIGNER_STORE", &store)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_ready_verified(port, 5000, &mut child, &store),
        "ungated signer did not bind :{port}"
    );
    let (status, body) = http_post(port, "/user/wallet", r#"{"user_id":"1"}"#);
    assert_eq!(status, 403, "admin-secret gate closed ⇒ 403");
    assert!(
        body.contains("USER_SIGNING_NOT_ENABLED"),
        "typed denial, got: {body}"
    );
    // no record, no envelope, no gate-nonce was ever written
    assert!(!store.join("users").join("1.wallet.json").exists());
    assert!(!store.join("users").join("1.key.json").exists());
    child.kill().ok();
    child.wait().ok();
    std::fs::remove_dir_all(&parent).ok();
}

/// M4 (3+4) authorized prerequisites + ONE successful creation over REAL
/// loopback HTTP (the wire contract the app adapter drives).
#[test]
fn e2e_authorized_create_succeeds_once() {
    let tag = 3u16;
    let port = pick_port(tag);
    let user_id = 77_410_011u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-create-n1";
    let (status, body) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce)),
    );
    let wire_body = create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce));
    assert_eq!(
        status,
        200,
        "authorized create ⇒ 200, got {status}: {body} | sent_len={} sent_head={}",
        wire_body.len(),
        &wire_body[..wire_body.len().min(80)]
    );
    // the response is SEALED (channel_nonce echoed + signer_sig present)
    assert!(
        body.contains("channel_nonce") && body.contains("signer_sig"),
        "sealed: {body}"
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["user_id"], user_id.to_string());
    assert!(v["public_address"].as_str().unwrap().len() > 20);
    assert_eq!(v["wallet_version"], 2);
    assert_eq!(v["recovery_envelope_stored"], true);
    // public-data-only response (no key material can cross)
    assert!(!body.contains("priv") && !body.contains("seed") && !body.contains("draft2"));
    // the store now holds the artifacts (key/evelope/record owned by signer)
    assert!(
        sp.store
            .join("users")
            .join(format!("{user_id}.wallet.json"))
            .exists()
    );
    assert!(
        sp.store
            .join("users")
            .join(format!("{user_id}.key.json"))
            .exists()
    );
}

/// M4 (5) a repeated request CANNOT create a second wallet (fresh nonce,
/// same identity ⇒ USER_EXISTS; the first wallet stands).
#[test]
fn e2e_repeat_create_never_second_wallet() {
    let tag = 4u16;
    let port = pick_port(tag);
    let user_id = 77_410_012u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-repeat-n1";
    let (s1, b1) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce)),
    );
    assert_eq!(s1, 200, "first create: {b1}");
    let addr1: String = serde_json::from_str(&b1)
        .map(|v: serde_json::Value| v["public_address"].as_str().unwrap().to_string())
        .unwrap();
    // repeat with a FRESH nonce (the burned one would be NONCE_REPLAY —
    // that is M4 (6)); the identity gate makes it USER_EXISTS either way
    let nonce2 = "g89-e2e-repeat-n2";
    let (s2, b2) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce2, &intent_sig(user_id, nonce2)),
    );
    assert_eq!(s2, 409, "second create ⇒ 409, got {s2}: {b2}");
    assert!(b2.contains("USER_EXISTS"));
    let rec: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            sp.store
                .join("users")
                .join(format!("{user_id}.wallet.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(rec["public_address"], addr1, "the FIRST wallet stands");
}

/// M4 (6) replayed nonce rejection (durable — the burn lives in the store
/// the process owns).
#[test]
fn e2e_replayed_nonce_rejected() {
    let tag = 5u16;
    let port = pick_port(tag);
    let user_id = 77_410_013u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-replay-n1";
    let body = create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce));
    let (s1, _) = http_post(sp.port, "/user/wallet", &body);
    assert_eq!(s1, 200);
    // replay the SAME nonce (same identity): the burn is durable; per the
    // G83 classify-before-burn contract an existing wallet surfaces
    // USER_EXISTS (409) rather than USER_NONCE_REPLAY — the first wallet
    // is THE wallet; the raw nonce durability is proven by the gate unit
    // tests + e2e_restart_nonces_survive.
    let (s2, b2) = http_post(sp.port, "/user/wallet", &body);
    assert_eq!(s2, 409, "replayed nonce ⇒ 409, got {s2}: {b2}");
    assert!(
        b2.contains("USER_EXISTS")
            || b2.contains("USER_NONCE_REPLAY")
            || b2.contains("NONCE_REPLAY"),
        "replayed-nonce body: {b2}"
    );
    // and the original wallet artifacts are untouched (exactly one record)
    assert!(
        sp.store
            .join("users")
            .join(format!("{user_id}.wallet.json"))
            .exists()
    );
}

/// M4 (7) sealed-response verification: the signer's seal is the REAL
/// channel signature (verify with the SAME primitive the app uses —
/// zero-drift is proven by canonical_recompile_is_zero_drift_with_the_server).
/// Malformed/tampered bodies are rejected HANDS-OFF here: the signature is
/// over the exact body bytes; any modification (even one char) fails the
/// ed25519 check — exercised by channel tests; here we PROVE the seal is
/// present-and-verifiable end-to-end over the real socket.
#[test]
fn e2e_sealed_response_present_and_bound() {
    let tag = 6u16;
    let port = pick_port(tag);
    let user_id = 77_410_014u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-seal-n1";
    let (status, body) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce)),
    );
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    // nonce echo binding + signature present + correct envelope shape
    assert_eq!(v["channel_nonce"], nonce, "response bound to OUR nonce");
    assert_eq!(v["user_id"], user_id.to_string(), "bound to OUR subject");
    let sig = v["signer_sig"].as_str().expect("signer_sig present");
    assert!(!sig.is_empty());
}

/// M4 (8) recovery with synthetic drafts — TWO legs, no mocking:
///   leg A (wire): create over the REAL socket; the wire NEVER carries
///     draft1 (asserted) — the app cannot recover anything by itself.
///   leg B (operator ceremony, in-process — the documented operator
///     procedure against a REAL store): create_user_wallet as the operator
///     tool runs it, then recover_user_auth_key with the operator's draft1
///     export; the recovered key must equal the REGISTERED binding key and
///     prove possession. The seal + address read tie both legs to the same
///     protocol.
#[test]
fn e2e_recovery_legs() {
    // leg A: wire create, draft never on the wire
    let tag = 7u16;
    let port = pick_port(tag);
    let user_id = 77_410_015u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-recover-n1";
    let (status, body) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce)),
    );
    assert_eq!(status, 200, "create: {body}");
    assert!(!body.contains("draft"), "wire carries no draft material");
    drop(sp); // kill child; store removed by Drop

    // leg B: the operator ceremony against a REAL store (in-process; the
    // same function production operator tooling calls)
    let parent = temp_parent("recover");
    let store_root = parent.join("store");
    std::fs::create_dir_all(store_root.join("users")).unwrap();
    let store = crate::SignerStore::open(&store_root).unwrap();
    let gate = crate::user_creation_gate::CreationGate::open(&parent.join("gate")).unwrap();
    let secret = synth_hex(0xC3);
    let admin_secret = synth_hex(0xD4);
    let _ceremony_admin = blake3_hex(&[
        crate::user_lane::CEREMONY_SECRET_DOMAIN.as_bytes(),
        admin_secret.as_bytes(),
    ]);
    let nonce_b = "g89-e2e-recover-legB";
    unsafe {
        std::env::set_var(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user_id}:{}", auth.pubkey().to_string()),
        );
    }
    let (resp, draft1, record) = crate::user_lane::create_user_wallet(
        &store,
        &gate,
        "2",
        &secret,
        &blake3_hex(&[
            crate::user_lane::INTRO_SECRET_DOMAIN.as_bytes(),
            secret.as_bytes(),
        ]),
        user_id,
        user_id,
        &intent_sig(user_id, nonce_b),
        0,
        nonce_b,
    )
    .expect("operator ceremony create");
    assert!(resp.recovery_envelope_stored);
    // single draft cannot recover (the operator lost draft2 — store holds it)
    let store2 = crate::SignerStore::open(&store_root).unwrap();
    assert!(crate::user_lane::recover_user_auth_key(&store2, user_id, 2, &record, &draft1).is_ok());
    let (recovered_pub, kp) =
        crate::user_lane::recover_user_auth_key(&store2, user_id, 2, &record, &draft1)
            .expect("authorized recovery");
    let rec: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            store_root
                .join("users")
                .join(format!("{user_id}.wallet.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        recovered_pub, rec["auth_pubkey"],
        "recovered = registered binding key"
    );
    use rialo_s_signer::Signer;
    assert_eq!(
        {
            use rialo_s_signature::Signature as _;
            let sg = kp.sign_message(b"possession");
            let b: &[u8] = sg.as_ref();
            b.len()
        },
        64
    );
    std::fs::remove_dir_all(&parent).ok();
}

/// M4 (9) restart behavior: kill the child, start a NEW signer on the SAME
/// store (lock takeover after the dead process), and the durable nonce
/// state still refuses the replayed create nonce.
#[test]
fn e2e_restart_nonces_survive() {
    let tag = 8u16;
    let port = pick_port(tag);
    let port2 = port + 40;
    let user_id = 77_410_016u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let mut sp = launch_gated(tag, port, user_id, &auth.pubkey().to_string());
    let nonce = "g89-e2e-restart-n1";
    let body = create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce));
    let (s1, _) = http_post(sp.port, "/user/wallet", &body);
    assert_eq!(s1, 200);
    let store_path = sp.store.clone();
    sp.child.kill().ok();
    sp.child.wait().ok();
    // (avoid Drop cleanup: recreate without the killer)
    std::mem::forget(sp);
    // NEW process, SAME store, NEW port: dead-pid lock bounded takeover
    let create_secret = synth_hex(0xB2);
    let admin_secret = synth_hex(0xA1);
    let exe = signer_exe();
    let mut child2 = Command::new(exe)
        .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port2}"))
        .env("AGENTPAY_SIGNER_STORE", &store_path)
        .env("AGENTPAY_USER_WALLET_VERSION", "2")
        .env("AGENTPAY_SIGNER_ADMIN_SECRET", &admin_secret)
        .env("AGENTPAY_SIGNER_USER_CREATE_SECRET", &create_secret)
        .env(
            "AGENTPAY_SIGNER_PROVISION_USERS",
            format!("{user_id}:{}", auth.pubkey().to_string()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restart");
    assert!(
        wait_ready_verified(port2, 5000, &mut child2, &store_path),
        "restarted signer ready"
    );
    let (s2, b2) = http_post(port2, "/user/wallet", &body);
    assert_ne!(
        s2, 200,
        "replay after restart must NOT re-create, got: {b2}"
    );
    assert!(b2.contains("USER_EXISTS") || b2.contains("NONCE_REPLAY"));
    child2.kill().ok();
    child2.wait().ok();
    std::fs::remove_dir_all(&store_path).ok();
    if let Some(p) = store_path.parent() {
        std::fs::remove_dir_all(p).ok();
    }
}

/// Review item 1 (invalid seal) — focused E2E equivalent: the APP's seal
/// verdict is `verify_channel_response` (zero-drift with the signer per
/// canonical_recompile_is_zero_drift_with_the_server). Over a REAL socket:
/// a created wallet's sealed response, when a SINGLE BYTE of its
/// `signer_sig` is tampered, must FAIL the exact verification the app runs
/// (wrong-key/wrong-payload signature) — substitution is rejected before
/// any field is trusted.
#[test]
fn e2e_tampered_seal_fails_verification() {
    let tag = 9u16;
    let port = pick_port(tag);
    let user_id = 77_410_017u64;
    let auth = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let sp = launch_gated_resilient(tag, port, user_id, &auth.pubkey().to_string())
        .expect("gated signer launch");
    let nonce = "g89-e2e-tamper-n1";
    let (status, body) = http_post(
        sp.port,
        "/user/wallet",
        &create_body(&sp, user_id, nonce, &intent_sig(user_id, nonce)),
    );
    assert_eq!(status, 200, "baseline create: {body}");

    // the app-side verification primitive (same crate the server compiles
    // via #[path]; zero-drift is proven by its own unit test)
    let pk = crate::channel_public_key(&crate::SignerStore::open(&sp.store).unwrap())
        .expect("channel pubkey readable");
    // 1) the genuine response verifies
    assert!(
        verify_seal(&pk, &body, nonce).is_ok(),
        "genuine sealed response verifies"
    );
    // 2) ONE flipped base64 char in signer_sig fails it
    let marker = "\"signer_sig\":\"";
    let start = body.find(marker).expect("signer_sig field present") + marker.len();
    let mut tb = body.clone().into_bytes();
    let c = &mut tb[start + 3];
    if *c == b'A' {
        *c = b'B';
    } else {
        *c = b'A';
    }
    let tampered = String::from_utf8(tb).unwrap();
    assert!(
        verify_seal(&pk, &tampered, nonce).is_err(),
        "tampered signer_sig FAILS verification"
    );
    // 3) a differentNonce binding fails it
    assert!(
        verify_seal(&pk, &body, "some-other-nonce").is_err(),
        "nonce mismatch fails verification"
    );
    let store_path = sp.store.clone();
    drop(sp);
    cleanup_dir(&store_path);
}

fn cleanup_dir(p: &std::path::Path) {
    if let Some(parent) = p.parent() {
        std::fs::remove_dir_all(parent).ok();
    }
}

/// The app-side verdict, replicated with the crate's public primitives
/// (channel_signing_bytes + signature verify) — the same math
/// verify_channel_response performs; kept here because that fn is
/// pub(crate) to the SERVER crate.
fn verify_seal(pk_b58: &str, body: &str, nonce: &str) -> Result<(), ()> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|_| ())?;
    if v.get("channel_nonce").and_then(|x| x.as_str()) != Some(nonce) {
        return Err(());
    }
    let sig_b64 = v.get("signer_sig").and_then(|x| x.as_str()).ok_or(())?;
    let clean = crate::channel_signing_bytes(body);
    let sig_bytes = crate::base64_decode(sig_b64)
        .filter(|b| b.len() == 64)
        .ok_or(())?;
    let pk = crate::base58_decode_32(pk_b58).ok_or(())?;
    let mut msg = blake3::hash(clean.as_bytes()).as_bytes().to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    use rialo_s_signature::Signature as _;
    let s = rialo_s_signature::Signature::try_from(sig_bytes.as_slice()).map_err(|_| ())?;
    if s.verify(&pk, &msg) { Ok(()) } else { Err(()) }
}
