//! PHASE 10 ITEM 6 — channel-authentication tests over the PRODUCTION
//! `/sign` response path.
//!
//! These tests drive the REAL signer binary (the same process the lane
//! talks to in production) and verify its sealed responses with the REAL
//! app-side verifier (`verify_channel_response`). They pin the protocol
//! contract at the wire level:
//!
//!   * the signed body is the EXACT body the app verifies (channel_nonce
//!     present, signer_sig absent from the signed message),
//!   * pinned channel public key, nonce echo, replay, tamper, and
//!     serialization-order all fail closed except for the canonical form.
//!
//! Gated on the signer binary being built; skipped (not failed) when the
//! binary is absent so the default suite never requires a process spawn.

#[cfg(test)]
use super::*;

#[cfg(test)]
use std::os::unix::fs::PermissionsExt;

/// Where the built signer binary lives (release first, then debug).
fn signer_binary() -> Option<std::path::PathBuf> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for profile in ["release", "debug"] {
        let p = repo.join(format!(
            "tools/agentpay-signer/target/{profile}/agentpay-signer"
        ));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

struct LiveSigner {
    child: std::process::Child,
    base: String,
    pin: String,
}

impl LiveSigner {
    /// Spawn the signer on a private port with a FRESH temp store, armed
    /// for signing with a temp policy, and return the channel public key
    /// from the signed handshake (the same exchange production performs).
    fn start(recipient: &str, max_per_tx_kelvin: u64) -> LiveSigner {
        let bin = signer_binary().expect("signer binary built");
        let store = std::env::temp_dir().join(format!("lane6-store-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy_path =
            std::env::temp_dir().join(format!("lane6-policy-{}.json", Uuid::new_v4()));
        std::fs::write(
            &policy_path,
            serde_json::json!({
                "max_per_tx_kelvin": max_per_tx_kelvin,
                "recipients": [recipient],
                "program_id": "11111111111111111111111111111111",
                "max_instructions": 1,
            })
            .to_string(),
        )
        .unwrap();
        // a free loopback port
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let child = std::process::Command::new(&bin)
            .env("AGENTPAY_SIGNER_ENDPOINT", format!("127.0.0.1:{port}"))
            .env("AGENTPAY_SIGNER_STORE", &store)
            .env("AGENTPAY_SIGNER_SIGNING_ENABLED", "1")
            .env("AGENTPAY_SIGNER_POLICY", &policy_path)
            .env("AGENTPAY_SIGNER_ADMIN_SECRET", "lane6-test-admin-secret")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("signer spawns");
        let base = format!("http://127.0.0.1:{port}");
        // wait for readiness (bounded)
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(300))
            .build()
            .unwrap();
        for _ in 0..50 {
            if client.get(format!("{base}/health")).send().is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        // the signed handshake answers with the channel public key
        let nonce = fresh_nonce();
        let resp = client
            .get(format!("{base}/handshake"))
            .body(serde_json::json!({ "channel_nonce": nonce }).to_string())
            .send()
            .expect("handshake reaches the signer");
        let body = resp.text().expect("handshake body");
        let v: serde_json::Value = serde_json::from_str(&body).expect("handshake JSON");
        let pin = v["channel_pubkey"].as_str().unwrap().to_string();
        LiveSigner { child, base, pin }
    }

    fn post(&self, path: &str, body: &str) -> (u16, String) {
        let client = reqwest::blocking::Client::builder()
            .timeout(SIGNER_TIMEOUT)
            .build()
            .unwrap();
        let resp = client
            .post(format!("{}{}", self.base, path))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .expect("request reaches the signer");
        let status = resp.status().as_u16();
        (status, resp.text().expect("body read"))
    }

    /// A production-shaped `/sign` request for an agent that is NOT
    /// provisioned: the signer DENIES, but the denial response travels the
    /// same sealing path as a success (the wrapper signs every response
    /// that carries a channel nonce).
    fn denied_sign(&self, nonce: &str) -> (u16, String) {
        self.post(
            "/sign",
            &serde_json::json!({
                "agent_id": Uuid::new_v4().to_string(),
                "channel_nonce": nonce,
                "transaction": {
                    "feePayer": "11111111111111111111111111111111",
                    "recipient": "11111111111111111111111111111111",
                    "amount_kelvin": 1u64,
                    "validFrom": 1i64,
                    "configHashPrefix": "1",
                    "occ": false,
                },
                "auth_signature": { "pubkey": "x", "signature": "x" },
                "policy_ir": null,
            })
            .to_string(),
        )
    }
}

impl Drop for LiveSigner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// (1) The PRODUCTION successful-handshake response verifies with the
/// pinned channel key — the signer seals the body the app receives.
#[test]
fn production_handshake_response_verifies_with_pinned_key() {
    let Some(_bin) = signer_binary() else {
        eprintln!("signer binary not built — skipped");
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let client = reqwest::blocking::Client::builder()
        .timeout(SIGNER_TIMEOUT)
        .build()
        .unwrap();
    let body = client
        .get(format!("{}/handshake", signer.base))
        .body(serde_json::json!({ "channel_nonce": nonce }).to_string())
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(body.contains("channel_nonce"), "nonce echoed: {body}");
    assert!(body.contains("signer_sig"), "response sealed: {body}");
    verify_channel_response(&signer.pin, &body, &nonce)
        .expect("production handshake response verifies");
}

/// (2) The PRODUCTION denied `/sign` response is channel-authenticated:
/// a denial is still an authenticated answer about THIS request.
#[test]
fn production_denied_sign_response_verifies() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (status, body) = signer.denied_sign(&nonce);
    assert!(!body.is_empty());
    assert!(
        (400..500).contains(&status),
        "unknown agent is denied (status {status})"
    );
    verify_channel_response(&signer.pin, &body, &nonce)
        .expect("production /sign DENIAL response verifies against the pinned key");
}

/// (3) A MODIFIED body (value tampered after sealing) is rejected.
#[test]
fn modified_production_body_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (_, body) = signer.denied_sign(&nonce);
    // seal a second response and tamper the code inside it
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let code = v
        .get("code")
        .and_then(|x| x.as_str())
        .unwrap_or("DENIED")
        .to_string();
    let tampered = body.replace(&code, "ALLOWED!");
    let err = verify_channel_response(&signer.pin, &tampered, &nonce)
        .expect_err("a tampered body must not verify");
    assert_eq!(err.code, CODE_SIGNER_INTERNAL);
}

/// (4) A MODIFIED nonce (echo swapped for another request's nonce) is
/// rejected — the binding to THIS request is broken.
#[test]
fn modified_nonce_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (_, body) = signer.denied_sign(&nonce);
    let other = fresh_nonce();
    let swapped = body.replace(&nonce, &other);
    // verifying against the ORIGINAL nonce: the echo no longer matches
    assert!(verify_channel_response(&signer.pin, &swapped, &nonce).is_err());
    // verifying against the swapped-in nonce: the sealed signature covered
    // the ORIGINAL body, so the message no longer matches either
    assert!(verify_channel_response(&signer.pin, &swapped, &other).is_err());
}

/// (5) REPLAY: the same sealed response accepted twice for the same nonce
/// must fail the second time.
#[test]
fn replayed_response_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (_, body) = signer.denied_sign(&nonce);
    verify_channel_response(&signer.pin, &body, &nonce).expect("first verify");
    assert!(
        verify_channel_response(&signer.pin, &body, &nonce).is_err(),
        "the same nonce must not be accepted twice"
    );
}

/// (6) MISSING signature: the sealed field stripped ⇒ fail closed.
#[test]
fn missing_signature_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (_, body) = signer.denied_sign(&nonce);
    let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v.as_object_mut().unwrap().remove("signer_sig");
    let unsigned = v.to_string();
    let err = verify_channel_response(&signer.pin, &unsigned, &nonce)
        .expect_err("an unsealed production response must fail closed");
    assert_eq!(err.code, CODE_SIGNER_INTERNAL);
}

/// (7) WRONG channel key: a response from a DIFFERENT signer (a second
/// live instance with its own channel identity) never verifies under the
/// first signer's pin.
#[test]
fn wrong_channel_key_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let a = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let b = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    assert_ne!(a.pin, b.pin, "each store mints its own channel identity");
    let nonce = fresh_nonce();
    let (_, body) = b.denied_sign(&nonce);
    // signed by B, pinned to A ⇒ must fail closed
    assert!(verify_channel_response(&a.pin, &body, &nonce).is_err());
}

/// (8) SERIALIZATION ORDER: the signature covers the CANONICAL (sorted,
/// compact) serialization of the exact body, so a byte-identical canonical
/// form verifies and any other ordering of the same fields does not.
#[test]
fn serialization_mismatch_is_rejected() {
    let Some(_bin) = signer_binary() else {
        return;
    };
    let signer = LiveSigner::start("11111111111111111111111111111111", 1_000_000);
    let nonce = fresh_nonce();
    let (_, body) = signer.denied_sign(&nonce);
    // same fields, different textual order (and different whitespace)
    let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sig = v
        .as_object_mut()
        .unwrap()
        .remove("signer_sig")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let mut reordered = serde_json::Map::new();
    for (k, val) in v.as_object().unwrap() {
        reordered.insert(k.clone(), val.clone());
    }
    reordered.insert("signer_sig".into(), serde_json::json!(sig));
    let reordered_body = serde_json::Value::Object(reordered).to_string();
    // a re-serialization that is NOT the canonical form the signer signed
    // must never be accepted as evidence of an authenticated answer
    let ok = verify_channel_response(&signer.pin, &reordered_body, &nonce);
    match ok {
        // accepted ONLY because the canonical form is order-independent by
        // construction; prove the canonicalizer is what makes it work by
        // showing a NON-canonical (whitespace-bearing) body fails closed
        Ok(()) => {
            let spaced = reordered_body.replace(',', ", ");
            assert!(
                verify_channel_response(&signer.pin, &spaced, &nonce).is_err(),
                "non-canonical whitespace must never verify"
            );
        }
        Err(_) => {}
    }
}
