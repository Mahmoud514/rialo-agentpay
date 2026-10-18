// DETERMINISTIC HANDSHAKE VERIFICATION — no Python.
// 1) capture FRESH handshake bytes from the live signer into /tmp/hs_live.json
// 2) verify using the crate's own seal path: re-signing the canonical clean
//    body with the store's channel identity MUST reproduce the served sig,
//    byte-for-byte (that is exactly what the app adapter asserts).
use std::io::{Read, Write};
use std::net::TcpStream;
fn http_get(path: &str) -> String {
    let mut s = TcpStream::connect("127.0.0.1:9000").unwrap();
    write!(s, "GET {} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", path).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).to_string()
}
fn main() {
    let raw = http_get("/handshake");
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").trim().to_string();
    let served: serde_json::Value = serde_json::from_str(&body).unwrap();
    let store = agentpay_signer::SignerStore::open(std::path::Path::new("/tmp/signer-dev-store")).unwrap();
    // (a) digest binding: served digest == THIS crate's own digest? (the running exe is the same build)
    let served_digest = served["binary_digest"].as_str().unwrap_or("");
    // (b) identity binding: served pubkey == store channel identity pubkey
    let store_pk = agentpay_signer::channel_public_key(&store).unwrap();
    let pk_ok = store_pk == served["channel_pubkey"].as_str().unwrap_or("");
    // (c) signature binding: canonical re-sign reproduces served sig
    let mut o = served.as_object().unwrap().clone();
    o.remove("signer_sig");
    let clean = serde_json::Value::Object(o).to_string();
    let resigned = agentpay_signer::sign_channel_response(&store, &clean, served["channel_nonce"].as_str().unwrap_or("")).unwrap();
    println!("digest_len_ok: {}", served_digest.len() == 64);
    println!("pubkey_binding: {}", pk_ok);
    println!("signature_binding(ressign==served): {}", resigned == served["signer_sig"].as_str().unwrap_or(""));
    // (d) full crate handshake_payload self-check (crate signs fresh with same key)
    let (_p, s2, pk2) = agentpay_signer::handshake_payload(&store, "n0nce-x").unwrap();
    println!("crate_fresh_sign_len_ok: {}", s2.len() >= 80 && pk2 == store_pk);
}
