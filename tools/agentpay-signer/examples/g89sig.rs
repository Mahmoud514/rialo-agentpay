fn main() {
    let user_id: u64 = std::env::args().nth(1).unwrap().parse().unwrap();
    let nonce = std::env::args().nth(2).unwrap();
    let kp = rialo_s_keypair::keypair_from_seed(&[61u8; 32]).unwrap();
    let mut m = Vec::new();
    m.extend_from_slice(b"g81-create-intent-v2");
    m.extend_from_slice(b"2");
    m.extend_from_slice(&user_id.to_le_bytes());
    m.extend_from_slice(nonce.as_bytes());
    use rialo_s_signer::Signer;
    let sig: [u8; 64] = kp.sign_message(&m).into();
    println!("{}", signature_to_b64(&sig));
}
// replicate crate::base64_encode (STANDARD base64 with padding)
fn signature_to_b64(sig: &[u8; 64]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(sig)
}
