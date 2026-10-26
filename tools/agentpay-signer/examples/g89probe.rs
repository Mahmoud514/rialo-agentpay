fn main() {
    let admin = "aabbccdd".to_string();
    let create = "11223344".to_string();
    let mut h = blake3::Hasher::new();
    h.update(b"g81-user-create-ceremony-v1");
    h.update(admin.as_bytes());
    println!("CEREMONY={}", h.finalize().to_hex());
    let mut h2 = blake3::Hasher::new();
    h2.update(b"g81-user-create-intro-v1");
    h2.update(create.as_bytes());
    println!("INTRO={}", h2.finalize().to_hex());
}
