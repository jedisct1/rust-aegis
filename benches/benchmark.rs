use aegis::aegis128l::Aegis128L;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, NewAead};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn test_encrypt(m: &[u8]) {
    let ad = b"";
    let key = b"YELLOW SUBMARINE";
    let nonce = [0u8; 16];

    let (c, tag) = Aegis128L::new(&nonce, key).encrypt(m, ad);
    black_box(c);
    black_box(tag);
}

fn test_encrypt_in_place(mc: &mut [u8]) {
    let ad = b"";
    let key = b"YELLOW SUBMARINE";
    let nonce = [0u8; 16];
    let tag = Aegis128L::new(&nonce, key).encrypt_in_place(mc, ad);
    black_box(tag);
}

fn test_aesgcm(m: &[u8]) {
    let key = aes_gcm::Key::from_slice(b"YELLOW SUBMARINE");
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    let c = state.encrypt(nonce, m).unwrap();
    black_box(c);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut m = vec![0u8; 1024 * 1024];
    c.bench_function("aegis128l", |b| b.iter(|| test_encrypt(black_box(&m))));
    c.bench_function("aegis128l (in place)", |b| {
        b.iter(|| test_encrypt_in_place(black_box(&mut m)))
    });
    c.bench_function("aes128-gcm", |b| b.iter(|| test_aesgcm(black_box(&m))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
