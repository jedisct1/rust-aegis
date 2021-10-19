use aegis::aegis128l::Aegis128L;
use aes_gcm::{
    aead::{AeadInPlace as _, NewAead as _},
    Aes128Gcm, Aes256Gcm,
};
use benchmark_simple::*;
use chacha20poly1305::ChaCha20Poly1305;

fn test_aes256gcm(mut m: &mut [u8]) {
    let key = aes_gcm::Key::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], &mut m).unwrap();
}

fn test_aes128gcm(mut m: &mut [u8]) {
    let key = aes_gcm::Key::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], &mut m).unwrap();
}

fn test_aegis128l(mut m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::new(&nonce, &key);
    state.encrypt_in_place(&mut m, &[]);
}

fn test_chacha20poly1305(mut m: &mut [u8]) {
    let key = chacha20poly1305::Key::from_slice(&[0u8; 32]);
    let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]);
    let state = ChaCha20Poly1305::new(key);
    state
        .encrypt_in_place_detached(&nonce, &[], &mut m)
        .unwrap();
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 1024 * 1024 * 1024];

    let res = bench.run(None, || test_aes256gcm(&mut m));
    println!("aes256-gcm        : {}", res.throughput(m.len() as _));

    let res = bench.run(None, || test_aes128gcm(&mut m));
    println!("aes128-gcm        : {}", res.throughput(m.len() as _));

    let res = bench.run(None, || test_chacha20poly1305(&mut m));
    println!("chacha20-poly1305 : {}", res.throughput(m.len() as _));

    let res = bench.run(None, || test_aegis128l(&mut m));
    println!("aegis128l         : {}", res.throughput(m.len() as _));
}
