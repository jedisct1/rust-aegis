use aegis::aegis128l::Aegis128L;
use aes_gcm::{
    aead::{AeadInPlace as _, KeyInit as _},
    Aes128Gcm, Aes256Gcm,
};
use benchmark_simple::*;
use chacha20poly1305::ChaCha20Poly1305;

fn test_aes256gcm(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_aes128gcm(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_chacha20poly1305(m: &mut [u8]) {
    let key = chacha20poly1305::Key::from_slice(&[0u8; 32]);
    let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]);
    let state = ChaCha20Poly1305::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_ascon128a(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = ascon_aead::Ascon128a::new(key.as_slice().into());
    state
        .encrypt_in_place_detached(nonce.as_slice().into(), &[], m)
        .unwrap();
}

fn test_aegis128l(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 100_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!("aegis128l         : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!("aes256-gcm        : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!("aes128-gcm        : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_chacha20poly1305(&mut m));
    println!("chacha20-poly1305 : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_ascon128a(&mut m));
    println!("ascon128a         : {}", res.throughput(m.len() as _));
}
