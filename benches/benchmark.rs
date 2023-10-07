use aegis::aegis128l::Aegis128L;
use aegis::aegis256::Aegis256;

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
use aegis::aegis128x2::Aegis128X2;
#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
use aegis::aegis128x4::Aegis128X4;
#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
use aegis::aegis256x2::Aegis256X2;

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

fn test_aes256gcm_boringssl(m: &mut [u8]) {
    use boring::symm;
    use symm::Cipher;

    let cipher = Cipher::aes_256_gcm();
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let _ = symm::encrypt_aead(cipher, &key, Some(&nonce), &[], m, &mut tag).unwrap();
}

fn test_aes128gcm(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&[0u8; 16]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes128Gcm::new(key);
    state.encrypt_in_place_detached(nonce, &[], m).unwrap();
}

fn test_aes128gcm_boringssl(m: &mut [u8]) {
    use boring::symm;
    use symm::Cipher;

    let cipher = Cipher::aes_128_gcm();
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let _ = symm::encrypt_aead(cipher, &key, Some(&nonce), &[], m, &mut tag).unwrap();
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

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
fn test_aegis128x2(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X2::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
fn test_aegis128x4(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X4::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis256(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
fn test_aegis256x2(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256X2::<16>::new(&nonce, &key);
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

    #[cfg(not(any(
        feature = "pure-rust",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    )))]
    {
        let res = bench.run(options, || test_aegis128x4(&mut m));
        println!("aegis128x4          : {}", res.throughput(m.len() as _));

        let res = bench.run(options, || test_aegis128x2(&mut m));
        println!("aegis128x2          : {}", res.throughput(m.len() as _));
    }

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!("aegis128l           : {}", res.throughput(m.len() as _));

    #[cfg(not(any(
        feature = "pure-rust",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    )))]
    {
        let res = bench.run(options, || test_aegis256x2(&mut m));
        println!("aegis256x2          : {}", res.throughput(m.len() as _));
    }

    let res = bench.run(options, || test_aegis256(&mut m));
    println!("aegis256            : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!("aes128-gcm (aes-gcm): {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes128gcm_boringssl(&mut m));
    println!("aes128-gcm (boring) : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!("aes256-gcm (aes-gcm): {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes256gcm_boringssl(&mut m));
    println!("aes256-gcm (boring) : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_chacha20poly1305(&mut m));
    println!("chacha20-poly1305   : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_ascon128a(&mut m));
    println!("ascon128a           : {}", res.throughput(m.len() as _));
}
