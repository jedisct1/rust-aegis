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
#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
use aegis::aegis256x4::Aegis256X4;

#[cfg(not(feature = "pure-rust"))]
use aegis::{aegis128l::Aegis128LMac, aegis128x2::Aegis128X2Mac, aegis128x4::Aegis128X4Mac};

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

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
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

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
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

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
fn test_aegis256x4(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256X4::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

#[cfg(not(feature = "pure-rust"))]
fn test_aegis128l_mac(state: &Aegis128LMac<32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

#[cfg(not(feature = "pure-rust"))]
fn test_aegis128x2_mac(state: &Aegis128X2Mac<32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

#[cfg(not(feature = "pure-rust"))]
fn test_aegis128x4_mac(state: &Aegis128X4Mac<32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

fn test_hmac_sha256(m: &[u8]) {
    let md = boring::hash::MessageDigest::sha256();
    let mut h1 = boring::hash::hash(md, m).unwrap().to_vec();
    h1.resize(128, 0);
    let h2 = boring::hash::hash(md, &h1).unwrap().to_vec();
    black_box(h2);
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

    #[cfg(not(feature = "pure-rust"))]
    {
        println!("* MACs:");
        println!();

        let state = Aegis128X4Mac::<32>::new(&[0u8; 16]);
        let res = bench.run(options, || test_aegis128x4_mac(&state, &m));
        println!("aegis128x4-mac      : {}", res.throughput(m.len() as _));

        let state = Aegis128X2Mac::<32>::new(&[0u8; 16]);
        let res = bench.run(options, || test_aegis128x2_mac(&state, &m));
        println!("aegis128x2-mac      : {}", res.throughput(m.len() as _));

        let state = Aegis128LMac::<32>::new(&[0u8; 16]);
        let res = bench.run(options, || test_aegis128l_mac(&state, &m));
        println!("aegis128l-mac       : {}", res.throughput(m.len() as _));

        let sthash = sthash::Hasher::new(sthash::Key::from_seed(&[0u8; 32], None), None);
        let res = bench.run(options, || sthash.hash(&m));
        println!("sthash              : {}", res.throughput(m.len() as _));

        let res = bench.run(options, || test_hmac_sha256(&m));
        println!("hmac-sha256 (boring): {}", res.throughput(m.len() as _));

        let b3 = blake3::Hasher::new_keyed(&[0u8; 32]);
        let res = bench.run(options, || b3.clone().update(&m).finalize());
        println!("blake3              : {}", res.throughput(m.len() as _));

        println!();
    }

    println!("* Encryption:");
    println!();

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

        let res = bench.run(options, || test_aegis256x4(&mut m));
        println!("aegis256x4          : {}", res.throughput(m.len() as _));
    }

    let res = bench.run(options, || test_aegis256(&mut m));
    println!("aegis256            : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_aes128gcm(&mut m));
    println!("aes128-gcm (aes-gcm): {}", res.throughput(m.len() as _));

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    {
        let res = bench.run(options, || test_aes128gcm_boringssl(&mut m));
        println!("aes128-gcm (boring) : {}", res.throughput(m.len() as _));
    }

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!("aes256-gcm (aes-gcm): {}", res.throughput(m.len() as _));

    #[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
    {
        let res = bench.run(options, || test_aes256gcm_boringssl(&mut m));
        println!("aes256-gcm (boring) : {}", res.throughput(m.len() as _));
    }

    let res = bench.run(options, || test_chacha20poly1305(&mut m));
    println!("chacha20-poly1305   : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_ascon128a(&mut m));
    println!("ascon128a           : {}", res.throughput(m.len() as _));
}
