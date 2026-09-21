#[cfg(not(feature = "pure-rust"))]
mod c_backend {
    use aes_gcm::aead::{AeadInOut as _, KeyInit as _};
    use ct_codecs::{Decoder as _, Hex};
    use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    const SAMPLES: usize = 7;
    const SAMPLE_TIME: Duration = Duration::from_millis(100);
    const CHUNK_SIZE: usize = 16 * 1024;
    const CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const CTR_PLAINTEXT: &str = concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81",
        "c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    );
    const CTR128_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const CTR128_CIPHERTEXT: &str = concat!(
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae",
        "4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"
    );
    const CTR256_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const CTR256_CIPHERTEXT: &str = concat!(
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5",
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"
    );

    fn measure(algorithm: &str, operation: &str, bytes: usize, mut run: impl FnMut()) {
        if std::env::var("AEGIS_BENCH_FILTER")
            .ok()
            .is_some_and(|filter| !algorithm.contains(&filter))
        {
            return;
        }
        let mut iterations = 1u64;
        loop {
            let start = Instant::now();
            for _ in 0..iterations {
                run();
            }
            if start.elapsed() >= SAMPLE_TIME {
                break;
            }
            iterations *= 2;
        }

        let mut rates = [0.0; SAMPLES];
        for rate in &mut rates {
            let start = Instant::now();
            for _ in 0..iterations {
                run();
            }
            *rate = bytes as f64 * iterations as f64 * 8.0 / start.elapsed().as_secs_f64() / 1e9;
        }
        let samples = rates.map(|rate| format!("{rate:.6}")).join(";");
        rates.sort_by(f64::total_cmp);
        println!(
            "{algorithm},{operation},{bytes},{iterations},{:.6},{:.6},{:.6},{samples}",
            rates[SAMPLES / 2],
            rates[0],
            rates[SAMPLES - 1]
        );
    }

    macro_rules! benchmark {
        ($module:ident, $cipher:ident, $mac:ident, $key_bytes:literal, $bytes:expr) => {{
            use aegis::$module::{$cipher, $mac};

            let key = black_box([0x42u8; $key_bytes]);
            let nonce = black_box([0x24u8; $key_bytes]);
            let mut buffer = vec![0xd0u8; $bytes];
            let name = stringify!($cipher);

            measure(name, "aead", $bytes, || {
                let state = $cipher::<16>::new(black_box(&key), black_box(&nonce));
                black_box(state.encrypt_in_place(black_box(&mut buffer), black_box(&[])));
                black_box(&buffer);
            });
            measure(name, "mac", $bytes, || {
                let mut state = $mac::<32>::new(black_box(&key));
                state.update(black_box(&buffer));
                black_box(state.finalize());
            });
            measure(name, "stream_xor", $bytes, || {
                let state = $cipher::<16>::new(black_box(&key), black_box(&nonce));
                state.stream_xor_in_place(black_box(&mut buffer));
                black_box(&buffer);
            });
            measure(name, "keystream", $bytes, || {
                let state = $cipher::<16>::new(black_box(&key), black_box(&nonce));
                state.stream(black_box(&mut buffer));
                black_box(&buffer);
            });
            measure(name, "incremental_aead", $bytes, || {
                let state = $cipher::<16>::new(black_box(&key), black_box(&nonce));
                let mut encryptor = state.encryptor(black_box(&[]));
                for chunk in black_box(&mut buffer).chunks_mut(CHUNK_SIZE) {
                    encryptor.update_in_place(chunk);
                }
                black_box(encryptor.finalize());
                black_box(&buffer);
            });
        }};
    }

    macro_rules! benchmark_aead {
        ($cipher:ty, $label:literal, $key_bytes:literal, $nonce_bytes:literal, $bytes:expr) => {{
            let key = black_box([0x42u8; $key_bytes]);
            let nonce = black_box([0x24u8; $nonce_bytes]);
            let mut buffer = vec![0xd0u8; $bytes];
            let state = <$cipher>::new((&key).into());
            let mut check = [0xabu8; 37];
            let tag = state
                .encrypt_inout_detached((&nonce).into(), &[], check.as_mut_slice().into())
                .unwrap();
            let ciphertext = check;
            state
                .decrypt_inout_detached((&nonce).into(), &[], check.as_mut_slice().into(), &tag)
                .unwrap();
            assert_eq!(check, [0xabu8; 37]);
            check = ciphertext;
            check[0] ^= 1;
            assert!(state
                .decrypt_inout_detached((&nonce).into(), &[], check.as_mut_slice().into(), &tag)
                .is_err());

            measure($label, "aead", $bytes, || {
                let state = <$cipher>::new(black_box(&key).into());
                black_box(
                    state
                        .encrypt_inout_detached(
                            black_box(&nonce).into(),
                            black_box(&[]),
                            black_box(buffer.as_mut_slice()).into(),
                        )
                        .unwrap(),
                );
                black_box(&buffer);
            });
        }};
    }

    macro_rules! benchmark_ctr {
        ($aes:ty, $label:literal, $key_hex:expr, $ciphertext_hex:expr, $bytes:expr) => {{
            type Cipher = ctr::Ctr128BE<$aes>;
            let key = Hex::decode_to_vec($key_hex, None).unwrap();
            let iv = Hex::decode_to_vec(CTR_IV, None).unwrap();
            let plaintext = Hex::decode_to_vec(CTR_PLAINTEXT, None).unwrap();
            let expected = Hex::decode_to_vec($ciphertext_hex, None).unwrap();
            for chunk_size in [7, plaintext.len()] {
                let mut check = plaintext.clone();
                let mut state = Cipher::new_from_slices(&key, &iv).unwrap();
                for chunk in check.chunks_mut(chunk_size) {
                    state.apply_keystream(chunk);
                }
                assert_eq!(check, expected);

                let mut check = vec![0xa5u8; plaintext.len()];
                let mut state = Cipher::new_from_slices(&key, &iv).unwrap();
                for chunk in check.chunks_mut(chunk_size) {
                    state.write_keystream(chunk);
                }
                for (byte, plaintext_byte) in check.iter_mut().zip(&plaintext) {
                    *byte ^= plaintext_byte;
                }
                assert_eq!(check, expected);
            }

            let mut buffer = vec![0xd0u8; $bytes];
            measure($label, "stream_xor", $bytes, || {
                let mut state = Cipher::new_from_slices(black_box(&key), black_box(&iv)).unwrap();
                state.apply_keystream(black_box(&mut buffer));
                black_box(&buffer);
            });
            measure($label, "keystream", $bytes, || {
                let mut state = Cipher::new_from_slices(black_box(&key), black_box(&iv)).unwrap();
                state.write_keystream(black_box(&mut buffer));
                black_box(&buffer);
            });
        }};
    }

    #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
    fn boring_ctr(
        cipher: boring::symm::Cipher,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) {
        use boring::symm::{Crypter, Mode};
        let mut state = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
        let count = state.update(input, output).unwrap();
        let final_count = state.finalize(&mut output[count..]).unwrap();
        assert_eq!(count + final_count, input.len());
    }

    #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
    fn benchmark_boring_ctr(bytes: usize) {
        use boring::symm::{Cipher, Crypter, Mode};
        let iv = Hex::decode_to_vec(CTR_IV, None).unwrap();
        let plaintext = Hex::decode_to_vec(CTR_PLAINTEXT, None).unwrap();
        let input = vec![0xd0u8; bytes];
        let zeros = vec![0u8; bytes];
        let mut output = vec![0u8; bytes + 16];
        for (label, cipher, key_hex, ciphertext_hex) in [
            (
                "AES-128-CTR (BoringSSL)",
                Cipher::aes_128_ctr(),
                CTR128_KEY,
                CTR128_CIPHERTEXT,
            ),
            (
                "AES-256-CTR (BoringSSL)",
                Cipher::aes_256_ctr(),
                CTR256_KEY,
                CTR256_CIPHERTEXT,
            ),
        ] {
            let key = Hex::decode_to_vec(key_hex, None).unwrap();
            let expected = Hex::decode_to_vec(ciphertext_hex, None).unwrap();
            let mut check = vec![0xa5u8; plaintext.len() + 16];
            boring_ctr(cipher, &key, &iv, &plaintext, &mut check);
            assert_eq!(&check[..plaintext.len()], expected);
            boring_ctr(cipher, &key, &iv, &zeros[..plaintext.len()], &mut check);
            for (byte, plaintext_byte) in check.iter_mut().zip(&plaintext) {
                *byte ^= plaintext_byte;
            }
            assert_eq!(&check[..plaintext.len()], expected);
            let mut state = Crypter::new(cipher, Mode::Encrypt, &key, Some(&iv)).unwrap();
            let mut written = 0;
            for chunk in plaintext.chunks(7) {
                written += state.update(chunk, &mut check[written..]).unwrap();
            }
            written += state.finalize(&mut check[written..]).unwrap();
            assert_eq!(&check[..written], expected);

            measure(label, "stream_xor", bytes, || {
                boring_ctr(
                    cipher,
                    black_box(&key),
                    black_box(&iv),
                    black_box(&input),
                    black_box(&mut output),
                );
                black_box(&output);
            });
            measure(label, "keystream", bytes, || {
                boring_ctr(
                    cipher,
                    black_box(&key),
                    black_box(&iv),
                    black_box(&zeros),
                    black_box(&mut output),
                );
                black_box(&output);
            });
        }
    }

    fn benchmark_stream_comparisons(bytes: usize) {
        benchmark_ctr!(
            aes::Aes128,
            "AES-128-CTR (aes/ctr crates)",
            CTR128_KEY,
            CTR128_CIPHERTEXT,
            bytes
        );
        benchmark_ctr!(
            aes::Aes256,
            "AES-256-CTR (aes/ctr crates)",
            CTR256_KEY,
            CTR256_CIPHERTEXT,
            bytes
        );
        #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
        benchmark_boring_ctr(bytes);
    }

    #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
    fn boring_encrypt(
        cipher: boring::symm::Cipher,
        key: &[u8],
        nonce: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> [u8; 16] {
        use boring::symm::{Crypter, Mode};
        let mut state = Crypter::new(cipher, Mode::Encrypt, key, Some(nonce)).unwrap();
        let count = state.update(input, output).unwrap();
        let final_count = state.finalize(&mut output[count..]).unwrap();
        assert_eq!(count + final_count, input.len());
        let mut tag = [0u8; 16];
        state.get_tag(&mut tag).unwrap();
        tag
    }

    #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
    fn benchmark_boring(bytes: usize) {
        use boring::symm::{decrypt_aead, Cipher};
        let input = vec![0xd0u8; bytes];
        let mut output = vec![0u8; bytes + 16];
        let nonce = black_box([0x24u8; 12]);
        for (label, cipher, key) in [
            (
                "AES-128-GCM (BoringSSL)",
                Cipher::aes_128_gcm(),
                &[0x42u8; 16][..],
            ),
            (
                "AES-256-GCM (BoringSSL)",
                Cipher::aes_256_gcm(),
                &[0x42u8; 32][..],
            ),
        ] {
            let key = black_box(key);
            let tag = boring_encrypt(cipher, key, &nonce, &input, &mut output);
            assert_eq!(
                decrypt_aead(cipher, key, Some(&nonce), &[], &output[..bytes], &tag).unwrap(),
                input
            );
            output[0] ^= 1;
            assert!(decrypt_aead(cipher, key, Some(&nonce), &[], &output[..bytes], &tag).is_err());
            measure(label, "aead", bytes, || {
                black_box(boring_encrypt(
                    cipher,
                    black_box(key),
                    black_box(&nonce),
                    black_box(&input),
                    black_box(&mut output),
                ));
                black_box(&output);
            });
        }

        assert_eq!(
            boring::hash::hmac_sha256(&[0x0b; 20], b"Hi There").unwrap(),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
        let key = black_box([0x42u8; 32]);
        measure("HMAC-SHA256 (BoringSSL)", "mac", bytes, || {
            black_box(boring::hash::hmac_sha256(black_box(&key), black_box(&input)).unwrap());
        });
    }

    fn benchmark_comparisons(bytes: usize) {
        benchmark_aead!(
            aes_gcm::Aes128Gcm,
            "AES-128-GCM (aes-gcm crate)",
            16,
            12,
            bytes
        );
        benchmark_aead!(
            aes_gcm::Aes256Gcm,
            "AES-256-GCM (aes-gcm crate)",
            32,
            12,
            bytes
        );
        benchmark_aead!(
            chacha20poly1305::ChaCha20Poly1305,
            "ChaCha20-Poly1305",
            32,
            12,
            bytes
        );
        benchmark_aead!(ascon_aead::AsconAead128, "Ascon-AEAD128", 16, 16, bytes);

        let input = vec![0xd0u8; bytes];
        let key = black_box([0x42u8; 32]);
        measure("BLAKE3 (keyed)", "mac", bytes, || {
            let mut state = blake3::Hasher::new_keyed(black_box(&key));
            state.update(black_box(&input));
            black_box(state.finalize());
        });
        let state = sthash::Hasher::new(sthash::Key::from_seed(&key, None), None);
        measure("STHash", "mac", bytes, || {
            black_box(state.hash(black_box(&input)));
        });

        #[cfg(all(feature = "boring", not(target_arch = "wasm32")))]
        benchmark_boring(bytes);
    }

    pub fn run() {
        println!("algorithm,operation,bytes,iterations,median_Gb_s,min_Gb_s,max_Gb_s,samples_Gb_s");
        for bytes in [16 * 1024, 16 * 1024 * 1024] {
            benchmark!(aegis128l, Aegis128L, Aegis128LMac, 16, bytes);
            benchmark!(aegis128x2, Aegis128X2, Aegis128X2Mac, 16, bytes);
            benchmark!(aegis128x4, Aegis128X4, Aegis128X4Mac, 16, bytes);
            benchmark!(aegis256, Aegis256, Aegis256Mac, 32, bytes);
            benchmark!(aegis256x2, Aegis256X2, Aegis256X2Mac, 32, bytes);
            benchmark!(aegis256x4, Aegis256X4, Aegis256X4Mac, 32, bytes);
            benchmark_comparisons(bytes);
            if bytes == 16 * 1024 * 1024 {
                benchmark_stream_comparisons(bytes);
            }
        }
    }
}

fn main() {
    #[cfg(not(feature = "pure-rust"))]
    c_backend::run();
    #[cfg(feature = "pure-rust")]
    eprintln!("The throughput benchmark requires the C backend.");
}
