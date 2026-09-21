#[cfg(not(feature = "pure-rust"))]
mod c_backend {
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    const SAMPLES: usize = 7;
    const SAMPLE_TIME: Duration = Duration::from_millis(100);
    const CHUNK_SIZE: usize = 16 * 1024;

    fn measure(algorithm: &str, operation: &str, bytes: usize, mut run: impl FnMut()) {
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

    pub fn run() {
        println!("algorithm,operation,bytes,iterations,median_Gb_s,min_Gb_s,max_Gb_s,samples_Gb_s");
        for bytes in [16 * 1024, 16 * 1024 * 1024] {
            benchmark!(aegis128l, Aegis128L, Aegis128LMac, 16, bytes);
            benchmark!(aegis128x2, Aegis128X2, Aegis128X2Mac, 16, bytes);
            benchmark!(aegis128x4, Aegis128X4, Aegis128X4Mac, 16, bytes);
            benchmark!(aegis256, Aegis256, Aegis256Mac, 32, bytes);
            benchmark!(aegis256x2, Aegis256X2, Aegis256X2Mac, 32, bytes);
            benchmark!(aegis256x4, Aegis256X4, Aegis256X4Mac, 32, bytes);
        }
    }
}

fn main() {
    #[cfg(not(feature = "pure-rust"))]
    c_backend::run();
    #[cfg(feature = "pure-rust")]
    eprintln!("The throughput benchmark requires the C backend.");
}
