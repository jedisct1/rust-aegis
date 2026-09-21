//! Tests for `stream`, `stream_xor` and `stream_xor_in_place`.
//!
//! The expected keystream comes from encrypting zeros with the AEAD functions, which the official test vectors already cover.

macro_rules! stream_tests {
    ($mod_name:ident, $cipher:ident) => {
        mod $mod_name {
            use crate::$mod_name::{$cipher, Key, Nonce};

            // Long enough to cross several blocks, even for the widest variant.
            const SHORT_LEN: usize = 4 * 128 + 3;
            const LONG_LEN: usize = 70001;

            fn fill(buf: &mut [u8], seed: u8) {
                for (i, byte) in buf.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(13).wrapping_add(seed);
                }
            }

            fn cipher<const TAG_BYTES: usize>() -> $cipher<TAG_BYTES> {
                let mut key = [0u8; core::mem::size_of::<Key>()];
                let mut nonce = [0u8; core::mem::size_of::<Nonce>()];
                fill(&mut key, 5);
                fill(&mut nonce, 11);
                $cipher::<TAG_BYTES>::new(&key, &nonce)
            }

            fn check_length(len: usize, expected: &mut [u8], out: &mut [u8], msg: &mut [u8]) {
                let (expected, out, msg) = (&mut expected[..len], &mut out[..len], &mut msg[..len]);

                expected.fill(0);
                cipher::<16>().encrypt_in_place(expected, &[]);
                out.fill(0xa5);
                cipher::<16>().stream(out);
                assert_eq!(out, expected, "stream, length {}", len);

                fill(msg, 1);
                for (byte, m) in expected.iter_mut().zip(msg.iter()) {
                    *byte ^= m;
                }
                out.copy_from_slice(msg);
                cipher::<16>().stream_xor_in_place(out);
                assert_eq!(out, expected, "stream_xor_in_place, length {}", len);

                cipher::<16>().stream_xor_in_place(out);
                assert_eq!(out, msg, "round trip, length {}", len);
            }

            #[test]
            fn matches_aead_keystream() {
                let mut expected = [0u8; SHORT_LEN];
                let mut out = [0u8; SHORT_LEN];
                let mut msg = [0u8; SHORT_LEN];
                for len in 0..=SHORT_LEN {
                    check_length(len, &mut expected, &mut out, &mut msg);
                }
            }

            #[test]
            #[cfg(feature = "std")]
            fn matches_aead_keystream_long() {
                let mut expected = vec![0u8; LONG_LEN];
                let mut out = vec![0u8; LONG_LEN];
                let mut msg = vec![0u8; LONG_LEN];
                for len in [65536, LONG_LEN] {
                    check_length(len, &mut expected, &mut out, &mut msg);
                }
            }

            #[test]
            #[cfg(feature = "std")]
            fn allocating_variant_matches_in_place() {
                let mut msg = [0u8; SHORT_LEN];
                fill(&mut msg, 1);
                let c = cipher::<16>().stream_xor(&msg);
                let mut expected = msg;
                cipher::<16>().stream_xor_in_place(&mut expected);
                assert_eq!(c, expected);
                assert_eq!(cipher::<16>().stream_xor(&c), msg);
            }

            #[test]
            fn tag_length_does_not_change_the_stream() {
                let mut a = [0u8; SHORT_LEN];
                let mut b = [0u8; SHORT_LEN];
                cipher::<16>().stream(&mut a);
                cipher::<32>().stream(&mut b);
                assert_eq!(a, b);
            }
        }
    };
}

stream_tests!(aegis128l, Aegis128L);
stream_tests!(aegis128x2, Aegis128X2);
stream_tests!(aegis128x4, Aegis128X4);
stream_tests!(aegis256, Aegis256);
stream_tests!(aegis256x2, Aegis256X2);
stream_tests!(aegis256x4, Aegis256X4);
