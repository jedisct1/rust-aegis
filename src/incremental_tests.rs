//! Tests for the incremental AEAD API.
//!
//! Everything is written against the public API, without allocation,
//! so the same suite runs under both backends and the `no_std` configurations.
//! The known-answer tests at the bottom need `std` for the JSON fixtures.

macro_rules! incremental_aead_tests {
    ($mod_name:ident, $cipher:ident, $rate:expr, $vectors:expr) => {
        mod $mod_name {
            use crate::$mod_name::{$cipher, Key, Nonce};
            use crate::Error;

            const RATE: usize = $rate;
            const MSG_LEN: usize = 4 * RATE + 3;
            const AD_MAX: usize = 3 * RATE + 5;

            fn key() -> Key {
                let mut key = [0u8; core::mem::size_of::<Key>()];
                for (i, byte) in key.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(23).wrapping_add(7);
                }
                key
            }

            fn nonce() -> Nonce {
                let mut nonce = [0u8; core::mem::size_of::<Nonce>()];
                for (i, byte) in nonce.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(41).wrapping_add(3);
                }
                nonce
            }

            fn message() -> [u8; MSG_LEN] {
                let mut msg = [0u8; MSG_LEN];
                for (i, byte) in msg.iter_mut().enumerate() {
                    *byte = (i as u8).wrapping_mul(13).wrapping_add(1);
                }
                msg
            }

            fn ad_storage() -> [u8; AD_MAX] {
                let mut ad = [0u8; AD_MAX];
                for (i, byte) in ad.iter_mut().enumerate() {
                    *byte = (i as u8) ^ 0x5a;
                }
                ad
            }

            fn cipher<const TAG_BYTES: usize>() -> $cipher<TAG_BYTES> {
                $cipher::<TAG_BYTES>::new(&key(), &nonce())
            }

            fn reference<const TAG_BYTES: usize>(
                msg: &[u8],
                ad: &[u8],
                ct: &mut [u8],
            ) -> [u8; TAG_BYTES] {
                ct[..msg.len()].copy_from_slice(msg);
                cipher::<TAG_BYTES>().encrypt_in_place(&mut ct[..msg.len()], ad)
            }

            fn encrypt_split_points<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..RATE + 3];
                let mut expected_ct = [0u8; MSG_LEN];
                let expected_tag = reference::<TAG_BYTES>(&msg, ad, &mut expected_ct);

                for split in 0..=MSG_LEN {
                    let mut ct = [0u8; MSG_LEN];
                    let mut enc = cipher::<TAG_BYTES>().encryptor(ad);
                    let (msg_head, msg_tail) = msg.split_at(split);
                    let (ct_head, ct_tail) = ct.split_at_mut(split);
                    enc.update(msg_head, ct_head);
                    enc.update(msg_tail, ct_tail);
                    let tag = enc.finalize();
                    assert_eq!(ct, expected_ct, "split {}", split);
                    assert_eq!(tag, expected_tag, "split {}", split);
                }
            }

            #[test]
            fn encrypt_split_points_tag16() {
                encrypt_split_points::<16>();
            }

            #[test]
            fn encrypt_split_points_tag32() {
                encrypt_split_points::<32>();
            }

            fn decrypt_split_points<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..RATE + 3];
                let mut ct = [0u8; MSG_LEN];
                let tag = reference::<TAG_BYTES>(&msg, ad, &mut ct);

                for split in 0..=MSG_LEN {
                    let mut pt = [0u8; MSG_LEN];
                    let mut dec = cipher::<TAG_BYTES>().decryptor(ad, &mut pt);
                    dec.update(&ct[..split]).unwrap();
                    dec.update(&ct[split..]).unwrap();
                    let out = dec.finalize(&tag).unwrap();
                    assert_eq!(&out[..], &msg[..], "split {}", split);
                }
            }

            #[test]
            fn decrypt_split_points_tag16() {
                decrypt_split_points::<16>();
            }

            #[test]
            fn decrypt_split_points_tag32() {
                decrypt_split_points::<32>();
            }

            fn byte_at_a_time_with_empty_updates<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..7];
                let mut expected_ct = [0u8; MSG_LEN];
                let expected_tag = reference::<TAG_BYTES>(&msg, ad, &mut expected_ct);

                let mut ct = [0u8; MSG_LEN];
                let mut enc = cipher::<TAG_BYTES>().encryptor(ad);
                enc.update(&[], &mut []);
                for i in 0..MSG_LEN {
                    enc.update(&msg[i..=i], &mut ct[i..=i]);
                    enc.update(&[], &mut []);
                }
                let tag = enc.finalize();
                assert_eq!(ct, expected_ct);
                assert_eq!(tag, expected_tag);

                let mut pt = [0u8; MSG_LEN];
                let mut dec = cipher::<TAG_BYTES>().decryptor(ad, &mut pt);
                dec.update(&[]).unwrap();
                for i in 0..MSG_LEN {
                    dec.update(&ct[i..=i]).unwrap();
                    dec.update(&[]).unwrap();
                }
                let out = dec.finalize(&tag).unwrap();
                assert_eq!(&out[..], &msg[..]);
            }

            #[test]
            fn byte_at_a_time_with_empty_updates_tag16() {
                byte_at_a_time_with_empty_updates::<16>();
            }

            #[test]
            fn byte_at_a_time_with_empty_updates_tag32() {
                byte_at_a_time_with_empty_updates::<32>();
            }

            fn in_place_matches_separate_buffers<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..RATE - 1];
                let mut expected_ct = [0u8; MSG_LEN];
                let expected_tag = reference::<TAG_BYTES>(&msg, ad, &mut expected_ct);

                for split in 0..=MSG_LEN {
                    let mut buffer = msg;
                    let mut enc = cipher::<TAG_BYTES>().encryptor(ad);
                    let (head, tail) = buffer.split_at_mut(split);
                    enc.update_in_place(head);
                    enc.update_in_place(tail);
                    let tag = enc.finalize();
                    assert_eq!(buffer, expected_ct, "split {}", split);
                    assert_eq!(tag, expected_tag, "split {}", split);
                }
            }

            #[test]
            fn in_place_matches_separate_buffers_tag16() {
                in_place_matches_separate_buffers::<16>();
            }

            #[test]
            fn in_place_matches_separate_buffers_tag32() {
                in_place_matches_separate_buffers::<32>();
            }

            fn associated_data_lengths<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                for ad_len in [0, 1, RATE - 1, RATE, RATE + 1, 3 * RATE, 3 * RATE + 5] {
                    let ad = &ad_storage[..ad_len];
                    let mut expected_ct = [0u8; MSG_LEN];
                    let expected_tag = reference::<TAG_BYTES>(&msg, ad, &mut expected_ct);

                    let mut ct = [0u8; MSG_LEN];
                    let mut enc = cipher::<TAG_BYTES>().encryptor(ad);
                    enc.update(&msg, &mut ct);
                    let tag = enc.finalize();
                    assert_eq!(ct, expected_ct, "ad_len {}", ad_len);
                    assert_eq!(tag, expected_tag, "ad_len {}", ad_len);

                    let mut pt = [0u8; MSG_LEN];
                    let mut dec = cipher::<TAG_BYTES>().decryptor(ad, &mut pt);
                    dec.update(&ct).unwrap();
                    let out = dec.finalize(&tag).unwrap();
                    assert_eq!(&out[..], &msg[..], "ad_len {}", ad_len);
                }
            }

            #[test]
            fn associated_data_lengths_tag16() {
                associated_data_lengths::<16>();
            }

            #[test]
            fn associated_data_lengths_tag32() {
                associated_data_lengths::<32>();
            }

            fn empty_message<const TAG_BYTES: usize>() {
                let ad_storage = ad_storage();
                let ad = &ad_storage[..5];
                let expected_tag = cipher::<TAG_BYTES>().encrypt_in_place(&mut [], ad);

                let enc = cipher::<TAG_BYTES>().encryptor(ad);
                assert_eq!(enc.finalize(), expected_tag);

                let mut enc = cipher::<TAG_BYTES>().encryptor(ad);
                enc.update(&[], &mut []);
                assert_eq!(enc.finalize(), expected_tag);

                let mut pt = [0u8; 0];
                let dec = cipher::<TAG_BYTES>().decryptor(ad, &mut pt);
                let out = dec.finalize(&expected_tag).unwrap();
                assert!(out.is_empty());
            }

            #[test]
            fn empty_message_tag16() {
                empty_message::<16>();
            }

            #[test]
            fn empty_message_tag32() {
                empty_message::<32>();
            }

            fn invalid_tag_erases_plaintext<const TAG_BYTES: usize>() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..3];
                let mut ct = [0u8; MSG_LEN];
                let tag = reference::<TAG_BYTES>(&msg, ad, &mut ct);
                let mut bad_tag = tag;
                bad_tag[0] ^= 1;

                let mut pt = [0xaau8; MSG_LEN];
                let mut dec = cipher::<TAG_BYTES>().decryptor(ad, &mut pt);
                dec.update(&ct).unwrap();
                assert_eq!(dec.finalize(&bad_tag).unwrap_err(), Error::InvalidTag);
                assert!(pt.iter().all(|&byte| byte == 0));
            }

            #[test]
            fn invalid_tag_erases_plaintext_tag16() {
                invalid_tag_erases_plaintext::<16>();
            }

            #[test]
            fn invalid_tag_erases_plaintext_tag32() {
                invalid_tag_erases_plaintext::<32>();
            }

            #[test]
            fn dropped_decryptor_erases_written_prefix() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..3];
                let mut ct = [0u8; MSG_LEN];
                let _tag = reference::<16>(&msg, ad, &mut ct);

                let written = RATE + 2;
                let mut pt = [0xaau8; MSG_LEN];
                {
                    let mut dec = cipher::<16>().decryptor(ad, &mut pt);
                    dec.update(&ct[..written]).unwrap();
                }
                assert!(pt[..written].iter().all(|&byte| byte == 0));
                assert!(pt[written..].iter().all(|&byte| byte == 0xaa));
            }

            #[test]
            fn undersized_destination_recovers() {
                let msg = message();
                let ad_storage = ad_storage();
                let ad = &ad_storage[..3];
                let mut ct = [0u8; MSG_LEN];
                let tag = reference::<16>(&msg, ad, &mut ct);

                let oversized = [0u8; MSG_LEN + 1];
                let mut pt = [0u8; MSG_LEN];
                let mut dec = cipher::<16>().decryptor(ad, &mut pt);
                assert_eq!(
                    dec.update(&oversized).unwrap_err(),
                    Error::OutputBufferTooSmall
                );
                dec.update(&ct).unwrap();
                let out = dec.finalize(&tag).unwrap();
                assert_eq!(&out[..], &msg[..]);
            }

            #[test]
            fn length_limit_accepts_max_encrypt() {
                let mut enc = cipher::<16>().encryptor(&[]);
                enc.set_consumed_length_for_tests(crate::MAX_AEAD_BYTES - 1);
                let mut byte = [0u8; 1];
                enc.update_in_place(&mut byte);
            }

            #[test]
            #[should_panic(expected = "total message length exceeds 2^61 - 1 bytes")]
            fn length_limit_rejects_above_max_encrypt() {
                let mut enc = cipher::<16>().encryptor(&[]);
                enc.set_consumed_length_for_tests(crate::MAX_AEAD_BYTES);
                let mut byte = [0u8; 1];
                enc.update_in_place(&mut byte);
            }

            #[test]
            fn length_limit_decrypt() {
                let mut pt = [0u8; 4];
                let mut dec = cipher::<16>().decryptor(&[], &mut pt);
                dec.set_consumed_length_for_tests(crate::MAX_AEAD_BYTES - 1);
                dec.update(&[0u8]).unwrap();
                assert_eq!(dec.update(&[0u8]).unwrap_err(), Error::MessageTooLong);
                dec.update(&[]).unwrap();
            }

            #[test]
            #[cfg(feature = "std")]
            fn debug_output_is_redacted() {
                let key_hint = std::format!("{}", key()[0]);
                let printed = std::format!("{:?}", cipher::<16>());
                assert!(printed.contains(".."));
                assert!(!printed.contains(&key_hint));

                let printed = std::format!("{:?}", cipher::<16>().encryptor(&[]));
                assert!(printed.contains("Encryptor"));
                assert!(printed.contains(".."));

                let mut pt = [0u8; 4];
                let printed = std::format!("{:?}", cipher::<16>().decryptor(&[], &mut pt));
                assert!(printed.contains("Decryptor"));
                assert!(printed.contains(".."));
            }

            #[test]
            #[cfg(feature = "std")]
            fn known_answer_chunk_layouts() {
                use ct_codecs::{Decoder, Hex};
                use serde_json::Value;
                use std::convert::TryInto;

                let data =
                    std::fs::read_to_string(concat!("src/test-vectors/", $vectors)).unwrap();
                let vectors: Vec<Value> = serde_json::from_str(&data).unwrap();

                for vector in vectors.iter() {
                    if vector.get("key").is_none()
                        || vector.get("ct").is_none()
                        || vector.get("msg").is_none()
                        || vector.get("ad").is_none()
                        || vector.get("tag128").is_none()
                        || vector.get("tag256").is_none()
                    {
                        continue;
                    }
                    let key: Key =
                        Hex::decode_to_vec(vector["key"].as_str().unwrap(), None)
                            .unwrap()
                            .try_into()
                            .unwrap();
                    let nonce: Nonce =
                        Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None)
                            .unwrap()
                            .try_into()
                            .unwrap();
                    let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
                    let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
                    let expected_ct =
                        Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
                    let tag128: [u8; 16] =
                        Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None)
                            .unwrap()
                            .try_into()
                            .unwrap();
                    let tag256: [u8; 32] =
                        Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None)
                            .unwrap()
                            .try_into()
                            .unwrap();

                    for chunk_len in [1, 2, 3, 7, RATE - 1, RATE, RATE + 1, 2 * RATE + 1] {
                        kat_one_layout::<16>(&key, &nonce, &ad, &msg, &expected_ct, &tag128, chunk_len);
                        kat_one_layout::<32>(&key, &nonce, &ad, &msg, &expected_ct, &tag256, chunk_len);
                    }
                }
            }

            #[cfg(feature = "std")]
            fn kat_one_layout<const TAG_BYTES: usize>(
                key: &Key,
                nonce: &Nonce,
                ad: &[u8],
                msg: &[u8],
                expected_ct: &[u8],
                expected_tag: &[u8; TAG_BYTES],
                chunk_len: usize,
            ) {
                let mut ct = std::vec![0u8; msg.len()];
                let mut enc = $cipher::<TAG_BYTES>::new(key, nonce).encryptor(ad);
                for (msg_chunk, ct_chunk) in msg.chunks(chunk_len).zip(ct.chunks_mut(chunk_len)) {
                    enc.update(msg_chunk, ct_chunk);
                }
                let tag = enc.finalize();
                assert_eq!(&ct[..], expected_ct, "chunk_len {}", chunk_len);
                assert_eq!(&tag, expected_tag, "chunk_len {}", chunk_len);

                let mut pt = std::vec![0u8; msg.len()];
                let mut dec = $cipher::<TAG_BYTES>::new(key, nonce).decryptor(ad, &mut pt);
                for ct_chunk in expected_ct.chunks(chunk_len) {
                    dec.update(ct_chunk).unwrap();
                }
                let out = dec.finalize(expected_tag).unwrap();
                assert_eq!(&out[..], msg, "chunk_len {}", chunk_len);
            }
        }
    };
}

incremental_aead_tests!(aegis128l, Aegis128L, 32, "aegis-128l-test-vectors.json");
incremental_aead_tests!(aegis128x2, Aegis128X2, 64, "aegis-128x2-test-vectors.json");
incremental_aead_tests!(aegis128x4, Aegis128X4, 128, "aegis-128x4-test-vectors.json");
incremental_aead_tests!(aegis256, Aegis256, 16, "aegis-256-test-vectors.json");
incremental_aead_tests!(aegis256x2, Aegis256X2, 32, "aegis-256x2-test-vectors.json");
incremental_aead_tests!(aegis256x4, Aegis256X4, 64, "aegis-256x4-test-vectors.json");
