#[cfg(all(test, feature = "std"))]
mod test_vectors {
    use ct_codecs::{Decoder, Hex};
    use serde_json::Value;
    use std::convert::TryInto;
    use std::fs;

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis128l_vectors() {
        use crate::aegis128l::Aegis128L;

        let data = fs::read_to_string("src/test-vectors/aegis-128l-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for (i, vector) in vectors.iter().enumerate() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            println!("Testing vector {}: {}", i, name);
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis128L::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128L::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis128L::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128L::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis128x2_vectors() {
        use crate::aegis128x2::Aegis128X2;

        let data = fs::read_to_string("src/test-vectors/aegis-128x2-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis128X2::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128X2::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis128X2::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128X2::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis128x4_vectors() {
        use crate::aegis128x4::Aegis128X4;

        let data = fs::read_to_string("src/test-vectors/aegis-128x4-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis128X4::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128X4::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis128X4::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis128X4::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis256_vectors() {
        use crate::aegis256::Aegis256;

        let data = fs::read_to_string("src/test-vectors/aegis-256-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis256::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis256::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis256x2_vectors() {
        use crate::aegis256x2::Aegis256X2;

        let data = fs::read_to_string("src/test-vectors/aegis-256x2-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis256X2::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256X2::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis256X2::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256X2::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis256x4_vectors() {
        use crate::aegis256x4::Aegis256X4;

        let data = fs::read_to_string("src/test-vectors/aegis-256x4-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            // Skip vectors that don't have all required fields for encryption/decryption testing
            if vector.get("key").is_none()
                || vector.get("ct").is_none()
                || vector.get("msg").is_none()
                || vector.get("ad").is_none()
                || vector.get("tag128").is_none()
            {
                continue;
            }

            let name = vector["name"].as_str().unwrap();
            let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
            let nonce_vec = Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
            let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
            let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
            let ad = Hex::decode_to_vec(vector["ad"].as_str().unwrap(), None).unwrap();
            let msg = Hex::decode_to_vec(vector["msg"].as_str().unwrap(), None).unwrap();
            let expected_ct = Hex::decode_to_vec(vector["ct"].as_str().unwrap(), None).unwrap();
            let expected_tag128 =
                Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
            let expected_tag256 =
                Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

            // Test with 128-bit tag
            {
                let (ct, tag) = Aegis256X4::<16>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag128[..],
                    "Test {} failed: tag128 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256X4::<16>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }

            // Test with 256-bit tag
            {
                let (ct, tag) = Aegis256X4::<32>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(ct, expected_ct, "Test {} failed: ciphertext mismatch", name);
                assert_eq!(
                    &tag[..],
                    &expected_tag256[..],
                    "Test {} failed: tag256 mismatch",
                    name
                );

                // Test decryption
                let decrypted = Aegis256X4::<32>::new(&key, &nonce)
                    .decrypt(&ct, &tag, &ad)
                    .expect(&format!("Decryption failed for test {}", name));
                assert_eq!(decrypted, msg, "Test {} failed: decryption mismatch", name);
            }
        }
    }

    #[test]
    #[cfg(all(feature = "std", not(feature = "pure-rust")))]
    fn test_aegismac_vectors() {
        use crate::aegis128l::Aegis128LMac;
        use crate::aegis128x2::Aegis128X2Mac;
        use crate::aegis128x4::Aegis128X4Mac;
        use crate::aegis256::Aegis256Mac;
        use crate::aegis256x2::Aegis256X2Mac;
        use crate::aegis256x4::Aegis256X4Mac;

        let data = fs::read_to_string("src/test-vectors/aegismac-test-vectors.json")
            .expect("Unable to read test vectors");
        let vectors: Vec<Value> =
            serde_json::from_str(&data).expect("Unable to parse test vectors");

        for vector in vectors.iter() {
            let name = vector["name"].as_str().unwrap();
            println!("Testing AEGIS-MAC vector: {}", name);

            if name.contains("AEGISMAC-128L") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis128LMac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis128LMac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            } else if name.contains("AEGISMAC-128X2") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis128X2Mac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis128X2Mac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            } else if name.contains("AEGISMAC-128X4") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 16] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 16] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis128X4Mac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis128X4Mac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            } else if name.contains("AEGISMAC-256X2") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis256X2Mac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis256X2Mac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            } else if name.contains("AEGISMAC-256X4") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis256X4Mac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis256X4Mac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            } else if name.contains("AEGISMAC-256") {
                let key_vec = Hex::decode_to_vec(vector["key"].as_str().unwrap(), None).unwrap();
                let nonce_vec =
                    Hex::decode_to_vec(vector["nonce"].as_str().unwrap(), None).unwrap();
                let key: [u8; 32] = key_vec.try_into().expect("Invalid key length");
                let nonce: [u8; 32] = nonce_vec.try_into().expect("Invalid nonce length");
                let data = Hex::decode_to_vec(vector["data"].as_str().unwrap(), None).unwrap();
                let expected_tag128 =
                    Hex::decode_to_vec(vector["tag128"].as_str().unwrap(), None).unwrap();
                let expected_tag256 =
                    Hex::decode_to_vec(vector["tag256"].as_str().unwrap(), None).unwrap();

                // Test with 128-bit tag
                {
                    let mut mac = Aegis256Mac::<16>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag128[..],
                        "{} failed: tag128 mismatch",
                        name
                    );
                }

                // Test with 256-bit tag
                {
                    let mut mac = Aegis256Mac::<32>::new_with_nonce(&key, &nonce);
                    mac.update(&data);
                    let tag = mac.finalize();
                    assert_eq!(
                        &tag[..],
                        &expected_tag256[..],
                        "{} failed: tag256 mismatch",
                        name
                    );
                }
            }
        }
    }
}
