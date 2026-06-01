#![cfg(all(
    feature = "raf-core",
    feature = "getrandom",
    not(feature = "pure-rust")
))]

use aegis::raf::{self, derive_key, Aegis128L, Aegis256, FileIo, Raf, RafBuilder};
use std::io::{Read, Seek, SeekFrom, Write};

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tmp");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

#[test]
fn derive_master_key_known_answer_128() {
    let master_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let expected = [
        0xfb, 0x80, 0x07, 0x2c, 0x5a, 0x6f, 0x1c, 0xdd, 0xc6, 0xe9, 0x7b, 0x35, 0xed, 0x1f, 0x3b,
        0xf3,
    ];

    let derived = Raf::<Aegis128L>::derive_master_key(&master_key, b"test-context").unwrap();
    assert_eq!(derived, expected);
}

#[test]
fn derive_master_key_known_answer_256() {
    let master_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let expected = [
        0xfe, 0xe2, 0xd3, 0xcc, 0x58, 0xc6, 0x9d, 0x8f, 0x43, 0xfd, 0x7b, 0x4e, 0x33, 0xea, 0xec,
        0x00, 0x53, 0x53, 0x96, 0x85, 0xc7, 0xe2, 0x84, 0xe6, 0xe1, 0x2e, 0xe9, 0xc4, 0xf4, 0x23,
        0xd1, 0x36,
    ];

    let derived = Raf::<Aegis256>::derive_master_key(&master_key, b"test-context").unwrap();
    assert_eq!(derived, expected);
}

#[test]
fn derive_master_key_empty_context_known_answer() {
    let master_key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let expected = [
        0x9b, 0x8e, 0x6d, 0xdb, 0x09, 0xc9, 0xeb, 0x01, 0x37, 0x88, 0x8c, 0xa2, 0xa3, 0x66, 0xfd,
        0xd0,
    ];

    let derived = Raf::<Aegis128L>::derive_master_key(&master_key, b"").unwrap();
    assert_eq!(derived, expected);
    assert_ne!(derived, master_key);
}

#[test]
fn derive_master_key_properties_and_limits() {
    let key16 = [0x42u8; 16];
    let key32 = [0x24u8; 32];

    let first = Raf::<Aegis128L>::derive_master_key(&key16, b"ctx").unwrap();
    let second = Raf::<Aegis128L>::derive_master_key(&key16, b"ctx").unwrap();
    assert_eq!(first, second);

    let other_context = Raf::<Aegis128L>::derive_master_key(&key16, b"other-ctx").unwrap();
    assert_ne!(first, other_context);

    Raf::<Aegis128L>::derive_master_key(&key16, &[0u8; 120]).unwrap();
    Raf::<Aegis256>::derive_master_key(&key32, &[0u8; 72]).unwrap();

    match Raf::<Aegis128L>::derive_master_key(&key16, &[0u8; 121]) {
        Err(raf::Error::InvalidArgument("context too long")) => {}
        other => panic!(
            "unexpected 128-bit result for too-long context: {:?}",
            other
        ),
    }
    match Raf::<Aegis256>::derive_master_key(&key32, &[0u8; 73]) {
        Err(raf::Error::InvalidArgument("context too long")) => {}
        other => panic!(
            "unexpected 256-bit result for too-long context: {:?}",
            other
        ),
    }
}

#[test]
fn derive_key_matches_algorithm_bound_form() {
    let key16 = [0x42u8; 16];
    let key32 = [0x24u8; 32];

    let generic16 = derive_key(&key16, b"ctx").unwrap();
    let bound16 = Raf::<Aegis128L>::derive_master_key(&key16, b"ctx").unwrap();
    assert_eq!(generic16, bound16);

    let generic32 = derive_key(&key32, b"ctx").unwrap();
    let bound32 = Raf::<Aegis256>::derive_master_key(&key32, b"ctx").unwrap();
    assert_eq!(generic32, bound32);
}

#[test]
fn derive_key_known_answers_and_limits() {
    let master16 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let expected16 = [
        0xfb, 0x80, 0x07, 0x2c, 0x5a, 0x6f, 0x1c, 0xdd, 0xc6, 0xe9, 0x7b, 0x35, 0xed, 0x1f, 0x3b,
        0xf3,
    ];
    assert_eq!(derive_key(&master16, b"test-context").unwrap(), expected16);

    derive_key(&master16, &[0u8; 120]).unwrap();
    match derive_key(&master16, &[0u8; 121]) {
        Err(raf::Error::InvalidArgument("context too long")) => {}
        other => panic!(
            "unexpected 16-byte result for too-long context: {:?}",
            other
        ),
    }

    let master32 = [0x24u8; 32];
    derive_key(&master32, &[0u8; 72]).unwrap();
    match derive_key(&master32, &[0u8; 73]) {
        Err(raf::Error::InvalidArgument("context too long")) => {}
        other => panic!(
            "unexpected 32-byte result for too-long context: {:?}",
            other
        ),
    }
}

#[test]
fn derive_key_rejects_invalid_length() {
    let bad = [0u8; 24];
    match derive_key(&bad, b"ctx") {
        Err(raf::Error::InvalidArgument("key length must be 16 or 32 bytes")) => {}
        other => panic!("unexpected result for 24-byte key: {:?}", other),
    }
}

#[test]
fn derive_master_key_roundtrip_and_context_separation() {
    let path = tmp_path("derive_key_roundtrip.raf");
    cleanup(&path);

    let master_key = [0x11u8; 16];
    let derived = Raf::<Aegis128L>::derive_master_key(&master_key, b"file-family-a").unwrap();
    let wrong_context = Raf::<Aegis128L>::derive_master_key(&master_key, b"file-family-b").unwrap();
    let data = b"context-derived RAF key";

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &derived).unwrap();
        f.write(data, 0).unwrap();
    }

    {
        let mut f = Raf::<Aegis128L>::open_file(&path, &derived).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.read(&mut buf, 0).unwrap();
        assert_eq!(&buf, data);
    }

    match Raf::<Aegis128L>::open_file(&path, &wrong_context) {
        Err(raf::Error::AuthenticationFailed) => {}
        Err(err) => panic!("unexpected open error with wrong derived key: {:?}", err),
        Ok(_) => panic!("opened with wrong derived key"),
    }

    cleanup(&path);
}

#[test]
fn roundtrip_128l() {
    let path = tmp_path("rt_128l.raf");
    cleanup(&path);

    let key = [0x42u8; 16];
    let data = b"hello, encrypted world!";

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        let written = f.write(data, 0).unwrap();
        assert_eq!(written, data.len());
        assert_eq!(f.size(), data.len() as u64);
    }

    {
        let mut f = Raf::<Aegis128L>::open_file(&path, &key).unwrap();
        assert_eq!(f.size(), data.len() as u64);
        let mut buf = vec![0u8; data.len()];
        let read = f.read(&mut buf, 0).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);
    }

    cleanup(&path);
}

#[test]
fn roundtrip_256() {
    let path = tmp_path("rt_256.raf");
    cleanup(&path);

    let key = [0xABu8; 32];
    let data = b"aegis-256 random access file test";

    {
        let mut f = Raf::<Aegis256>::create_file(&path, &key).unwrap();
        f.write(data, 0).unwrap();
    }

    {
        let mut f = Raf::<Aegis256>::open_file(&path, &key).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.read(&mut buf, 0).unwrap();
        assert_eq!(&buf, data);
    }

    cleanup(&path);
}

macro_rules! roundtrip_variant {
    ($test_name:ident, $algo:ty, $key_len:literal) => {
        #[test]
        fn $test_name() {
            let path = tmp_path(&format!("{}.raf", stringify!($test_name)));
            cleanup(&path);

            let key = [0x55u8; $key_len];
            let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

            {
                let mut f = Raf::<$algo>::create_file(&path, &key).unwrap();
                f.write(&data, 0).unwrap();
            }

            {
                let mut f = Raf::<$algo>::open_file(&path, &key).unwrap();
                let mut buf = vec![0u8; data.len()];
                f.read(&mut buf, 0).unwrap();
                assert_eq!(buf, data);
            }

            cleanup(&path);
        }
    };
}

roundtrip_variant!(roundtrip_aegis128x2, raf::Aegis128X2, 16);
roundtrip_variant!(roundtrip_aegis128x4, raf::Aegis128X4, 16);
roundtrip_variant!(roundtrip_aegis256x2, raf::Aegis256X2, 32);
roundtrip_variant!(roundtrip_aegis256x4, raf::Aegis256X4, 32);

#[test]
fn open_after_create_auto_scratch() {
    let path = tmp_path("auto_scratch.raf");
    cleanup(&path);

    let key = [0x77u8; 16];
    let chunk_size = 2048u32;
    let data = vec![0xAAu8; 8192];

    {
        let io = FileIo::create(&path).unwrap();
        let mut f = RafBuilder::<Aegis128L>::new()
            .chunk_size(chunk_size)
            .truncate(true)
            .create(io, &key)
            .unwrap();
        f.write(&data, 0).unwrap();
    }

    {
        let mut f = Raf::<Aegis128L>::open_file(&path, &key).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.read(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
    }

    cleanup(&path);
}

#[test]
fn truncate_file() {
    let path = tmp_path("truncate.raf");
    cleanup(&path);

    let key = [0x99u8; 16];
    let data = vec![0xBBu8; 4096];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        f.write(&data, 0).unwrap();
        assert_eq!(f.size(), 4096);

        f.truncate(1024).unwrap();
        assert_eq!(f.size(), 1024);

        let mut buf = vec![0u8; 1024];
        let n = f.read(&mut buf, 0).unwrap();
        assert_eq!(n, 1024);
        assert_eq!(&buf[..], &data[..1024]);
    }

    cleanup(&path);
}

#[test]
fn cursor_read_write_seek() {
    let path = tmp_path("cursor.raf");
    cleanup(&path);

    let key = [0xCCu8; 16];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        let mut cursor = f.cursor();

        cursor.write_all(b"hello ").unwrap();
        cursor.write_all(b"world").unwrap();
        cursor.flush().unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();
        let mut buf = String::new();
        cursor.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world");

        let pos = cursor.seek(SeekFrom::End(-5)).unwrap();
        assert_eq!(pos, 6);
    }

    cleanup(&path);
}

#[test]
fn probe_file() {
    let path = tmp_path("probe.raf");
    cleanup(&path);

    let key = [0xDDu8; 16];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        f.write(b"test", 0).unwrap();
    }

    {
        let mut io = FileIo::open(&path).unwrap();
        let info = raf::probe(&mut io).unwrap();
        assert_eq!(info.algorithm, raf::AlgorithmId::Aegis128L);
        assert!(info.chunk_size >= 1024);
        assert_eq!(info.file_size, 4);
    }

    cleanup(&path);
}

#[test]
fn wrong_key_fails() {
    let path = tmp_path("wrong_key.raf");
    cleanup(&path);

    let key = [0x11u8; 16];
    let wrong_key = [0x22u8; 16];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        f.write(b"secret", 0).unwrap();
    }

    {
        let result = Raf::<Aegis128L>::open_file(&path, &wrong_key);
        assert!(result.is_err());
    }

    cleanup(&path);
}

#[test]
fn wrong_algorithm_fails() {
    let path = tmp_path("wrong_algo.raf");
    cleanup(&path);

    let key16 = [0x33u8; 16];
    let key32 = [0x33u8; 32];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key16).unwrap();
        f.write(b"data", 0).unwrap();
    }

    {
        let result = Raf::<Aegis256>::open_file(&path, &key32);
        assert!(result.is_err());
        if let Err(raf::Error::InvalidArgument(msg)) = result {
            assert_eq!(msg, "algorithm mismatch");
        }
    }

    cleanup(&path);
}

#[test]
fn write_at_offset() {
    let path = tmp_path("offset_write.raf");
    cleanup(&path);

    let key = [0xEEu8; 16];

    {
        let mut f = Raf::<Aegis128L>::create_file(&path, &key).unwrap();
        f.write(b"AAAA", 0).unwrap();
        f.write(b"BB", 2).unwrap();

        let mut buf = vec![0u8; 4];
        f.read(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"AABB");
    }

    cleanup(&path);
}

#[test]
fn large_multi_chunk_write() {
    let path = tmp_path("multi_chunk.raf");
    cleanup(&path);

    let key = [0xFFu8; 16];
    let chunk_size = 1024u32;
    let data: Vec<u8> = (0..10000).map(|i| (i % 257) as u8).collect();

    {
        let io = FileIo::create(&path).unwrap();
        let mut f = RafBuilder::<Aegis128L>::new()
            .chunk_size(chunk_size)
            .truncate(true)
            .create(io, &key)
            .unwrap();
        f.write(&data, 0).unwrap();
    }

    {
        let mut f = Raf::<Aegis128L>::open_file(&path, &key).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.read(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
    }

    cleanup(&path);
}
