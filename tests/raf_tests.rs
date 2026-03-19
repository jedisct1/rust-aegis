#![cfg(all(feature = "raf-core", feature = "getrandom", not(feature = "pure-rust")))]

use aegis::raf::{self, Aegis128L, Aegis256, FileIo, Raf, RafBuilder};
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
