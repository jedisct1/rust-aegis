# AEGIS for Rust

This is a Rust implementation of [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/).

AEGIS is a new family of authenticated encryption algorithms, offering high security and exceptional performance on modern desktop, server, and mobile CPUs.

# [API documentation](https://docs.rs/aegis)

# Cargo flags

- `std`: allow dynamic allocations. This is the default.

- `pure-rust`: don't use the `cc` crate to take advantage of the implementations from [`libaegis`](https://github.com/jedisct1/libaegis). Setting this flag will substantially degrade performance and some features may not be available. When using the pure-rust implementation, adding `RUSTFLAGS="-C target-cpu=native"` to the environment variable prior to compiling the project is highly recommended for better performance.

- `rustcrypto-traits-06`: add traits from `rust-crypto/aead` version 0.6. Alternative interfaces are available in the `compat` namespace.

- `raf`: encrypted random-access file I/O with OS-provided randomness. Requires `std` and the C backend (incompatible with `pure-rust`). See the [RAF section](#random-access-files-raf) below.

- `raf-core`: like `raf` but without `getrandom`. Use this on platforms where OS randomness is unavailable (e.g. freestanding wasm) and supply your own RNG via `RafBuilder::with_rng()`.

- `js`: enables `getrandom` with the `wasm_js` backend for use in `wasm32-unknown-unknown` environments with JavaScript.

# Usage

Each variant lives in its own module and is parameterized by the tag length in bytes (16 or 32).
One-shot encryption produces the ciphertext along with a detached tag:

```rust
use aegis::aegis128l::Aegis128L;

let key = [0u8; 16];
let nonce = [0u8; 16]; // Never reuse a nonce with the same key!
let ad = b"additional data";

let mut buf = *b"AEGIS is fast";
let tag = Aegis128L::<16>::new(&key, &nonce).encrypt_in_place(&mut buf, ad);
Aegis128L::<16>::new(&key, &nonce)
    .decrypt_in_place(&mut buf, &tag, ad)
    .unwrap();
assert_eq!(&buf, b"AEGIS is fast");
```

The in-place functions work without allocations and without `std`.
With the default `std` feature, `encrypt` and `decrypt` do the same into freshly allocated buffers.

# Incremental encryption and decryption

Every variant exposes an `Encryptor` and a `Decryptor` for processing a single message in chunks of arbitrary sizes, without allocations and without `std`.

The associated data must be known up front; the message itself can arrive piece by piece.
Encryption emits exactly one ciphertext byte per plaintext byte, and finalization returns the detached tag:

```rust
use aegis::aegis128l::Aegis128L;

let key = [0u8; 16];
let nonce = [0u8; 16]; // Never reuse a nonce with the same key!
let msg = b"AEGIS is fast";
let ad = b"additional data";

let cipher = Aegis128L::<16>::new(&key, &nonce);
let mut encryptor = cipher.encryptor(ad);
let mut ct = [0u8; 13];
encryptor.update(&msg[..5], &mut ct[..5]);
encryptor.update(&msg[5..], &mut ct[5..]);
let tag = encryptor.finalize();

// Decryption borrows the destination buffer until the tag has been verified.
let mut pt = [0u8; 13];
let mut decryptor = cipher.decryptor(ad, &mut pt);
decryptor.update(&ct[..7]).unwrap();
decryptor.update(&ct[7..]).unwrap();
let msg2 = decryptor.finalize(&tag).unwrap();
assert_eq!(msg2, &msg[..]);
```

Incremental decryption necessarily produces plaintext before the tag can be checked, and acting on unauthenticated plaintext is a classic protocol break.

The API prevents it structurally: the `Decryptor` exclusively borrows the whole destination buffer, so the decrypted bytes only become reachable through the slice returned by a successful `finalize`.

If the tag turns out to be invalid, or if the decryptor is dropped before finalization, whatever was provisionally written is erased.

This means the destination must be sized for the complete message up front.

The design is meant for messages that arrive in chunks, not for messages too large to hold in memory; the latter needs a record protocol that splits the stream into independently authenticated messages.

# Random Access Files (RAF)

The `raf` feature exposes an encrypted random-access file API built on top of libaegis. Files are split into independently encrypted chunks, each authenticated with AEAD. Reads and writes at arbitrary byte offsets are supported without decrypting the entire file. An optional Merkle tree provides whole-file integrity verification.

## Supported algorithms

All six AEGIS variants are available: `Aegis128L`, `Aegis128X2`, `Aegis128X4`, `Aegis256`, `Aegis256X2`, `Aegis256X4`.

## Quick start

```rust,ignore
use aegis::raf::{Raf, Aegis256};

// Create a new encrypted file
let master_key = [0u8; 32];
let key = Raf::<Aegis256>::derive_master_key(&master_key, b"my-app/files").unwrap();
let mut f = Raf::<Aegis256>::create_file("data.raf", &key).unwrap();
f.write(b"hello world", 0).unwrap();
drop(f);

// Open and read back
let mut f = Raf::<Aegis256>::open_file("data.raf", &key).unwrap();
let mut buf = vec![0u8; 11];
f.read(&mut buf, 0).unwrap();
assert_eq!(&buf, b"hello world");
```

You can also use the builder API for more control, or to supply a custom RNG on platforms without OS randomness (e.g. freestanding wasm):

```rust,ignore
use aegis::raf::{RafBuilder, Aegis128L, FileIo};

struct MyRng;

impl aegis::raf::RafRng for MyRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), aegis::raf::Error> {
        // fill buf with random bytes from your source
        Ok(())
    }
}

let io = FileIo::create("data.raf").unwrap();
let key = [0u8; 16];
let mut f = RafBuilder::<Aegis128L>::with_rng(MyRng)
    .chunk_size(4096)
    .truncate(true)
    .create(io, &key)
    .unwrap();
```

## Context-bound keys

If an application has a long-lived master key, derive a RAF key for each file or
file family instead of reusing the raw master key directly:

```rust,ignore
use aegis::raf::{Aegis128L, Raf};

let master_key = [0u8; 16];
let key = Raf::<Aegis128L>::derive_master_key(&master_key, b"my-app/files").unwrap();
```

Different contexts produce independent keys. An empty context is allowed and
still derives a RAF-scoped key; it is not a pass-through of the master key.
Contexts are limited to 120 bytes for 128-bit variants and 72 bytes for 256-bit
variants.

When you do not have an algorithm in hand, `derive_key` performs the same
derivation parameterized only by the key length (16 or 32 bytes), inferred from
the master key:

```rust,ignore
use aegis::raf::derive_key;

let master_key = [0u8; 32];
let key = derive_key(&master_key, b"my-app/files").unwrap();
```

## Builder options

`RafBuilder` controls file creation and opening:

- `chunk_size(n)` -- set the chunk size in bytes (default: 65536, only used on create).
- `truncate(true)` -- truncate the file on create.
- `rng(r)` -- supply a custom `RafRng` implementation.
- `merkle(hasher, max_chunks)` -- enable Merkle tree integrity with a custom `MerkleHasher`.

## Operations

`Raf<A>` provides:

- `read(buf, offset)` / `write(data, offset)` -- random-access I/O at any byte offset.
- `size()` -- current logical file size.
- `truncate(new_size)` -- shrink the file.
- `sync()` -- flush to storage.
- `cursor()` -- returns a `RafCursor` implementing `std::io::Read`, `Write`, and `Seek`.
- `merkle_rebuild()` / `merkle_verify()` / `merkle_commitment(out)` -- Merkle tree operations (requires Merkle to be enabled via the builder).

## Custom I/O

Implement the `RafIo` trait to use any storage backend:

```rust,ignore
pub trait RafIo {
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()>;
    fn write_at(&mut self, buf: &[u8], offset: u64) -> std::io::Result<()>;
    fn get_size(&mut self) -> std::io::Result<u64>;
    fn set_size(&mut self, size: u64) -> std::io::Result<()>;
    fn sync(&mut self) -> std::io::Result<()> { Ok(()) }
}
```

`FileIo` is the provided implementation for `std::fs::File`.

## Probing files

To inspect an encrypted file without opening it:

```rust,ignore
use aegis::raf::{self, FileIo};

let mut io = FileIo::open("data.raf").unwrap();
let info = raf::probe(&mut io).unwrap();
println!("algorithm: {:?}, chunk_size: {}, file_size: {}",
    info.algorithm, info.chunk_size, info.file_size);
```

## WebAssembly

RAF works on WebAssembly targets:

- Freestanding wasm (`wasm32-unknown-unknown` without JS): use `--features raf-core` and supply a custom `RafRng` via `RafBuilder::with_rng()`.
- wasm + JavaScript: use `--features raf-core,js` to get `OsRng` backed by `crypto.getRandomValues`.
- WASI: use `--features raf` for automatic OS-provided randomness.

# Benchmarks

AEGIS is very fast on CPUs with parallel execution pipelines and AES support.

Benchmarks can be reproduced using `export CC="clang -O3 -march=native"` and the `cargo bench` or `cargo-zigbuild bench` commands.

For performance, `clang` is recommended over `gcc`.

## Encryption (16 KB)

![AEGIS benchmark results](https://raw.githubusercontent.com/jedisct1/rust-aegis/master/img/bench-encryption.png)

## Authentication (64 KB)

![AEGIS-MAC benchmark results](https://raw.githubusercontent.com/jedisct1/rust-aegis/master/img/bench-mac.png)

### Mobile benchmarks

![AEGIS mobile benchmark results](https://raw.githubusercontent.com/jedisct1/rust-aegis/master/img/bench-mobile.png)
