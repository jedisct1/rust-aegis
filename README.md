# AEGIS for Rust

This is a Rust implementation of the
[AEGIS-128L](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/)
authenticated cipher, ported from the Zig standard library.

AEGIS is extremely fast on CPUs with AES acceleration, has a large nonce size,
and is key committing.

# Cargo flags

- `std`: allow dynamic allocations

`std` is the default.

- `pure-rust`: don't use the `cc` crate to take advantage of the optimized implementation ported from libsodium. Setting this flag will substantially degrade performance. Only required if you need to support old x86_64 or ARM CPUs without AES acceleration.

A benchmark can be run that way:

```sh
export RUSTFLAGS="-C target-cpu=native"
cargo bench
```

For benchmarking, `RUSTFLAGS` is set so that the AES-GCM implementations can take advantage of hardware acceleration.

# Benchmarks

Benchmarks take a 16384 bytes input block. Results are in bytes per second.

## Rust implementations

Crates:

- `aes-gcm`
- `boring`
- `chacha20poly1305`
- `aegis128l`

## AMD Zen2

| cipher                       |      speed |
| ---------------------------- | ---------: |
| aes256-gcm (`aes-gcm` crate) | 934.41 M/s |
| aes128-gcm (`aes-gcm` crate) | 973.18 M/s |
| chacha20-poly1305            |   1.35 G/s |
| aes256-gcm (`boring` crate)  |   3.31 G/s |
| aes128-gcm (`boring` crate)  |   3.61 G/s |
| aegis128l                    |  13.70 G/s |

## AMD Zen4

| cipher                       |     speed |
| ---------------------------- | --------: |
| aes128-gcm (`aes-gcm` crate) |  1.73 G/s |
| aes256-gcm (`aes-gcm` crate) |  1.86 G/s |
| chacha20-poly1305            |  2.47 G/s |
| aes256-gcm (`boring` crate)  |  5.14 G/s |
| aes128-gcm (`boring` crate)  |  5.92 G/s |
| aegis128l                    | 23.35 G/s |

## Macbook Pro - Apple M1

| cipher                       |      speed |
| ---------------------------- | ---------: |
| aes256-gcm (`aes-gcm` crate) | 139.66 M/s |
| aes128-gcm (`aes-gcm` crate) | 173.09 M/s |
| chacha20-poly1305            | 265.48 M/s |
| aes256-gcm (`boring` crate)  |   5.14 G/s |
| aes128-gcm (`boring` crate)  |   6.08 G/s |
| aegis128l                    |  13.88 G/s |

## WebAssembly (Wasmtime, Zen4)

| cipher            |      speed |
| ----------------- | ---------: |
| aes256-gcm        |  62.97 M/s |
| aes128-gcm        |  73.83 M/s |
| chacha20-poly1305 |  88.92 M/s |
| aegis128l         | 537.49 M/s |

## WebAssembly (Wasmtime, Apple M1)

| cipher            |      speed |
| ----------------- | ---------: |
| aes256-gcm        |  49.43 M/s |
| aes128-gcm        |  59.37 M/s |
| chacha20-poly1305 | 177.85 M/s |
| aegis128l         | 533.85 M/s |

## Other implementations, AMD Zen2

| cipher (implementation)     |     speed |
| --------------------------- | --------: |
| chacha20-poly1305 (OpenSSL) |  2.67 G/s |
| aes256-gcm (OpenSSL)        |  4.97 G/s |
| aes128-gcm (OpenSSL)        |  6.89 G/s |
| aes128-ocb (OpenSSL)        |  7.10 G/s |
| aegis128l (Zig)             | 14.08 G/s |