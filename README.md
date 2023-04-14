# AEGIS for Rust

This is a Rust implementation of the
[AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/)
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
- `chacha20poly1305`
- `aegis128l`

`rustc` version `1.65.0`, `wasmtime` version `4.0.0`.

## Zen2

| cipher            | speed      |
| ----------------- | ---------- |
| aes256-gcm        | 934.41 M/s |
| aes128-gcm        | 973.18 M/s |
| chacha20-poly1305 | 1.35 G/s   |
| aegis128l         | 13.70 G/s  |

## Macbook Pro - Apple M1

| cipher            | speed      |
| ----------------- | ---------- |
| aes256-gcm        | 139.66 M/s |
| aes128-gcm        | 173.09 M/s |
| chacha20-poly1305 | 265.48 M/s |
| aegis128l         | 13.88 G/s  |

## WebAssembly (Wasmtime, Zen2)

| cipher            | speed     |
| ----------------- | --------- |
| aes256-gcm        | 26.07 M/s |
| aes128-gcm        | 30.10 M/s |
| chacha20-poly1305 | 43.40 M/s |
| aegis128l         | 33.68 M/s |

## WebAssembly (Wasmtime, Apple M1)

| cipher            | speed    |
| ----------------- | -------- |
| aes256-gcm        | 2.75 M/s |
| aes128-gcm        | 3.33 M/s |
| chacha20-poly1305 | 4.10 M/s |
| aegis128l         | 3.64 M/s |

## Other implementations, Zen2

| cipher (implementation)     | speed     |
| --------------------------- | --------- |
| aes256-gcm (OpenSSL)        | 4.97 G/s  |
| aes128-gcm (OpenSSL)        | 6.89 G/s  |
| chacha20-poly1305 (OpenSSL) | 2.67 G/s  |
| aes128-ocb (OpenSSL)        | 7.10 G/s  |
| aegis128l (Zig)             | 14.08 G/s |