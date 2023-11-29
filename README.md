# AEGIS for Rust

This is a Rust implementation of the
[AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/)
authenticated cipher.

AEGIS is extremely fast on CPUs with AES acceleration, has a large nonce size,
and is key committing.

# [API documentation](https://docs.rs/aegis)

# Cargo flags

- `std`: allow dynamic allocations

`std` is the default.

- `pure-rust`: don't use the `cc` crate to take advantage of the implementations from [`libaegis`](https://github.com/jedisct1/libaegis). Setting this flag will substantially degrade performance, and parallel variants will not be available.

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
- `aegis`

## AMD Zen4

rust 1.73, zig cc 0.11

| cipher                       |     speed |
| ---------------------------- | --------: |
| aes128-gcm (`aes-gcm` crate) |  2.19 G/s |
| aes256-gcm (`aes-gcm` crate) |  2.03 G/s |
| chacha20-poly1305            |  2.00 G/s |
| aes256-gcm (`boring` crate)  |  5.93 G/s |
| aes128-gcm (`boring` crate)  |  6.33 G/s |
| aegis256                     | 15.40 G/s |
| aegis256x2                   | 30.60 G/s |
| aegis256x4                   | 46.17 G/s |
| aegis128l                    | 26.16 G/s |
| aegis128x2                   | 50.35 G/s |
| aegis128x4                   | 66.22 G/s |

## Macbook Pro - Apple M1

rust 1.73, Xcode

| cipher                       |      speed |
| ---------------------------- | ---------: |
| aes256-gcm (`aes-gcm` crate) | 139.66 M/s |
| aes128-gcm (`aes-gcm` crate) | 173.09 M/s |
| chacha20-poly1305            | 265.48 M/s |
| aes256-gcm (`boring` crate)  |   5.14 G/s |
| aes128-gcm (`boring` crate)  |   6.08 G/s |
| aegis256                     |   7.94 G/s |
| aegis256x2                   |  10.56 G/s |
| aegis256x4                   |  11.20 G/s |
| aegis128l                    |  14.27 G/s |
| aegis128x2                   |  15.98 G/s |
| aegis128x4                   |  12.01 G/s |

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
