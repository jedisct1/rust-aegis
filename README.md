# AEGIS for Rust

This is a Rust implementation of the
[AEGIS](https://datatracker.ietf.org/doc/draft-denis-aegis-aead/)
authenticated cipher, ported from the Zig standard library.

AEGIS is extremely fast on CPUs with AES acceleration, has a large nonce size,
and is key committing.

# Cargo flags

- `std`: allow dynamic allocations

`std` is the default.

**IMPORTANT:** In order to get decent code on x86 and x86_64 CPUs, you should set
additional `rustc` flags prior to compiling that crate or a project using it:

```sh
export RUSTFLAGS="-Ctarget-feature=+aes,+sse4.1"
```

A benchmark can be run that way:

```sh
export RUSTFLAGS="-C target-cpu=native -Ctarget-feature=+aes,+pclmul,+sse4.1"
cargo bench
```

# Benchmarks

Benchmarks take a 16384 bytes input block. Results are in bytes per second.

## Rust implementations

Crates:

- `aes-gcm`
- `chacha20poly1305`
- `aegis128l`

Macbook Pro - 2,4 GHz Intel Core i9, `RUSTFLAGS` set.

| cipher            | speed    |
| ----------------- | -------- |
| aes256-gcm        | 1.59 G/s |
| aes128-gcm        | 1.91 G/s |
| chacha20-poly1305 | 1.48 G/s |
| aegis128l         | 6.21 G/s |

WebAssembly (Wasmtime)

| cipher            | speed      |
| ----------------- | ---------- |
| aes256-gcm        | 36.88 M/s  |
| aes128-gcm        | 44.13 M/s  |
| chacha20-poly1305 | 193.05 M/s |
| aegis128l         | 48.98 M/s  |

## Other implementations

| cipher (implementation)     | speed     |
| --------------------------- | --------- |
| aes256-gcm (OpenSSL)        | 4.97 G/s  |
| aes128-gcm (OpenSSL)        | 6.89 G/s  |
| chacha20-poly1305 (OpenSSL) | 2.67 G/s  |
| aes128-ocb (OpenSSL)        | 7.10 G/s  |
| aegis128l (Zig)             | 14.08 G/s |
| rocca (Zig)                 | 16.28 G/s |
