# AEGIS for Rust

This is a Rust implementation of the AEGIS authenticated cipher, ported from
the Zig standard library.

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
cargo bench --no-default-features
```

# Benchmarks

## Rust implementations

Crates:

- `aes-gcm`
- `chacha20poly1305`
- `aegis128l`

Macbook Pro - 2,4 GHz Intel Core i9, `RUSTFLAGS` set.

| cipher            | speed   |
| ----------------- | ------- |
| aes256-gcm        | 1.49G/s |
| aes128-gcm        | 1.72G/s |
| chacha20-poly1305 | 1.53G/s |
| aegis128l         | 4.91G/s |

WebAssembly (Wasmtime)

| cipher            | speed      |
| ----------------- | ---------- |
| aes256-gcm        | 36.24 M/s  |
| aes128-gcm        | 42.93 M/s  |
| chacha20-poly1305 | 192.31 M/s |
| aegis128l         | 49.51 M/s  |

## Other implementations

| cipher (implementation)     | speed     |
| --------------------------- | --------- |
| aes256-gcm (OpenSSL)        | 4.97 G/s  |
| aes128-gcm (OpenSSL)        | 6.89 G/s  |
| chacha20-poly1305 (OpenSSL) | 2.67 G/s  |
| aes128-ocb (OpenSSL)        | 7.10 G/s  |
| aegis128l (Zig)             | 10.13 G/s |
