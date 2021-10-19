# AEGIS for Rust

This is a Rust implementation of the AEGIS authenticated cipher,
ported from the Zig standard library.

AEGIS is extremely fast on CPUs with AES acceleration, has a
large nonce size, and is key committing.

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

Macbook Pro - 2,4 GHz Intel Core i9

| cipher            | speed   |
| ----------------- | ------- |
| aes256-gcm        | 1.44G/s |
| chacha20-poly1305 | 1.51G/s |
| aegis128l         | 4.71G/s |