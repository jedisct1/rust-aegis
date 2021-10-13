# AEGIS for Rust

This is a Rust implementation of the AEGIS authenticated cipher,
ported from the Zig standard library.

AEGIS is extremely fast on CPUs with AES acceleration, has a
large nonce size, and is key committing.

# Cargo flags

- `std`: allow dynamic allocations
- `aes_crate`: use the `aes` crate, which works on all platforms
- `aesni`: use an optimized implementation for x86 CPUs with AES extensions

`std, aes_crate` is the default.
