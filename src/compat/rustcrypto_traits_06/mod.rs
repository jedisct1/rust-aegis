//! Implementations of the RustCrypto `aead` 0.6 traits for all six AEGIS variants.
//!
//! Every variant is wrapped in an adapter type that implements `KeyInit`, `AeadCore`,
//! and `AeadInOut`, so the ciphers can be driven through the same interface as any
//! other RustCrypto AEAD. Both the 16-byte and 32-byte authentication tag sizes are
//! supported.

mod aegis128l;
mod aegis128x2;
mod aegis128x4;

mod aegis256;
mod aegis256x2;
mod aegis256x4;

pub use aegis128l::*;
pub use aegis128x2::*;
pub use aegis128x4::*;

pub use aegis256::*;
pub use aegis256x2::*;
pub use aegis256x4::*;
