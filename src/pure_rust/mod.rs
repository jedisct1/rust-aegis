#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes"),
    all(target_arch = "aarch64", target_feature = "aes")
)))]
mod aes_soft;
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes"),
    all(target_arch = "aarch64", target_feature = "aes")
)))]
use aes_soft::{AesBlock, AesBlock2, AesBlock4};

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
))]
mod aes_ni;

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
))]
use aes_ni::{AesBlock, AesBlock2, AesBlock4};

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aes_armcrypto;

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use aes_armcrypto::{AesBlock, AesBlock2, AesBlock4};

/// AEGIS-128L.
pub mod aegis128l;
/// AEGIS-128X2 (2-lane variant of AEGIS-128L).
pub mod aegis128x2;
/// AEGIS-128X4 (4-lane variant of AEGIS-128L).
pub mod aegis128x4;
/// AEGIS-256.
pub mod aegis256;
/// AEGIS-256X2 (2-lane variant of AEGIS-256).
pub mod aegis256x2;
/// AEGIS-256X4 (4-lane variant of AEGIS-256).
pub mod aegis256x4;
