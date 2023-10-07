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
use aes_soft::AesBlock;

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
))]
mod aes_ni;

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
))]
use aes_ni::AesBlock;

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aes_armcrypto;

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
use aes_armcrypto::AesBlock;

pub mod aegis128l;
