#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_soft;
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_soft::AesBlock;

#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
mod aes_ni;

#[cfg(all(any(
    all(target_arch = "x86_64", target_feature = "aes"),
    all(target_arch = "x86", target_feature = "aes")
)))]
use aes_ni::AesBlock;

pub mod aegis128l;
