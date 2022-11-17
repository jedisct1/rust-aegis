#![cfg_attr(not(feature = "std"), no_std)]

use std::fmt;

#[cfg(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
mod pure_rust;
#[cfg(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub use pure_rust::*;

#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
mod c;
#[cfg(not(any(
    feature = "pure-rust",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
)))]
pub use c::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    InvalidTag,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use crate::aegis128l::Aegis128L;

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Aegis128L::new(&nonce, key).encrypt(m, ad);
        let expected_c = [
            137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159,
            166, 71, 169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131,
            148, 166, 200, 180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196,
            143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206,
            238, 139, 2, 251, 194, 222, 185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127,
            160, 215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69, 205, 251, 65, 159,
            177, 3, 101,
        ];
        let expected_tag = [
            16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Aegis128L::new(&nonce, key).decrypt(&c, &tag, ad).unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_aegis_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Aegis128L::new(&nonce, key).encrypt_in_place(&mut mc, ad);
        let expected_mc = [
            137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159,
            166, 71, 169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131,
            148, 166, 200, 180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196,
            143, 98, 25, 129, 118, 132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206,
            238, 139, 2, 251, 194, 222, 185, 59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127,
            160, 215, 89, 217, 109, 89, 76, 225, 102, 118, 69, 94, 252, 2, 69, 205, 251, 65, 159,
            177, 3, 101,
        ];
        let expected_tag = [
            16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150,
        ];
        assert_eq!(mc, expected_mc);
        assert_eq!(tag, expected_tag);

        Aegis128L::new(&nonce, key)
            .decrypt_in_place(&mut mc, &tag, ad)
            .unwrap();
        assert_eq!(mc, m);
    }
}
