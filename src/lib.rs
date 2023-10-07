#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
    use crate::aegis256::Aegis256;

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Aegis128L::<16>::new(key, &nonce).encrypt(m, ad);
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

        let m2 = Aegis128L::<16>::new(key, &nonce)
            .decrypt(&c, &tag, ad)
            .unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_aegis_in_place() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let mut mc = m.to_vec();
        let tag = Aegis128L::<16>::new(key, &nonce).encrypt_in_place(&mut mc, ad);
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

        Aegis128L::<16>::new(key, &nonce)
            .decrypt_in_place(&mut mc, &tag, ad)
            .unwrap();
        assert_eq!(mc, m);
    }

    #[test]
    fn test_aegis_tag256() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINE";
        let nonce = [0u8; 16];

        let (c, tag) = Aegis128L::<32>::new(key, &nonce).encrypt(m, ad);
        let m2 = Aegis128L::<32>::new(key, &nonce)
            .decrypt(&c, &tag, ad)
            .unwrap();
        assert_eq!(m2, m);
    }

    #[test]
    fn test_aegis256() {
        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINEyellow submarine";
        let nonce = [0u8; 32];

        let (c, tag) = Aegis256::<16>::new(key, &nonce).encrypt(m, ad);
        let expected_c = [
            28, 86, 25, 203, 194, 96, 35, 113, 83, 56, 121, 160, 252, 40, 16, 52, 168, 107, 157,
            22, 5, 184, 93, 52, 56, 228, 198, 179, 17, 239, 55, 60, 36, 31, 55, 181, 19, 55, 23,
            242, 188, 226, 59, 198, 71, 124, 124, 139, 40, 64, 229, 233, 149, 239, 19, 34, 19, 253,
            171, 97, 1, 103, 5, 118, 182, 174, 140, 67, 10, 68, 251, 70, 119, 28, 42, 245, 143,
            132, 252, 28, 133, 61, 225, 187, 133, 32, 81, 17, 63, 178, 172, 206, 64, 49, 56, 4, 8,
            117, 42, 115, 150, 157, 187, 110, 161, 229, 148, 33, 107, 246, 11, 21, 71, 120,
        ];
        let expected_tag = [
            165, 12, 79, 88, 207, 169, 198, 202, 14, 54, 207, 237, 114, 121, 97, 30,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Aegis256::<16>::new(key, &nonce)
            .decrypt(&c, &tag, ad)
            .unwrap();
        assert_eq!(m2, m);
    }
}
