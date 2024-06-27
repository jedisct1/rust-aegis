#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
use std::fmt;

#[cfg(feature = "pure-rust")]
mod pure_rust;
#[cfg(feature = "pure-rust")]
pub use pure_rust::*;

#[cfg(not(feature = "pure-rust"))]
mod c;
#[cfg(not(feature = "pure-rust"))]
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

    #[test]
    #[cfg(feature = "std")]
    fn test_aegis() {
        use crate::aegis128l::Aegis128L;

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
        use crate::aegis128l::Aegis128L;

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

    #[cfg(feature = "std")]
    #[test]
    fn test_aegis_tag256() {
        use crate::aegis128l::Aegis128L;

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

    #[cfg(feature = "std")]
    #[test]
    fn test_aegis256() {
        use crate::aegis256::Aegis256;

        let m = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ad = b"Comment numero un";
        let key = b"YELLOW SUBMARINEyellow submarine";
        let nonce = [0u8; 32];

        let (c, tag) = Aegis256::<16>::new(key, &nonce).encrypt(m, ad);
        let expected_c = [
            62, 90, 21, 90, 245, 182, 17, 214, 55, 102, 124, 12, 140, 5, 78, 233, 79, 134, 10, 29,
            103, 105, 233, 197, 238, 49, 221, 109, 44, 245, 42, 101, 43, 204, 250, 251, 9, 111, 4,
            6, 190, 106, 238, 190, 80, 100, 12, 203, 168, 27, 250, 240, 222, 50, 155, 250, 247, 76,
            26, 233, 228, 18, 17, 187, 52, 229, 159, 66, 12, 62, 120, 255, 42, 90, 14, 50, 243,
            148, 197, 107, 194, 159, 186, 95, 69, 120, 85, 99, 212, 193, 142, 67, 74, 194, 34, 196,
            9, 135, 148, 118, 215, 39, 44, 71, 146, 241, 247, 72, 50, 60, 16, 52, 156, 226,
        ];
        let expected_tag = [
            89, 198, 229, 213, 31, 223, 43, 199, 193, 71, 4, 63, 201, 114, 129, 176,
        ];
        assert_eq!(c, expected_c);
        assert_eq!(tag, expected_tag);

        let m2 = Aegis256::<16>::new(key, &nonce)
            .decrypt(&c, &tag, ad)
            .unwrap();
        assert_eq!(m2, m);
    }

    #[cfg(not(feature = "pure-rust"))]
    #[test]
    fn test_aegis128l_mac() {
        use crate::aegis128l::Aegis128LMac;

        let key = b"YELLOW SUBMARINE";
        let mut st: Aegis128LMac<16> = Aegis128LMac::new(key);
        let mut st2 = st.clone();
        let expected_mac: [u8; 16] = [
            76, 47, 241, 40, 153, 182, 236, 199, 34, 12, 236, 15, 210, 193, 95, 189,
        ];
        st.update(b"a");
        st.verify(&expected_mac).unwrap();
        st2.update(b"a");
        st2.verify(&expected_mac).unwrap();
    }
}
