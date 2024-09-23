use crate::*;
use aead::array::Array;
use aead::consts::*;
use aead::*;

pub struct Aegis256X4<const TAG_BYTES: usize> {
    key: Array<u8, U32>,
}

impl AeadCore for Aegis256X4<16> {
    type NonceSize = U32;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadCore for Aegis256X4<32> {
    type NonceSize = U32;
    type TagSize = U32;
    type CiphertextOverhead = U0;
}

impl<const TAG_SIZE: usize> KeySizeUser for Aegis256X4<TAG_SIZE> {
    type KeySize = U32;
}

impl<const TAG_SIZE: usize> KeyInit for Aegis256X4<TAG_SIZE> {
    fn new(key: &Array<u8, Self::KeySize>) -> Self {
        Self { key: *key }
    }
}

impl AeadInPlace for Aegis256X4<16> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        let state = aegis256x4::Aegis256X4::<16>::new(self.key.as_ref(), nonce.as_ref());
        let tag = state.encrypt_in_place(buffer, associated_data);
        Ok(tag.into())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        let state = aegis256x4::Aegis256X4::<16>::new(self.key.as_ref(), nonce.as_ref());
        state
            .decrypt_in_place(buffer, tag.as_ref(), associated_data)
            .map_err(|_| aead::Error)
    }
}

impl AeadInPlace for Aegis256X4<32> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag<Self>> {
        let state = aegis256x4::Aegis256X4::<32>::new(self.key.as_ref(), nonce.as_ref());
        let tag = state.encrypt_in_place(buffer, associated_data);
        Ok(tag.into())
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag<Self>,
    ) -> Result<()> {
        let state = aegis256x4::Aegis256X4::<32>::new(self.key.as_ref(), nonce.as_ref());
        state
            .decrypt_in_place(buffer, tag.as_ref(), associated_data)
            .map_err(|_| aead::Error)
    }
}

#[test]
fn test_wrappers() {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256X4::<16>::new(&key.into());
    let mut buffer = [0u8; 16];
    let tag = state
        .encrypt_in_place_detached(&nonce.into(), &[], &mut buffer)
        .unwrap();
    state
        .decrypt_in_place_detached(&nonce.into(), &[], &mut buffer, &tag)
        .unwrap();
}
