use crate::*;
use aead::array::Array;
use aead::consts::*;
use aead::*;
use inout::InOutBuf;

pub struct Aegis256<const TAG_BYTES: usize> {
    key: Array<u8, U32>,
}

impl AeadCore for Aegis256<16> {
    type NonceSize = U32;
    type TagSize = U16;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl AeadCore for Aegis256<32> {
    type NonceSize = U32;
    type TagSize = U32;
    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<const TAG_SIZE: usize> KeySizeUser for Aegis256<TAG_SIZE> {
    type KeySize = U32;
}

impl<const TAG_SIZE: usize> KeyInit for Aegis256<TAG_SIZE> {
    fn new(key: &Array<u8, Self::KeySize>) -> Self {
        Self { key: *key }
    }
}

impl AeadInOut for Aegis256<16> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>> {
        let input = buffer.get_in().to_vec();
        let output = buffer.get_out();
        output.copy_from_slice(&input);
        let state = aegis256::Aegis256::<16>::new(self.key.as_ref(), nonce.as_ref());
        let tag = state.encrypt_in_place(output, associated_data);
        Ok(tag.into())
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()> {
        let input = buffer.get_in().to_vec();
        let output = buffer.get_out();
        output.copy_from_slice(&input);
        let state = aegis256::Aegis256::<16>::new(self.key.as_ref(), nonce.as_ref());
        state
            .decrypt_in_place(output, tag.as_ref(), associated_data)
            .map_err(|_| aead::Error)
    }
}

impl AeadInOut for Aegis256<32> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>> {
        let input = buffer.get_in().to_vec();
        let output = buffer.get_out();
        output.copy_from_slice(&input);
        let state = aegis256::Aegis256::<32>::new(self.key.as_ref(), nonce.as_ref());
        let tag = state.encrypt_in_place(output, associated_data);
        Ok(tag.into())
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<()> {
        let input = buffer.get_in().to_vec();
        let output = buffer.get_out();
        output.copy_from_slice(&input);
        let state = aegis256::Aegis256::<32>::new(self.key.as_ref(), nonce.as_ref());
        state
            .decrypt_in_place(output, tag.as_ref(), associated_data)
            .map_err(|_| aead::Error)
    }
}

#[test]
fn test_wrappers() {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256::<16>::new(&key.into());
    let mut buffer = [0u8; 16];
    let tag = state
        .encrypt_in_place_detached(&nonce.into(), &[], &mut buffer)
        .unwrap();
    state
        .decrypt_in_place_detached(&nonce.into(), &[], &mut buffer, &tag)
        .unwrap();
}
