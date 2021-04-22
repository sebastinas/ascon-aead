mod asconcore;

pub use aead::{self, AeadCore, AeadInPlace, Buffer, Error, NewAead};
use asconcore::Core;
pub use asconcore::{Key, Nonce, Parameters128, Parameters128A, Tag};
use cipher::consts::{U0, U16};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Maximum length of associated data
pub const A_MAX: usize = 1 << 36;

/// Maximum length of plaintext
pub const P_MAX: usize = 1 << 36;

/// Maximum length of ciphertext
pub const C_MAX: usize = (1 << 36) + 16;

pub struct Ascon {
    key: Key,
}

#[cfg(feature = "zeroize")]
impl Drop for Ascon {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl NewAead for Ascon {
    type KeySize = U16;

    fn new(key: &Key) -> Self {
        Self { key: *key }
    }
}

impl AeadCore for Ascon {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl AeadInPlace for Ascon {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() > P_MAX || associated_data.len() > A_MAX {
            return Err(Error);
        }

        let mut core = Core::<Parameters128>::new(&self.key, nonce);
        let tag = core.encrypt_inplace(buffer, associated_data);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        if buffer.len() > C_MAX || associated_data.len() > A_MAX {
            return Err(Error);
        }

        let mut core = Core::<Parameters128>::new(&self.key, nonce);
        core.decrypt_inplace(buffer, associated_data, tag)?;
        Ok(())
    }
}
