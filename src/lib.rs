#![no_std]

mod asconcore;

pub use aead::{self, AeadCore, AeadInPlace, Buffer, Error, NewAead};
use asconcore::Core;
pub use asconcore::{Key, Nonce, Parameters, Parameters128, Parameters128A, Tag};
use cipher::consts::{U0, U16};
use core::marker::PhantomData;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Maximum length of associated data
pub const A_MAX: usize = 1 << 36;

/// Maximum length of plaintext
pub const P_MAX: usize = 1 << 36;

/// Maximum length of ciphertext
pub const C_MAX: usize = (1 << 36) + 16;

/// Ascon generic over some Parameters
pub struct Ascon<P: Parameters> {
    key: Key,
    parameters: PhantomData<P>,
}

/// Ascon128
pub type Ascon128 = Ascon<Parameters128>;
/// Ascon128A
pub type Ascon128A = Ascon<Parameters128A>;

#[cfg(feature = "zeroize")]
impl<P: Parameters> Drop for Ascon<P> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<P: Parameters> NewAead for Ascon<P> {
    type KeySize = U16;

    fn new(key: &Key) -> Self {
        Self {
            key: *key,
            parameters: PhantomData,
        }
    }
}

impl<P: Parameters> AeadCore for Ascon<P> {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<P: Parameters> AeadInPlace for Ascon<P> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        if buffer.len() > P_MAX || associated_data.len() > A_MAX {
            return Err(Error);
        }

        let mut core = Core::<P>::new(&self.key, nonce);
        Ok(core.encrypt_inplace(buffer, associated_data))
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

        let mut core = Core::<P>::new(&self.key, nonce);
        core.decrypt_inplace(buffer, associated_data, tag)
    }
}
