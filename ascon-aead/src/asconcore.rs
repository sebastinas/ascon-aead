// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

use aead::{
    consts::{U16, U20},
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    Error,
};
use ascon_core::{clear, pad, State};
use subtle::ConstantTimeEq;

#[inline(always)]
const fn keyrot(lo2hi: u64, hi2lo: u64) -> u64 {
    lo2hi << 32 | hi2lo >> 32
}

/// Helper trait for handling differences in key usage of Ascon-128* and Ascon-80*
///
/// For internal use-only.
pub trait InternalKey<KS: ArrayLength<u8>>:
    Sized + Clone + for<'a> From<&'a GenericArray<u8, KS>>
{
    /// Return K0.
    fn get_k0(&self) -> u64;
    /// Return K1.
    fn get_k1(&self) -> u64;
    /// Return K2.
    fn get_k2(&self) -> u64;
}

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct InternalKey16(u64, u64);

impl InternalKey<U16> for InternalKey16 {
    #[inline(always)]
    fn get_k0(&self) -> u64 {
        0
    }

    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.1
    }
}

impl From<&GenericArray<u8, U16>> for InternalKey16 {
    fn from(key: &GenericArray<u8, U16>) -> Self {
        // the array is exactly 16 bytes long, hence the following .try_into().unwrap() never fail
        Self(
            u64::from_be_bytes(key[..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..].try_into().unwrap()),
        )
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct InternalKey20(u64, u64, u32);

impl InternalKey<U20> for InternalKey20 {
    #[inline(always)]
    fn get_k0(&self) -> u64 {
        self.2 as u64
    }

    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.1
    }
}

impl From<&GenericArray<u8, U20>> for InternalKey20 {
    fn from(key: &GenericArray<u8, U20>) -> Self {
        // the array is exactly 20 bytes long, hence the following .try_into().unwrap() never fail
        Self(
            u64::from_be_bytes(key[4..12].try_into().unwrap()),
            u64::from_be_bytes(key[12..].try_into().unwrap()),
            u32::from_be_bytes(key[..4].try_into().unwrap()),
        )
    }
}

/// Parameters of an Ascon instance
pub trait Parameters {
    /// Size of the secret key
    ///
    /// For internal use-only.
    type KeySize: ArrayLength<u8>;
    /// Internal storage for secret keys
    ///
    /// For internal use-only.
    type InternalKey: InternalKey<Self::KeySize>;

    /// Number of bytes to process per round
    const COUNT: usize;
    /// Initialization vector used to initialize Ascon's state
    ///
    /// For internal use-only
    const IV: u64;
    /// Maximum blocks to be processed per key
    const B_MAX: u64;
}

/// Parameters for Ascon-128
pub struct Parameters128;
impl Parameters for Parameters128 {
    type KeySize = U16;
    type InternalKey = InternalKey16;

    const COUNT: usize = 8;
    const IV: u64 = 0x80400c0600000000;
    const B_MAX: u64 = u64::MAX; // 2^64;
}

/// Parameters for Ascon-128a
pub struct Parameters128a;

impl Parameters for Parameters128a {
    type KeySize = U16;
    type InternalKey = InternalKey16;

    const COUNT: usize = 16;
    const IV: u64 = 0x80800c0800000000;
    const B_MAX: u64 = u64::MAX; // 2^64;
}

/// Parameters for Ascon-80pq
pub struct Parameters80pq;

impl Parameters for Parameters80pq {
    type KeySize = U20;
    type InternalKey = InternalKey20;

    const COUNT: usize = 8;
    const IV: u64 = 0xa0400c0600000000;
    const B_MAX: u64 = u64::MAX;
}

/// Core implementation of Ascon for one encryption/decryption operation
pub(crate) struct AEADCore<'a, P: Parameters> {
    state: State,
    key: &'a P::InternalKey,
}

impl<'a, P: Parameters> AEADCore<'a, P> {
    pub(crate) fn new(internal_key: &'a P::InternalKey, nonce: &GenericArray<u8, U16>) -> Self {
        let mut state = State::new(
            if P::KeySize::USIZE == 20 {
                P::IV ^ internal_key.get_k0()
            } else {
                P::IV
            },
            internal_key.get_k1(),
            internal_key.get_k2(),
            u64::from_be_bytes(nonce[..8].try_into().unwrap()),
            u64::from_be_bytes(nonce[8..].try_into().unwrap()),
        );

        state.permute_12();
        if P::KeySize::USIZE == 20 {
            state[2] ^= internal_key.get_k0();
        }
        state[3] ^= internal_key.get_k1();
        state[4] ^= internal_key.get_k2();

        Self {
            state,
            key: internal_key,
        }
    }

    /// Permutation with 12 rounds and application of the key at the end
    fn permute_12_and_apply_key(&mut self) {
        self.state.permute_12();
        self.state[3] ^= self.key.get_k1();
        self.state[4] ^= self.key.get_k2();
    }

    /// Permutation with 6 or 8 rounds based on the parameters
    #[inline(always)]
    fn permute_state(&mut self) {
        if P::COUNT == 8 {
            self.state.permute_6();
        } else {
            self.state.permute_8();
        }
    }

    fn process_associated_data(&mut self, mut associated_data: &[u8]) {
        if !associated_data.is_empty() {
            // TODO: rewrite with as_chunks once stabilized
            // https://github.com/rust-lang/rust/issues/74985

            while associated_data.len() >= P::COUNT {
                // process full block of associated data
                self.state[0] ^= u64::from_be_bytes(associated_data[..8].try_into().unwrap());
                if P::COUNT == 16 {
                    self.state[1] ^= u64::from_be_bytes(associated_data[8..16].try_into().unwrap());
                }
                self.permute_state();
                associated_data = &associated_data[P::COUNT..];
            }

            // process partial block if it exists
            let sidx = if P::COUNT == 16 && associated_data.len() >= 8 {
                self.state[0] ^= u64::from_be_bytes(associated_data[..8].try_into().unwrap());
                associated_data = &associated_data[8..];
                1
            } else {
                0
            };
            self.state[sidx] ^= pad(associated_data.len());
            if !associated_data.is_empty() {
                let mut tmp = [0u8; 8];
                tmp[0..associated_data.len()].copy_from_slice(associated_data);
                self.state[sidx] ^= u64::from_be_bytes(tmp);
            }
            self.permute_state();
        }

        // domain separation
        self.state[4] ^= 1;
    }

    fn process_encrypt_inplace(&mut self, mut message: &mut [u8]) {
        while message.len() >= P::COUNT {
            // process full block of message
            self.state[0] ^= u64::from_be_bytes(message[..8].try_into().unwrap());
            message[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            if P::COUNT == 16 {
                self.state[1] ^= u64::from_be_bytes(message[8..16].try_into().unwrap());
                message[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1]));
            }
            self.permute_state();
            message = &mut message[P::COUNT..];
        }

        // process partial block if it exists
        let sidx = if P::COUNT == 16 && message.len() >= 8 {
            self.state[0] ^= u64::from_be_bytes(message[..8].try_into().unwrap());
            message[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            message = &mut message[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(message.len());
        if !message.is_empty() {
            let mut tmp = [0u8; 8];
            tmp[0..message.len()].copy_from_slice(message);
            self.state[sidx] ^= u64::from_be_bytes(tmp);
            message.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..message.len()]);
        }
    }

    fn process_decrypt_inplace(&mut self, mut ciphertext: &mut [u8]) {
        while ciphertext.len() >= P::COUNT {
            // process full block of ciphertext
            let cx = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
            ciphertext[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            if P::COUNT == 16 {
                let cx = u64::from_be_bytes(ciphertext[8..16].try_into().unwrap());
                ciphertext[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1] ^ cx));
                self.state[1] = cx;
            }
            self.permute_state();
            ciphertext = &mut ciphertext[P::COUNT..];
        }

        // process partial block if it exists
        let sidx = if P::COUNT == 16 && ciphertext.len() >= 8 {
            let cx = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
            ciphertext[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            ciphertext = &mut ciphertext[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(ciphertext.len());
        if !ciphertext.is_empty() {
            let mut tmp = [0u8; 8];
            tmp[0..ciphertext.len()].copy_from_slice(ciphertext);
            let cx = u64::from_be_bytes(tmp);
            self.state[sidx] ^= cx;
            ciphertext.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..ciphertext.len()]);
            self.state[sidx] = clear(self.state[sidx], ciphertext.len()) ^ cx;
        }
    }

    fn process_final(&mut self) -> [u8; 16] {
        if P::KeySize::USIZE == 16 && P::COUNT == 8 {
            self.state[1] ^= self.key.get_k1();
            self.state[2] ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 16 && P::COUNT == 16 {
            self.state[2] ^= self.key.get_k1();
            self.state[3] ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 20 {
            self.state[1] ^= keyrot(self.key.get_k0(), self.key.get_k1());
            self.state[2] ^= keyrot(self.key.get_k1(), self.key.get_k2());
            self.state[3] ^= keyrot(self.key.get_k2(), 0);
        }

        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state[3]));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state[4]));
        tag
    }

    pub(crate) fn encrypt_inplace(
        &mut self,
        message: &mut [u8],
        associated_data: &[u8],
    ) -> GenericArray<u8, U16> {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        GenericArray::from(self.process_final())
    }

    pub(crate) fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &GenericArray<u8, U16>,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt_inplace(ciphertext);

        let tag = self.process_final();
        if bool::from(tag.ct_eq(expected_tag)) {
            Ok(())
        } else {
            Err(Error)
        }
    }
}
