use aead::generic_array::ArrayLength;
use aead::{
    consts::{U16, U20},
    generic_array::{typenum::Unsigned, GenericArray},
    Error,
};
use subtle::ConstantTimeEq;

/// Ascon nonces
pub type Nonce = GenericArray<u8, U16>;

/// Ascon tags
pub type Tag = GenericArray<u8, U16>;

/// Helper trait for handling differences in key usage of Ascon-128* and Ascon-80*
///
/// For internal use-only.
pub trait InternalKey<KS: ArrayLength<u8>>:
    Sized + Copy + for<'a> From<&'a GenericArray<u8, KS>>
{
    /// Return K0.
    fn get_k0(&self) -> u64;
    /// Return K1.
    fn get_k1(&self) -> u64;
    /// Return K2.
    fn get_k2(&self) -> u64;
}

#[derive(Clone, Copy)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
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
        Self(
            u64::from_be_bytes(key[..8].try_into().unwrap()),
            u64::from_be_bytes(key[8..].try_into().unwrap()),
        )
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize))]
pub struct InternalKey24(u64, u64, u64);

impl InternalKey<U20> for InternalKey24 {
    #[inline(always)]
    fn get_k0(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.1
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.2
    }
}

impl From<&GenericArray<u8, U20>> for InternalKey24 {
    fn from(key: &GenericArray<u8, U20>) -> Self {
        Self(
            u32::from_be_bytes(key[..4].try_into().unwrap()) as u64,
            u64::from_be_bytes(key[4..12].try_into().unwrap()),
            u64::from_be_bytes(key[12..].try_into().unwrap()),
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
    type InternalKey = InternalKey24;

    const COUNT: usize = 8;
    const IV: u64 = 0xa0400c0600000000;
    const B_MAX: u64 = u64::MAX;
}

#[inline(always)]
fn pad(n: usize) -> u64 {
    (0x80_u64) << (56 - 8 * n)
}

#[inline(always)]
fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}

#[inline(always)]
fn keyrot(lo2hi: u64, hi2lo: u64) -> u64 {
    lo2hi << 32 | hi2lo >> 32
}

/// The state of Ascon's permutation
struct State {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
}

impl State {
    fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State { x0, x1, x2, x3, x4 }
    }

    /// Permute with a single round
    fn round(&mut self, c: u64) {
        // S-box layer
        let x0 = self.x0 ^ self.x4;
        let x2 = self.x2 ^ self.x1 ^ c; // with round constant
        let x4 = self.x4 ^ self.x3;

        let tx0 = x0 ^ (!self.x1 & x2);
        let tx1 = self.x1 ^ (!x2 & self.x3);
        let tx2 = x2 ^ (!self.x3 & x4);
        let tx3 = self.x3 ^ (!x4 & x0);
        let tx4 = x4 ^ (!x0 & self.x1);
        let tx1 = tx1 ^ tx0;
        let tx3 = tx3 ^ tx2;
        let tx0 = tx0 ^ tx4;

        // linear layer
        let x0 = tx0 ^ tx0.rotate_right(9);
        let x1 = tx1 ^ tx1.rotate_right(22);
        let x2 = tx2 ^ tx2.rotate_right(5);
        let x3 = tx3 ^ tx3.rotate_right(7);
        let x4 = tx4 ^ tx4.rotate_right(34);
        self.x0 = tx0 ^ x0.rotate_right(19);
        self.x1 = tx1 ^ x1.rotate_right(39);
        self.x2 = !(tx2 ^ x2.rotate_right(1));
        self.x3 = tx3 ^ x3.rotate_right(10);
        self.x4 = tx4 ^ x4.rotate_right(7);
    }

    /// Permutation with 12 rounds
    fn permute_12(&mut self) {
        self.round(0xf0);
        self.round(0xe1);
        self.round(0xd2);
        self.round(0xc3);
        self.round(0xb4);
        self.round(0xa5);
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5a);
        self.round(0x4b);
    }

    /// Permutation with 8 rounds
    fn permute_8(&mut self) {
        self.round(0xb4);
        self.round(0xa5);
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5a);
        self.round(0x4b);
    }

    /// Permutation with 6 rounds
    fn permute_6(&mut self) {
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5a);
        self.round(0x4b);
    }
}

/// Core implementation of Ascon for one encryption/decryption operation
pub struct Core<P: Parameters> {
    state: State,
    key: P::InternalKey,
}

impl<P: Parameters> Core<P> {
    pub fn new(internal_key: &P::InternalKey, nonce: &Nonce) -> Self {
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
            state.x2 ^= internal_key.get_k0();
        }
        state.x3 ^= internal_key.get_k1();
        state.x4 ^= internal_key.get_k2();

        Self {
            state,
            key: *internal_key,
        }
    }

    /// Permutation with 12 rounds and application of the key at the end
    fn permute_12_and_apply_key(&mut self) {
        self.state.permute_12();
        self.state.x3 ^= self.key.get_k1();
        self.state.x4 ^= self.key.get_k2();
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

    fn process_associated_data(&mut self, associated_data: &[u8]) {
        let mut len = associated_data.len();
        let mut idx: usize = 0;
        if len > 0 {
            while len >= P::COUNT {
                // process full block of associated data
                self.state.x0 ^=
                    u64::from_be_bytes(associated_data[idx..idx + 8].try_into().unwrap());
                if P::COUNT == 16 {
                    self.state.x1 ^=
                        u64::from_be_bytes(associated_data[idx + 8..idx + 16].try_into().unwrap());
                }
                self.permute_state();
                len -= P::COUNT;
                idx += P::COUNT;
            }

            // process partial block if it exists
            let px = if P::COUNT == 16 && len >= 8 {
                self.state.x0 ^=
                    u64::from_be_bytes(associated_data[idx..idx + 8].try_into().unwrap());
                len -= 8;
                idx += 8;
                &mut self.state.x1
            } else {
                &mut self.state.x0
            };
            *px ^= pad(len);
            if len > 0 {
                let mut tmp: [u8; 8] = [0; 8];
                tmp[0..len].copy_from_slice(&associated_data[idx..]);
                *px ^= u64::from_be_bytes(tmp);
            }
            self.permute_state();
        }

        // domain separation
        self.state.x4 ^= 1;
    }

    fn process_encrypt_inplace(&mut self, message: &mut [u8]) {
        let mut len = message.len();
        let mut idx: usize = 0;
        while len >= P::COUNT {
            // process full block of message
            self.state.x0 ^= u64::from_be_bytes(message[idx..idx + 8].try_into().unwrap());
            message[idx..idx + 8].copy_from_slice(&u64::to_be_bytes(self.state.x0));
            if P::COUNT == 16 {
                self.state.x1 ^= u64::from_be_bytes(message[idx + 8..idx + 16].try_into().unwrap());
                message[idx + 8..idx + 16].copy_from_slice(&u64::to_be_bytes(self.state.x1));
            }
            self.permute_state();
            len -= P::COUNT;
            idx += P::COUNT;
        }

        // process partial block if it exists
        let px = if P::COUNT == 16 && len >= 8 {
            self.state.x0 ^= u64::from_be_bytes(message[idx..idx + 8].try_into().unwrap());
            message[idx..idx + 8].copy_from_slice(&u64::to_be_bytes(self.state.x0));
            len -= 8;
            idx += 8;
            &mut self.state.x1
        } else {
            &mut self.state.x0
        };
        *px ^= pad(len);
        if len > 0 {
            let mut tmp: [u8; 8] = [0; 8];
            tmp[0..len].copy_from_slice(&message[idx..]);
            *px ^= u64::from_be_bytes(tmp);
            message[idx..].copy_from_slice(&u64::to_be_bytes(*px)[0..len]);
        }
    }

    fn process_decrypt_inplace(&mut self, ciphertext: &mut [u8]) {
        let mut len = ciphertext.len();
        let mut idx: usize = 0;
        while len >= P::COUNT {
            // process full block of ciphertext
            let cx = u64::from_be_bytes(ciphertext[idx..idx + 8].try_into().unwrap());
            ciphertext[idx..idx + 8].copy_from_slice(&u64::to_be_bytes(self.state.x0 ^ cx));
            self.state.x0 = cx;
            if P::COUNT == 16 {
                let cx = u64::from_be_bytes(ciphertext[idx + 8..idx + 16].try_into().unwrap());
                ciphertext[idx + 8..idx + 16]
                    .copy_from_slice(&u64::to_be_bytes(self.state.x1 ^ cx));
                self.state.x1 = cx;
            }
            self.permute_state();
            len -= P::COUNT;
            idx += P::COUNT;
        }

        // process partial block if it exists
        let px = if P::COUNT == 16 && len >= 8 {
            let cx = u64::from_be_bytes(ciphertext[idx..idx + 8].try_into().unwrap());
            ciphertext[idx..idx + 8].copy_from_slice(&u64::to_be_bytes(self.state.x0 ^ cx));
            self.state.x0 = cx;
            len -= 8;
            idx += 8;
            &mut self.state.x1
        } else {
            &mut self.state.x0
        };
        *px ^= pad(len);
        if len > 0 {
            let mut tmp: [u8; 8] = [0; 8];
            tmp[0..len].copy_from_slice(&ciphertext[idx..]);
            let cx = u64::from_be_bytes(tmp);
            *px ^= cx;
            ciphertext[idx..].copy_from_slice(&u64::to_be_bytes(*px)[0..len]);
            *px = clear(*px, len) ^ cx;
        }
    }

    fn process_final(&mut self) -> Tag {
        if P::KeySize::USIZE == 16 && P::COUNT == 8 {
            self.state.x1 ^= self.key.get_k1();
            self.state.x2 ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 16 && P::COUNT == 16 {
            self.state.x2 ^= self.key.get_k1();
            self.state.x3 ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 20 {
            self.state.x1 ^= keyrot(self.key.get_k0(), self.key.get_k1());
            self.state.x2 ^= keyrot(self.key.get_k1(), self.key.get_k2());
            self.state.x3 ^= keyrot(self.key.get_k2(), 0);
        }

        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state.x3));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state.x4));
        Tag::from(tag)
    }

    pub fn encrypt_inplace(&mut self, message: &mut [u8], associated_data: &[u8]) -> Tag {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        self.process_final()
    }

    pub fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &Tag,
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

#[cfg(test)]
mod tests {
    use super::{clear, pad, State};

    #[test]
    fn pad_0to7() {
        assert_eq!(pad(0), 0x8000000000000000);
        assert_eq!(pad(1), 0x80000000000000);
        assert_eq!(pad(2), 0x800000000000);
        assert_eq!(pad(3), 0x8000000000);
        assert_eq!(pad(4), 0x80000000);
        assert_eq!(pad(5), 0x800000);
        assert_eq!(pad(6), 0x8000);
        assert_eq!(pad(7), 0x80);
    }

    #[test]
    fn clear_0to7() {
        assert_eq!(clear(0x0123456789abcdef, 1), 0x23456789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 2), 0x456789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 3), 0x6789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 4), 0x89abcdef);
        assert_eq!(clear(0x0123456789abcdef, 5), 0xabcdef);
        assert_eq!(clear(0x0123456789abcdef, 6), 0xcdef);
        assert_eq!(clear(0x0123456789abcdef, 7), 0xef);
    }

    #[test]
    fn state_permute_12() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_12();
        assert_eq!(state.x0, 0x206416dfc624bb14);
        assert_eq!(state.x1, 0x1b0c47a601058aab);
        assert_eq!(state.x2, 0x8934cfc93814cddd);
        assert_eq!(state.x3, 0xa9738d287a748e4b);
        assert_eq!(state.x4, 0xddd934f058afc7e1);
    }

    #[test]
    fn state_permute_128() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_6();
        assert_eq!(state.x0, 0xc27b505c635eb07f);
        assert_eq!(state.x1, 0xd388f5d2a72046fa);
        assert_eq!(state.x2, 0x9e415c204d7b15e7);
        assert_eq!(state.x3, 0xce0d71450fe44581);
        assert_eq!(state.x4, 0xdd7c5fef57befe48);
    }

    #[test]
    fn state_permute_128a() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_8();
        assert_eq!(state.x0, 0x67ed228272f46eee);
        assert_eq!(state.x1, 0x80bc0b097aad7944);
        assert_eq!(state.x2, 0x2fa599382c6db215);
        assert_eq!(state.x3, 0x368133fae2f7667a);
        assert_eq!(state.x4, 0x28cefb195a7c651c);
    }
}
