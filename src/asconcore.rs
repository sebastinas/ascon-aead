use aead::{consts::U16, generic_array::GenericArray, Error};
use core::convert::TryInto;
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Ascon keys
pub type Key = GenericArray<u8, U16>;

/// Ascon nonces
pub type Nonce = GenericArray<u8, U16>;

/// Ascon tags
pub type Tag = GenericArray<u8, U16>;

/// Parameters of an Ascon instance
pub trait Parameters {
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
    const COUNT: usize = 8;
    const IV: u64 = 0x80400c0600000000;
    const B_MAX: u64 = u64::MAX; // 2^64;
}

/// Parameters for Ascon-128a
pub struct Parameters128a;
impl Parameters for Parameters128a {
    const COUNT: usize = 16;
    const IV: u64 = 0x80800c0800000000;
    const B_MAX: u64 = u64::MAX; // 2^64;
}

#[inline(always)]
fn pad(n: usize) -> u64 {
    (0x80_u64) << (56 - 8 * n)
}

#[inline(always)]
fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}

/// The state of Ascon's permutation
struct State<P: Parameters> {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    parameters: PhantomData<P>,
}

impl<P: Parameters> State<P> {
    fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x0,
            x1,
            x2,
            x3,
            x4,
            parameters: PhantomData,
        }
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

    /// Permutation with 8 rounds and application of the key at the end
    fn permute_12_and_apply(&mut self, k0: u64, k1: u64) {
        self.permute_12();
        self.x3 ^= k0;
        self.x4 ^= k1;
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

    /// Permutation with 6 or 8 rounds based on the parameters
    #[inline(always)]
    fn permute(&mut self) {
        if P::COUNT == 8 {
            self.permute_6();
        } else {
            self.permute_8();
        }
    }
}

/// Core implementation of Ascon for one encryption/decryption operation
pub struct Core<P: Parameters> {
    state: State<P>,
    key: [u64; 2],
}

impl<P: Parameters> Core<P> {
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let key_1 = u64::from_be_bytes(key[..8].try_into().unwrap());
        let key_2 = u64::from_be_bytes(key[8..].try_into().unwrap());

        let mut state = State::new(
            P::IV,
            key_1,
            key_2,
            u64::from_be_bytes(nonce[..8].try_into().unwrap()),
            u64::from_be_bytes(nonce[8..].try_into().unwrap()),
        );

        state.permute_12_and_apply(key_1, key_2);
        Self {
            state,
            key: [key_1, key_2],
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
                self.state.permute();
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
            self.state.permute();
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
            self.state.permute();
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
            self.state.permute();
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
        if P::COUNT == 8 {
            self.state.x1 ^= self.key[0];
            self.state.x2 ^= self.key[1];
        } else if P::COUNT == 16 {
            self.state.x2 ^= self.key[0];
            self.state.x3 ^= self.key[1];
        }
        self.state.permute_12_and_apply(self.key[0], self.key[1]);

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

#[cfg(feature = "zeroize")]
impl<P: Parameters> Drop for Core<P> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{clear, pad, Parameters128, Parameters128a, State};

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
        let mut state = State::<Parameters128>::new(
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
        let mut state = State::<Parameters128>::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute();
        assert_eq!(state.x0, 0xc27b505c635eb07f);
        assert_eq!(state.x1, 0xd388f5d2a72046fa);
        assert_eq!(state.x2, 0x9e415c204d7b15e7);
        assert_eq!(state.x3, 0xce0d71450fe44581);
        assert_eq!(state.x4, 0xdd7c5fef57befe48);
    }

    #[test]
    fn state_permute_128a() {
        let mut state = State::<Parameters128a>::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute();
        assert_eq!(state.x0, 0x67ed228272f46eee);
        assert_eq!(state.x1, 0x80bc0b097aad7944);
        assert_eq!(state.x2, 0x2fa599382c6db215);
        assert_eq!(state.x3, 0x368133fae2f7667a);
        assert_eq!(state.x4, 0x28cefb195a7c651c);
    }
}
