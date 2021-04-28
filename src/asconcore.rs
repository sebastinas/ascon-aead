use aead::{generic_array::GenericArray, Error};
use cipher::consts::U16;
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

#[cfg(test)]
mod tests {
    use super::{clear, pad};

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

        let mut state = State {
            x0: P::IV,
            x1: key_1,
            x2: key_2,
            x3: u64::from_be_bytes(nonce[..8].try_into().unwrap()),
            x4: u64::from_be_bytes(nonce[8..].try_into().unwrap()),
            parameters: PhantomData,
        };

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

    /*
    fn process_encrypt(&mut self, ciphertext: &mut [u8], message: &[u8]) {
        let mut len = message.len();
        let mut rdr = Cursor::new(message);
        let mut wrr = Cursor::new(ciphertext);
        while len >= P::COUNT {
            // process full block of message
            self.state.x0 ^= rdr.read_u64::<BigEndian>().unwrap();
            wrr.write_u64::<BigEndian>(self.state.x0).unwrap();
            if P::COUNT == 16 {
                self.state.x1 ^= rdr.read_u64::<BigEndian>().unwrap();
                wrr.write_u64::<BigEndian>(self.state.x1).unwrap();
            }
            self.state.permute();
            len -= P::COUNT;
        }

        // process partial block if it exists
        let px = if P::COUNT == 16 && len >= 8 {
            self.state.x0 ^= rdr.read_u64::<BigEndian>().unwrap();
            wrr.write_u64::<BigEndian>(self.state.x0).unwrap();
            len -= 8;
            &mut self.state.x1
        } else {
            &mut self.state.x0
        };
        *px ^= pad(len);
        if len > 0 {
            *px ^= rdr.read_uint::<BigEndian>(len).unwrap() << ((8 - len) * 8);
            wrr.write_uint::<BigEndian>(self.state.x0 >> ((8 - len) * 8), len)
                .unwrap();
        }
    }
    */

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

    /*
    fn process_decrypt(&mut self, message: &mut [u8], ciphertext: &[u8]) {
        let mut len = ciphertext.len();
        let mut rdr = Cursor::new(ciphertext);
        let mut wrr = Cursor::new(message);
        while len >= P::COUNT {
            // process full block of ciphertext
            let cx = rdr.read_u64::<BigEndian>().unwrap();
            wrr.write_u64::<BigEndian>(self.state.x0 ^ cx).unwrap();
            self.state.x0 = cx;
            if P::COUNT == 16 {
                let cx = rdr.read_u64::<BigEndian>().unwrap();
                wrr.write_u64::<BigEndian>(self.state.x1 ^ cx).unwrap();
                self.state.x1 = cx;
            }
            self.state.permute();
            len -= P::COUNT;
        }

        // process partial block if it exists
        let px = if P::COUNT == 16 && len >= 8 {
            let cx = rdr.read_u64::<BigEndian>().unwrap();
            wrr.write_u64::<BigEndian>(self.state.x0 ^ cx).unwrap();
            self.state.x0 = cx;
            len -= 8;
            &mut self.state.x1
        } else {
            &mut self.state.x0
        };
        *px ^= pad(len);
        if len > 0 {
            let cx = rdr.read_uint::<BigEndian>(len).unwrap() << ((8 - len) * 8);
            *px ^= cx;
            wrr.write_uint::<BigEndian>(*px >> ((8 - len) * 8), len)
                .unwrap();
            *px = clear(*px, len) ^ cx;
        }
    }
    */

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

    fn process_final(&mut self) {
        if P::COUNT == 8 {
            self.state.x1 ^= self.key[0];
            self.state.x2 ^= self.key[1];
        } else if P::COUNT == 16 {
            self.state.x2 ^= self.key[0];
            self.state.x3 ^= self.key[1];
        }
        self.state.permute_12_and_apply(self.key[0], self.key[1]);
    }

    /*
    pub fn encrypt(
        &mut self,
        ciphertext: &mut [u8],
        message: &[u8],
        associated_data: &[u8],
    ) -> Tag {
        self.process_associated_data(associated_data);
        self.process_encrypt(ciphertext, message);
        self.process_final();

        let mut tag: [u8; 16] = Default::default();
        let mut wrr = Cursor::new(&mut tag as &mut [u8]); // why?!
        wrr.write_u64::<BigEndian>(self.state.x3).unwrap();
        wrr.write_u64::<BigEndian>(self.state.x4).unwrap();
        Tag::from(tag)
    }
    */

    pub fn encrypt_inplace(&mut self, message: &mut [u8], associated_data: &[u8]) -> Tag {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        self.process_final();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state.x3));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state.x4));
        Tag::from(tag)
    }

    /*
    pub fn decrypt(
        &mut self,
        message: &mut [u8],
        ciphertext: &[u8],
        associated_data: &[u8],
        expected_tag: &Tag,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt(message, ciphertext);
        self.process_final();

        let mut tag: [u8; 16] = Default::default();
        let mut wrr = Cursor::new(&mut tag as &mut [u8]); // why?!
        wrr.write_u64::<BigEndian>(self.state.x3).unwrap();
        wrr.write_u64::<BigEndian>(self.state.x4).unwrap();

        if Tag::from(tag).ct_eq(expected_tag).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(Error)
        }
    }
    */

    pub fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &Tag,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt_inplace(ciphertext);
        self.process_final();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state.x3));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state.x4));

        if Tag::from(tag).ct_eq(expected_tag).unwrap_u8() == 1 {
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
