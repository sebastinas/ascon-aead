// Copyright 2022-2025 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

//! ## Usage (Hashing)
//!
//! ```
//! use ascon_hash::{AsconHash256, Digest};
//!
//! let mut hasher = AsconHash256::new();
//! hasher.update(b"some bytes");
//! let digest = hasher.finalize();
//! assert_eq!(&digest[..], b"\xe9\x09\xc2\xf6\xda\x9c\xb3\x02\x84\x23\x26\x5c\x8f\x23\xfc\x2d\x26\xbf\xc0\xf3\xdb\x70\x46\x83\xef\x16\xb7\x87\xa9\x45\xed\x68");
//! ```
//!
//! ## Usage (XOF)
//!
//! ```
//! use ascon_hash::{AsconXof128, ExtendableOutput, Update, XofReader};
//!
//! let mut xof = AsconXof128::default();
//! xof.update(b"some bytes");
//! let mut reader = xof.finalize_xof();
//! let mut dst = [0u8; 5];
//! reader.read(&mut dst);
//! assert_eq!(&dst, b"\x8c\x7d\xd1\x14\xa0");
//! ```

use core::marker::PhantomData;

use ascon_core::State;
pub use digest::{self, Digest, ExtendableOutput, Reset, Update, XofReader};
use digest::{
    HashMarker, Output, OutputSizeUser,
    block_buffer::Eager,
    consts::{U8, U32},
    core_api::{
        AlgorithmName, Block, Buffer, BufferKindUser, CoreWrapper, ExtendableOutputCore,
        FixedOutputCore, UpdateCore, XofReaderCore, XofReaderCoreWrapper,
    },
    crypto_common::BlockSizeUser,
};

/// Produce mask for padding.
#[inline(always)]
const fn pad(n: usize) -> u64 {
    0x01_u64 << (8 * n)
}

/// Parameters for Ascon hash instances.
///
/// These parameters represent the permutation applied to the zero-extended IV.
trait HashParameters {
    /// Part of the IV.
    const IV0: u64;
    /// Part of the IV.
    const IV1: u64;
    /// Part of the IV.
    const IV2: u64;
    /// Part of the IV.
    const IV3: u64;
    /// Part of the IV.
    const IV4: u64;
}

/// Parameters for Ascon-Hash256.
#[derive(Clone, Debug)]
struct Parameters;

impl HashParameters for Parameters {
    const IV0: u64 = 0x9b1e5494e934d681;
    const IV1: u64 = 0x4bc3a01e333751d2;
    const IV2: u64 = 0xae65396c6b34b81a;
    const IV3: u64 = 0x3c7fd4a4d56a4db3;
    const IV4: u64 = 0x1a5c464906c5976d;
}

/// Parameters for Ascon-XOF128
#[derive(Clone, Debug)]
struct ParametersXof;

impl HashParameters for ParametersXof {
    const IV0: u64 = 0xda82ce768d9447eb;
    const IV1: u64 = 0xcc7ce6c75f1ef969;
    const IV2: u64 = 0xe7508fd780085631;
    const IV3: u64 = 0x0ee0ea53416b58cc;
    const IV4: u64 = 0xe0547524db6f0bde;
}

#[derive(Clone, Debug)]
struct HashCore<P: HashParameters> {
    state: State,
    phantom: PhantomData<P>,
}

impl<P: HashParameters> HashCore<P> {
    fn absorb_block(&mut self, block: &[u8; 8]) {
        self.state[0] ^= u64::from_le_bytes(*block);
        self.permute_state();
    }

    fn absorb_last_block(&mut self, block: &[u8]) {
        debug_assert!(block.len() < 8);

        let len = block.len();
        if len > 0 {
            let mut tmp = [0u8; 8];
            tmp[0..len].copy_from_slice(block);
            self.state[0] ^= u64::from_le_bytes(tmp);
        }
        self.state[0] ^= pad(len);
        self.state.permute_12();
    }

    // for fixed-sized output
    fn squeeze(&mut self, mut block: &mut [u8]) {
        debug_assert_eq!(block.len() % 8, 0);

        while block.len() > 8 {
            block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0]));
            self.permute_state();
            block = &mut block[8..];
        }
        block[..8].copy_from_slice(&u64::to_le_bytes(self.state[0]));
    }

    // for XOF output
    fn squeeze_block(&mut self) -> [u8; 8] {
        let ret = u64::to_le_bytes(self.state[0]);
        self.permute_state();
        ret
    }

    #[inline(always)]
    fn permute_state(&mut self) {
        self.state.permute_12();
    }
}

impl<P: HashParameters> Default for HashCore<P> {
    fn default() -> Self {
        Self {
            state: State::new(P::IV0, P::IV1, P::IV2, P::IV3, P::IV4),
            phantom: PhantomData,
        }
    }
}

/// Ascon hash implementation
#[derive(Clone, Debug, Default)]
pub struct AsconCore {
    state: HashCore<Parameters>,
}

impl HashMarker for AsconCore {}

impl BlockSizeUser for AsconCore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconCore {
    type OutputSize = U32;
}

impl UpdateCore for AsconCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

impl FixedOutputCore for AsconCore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        self.state.squeeze(out);
    }
}

impl Reset for AsconCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-Hash256")
    }
}

/// Ascon XOF
#[derive(Clone, Debug, Default)]
pub struct AsconXofCore {
    state: HashCore<ParametersXof>,
}

impl HashMarker for AsconXofCore {}

impl BlockSizeUser for AsconXofCore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconXofCore {
    type BufferKind = Eager;
}

impl UpdateCore for AsconXofCore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

/// Reader for XOF output
#[derive(Clone, Debug)]
pub struct AsconXofReaderCore {
    hasher: HashCore<ParametersXof>,
}

impl BlockSizeUser for AsconXofReaderCore {
    type BlockSize = U8;
}

impl XofReaderCore for AsconXofReaderCore {
    fn read_block(&mut self) -> Block<Self> {
        self.hasher.squeeze_block().into()
    }
}

impl ExtendableOutputCore for AsconXofCore {
    type ReaderCore = AsconXofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        Self::ReaderCore {
            hasher: self.state.clone(),
        }
    }
}

impl Reset for AsconXofCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconXofCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconXOF")
    }
}

/// Ascon-Hash256
///
/// ```
/// use ascon_hash::{AsconHash256, Digest};
///
/// let mut hasher = AsconHash256::new();
/// hasher.update(b"some bytes");
/// let digest = hasher.finalize();
/// assert_eq!(&digest[..], b"\xe9\x09\xc2\xf6\xda\x9c\xb3\x02\x84\x23\x26\x5c\x8f\x23\xfc\x2d\x26\xbf\xc0\xf3\xdb\x70\x46\x83\xef\x16\xb7\x87\xa9\x45\xed\x68");
/// ```
pub type AsconHash256 = CoreWrapper<AsconCore>;
/// Ascon-XOF128
///
/// ```
/// use ascon_hash::{AsconXof128, ExtendableOutput, Update, XofReader};
///
/// let mut xof = AsconXof128::default();
/// xof.update(b"some bytes");
/// let mut reader = xof.finalize_xof();
/// let mut dst = [0u8; 5];
/// reader.read(&mut dst);
/// assert_eq!(&dst, b"\x8c\x7d\xd1\x14\xa0");
/// ```
pub type AsconXof128 = CoreWrapper<AsconXofCore>;
/// Reader for AsconXOF output
pub type AsconXof128Reader = XofReaderCoreWrapper<AsconXofReaderCore>;
