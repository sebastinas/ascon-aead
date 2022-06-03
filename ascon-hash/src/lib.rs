// Copyright 2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

//! # Hashing with [Ascon](https://ascon.iaik.tugraz.at/index.html)
//!
//! This crate provides implementations of the cryptographic hashes, AsconHash
//! and AsconAHash, which are both based on the Ascon permutation.
//!
//! ## Security Notes
//!
//! This crate has received no security audit. Use at your own risk.
//!
//! ## Usage
//!
//! ```
//! use ascon_hash::{AsconHash, Digest}; // Or `AsconAHash
//!
//! let mut hasher = AsconHash::new();
//! hasher.update(b"some bytes");
//! let digest = hasher.finalize();
//! assert_eq!(&digest[..], b"\xb7\x42\xca\x75\xe5\x70\x38\x75\x70\x59\xcc\xcc\x68\x74\x71\x4f\x9d\xbd\x7f\xc5\x92\x4a\x7d\xf4\xe3\x16\x59\x4f\xd1\x42\x6c\xa8");
//! ```

#![no_std]
#![warn(missing_docs)]

use core::marker::PhantomData;

use ascon_core::{pad, State};
pub use digest::{self, Digest};
use digest::{
    block_buffer::Eager,
    consts::{U32, U8},
    core_api::{
        AlgorithmName, Block, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
    crypto_common::BlockSizeUser,
    HashMarker, Output, OutputSizeUser, Reset,
};

/// Parameters for Ascon hash instances.
trait HashParameters {
    /// Number of rounds for the permutation.
    const ROUNDS: usize;
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

/// Parameters for AsconA hash.
#[derive(Clone, Debug)]
struct Parameters;

impl HashParameters for Parameters {
    const ROUNDS: usize = 12;
    const IV0: u64 = 0xee9398aadb67f03d;
    const IV1: u64 = 0x8bb21831c60f1002;
    const IV2: u64 = 0xb48a92db98d5da62;
    const IV3: u64 = 0x43189921b8f8e3e8;
    const IV4: u64 = 0x348fa5c9d525e140;
}

/// Parameters for AsconA hash.
#[derive(Clone, Debug)]
struct ParametersA;

impl HashParameters for ParametersA {
    const ROUNDS: usize = 8;
    const IV0: u64 = 0x01470194fc6528a6;
    const IV1: u64 = 0x738ec38ac0adffa7;
    const IV2: u64 = 0x2ec8e3296c76384c;
    const IV3: u64 = 0xd6f6a54d7f52377d;
    const IV4: u64 = 0xa13c42a223be8d87;
}

#[derive(Clone, Debug)]
struct HashCore<P: HashParameters> {
    state: State,
    phantom: PhantomData<P>,
}

impl<P: HashParameters> HashCore<P> {
    fn absorb_block(&mut self, block: &[u8; 8]) {
        self.state[0] ^= u64::from_be_bytes(*block);
        self.permute_state();
    }

    fn absorb_last_block(&mut self, block: &[u8]) {
        debug_assert!(block.len() < 8);

        let len = block.len();
        if len > 0 {
            let mut tmp = [0u8; 8];
            tmp[0..len].copy_from_slice(block);
            self.state[0] ^= u64::from_be_bytes(tmp);
        }
        self.state[0] ^= pad(len);
        self.state.permute_12();
    }

    fn squeeze(&mut self, mut block: &mut [u8]) {
        debug_assert_eq!(block.len() % 8, 0);

        while block.len() > 8 {
            block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            self.permute_state();
            block = &mut block[8..];
        }
        block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
    }

    #[inline(always)]
    fn permute_state(&mut self) {
        if P::ROUNDS == 12 {
            self.state.permute_12();
        } else if P::ROUNDS == 8 {
            self.state.permute_8();
        } else if P::ROUNDS == 6 {
            self.state.permute_6();
        }
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
        f.write_str("AsconHash")
    }
}

/// Ascon hash implementation
#[derive(Clone, Debug, Default)]
pub struct AsconACore {
    state: HashCore<ParametersA>,
}

impl HashMarker for AsconACore {}

impl BlockSizeUser for AsconACore {
    type BlockSize = U8;
}

impl BufferKindUser for AsconACore {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconACore {
    type OutputSize = U32;
}

impl UpdateCore for AsconACore {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block.as_ref());
        }
    }
}

impl FixedOutputCore for AsconACore {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        self.state.squeeze(out);
    }
}

impl Reset for AsconACore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for AsconACore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AsconAHash")
    }
}

/// Ascon hash
pub type AsconHash = CoreWrapper<AsconCore>;
/// AsconA hash
pub type AsconAHash = CoreWrapper<AsconACore>;
