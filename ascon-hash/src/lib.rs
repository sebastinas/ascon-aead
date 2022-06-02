//! # Ascon hash

#![no_std]
#![warn(missing_docs)]

use core::marker::PhantomData;

use ascon_core::{pad, State};
pub use digest;
use digest::{
    block_buffer::Eager,
    consts::{U32, U8},
    core_api::{AlgorithmName, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore},
    crypto_common::BlockSizeUser,
    HashMarker, OutputSizeUser, Reset,
};

/// Parameters for Ascon hash instances.
///
/// This trait is for internal use only, but needs to be exposed.
// TODO: Hide this informaton from the public interface
pub trait HashParameters {
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
    /// Name of the hash.
    const NAME: &'static str;
}

/// Parameters for AsconA hash.
///
/// This struct is for internal use only, but needs to be exposed.
#[derive(Clone)]
pub struct Parameters;

impl HashParameters for Parameters {
    const ROUNDS: usize = 12;
    const IV0: u64 = 0xee9398aadb67f03d;
    const IV1: u64 = 0x8bb21831c60f1002;
    const IV2: u64 = 0xb48a92db98d5da62;
    const IV3: u64 = 0x43189921b8f8e3e8;
    const IV4: u64 = 0x348fa5c9d525e140;
    const NAME: &'static str = "AsconHash";
}

/// Parameters for AsconA hash.
///
/// This struct is for internal use only, but needs to be exposed.
#[derive(Clone)]
pub struct ParametersA;

impl HashParameters for ParametersA {
    const ROUNDS: usize = 8;
    const IV0: u64 = 0x01470194fc6528a6;
    const IV1: u64 = 0x738ec38ac0adffa7;
    const IV2: u64 = 0x2ec8e3296c76384c;
    const IV3: u64 = 0xd6f6a54d7f52377d;
    const IV4: u64 = 0xa13c42a223be8d87;
    const NAME: &'static str = "AsconAHash";
}

#[derive(Clone)]
struct HashCore<P: HashParameters> {
    state: State,
    phantom: PhantomData<P>,
}

impl<P: HashParameters> HashCore<P> {
    fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len() % 8, 0);

        for b in block.chunks_exact(8) {
            self.state[0] ^= u64::from_be_bytes(b.try_into().unwrap());
            self.permute_state();
        }
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
#[derive(Clone)]
pub struct Hasher<P>
where
    P: HashParameters,
{
    state: HashCore<P>,
}

impl<P> Default for Hasher<P>
where
    P: HashParameters,
{
    fn default() -> Self {
        Self {
            state: HashCore::default(),
        }
    }
}

impl<P> HashMarker for Hasher<P> where P: HashParameters {}

impl<P> BlockSizeUser for Hasher<P>
where
    P: HashParameters,
{
    type BlockSize = U8;
}

impl<P> BufferKindUser for Hasher<P>
where
    P: HashParameters,
{
    type BufferKind = Eager;
}

impl<P> OutputSizeUser for Hasher<P>
where
    P: HashParameters,
{
    type OutputSize = U32;
}

impl<P> UpdateCore for Hasher<P>
where
    P: HashParameters,
{
    fn update_blocks(&mut self, blocks: &[digest::core_api::Block<Self>]) {
        for block in blocks {
            self.state.absorb_block(block);
        }
    }
}

impl<P> FixedOutputCore for Hasher<P>
where
    P: HashParameters,
{
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut digest::core_api::Buffer<Self>,
        out: &mut digest::Output<Self>,
    ) {
        debug_assert!(buffer.get_pos() < 8);
        self.state
            .absorb_last_block(&buffer.get_data()[..buffer.get_pos()]);
        self.state.squeeze(out);
    }
}

impl<P> Reset for Hasher<P>
where
    P: HashParameters,
{
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<P> AlgorithmName for Hasher<P>
where
    P: HashParameters,
{
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::NAME)
    }
}

/// Ascon hash
pub type AsconHash = CoreWrapper<Hasher<Parameters>>;
/// AsconA hash
pub type AsconAHash = CoreWrapper<Hasher<ParametersA>>;
