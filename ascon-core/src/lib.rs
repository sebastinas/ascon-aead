// Copyright 2021-2025 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::{
    mem::size_of,
    ops::{Index, IndexMut},
};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compute round constant
#[inline(always)]
const fn round_constant(round: u64) -> u64 {
    ((0xfu64 - round) << 4) | round
}

#[cfg(not(ascon_impl = "no_unroll"))]
macro_rules! apply_permutation {
    ($state:expr, $rc:literal) => {
        round($state, $rc)
    };
    ($state:expr, $rc:literal, $($rcs:literal),+) => {
        apply_permutation!(round($state, $rc), $($rcs),+)
    };
}

#[cfg(ascon_impl = "no_unroll")]
macro_rules! apply_permutation {
    ($state:expr, $($rcs:literal),+) => {
        [$($rcs),+].into_iter().fold($state, round)
    };
}

/// The state of Ascon's permutation.
///
/// The permutation operates on a state of 320 bits represented as 5 64 bit words.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct State {
    x: [u64; 5],
}

/// Ascon's round function
const fn round(x: [u64; 5], c: u64) -> [u64; 5] {
    // S-box layer
    let x0 = x[0] ^ x[4];
    let x2 = x[2] ^ x[1] ^ c; // with round constant
    let x4 = x[4] ^ x[3];

    let tx0 = x0 ^ (!x[1] & x2);
    let tx1 = x[1] ^ (!x2 & x[3]);
    let tx2 = x2 ^ (!x[3] & x4);
    let tx3 = x[3] ^ (!x4 & x0);
    let tx4 = x4 ^ (!x0 & x[1]);
    let tx1 = tx1 ^ tx0;
    let tx3 = tx3 ^ tx2;
    let tx0 = tx0 ^ tx4;

    // linear layer
    let x0 = tx0 ^ tx0.rotate_right(9);
    let x1 = tx1 ^ tx1.rotate_right(22);
    let x2 = tx2 ^ tx2.rotate_right(5);
    let x3 = tx3 ^ tx3.rotate_right(7);
    let x4 = tx4 ^ tx4.rotate_right(34);
    [
        tx0 ^ x0.rotate_right(19),
        tx1 ^ x1.rotate_right(39),
        !(tx2 ^ x2.rotate_right(1)),
        tx3 ^ x3.rotate_right(10),
        tx4 ^ x4.rotate_right(7),
    ]
}

impl State {
    /// Instantiate new state from the given values.
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x: [x0, x1, x2, x3, x4],
        }
    }

    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        self.x = apply_permutation!(
            self.x, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        );
    }

    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = apply_permutation!(self.x, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b);
    }

    /// Perform a given number (up to 12) of permutations
    ///
    /// Panics (in debug mode) if `rounds` is larger than 12.
    pub fn permute_n(&mut self, rounds: usize) {
        debug_assert!(rounds <= 12);

        let start = 12 - rounds;
        self.x = (start..12).fold(self.x, |x, round_index| {
            round(x, round_constant(round_index as u64))
        });
    }

    /// Convert state to bytes.
    pub fn as_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; size_of::<u64>() * 5];
        for (dst, src) in bytes
            .chunks_exact_mut(size_of::<u64>())
            .zip(self.x.into_iter())
        {
            dst.copy_from_slice(&u64::to_be_bytes(src));
        }
        bytes
    }
}

impl Index<usize> for State {
    type Output = u64;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.x[index]
    }
}

impl IndexMut<usize> for State {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.x[index]
    }
}

impl TryFrom<&[u64]> for State {
    type Error = ();

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        match value.len() {
            5 => Ok(Self::new(value[0], value[1], value[2], value[3], value[4])),
            _ => Err(()),
        }
    }
}

impl From<&[u64; 5]> for State {
    fn from(value: &[u64; 5]) -> Self {
        Self { x: *value }
    }
}

impl TryFrom<&[u8]> for State {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<u64>() * 5 {
            return Err(());
        }

        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        Ok(state)
    }
}

impl From<&[u8; size_of::<u64>() * 5]> for State {
    fn from(value: &[u8; size_of::<u64>() * 5]) -> Self {
        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        state
    }
}

impl AsRef<[u64]> for State {
    fn as_ref(&self) -> &[u64] {
        &self.x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_constants() {
        assert_eq!(round_constant(0), 0xf0);
        assert_eq!(round_constant(1), 0xe1);
        assert_eq!(round_constant(2), 0xd2);
        assert_eq!(round_constant(3), 0xc3);
        assert_eq!(round_constant(4), 0xb4);
        assert_eq!(round_constant(5), 0xa5);
        assert_eq!(round_constant(6), 0x96);
        assert_eq!(round_constant(7), 0x87);
        assert_eq!(round_constant(8), 0x78);
        assert_eq!(round_constant(9), 0x69);
        assert_eq!(round_constant(10), 0x5a);
        assert_eq!(round_constant(11), 0x4b);
    }

    #[test]
    fn one_round() {
        let state = round(
            [
                0x0123456789abcdef,
                0x23456789abcdef01,
                0x456789abcdef0123,
                0x6789abcdef012345,
                0x89abcde01234567f,
            ],
            0x1f,
        );
        assert_eq!(
            state,
            [
                0x3c1748c9be2892ce,
                0x5eafb305cd26164f,
                0xf9470254bb3a4213,
                0xf0428daf0c5d3948,
                0x281375af0b294899
            ]
        );
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
        assert_eq!(state[0], 0x206416dfc624bb14);
        assert_eq!(state[1], 0x1b0c47a601058aab);
        assert_eq!(state[2], 0x8934cfc93814cddd);
        assert_eq!(state[3], 0xa9738d287a748e4b);
        assert_eq!(state[4], 0xddd934f058afc7e1);
    }

    #[test]
    fn state_permute_8() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_8();
        assert_eq!(state[0], 0x67ed228272f46eee);
        assert_eq!(state[1], 0x80bc0b097aad7944);
        assert_eq!(state[2], 0x2fa599382c6db215);
        assert_eq!(state[3], 0x368133fae2f7667a);
        assert_eq!(state[4], 0x28cefb195a7c651c);
    }

    #[test]
    fn state_permute_n() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let mut state2 = state.clone();

        state.permute_8();
        state2.permute_n(8);
        assert_eq!(state.x, state2.x);

        state.permute_12();
        state2.permute_n(12);
        assert_eq!(state.x, state2.x);
    }

    #[test]
    fn state_convert_bytes() {
        let state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let bytes = state.as_bytes();

        // test TryFrom<&[u8]>
        let state2 = State::try_from(&bytes[..]);
        assert_eq!(state2.expect("try_from bytes").x, state.x);

        let state2 = State::from(&bytes);
        assert_eq!(state2.x, state.x);
    }
}
