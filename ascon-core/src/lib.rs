// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

//! # Ascon permutation
//!
//! This crate provides an implementation of the Ascon permutation optimized for 64
//! bit systems. Unless you specfically need this crate, you are most likely
//! looking for the `ascon-aead` crate.

#![no_std]
#![warn(missing_docs)]

/// Produce mask for padding.
#[inline(always)]
pub const fn pad(n: usize) -> u64 {
    (0x80_u64) << (56 - 8 * n)
}

/// Clear bytes from a 64 bit word.
#[inline(always)]
pub const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}

/// The state of Ascon's permutation.
#[derive(Clone, Copy, Debug)]
pub struct State {
    x: [u64; 5],
}

impl State {
    /// Instantiate new state from the given values.
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x: [x0, x1, x2, x3, x4],
        }
    }

    /// Permute with a single round.
    fn round(&mut self, c: u64) {
        // S-box layer
        let x0 = self.x[0] ^ self.x[4];
        let x2 = self.x[2] ^ self.x[1] ^ c; // with round constant
        let x4 = self.x[4] ^ self.x[3];

        let tx0 = x0 ^ (!self.x[1] & x2);
        let tx1 = self.x[1] ^ (!x2 & self.x[3]);
        let tx2 = x2 ^ (!self.x[3] & x4);
        let tx3 = self.x[3] ^ (!x4 & x0);
        let tx4 = x4 ^ (!x0 & self.x[1]);
        let tx1 = tx1 ^ tx0;
        let tx3 = tx3 ^ tx2;
        let tx0 = tx0 ^ tx4;

        // linear layer
        let x0 = tx0 ^ tx0.rotate_right(9);
        let x1 = tx1 ^ tx1.rotate_right(22);
        let x2 = tx2 ^ tx2.rotate_right(5);
        let x3 = tx3 ^ tx3.rotate_right(7);
        let x4 = tx4 ^ tx4.rotate_right(34);
        self.x[0] = tx0 ^ x0.rotate_right(19);
        self.x[1] = tx1 ^ x1.rotate_right(39);
        self.x[2] = !(tx2 ^ x2.rotate_right(1));
        self.x[3] = tx3 ^ x3.rotate_right(10);
        self.x[4] = tx4 ^ x4.rotate_right(7);
    }

    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
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

    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.round(0xb4);
        self.round(0xa5);
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5a);
        self.round(0x4b);
    }

    /// Perform with 6 rounds.
    pub fn permute_6(&mut self) {
        self.round(0x96);
        self.round(0x87);
        self.round(0x78);
        self.round(0x69);
        self.round(0x5a);
        self.round(0x4b);
    }
}

impl core::ops::Index<usize> for State {
    type Output = u64;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.x[index]
    }
}

impl core::ops::IndexMut<usize> for State {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.x[index]
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
        assert_eq!(state[0], 0x206416dfc624bb14);
        assert_eq!(state[1], 0x1b0c47a601058aab);
        assert_eq!(state[2], 0x8934cfc93814cddd);
        assert_eq!(state[3], 0xa9738d287a748e4b);
        assert_eq!(state[4], 0xddd934f058afc7e1);
    }

    #[test]
    fn state_permute_6() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_6();
        assert_eq!(state[0], 0xc27b505c635eb07f);
        assert_eq!(state[1], 0xd388f5d2a72046fa);
        assert_eq!(state[2], 0x9e415c204d7b15e7);
        assert_eq!(state[3], 0xce0d71450fe44581);
        assert_eq!(state[4], 0xdd7c5fef57befe48);
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
}
