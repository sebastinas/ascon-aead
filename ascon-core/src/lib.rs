// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

//! # DEPRECATED: Ascon permutation
//!
//! Use the `ascon` crate instead.

#![no_std]

pub use ascon::*;

/// Clear bytes from a 64 bit word.
#[inline(always)]
pub const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}
