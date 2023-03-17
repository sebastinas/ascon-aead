// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: MIT

//! # Ascon permutation
//!
//! This crate provides an implementation of the Ascon permutation optimized for 64
//! bit systems. Unless you specfically need this crate, you are most likely
//! looking for the `ascon-aead` crate.

#![no_std]

pub use ascon::*;

/// Clear bytes from a 64 bit word.
#[inline(always)]
pub const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}
