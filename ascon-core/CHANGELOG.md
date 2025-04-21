# Changelog

All notable changes to this project will be documented in this file.

## 0.5.1 (2025-05-21)

* Re-add permutation with 1 and 6 rounds with feature flags (`permutate_1` and `permute_6`)
* Select `no_unroll` implementation with `cfg` flag
* Fix crate metadata

## 0.5.0 (2025-04-17)

* Bump MSRV to 1.85 and edition to 2024
* Remove unused permutations and padding functions

## 0.4.1 (2025-04-17)

* Rename back to `ascon-core`
* Bump MSRV to 1.60 and edition to 2021

## 0.4.0 (2023-07-27)
### Added
- `zeroize` feature ([#57])

### Removed
- Implementation of `Copy` trait for `State` ([#57])

[#57]: https://github.com/RustCrypto/sponges/pull/57

## 0.3.1 (2023-03-19)
### Changed
- Drop MSRV to 1.56 ([#51])

[#51]: https://github.com/RustCrypto/sponges/pull/51

## 0.3.0 (2023-03-17)
### Added
- `State` type and permutation from `ascon-core` crate ([#49])
- `no_unroll` feature

### Removed
- AEAD API and `aead` dependency
  The implementation of the AEAD API is provided by `ascon-aead`.
- `Ascon`, `Key`, `Nonce` types
- `alloc`, `std`, and `aead` features

[#49]: https://github.com/RustCrypto/sponges/pull/49

## 0.2.0 (2023-02-25)
### Added
-  `no_std` support ([#36])
- `Ascon` permutation type ([#39])
- `Key` type alias ([#42])
- `Nonce` type alias ([#43])

### Changed
- 2021 edition ([#40])
- Use `aead` crate for AEAD API ([#44])
- MSRV 1.60 ([#44])

### Removed
- `byteorder` dependency ([#37])

[#36]: https://github.com/RustCrypto/sponges/pull/36
[#37]: https://github.com/RustCrypto/sponges/pull/37
[#39]: https://github.com/RustCrypto/sponges/pull/39
[#40]: https://github.com/RustCrypto/sponges/pull/40
[#42]: https://github.com/RustCrypto/sponges/pull/42
[#43]: https://github.com/RustCrypto/sponges/pull/43
[#44]: https://github.com/RustCrypto/sponges/pull/44

## 0.1.4 (2023-03-21)

* Add more deprecation notes.
* Remove benchmarks

## 0.1.3 (2023-03-17)

* Deprecate this crate in favor of `ascon`.

## 0.1.2 (2022-06-26)

* Implement `Default` for `State`.
* Add `no_unroll` feature to reduce binary size if needed.

## 0.1.1 (2022-06-11)

* Add permutation with user-specified number of rounds (up to 12).
* Add permutation with 1 round.
* Add benchmarks

## 0.1 (2022-06-03)

* Split permutation off of `ascon-aead`.
