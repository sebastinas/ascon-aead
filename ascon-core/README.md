# Ascon permutation

Pure Rust implementation of the permutation of [Ascon], a family of
authenticated encryption and hashing algorithms designed to be lightweight and
easy to implement.

## About

Ascon is a family of lightweight algorithms built on a core permutation
algorithm. These algorithms include:

- [x] [`ascon-aead`]: Authenticated Encryption with Associated Data
- [x] [`ascon-hash`]: Hash functions and extendible-output functions (XOF)
- [ ] Pseudo-random functions (PRF) and message authentication codes (MAC)

Ascon has been selected as [new standard for lightweight cryptography] in the
[NIST Lightweight Cryptography] competition, and has also been selected as the
primary choice for lightweight authenticated encryption in the final
portfolio of the [CAESAR competition].

## Configuration options

Per default, the permutation is unrolled. If this is not desired, e.g., due to
space constraints, build with `--cfg ascon_impl=no_unroll` switch to a more
compact implementation. The performance/size impact needs to be measured per
target platform, though.

## Minimum Supported Rust Version

This crate requires **Rust 1.85** at a minimum.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (links)

[`ascon-aead`]: https://crates.io/crate/ascon-aead
[`ascon-hash`]: https://crates.io/crate/ascon-hash
[Ascon]: https://ascon.iaik.tugraz.at/
[New standard for lightweight cryptography]: https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices
[NIST Lightweight Cryptography]: https://csrc.nist.gov/projects/lightweight-cryptography/finalists
[CAESAR competition]: https://competitions.cr.yp.to/caesar-submissions.html
