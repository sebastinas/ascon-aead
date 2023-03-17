# Ascon permutation

Pure Rust implementation of the permutation used in the lightweight Authenticated Encryption and Associated Data (AEAD) Ascon-128, Ascon-128a, and Ascon-80pq and the hashes AsconHash-128 and AsconHash-128a. For more information visit the [Ascon website](https://ascon.iaik.tugraz.at).

## Deprecation warning

This crate is deprecated. Use the [`ascon`](https://crates.io/crates/ascon) crate instead.

## Features

This crate supports the following features:

* `no_unroll`: do not unroll loops to reduce binary size

## Security Notes

This crate has received no security audit. Use at your own risk.

## License

This crate is licensed under the MIT license.
