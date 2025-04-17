# Changelog

All notable changes to this project will be documented in this file.

## 0.3.0 (2025-04-17)

* Bump MSRV to 1.85 and edition to 2024
* Bump `ascon-core` to 0.5
* Update for compliance with NIST [draft]
  - Rename `AsconHash` to `AsconHash256`
  - Rename `AsconXof` to `AsconXof128`
  - Remove `AsconAHash` and `AsconAXof`

[draft]: https://doi.org/10.6028/NIST.SP.800-232.ipd

## 0.2.1 (2025-04-17)

* Bump MSRV to 1.60 and edition to 2021
* Switch to `ascon-core`
* Add `zeroize` feature

## 0.2.0 (2023-03-21)
### Changed
- Drop MSRV back to 1.56 and keep it in sync with `ascon` ([#459])
- Relicense as Apache-2.0 or MIT ([#459])
- Renamed public types to follow UpperCamelCase naming convention ([#459])
  - `AsconXOF` -> `AsconXof`
  - `AsconXOFReader` -> `AsconXofReader`
  - `AsconAXOF` -> `AsconAXof`
  - `ASconAXOFReader`-> `AsconAXofReader`

[#459]: https://github.com/RustCrypto/hashes/pull/459

## 0.1.1 (2023-03-17)

* Use `aead` instead of `aead-core`.
* Bump MSRV to 1.60.
* Add benchmarks.

## 0.1 (2022-06-03)

* Initial release.
