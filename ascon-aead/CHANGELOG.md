# Changelog

## 0.2 (2022-05-28)

* Implement support for Ascon-80pq
  * Change interface to closer resamble `aead`
  * `Key`, `Tag` and `Nonce` are now re-exported from `aead`
* Reduce the number of re-exports
* Bump `zeroize` dependency to 1.5

## 0.1.4 (2022-03-14)

* Bump edition to 2021 and MSRV to 1.56
* Remove dependency on `cipher`

## 0.1.3 (2021-10-22)

* Declare MSRV as 1.51
* Avoid `>=` dependencies

## 0.1.2 (2021-10-19)

* Bump `aead` dependency to 0.4
* Bump `cipher` dependency to 0.3

## 0.1.1 (2021-10-19)

* Add benchmarks
* Minor code improvements

## 0.1 (2021-04-28)

* Initial release
