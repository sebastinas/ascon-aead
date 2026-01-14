// Copyright 2022-2026 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::hint::black_box;

use ascon_aead::{
    AsconAead128,
    aead::{Aead, AeadInOut, KeyInit, array::typenum::Unsigned},
};
use criterion::{Bencher, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng, rngs::StdRng};

const KB: usize = 1024;

fn bench_for_size<A: KeyInit + Aead>(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut plaintext = vec![0u8; size];
    rng.fill_bytes(plaintext.as_mut_slice());

    let cipher = A::new(key.as_slice().try_into().unwrap());
    let nonce = key.as_slice().try_into().unwrap();

    b.iter(|| black_box(cipher.encrypt(nonce, plaintext.as_slice())));
}

fn bench_for_size_inplace<A: KeyInit + AeadInOut>(
    b: &mut Bencher,
    rng: &mut dyn RngCore,
    size: usize,
) {
    let mut key = vec![0u8; A::KeySize::USIZE];
    rng.fill_bytes(key.as_mut_slice());
    let mut nonce = vec![0u8; A::NonceSize::USIZE];
    rng.fill_bytes(nonce.as_mut_slice());
    let mut buffer = vec![0u8; size + 16];
    rng.fill_bytes(buffer.as_mut_slice());

    let cipher = A::new(key.as_slice().try_into().unwrap());
    let nonce = key.as_slice().try_into().unwrap();

    b.iter(|| black_box(cipher.encrypt_in_place(nonce, b"", &mut buffer)));
}

fn criterion_benchmark<A: KeyInit + Aead>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_benchmark_inplace<A: KeyInit + AeadInOut>(c: &mut Criterion, name: &str) {
    let mut rng = StdRng::from_entropy();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size_inplace::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_bench_ascon128(c: &mut Criterion) {
    criterion_benchmark::<AsconAead128>(c, "AsconAead128");
}

fn criterion_bench_ascon128_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<AsconAead128>(c, "AsconAead128 (inplace)");
}

criterion_group!(
    bench_ascon128,
    criterion_bench_ascon128,
    criterion_bench_ascon128_inplace,
);
criterion_main!(bench_ascon128);
