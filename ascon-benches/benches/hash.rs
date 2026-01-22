// Copyright 2022-2026 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::hint::black_box;

use ascon_hash::{AsconHash256, Digest};
use criterion::{Bencher, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::RngCore;

const KB: usize = 1024;

fn bench_for_size<H: Digest + Default>(b: &mut Bencher, rng: &mut dyn RngCore, size: usize) {
    let mut plaintext = vec![0u8; size];
    rng.fill_bytes(plaintext.as_mut_slice());

    b.iter(|| {
        let mut hasher = H::default();
        hasher.update(&plaintext);
        black_box(hasher.finalize())
    });
}

fn criterion_benchmark<A: Digest + Default>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let mut group = c.benchmark_group(name);
    for size in [KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].into_iter() {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            bench_for_size::<A>(b, &mut rng, size)
        });
    }
    group.finish();
}

fn criterion_bench_ascon(c: &mut Criterion) {
    criterion_benchmark::<AsconHash256>(c, "AsconHash256");
}

criterion_group!(bench_ascon, criterion_bench_ascon,);
criterion_main!(bench_ascon);
