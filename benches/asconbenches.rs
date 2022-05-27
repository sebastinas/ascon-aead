use ascon_aead::{
    aead::{generic_array::typenum::Unsigned, Aead, AeadInPlace, NewAead},
    Ascon, Key, Nonce, Parameters, Parameters128, Parameters128a, Parameters80pq,
};
use criterion::{
    black_box, criterion_group, criterion_main, Bencher, BenchmarkId, Criterion, Throughput,
};

const KB: usize = 1024;

fn bench_for_size<P: Parameters>(b: &mut Bencher, size: usize) {
    let cipher = Ascon::<P>::new(Key::<Ascon<P>>::from_slice(
        &b"very secret key.0123"[..P::KeySize::USIZE],
    ));
    let nonce = Nonce::from_slice(b"unique nonce 012");
    let plaintext = vec![0u8; size];

    b.iter(|| black_box(cipher.encrypt(nonce, plaintext.as_slice()).unwrap()));
}

fn bench_for_size_inplace<P: Parameters>(b: &mut Bencher, size: usize) {
    let cipher = Ascon::<P>::new(Key::<Ascon<P>>::from_slice(
        &b"very secret key.0123"[..P::KeySize::USIZE],
    ));
    let nonce = Nonce::from_slice(b"unique nonce 012");
    let mut buffer = vec![0u8; size + 16];

    b.iter(|| black_box(cipher.encrypt_in_place(nonce, b"", &mut buffer).unwrap()));
}

fn criterion_benchmark<P: Parameters>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for size in [1 * KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size::<P>(b, size)
        });
    }
    group.finish();
}

fn criterion_benchmark_inplace<P: Parameters>(c: &mut Criterion, name: &str) {
    let mut group = c.benchmark_group(name);
    for size in [1 * KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size_inplace::<P>(b, size)
        });
    }
    group.finish();
}

fn criterion_bench_ascon128(c: &mut Criterion) {
    criterion_benchmark::<Parameters128>(c, "Ascon-128");
}

fn criterion_bench_ascon128a(c: &mut Criterion) {
    criterion_benchmark::<Parameters128a>(c, "Ascon-128a");
}

fn criterion_bench_ascon80pq(c: &mut Criterion) {
    criterion_benchmark::<Parameters80pq>(c, "Ascon-80pq");
}

fn criterion_bench_ascon128_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Parameters128>(c, "Ascon-128 (inplace)");
}

fn criterion_bench_ascon128a_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Parameters128a>(c, "Ascon-128a (inplace)");
}

fn criterion_bench_ascon80pq_inplace(c: &mut Criterion) {
    criterion_benchmark_inplace::<Parameters80pq>(c, "Ascon-80pq (inplace)");
}

criterion_group!(
    bench_ascon128,
    criterion_bench_ascon128,
    criterion_bench_ascon128_inplace,
);
criterion_group!(
    bench_ascon128a,
    criterion_bench_ascon128a,
    criterion_bench_ascon128a_inplace
);
criterion_group!(
    bench_ascon80pq,
    criterion_bench_ascon80pq,
    criterion_bench_ascon80pq_inplace
);
criterion_main!(bench_ascon128, bench_ascon128a, bench_ascon80pq);
