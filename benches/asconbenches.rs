use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput, BenchmarkId, Bencher};
use ascon_aead::{aead::{Aead, NewAead}, Ascon, Key, Nonce, Parameters, Parameters128, Parameters128a};

fn bench_for_size<P: Parameters>(b: &mut Bencher, size: usize) {
    let cipher = Ascon::<P>::new(Key::from_slice(b"very secret key."));
    let nonce = Nonce::from_slice(b"unique nonce 012");
    let plaintext = vec![0u8; size];

    b.iter(|| black_box(cipher.encrypt(nonce, plaintext.as_slice()).unwrap()));
}

fn criterion_benchmark<P: Parameters>(c: &mut Criterion, name: &str) {
    const KB: usize = 1024;

    let mut group = c.benchmark_group(name);
    for size in [1 * KB, 2 * KB, 4 * KB, 8 * KB, 16 * KB, 32 * KB, 64 * KB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            bench_for_size::<P>(b, size)
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

criterion_group!(benches, criterion_bench_ascon128, criterion_bench_ascon128a);
criterion_main!(benches);