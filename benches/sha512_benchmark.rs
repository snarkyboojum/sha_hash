use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use sha_hash::sha512_hash;

fn sha512_throughput(c: &mut Criterion) {
    let message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let correct_hash: [u64; 8] = [
        0x204a8fc6dda82f0a,
        0x0ced7beb8e08a416,
        0x57c16ef468b228a8,
        0x279be331a703c335,
        0x96fd15c13b1b07f9,
        0xaa1d3bea57789ca0,
        0x31ad85c7a71dd703,
        0x54ec631238ca3445,
    ];

    let mut group = c.benchmark_group("sha512_throughput");
    group.throughput(Throughput::Bytes(message.len() as u64));
    group.bench_function("sha512 data", |b| {
        b.iter(|| {
            let _hashes: [u64; 8] = sha512_hash(message.as_bytes()).unwrap();
        })
    });
    group.finish();
}

criterion_group!(benches, sha512_throughput);
criterion_main!(benches);
