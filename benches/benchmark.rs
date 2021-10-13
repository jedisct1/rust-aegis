use aegis::aegis128l::Aegis128L;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn test_encrypt(m: &[u8]) {
    let ad = b"Comment numero un";
    let key = b"YELLOW SUBMARINE";
    let nonce = [0u8; 16];

    let (c, tag) = Aegis128L::new(&nonce, key).encrypt(m, ad);
    black_box(c);
    black_box(tag);
}

fn test_encrypt_in_place(mc: &mut [u8]) {
    let ad = b"Comment numero un";
    let key = b"YELLOW SUBMARINE";
    let nonce = [0u8; 16];
    let tag = Aegis128L::new(&nonce, key).encrypt_in_place(mc, ad);
    black_box(tag);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut m = vec![0u8; 1024 * 1024];
    c.bench_function("aegis128l", |b| b.iter(|| test_encrypt(black_box(&m))));
    c.bench_function("aegis128l (in place)", |b| {
        b.iter(|| test_encrypt_in_place(black_box(&mut m)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
