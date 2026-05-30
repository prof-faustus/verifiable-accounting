// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Benchmarks for the zk layer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use vaa_commit::{Blinding, Commitment};
use vaa_zk::RangeProof;

fn r(byte: u8) -> Blinding {
    Blinding::from_bytes([byte; 32]).expect("valid scalar")
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(20_260_530)
}

fn bench_range_prove(c: &mut Criterion) {
    let mut g = c.benchmark_group("range_prove");
    for &bits in &[8_u8, 32, 64] {
        g.bench_with_input(BenchmarkId::from_parameter(bits), &bits, |b, &bits| {
            b.iter_with_setup(rng, |mut r_| {
                let blinding = r(0x42);
                RangeProof::prove(black_box(123_456), black_box(&blinding), 0, bits, &mut r_)
                    .unwrap()
            });
        });
    }
    g.finish();
}

fn bench_range_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("range_verify");
    for &bits in &[8_u8, 32, 64] {
        let blinding = r(0x42);
        let value = 123_456_u64;
        let proof = RangeProof::prove(value, &blinding, 0, bits, &mut rng()).unwrap();
        let commitment = Commitment::commit(value, &blinding);
        g.bench_with_input(
            BenchmarkId::from_parameter(bits),
            &(proof, commitment),
            |b, (p, c_)| {
                b.iter(|| p.verify(black_box(c_)).unwrap());
            },
        );
    }
    g.finish();
}

criterion_group!(benches, bench_range_prove, bench_range_verify);
criterion_main!(benches);
