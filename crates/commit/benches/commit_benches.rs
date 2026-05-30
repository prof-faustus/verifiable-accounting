// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Benchmarks for the commit layer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use vaa_commit::{verify_sum_equal, Blinding, Commitment};

fn r(byte: u8) -> Blinding {
    Blinding::from_bytes([byte; 32]).expect("valid scalar")
}

fn bench_commit(c: &mut Criterion) {
    let blinding = r(7);
    c.bench_function("commit_single", |b| {
        b.iter(|| Commitment::commit(black_box(100_000), black_box(&blinding)));
    });
}

fn bench_verify_open(c: &mut Criterion) {
    let blinding = r(7);
    let commitment = Commitment::commit(100_000, &blinding);
    c.bench_function("verify_open", |b| {
        b.iter(|| {
            assert!(commitment.verify_open(black_box(100_000), black_box(&blinding)));
        });
    });
}

fn bench_sum_equal(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify_sum_equal");
    for &n in &[2_usize, 8, 32] {
        // Build n commitments on each side where blinding sums match by construction.
        let mut lhs = Vec::with_capacity(n);
        let mut rhs = Vec::with_capacity(n);
        for i in 0..n {
            let byte = u8::try_from(i + 1).unwrap();
            lhs.push(Commitment::commit(
                1_000 + u64::try_from(i).unwrap(),
                &r(byte),
            ));
            rhs.push(Commitment::commit(
                1_000 + u64::try_from(i).unwrap(),
                &r(byte),
            ));
        }
        g.bench_with_input(BenchmarkId::from_parameter(n), &(lhs, rhs), |b, (l, r_)| {
            b.iter(|| assert!(verify_sum_equal(black_box(l), black_box(r_))));
        });
    }
    g.finish();
}

criterion_group!(benches, bench_commit, bench_verify_open, bench_sum_equal);
criterion_main!(benches);
