// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Benchmarks for the merkle layer.
//!
//! Criterion reports median + IQR per measurement; never extrapolate a
//! transactions-per-second figure from these cryptographic-core micro-bench
//! numbers (see `docs/SECURITY.md`).
//!
//! Run with: `cargo bench -p vaa-merkle`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vaa_merkle::{merkle_proof, merkle_root, Hash};

fn synth_leaves(n: usize) -> Vec<Hash> {
    (0..n)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0..8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
            h
        })
        .collect()
}

fn bench_merkle_root(c: &mut Criterion) {
    let mut g = c.benchmark_group("merkle_root");
    for &n in &[16_usize, 256, 4096] {
        let leaves = synth_leaves(n);
        g.throughput(Throughput::Elements(u64::try_from(n).unwrap()));
        g.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, l| {
            b.iter(|| merkle_root(black_box(l)).unwrap());
        });
    }
    g.finish();
}

fn bench_merkle_proof(c: &mut Criterion) {
    let mut g = c.benchmark_group("merkle_proof");
    for &n in &[16_usize, 256, 4096] {
        let leaves = synth_leaves(n);
        let idx = n / 2;
        g.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(&leaves, idx),
            |b, (l, i)| {
                b.iter(|| merkle_proof(black_box(*l), black_box(*i)).unwrap());
            },
        );
    }
    g.finish();
}

fn bench_merkle_verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("merkle_verify");
    for &n in &[16_usize, 256, 4096] {
        let leaves = synth_leaves(n);
        let root = merkle_root(&leaves).unwrap();
        let idx = n / 2;
        let proof = merkle_proof(&leaves, idx).unwrap();
        let leaf = leaves[idx];
        g.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(proof, leaf, root),
            |b, (p, l, r)| {
                b.iter(|| p.verify(black_box(l), black_box(r)).unwrap());
            },
        );
    }
    g.finish();
}

criterion_group!(
    benches,
    bench_merkle_root,
    bench_merkle_proof,
    bench_merkle_verify
);
criterion_main!(benches);
