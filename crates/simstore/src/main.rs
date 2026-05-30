// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Proof-store storage and retrieval efficiency study.
//!
//! Builds a deterministic synthetic leaf population of size `N`, anchors
//! every queried leaf into a `ProofStore`, and measures the storage and
//! retrieval-payload advantage of the sharded/proof-assistance design
//! (WO 2025/119666 claims 2–8) versus a naive full-proof baseline.
//!
//! Every byte count comes from the actual populated `ProofStore` — never
//! from a parallel formula. The baseline is computed as
//! `Q · ceil(log2 N) · 32` AND re-derived from a count of the full proof
//! sibling lists.
//!
//! Determinism: leaves and the query workload are produced by a seeded
//! `ChaCha20Rng` (`SEED` below) so every byte count is reproducible
//! bit-for-bit.
//!
//! Output: machine-readable lines on stdout, one per measurement, plus
//! a JSON file at `vectors/study/storage_<N>.json` for the deterministic
//! fast-CI point so `vaa reproduce` can diff it.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use vaa_merkle::Hash;
use vaa_proofstore::{Direction, IndexKey, ProofStore, ReconstructionMode, StoredProof};

/// Fixed seed for the deterministic leaf set and query workload.
const SEED: u64 = 2_026_053_001;
/// Hash size in bytes (BSV double-SHA256).
const HASH_BYTES: usize = 32;

#[derive(Debug, Parser)]
#[command(
    name = "vaa-simstore",
    about = "Storage / retrieval study for the proof-store layer."
)]
struct Args {
    /// Number of leaves in the synthetic population.
    #[arg(short = 'n', long, default_value_t = 1024)]
    n: usize,
    /// Number of query items (sampled from the leaves).
    #[arg(short = 'q', long, default_value_t = 256)]
    q: usize,
    /// Predetermined level k for proof-assistance. If omitted, uses
    /// floor(log2(N) / 2).
    #[arg(short = 'k', long)]
    predetermined_level: Option<usize>,
    /// Optional path to write the deterministic vector JSON. Set by the
    /// reproduce harness; ignored if omitted.
    #[arg(long)]
    vector_out: Option<std::path::PathBuf>,
}

/// One report point recorded into a vector JSON.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Report {
    n_leaves: usize,
    q_queries: usize,
    predetermined_level: usize,
    tree_depth: usize,
    // baseline
    baseline_bytes_formula: usize,
    baseline_bytes_realised: usize,
    // sharded — three honest variants reported separately
    store_held_bytes_no_dedup: usize,
    store_held_bytes_upper_dedup: usize,
    minimum_viable_bytes: usize,
    assistance_bytes: usize,
    // advantage
    avoided_bytes_no_dedup: i64,
    ratio_no_dedup: f64,
    avoided_bytes_upper_dedup: i64,
    ratio_upper_dedup: f64,
    avoided_bytes_minimum_viable: i64,
    ratio_minimum_viable: f64,
    // retrieval payloads (per single query)
    retrieval_adversarial_bytes: usize,
    retrieval_assisted_bytes: usize,
    // verification timing — crypto-core/local, never extrapolated
    verify_median_us: u128,
    verify_min_us: u128,
    verify_max_us: u128,
    verify_with_assistance_median_us: u128,
    verify_with_assistance_min_us: u128,
    verify_with_assistance_max_us: u128,
    // seeds
    seed: u64,
}

fn synth_leaves(n: usize, rng: &mut ChaCha20Rng) -> Vec<Hash> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut h = [0u8; HASH_BYTES];
        rng.fill_bytes(&mut h);
        out.push(h);
    }
    out
}

fn sample_indices(n: usize, q: usize, rng: &mut ChaCha20Rng) -> Vec<usize> {
    use std::collections::BTreeSet;
    let q = q.min(n);
    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    while chosen.len() < q {
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut b);
        chosen.insert((u64::from_le_bytes(b) as usize) % n);
    }
    chosen.into_iter().collect()
}

fn key_for(index: usize, leaf: &Hash) -> IndexKey {
    IndexKey {
        txid: *leaf,
        direction: Direction::Output,
        position: 0,
        block_position: u32::try_from(index).unwrap_or(u32::MAX),
        locking_script: None,
        unlocking_script: None,
        amount: None,
    }
}

/// `ceil(log2 n)` for `n >= 1`. Returns 0 for n in {0, 1}.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (n - 1).ilog2() as usize + 1
    }
}

/// Total siblings across all shards of one StoredProof.
fn proof_total_siblings(p: &StoredProof) -> usize {
    p.shards.iter().map(|s| s.siblings.len()).sum()
}

/// Count actual bytes the store holds, three honest interpretations.
fn measure_store_bytes(
    stored: &[&StoredProof],
    predetermined_level: usize,
    assistance_bytes: usize,
) -> (usize, usize, usize) {
    // (no-dedup) — every shard of every StoredProof counted in full + assistance.
    let no_dedup: usize = stored
        .iter()
        .flat_map(|p| p.shards.iter())
        .map(|s| s.siblings.len() * HASH_BYTES)
        .sum::<usize>()
        + assistance_bytes;

    // (upper-dedup) — lower shards per-query in full, upper shards deduplicated
    // by content (shared across queries that visit the same upper subtree).
    let mut lower_bytes: usize = 0;
    let mut unique_upper: HashSet<Vec<Hash>> = HashSet::new();
    for p in stored {
        for s in &p.shards {
            if s.from_level < predetermined_level {
                lower_bytes += s.siblings.len() * HASH_BYTES;
            } else {
                unique_upper.insert(s.siblings.clone());
            }
        }
    }
    let upper_dedup_upper_bytes: usize = unique_upper
        .iter()
        .map(|v| v.len() * HASH_BYTES)
        .sum::<usize>();
    let upper_dedup = lower_bytes + upper_dedup_upper_bytes + assistance_bytes;

    // (minimum-viable) — drop upper shards entirely (the proof-assistance
    // labels already let a verifier reconstruct above predetermined_level
    // from public on-chain data). Lower per-query + assistance once.
    let minimum_viable = lower_bytes + assistance_bytes;

    (no_dedup, upper_dedup, minimum_viable)
}

/// Bytes returned to the verifier for an adversarial-mode retrieval (the
/// full set of sibling hashes the verifier needs to walk leaf → root).
fn retrieval_adversarial_bytes(p: &StoredProof) -> usize {
    proof_total_siblings(p) * HASH_BYTES + std::mem::size_of::<usize>() // leaf_index
}

/// Bytes returned to the verifier in the assisted path (only lower-shard
/// siblings; the rest comes from public assistance the verifier already has).
fn retrieval_assisted_bytes(p: &StoredProof, predetermined_level: usize) -> usize {
    let lower: usize = p
        .shards
        .iter()
        .filter(|s| s.from_level < predetermined_level)
        .map(|s| s.siblings.len() * HASH_BYTES)
        .sum();
    lower + std::mem::size_of::<usize>()
}

fn percentile(mut samples: Vec<Duration>, pct: f64) -> Duration {
    samples.sort();
    let idx = ((samples.len() as f64) * pct).floor() as usize;
    samples[idx.min(samples.len() - 1)]
}

fn main() -> Result<()> {
    let args = Args::parse();
    let n = args.n;
    let q = args.q.min(n);
    if n == 0 {
        anyhow::bail!("N must be >= 1");
    }
    let depth = ceil_log2(n);
    let k = args.predetermined_level.unwrap_or(depth / 2);

    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let leaves = synth_leaves(n, &mut rng);
    let indices = sample_indices(n, q, &mut rng);

    // Build the store and anchor every queried index.
    let mut store = ProofStore::new(k);
    for &i in &indices {
        store
            .anchor(key_for(i, &leaves[i]), &leaves, i)
            .context("anchor")?;
    }

    // Pull every stored proof for measurement.
    let stored_keys: Vec<IndexKey> = indices.iter().map(|&i| key_for(i, &leaves[i])).collect();
    let stored: Vec<&StoredProof> = stored_keys
        .iter()
        .map(|k| store.query(k).expect("queried key present"))
        .collect();
    let root = stored[0].expected_root;
    let assistance = store
        .proof_assistance_for(&root)
        .expect("assistance present");
    let assistance_bytes = assistance.node_labels.len() * HASH_BYTES;

    // Baseline (formula AND realised). For Q items each with a full Merkle
    // proof, baseline = Q · depth · 32 bytes (+ leaf-index size per proof).
    let baseline_formula = q * depth * HASH_BYTES;
    let baseline_realised: usize = stored
        .iter()
        .map(|p| proof_total_siblings(p) * HASH_BYTES)
        .sum();

    let (sharded_no, sharded_dedup, sharded_min) =
        measure_store_bytes(&stored, k, assistance_bytes);

    let avoided_no = baseline_formula as i64 - sharded_no as i64;
    let avoided_dedup = baseline_formula as i64 - sharded_dedup as i64;
    let avoided_min = baseline_formula as i64 - sharded_min as i64;
    let ratio = |s: usize| -> f64 {
        if baseline_formula == 0 {
            0.0
        } else {
            s as f64 / baseline_formula as f64
        }
    };

    // Retrieval payloads — pick the first stored item as the representative.
    let rep = stored[0];
    let retrieval_adv_bytes = retrieval_adversarial_bytes(rep);
    let retrieval_ast_bytes = retrieval_assisted_bytes(rep, k);

    // Verification timings — median + min/max across the workload.
    let mut verify_samples = Vec::with_capacity(stored.len());
    let mut verify_assist_samples = Vec::with_capacity(stored.len());
    for (i, p) in stored.iter().enumerate() {
        let leaf = leaves[indices[i]];
        let t = Instant::now();
        store
            .verify(&leaf, p, ReconstructionMode::Adversarial)
            .context("adversarial verify")?;
        verify_samples.push(t.elapsed());
        let t = Instant::now();
        store
            .verify_with_assistance(&leaf, p)
            .context("assisted verify")?;
        verify_assist_samples.push(t.elapsed());
    }
    let verify_median = percentile(verify_samples.clone(), 0.5);
    let verify_min = *verify_samples.iter().min().unwrap();
    let verify_max = *verify_samples.iter().max().unwrap();
    let assist_median = percentile(verify_assist_samples.clone(), 0.5);
    let assist_min = *verify_assist_samples.iter().min().unwrap();
    let assist_max = *verify_assist_samples.iter().max().unwrap();

    let report = Report {
        n_leaves: n,
        q_queries: q,
        predetermined_level: k,
        tree_depth: depth,
        baseline_bytes_formula: baseline_formula,
        baseline_bytes_realised: baseline_realised,
        store_held_bytes_no_dedup: sharded_no,
        store_held_bytes_upper_dedup: sharded_dedup,
        minimum_viable_bytes: sharded_min,
        assistance_bytes,
        avoided_bytes_no_dedup: avoided_no,
        ratio_no_dedup: ratio(sharded_no),
        avoided_bytes_upper_dedup: avoided_dedup,
        ratio_upper_dedup: ratio(sharded_dedup),
        avoided_bytes_minimum_viable: avoided_min,
        ratio_minimum_viable: ratio(sharded_min),
        retrieval_adversarial_bytes: retrieval_adv_bytes,
        retrieval_assisted_bytes: retrieval_ast_bytes,
        verify_median_us: verify_median.as_micros(),
        verify_min_us: verify_min.as_micros(),
        verify_max_us: verify_max.as_micros(),
        verify_with_assistance_median_us: assist_median.as_micros(),
        verify_with_assistance_min_us: assist_min.as_micros(),
        verify_with_assistance_max_us: assist_max.as_micros(),
        seed: SEED,
    };

    // Machine-readable single line per metric.
    println!(
        "storage.N={} Q={} k={} depth={} baseline_formula={} baseline_realised={} \
         store_no_dedup={} store_upper_dedup={} minimum_viable={} assistance={} \
         avoided_no_dedup={} ratio_no_dedup={:.4} avoided_upper_dedup={} ratio_upper_dedup={:.4} \
         avoided_min={} ratio_min={:.4} retrieval_adv_bytes={} retrieval_assisted_bytes={} \
         verify_median_us={} verify_min_us={} verify_max_us={} \
         verify_with_assistance_median_us={} verify_with_assistance_min_us={} verify_with_assistance_max_us={} \
         seed={}",
        report.n_leaves,
        report.q_queries,
        report.predetermined_level,
        report.tree_depth,
        report.baseline_bytes_formula,
        report.baseline_bytes_realised,
        report.store_held_bytes_no_dedup,
        report.store_held_bytes_upper_dedup,
        report.minimum_viable_bytes,
        report.assistance_bytes,
        report.avoided_bytes_no_dedup,
        report.ratio_no_dedup,
        report.avoided_bytes_upper_dedup,
        report.ratio_upper_dedup,
        report.avoided_bytes_minimum_viable,
        report.ratio_minimum_viable,
        report.retrieval_adversarial_bytes,
        report.retrieval_assisted_bytes,
        report.verify_median_us,
        report.verify_min_us,
        report.verify_max_us,
        report.verify_with_assistance_median_us,
        report.verify_with_assistance_min_us,
        report.verify_with_assistance_max_us,
        report.seed,
    );

    if let Some(path) = args.vector_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // For the committed vector we strip timings (host-dependent) so the
        // file is bit-stable across machines. Reproduce diffs against the
        // structural fields; timings are reported separately as crypto-core/local.
        let stable = serde_json::json!({
            "n_leaves": report.n_leaves,
            "q_queries": report.q_queries,
            "predetermined_level": report.predetermined_level,
            "tree_depth": report.tree_depth,
            "baseline_bytes_formula": report.baseline_bytes_formula,
            "baseline_bytes_realised": report.baseline_bytes_realised,
            "store_held_bytes_no_dedup": report.store_held_bytes_no_dedup,
            "store_held_bytes_upper_dedup": report.store_held_bytes_upper_dedup,
            "minimum_viable_bytes": report.minimum_viable_bytes,
            "assistance_bytes": report.assistance_bytes,
            "retrieval_adversarial_bytes": report.retrieval_adversarial_bytes,
            "retrieval_assisted_bytes": report.retrieval_assisted_bytes,
            "seed": report.seed,
            "note": "Timings are host-dependent (crypto-core/local) and omitted from the committed vector.",
        });
        std::fs::write(&path, serde_json::to_string_pretty(&stable)?)
            .with_context(|| format!("writing vector to {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// At every tested scale, the deduplicated and minimum-viable sharded
    /// counts must not exceed the baseline.
    #[test]
    fn sharded_does_not_exceed_baseline_across_scales() {
        for &n in &[16_usize, 64, 256] {
            let q = (n / 2).max(2);
            let depth = ceil_log2(n);
            let k = depth / 2;
            let mut rng = ChaCha20Rng::seed_from_u64(SEED + n as u64);
            let leaves = synth_leaves(n, &mut rng);
            let indices = sample_indices(n, q, &mut rng);
            let mut store = ProofStore::new(k);
            for &i in &indices {
                store.anchor(key_for(i, &leaves[i]), &leaves, i).unwrap();
            }
            let stored_keys: Vec<IndexKey> =
                indices.iter().map(|&i| key_for(i, &leaves[i])).collect();
            let stored: Vec<&StoredProof> = stored_keys
                .iter()
                .map(|k| store.query(k).unwrap())
                .collect();
            let root = stored[0].expected_root;
            let assistance = store.proof_assistance_for(&root).unwrap();
            let assistance_bytes = assistance.node_labels.len() * HASH_BYTES;
            let baseline = q * depth * HASH_BYTES;
            let (_, dedup, min_viable) = measure_store_bytes(&stored, k, assistance_bytes);
            assert!(
                min_viable <= baseline,
                "N={n}: minimum-viable {min_viable} > baseline {baseline}"
            );
            assert!(
                dedup <= baseline,
                "N={n}: upper-dedup {dedup} > baseline {baseline}"
            );
        }
    }

    /// Adversarial soundness at scale: a tampered leaf MUST be rejected by
    /// both verify paths, and an honest leaf MUST be accepted.
    #[test]
    fn adversarial_soundness_holds_at_scale() {
        let n = 256_usize;
        let depth = ceil_log2(n);
        let k = depth / 2;
        let mut rng = ChaCha20Rng::seed_from_u64(SEED);
        let leaves = synth_leaves(n, &mut rng);
        let indices = sample_indices(n, 16, &mut rng);
        let mut store = ProofStore::new(k);
        for &i in &indices {
            store.anchor(key_for(i, &leaves[i]), &leaves, i).unwrap();
        }
        let key = key_for(indices[0], &leaves[indices[0]]);
        let stored = store.query(&key).unwrap();
        // Honest leaf accepts via both paths.
        store
            .verify(&leaves[indices[0]], stored, ReconstructionMode::Adversarial)
            .unwrap();
        store
            .verify_with_assistance(&leaves[indices[0]], stored)
            .unwrap();
        // Tampered leaf rejects via both paths.
        let mut tampered = leaves[indices[0]];
        tampered[0] ^= 1;
        assert!(store
            .verify(&tampered, stored, ReconstructionMode::Adversarial)
            .is_err());
        assert!(store.verify_with_assistance(&tampered, stored).is_err());
    }

    /// ceil_log2 reference values.
    #[test]
    fn ceil_log2_known_values() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(4), 2);
        assert_eq!(ceil_log2(5), 3);
        assert_eq!(ceil_log2(1024), 10);
    }
}
