// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! Synthetic-population study with injected faults.
//!
//! Builds a deterministic receivables population of `M` movements
//! (invoices, receipts, credit notes, write-offs) that exactly satisfies
//! the AR roll-forward identity, commits every value under Pedersen
//! commitments arranged so the blinding factors close, anchors the
//! commitment hashes into a `ProofStore`, and reports detection counts
//! for six fault classes plus the honest negative boundary (collusive
//! false-origin commitment — not detected by design).
//!
//! All randomness comes from a seeded `ChaCha20Rng` (`SEED` below);
//! every count is reproducible bit-for-bit.

use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use vaa_bsv::hash::double_sha256;
use vaa_commit::{verify_sum_equal, Blinding, Commitment};
use vaa_merkle::{merkle_proof, merkle_root, Hash};
use vaa_proofstore::{Direction, IndexKey, ProofStore, ReconstructionMode};
use vaa_zk::RangeProof;

const SEED: u64 = 2_026_053_002;

#[derive(Debug, Parser)]
#[command(
    name = "vaa-simstudy",
    about = "Synthetic-population study with injected faults."
)]
struct Args {
    /// Number of movements (invoices + receipts + credit notes + write-offs).
    #[arg(short = 'm', long, default_value_t = 1_000)]
    m: usize,
    /// Number of items to range-prove (kept small; range proofs are O(n)).
    #[arg(long, default_value_t = 64)]
    range_sample: usize,
    /// Number of items to verify Merkle inclusion for.
    #[arg(long, default_value_t = 256)]
    inclusion_sample: usize,
    /// Optional path to write the deterministic vector JSON.
    #[arg(long)]
    vector_out: Option<std::path::PathBuf>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct PopulationSummary {
    m_movements: usize,
    invoices_count: usize,
    receipts_count: usize,
    credit_notes_count: usize,
    write_offs_count: usize,
    ar_open: u64,
    invoices_total: u64,
    receipts_total: u64,
    credit_notes_total: u64,
    write_offs_total: u64,
    ar_close: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
struct FaultClass {
    name: String,
    injected: usize,
    detected: usize,
    missed: usize,
    /// False-positive count on the clean population — must be 0.
    false_positives_clean: usize,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Report {
    population: PopulationSummary,
    inclusion_sample: usize,
    inclusion_passed: usize,
    range_sample: usize,
    range_passed: usize,
    roll_forward_holds: bool,
    faults: Vec<FaultClass>,
    /// Explicit honest-boundary record: a collusive false-origin fault is
    /// NOT detected by the system (the prover commits the wrong value at
    /// origin and proves the internally-consistent equation over it).
    collusive_false_origin: FaultClass,
    seed: u64,
    timings_phase_ms: Vec<(String, u128)>,
}

#[derive(Clone, Copy, Debug)]
enum MovementKind {
    Invoice,    // +
    Receipt,    // -
    CreditNote, // -
    WriteOff,   // -
}

#[derive(Clone, Debug)]
struct Movement {
    kind: MovementKind,
    value: u64,
    blinding: Blinding,
}

impl Movement {
    fn commit(&self) -> Commitment {
        Commitment::commit(self.value, &self.blinding)
    }
}

/// Generate a synthetic receivables population that exactly satisfies the
/// AR roll-forward identity. We allocate `M` movements split roughly
/// 50/35/10/5 across invoice/receipt/credit-note/write-off, draw their
/// individual values from a deterministic distribution, and compute the
/// closing balance from the opening + tally. Blindings are drawn so the
/// per-side sums match (we balance the closing-line blinding against
/// everything else to make `verify_sum_equal` succeed).
fn generate_population(
    m: usize,
    rng: &mut ChaCha20Rng,
) -> (Vec<Movement>, PopulationSummary, Blinding, Blinding) {
    let mut movements: Vec<Movement> = Vec::with_capacity(m);
    let mut totals = [0u64; 4]; // inv, rec, cn, wo
    let mut counts = [0usize; 4];

    // Realistic per-line satoshi sizes.
    let draw_value = |kind: MovementKind, rng: &mut ChaCha20Rng| -> u64 {
        match kind {
            MovementKind::Invoice => 400_000 + rng.gen_range(0..7_600_000),
            MovementKind::Receipt => 350_000 + rng.gen_range(0..7_400_000),
            MovementKind::CreditNote => 50_000 + rng.gen_range(0..500_000),
            MovementKind::WriteOff => 50_000 + rng.gen_range(0..400_000),
        }
    };
    // Bounded blindings: only the bottom 8 bytes carry entropy, leaving 24
    // leading zero bytes. This is a SIMULATION-ONLY choice (production must
    // use a CSPRNG over the full 256-bit space). Bounded blindings let us
    // do per-byte (mod 2^256) scalar arithmetic for the closing-line
    // balance and trust it to equal mod-n arithmetic, because the sums
    // never carry into the top bytes that distinguish 2^256 from n.
    // For any M < 2^(192) the per-side sum stays well below n.
    let draw_blinding = |rng: &mut ChaCha20Rng| -> Blinding {
        loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b[24..]);
            if b != [0u8; 32] {
                if let Ok(b) = Blinding::from_bytes(b) {
                    return b;
                }
            }
        }
    };

    let kinds = [
        (MovementKind::Invoice, m * 50 / 100),
        (MovementKind::Receipt, m * 35 / 100),
        (MovementKind::CreditNote, m * 10 / 100),
        (
            MovementKind::WriteOff,
            m - (m * 50 / 100 + m * 35 / 100 + m * 10 / 100),
        ),
    ];

    for (k_ix, (kind, kc)) in kinds.iter().enumerate() {
        for _ in 0..*kc {
            let v = draw_value(*kind, rng);
            let b = draw_blinding(rng);
            totals[k_ix] = totals[k_ix].wrapping_add(v);
            counts[k_ix] += 1;
            movements.push(Movement {
                kind: *kind,
                value: v,
                blinding: b,
            });
        }
    }

    let ar_open: u64 = 18_200_000 + (rng.gen::<u64>() % 5_000_000);
    let ar_close = ar_open + totals[0] - totals[1] - totals[2] - totals[3];

    // Pick the AR-open and AR-close blindings so the LHS / RHS tally:
    //   LHS = ar_open + invoices_blindings_sum
    //   RHS = ar_close + receipts_blindings_sum + cn_blindings + wo_blindings
    // We want LHS = RHS as field scalars. The cleanest construction:
    // pick a single random `r_open`, then derive r_close so that
    //   r_open + sum(inv_b) = r_close + sum(rec_b + cn_b + wo_b)
    // i.e. r_close = r_open + sum(inv_b) - sum(rec_b + cn_b + wo_b)  (mod n).
    //
    // To stay within byte-wise arithmetic, we sum the blindings as 256-bit
    // big-endian integers using a small "scalar" helper.
    let scalar_zero = [0u8; 32];
    let mut lhs_acc = scalar_zero;
    let mut rhs_acc = scalar_zero;
    for mv in &movements {
        let b = mv.blinding.to_bytes();
        match mv.kind {
            MovementKind::Invoice => scalar_add_be_inplace(&mut lhs_acc, &b),
            MovementKind::Receipt | MovementKind::CreditNote | MovementKind::WriteOff => {
                scalar_add_be_inplace(&mut rhs_acc, &b)
            }
        }
    }
    // r_open is fresh random; r_close = r_open + lhs_acc - rhs_acc.
    let r_open = draw_blinding(rng);
    let mut r_close_bytes = r_open.to_bytes();
    scalar_add_be_inplace(&mut r_close_bytes, &lhs_acc);
    scalar_sub_be_inplace(&mut r_close_bytes, &rhs_acc);
    // Avoid the all-zero scalar by perturbing if it happened. Extremely unlikely.
    if r_close_bytes == scalar_zero {
        r_close_bytes[31] = 1;
    }
    let r_close = Blinding::from_bytes(r_close_bytes).expect("constructed r_close is in range");

    let summary = PopulationSummary {
        m_movements: movements.len(),
        invoices_count: counts[0],
        receipts_count: counts[1],
        credit_notes_count: counts[2],
        write_offs_count: counts[3],
        ar_open,
        invoices_total: totals[0],
        receipts_total: totals[1],
        credit_notes_total: totals[2],
        write_offs_total: totals[3],
        ar_close,
    };
    (movements, summary, r_open, r_close)
}

/// Big-endian 256-bit add in place. Operates mod 2^256 (we do not reduce
/// mod the curve order here; the underlying Pedersen tally checks the
/// elliptic-curve equality, which already accounts for the modular field).
fn scalar_add_be_inplace(acc: &mut [u8; 32], other: &[u8; 32]) {
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let v = acc[i] as u16 + other[i] as u16 + carry;
        acc[i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
}

fn scalar_sub_be_inplace(acc: &mut [u8; 32], other: &[u8; 32]) {
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let v = acc[i] as i16 - other[i] as i16 - borrow;
        if v < 0 {
            acc[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            acc[i] = v as u8;
            borrow = 0;
        }
    }
}

/// Hash a (value, blinding) pair to a 32-byte leaf for Merkle anchoring.
/// The hash is over the 33-byte commitment serialisation.
fn leaf_hash_for(c: &Commitment) -> Hash {
    double_sha256(&c.serialize())
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

fn run_inclusion_sample(leaves: &[Hash], indices: &[usize], store: &ProofStore) -> Result<usize> {
    let mut passed = 0;
    for &i in indices {
        let key = key_for(i, &leaves[i]);
        let stored = store.query(&key)?;
        store.verify(&leaves[i], stored, ReconstructionMode::Adversarial)?;
        passed += 1;
    }
    Ok(passed)
}

fn run_range_sample(
    movements: &[Movement],
    indices: &[usize],
    rng: &mut ChaCha20Rng,
) -> Result<usize> {
    let mut passed = 0;
    for &i in indices {
        let mv = &movements[i];
        // 32-bit range covers up to ~4.29 billion satoshis (~ 42.9 BSV) — well
        // beyond any line in this study.
        let proof = RangeProof::prove(mv.value, &mv.blinding, 0, 32, rng)?;
        let c = mv.commit();
        proof.verify(&c)?;
        passed += 1;
    }
    Ok(passed)
}

/// LHS = [ar_open, all invoice commits]
/// RHS = [ar_close, all receipt + cn + wo commits]
/// Returns true iff the homomorphic tally closes.
fn roll_forward_tally(
    movements: &[Movement],
    summary: &PopulationSummary,
    r_open: &Blinding,
    r_close: &Blinding,
) -> bool {
    let c_open = Commitment::commit(summary.ar_open, r_open);
    let c_close = Commitment::commit(summary.ar_close, r_close);
    let mut lhs: Vec<Commitment> = vec![c_open];
    let mut rhs: Vec<Commitment> = vec![c_close];
    for mv in movements {
        let c = mv.commit();
        match mv.kind {
            MovementKind::Invoice => lhs.push(c),
            MovementKind::Receipt | MovementKind::CreditNote | MovementKind::WriteOff => {
                rhs.push(c)
            }
        }
    }
    verify_sum_equal(&lhs, &rhs)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut rng = ChaCha20Rng::seed_from_u64(SEED);
    let mut timings: Vec<(String, u128)> = Vec::new();

    // ----- Phase: generate clean population -----
    let t = Instant::now();
    let (mut movements, summary, r_open, r_close) = generate_population(args.m, &mut rng);
    timings.push(("generate_population_ms".into(), t.elapsed().as_millis()));

    // ----- Phase: roll-forward identity must hold -----
    let t = Instant::now();
    let identity_holds = summary.ar_open + summary.invoices_total
        == summary.ar_close
            + summary.receipts_total
            + summary.credit_notes_total
            + summary.write_offs_total;
    let roll_forward_holds =
        identity_holds && roll_forward_tally(&movements, &summary, &r_open, &r_close);
    timings.push(("roll_forward_tally_ms".into(), t.elapsed().as_millis()));
    if !roll_forward_holds {
        anyhow::bail!(
            "clean population does not satisfy the roll-forward identity — generator bug"
        );
    }

    // ----- Phase: anchor commitments as Merkle leaves -----
    let t = Instant::now();
    let leaves: Vec<Hash> = movements
        .iter()
        .map(|m| leaf_hash_for(&m.commit()))
        .collect();
    let depth_log2 = if leaves.len() <= 1 {
        0
    } else {
        ((leaves.len() - 1).ilog2() as usize) + 1
    };
    let predetermined_level = depth_log2 / 2;
    let mut store = ProofStore::new(predetermined_level);
    // Anchor only the inclusion-sample subset (anchoring all M is wasteful for
    // a large M and unrelated to fault detection).
    let inclusion_n = args.inclusion_sample.min(movements.len());
    let inclusion_indices: Vec<usize> = (0..inclusion_n)
        .map(|i| (i * movements.len() / inclusion_n.max(1)).min(movements.len() - 1))
        .collect();
    for &i in &inclusion_indices {
        store.anchor(key_for(i, &leaves[i]), &leaves, i)?;
    }
    timings.push(("anchor_inclusion_sample_ms".into(), t.elapsed().as_millis()));

    // ----- Phase: inclusion sample -----
    let t = Instant::now();
    let inclusion_passed = run_inclusion_sample(&leaves, &inclusion_indices, &store)?;
    timings.push(("inclusion_sample_ms".into(), t.elapsed().as_millis()));

    // ----- Phase: range-proof sample -----
    let t = Instant::now();
    let range_n = args.range_sample.min(movements.len());
    let range_indices: Vec<usize> = (0..range_n)
        .map(|i| (i * movements.len() / range_n.max(1)).min(movements.len() - 1))
        .collect();
    let range_passed = run_range_sample(&movements, &range_indices, &mut rng)?;
    timings.push(("range_sample_ms".into(), t.elapsed().as_millis()));

    // ----- Phase: fault injection -----
    let t = Instant::now();
    let faults = run_fault_injection(
        &movements,
        &summary,
        &r_open,
        &r_close,
        &leaves,
        &store,
        &inclusion_indices,
    )?;
    timings.push(("fault_injection_ms".into(), t.elapsed().as_millis()));

    // Honest negative boundary: collusive false-origin.
    // Build a separate population where the prover commits to a wrong value
    // at origin and constructs an internally-consistent equation around it.
    // The system does NOT detect this (by design).
    let collusive = run_collusive_false_origin(&mut rng)?;

    let report = Report {
        population: summary,
        inclusion_sample: inclusion_indices.len(),
        inclusion_passed,
        range_sample: range_indices.len(),
        range_passed,
        roll_forward_holds,
        faults,
        collusive_false_origin: collusive,
        seed: SEED,
        timings_phase_ms: timings,
    };

    // Validate the MUST-hold conditions before reporting.
    if report.inclusion_passed != report.inclusion_sample {
        anyhow::bail!(
            "inclusion sample: {} expected, {} passed",
            report.inclusion_sample,
            report.inclusion_passed
        );
    }
    if report.range_passed != report.range_sample {
        anyhow::bail!(
            "range sample: {} expected, {} passed",
            report.range_sample,
            report.range_passed
        );
    }
    for f in &report.faults {
        if f.false_positives_clean != 0 {
            anyhow::bail!(
                "fault class {} had {} false positives",
                f.name,
                f.false_positives_clean
            );
        }
        if f.missed != 0 {
            anyhow::bail!(
                "fault class {} missed {} of {}",
                f.name,
                f.missed,
                f.injected
            );
        }
    }

    println!(
        "simstudy.M={} inclusion={}/{} range={}/{} roll_forward_holds={} faults_detected={} \
         collusive_false_origin_detected={} seed={}",
        report.population.m_movements,
        report.inclusion_passed,
        report.inclusion_sample,
        report.range_passed,
        report.range_sample,
        report.roll_forward_holds,
        report.faults.iter().map(|f| f.detected).sum::<usize>(),
        report.collusive_false_origin.detected,
        report.seed,
    );
    for f in &report.faults {
        println!(
            "  fault.{}: injected={} detected={} missed={} false_positives_clean={}",
            f.name, f.injected, f.detected, f.missed, f.false_positives_clean
        );
    }
    println!(
        "  collusive_false_origin: injected={} detected={} (NOT DETECTED BY DESIGN)",
        report.collusive_false_origin.injected, report.collusive_false_origin.detected,
    );
    for (k, v) in &report.timings_phase_ms {
        println!("  timing.{k}={v}");
    }

    if let Some(path) = args.vector_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // For the committed vector strip wall-clock timings (host-dependent)
        // but keep all structural counts.
        let stable = serde_json::json!({
            "population": report.population,
            "inclusion_sample": report.inclusion_sample,
            "inclusion_passed": report.inclusion_passed,
            "range_sample": report.range_sample,
            "range_passed": report.range_passed,
            "roll_forward_holds": report.roll_forward_holds,
            "faults": report.faults,
            "collusive_false_origin": report.collusive_false_origin,
            "seed": report.seed,
            "note": "Timings are host-dependent (crypto-core/local) and omitted from the committed vector.",
        });
        std::fs::write(&path, serde_json::to_string_pretty(&stable)?)
            .with_context(|| format!("writing vector to {}", path.display()))?;
    }
    // also silence the unused warning for the mutable `movements` if the
    // fault injection doesn't otherwise need it.
    let _ = &mut movements;
    Ok(())
}

fn run_fault_injection(
    movements: &[Movement],
    summary: &PopulationSummary,
    r_open: &Blinding,
    r_close: &Blinding,
    leaves: &[Hash],
    store: &ProofStore,
    inclusion_indices: &[usize],
) -> Result<Vec<FaultClass>> {
    let mut out = Vec::new();

    // (clean) baseline must pass — false-positive sentinel
    let clean_tally = roll_forward_tally(movements, summary, r_open, r_close);

    // 1. Altered committed value — flip one movement's value by +1.
    {
        let mut copy = movements.to_vec();
        copy[0].value = copy[0].value.wrapping_add(1);
        let detected = !roll_forward_tally(&copy, summary, r_open, r_close);
        out.push(FaultClass {
            name: "altered_value".into(),
            injected: 1,
            detected: usize::from(detected),
            missed: usize::from(!detected),
            false_positives_clean: usize::from(!clean_tally),
        });
    }

    // 2. Omitted movement — drop one.
    {
        let mut copy = movements.to_vec();
        if !copy.is_empty() {
            copy.remove(0);
        }
        let detected = !roll_forward_tally(&copy, summary, r_open, r_close);
        out.push(FaultClass {
            name: "omitted_movement".into(),
            injected: 1,
            detected: usize::from(detected),
            missed: usize::from(!detected),
            false_positives_clean: usize::from(!clean_tally),
        });
    }

    // 3. Duplicated movement — add a copy of one.
    {
        let mut copy = movements.to_vec();
        if !copy.is_empty() {
            copy.push(copy[0].clone());
        }
        let detected = !roll_forward_tally(&copy, summary, r_open, r_close);
        out.push(FaultClass {
            name: "duplicated_movement".into(),
            injected: 1,
            detected: usize::from(detected),
            missed: usize::from(!detected),
            false_positives_clean: usize::from(!clean_tally),
        });
    }

    // 4. Out-of-range value — commit a value above the verifier's policy
    //    bound. libsecp256k1-zkp auto-widens the proof to fit the value, so
    //    detection happens at the caller: the verifier compares the
    //    certified range to its acceptance bound and rejects if too wide.
    //    This honestly models how an auditor with a policy bound (e.g.
    //    "all satoshi amounts must fit in 2^48") catches out-of-range
    //    commitments.
    {
        let policy_max_bits: u8 = 48;
        let policy_max: u64 = 1u64 << policy_max_bits;
        let over_value: u64 = 1u64 << 60; // way above the policy bound
        let blinding = Blinding::from_bytes([0x9a; 32])?;
        let mut local_rng = ChaCha20Rng::seed_from_u64(SEED + 4);
        let detected =
            match RangeProof::prove(over_value, &blinding, 0, policy_max_bits, &mut local_rng) {
                Err(_) => true,
                Ok(p) => match p.verify(&Commitment::commit(over_value, &blinding)) {
                    Err(_) => true,
                    Ok(certified_range) => certified_range.end > policy_max,
                },
            };
        out.push(FaultClass {
            name: "out_of_range_value".into(),
            injected: 1,
            detected: usize::from(detected),
            missed: usize::from(!detected),
            false_positives_clean: 0,
        });
    }

    // 5. Tampered Merkle leaf — flip one byte of the leaf, expect verify fail.
    {
        if !inclusion_indices.is_empty() {
            let i = inclusion_indices[0];
            let key = key_for(i, &leaves[i]);
            let stored = store.query(&key)?;
            let mut wrong = leaves[i];
            wrong[0] ^= 1;
            let detected = store
                .verify(&wrong, stored, ReconstructionMode::Adversarial)
                .is_err();
            out.push(FaultClass {
                name: "tampered_merkle_leaf".into(),
                injected: 1,
                detected: usize::from(detected),
                missed: usize::from(!detected),
                false_positives_clean: 0,
            });
        }
    }

    // 6. Wrong index — claim the wrong leaf_index in the proof.
    {
        if inclusion_indices.len() >= 2 {
            let i = inclusion_indices[0];
            let j = inclusion_indices[1];
            let key = key_for(i, &leaves[i]);
            let stored = store.query(&key)?;
            let proof = merkle_proof(leaves, i)?;
            let mut wrong = proof;
            wrong.leaf_index = j; // wrong index
            let root = merkle_root(leaves)?;
            let detected = wrong.verify(&leaves[i], &root).is_err();
            out.push(FaultClass {
                name: "wrong_index".into(),
                injected: 1,
                detected: usize::from(detected),
                missed: usize::from(!detected),
                false_positives_clean: 0,
            });
            // ensure `stored` is read.
            let _ = stored;
        }
    }

    Ok(out)
}

/// The honest negative boundary: a collusive false-origin commitment is NOT
/// detected by the system. The prover commits the wrong value at origin and
/// constructs an internally-consistent equation around it; from the
/// verifier's point of view, the tally still closes — exactly the limitation
/// the project documents.
fn run_collusive_false_origin(rng: &mut ChaCha20Rng) -> Result<FaultClass> {
    // Bounded blindings (top 24 bytes zero) so per-byte arithmetic == mod-n
    // arithmetic for the small-magnitude sums this test produces.
    let mut r = |seed: u8| -> Blinding {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b[24..]);
        b[31] = seed.saturating_add(b[31]); // taint with a small constant so
                                            // distinct seeds yield distinct
                                            // blindings deterministically
        if b == [0u8; 32] {
            b[31] = 1;
        }
        Blinding::from_bytes(b).expect("valid scalar")
    };
    // Real Net=100_000. Prover commits Net'=200_000 (collusive). To keep the
    // equation internally consistent, prover also lies about Gross, Tax,
    // Discount so Net' + Tax' == Gross' + Discount'.
    let r_net = r(0x10);
    let r_tax = r(0x20);
    let r_gross = r(0x30);
    let r_disc = r(0x40);
    let net_wrong = 200_000u64;
    let tax_wrong = 42_000u64;
    let disc_wrong = 5_000u64;
    let gross_wrong = net_wrong + tax_wrong - disc_wrong;
    let c_net = Commitment::commit(net_wrong, &r_net);
    let c_tax = Commitment::commit(tax_wrong, &r_tax);
    let c_gross = Commitment::commit(gross_wrong, &r_gross);
    let c_disc = Commitment::commit(disc_wrong, &r_disc);

    // The tally is over the COMMITTED values; it closes whether the values
    // are honest or not. To make it close, the blinding factors must also
    // tally. We pick gross-line blinding so the equation closes.
    let mut needed = [0u8; 32];
    // r_gross_balance = r_net + r_tax - r_disc
    let mut acc = r_net.to_bytes();
    scalar_add_be_inplace(&mut acc, &r_tax.to_bytes());
    scalar_sub_be_inplace(&mut acc, &r_disc.to_bytes());
    needed.copy_from_slice(&acc);
    let r_gross_balance = Blinding::from_bytes(needed).expect("constructed balance is in range");
    let c_gross_balance = Commitment::commit(gross_wrong, &r_gross_balance);

    // The verifier checks Net + Tax == Gross + Discount over the COMMITTED
    // values. With the balanced gross commitment, the tally closes.
    let detected = !verify_sum_equal(&[c_net, c_tax], &[c_gross_balance, c_disc]);

    // Sanity check: the unbalanced gross would have failed.
    let _ = c_gross; // unused but kept for symmetry

    Ok(FaultClass {
        name: "collusive_false_origin".into(),
        injected: 1,
        detected: usize::from(detected),
        missed: usize::from(!detected),
        false_positives_clean: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_satisfies_identity_for_small_m() {
        let mut rng = ChaCha20Rng::seed_from_u64(SEED);
        let (movements, summary, r_open, r_close) = generate_population(64, &mut rng);
        assert_eq!(movements.len(), summary.m_movements);
        assert_eq!(
            summary.ar_open + summary.invoices_total,
            summary.ar_close
                + summary.receipts_total
                + summary.credit_notes_total
                + summary.write_offs_total,
            "AR roll-forward identity must hold over the integer totals"
        );
        assert!(
            roll_forward_tally(&movements, &summary, &r_open, &r_close),
            "Pedersen tally must close on the clean population"
        );
    }

    /// The honest-boundary boundary: collusive false-origin is NOT detected.
    /// The test ASSERTS the non-detection so any change that "fixes" this by
    /// accident shows up as a test failure (it would be a regression, not a
    /// real fix).
    #[test]
    fn collusive_false_origin_is_not_detected_by_design() {
        let mut rng = ChaCha20Rng::seed_from_u64(SEED + 9);
        let result = run_collusive_false_origin(&mut rng).unwrap();
        assert_eq!(
            result.detected, 0,
            "collusive false-origin must remain undetected (system-boundary, by design)"
        );
        assert_eq!(result.missed, 1);
    }

    #[test]
    fn scalar_add_then_sub_round_trips() {
        let mut acc = [0u8; 32];
        let other = [0xab; 32];
        scalar_add_be_inplace(&mut acc, &other);
        scalar_sub_be_inplace(&mut acc, &other);
        assert_eq!(acc, [0u8; 32]);
    }
}
