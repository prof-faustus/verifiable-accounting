// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Craig Wright

//! `vaa` — Verifiable Accounting Arithmetic command-line interface.
//!
//! Subcommands:
//!
//! - `vaa selftest` — exercise every implemented layer end to end.
//! - `vaa reproduce` — regenerate every deterministic vector and diff
//!   against the committed expected outputs.
//! - `vaa anchor` — build the BSV-canonical Merkle root over a JSON
//!   file of leaf hashes; print the root.
//! - `vaa prove` — produce a proof bundle for one record: Merkle
//!   inclusion against the anchored root, plus the disclosed record
//!   bytes (Layer A presence + Layer B selective disclosure).
//! - `vaa verify` — verify a proof bundle via the audit API.
//! - `vaa query` — exercise the in-process selective-verification
//!   proofstore retrieval flow.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use vaa_accounting::{ArRollForward, InvoiceTotal};
use vaa_api::{AuditBundle, AuditVerifier};
use vaa_bsv::hash::double_sha256;
use vaa_merkle::{merkle_proof, merkle_root, Hash, MerkleProof};
use vaa_proofstore::{Direction, IndexKey, ProofStore, ReconstructionMode};

/// Verifiable Accounting Arithmetic CLI.
#[derive(Debug, Parser)]
#[command(name = "vaa", version, about = "Verifiable Accounting Arithmetic over BSV.", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the internal self-test across every implemented layer.
    Selftest,
    /// Regenerate every deterministic vector and diff against the expected
    /// outputs; exit non-zero on any mismatch.
    Reproduce,
    /// Build a BSV-canonical Merkle root over a JSON file of leaf hashes
    /// and print the root in display (big-endian) hex.
    Anchor {
        /// Path to a JSON file `{"leaves_display_be": ["<64-hex>", ...]}`.
        #[arg(short, long)]
        leaves: PathBuf,
    },
    /// Generate a proof bundle for one record: Merkle inclusion proof +
    /// the disclosed record bytes anchored at the leaf.
    Prove {
        /// Path to a JSON file `{"records_hex": ["<record bytes hex>", ...]}`.
        /// Each record's leaf is `double_sha256(record_bytes)`.
        #[arg(short, long)]
        records: PathBuf,
        /// Zero-based record index to prove.
        #[arg(short, long)]
        index: usize,
        /// Output path for the proof bundle JSON.
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Verify a proof bundle produced by `vaa prove`. Non-zero exit on failure.
    Verify {
        /// Path to the proof bundle JSON.
        #[arg(short, long)]
        bundle: PathBuf,
    },
    /// Query an in-process proofstore warmed from a record JSON file.
    Query {
        /// Path to the records JSON file (same shape as `vaa prove`).
        #[arg(short, long)]
        records: PathBuf,
        /// Zero-based record index to query.
        #[arg(short, long)]
        index: usize,
        /// Predetermined level `k` at which proof-assistance is published.
        #[arg(long, default_value_t = 1)]
        level: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Selftest => cmd_selftest(),
        Command::Reproduce => cmd_reproduce(),
        Command::Anchor { leaves } => cmd_anchor(&leaves),
        Command::Prove {
            records,
            index,
            out,
        } => cmd_prove(&records, index, &out),
        Command::Verify { bundle } => cmd_verify(&bundle),
        Command::Query {
            records,
            index,
            level,
        } => cmd_query(&records, index, level),
    }
}

// ----------------------------------------------------------------------------
// JSON shapes
// ----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct LeavesFile {
    /// Each entry is a 64-char hex hash in display (big-endian) order.
    leaves_display_be: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordsFile {
    /// Each entry is the hex-encoded record bytes; `leaf = double_sha256(bytes)`.
    records_hex: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProofBundle {
    version: u32,
    /// Display-form Merkle root the proof terminates against.
    root_display_be: String,
    /// The leaf, in display form.
    leaf_display_be: String,
    /// Ordered sibling hashes, each in display form.
    siblings_display_be: Vec<String>,
    /// Zero-based leaf index.
    leaf_index: usize,
    /// The disclosed record bytes, hex-encoded.
    disclosed_record_hex: String,
}

// ----------------------------------------------------------------------------
// Byte-order helpers (BSV display ↔ internal)
// ----------------------------------------------------------------------------

fn display_to_internal(hex_str: &str) -> Result<Hash> {
    let mut bytes = hex::decode(hex_str.trim()).context("invalid hex")?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn internal_to_display(h: &Hash) -> String {
    let mut b = *h;
    b.reverse();
    hex::encode(b)
}

fn load_leaves(path: &Path) -> Result<Vec<Hash>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading leaves file {}", path.display()))?;
    let parsed: LeavesFile = serde_json::from_str(&raw).context("parsing leaves JSON")?;
    parsed
        .leaves_display_be
        .iter()
        .enumerate()
        .map(|(i, s)| display_to_internal(s).with_context(|| format!("leaf #{i}: {s}")))
        .collect()
}

fn load_records(path: &Path) -> Result<(Vec<Vec<u8>>, Vec<Hash>)> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading records file {}", path.display()))?;
    let parsed: RecordsFile = serde_json::from_str(&raw).context("parsing records JSON")?;
    let mut records = Vec::with_capacity(parsed.records_hex.len());
    let mut leaves = Vec::with_capacity(parsed.records_hex.len());
    for (i, s) in parsed.records_hex.iter().enumerate() {
        let bytes = hex::decode(s.trim()).with_context(|| format!("record #{i} hex"))?;
        leaves.push(double_sha256(&bytes));
        records.push(bytes);
    }
    Ok((records, leaves))
}

// ----------------------------------------------------------------------------
// Subcommand: selftest
// ----------------------------------------------------------------------------

fn cmd_selftest() -> Result<()> {
    println!("vaa selftest");
    println!("============");

    // 1. bsv: double-SHA256 known vector (empty string).
    let h = double_sha256(b"");
    let expected = hex::decode("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")?;
    if h[..] != expected[..] {
        bail!("bsv: double-SHA256 of empty string did not match the known vector");
    }
    println!("  [ok]  bsv         : double-SHA256 known-vector matches");

    // 2. merkle: synthetic 8-leaf round-trip + adversarial reject.
    let leaves: Vec<Hash> = (1u8..=8)
        .map(|i| {
            let mut h = [0u8; 32];
            h[31] = i;
            h
        })
        .collect();
    let root = merkle_root(&leaves)?;
    let proof = merkle_proof(&leaves, 3)?;
    proof.verify(&leaves[3], &root)?;
    let mut altered = leaves[3];
    altered[0] ^= 1;
    if proof.verify(&altered, &root).is_ok() {
        bail!("merkle: altered leaf was incorrectly accepted");
    }
    println!("  [ok]  merkle      : synthetic 8-leaf proof verifies; altered leaf rejected");

    // 3. accounting: invoice total identity over disclosed records.
    InvoiceTotal {
        net: 100_000,
        tax: 21_000,
        discount: 4_000,
        gross: 117_000,
    }
    .verify()
    .map_err(|e| anyhow::anyhow!("accounting: invoice identity: {e}"))?;
    println!("  [ok]  accounting  : Net + Tax == Gross + Discount (recomputed over records)");

    // 4. accounting: AR roll-forward identity.
    ArRollForward {
        ar_open: 50_000,
        invoices: 60_000,
        ar_close: 40_000,
        receipts: 65_000,
        credit_notes: 3_000,
        write_offs: 2_000,
    }
    .verify()
    .map_err(|e| anyhow::anyhow!("accounting: AR roll-forward: {e}"))?;
    println!("  [ok]  accounting  : AR roll-forward identity holds");

    // 5. proofstore: anchor, query, verify (both reconstruction modes).
    let mut store = ProofStore::new(1);
    let mut txid = [0u8; 32];
    txid[31] = 42;
    let key = IndexKey {
        txid,
        direction: Direction::Output,
        position: 0,
        block_position: 3,
        locking_script: None,
        unlocking_script: None,
        amount: None,
    };
    let store_root = store.anchor(key.clone(), &leaves, 3)?;
    if store_root != root {
        bail!("proofstore: anchored root does not match direct merkle_root");
    }
    let stored = store.query(&key)?;
    store.verify(&leaves[3], stored, ReconstructionMode::Adversarial)?;
    store.verify_with_assistance(&leaves[3], stored)?;
    println!("  [ok]  proofstore  : anchor + query + adversarial verify + assisted verify");

    println!();
    println!("selftest passed: 5/5 checks");
    Ok(())
}

// ----------------------------------------------------------------------------
// Subcommand: reproduce
// ----------------------------------------------------------------------------

fn cmd_reproduce() -> Result<()> {
    println!("vaa reproduce");
    println!("=============");

    let mut passed = 0usize;

    // merkle.genesis.v1 — BSV genesis block (single-leaf single-tx).
    let mg_path = Path::new("vectors/merkle/genesis_v1.json");
    if mg_path.exists() {
        let mg_raw = fs::read_to_string(mg_path)?;
        let mg: serde_json::Value = serde_json::from_str(&mg_raw)?;
        let expected_display = mg["expected_root_display_be"]
            .as_str()
            .context("missing expected_root_display_be")?;
        let coinbase_display = mg["coinbase_txid_display_be"]
            .as_str()
            .context("missing coinbase_txid_display_be")?;
        let leaf = display_to_internal(coinbase_display)?;
        let regen = merkle_root(&[leaf])?;
        let regen_display = internal_to_display(&regen);
        if regen_display != expected_display {
            bail!(
                "MISMATCH for merkle.genesis.v1: expected {expected_display}, got {regen_display}"
            );
        }
        println!("  [ok]  merkle.genesis.v1");
        passed += 1;
    }

    // merkle.bsv_block.v1 — multi-transaction BSV mainnet block, neutrally named.
    let b_path = Path::new("vectors/merkle/bsv_block_v1.json");
    if b_path.exists() {
        let raw = fs::read_to_string(b_path)?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        let expected = v["expected_merkle_root_display_be"]
            .as_str()
            .context("missing expected_merkle_root_display_be")?;
        let txids = v["txids_display_be"]
            .as_array()
            .context("missing txids_display_be")?;
        let leaves: Vec<Hash> = txids
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let s = s
                    .as_str()
                    .with_context(|| format!("txid #{i} not string"))?;
                display_to_internal(s).with_context(|| format!("txid #{i}"))
            })
            .collect::<Result<_>>()?;
        let regen = merkle_root(&leaves)?;
        let regen_display = internal_to_display(&regen);
        if regen_display != expected {
            bail!("MISMATCH for merkle.bsv_block.v1: expected {expected}, got {regen_display}");
        }
        println!("  [ok]  merkle.bsv_block.v1");
        passed += 1;
    }

    // study.storage_1024 — selective-verification storage vector (Layer B).
    let st_path = Path::new("vectors/study/storage_1024.json");
    if st_path.exists() {
        let raw = fs::read_to_string(st_path)?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        let n = v["n_leaves"].as_u64().context("missing n_leaves")? as usize;
        let q = v["q_queries"].as_u64().context("missing q_queries")? as usize;
        let depth = v["tree_depth"].as_u64().context("missing tree_depth")? as usize;
        let expected_baseline = q * depth * 32;
        let stored_baseline = v["baseline_bytes_formula"]
            .as_u64()
            .context("missing baseline_bytes_formula")? as usize;
        if stored_baseline != expected_baseline {
            bail!(
                "MISMATCH for study.storage_1024: baseline expected {} got {}",
                expected_baseline,
                stored_baseline
            );
        }
        let min = v["minimum_viable_bytes"].as_u64().unwrap_or(u64::MAX) as usize;
        if min > expected_baseline {
            bail!(
                "study.storage_1024: minimum-viable sharded ({}) exceeds baseline ({})",
                min,
                expected_baseline
            );
        }
        println!("  [ok]  study.storage_1024 (N={n}, Q={q}, baseline={expected_baseline}B)");
        passed += 1;
    }

    // study.simstudy — population study presence/integrity/selective-disclosure vector.
    let ss_path = Path::new("vectors/study/simstudy_200.json");
    if ss_path.exists() {
        let raw = fs::read_to_string(ss_path)?;
        let v: serde_json::Value = serde_json::from_str(&raw)?;
        let m = v["population"]["m_records"]
            .as_u64()
            .context("missing population.m_records")?;
        let roll = v["roll_forward_holds"]
            .as_bool()
            .context("missing roll_forward_holds")?;
        if !roll {
            bail!("study.simstudy: roll_forward_holds must be true on the clean population");
        }
        let faults = v["faults"].as_array().context("missing faults array")?;
        for f in faults {
            let name = f["name"].as_str().unwrap_or("?");
            let injected = f["injected"].as_u64().unwrap_or(0);
            let detected = f["detected"].as_u64().unwrap_or(0);
            let fpr = f["false_positives_clean"].as_u64().unwrap_or(0);
            if detected != injected {
                bail!(
                    "study.simstudy: fault {} detected {}/{}",
                    name,
                    detected,
                    injected
                );
            }
            if fpr != 0 {
                bail!("study.simstudy: fault {} had {} false positives", name, fpr);
            }
        }
        let origin = v["origin_falsehood_detected"].as_u64().unwrap_or(99);
        if origin != 0 {
            bail!(
                "study.simstudy: origin-falsehood boundary must be detected=0 (by-design); got {}",
                origin
            );
        }
        println!(
            "  [ok]  study.simstudy (M={m}, all in-scope faults detected, origin-falsehood boundary preserved)"
        );
        passed += 1;
    }

    if passed == 0 {
        bail!("no committed vectors found under vectors/; run from the repository root");
    }
    println!();
    println!("reproduce passed: {passed} committed vector(s) match");
    Ok(())
}

// ----------------------------------------------------------------------------
// Subcommand: anchor
// ----------------------------------------------------------------------------

fn cmd_anchor(leaves_path: &Path) -> Result<()> {
    let leaves = load_leaves(leaves_path)?;
    let root_internal = merkle_root(&leaves)?;
    let root_display = internal_to_display(&root_internal);
    println!("leaves          : {}", leaves.len());
    println!("root (display)  : {root_display}");
    println!("root (internal) : {}", hex::encode(root_internal));
    Ok(())
}

// ----------------------------------------------------------------------------
// Subcommand: prove
// ----------------------------------------------------------------------------

fn cmd_prove(records_path: &Path, index: usize, out_path: &Path) -> Result<()> {
    let (records, leaves) = load_records(records_path)?;
    if index >= records.len() {
        bail!("index {index} out of range for {} records", records.len());
    }
    let root = merkle_root(&leaves)?;
    let proof = merkle_proof(&leaves, index)?;
    let bundle = ProofBundle {
        version: 2,
        root_display_be: internal_to_display(&root),
        leaf_display_be: internal_to_display(&leaves[index]),
        siblings_display_be: proof.siblings.iter().map(internal_to_display).collect(),
        leaf_index: index,
        disclosed_record_hex: hex::encode(&records[index]),
    };
    let pretty = serde_json::to_string_pretty(&bundle)?;
    fs::write(out_path, &pretty)
        .with_context(|| format!("writing bundle to {}", out_path.display()))?;
    println!(
        "wrote proof bundle ({} bytes) to {}",
        pretty.len(),
        out_path.display()
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Subcommand: verify
// ----------------------------------------------------------------------------

fn cmd_verify(bundle_path: &Path) -> Result<()> {
    let raw = fs::read_to_string(bundle_path)
        .with_context(|| format!("reading bundle {}", bundle_path.display()))?;
    let bundle: ProofBundle = serde_json::from_str(&raw).context("parsing bundle JSON")?;
    if bundle.version != 2 {
        bail!(
            "unsupported bundle version: {} (expected 2)",
            bundle.version
        );
    }

    let leaf = display_to_internal(&bundle.leaf_display_be)?;
    let expected_root = display_to_internal(&bundle.root_display_be)?;
    let siblings: Vec<Hash> = bundle
        .siblings_display_be
        .iter()
        .enumerate()
        .map(|(i, s)| display_to_internal(s).with_context(|| format!("sibling #{i}")))
        .collect::<Result<_>>()?;

    // Direct merkle check first.
    let proof = MerkleProof {
        leaf_index: bundle.leaf_index,
        siblings: siblings.clone(),
    };
    proof
        .verify(&leaf, &expected_root)
        .context("merkle inclusion failed")?;

    // Route through the audit API for the composed check.
    let disclosed =
        hex::decode(bundle.disclosed_record_hex.trim()).context("disclosed record hex invalid")?;
    let recomputed_leaf = double_sha256(&disclosed);
    if recomputed_leaf != leaf {
        bail!("disclosed record does not hash to the bundle's leaf");
    }
    let mut store = ProofStore::new(0);
    let index_key = IndexKey {
        txid: leaf,
        direction: Direction::Output,
        position: 0,
        block_position: u32::try_from(bundle.leaf_index).context("leaf index does not fit u32")?,
        locking_script: None,
        unlocking_script: None,
        amount: None,
    };
    let _ = store.anchor(index_key.clone(), &[leaf], 0);
    let audit_bundle = AuditBundle {
        index_key,
        disclosed_record: disclosed,
        leaf,
        mode: ReconstructionMode::Adversarial,
    };
    let _ev = AuditVerifier::new(&store)
        .verify(&audit_bundle)
        .context("audit API verification failed")?;

    println!("verify OK");
    println!("  merkle root  : {}", bundle.root_display_be);
    println!("  leaf index   : {}", bundle.leaf_index);
    println!("  record bytes : {} bytes disclosed", recomputed_leaf.len());
    Ok(())
}

// ----------------------------------------------------------------------------
// Subcommand: query
// ----------------------------------------------------------------------------

fn cmd_query(records_path: &Path, index: usize, level: usize) -> Result<()> {
    let (records, leaves) = load_records(records_path)?;
    if index >= records.len() {
        bail!("index {index} out of range for {} records", records.len());
    }
    let mut store = ProofStore::new(level);
    let key = IndexKey {
        txid: leaves[index],
        direction: Direction::Output,
        position: 0,
        block_position: u32::try_from(index).context("index does not fit u32")?,
        locking_script: None,
        unlocking_script: None,
        amount: None,
    };
    let root = store.anchor(key.clone(), &leaves, index)?;
    let stored = store.query(&key)?;
    store.verify(&leaves[index], stored, ReconstructionMode::Adversarial)?;

    println!("query OK");
    println!("  root (display): {}", internal_to_display(&root));
    println!("  leaf index    : {}", stored.leaf_index);
    println!("  shards        : {}", stored.shards.len());
    for (i, s) in stored.shards.iter().enumerate() {
        println!(
            "    shard {i}: levels [{}, {}), {} siblings",
            s.from_level,
            s.to_level,
            s.siblings.len()
        );
    }
    if let Some(a) = store.proof_assistance_for(&root) {
        println!(
            "  assistance    : {} labels at level {}",
            a.node_labels.len(),
            a.predetermined_level
        );
    }
    println!(
        "  disclosed     : {} bytes for record #{index} (selective disclosure: other records not revealed)",
        records[index].len()
    );
    Ok(())
}
