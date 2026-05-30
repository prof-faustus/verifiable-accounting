# Audit status and formal-verification notes

This document is the canonical statement of what review the codebase has and has not received. It is updated as audit and verification milestones are reached.

## Current status

**No third-party audit has been performed.** This is a sole-author reference implementation; consumers planning a production deployment should commission an independent review before relying on it.

### Self-certification by layer

| Layer | Self-certification |
|---|---|
| `vaa-bsv` (BSV double-SHA256) | Known-vector test against the SHA-256(SHA-256("")) constant. |
| `vaa-merkle` (BSV block Merkle tree, Layer A) | Tests for the single-leaf root convention, the BSV genesis vector, a real BSV mainnet multi-transaction block reconstructed bit-for-bit (`vectors/merkle/bsv_block_v1.json`), property tests for round-trip, depth-bound, leaf/sibling/root tamper detection, and adversarial cases for wrong index, wrong root, truncated path, extra sibling, panic-safety on `usize::MAX` index. |
| `vaa-proofstore` (Selective Verification, Layer B) | Tests covering anchor + query + verify in both reconstruction modes, non-overlapping shard structure, shard-tamper detection, assistance-label tampering, distinct index-key resolution. |
| `vaa-accounting` (five equations, recomputation) | Tests for each equation's correctness and off-by-one rejection; explicit `u64` overflow detection. |
| `vaa-api` (composition layer) | Tests for the happy path; rejection of non-adversarial mode at the audit surface, unknown index key, wrong leaf, disclosed record that does not hash to the claimed leaf. |
| `vaa-simstore` (storage / retrieval study) | Asserts the sharded byte count never exceeds the naive baseline; asserts adversarial soundness at scale; writes deterministic vectors checked by `vaa reproduce`. |
| `vaa-simstudy` (population study) | Asserts the AR roll-forward identity over the synthetic clean population, zero false positives on the clean population, and full detection of every in-scope fault class (altered/omitted/duplicated record, tampered leaf, wrong index, wrong root). Records the origin-falsehood boundary as **not detected** (by design). |

CI runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `vaa reproduce` on every push.

### What has NOT been done

| Item | Status |
|---|---|
| Independent third-party audit | Not commissioned. Hire a recognised firm before production reliance. |
| Formal verification (Coq / Lean / TLA+) | None. |
| Side-channel analysis | The implemented layers do not handle long-lived secrets; the cryptographic primitives in scope are public-input hash composition (SHA-256) over public data. No secret-dependent branching exists in the live tree. |
| Fuzzing (libfuzzer, AFL++, cargo-fuzz) | None. A fuzz harness around `MerkleProof::verify`, `vaa anchor` / `vaa verify` JSON parsing, and the proofstore retrieval surface is the obvious next step. |
| Memory-safety audit | `#![forbid(unsafe_code)]` is set in every live crate. There is no `unsafe` code path. |

## Vetted external primitives

The live tree depends on these external Rust crates only at the project's chosen versions; they are not audited by this project:

| Crate | What we use |
|---|---|
| `sha2` (RustCrypto) | SHA-256 used inside BSV double-SHA256. |
| `serde`, `serde_json`, `ciborium`, `hex`, `hex-literal` | Encoding / serialisation only. |
| `thiserror`, `anyhow` | Error types only. |
| `clap` | CLI argument parsing only. |
| `proptest`, `criterion` | Test / benchmark harnesses only. |
| `rand`, `rand_chacha` | Deterministic seeded RNG for tests and the simulation studies. |

If any of these has an advisory affecting our use, the `cargo-audit` job in CI surfaces it.

## Properties worth formalising

1. **Merkle proof soundness.** For any `(leaves, index)` with `index < leaves.len()`, `merkle_proof(leaves, index).verify(leaves[index], merkle_root(leaves)) = Ok(())`. For any altered leaf or altered sibling, the same `verify` returns `Err(RootMismatch)`. Soundness reduces to collision-resistance of SHA-256.
2. **Selective-verification reconstruction soundness.** If `verify_with_assistance` accepts, there exists a chain of double-SHA256 hashes from the disclosed leaf to the BSV-anchored root via the published level-k labels.
3. **Selective disclosure non-leakage.** A query for record `i` returns exactly the disclosed record `i` bytes + sibling hashes on the path. The sibling hashes are SHA-256-composed and reveal no preimage information about other records' bytes (collision-resistance / one-wayness).

## Reporting a vulnerability

See `SECURITY.md`. Private disclosure address: `cw881@exeter.ac.uk`. Public issues for security bugs are discouraged.

## Audit log

| Date | Reviewer | Scope | Outcome |
|---|---|---|---|
| (latest) | (sole author) | Self-review against this checklist. | All test gates green; recorded above. |
| — | — | (Awaiting an independent reviewer.) | — |
