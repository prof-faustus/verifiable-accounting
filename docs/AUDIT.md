# Audit status and formal-verification notes

This document is the canonical statement of what review the codebase has and has not received. It is updated as audit and verification milestones are reached.

## Current status (v0.2.x)

**No third-party cryptographic audit has been performed.** This is a sole-author reference implementation; consumers planning a production deployment should commission an independent review before relying on it.

### What has been done (self-certification)

| Layer | Self-certification |
|---|---|
| `vaa-bsv` (double-SHA256) | Known-vector test against the SHA-256(SHA-256("")) constant. |
| `vaa-merkle` (BSV block Merkle) | 24 tests: known small-tree cases (1 / 2 / 3 / 4 / 7 / 8 leaves), the BSV genesis single-leaf root, **a real BSV mainnet block at height 170 with the published merkleroot reconstructed bit-for-bit**, 5 property tests covering round-trip, depth-bound, leaf-tamper, sibling-tamper, root-change, and 7 adversarial cases (wrong index, wrong root, wrong leaf, truncated path, extra sibling, tampered sibling, panic-safety on `usize::MAX` index and over-long proof). |
| `vaa-commit` (Pedersen on secp256k1) | 29 tests: open round-trip, binding, hiding, homomorphic tally including the `Net + Tax = Gross + Discount` equation, group-order boundary (`n` rejected, `n - 1` accepted), zero-blinding rejection (rejected at `from_bytes`, `TryFrom`, **and** the `serde` deserialise path), 7 property tests, redacted `Debug` impl with a regression test, 33-byte serialisation round-trip with garbage-input rejection. |
| `vaa-proofstore` (selective verification) | 17 tests covering anchor + query + verify in both adversarial and assistance-based reconstruction, non-overlapping shard structure, shard-tamper detection, assistance-label tampering, distinct-index-key resolution. |
| `vaa-zk` (Σ + Bulletproofs) | 7 tests: linear-equation tally including the invoice-total and debit/credit identities; range-proof round-trip, wrong-commitment rejection, serialisation round-trip, garbage-bytes rejection. |
| `vaa-accounting` (five equations) | 10 tests: correctness and off-by-one rejection for `InvoiceTotal`, `ArRollForward`, `DebitsCredits`, `BankReconciliation`, `VatPayable`. |
| `vaa-api` (composition layer) | 7 tests: happy paths with and without range proofs; rejection of non-adversarial mode at the audit surface, unknown index key, wrong leaf, wrong opening, wrong-commitment range proof. |

**Aggregate:** 95 tests passing, zero ignored, on Windows MSVC and on GitHub Actions Linux. `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` are also enforced on every push.

### What has NOT been done

| Item | Status |
|---|---|
| Independent cryptographic audit | Not commissioned. Hire a recognised firm before any production reliance. |
| Formal verification (Coq / Lean / TLA+ / Cryptol) | None. See "Properties worth formalising" below. |
| Side-channel analysis (timing, power, EM) | None. The Rust code does not introduce secret-dependent branching; the underlying `libsecp256k1` and `libsecp256k1-zkp` are designed with constant-time primitives but have not been re-audited against this specific composition. |
| Fuzzing (libfuzzer, AFL++, cargo-fuzz) | None. A fuzz harness around `Commitment::from_bytes`, `RangeProof::from_bytes`, `MerkleProof::verify`, and `vaa anchor` JSON parsing is the obvious next step. |
| Concurrency / TOCTOU review | Not applicable in v0.2 (single-threaded, no shared mutable state outside the OnceLock caches in `vaa-commit`). |
| Memory-safety audit | `#![forbid(unsafe_code)]` is set in every implemented crate. The transitively-pulled `libsecp256k1-zkp` C library is the only path to unsafe code. |

## Vetted external primitives (project assumptions)

The project relies on but does not audit:

| Library | What we use | Trust basis |
|---|---|---|
| `sha2` (RustCrypto) | SHA-256 used inside BSV double-SHA256. | RustCrypto suite, broadly reviewed. |
| `libsecp256k1` (Bitcoin Core) via the `secp256k1` Rust crate | secp256k1 curve operations, ECDSA, ECDH. | The reference implementation used by Bitcoin Core; the most-reviewed secp256k1 implementation in existence. |
| `libsecp256k1-zkp` (Blockstream) via the `secp256k1-zkp` Rust crate | Pedersen commitments, Bulletproofs range proofs, generator construction. | Production-deployed in Liquid (Blockstream) and Grin (Mimblewimble). Less reviewed than `libsecp256k1` proper but the most mature secp256k1-Bulletproofs implementation available. |

If any of these libraries is found to have a vulnerability that affects this codebase, it propagates through this codebase unchanged. The vulnerability-tracking job in `.github/workflows/ci.yml` runs `cargo-audit` on every push (non-blocking) to surface advisories.

## Properties worth formalising

The following invariants are good targets if formal verification is pursued (in roughly increasing difficulty):

1. **Merkle proof verification soundness.** For any `(leaves, index)` with `index < leaves.len()`, `merkle_proof(leaves, index).verify(leaves[index], merkle_root(leaves)) = Ok(())`, and for any `(leaves, index, altered)` with `altered != leaves[index]`, the same `verify` returns `Err(RootMismatch)`. Already empirically established by the property-test suite; a paper proof under the assumption that double-SHA256 is collision-resistant is straightforward.
2. **Pedersen hiding and binding.** Standard reductions from the discrete-log assumption on secp256k1. Documented in the cryptography literature; this codebase's contribution is only that it correctly invokes the library.
3. **Σ-protocol soundness for `LinearEquation`.** Soundness reduces to the binding of Pedersen and the homomorphism: if `Σ_pos c_i ≠ Σ_neg c_j` over the openings, then the elliptic-curve sum differs and `verify_sum_equal` returns false. The codebase establishes this empirically via the off-by-one rejection tests in `vaa-accounting`.
4. **Bulletproofs zero-knowledge and soundness.** Established in Bünz et al. (2018). The codebase relies on the implementation in `libsecp256k1-zkp`.
5. **Selective-verification reconstruction soundness.** If `verify_with_assistance` accepts, then there exists a chain of double-SHA256 hashes from the leaf to the anchored root via the published level-k labels. Equivalent to a paired statement of Merkle soundness + label-publication integrity.

## Reporting a vulnerability

See `SECURITY.md`. Private disclosure address: `cw881@exeter.ac.uk`. Public GitHub issues for security bugs are discouraged.

## Audit log

| Date | Reviewer | Scope | Outcome |
|---|---|---|---|
| 2026-05-30 | (sole author) | Self-review against this checklist. | All test gates green; recorded above. |
| — | — | (Awaiting an independent reviewer.) | — |
