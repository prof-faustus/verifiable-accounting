# Architecture

This document records the layer model of the system and the role of each crate. It is the architectural reference engineers should read first when working in the codebase.

## Three-layer assurance stack

```
                ┌─────────────────────────────────────────────┐
                │  Verifier-facing API / CLI                  │   api / cli
                ├─────────────────────────────────────────────┤
                │  Accounting equations + encodings + rules   │   accounting
                ├─────────────────────────────────────────────┤
   Layer 3 — ZK │  Σ-protocols + Bulletproofs range proofs    │   zk
                ├─────────────────────────────────────────────┤
                │  Pedersen commitments on secp256k1          │   commit
                ├─────────────────────────────────────────────┤
   Layer 2 — PS │  Selective verification / proof-sharding    │   proofstore
                ├─────────────────────────────────────────────┤
   Layer 1 — MP │  Merkle Proof Entity (BSV block Merkle)     │   merkle
                ├─────────────────────────────────────────────┤
                │  BSV types (txid, header, tx, script, SPV)  │   bsv
                └─────────────────────────────────────────────┘
                                       ↓ anchors to
                              BSV block header chain
```

Verification climbs from a verifier query at the top down to a BSV block-header root at the bottom. The proof server lives in the `proofstore` layer; it serves availability, never trust. **No verifier ever accepts a result that has not terminated in a BSV-anchored Merkle root.**

## Layer 1 — Merkle Proof Entity (`merkle` + `bsv`)

Implements **WO 2022/100946 A1**.

- Node rule: `N(i,j) = H(D_i)` for leaves; `N(i,j) = H(N(i,k) || N(k+1,j))` for internal.
- `H` = BSV double-SHA256. Fixed. Provided by `bsv::hash::double_sha256`.
- Odd-node duplication rule (BSV/Bitcoin convention): when a level has an odd count, the last node is concatenated with itself before hashing.
- Merkle proof = `(leaf_index, ordered Vec<Hash>)`. The index bits drive sibling ordering at each level.
- Verification recomputes the root from the leaf + path; accepts iff it matches the anchored root.
- Tests include round-trip property tests against random trees and reconstruction against real BSV block Merkle roots checked into `/vectors`.

The `bsv` crate carries the consensus-sensitive types (`Txid`, `BlockHeader`, `Transaction`, `Script`, endianness conversions) and the SPV header-chain check.

## Layer 2 — Selective verification / proof-sharding (`proofstore`)

Implements **WO 2025/119666 A1**, claims 1–12.

| Claim | What the crate exposes |
|---|---|
| 1 | `ProofStore::generate_and_store(tx_part) → ProofHandle` |
| 2–3 | `ProofShard` type; non-overlapping division of the Merkle path |
| 4 | Index built from the third-data fields published on chain |
| 5–6 | Index schema fields: txid, in/out flag, in/out position, locking script, unlocking script, amount, block-position |
| 7 | `ThirdData` = function(s) used to determine the proof |
| 8 | `ProofAssistance` = node labels at a predetermined level (public; verifier reconstructs from there up) |
| 9–11 | Optional `EcCompressed` form (sum of EC points at the predetermined level) — trusted operational mode only |
| 12 | `ProofStore::query(index_key) → Vec<ProofShard>` |

### Two assurance modes

`ReconstructionMode::Adversarial` (default) — verify by recomputing the Merkle path against published node labels and the on-chain root. **The only mode the audit API exposes.**

`ReconstructionMode::TrustedOperational` (opt-in) — verify using EC-point compression. Faster, easier to manipulate, not adversarially secure. Selecting this mode requires an explicit `mode = TrustedOperational` argument on the API; there is no silent fallback. The `audit` API rejects results from this mode.

## Layer 3 — ZK accounting arithmetic (`commit` + `zk` + `accounting`)

### `commit`
Pedersen commitments on secp256k1: `C(v, r) = v·G + r·H`. The second generator `H` is a NUMS point derived by hash-to-curve from a fixed domain-separation string; the derivation is documented and tested. Uses `libsecp256k1-zkp` for curve operations. No hand-rolled arithmetic.

### `zk`
- **Σ-protocols on Pedersen commitments** for linear equations. The accounting equations defined in `crates/accounting/src/lib.rs` are all linear over committed values, so equation proofs reduce to proofs of knowledge of openings whose blinding factors satisfy a linear relation. Fiat–Shamir for non-interactivity.
- **Range / validity proofs** via `secp256k1-zkp` Bulletproofs (transparent setup; no ceremony).
- Validity rules (tax-rate in authorised set, period in valid set, no double-use, disclosed value matches commitment) are encoded as either range proofs or set-membership Σ-protocols.

### `accounting`
- Equation library: `Gross = Net + Tax − Discount`, AR roll-forward, debit=credit, bank reconciliation, VAT.
- Encodings: how each accounting value (currency, period, account) maps to committed scalars.
- Validity rules: tax-rate set membership, currency bounds, sign convention, double-use prevention.

## Verifier-facing layer (`api` + `cli`)

`api` is the programmatic verifier interface: query → presence → retrieval → arithmetic → range → selective opening → result + residual assertions. Each step produces evidence the caller can store in their working papers.

`cli` is the `vaa` binary: `vaa selftest`, `vaa reproduce`, `vaa anchor`, `vaa prove`, `vaa verify`, `vaa query`.

## Determinism and reproducibility

- `commit` uses ChaCha-seeded blinding factors when called from the reproduction harness, so test vectors are bit-deterministic.
- `cargo run -p cli --release -- reproduce` regenerates every committed vector under `/vectors`, builds the benchmark tables under `/bench`, and diffs them against expected outputs. Non-zero exit on any mismatch.
- CI runs `reproduce` on every push.

## What this system does not do

These boundaries are stated as code-level assertions and in `docs/SECURITY.md`:

1. The system does not prove values are truthful or that any economic event occurred.
2. It does not detect collusively-recorded false-origin commitments. This boundary is asserted by an explicit negative test that must fail; do not paper over it.
3. It does not bind classification, recognition, or population-completeness judgements.
4. It makes no claim of legal admissibility in any jurisdiction.
