# Architecture

This document is the architectural reference engineers should read first when working in the codebase.

## Two layers over BSV

The live system implements exactly two methods over BSV, plus the application layers that turn them into accounting evidence infrastructure.

```
                ┌─────────────────────────────────────────────┐
                │  Verifier-facing API / CLI                  │   api / cli
                ├─────────────────────────────────────────────┤
                │  Accounting equations (recomputation)       │   accounting
                ├─────────────────────────────────────────────┤
   Layer B      │  Selective Verification / proof-sharding    │   proofstore
                ├─────────────────────────────────────────────┤
   Layer A      │  Merkle Proof Entity (BSV block Merkle)     │   merkle
                ├─────────────────────────────────────────────┤
                │  BSV double-SHA256 primitive                │   bsv
                └─────────────────────────────────────────────┘
                                       ↓ anchors to
                              BSV block header chain
```

Verification climbs from a verifier query at the top down to a BSV block-header Merkle root at the bottom. The proof server lives in the `proofstore` layer; it serves **availability**, never trust. **No verifier ever accepts a result that has not terminated in a BSV-anchored Merkle root.**

## Layer A — Merkle Proof Entity (`merkle` + `bsv`)

Implements **WO 2022/100946 A1**.

- Node rule: `N(i, j) = H(D_i)` for leaves; `N(i, j) = H(N(i, k) || N(k+1, j))` for internal.
- `H` = BSV double-SHA256. Fixed. Provided by `bsv::hash::double_sha256`.
- Odd-node duplication rule (BSV convention): when a level has an odd count, the last node is concatenated with itself before hashing.
- Merkle proof = `(leaf_index, ordered Vec<Hash>)`. The index bits drive sibling ordering at each level.
- Verification recomputes the root from the leaf + path; accepts iff it matches the anchored root.
- Tests include round-trip property tests against random trees and reconstruction against real BSV mainnet block Merkle roots committed under `/vectors/merkle/`.

## Layer B — Selective Verification (`proofstore`)

Implements **WO 2025/119666 A1**, claims 1–12.

| Claim | What the crate exposes |
|---|---|
| 1 | `ProofStore::anchor(IndexKey, leaves, leaf_index) → Hash` (Merkle root, anchored on BSV by the caller) |
| 2–3 | `ProofShard` type; non-overlapping division of the Merkle path |
| 4 | Index built from the same on-chain attributes used to publish proof-assistance |
| 5–6 | Index schema fields: txid, in/out flag, in/out position, locking script, unlocking script, amount (minor units), block-position |
| 7 | The function used to determine the proof is the BSV Merkle hash; documented as fixed |
| 8 | `ProofAssistance` = node labels at the predetermined level (public on BSV; verifier reconstructs from there up) |
| 9–11 | Optional homomorphic compression of the level-`k` labels on the BSV curve — trusted-environment mode only |
| 12 | `ProofStore::query(index_key) → &StoredProof` returns only the queried record's fragment |

### The privacy mechanism

Selective disclosure is the privacy mechanism. A query for one record returns the disclosed record's bytes + the opaque sibling hashes on its path to the BSV-anchored root. Nothing about any other anchored record is revealed beyond those opaque siblings. No hidden-value cryptography of any kind is added in the live tree — only BSV double-SHA256 Merkle hashing.

### Two assurance modes

`ReconstructionMode::Adversarial` (default) — verify by recomputing the Merkle path against published node labels and the on-chain root. **The only mode the audit API exposes.**

`ReconstructionMode::TrustedOperational` (opt-in) — verify using homomorphic compression of the proof-assistance data on the BSV curve. Faster, easier to manipulate, not adversarially secure. Selecting this mode requires an explicit `mode = TrustedOperational` argument on the API; there is no silent fallback. The audit API rejects results from this mode.

## Application layer (`accounting` + `api` + `cli`)

### `accounting`

Five named equations, each verified by direct recomputation over disclosed `u64` records:

- `InvoiceTotal`: `Gross = Net + Tax − Discount`
- `ArRollForward`: `AR_close = AR_open + Invoices − Receipts − CreditNotes − WriteOffs`
- `DebitsCredits`: `Σ Debits = Σ Credits`
- `BankReconciliation`: `BookCash + Σ ReconcilingItems = BankBalance`
- `VatPayable`: `VAT_payable = OutputVAT − InputVAT`

Overflow is checked via `u64::checked_add`; the library distinguishes "equation does not hold" from "arithmetic overflowed `u64`".

### `api`

`AuditVerifier::verify(bundle)` composes:

1. Reject any non-adversarial reconstruction mode at the audit surface.
2. Recompute `double_sha256(disclosed_record)` and assert it equals the bundle's leaf.
3. Query the proofstore for the stored Merkle proof.
4. Adversarial Merkle reconstruction back to the BSV-anchored root.

Returns `AuditEvidence { merkle_root, leaf_index, disclosed_record }`.

### `cli`

`vaa` binary with the six subcommands: `selftest`, `reproduce`, `anchor`, `prove`, `verify`, `query`.

## Determinism and reproducibility

- Every committed deterministic vector under `/vectors/` is regenerated by the source it documents and asserted by `vaa reproduce`.
- The simulation studies (`simstore`, `simstudy`) use seeded `ChaCha20Rng` and write small-CI-point vectors to `/vectors/study/`; the reproduce harness diffs them on every push.
- Wall-clock timings are reported as crypto-core/local on stated hardware; no throughput figure is extrapolated.

## What this system does not do

These boundaries are stated as code-level assertions and in `docs/SECURITY.md`:

1. The system does not prove values are truthful or that any economic event occurred.
2. It does not detect a record entered falsely **at origin** in an internally consistent population. The boundary is asserted by an explicit negative test that must not flip to "detected"; do not paper over it.
3. It does not bind classification, recognition, or population-completeness judgements.
4. It makes no claim of legal admissibility in any jurisdiction.
