# Verifiable Accounting Arithmetic

Reference implementation of the architecture described in the manuscript "Verifiable Accounting Arithmetic Without Disclosure," International Journal of Accounting Information Systems. The system proves, without disclosing the underlying figures, that committed accounting values are anchored on the BSV blockchain, are selectively retrievable, and satisfy the standard accounting equations.

This repository is the artefact cited by the paper. It must regenerate every numeric value the paper reports.

> **Status:** v0.2. Every layer is implemented end-to-end. `bsv`, `merkle`, `commit`, `proofstore`, `zk`, `accounting`, `api`, and `cli` all carry tests and clean clippy. Real Bulletproofs range proofs from `libsecp256k1-zkp` wired through `vaa-zk`; five linear accounting equations in `vaa-accounting`; single-call audit verification in `vaa-api`; criterion benchmarks under each crate's `benches/`.

## Three-layer assurance stack

1. **Merkle proof entity** (presence). A target transaction is included in a BSV block Merkle tree, verified by rehashing along the path from leaf to anchored block-header root. Implements WO 2022/100946 A1 "Merkle Proof Entity."
2. **Selective verification / proof-sharding** (availability). Merkle proof data is generated, stored, divided into non-overlapping portions, and indexed against an on-chain proof-assistance schema, so a verifier can retrieve only the fragment needed for a query. Implements WO 2025/119666 A1 "Method and System for Enabling Verification of Data."
3. **Zero-knowledge accounting arithmetic** (private correctness). Committed accounting values are proven to satisfy invoice totals, receivables roll-forward, debit=credit, bank reconciliation, and VAT identities, without disclosing the values themselves. Σ-protocols on Pedersen commitments for the linear equations; Bulletproofs from `libsecp256k1-zkp` for range / validity proofs.

Verification always terminates in a BSV public anchor or block Merkle root, never in the proof server. The proof server is an *availability and retrieval* service, not a trust anchor.

## Target platform

BSV (Bitcoin SV). Fixed, not configurable. Hash is double-SHA256, Merkle tree is the BSV block tree with the standard odd-node duplication rule, txids are big-endian for display / little-endian internal. The selective-verification index schema maps directly onto BSV's UTXO model (txid, input/output position, in/out flag, locking script, unlocking script, amount, block position). Accounting commitment roots are anchored in BSV data-carrier outputs; the exact data-output convention is recorded in `docs/DECISIONS.md`.

## Two assurance modes

This implementation exposes both modes the selective-verification patent identifies, and enforces the boundary between them:

| Mode | Reconstruction | Use | Default |
|---|---|---|---|
| **Adversarial audit** | Ordinary Merkle reconstruction against public node labels and the on-chain root. | Independent audit evidence. The only mode that yields adversarially-sound verification. | **On.** |
| **Trusted operational** | EC-point homomorphic compression of proof-assistance data (claims 9–11 of WO 2025/119666). | Internal efficiency / error detection inside a trusted operational environment. | **Off.** Opt-in only via an explicit API flag. |

> **Warning.** The trusted operational mode is **not** adversarially secure and is **not** equivalent to audit-mode verification. It must never be relied upon as audit evidence. The API rejects silent selection of this mode.

## Stack

Single-language Rust workspace. Crypto floor is `libsecp256k1` + `libsecp256k1-zkp` via their Rust bindings. Eight crates:

| Crate | Responsibility |
|---|---|
| `bsv` | BSV-specific types: txid, block header, transaction, script, data-carrier output convention, SPV header-chain glue. |
| `merkle` | Merkle Proof Entity construction, proof generation, and verification per WO 2022/100946 A1. BSV double-SHA256 and odd-node duplication. |
| `proofstore` | Selective-verification layer per WO 2025/119666 A1: non-overlapping proof sharding, the index schema (claims 5–6), proof-assistance node publication (claim 8), query/retrieval (claim 12), and the optional EC-compression trusted mode. |
| `commit` | Pedersen commitments on secp256k1 via `secp256k1-zkp`. |
| `zk` | Σ-protocols for the linear accounting equations; range / validity proofs via `secp256k1-zkp` Bulletproofs. |
| `accounting` | Equation definitions (Gross/Net/Tax, AR roll-forward, debit=credit, bank reconciliation, VAT), encodings, validity rules. |
| `api` | Verifier-facing query → presence → retrieval → arithmetic → range → selective opening → result. |
| `cli` | `vaa` binary: `selftest`, `reproduce`, anchor, prove, verify, query. |

## Quickstart

```
git clone https://github.com/prof-faustus/verifiable-accounting
cd verifiable-accounting
cargo build --workspace --release
cargo test  --workspace
cargo run -p vaa-cli -- --help
```

Six end-to-end CLI commands (every one exercises real crypto):

```
cargo run -p vaa-cli -- selftest
cargo run -p vaa-cli -- reproduce
cargo run -p vaa-cli -- anchor   --leaves examples/sample_leaves.json
cargo run -p vaa-cli -- prove    --leaves examples/sample_leaves.json --index 2 \
                                 --value 100000 \
                                 --blinding-hex 0707070707070707070707070707070707070707070707070707070707070707 \
                                 --out examples/sample_bundle.json
cargo run -p vaa-cli -- verify   --bundle examples/sample_bundle.json
cargo run -p vaa-cli -- query    --leaves examples/sample_leaves.json --index 2 --level 1
```

Reproduce every committed vector:

```
cargo run -p vaa-cli --release -- reproduce
```

Runs the deterministic-vector check (currently `merkle.genesis.v1` and `commit.h_tag.v1`); exits non-zero on any mismatch. CI runs the same command on every push.

Run the criterion benchmark suite (median + IQR; no transactions-per-second extrapolated):

```
cargo bench --workspace
```

## What this proves and what it does not

The system establishes, over committed accounting values:

- inclusion (the transaction is in the anchored BSV block),
- integrity (the commitment binds the value),
- retrievability (the indexed proof fragment is recoverable from the proofstore),
- arithmetic correctness (the equations hold over the committed values),
- range validity (the values are within their declared bounds).

It does **not** prove:

- that the values are truthful or that any economic event occurred (the garbage-in boundary),
- that classification or recognition is correct,
- that the population is complete absent population controls,
- that anything is legally enforceable.

These boundaries are stated in code and in `docs/SECURITY.md`.

## Documentation

- `docs/ARCHITECTURE.md` — three-layer stack, the two patents' roles, crate boundaries.
- `docs/DECISIONS.md` — stack and crypto choices, BSV library pinning, data-output convention.
- `docs/SECURITY.md` — threat model: proof-store adversary, public-medium adversary, metadata leakage, trusted-setup governance.
- `docs/REPRODUCIBILITY.md` — exact commands to regenerate every paper number.
- `docs/AUDIT.md` — current audit status, what's been self-certified, what would benefit from third-party review.

## Examples

- `examples/sample_leaves.json` / `examples/sample_bundle.json` — toy 8-leaf sample for the quickstart commands.
- `examples/realistic_quarter/` — a complete Q2-2026 close for a hypothetical BSV-billing firm (48 invoices, 43 payments, credit notes, write-offs) with 93 leaves and a verifiable proof bundle.
- `examples/integration/README.md` — integration overview for the two sister repos.
- `examples/integration/tea-anchor.md` — anchoring triple-entry-evidence note batches.
- `examples/integration/channel-verify.md` — verifying bonded-subsat-channel settlement inclusion.
- `examples/integration/bridge.py` — runnable Python bridge with `demo-tea`, `demo-channel <height>`, and `from-channel-ledger <path>` subcommands.
- `examples/integration/full_stack_demo.py` — single-command end-to-end run (channel → TEA → vaa → live BSV-block check).

## Docker

```sh
docker build -t vaa:v0.3.0 .
docker run --rm vaa:v0.3.0 selftest
docker run --rm vaa:v0.3.0 reproduce
```

The image is built from `Dockerfile` (multi-stage; Rust toolchain in the build stage, slim Debian runtime with the `vaa` binary as entrypoint). Vectors and example data are bundled at `/opt/vaa/{vectors,examples}` so `reproduce` works without mounting anything.

## Pre-built binaries

Each `v*.*.*` tag triggers the release workflow (`.github/workflows/release.yml`) which builds `vaa` for Linux x86_64, macOS aarch64, and Windows x86_64 and uploads the archives to the GitHub Release.

## Security & Disclaimer

This software is provided **as-is, without warranty of any kind, express or implied**, including but not limited to merchantability, fitness for a particular purpose, and non-infringement. See `LICENSE` for the full terms.

**Cryptographic primitives** come from `libsecp256k1` and `libsecp256k1-zkp` (Pedersen commitments, Bulletproofs) and the `RustCrypto` `sha2` crate (BSV double-SHA256). No curve arithmetic or hash primitive is implemented in this codebase. The author has audited the integration of these libraries but has not audited the libraries themselves; consumers should perform their own due diligence before any production deployment.

**Security boundary.** The system proves, over committed accounting values, that:
- the relevant transaction is included in the anchored BSV block (presence),
- committed values bind to their openings (integrity),
- the indexed proof fragment is retrievable from the proofstore (retrievability),
- declared equations hold over the committed values (arithmetic correctness),
- values are within their declared bounds (range validity).

It does **not** prove:
- that the values are truthful or that any economic event occurred (the *garbage-in* boundary — collusively-recorded false-origin commitments are out of scope by design),
- that classification, recognition, or accounting judgement is correct,
- that the population is complete absent explicit population controls,
- that anything is legally admissible or enforceable in any jurisdiction.

**Two assurance modes.** The default reconstruction mode (`Adversarial`) is the only mode that yields independent audit evidence. The opt-in `TrustedOperational` mode (EC-point compression per WO 2025/119666 claims 9–11) is for internal efficiency in trusted environments only and is **not** adversarially secure; the API rejects results from that mode in any audit-facing surface.

**Vulnerability reporting.** Please report suspected security issues privately by email to `cw881@exeter.ac.uk`, not via public GitHub issues. The full disclosure policy and threat model are in `SECURITY.md` and `docs/SECURITY.md`.

**Patents.** Two PCT publications underlie the BSV-anchoring and selective-verification layers (WO 2022/100946 A1; WO 2025/119666 A1). They are cited as prior-art technical disclosures, not as peer-reviewed work, and the academic novelty claimed by this repository is only in the integration and the accounting layer, never in the underlying mechanisms.

## Citing this artefact

Code is licensed under MIT (see `LICENSE`). Every source file carries the SPDX identifier `MIT` at the top. If you build on this code for academic work, please cite the paper above. The GitHub release tagged for the camera-ready paper version will be archived to Zenodo for a citable DOI.

## Author

Craig Wright
University of Exeter
ORCID: 0000-0001-9374-0507
Email: cw881@exeter.ac.uk

## License

MIT. See `LICENSE`.
