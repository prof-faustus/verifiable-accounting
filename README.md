# Verifiable Accounting Arithmetic

A BSV-native reference implementation of two methods for anchoring accounting evidence on the BSV public chain and selectively disclosing it for audit:

- **Layer A — Merkle Proof Entity** (WO 2022/100946 A1). Proves a target data item of a BSV transaction is present in a BSV block, via a Merkle proof whose root is the block-header `merkleroot`. Verification rehashes leaf-to-root and terminates in the validated BSV header chain. Double-SHA256, BSV block Merkle tree with the odd-node duplication rule, internal/display byte order handled once and tested against real BSV mainnet blocks.
- **Layer B — Selective Verification** (WO 2025/119666 A1). Makes Layer A proofs available at scale. Generates Merkle proof data, stores it, publishes proof-assistance data on BSV (Merkle node labels at a predetermined tree level), divides proof data into non-overlapping portions, indexes them by BSV transaction attributes (txid, in/out flag, in/out position, position-of-tx-in-block, locking script, unlocking script, amount in minor units), and on a query returns **only** the proof fragment needed to verify that one item. Selective disclosure of the queried fragment **is** the privacy mechanism — nothing about any other anchored record is revealed; no added cryptography is required.

The system proves **presence**, **integrity**, **retrievability**, and **selective disclosure** of accounting evidence anchored on BSV. The five named accounting equations (invoice total, AR roll-forward, debit=credit, bank reconciliation, VAT) are checked by **direct recomputation** over the disclosed records.

## Status

- `bsv`, `merkle`, `proofstore`, `accounting`, `api`, `cli`, `simstore`, `simstudy` — implemented, with tests.
- `vaa reproduce` regenerates the committed deterministic vectors and exits non-zero on any mismatch.
- Real BSV mainnet block data is committed under `vectors/merkle/`; the simulation studies write deterministic outputs to `vectors/study/`.

## Quickstart

```sh
git clone <repo-url>
cd verifiable-accounting
cargo build --workspace --release
cargo test  --workspace
cargo run -p vaa-cli -- --help
```

Six CLI subcommands:

```sh
cargo run -p vaa-cli -- selftest
cargo run -p vaa-cli -- reproduce
cargo run -p vaa-cli -- anchor   --leaves <leaves.json>
cargo run -p vaa-cli -- prove    --records <records.json> --index 17 --out /tmp/bundle.json
cargo run -p vaa-cli -- verify   --bundle /tmp/bundle.json
cargo run -p vaa-cli -- query    --records <records.json> --index 17 --level 1
```

A complete worked example lives in `examples/realistic_quarter/` — run `python examples/realistic_quarter/generate.py` to regenerate every artefact in that directory, then run the six commands above against it.

## Two assurance modes

The selective-verification layer implements two reconstruction modes and enforces the boundary between them:

| Mode | Reconstruction | Audit-evidence | Default |
|---|---|---|---|
| `Adversarial` | Ordinary Merkle reconstruction against published node labels and the BSV-anchored root. | Yes — the only mode that yields independent audit evidence. | **On.** |
| `TrustedOperational` | Homomorphic compression of the proof-assistance data, on the BSV curve. | **No.** Documented as a trusted-environment option only. | **Off.** Opt-in by explicit API flag; the audit-API path rejects it. |

## Modules

| Crate | Responsibility |
|---|---|
| `bsv` | BSV double-SHA256 primitive and BSV byte-order conventions. |
| `merkle` | Merkle Proof Entity (Layer A): root, proof, verify; BSV odd-node duplication. |
| `proofstore` | Selective Verification (Layer B): non-overlapping shards, index schema, proof-assistance, query/retrieve. |
| `accounting` | Five named accounting equations, checked by recomputation over disclosed records. |
| `api` | `AuditVerifier` composing inclusion + selective-disclosure + recomputation. |
| `cli` | `vaa` binary: `selftest`, `reproduce`, `anchor`, `prove`, `verify`, `query`. |
| `simstore` | Storage / retrieval efficiency study for Layer B. |
| `simstudy` | Synthetic-population study: presence, selective disclosure, fault detection. |

## What this proves and what it does not

The system establishes, over the disclosed accounting records:

- **inclusion** (the record's leaf is in the BSV-anchored Merkle tree),
- **integrity** (`double_sha256(record_bytes) == leaf`),
- **selective disclosure** (only the queried record is revealed; other records remain opaque sibling hashes),
- **arithmetic correctness** (the named equations hold when recomputed over the disclosed records).

It does **not** prove:

- that the values are truthful or that any economic event occurred,
- that classification or recognition is correct,
- that the population is complete absent population controls,
- that anything is legally enforceable.

Specifically, a record entered falsely **at origin** in an internally consistent population is **not detected** — the system does not solve the garbage-in problem. The boundary is asserted in code (`crates/simstudy`) so it cannot be papered over.

## Documentation

- `docs/ARCHITECTURE.md` — the two layers, the crate map, the verification flow.
- `docs/DECISIONS.md` — stack and design choices.
- `docs/SECURITY.md` — threat model, posture, disclosure address.
- `docs/REPRODUCIBILITY.md` — exact commands to regenerate every reported value.
- `docs/AUDIT.md` — current audit status and self-certifying tests.

## Examples

- `examples/realistic_quarter/` — quarter-end close for a hypothetical mid-cap firm: 93 records, AR roll-forward, a worked proof bundle. Regenerated deterministically by `generate.py`.
- `examples/integration/` — runnable Python bridges for the two integration flows (anchor a record batch; verify settlement inclusion in a BSV block) and a one-command full-stack demo.

## Author

Craig Wright
University of Exeter
Email: cw881@exeter.ac.uk

## License

MIT. See `LICENSE`. Every source file carries the SPDX identifier `MIT` at the top.
