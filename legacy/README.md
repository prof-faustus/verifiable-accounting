# legacy/ — superseded material

This directory holds source preserved for the historical record. It is **superseded** by the live BSV-native project at the repository root and is **not** part of the live build.

- Not consumed by the live project.
- Not part of CI.
- Not maintained.
- Not a reference for new work.

`PROJECT_README.md` in this directory is the previous project's own README, retained verbatim so the supersession is fully traceable.

The live project is the BSV-native Rust workspace implementing:

- **Layer A — Merkle Proof Entity** (WO 2022/100946 A1): presence of a target data item in a BSV block, verifiable against the BSV block header chain via BSV double-SHA256 Merkle reconstruction.
- **Layer B — Selective Verification / proof-sharding** (WO 2025/119666 A1): non-overlapping proof fragments retrievable by a published index over BSV transaction attributes, verified against proof-assistance node labels at a predetermined Merkle level.

The accounting equations are checked by direct recomputation over disclosed `u64` records; privacy comes from selective disclosure. No hidden-value cryptography of any kind is part of the live tree.

### What was archived here

- `crates/commit/` — an earlier commitment-scheme crate. Superseded; the live system does not hide values, it discloses them selectively.
- `crates/zk/` — an earlier zero-knowledge-proof-of-equation crate. Superseded; the live system checks accounting equations by direct recomputation over disclosed records.
- `examples/` and `vectors/commit/` — earlier examples and test vectors that referenced the archived crates.

See the live project's `README.md`, `docs/`, and `crates/` at the repository root for the current implementation.
