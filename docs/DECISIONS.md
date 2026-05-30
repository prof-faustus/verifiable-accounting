# Design decisions

Decisions are recorded one per section, in the order they were made. Each has a date, the decision, the rationale, and the alternatives considered and rejected. Once recorded, decisions are not edited; superseded decisions get a new entry below.

---

## D-001 — Stack: Rust workspace, single language end-to-end
**Decision:** Build the reference implementation as a single Cargo workspace in Rust stable.
**Rationale:** Strong types for the selective-verification index schema (claims 5–6 of WO 2025/119666) and for the BSV byte-order conventions pay off in correctness. Hashing-only cryptographic floor (BSV double-SHA256) keeps the dependency surface small and BSV-native.
**Alternatives rejected:** Mixed-language stacks add build complexity for no benefit at this scope; pure scripting languages lose the type discipline that protects the index schema and byte-order handling.

---

## D-002 — Target platform: BSV
**Decision:** The public medium is fixed as BSV. Hash is double-SHA256; Merkle tree is the BSV block Merkle tree with the standard odd-node duplication rule; endianness follows the BSV convention (internal little-endian, display big-endian); records are anchored via BSV data-carrier outputs; verification terminates in the BSV block header chain.
**Rationale:** BSV is the fixed target platform for this project, not an open choice. BSV's restored opcodes and unbounded block size are compatible with the design (large on-chain proof-assistance data, on-chain script-side verification options).
**Consequences:**
- Hash is not pluggable. The `merkle` crate calls `bsv::hash::double_sha256` directly; no single-SHA256 mode.
- The selective-verification index schema (claims 5–6) maps directly onto the BSV UTXO transaction structure (txid, in/out position, in/out flag, position-of-tx-in-block, locking script, unlocking script, amount in minor units).

---

## D-003 — Crate layout
**Decision:** `bsv`, `merkle`, `proofstore`, `accounting`, `api`, `cli`, plus the two simulation-study binaries `simstore` and `simstudy`. `cli`, `simstore`, `simstudy` are binaries; the rest are libraries.
**Rationale:** Separate crates enforce module boundaries through Cargo dependencies. Each maps to one responsibility in the layer model recorded in `docs/ARCHITECTURE.md`. The `bsv` crate isolates the BSV double-SHA256 primitive and BSV byte-order conventions so the `merkle` layer can focus on Merkle Proof Entity per WO 2022/100946 A1.

---

## D-004 — Privacy mechanism is selective disclosure of proof fragments
**Decision:** The privacy mechanism is the selective disclosure of proof fragments, per WO 2025/119666 A1 claim 12: a query for one record returns only that record's bytes + the opaque sibling hashes on its Merkle path. Nothing about any other anchored record is revealed.
**Rationale:** Selective disclosure achieves the privacy goal without added cryptographic infrastructure. No hidden-value cryptography of any kind is part of the live tree. The accounting equations are checked by direct recomputation over the disclosed records.
**Consequence:** The system does not detect a record entered falsely at origin in an internally consistent population. This boundary is asserted by an explicit negative test in `crates/simstudy` (the boundary is preserved, not papered over).

---

## D-005 — Predetermined level `k` for proof-assistance
**Decision:** The default predetermined level used by the proofstore and the simulation studies is `floor(log2(N) / 2)` where `N` is the leaf population. Callers can pass `k` explicitly.
**Rationale:** A balanced split between per-query lower-shard bytes and one-time public assistance bytes. Documented explicitly in the simulation-study output so any reader can re-derive the trade-off.

---

## D-006 — Reproducibility: deterministic vectors checked on every push
**Decision:** Every deterministic output the project reports has a committed vector under `/vectors/` and is regenerated + diffed by `vaa reproduce`. CI runs `vaa reproduce` on every push.
**Rationale:** Hard Rule from the project's own policy: no fabricated numbers; every reported value comes from running the code, and any drift between code and committed vectors fails CI.

---

## D-007 — Two assurance modes; audit API rejects the non-adversarial one
**Decision:** `ReconstructionMode::Adversarial` (default) reconstructs the Merkle path against public node labels and the BSV-anchored root. `ReconstructionMode::TrustedOperational` (opt-in) uses homomorphic compression of the proof-assistance labels on the BSV curve. The audit API rejects results from the trusted-operational mode.
**Rationale:** The two modes have different security postures. Letting an audit caller silently fall back to the operational mode would launder that distinction. A regression test (`rejects_non_adversarial_mode` in `crates/api/src/lib.rs`) asserts the rejection.

---

## D-008 — `BUILD ORDER` followed; `simstore` and `simstudy` measure the live system
**Decision:** `simstore` measures Layer B storage / retrieval efficiency (sharded vs full-proof baseline, proof-assistance size, retrieval payload, verify time). `simstudy` measures Layer A inclusion + Layer B selective disclosure + fault detection across the six in-scope fault classes (altered/omitted/duplicated record, tampered Merkle leaf, wrong index, wrong root), with zero false positives on the clean population and an honest record of the origin-falsehood boundary (not detected by design).
**Rationale:** The mandatory simulation studies must measure **this** system. They contain no cryptographic concept beyond BSV double-SHA256 Merkle hashing.
