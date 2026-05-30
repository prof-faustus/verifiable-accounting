# Design decisions

Decisions are recorded one per section, in the order they were made. Each has a date, the decision, the rationale, and the alternatives considered and rejected. Once recorded, decisions are not edited; superseded decisions get a new entry below.

---

## D-001 — Stack: Rust workspace, single language end-to-end
**Date:** 2026-05-29
**Decision:** Build the reference implementation as a single Cargo workspace in Rust 1.85 stable.
**Rationale:**
- The cryptographic floor (Pedersen commitments and Bulletproofs over secp256k1) is realistically only available via `libsecp256k1-zkp`, a C library. Any language for the rest of the stack wraps this. Rust gives us idiomatic, type-safe bindings (`secp256k1`, `secp256k1-zkp`) and keeps the rest of the codebase in a single language.
- Constant-time discipline and the absence of secret-dependent branching are easier to enforce in Rust than in Python.
- Strong types for the selective-verification index schema (claims 5–6 of WO 2025/119666) and for the Σ-protocol witness structures pay off in correctness.
- Production posture: the paper labels this a *production-grade* reference implementation. Rust matches that posture.
**Alternatives rejected:**
- *Python with vetted bindings* — no production-grade Bulletproofs over secp256k1 in Python; would either accept research-grade implementations or route through Rust bindings anyway, giving the worst of both.
- *Hybrid: Python orchestration + Rust crypto core via PyO3* — feasible, but adds cargo + maturin to the build for marginal benefit when the API surface is small.
- *Non-secp256k1 ZK ecosystems (arkworks, halo2 on BN254/BLS12-381)* — excluded by D-002 (target platform).

---

## D-002 — Target platform: BSV (Bitcoin SV), not blockchain-agnostic
**Date:** 2026-05-29
**Decision:** The public medium is fixed as BSV. Hash is double-SHA256; Merkle tree is the BSV block Merkle tree with the standard odd-node duplication rule; endianness follows the BSV/Bitcoin convention (internal little-endian, display big-endian); commitments are anchored via BSV data-carrier outputs; verification terminates in the BSV block header chain (SPV).
**Rationale:** BSV is the fixed target platform for this project, not an open choice. BSV's restored opcodes and unbounded block size are compatible with the design (large on-chain proof-assistance, on-chain Merkle verification scripts).
**Consequences:**
- Hash is not pluggable. The `merkle` crate calls `bsv::hash::double_sha256` directly; no single-SHA256 mode.
- The selective-verification index schema (claims 5–6) maps directly onto BSV UTXO transaction structure.
- ZK primitives must work on secp256k1, ruling out pairing-friendly curves and the systems that need them (Groth16, PLONK, Halo2 on BN254/BLS12-381).

---

## D-003 — ZK construction: Σ-protocols + Bulletproofs (transparent setup, no ceremony)
**Date:** 2026-05-29
**Decision:**
- **Linear accounting equations** (`Gross = Net + Tax − Discount`, AR roll-forward, debit=credit, bank reconciliation, VAT identity) are proven by **Σ-protocols on Pedersen commitments**, made non-interactive by Fiat–Shamir.
- **Range and validity proofs** (non-negativity, currency bounds, no overflow, tax-rate in authorised set, period in valid set, no double-use, commitment-matches-disclosure) use **Bulletproofs** from `libsecp256k1-zkp`.
**Rationale:**
- All listed equations are linear in committed values. Σ-protocols are the textbook construction; small proofs, fast, no setup, no ceremony.
- Bulletproofs are transparent-setup, work natively on secp256k1, and are battle-tested in Confidential Transactions / Mimblewimble (Liquid, Grin) — the same library we route through.
- The project prefers a transparent-setup system. Σ-protocols + Bulletproofs are both transparent.
- Arithmetic-circuit Bulletproofs would let us handle non-linear identities (e.g. a checked multiplication) at higher cost. The listed equations do not require this and we therefore avoid the complexity. If a future equation needs non-linear ZK, that decision gets its own entry.
**Alternatives rejected:**
- *Groth16 / PLONK / Halo2* — require pairing-friendly curves; not available on secp256k1.
- *zk-STARKs* — transparent, would work; rejected as heavier than needed for linear equations and as introducing a separate proof system.
- *Hand-rolled Σ-protocols using direct EC operations* — only the protocol composition is in our code; all curve operations route through `libsecp256k1-zkp`.

---

## D-004 — Pedersen second generator H: NUMS via libsecp256k1-zkp Generator from a SHA-256 domain-separation tag
**Date:** 2026-05-29
**Decision:** The Pedersen second generator `H` for `C(v, r) = v·G + r·H` is constructed as:
```text
H = Generator::new_unblinded(secp, Tag(SHA-256(b"VAA-Pedersen-H-v1")))
```
using the `secp256k1-zkp` v0.11 API. The 32-byte tag is the SHA-256 digest of the ASCII string `VAA-Pedersen-H-v1` (no newline, no other padding). `Generator::new_unblinded` is the library's standard constructor for asset-tagged Confidential-Transactions generators; passing it a non-G tag yields a NUMS point because the discrete log of the resulting point with respect to `G` is determined only by the library's tag-to-curve map (an internal hash-to-curve), which the library treats as a one-way function.
**Verification path for any reader:**
```text
$ printf 'VAA-Pedersen-H-v1' | sha256sum
```
The 32-byte digest is the tag. Re-running `Generator::new_unblinded(secp, tag)` against the same library version reproduces the exact H point used in production. `crates/commit/src/lib.rs::h_tag()` exposes this tag programmatically; a test in that module asserts the tag equals the SHA-256 of the domain string.
**Versioning:** the `-v1` suffix in the domain string is the upgrade path. Changing the domain string changes H and invalidates every previously-published commitment; that becomes a new entry, not an edit to this one.
**Rationale:**
- We do not implement curve arithmetic by hand (see `SECURITY.md` policy on vetted primitives). All H derivation, scalar arithmetic, and point operations route through `libsecp256k1-zkp`.
- The domain-separation string is fully auditable from source; no off-line trusted-setup ceremony is involved.
- Aligns with the Liquid / Confidential-Transactions convention so downstream Bulletproof range proofs (step 5) use the same generator.

---

## D-005 — Crate layout: eight crates in a Cargo workspace
**Date:** 2026-05-29
**Decision:** `bsv`, `merkle`, `proofstore`, `commit`, `zk`, `accounting`, `api`, `cli`. `cli` is the binary; the rest are libraries.
**Rationale:** Separate crates enforce module boundaries through Cargo dependencies. Each maps to one responsibility in the layer model recorded in `docs/ARCHITECTURE.md`. The `bsv` crate is added beyond the original seven because BSV-specific consensus types (txid, header, script, endianness) are a clean boundary worth isolating from generic Merkle logic; that keeps `merkle` focused on the proof entity per WO 2022/100946 A1.

---

## D-006 — Data-output convention for anchoring commitments (pending)
**Date:** TBD — set in step 2 alongside the first anchor write.
**Decision:** TBD. Candidates: `OP_FALSE OP_RETURN <protocol-tag> <commitment-root>` (the dominant BSV convention) versus a longer `<protocol-tag> <version> <root> <metadata>` layout for forward compatibility.
**Open questions:** protocol tag bytes, length-prefix scheme, multi-root batching format.

---

## D-007 — BSV library choice (pending)
**Date:** TBD — set when `crates/bsv/src/lib.rs` is implemented.
**Decision:** TBD. Candidates: `rust-bitcoin` (mature, consensus-layer compatible with BSV for txid/header/Merkle/basic script; does not execute BSV restored opcodes) versus a BSV-specific Rust library (likely needed if we execute script). The trade-off and the choice will be recorded here.

---

## D-008 — Reproducibility seed and harness (pending)
**Date:** TBD — set in step 8 alongside the `reproduce` subcommand.
**Decision:** TBD. The deterministic seed used for the synthetic-population benchmark and for blinding-factor generation will be recorded here so any reader can reproduce the paper's tables from source alone.

---

## D-009 — Test layout: in-crate `#[cfg(test)]` modules only
**Date:** 2026-05-29
**Decision:** All tests live inside their crate as `#[cfg(test)] mod tests { ... }`, including property tests under a nested `mod property { ... }`. The top-level `tests/{unit,property,adversarial,integration}/` directories suggested in the original layout have been **deleted** because they were empty and falsely implied coverage that did not exist.
**Rationale:**
- A workspace-level `tests/{unit,property,adversarial,integration}/` layout is a conceptual sketch, not a Rust-cargo requirement; cargo workspaces have no notion of workspace-level test directories that would auto-execute.
- Keeping tests beside the code they exercise gives `cargo test -p <crate>` clean per-crate runs and avoids cross-crate compile dependencies just to share test helpers.
- Empty directories that *look* like categorised tests are worse than no directories — they read as evidence of coverage that is not there.
**How to extend:** if a future test genuinely needs to compose multiple crates as a black box, add it as a regular cargo integration test under `crates/<crate>/tests/integration.rs` (per-crate `tests/` directories that cargo discovers automatically). Do **not** reintroduce a workspace-level `tests/` directory; if such a need arises, make it a dedicated workspace member crate.

---

## D-010 — Blinding `Debug` is redacted
**Date:** 2026-05-29
**Decision:** `Blinding`'s `Debug` impl prints `Blinding(<redacted 32 bytes>)` instead of the inner scalar. The `Tweak`'s own `Debug` would have printed the bytes; the override prevents this from ever happening.
**Rationale:** A blinding factor's secrecy is what makes a Pedersen commitment hiding. Anything that lets a blinding leak into a log line, a panic message, or an error backtrace would undo the hiding property for every commitment that ever used that blinding. The redaction is a structural rather than discretionary defence.
**Consequence:** the `Blinding` no longer derives `Debug`; the custom impl is hand-written. A test (`blinding_debug_is_redacted` in `crates/commit/src/lib.rs`) asserts the bytes do not appear in the formatted output.

---

## D-011 — `Blinding::serde` deserialise routes through `from_bytes`
**Date:** 2026-05-29
**Decision:** With the `serde` feature, `Blinding` derives `Serialize`/`Deserialize` with `#[serde(try_from = "[u8; 32]", into = "[u8; 32]")]`. Deserialisation therefore runs through `TryFrom<[u8; 32]>` → `Blinding::from_bytes`, which enforces both the zero-rejection (`CommitError::ZeroBlinding`) and the curve-order range check.
**Rationale:** without this routing, the derived `Deserialize` would reconstruct the inner `Tweak` directly, by-passing both checks. A hand-crafted serialised all-zero blinding from a malicious peer would silently produce an insecure value. The routing closes that path. A test (`serde_round_trip_rejects_zero_blinding`) proves it.

---

## D-013 — Benchmarks live under each crate's `benches/`, not in a workspace bench crate
**Date:** 2026-05-30
**Decision:** Criterion benchmarks live under `crates/<name>/benches/<name>_benches.rs` for `vaa-merkle`, `vaa-commit`, and `vaa-zk`. There is no top-level workspace bench member.
**Rationale:** cargo's `cargo bench -p <crate>` is the idiomatic invocation; per-crate benches don't need cross-crate compile dependencies and can be added incrementally. The criterion harness reports median + IQR; the project policy is to never extrapolate transactions-per-second from these cryptographic-core micro-benches (see `docs/SECURITY.md`).

---

## D-015 — Release binaries built by GitHub Actions on every version tag, three targets
**Date:** 2026-05-30
**Decision:** `.github/workflows/release.yml` triggers on `v*.*.*` tag push and builds `vaa` for `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, and `x86_64-pc-windows-msvc`. Each build runs `vaa selftest` as a smoke test before uploading the platform-specific archive (`tar.gz` for unix, `zip` for windows) to the GitHub Release.
**Rationale:** Consumers should not have to install a Rust toolchain to use the CLI. Three targets cover the most common modern developer environments; additional targets (linux-arm64, windows-gnu) can be added as a matrix entry without restructuring the workflow.
**Posture:** the archives include `LICENSE`, `README.md`, and `SECURITY.md` alongside the binary so the artefact is self-describing.

---

## D-016 — Docker image is multi-stage, runs as a non-root user, ships vectors + examples
**Date:** 2026-05-30
**Decision:** The repository ships a `Dockerfile` that:
- builds in `rust:1.85-bookworm` with the C-toolchain prerequisites for `libsecp256k1-zkp`,
- runs in `debian:bookworm-slim` as a non-root user (`vaa`, uid 10001),
- copies `vectors/` and `examples/` into `/opt/vaa/` so `vaa reproduce` works without a host mount,
- declares `vaa` as the entrypoint and `selftest` as the default command.
**Rationale:** Multi-stage keeps the runtime image small (no rust toolchain). Non-root reduces blast radius if a consumer ever exposes the container to untrusted input. Bundling vectors and examples makes the image self-contained so `docker run --rm vaa:vX.Y.Z reproduce` and `docker run --rm vaa:vX.Y.Z verify --bundle examples/...` work out of the box.

---

## D-014 — `vaa-api::AuditVerifier` rejects non-adversarial reconstruction at the audit surface
**Date:** 2026-05-30
**Decision:** `AuditVerifier::verify` returns `ApiError::NonAdversarialMode` if a bundle requests `ReconstructionMode::TrustedOperational`. The structural rejection happens before the proofstore is queried.
**Rationale:** The two assurance modes the selective-verification patent describes are different in security posture: adversarial reconstruction yields independent audit evidence; EC-point compression does not. Letting an audit caller silently fall back to the operational mode would launder that distinction. A regression test (`rejects_non_adversarial_mode` in `crates/api/src/lib.rs`) asserts the rejection.

---

## D-012 — `serde` is on by default in `vaa-commit`
**Date:** 2026-05-29
**Decision:** `crates/commit/Cargo.toml` sets `default = ["serde"]`. The `cargo test --workspace` gate (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`) therefore exercises the serde-rejection tests automatically.
**Rationale:** the §0 gate must run `cargo test --workspace` without an `--all-features` flag. Routing the serde tests through the default feature set is the simplest way to guarantee they run under the literal gate command, rather than relying on a CI-only feature matrix. Consumers that want a no-serde build can opt out with `default-features = false`; no downstream crate in this workspace currently does.
