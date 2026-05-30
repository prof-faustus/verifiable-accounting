# Threat model

This document expands the `SECURITY.md` policy with the engineering-level threat model. It is the document an auditor or independent reviewer should read first.

## Goal of the system

To prove, without disclosing the underlying values, that committed accounting figures (a) exist on the BSV public medium, (b) are retrievable through the proofstore at audit time, and (c) satisfy the standard accounting equations within declared bounds. Verification terminates in a BSV block-header Merkle root; the proof server is an availability service.

## Trust model

| Party | What we assume about them |
|---|---|
| Author / system owner | Honest at the time of recording. The system does not protect against the owner intentionally encoding a false figure (the garbage-in boundary). |
| Proof-store operator | May be adversarial. May withhold, alter, duplicate, or fabricate stored proof fragments. |
| Public medium (BSV) | Reorganisations possible within a finality window. Honest-majority assumption for the SPV chain. |
| Verifier (auditor) | Honest. Has access to a trusted BSV header source (own node, a service, or an aggregated source). |
| Trusted-setup ceremony participants | Not in scope — the system uses transparent-setup primitives (Σ-protocols + Bulletproofs). There is no ceremony to subvert. |

## Adversaries

### A1 — Proof-store operator
**Capability.** Withhold individual shards; alter shard contents; duplicate shards; return shards under the wrong index key.
**Defence.** Verification always reconstructs against the on-chain anchor and rejects on mismatch. Shards are non-overlapping by construction (claim 2 of WO 2025/119666); duplicated shards are detected at reconstruction. The index is built from the on-chain third-data (claim 4), so the operator cannot index-shop without altering on-chain data.
**Residual risk.** A withholding operator can deny service. The system surfaces denial-of-service as a reconciliation exception, not as a successful verification. The auditor's response is to demand the missing fragment or to treat the item as unverified.

### A2 — Public-medium reorganisation
**Capability.** A short BSV reorganisation moves a previously-anchored transaction out of the longest chain.
**Defence.** SPV verification requires `k` confirmations before treating an anchor as final; `k` is a deployment parameter recorded in `docs/REPRODUCIBILITY.md`. Any anchor younger than `k` is reported as "not yet final" rather than confirmed.
**Residual risk.** A successful long-range reorganisation breaks SPV-style assurance. This is a property of the medium, not of this code.

### A3 — Metadata observation
**Capability.** A passive observer of query traffic correlates query patterns to infer counterparty relationships, time-of-day rhythms, or commercial volumes.
**Defence.** The index schema (claims 5–6) is structured around opaque txid + position fields, not human-readable counterparty labels. Query batching at the API layer is documented as a partial mitigation. Field-level commitments hide values from the medium.
**Residual risk.** Query timing and frequency leak. The system does not provide oblivious access; an adversary with full traffic visibility can still infer activity. Documented as a known limit.

### A4 — Tampering with the proof-assistance data on-chain
**Capability.** An adversary publishes false proof-assistance node labels on-chain.
**Defence.** The proof-assistance node labels are Merkle nodes at a predetermined level of the tree (claim 8 of WO 2025/119666). A verifier reconstructs from those labels up to the anchored root and rejects any inconsistency. False proof-assistance data fails reconstruction.

### A5 — Trusted-operational EC-compression abuse
**Capability.** An operator selects the EC-compression mode (claims 9–11 of WO 2025/119666) and presents the result as audit evidence.
**Defence.** The mode is opt-in and gated by an explicit `mode = TrustedOperational` argument. The `audit` API surface rejects any verification that did not use `Adversarial` mode. The CLI emits a warning when `TrustedOperational` is used.
**Residual risk.** A user who deliberately mislabels operational output as audit evidence is operating outside the system. The code makes that hard but cannot prevent it.

### A6 — Compromised commitment opener
**Capability.** An adversary obtains the blinding factor for a previously-published commitment.
**Defence.** Blinding factors are not stored alongside commitments outside the key-custody layer. Each disclosure opens only the field requested, not the whole transaction; per-field blinding factors derived via the key hierarchy isolate the blast radius.
**Residual risk.** If a master key is compromised the entity's privacy across covered transactions collapses; this is the standard key-custody risk for any hierarchical commitment scheme.

## Boundaries that are not defects (do not file as findings)

These are explicit *non-claims* of the system:

1. **Garbage-in.** A figure that is wrong at the moment of commitment is recorded faithfully. The system detects later alteration; it does not detect a number that was wrong from the outset.
2. **Recognition and classification.** The system proves arithmetic over committed values. Whether the values represent revenue under IFRS 15, or are correctly classified between current and non-current, is a judgement the system does not make.
3. **Population completeness.** Absent independent population controls (e.g. enumeration of authorised counterparties), the system cannot prove the auditor has seen every transaction.
4. **Legal admissibility.** The cryptographic evidence may or may not be admissible in any given jurisdiction. The system makes no claim here.

## Constant-time and side-channel posture

- All curve operations route through `libsecp256k1` / `libsecp256k1-zkp`. These libraries are designed with constant-time operations on secret values. We do not implement curve arithmetic in this codebase.
- Hashing is via the `sha2` crate. Hash inputs are public.
- No secret-dependent branching in code paths that handle blinding factors or private witnesses. Lints in CI enforce this where automatable.

## Reproducibility-as-security

The `reproduce` subcommand regenerates every committed vector and every paper number from source. CI runs it on every push. Any drift between code and vectors fails the build. This protects against silent regressions in the cryptographic core.

## Blinding-factor handling

The blinding factor in a Pedersen commitment `C(v, r) = v·G + r·H` is what makes the commitment hiding. Three structural defences are in place:

- **Zero rejection.** `crates/commit/src/lib.rs` rejects the all-zero scalar with [`CommitError::ZeroBlinding`] before it ever reaches the inner `Tweak` constructor. A zero blinding would collapse `C` to `v·G` — a deterministic function of the value alone — and anyone could confirm a guessed `v` by recomputing `v·G`. This applies to every constructor path: `Blinding::from_bytes`, `Blinding::try_from`, and the `serde` deserialiser (which routes through `from_bytes` via `#[serde(try_from = "[u8; 32]")]`). A test in the same module proves the serde path. Recorded in `docs/DECISIONS.md` D-011.

- **Out-of-range rejection.** Scalars at or above the secp256k1 group order `n` are rejected with [`CommitError::InvalidBlinding`], delegated to the audited `secp256k1_zkp::Tweak::from_inner`. The boundary cases — `n` (rejected) and `n - 1` (accepted) — are exercised by named tests in the commit crate.

- **Debug redaction.** `Blinding`'s `Debug` impl prints `Blinding(<redacted 32 bytes>)` instead of the scalar; a test asserts the bytes do not appear in the formatted output. This stops a blinding from leaking into a log line, a panic message, or an error backtrace. Recorded in `docs/DECISIONS.md` D-010.

The same hygiene is expected of any future random-blinding helper: it must loop on a CSPRNG until a non-zero in-range scalar is drawn, and it must never log or `Debug`-print the result outside the redacted form.

## H-generator derivation audit

The Pedersen value-blinding generator `H` is derived as `Generator::new_unblinded(secp, Tag(SHA-256(b"VAA-Pedersen-H-v1")))` (recorded in `docs/DECISIONS.md` D-004). Two audit paths are exposed:

- `crates/commit/src/lib.rs::h_tag()` returns the 32-byte SHA-256 tag at runtime.
- `printf 'VAA-Pedersen-H-v1' | sha256sum` reproduces the same bytes offline.

A test (`h_tag_is_sha256_of_domain_string`) asserts the runtime path equals the offline derivation. Together these prevent the H generator from being changed silently — any drift would either change the test or change one of the two derivation paths visibly.

## Disclosure policy

See `SECURITY.md` in the repository root for the disclosure address and timeline.
