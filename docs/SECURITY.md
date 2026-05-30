# Threat model

This document expands `SECURITY.md` with the engineering-level threat model.

## Goal of the system

To prove, without trusting any service component, that an accounting record is included in a BSV block and to selectively disclose individual records for audit. Verification terminates in a BSV block-header Merkle root; the proof server is an availability service.

## Trust model

| Party | What we assume about them |
|---|---|
| Auditor / verifier | Honest. Has access to a trusted BSV header source (own BSV node, an aggregator, etc.). |
| Record owner | Honest at the time of recording. The system does not protect against the owner intentionally encoding a false figure (the origin-falsehood boundary). |
| Proof-store operator | May be adversarial. May withhold, alter, duplicate, or fabricate stored proof fragments. |
| BSV chain | Honest-majority assumption for the BSV header chain; reorganisations possible within a finality window. |

## Adversaries

### A1 — Proof-store operator
**Capability.** Withhold individual shards; alter shard contents; duplicate shards; return shards under the wrong index key.
**Defence.** Verification always reconstructs against the BSV-anchored root and rejects on mismatch. Shards are non-overlapping by construction (claim 2 of WO 2025/119666); duplicated shards are detected at reconstruction. The index is built from BSV-on-chain attributes (claim 4).
**Residual risk.** A withholding operator can deny service. The system surfaces denial-of-service as a reconciliation exception, not as a successful verification.

### A2 — BSV chain reorganisation
**Capability.** A short BSV reorganisation moves a previously-anchored transaction out of the longest chain.
**Defence.** Verification requires `k` confirmations before treating an anchor as final; `k` is a deployment parameter recorded in `docs/REPRODUCIBILITY.md`. Any anchor younger than `k` is reported as "not yet final" rather than confirmed.
**Residual risk.** A successful long-range reorganisation breaks the assurance. This is a property of the public medium, not of this code.

### A3 — Metadata observation
**Capability.** A passive observer of query traffic correlates query patterns to infer counterparty relationships or commercial volumes.
**Defence.** The index schema (claims 5–6) is structured around opaque txid + position fields. Query batching at the API layer is a partial mitigation; oblivious access is not provided.
**Residual risk.** Query timing and frequency leak. Documented as a known limit.

### A4 — Tampering with the proof-assistance data on BSV
**Capability.** An adversary publishes false proof-assistance node labels on BSV.
**Defence.** Proof-assistance node labels are Merkle nodes at a predetermined level of the tree (claim 8 of WO 2025/119666). A verifier reconstructs from those labels up to the BSV-anchored root and rejects any inconsistency. False proof-assistance data fails reconstruction.

### A5 — Trusted-operational mode misuse
**Capability.** An operator selects the trusted-operational mode (claims 9–11 of WO 2025/119666) and presents the result as audit evidence.
**Defence.** The mode is opt-in and gated by an explicit `mode = TrustedOperational` argument. The audit-API path rejects any verification that did not use `Adversarial` mode.

### A6 — Disclosed-record forgery
**Capability.** An adversary discloses arbitrary record bytes that do not hash to the claimed leaf.
**Defence.** The audit verifier recomputes `double_sha256(disclosed_record)` and rejects any bundle where the recomputed leaf does not equal the bundle's claimed leaf. The Merkle proof then terminates against the BSV-anchored root; an adversary cannot substitute arbitrary record bytes.

## Boundaries that are not defects (do not file as findings)

1. **Origin falsehood.** A record entered falsely at origin in an internally consistent population is recorded faithfully and is not detected by the system. The system detects later alteration; it does not detect a value that was wrong from the outset.
2. **Recognition and classification.** The system checks that the named accounting equations hold over the disclosed records. Whether a value represents revenue under any specific accounting standard is a judgement the system does not make.
3. **Population completeness.** Absent independent population controls, the system cannot prove the auditor has seen every transaction.
4. **Legal admissibility.** The system makes no claim of legal admissibility in any jurisdiction.

## Reproducibility-as-security

`vaa reproduce` regenerates every committed vector and asserts it against the committed expected output. CI runs it on every push. Any drift between code and vectors fails the build.

## Disclosure policy

See `SECURITY.md` in the repository root for the disclosure address and timeline.
