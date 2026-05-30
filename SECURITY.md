# Security policy

## Reporting a vulnerability

Please report suspected security issues privately to the author by email rather than opening a public GitHub issue:

Craig Wright — cw881@exeter.ac.uk

You will receive an acknowledgement within seven days. Coordinated disclosure timelines will be agreed case by case.

## Scope

In scope:

- Correctness of the Merkle Proof Entity (Layer A): node construction, odd-node duplication, byte-order handling, proof verification.
- Correctness of the Selective Verification layer (Layer B): non-overlapping shard structure, index correctness, query-time authorisation, the proof-assistance reconstruction path, the trusted-operational mode boundary.
- The accounting equation library: correctness of the recomputation, overflow detection, equation rejection on off-by-one.
- The verification chain that closes against the BSV block header.
- The CLI and verifier-facing API surface.

Explicitly out of scope as security findings (these are stated boundaries of the system, not bugs):

- The origin-falsehood problem: a record entered falsely at origin in an internally consistent population is not detected by design. See the `docs/SECURITY.md` threat model and the boundary section of `docs/ARCHITECTURE.md`.
- Legal admissibility of accounting evidence in any jurisdiction.
- Population-completeness assertions absent explicit population controls.
- The trusted-operational mode: it is documented as not adversarially secure and is never accepted by the audit-API path. Reporting it as such is not a finding.

## Threat model summary

See `docs/SECURITY.md` for the full model. Headline threats considered:

| Adversary | Capability | Mitigation |
|---|---|---|
| Proof-store operator | Withholds, alters, or duplicates stored proof fragments. | Verification terminates at the BSV-anchored root, never at the proof store. Detected by reconstruction failure. |
| BSV public-medium adversary | Reorganises the BSV chain or fails to publish. | Verification requires header-chain confirmation; finality window documented per deployment. |
| Metadata observer | Observes query patterns to infer counterparty relationships. | Index schema and retrieval API designed so query-time linkability is bounded; documented in `docs/SECURITY.md`. |
| Disclosed-record forger | Discloses arbitrary record bytes that do not hash to the leaf. | Audit verifier recomputes `double_sha256(disclosed_record)` and rejects any bundle whose recomputed leaf does not equal the claimed leaf. |

## Hard rules

- Verification terminates in a BSV public anchor / block-header Merkle root; the proof store is an availability/retrieval service, never a trust anchor.
- The two assurance modes are explicit; the trusted-operational mode is opt-in, off by default, never accepted by the audit-API path.
- No secrets, keys, or credentials committed to the repo.
- BSV is the entire technical universe of this project. Nothing in source, comments, docs, dependencies, transitive dependencies, lockfile, configuration, fixtures, vector filenames, or example data may name or imply any other chain, protocol, or ecosystem.
