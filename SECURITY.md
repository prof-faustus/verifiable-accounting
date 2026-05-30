# Security policy

## Reporting a vulnerability

Please report suspected security issues privately to the author by email rather than opening a public GitHub issue:

Craig Wright — cw881@exeter.ac.uk

You will receive an acknowledgement within seven days. Coordinated disclosure timelines will be agreed case by case.

## Scope

In scope:

- Cryptographic correctness of the Merkle proof entity, Pedersen commitments, Σ-protocols for the accounting equations, and the Bulletproofs range/validity proofs.
- The selective-verification proofstore: sharding boundaries, index correctness, query-time authorisation, and the adversarial-mode reconstruction.
- The data-output convention used to anchor commitment roots on BSV, and the SPV verification chain that closes against the BSV block header.
- The CLI and verifier-facing API surface.

Explicitly out of scope as security findings (these are stated boundaries of the system, not bugs):

- The garbage-in problem: collusively-recorded false-origin commitments are not detected by design. See the `docs/SECURITY.md` threat model and the boundary section of `docs/ARCHITECTURE.md`.
- Legal admissibility of cryptographic accounting evidence in any jurisdiction.
- Population-completeness assertions absent explicit population controls.
- The trusted operational EC-compression mode: it is documented as not adversarially secure. Reporting it as such is not a finding.

## Threat model summary

See `docs/SECURITY.md` for the full model. Headline threats considered:

| Adversary | Capability | Mitigation |
|---|---|---|
| Proof-store operator | Withholds, alters, or duplicates stored proof fragments. | Verification terminates at the BSV-anchored root, never at the proof store. Detected by reconstruction failure. |
| Public-medium adversary | Reorganises the BSV chain or fails to publish. | SPV verification requires header-chain confirmation; finality window documented per deployment. |
| Metadata adversary | Observes query patterns to infer counterparty relationships. | Index schema and retrieval API designed so query-time linkability is bounded; documented in `docs/SECURITY.md`. |
| Trusted-setup adversary | Subverts setup parameters of a trusted-setup ZK system. | The system uses transparent-setup primitives (Σ-protocols + Bulletproofs); there is no trusted setup. |

## Hard rules

- No cryptographic primitive is implemented by hand. All primitives come from audited libraries.
- No secret-dependent branching in security-critical paths; constant-time where it matters.
- The proof server / proof store is an availability and retrieval service, never a trust anchor.
- The two assurance modes are explicit; EC-point compression is opt-in, off by default, never presented as adversarially secure.
- No secrets, keys, or credentials committed to the repo.
