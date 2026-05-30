# Pull request

## Summary

<!-- One short paragraph: what changes, and why. Link to any issue. -->

## Type of change

- [ ] Bug fix (no API change)
- [ ] New feature (additive; no breaking change)
- [ ] Breaking change (consumers must update)
- [ ] Documentation only
- [ ] Tooling / CI / build

## Checklist

### Gate (must all be green locally before requesting review)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`

### Tests

- [ ] Unit tests added for every new public function
- [ ] Property tests added if the change touches `merkle` or `proofstore`
- [ ] Adversarial / negative tests assert the failure path explicitly (no silent pass)
- [ ] Boundary cases tested where relevant (empty, single-element, max-size, off-by-one)

### BSV

- [ ] Hashing uses `vaa_bsv::hash::double_sha256` (no other hash function added)
- [ ] Byte-order handling is consistent: internal little-endian for hashing/computation, display big-endian only at the user-facing boundary
- [ ] No assumption about anything outside BSV is introduced (nothing in source/docs/deps/lockfile names anything outside BSV)

### Documentation

- [ ] Every new public item has a doc comment
- [ ] Functions returning `Result` have a `# Errors` section
- [ ] Functions using `.expect()` / `.unwrap()` have a `# Panics` section, or refactored to return `Result`
- [ ] User-facing changes reflected in `README.md`
- [ ] Design decisions recorded in `docs/DECISIONS.md`
- [ ] Threat-model implications reflected in `docs/SECURITY.md`

### Reproducibility

- [ ] No fabricated numbers, vectors, or chain fixtures — every reported value comes from running code
- [ ] If a vector changes, the expected output under `vectors/` is regenerated in the same commit
- [ ] `vaa reproduce` exits zero locally

### Hygiene

- [ ] No secrets, keys, credentials, or personal-instruction files in the diff
- [ ] Commit messages are imperative, descriptive, and free of internal-tool references

## Test plan

```
cargo build --workspace --release
cargo test --workspace
cargo run -p vaa-cli --release -- selftest
cargo run -p vaa-cli --release -- reproduce
```

## Notes for reviewer

<!-- Anything you want the reviewer to focus on, or known follow-ups. -->
