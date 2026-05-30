# Integration examples

`verifiable-accounting` is the BSV-anchoring + Merkle-proof + Pedersen-commitment + selective-verification layer that sits **under** other accounting-flow components. This directory shows how to plug it into two sister repositories.

| Repository | Role | Where vaa plugs in |
|---|---|---|
| [`prof-faustus/triple-entry-evidence`](https://github.com/prof-faustus/triple-entry-evidence) | Reference implementation of the triple-entry accounting (TEA) artefact. Generates per-field commitments, linkage tags, and signed notes — but explicitly does **not** anchor anything on-chain. | `vaa` takes a batch of TEA note hashes, builds the Merkle root, and produces an anchored proof bundle. The TEA prototype's commitments become the *third entry* on BSV. See [`./tea-anchor.md`](./tea-anchor.md). |
| [`prof-faustus/bonded-subsat-channel`](https://github.com/prof-faustus/bonded-subsat-channel) | Bonded sub-satoshi BSV payment channels: open / transfer / close / contested. Produces channel state transitions, JSON transcripts, and on-chain settlement transactions. | `vaa` queries the inclusion of a channel's open / close transaction and produces a verifiable proof for the auditor. The channel daemon's JSON transcripts become the input leaves; the on-chain settlement transactions become the leaf-of-interest. See [`./channel-verify.md`](./channel-verify.md). |

Both integrations use only the `vaa` CLI — no library coupling, no shared Rust trait. That keeps the two sister repositories (both Python) free to evolve without binding to this Rust workspace.

## Common pattern

Every integration follows the same three-step flow:

1. **Collect leaves.** The sister repo produces a list of 32-byte hashes (txids, note hashes, or commitment hashes). Write them to a JSON file shaped as `{ "leaves_display_be": ["<64-char hex>", ...] }`.
2. **Anchor.** Run `vaa anchor --leaves leaves.json` to get the BSV-canonical Merkle root. Embed that root in a BSV data-carrier output yourself (the chosen on-chain anchoring convention lives in `docs/DECISIONS.md` D-006).
3. **Prove and verify.** For any single leaf you want to disclose, run `vaa prove --leaves leaves.json --index <i> --value <v> --blinding-hex <r> --out bundle.json`. The auditor runs `vaa verify --bundle bundle.json` and gets `verify OK` iff the Merkle path reconstructs to the anchored root **and** the Pedersen commitment opens to `(value, blinding)`.

See the per-repo docs for the exact mapping of fields.
