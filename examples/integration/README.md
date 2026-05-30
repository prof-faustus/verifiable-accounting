# Integration examples

`verifiable-accounting` is the BSV-anchoring + Merkle Proof Entity + selective-verification layer that sits **under** an accounting flow. This directory shows how to plug it in for two representative flows.

| Flow | What it demonstrates | Detail |
|---|---|---|
| **Anchor a batch of accounting records** | A batch of accounting records (invoices, receipts, credits, write-offs) is hashed leaf-by-leaf, the BSV-canonical Merkle root is computed and anchored in a BSV data-carrier output, and one record's inclusion is proven and verified end to end. | [`./anchor-record-batch.md`](./anchor-record-batch.md) |
| **Verify settlement inclusion in a BSV block** | A settlement transaction's inclusion in a BSV mainnet block is verified by reconstructing the block's Merkle root from the canonical tx-ordered txid list and matching it against the published BSV block-header `merkleroot`. | [`./settlement-verify.md`](./settlement-verify.md) |

Both flows use only the `vaa` CLI — no library coupling, no shared trait. Records and amounts are in **minor units**.

## Common pattern

Every integration follows the same three-step flow:

1. **Collect leaves.** Produce a list of 32-byte hashes — either record hashes (`double_sha256(record_bytes)`) or txids — and write them to a JSON file shaped per the relevant subcommand.
2. **Anchor.** Run `vaa anchor --leaves leaves.json` to get the BSV-canonical Merkle root, then embed that root in a BSV data-carrier output (`OP_FALSE OP_RETURN <protocol-tag> <root>` or the project's chosen convention; see `docs/DECISIONS.md`).
3. **Prove and verify.** For any one record you want to disclose, run `vaa prove --records records.json --index <i> --out bundle.json`. The auditor runs `vaa verify --bundle bundle.json` and gets `verify OK` iff the leaf hashes to the disclosed record bytes AND the Merkle path reconstructs to the anchored root.

## Runnable end-to-end

`./bridge.py` and `./full_stack_demo.py` exercise both flows from the command line. Both speak BSV only.

## Privacy model

The privacy mechanism is selective disclosure: a query for one record returns only that record's bytes + the sibling hashes needed to reconstruct the path to the anchored root. Nothing about any other anchored record is revealed. No added cryptography is involved.

## Boundary

These flows prove **presence + integrity + selective disclosure**, with the accounting equation checked by direct recomputation over the disclosed records. They do not detect a record entered falsely at origin in an internally consistent population — that is the documented system boundary (`docs/SECURITY.md`).
