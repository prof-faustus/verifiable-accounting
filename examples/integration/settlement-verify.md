# Verifying settlement inclusion in a BSV block with `vaa`

This integration takes a settlement transaction that has landed in a BSV mainnet block and verifies, without trusting any service, that the transaction is included in the block by reconstructing the block's Merkle root from the canonical tx-ordered txid list and comparing it against the published BSV block-header `merkleroot`.

Unlike the record-anchor flow, this integration does **not** produce new on-chain data — it proves inclusion of data that already settled.

## Step 1 — get the settlement txid

After your accounting workflow produces a settlement on BSV (any settlement transaction whose inclusion you want to verify), capture its txid in display (big-endian) hex.

```json
{
  "settlement_txid_display_be": "<64-char hex>"
}
```

## Step 2 — collect the block's tx-ordered txid list

Fetch the ordered txid list for the BSV mainnet block containing the settlement from a BSV-native source (your own BSV node, a public BSV explorer such as WhatsOnChain). Write the result to a leaves JSON file:

```json
{
  "leaves_display_be": [
    "<coinbase txid>",
    "<tx 1 txid>",
    "...",
    "<settlement txid from step 1>",
    "...",
    "<last tx txid>"
  ]
}
```

The settlement txid lives at some position `i` (zero-based; coinbase at index 0).

## Step 3 — reconstruct the Merkle root and match the header

```
$ vaa anchor --leaves <leaves.json>
leaves          : <tx_count>
root (display)  : <64-char hex>
root (internal) : <64-char hex>
```

Compare the display-form root to the `merkleroot` field of the same BSV block header (pulled from the same BSV-native source). They must match bit-for-bit. If they don't, the leaves file is wrong — wrong tx order, missing txs, or wrong byte order.

## Step 4 — produce the inclusion proof

```
$ vaa prove \
    --records <records.json> \
    --index <i> \
    --out settlement_inclusion.json
```

The records JSON shape is the same as in the record-anchor flow: each entry is the hex-encoded canonical bytes of a record. Here each record can be the txid hex (or whatever the auditor's bundle format requires).

## Step 5 — verify offline

```
$ vaa verify --bundle settlement_inclusion.json
verify OK
  merkle root  : <64-char hex>
  leaf index   : <i>
  record bytes : 32 bytes disclosed
```

The verifier confirms the settlement transaction sits at the claimed position in the block and the position reconstructs through the standard BSV Merkle path to the published header's Merkle root.

## Scope

- Script-level verification of the settlement (that the script enforces the rules the auditor expects) is out of scope for `vaa` and remains the auditor's responsibility.
- Cross-block correlation for multi-transaction settlements is out of scope; repeat the prove/verify on each relevant transaction.
- Live BSV header retrieval is out of scope for v0.x; the auditor is expected to fetch the BSV header from a BSV-native source they trust.
