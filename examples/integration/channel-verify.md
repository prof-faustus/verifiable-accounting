# Verifying a bonded-subsat-channel settlement on BSV with vaa

[`bonded-subsat-channel`](https://github.com/prof-faustus/bonded-subsat-channel) implements bonded sub-satoshi BSV payment channels (`channel open / transfer / close / contested`). Each settled or contested channel ends with an on-chain BSV transaction. This integration uses `vaa` to:

1. Extract the channel's settlement txid (or set of txids for a contested resolution).
2. Build a Merkle root over the block's tx-ordered txid list.
3. Prove that the channel's settlement transaction is included in the anchored block.
4. Hand an auditor a self-contained bundle they can verify offline.

Unlike the TEA flow, this integration does not produce new on-chain data — it **proves inclusion** of data that already settled.

## Step 1 — get the channel settlement txid

After `channel close` (or `channel contested`), bonded-subsat-channel emits a Phase 12 transcript or a structured log entry naming the settlement transaction. Parse the txid (display form, big-endian, 64-char hex) out of that.

```
$ channel close                 # bonded-subsat-channel CLI
{ "settlement_txid": "ab12...cd34", "block_height": 850123, ... }
```

## Step 2 — collect the block's tx-ordered txid list

Pull the full ordered txid list for the block at `block_height` from a BSV-native source (your own BSV node's RPC, a P2P fetch, etc.). **Do not use a Bitcoin or Bitcoin Cash source — only BSV.** Write the result to a leaves JSON file:

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

The settlement txid lives at some position `i` (zero-based, including coinbase at index 0).

## Step 3 — verify the block's Merkle root matches the on-chain header

```
$ vaa anchor --leaves block_850123_leaves.json
leaves       : 4521
root (display): 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
```

Compare this against the `merkle_root` field of the block 850123 header (again, pulled from a BSV-native source). They must match bit-for-bit — if they don't, the leaves file is wrong (missing tx, wrong order, or wrong byte order).

## Step 4 — produce the inclusion proof

The "value" and "blinding" in this flow don't represent a Pedersen-hidden amount — they hold whatever the channel's auditor wants to commit to alongside the inclusion proof (for example, the settled satoshi total). If the auditor only needs the inclusion proof, supply any non-zero blinding and a placeholder value of 0:

```
$ vaa prove \
    --leaves block_850123_leaves.json \
    --index <i> \
    --value 0 \
    --blinding-hex 0101010101010101010101010101010101010101010101010101010101010101 \
    --out channel_inclusion.json
```

For a real audit, anchor the channel's settled state commitment alongside:

```
$ vaa prove \
    --leaves block_850123_leaves.json \
    --index <i> \
    --value <total_settled_satoshis> \
    --blinding-hex <fresh 32-byte CSPRNG blinding> \
    --out channel_inclusion.json
```

## Step 5 — verify offline

```
$ vaa verify --bundle channel_inclusion.json
verify OK
  merkle root  : 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff
  leaf index   : <i>
  commitment   : <33 bytes> (opens to value <total_settled_satoshis>)
```

The auditor confirms:
- The settlement transaction sits at position `i` in block 850123.
- Position `i` reconstructs through the standard BSV Merkle path (with odd-node duplication) to the published header's Merkle root.
- The Pedersen commitment opens to the disclosed settled-satoshi total.

## What stays out of scope

- **Script-level verification of the settlement** — that the channel's settlement script enforces the bonded sub-satoshi rules. That is the bonded-subsat-channel repo's domain, not vaa's. vaa proves *inclusion in the block*, not *correctness of the script*.
- **Contested-channel resolution evidence** chained across multiple transactions. For a multi-tx contested flow, repeat the prove/verify on each relevant transaction; cross-linking them into a single audit bundle is a future helper.
- **Live BSV header retrieval.** vaa does not currently fetch BSV block headers; the integration assumes you have a BSV-native source. A `--live` flag on `vaa verify` is on the roadmap.
