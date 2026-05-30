# Anchoring a batch of accounting records on BSV with `vaa`

This integration takes a batch of accounting records (invoices, receipts, credit notes, write-offs), hashes each to a leaf, builds the BSV-canonical Merkle root, anchors that root in a BSV data-carrier output, and produces an auditor-verifiable proof bundle for any one record on demand.

The amounts are in **minor units**. The flow is end to end against the `vaa` CLI; no other dependency is required.

## Step 1 — produce the records

A record is the canonical, deterministic byte serialisation of one accounting line: invoice, receipt, credit note, or write-off. The simplest canonical form is a tightly-formatted JSON object with sorted keys:

```python
import json, hashlib
def record_bytes(kind, ix, value, counterparty):
    obj = {"kind": kind, "id": ix, "value": int(value), "counterparty": counterparty}
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")

def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()
```

Each leaf is `double_sha256(record_bytes(...))`. Write the records to a JSON file:

```json
{
  "records_hex": ["<hex record 0>", "<hex record 1>", "..."]
}
```

A complete worked example is in `examples/realistic_quarter/` — run `examples/realistic_quarter/generate.py` to reproduce it.

## Step 2 — anchor

```
$ vaa anchor --leaves <leaves.json>
leaves          : 93
root (display)  : <64-char hex>
root (internal) : <64-char hex>
```

`vaa anchor` accepts the leaves JSON shape `{"leaves_display_be": [...]}`. To produce that from the records JSON, hash each record and take the byte-reverse for display order. Use the display-form root in a BSV `OP_FALSE OP_RETURN <protocol-tag> <root>` output (or the project's chosen data-output convention — record it in your own deployment docs).

## Step 3 — prove one record

```
$ vaa prove \
    --records examples/realistic_quarter/records.json \
    --index 17 \
    --out /tmp/bundle.json
wrote proof bundle (...) to /tmp/bundle.json
```

The bundle is self-contained JSON: it carries the disclosed record bytes (the leaf), the leaf index, the ordered sibling hashes, and the display-form anchored root.

## Step 4 — verify

```
$ vaa verify --bundle /tmp/bundle.json
verify OK
  merkle root  : <64-char hex>
  leaf index   : 17
  record bytes : 32 bytes disclosed
```

The verifier confirms:

- `double_sha256(disclosed_record)` equals the bundle's claimed leaf, and
- the leaf at the claimed index, walked up through the ordered sibling hashes, reconstructs to the BSV-anchored root.

Selective disclosure: the bundle reveals **only** record #17. Nothing about records #0…#16 or #18…#92 is disclosed beyond their opaque sibling hashes on the proof path.

## Boundary

The accounting equation (AR roll-forward, debit=credit, VAT, etc.) is checked by direct recomputation over the disclosed records — see `examples/realistic_quarter/ar_rollforward.json`. The system does not detect a record entered falsely at origin in an internally consistent population (the system boundary; see `docs/SECURITY.md`).
