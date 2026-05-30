# Anchoring a triple-entry-evidence batch on BSV with vaa

[`triple-entry-evidence`](https://github.com/prof-faustus/triple-entry-evidence) generates per-field Pedersen-style commitments and per-note linkage tags via `refimpl.py`, but explicitly does not anchor anything on-chain. This integration uses `vaa` to:

1. Collect the per-note hashes the TEA prototype emits.
2. Build a BSV-canonical Merkle root over the batch.
3. Anchor that root in a BSV data-carrier output (you do this; vaa returns the root in display form so you can drop it into your transaction builder).
4. Produce auditor-verifiable proof bundles for individual notes on demand.

## Step 1 — emit the leaves

Run the TEA reference implementation:

```
$ git clone https://github.com/prof-faustus/triple-entry-evidence.git
$ cd triple-entry-evidence
$ python refimpl.py > refimpl_out.txt
```

The stdout contains `C_field[*]` lines — the per-field commitments for one invoice note. For an anchoring batch you want one **note hash** per note, not one commitment per field. A note hash is the BSV double-SHA256 of the canonical serialised note body:

```python
# bridge.py — minimal example you keep in your own integration repo, NOT in either upstream
import hashlib, json, sys

def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

notes = json.load(sys.stdin)        # [{"body_hex": "..."}, ...]
leaves_display_be = [
    double_sha256(bytes.fromhex(n["body_hex"]))[::-1].hex()
    for n in notes
]
print(json.dumps({"leaves_display_be": leaves_display_be}, indent=2))
```

The `[::-1]` byte-reverse converts internal byte order → display order, matching vaa's `leaves_display_be` convention.

## Step 2 — anchor

```
$ vaa anchor --leaves leaves.json
leaves       : 156
root (display): 9c04f6d3a73169dc1084150a0d8ff775558cf9b0329de765fb3b0efe759dbc5d
root (internal): 5dbc9d75fe0e3bfb65e79d32b0f98c5575f78f0d0a158410dc6931a7d3f6049c
```

Use the display-form root inside a BSV `OP_FALSE OP_RETURN <protocol-tag> <root>` output (or your chosen data-output convention — record it in your own deployment docs). Once that transaction confirms, the root is anchored.

## Step 3 — prove one note

To prove inclusion of the note at position `42` in the batch, plus the opening of one of its Pedersen commitments:

```
$ vaa prove \
    --leaves leaves.json \
    --index 42 \
    --value 12100 \
    --blinding-hex <64-char hex blinding from the TEA prover> \
    --out note_42_bundle.json
```

The bundle is a self-contained JSON; the auditor needs only the bundle and (separately) the anchored root they read from the BSV transaction.

## Step 4 — verify

```
$ vaa verify --bundle note_42_bundle.json
verify OK
  merkle root  : 9c04f6d3a73169dc1084150a0d8ff775558cf9b0329de765fb3b0efe759dbc5d
  leaf index   : 42
  commitment   : <33-byte Pedersen commit> (opens to value 12100)
```

The verifier confirms:
- The note hash sits at position 42 of the batch (Merkle inclusion against the anchored root).
- The Pedersen commitment in the bundle opens to the disclosed value 12100 under the disclosed blinding.

This is the bilateral linkage the TEA paper describes, made concrete on BSV.

## What stays out of scope

- The Pedersen commitment in the bundle is the `vaa-commit` Pedersen on secp256k1 via `libsecp256k1-zkp`. The TEA prototype's `C_field` lines are hash-only commitments (SHA-256 of `K_field || label || value`). To bridge, either re-commit with vaa's Pedersen or extend vaa with a "hash-commit" mode — the latter is not on the v0.1 roadmap.
- The TEA paper's selective-disclosure transcript (per-field key release with auditor identity + expiry) is **not** yet handled by vaa. vaa proves *opening*, not authorisation. Treat the bundle as evidence the auditor verifies after they have already received the authorised disclosure out-of-band.
