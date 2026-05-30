# Realistic quarterly-close example

A complete, end-to-end vaa workflow that mirrors a real BSV-billing small business closing its books for one quarter. Replaces the toy `examples/sample_leaves.json` with something an auditor would actually receive.

## The hypothetical entity

**Helix Subsat Services Ltd.** — a fictitious mid-market services firm that bills clients in BSV. All amounts are expressed in **satoshis** (1 BSV = 100,000,000 satoshis) so the figures fit in `u64` and round-trip through the Pedersen commitment cleanly.

For the period **2026-04-01 to 2026-06-30** (financial Q2):
- 48 invoices issued to 12 distinct counterparties
- 43 invoices settled within the quarter
- 5 outstanding at quarter-end (rolled into closing AR)
- 1 credit note issued
- 1 receivable written off

## Files

| File | What it contains |
|---|---|
| `notes.json` | The 48 invoice notes + 43 payment notes + 1 credit + 1 write-off, each with a deterministic note-body hash. Suitable as the leaves input to `vaa anchor`. |
| `ar_rollforward.json` | The Q2 AR roll-forward inputs: opening AR, invoices, receipts, credit notes, write-offs, and the closing AR — every figure committed under a Pedersen commitment with a per-line blinding factor. |
| `bundle_invoice_017.json` | A worked proof bundle for invoice #17 (a 3,341,000-satoshi invoice to "Quill Estates"). Verifiable via `vaa verify`. |

## Why this matters versus the toy `sample_leaves.json`

The toy sample uses synthetic 32-byte values with one byte set per leaf — fine to demonstrate that the CLI runs, useless for an auditor trying to reason about real-world accounting flows. The realistic sample:

- exercises every accounting equation in `vaa-accounting` against numbers an auditor would actually plug into IFRS-aligned working papers;
- spans a full reporting period;
- exposes the *kind* of variance an auditor cares about (open AR, credit notes, write-offs) rather than abstract integer values; and
- demonstrates the bridge from accounting workpaper (period totals) to anchoring artefact (Merkle leaves).

## How to use

```sh
# 1. Anchor the note batch.
vaa anchor --leaves examples/realistic_quarter/notes.json

# 2. Produce a proof bundle for one invoice (already pre-generated as
#    bundle_invoice_017.json; this command regenerates it from scratch).
vaa prove \
    --leaves examples/realistic_quarter/notes.json \
    --index 17 \
    --value 3341000 \
    --blinding-hex <see generate.py blinding_hex(17, "invoice-line") for the value> \
    --out /tmp/bundle_invoice_017.json

# 3. Verify the pre-generated bundle (no live BSV node required).
vaa verify --bundle examples/realistic_quarter/bundle_invoice_017.json

# 4. Verify the AR roll-forward identity at the Rust API level
#    (no CLI subcommand for this in v0.2; this is what `vaa-accounting`
#    does internally given the commitments in ar_rollforward.json):
#
#       AR_close = AR_open + Invoices - Receipts - CreditNotes - WriteOffs
```

## Numbers

In satoshis. Amounts are realistic for a small services firm.

| Line | Satoshis |
|---|---|
| AR opening (2026-04-01) | 18,200,000 |
| Invoices issued in Q2 | 183,944,000 |
| Receipts in Q2 | 173,419,000 |
| Credit notes in Q2 | 1,800,000 |
| Write-offs in Q2 | 950,000 |
| **AR closing (2026-06-30)** | **25,975,000** |

Identity check: `18,200,000 + 183,944,000 − 173,419,000 − 1,800,000 − 950,000 = 25,975,000` ✓

(Exact figures are generated deterministically by `generate.py` from a seed; the source is `vectors/<file>.json` after running that script.)

## Q sub-satoshi units (forward note)

When the bonded-subsat-channel integration lands, each satoshi will subdivide into Q units (the sub-satoshi quanta the channel maintains off-chain). At that point this example will gain a second amounts column denominated in Q. The accounting equation is unchanged — only the unit and the integer magnitude shift — so the `vaa-accounting` types accept Q-unit amounts unchanged, as long as they still fit in `u64`. (`u64` holds 1.8 × 10^19; a satoshi divided into a billion Q gives 10^17 Q per 10^8 satoshi per BSV, well within range.)

## Anonymisation

The counterparty names and figures are fictitious. The hashes are deterministic from the note bodies and reproducible. No real customer data appears in this directory.
