#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Craig Wright

"""One-command full-stack demo of the BSV-anchoring + selective-verification flow.

Runs the entire pipeline end to end in five labelled steps:

    1. Load a settlement-ledger JSON (synthetic by default; pass
       --ledger=<path> to load a real one).
    2. Load the realistic quarterly accounting record batch from
       examples/realistic_quarter/records.json as the off-chain ledger.
    3. Anchor the batch via `vaa anchor` and print the BSV-canonical
       Merkle root.
    4. Verify the pre-built proof bundle for record #17 via `vaa verify`.
    5. Fetch a BSV mainnet block (default --bsv-block=170) and verify
       via `vaa anchor` that the published header merkleroot reconstructs
       from the live tx-ordered txid list.

Self-contained: needs only the `vaa` binary on PATH (or $VAA) and the
deterministic realistic-quarter generator output. The BSV block is real.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent


def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def run_vaa(vaa: str, args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        [vaa, *args], capture_output=True, text=True, cwd=cwd, check=False
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"vaa {args[0]} failed (exit {proc.returncode})")
    return proc.stdout


def fetch_bsv_block(api: str, height: int) -> dict:
    url = f"{api.rstrip('/')}/v1/bsv/main/block/height/{height}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "verifiable-accounting/0.3.0 (+bsv) full_stack_demo.py",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        raise SystemExit(f"BSV API failed for {url}: {e}")


def synthetic_settlement_ledger() -> dict:
    """Stand-in settlement record. Real input would be the auditor's actual
    settlement JSON from their accounting workflow."""
    return {
        "settlement_id": "settlement-demo-0001",
        "parties": ["counterparty_a", "counterparty_b"],
        "units": "minor_units",
        "settlement_txid_display_be":
            double_sha256(b"full_stack_demo|settlement|0001")[::-1].hex(),
        "balances_minor_units": {
            "counterparty_a": 312_415,
            "counterparty_b": 287_010,
        },
    }


def step(n: int, total: int, title: str) -> None:
    bar = "=" * 60
    print()
    print(bar)
    print(f"  STEP {n}/{total}: {title}")
    print(bar)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--vaa", default=os.environ.get("VAA", "vaa"))
    parser.add_argument(
        "--ledger",
        type=Path,
        default=None,
        help="settlement-ledger JSON (uses synthetic if omitted)",
    )
    parser.add_argument(
        "--bsv-block",
        type=int,
        default=170,
        help="BSV mainnet block height to verify (default 170)",
    )
    parser.add_argument("--bsv-api", default="https://api.whatsonchain.com")
    args = parser.parse_args()

    records_path = REPO_ROOT / "examples" / "realistic_quarter" / "records.json"
    if not records_path.exists():
        raise SystemExit(
            f"missing {records_path}; run examples/realistic_quarter/generate.py first"
        )

    step(1, 5, "Load settlement-ledger record")
    if args.ledger is not None:
        ledger = json.loads(args.ledger.read_text())
        print(f"  loaded real ledger from {args.ledger}")
    else:
        ledger = synthetic_settlement_ledger()
        print("  (synthetic ledger — pass --ledger for a real one)")
    print(f"  settlement id        : {ledger.get('settlement_id')}")
    print(f"  parties              : {', '.join(ledger.get('parties', []))}")
    print(f"  settlement txid (BE) : {ledger.get('settlement_txid_display_be')}")

    step(2, 5, "Load realistic-quarter accounting records")
    records_count = len(json.loads(records_path.read_text())["records_hex"])
    print(f"  records file : {records_path.relative_to(REPO_ROOT)}")
    print(f"  records      : {records_count}")

    step(3, 5, "Anchor the record batch — `vaa anchor`")
    # `vaa anchor` reads leaves JSON. Hash each record into a leaf first.
    with tempfile.TemporaryDirectory(prefix="vaa-fs-") as td:
        leaves_path = Path(td) / "leaves.json"
        rec_hex_list = json.loads(records_path.read_text())["records_hex"]
        leaves = [double_sha256(bytes.fromhex(h)) for h in rec_hex_list]
        leaves_path.write_text(
            json.dumps(
                {"leaves_display_be": [h[::-1].hex() for h in leaves]}, indent=2
            )
        )
        out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
        print(out.rstrip())

    step(4, 5, "Verify the pre-built record-17 bundle — `vaa verify`")
    bundle_path = REPO_ROOT / "examples" / "realistic_quarter" / "bundle_record_017.json"
    if not bundle_path.exists():
        raise SystemExit(
            f"missing {bundle_path}; run examples/realistic_quarter/generate.py first"
        )
    out = run_vaa(args.vaa, ["verify", "--bundle", str(bundle_path)])
    print(out.rstrip())

    step(5, 5, f"Verify BSV mainnet block {args.bsv_block} merkleroot — `vaa anchor`")
    block = fetch_bsv_block(args.bsv_api, args.bsv_block)
    txids = block.get("tx") or []
    if not txids:
        raise SystemExit(
            "BSV API returned no tx list (this block may be pruned at the public endpoint)"
        )
    print(f"  block hash       : {block['hash']}")
    print(f"  header merkleroot: {block['merkleroot']}")
    print(f"  tx count         : {len(txids)}")

    with tempfile.TemporaryDirectory(prefix="vaa-fs-b-") as td:
        leaves_path = Path(td) / "leaves.json"
        leaves_path.write_text(json.dumps({"leaves_display_be": txids}, indent=2))
        out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
        print(out.rstrip())
        computed = None
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("root (display)"):
                computed = s.split(":", 1)[1].strip()
                break
        if computed != block["merkleroot"]:
            raise SystemExit(
                f"BSV merkleroot mismatch:\n  computed  : {computed}\n  published : {block['merkleroot']}"
            )

    print()
    print("=" * 60)
    print("  FULL-STACK DEMO OK")
    print("=" * 60)
    print(
        "  settlement ledger → record batch → vaa anchor / verify → BSV mainnet header"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
