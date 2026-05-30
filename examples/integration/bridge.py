#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Craig Wright

"""Runnable integration bridge for the two BSV-native accounting flows.

Demonstrates two end-to-end flows that use the `vaa` CLI as the BSV-anchoring
+ Merkle Proof Entity + selective-verification layer underneath:

    1. anchor-records      Hash a batch of accounting records, build the
                           BSV-canonical Merkle root via `vaa anchor`,
                           produce + verify a proof bundle for one chosen
                           record via `vaa prove` + `vaa verify`.

    2. verify-bsv-block <h> Fetch a BSV mainnet block at height <h>, feed
                           the canonical tx-ordered txid list to `vaa anchor`,
                           and assert the computed Merkle root matches the
                           published header merkleroot.

    3. from-settlement     Take a settlement-ledger JSON record, fetch its
                           BSV block, verify the block tx list reconstructs
                           to the header merkleroot, and produce an
                           inclusion proof bundle for the settlement txid.

The script is self-contained: it does not require any external library
beyond the Python standard library and the `vaa` binary on PATH (or $VAA).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def to_display_be(internal_le: bytes) -> str:
    return internal_le[::-1].hex()


def from_display_be(display_be_hex: str) -> bytes:
    return bytes.fromhex(display_be_hex.strip())[::-1]


def run_vaa(vaa: str, args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(
        [vaa, *args], capture_output=True, text=True, cwd=cwd, check=False
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"vaa {args[0]} failed (exit {proc.returncode})")
    return proc.stdout


# --------------------------------------------------------------------------
# anchor-records: synthetic accounting records -> vaa anchor + prove + verify
# --------------------------------------------------------------------------


def synthetic_records(n: int) -> list[bytes]:
    """n deterministic synthetic accounting record bodies.

    A real bridge would parse the integrating system's record format. Here
    we use a deterministic stand-in so the script runs offline: each record
    is a canonical JSON object with a sequential id and a stable structure.
    """
    out: list[bytes] = []
    for i in range(n):
        obj = {
            "kind": "invoice" if i % 2 == 0 else "receipt",
            "id": i,
            "value": 1_000_000 + (i * 137) % 9_000_000,
            "counterparty": f"counterparty-{i % 12:02d}",
        }
        out.append(
            json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("ascii")
        )
    return out


def cmd_anchor_records(args: argparse.Namespace) -> int:
    records = synthetic_records(args.records_count)
    workdir = Path(tempfile.mkdtemp(prefix="vaa-rec-"))

    records_path = workdir / "records.json"
    records_path.write_text(
        json.dumps({"records_hex": [r.hex() for r in records]}, indent=2)
    )
    print(f"records bridge: {len(records)} records → {records_path}")

    out = run_vaa(args.vaa, ["anchor", "--leaves", str(workdir / "leaves.json")]) if False else ""
    # `vaa anchor` reads leaves JSON, not records JSON. Build the leaves
    # JSON from the records first.
    leaves_path = workdir / "leaves.json"
    leaves = [double_sha256(r) for r in records]
    leaves_path.write_text(
        json.dumps({"leaves_display_be": [to_display_be(h) for h in leaves]}, indent=2)
    )
    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    chosen = args.index
    if chosen >= len(records):
        raise SystemExit(f"--index {chosen} out of range for {len(records)} records")
    bundle_path = workdir / "bundle.json"
    run_vaa(
        args.vaa,
        [
            "prove",
            "--records", str(records_path),
            "--index", str(chosen),
            "--out", str(bundle_path),
        ],
    )
    print(f"--- vaa prove ---  wrote {bundle_path}")

    out = run_vaa(args.vaa, ["verify", "--bundle", str(bundle_path)])
    print("--- vaa verify ---")
    print(out.rstrip())

    print()
    print(f"anchor-records demo OK. Working files preserved in {workdir}")
    return 0


# --------------------------------------------------------------------------
# verify-bsv-block: live BSV mainnet block merkleroot check
# --------------------------------------------------------------------------


def fetch_bsv_block(api: str, height: int) -> dict:
    """Fetch the block header + tx list for a BSV mainnet block by height.

    Uses a public BSV explorer endpoint. Sends a project User-Agent so the
    endpoint does not treat the request as an unknown bot.
    """
    url = f"{api.rstrip('/')}/v1/bsv/main/block/height/{height}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "verifiable-accounting/0.3.0 (+bsv) bridge.py",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"BSV API HTTP {e.code} for {url}: {e.reason}")
    except urllib.error.URLError as e:
        raise SystemExit(f"BSV API unreachable ({url}): {e.reason}")


def cmd_verify_bsv_block(args: argparse.Namespace) -> int:
    print(f"BSV block verify: fetching BSV mainnet block height {args.height} from {args.api}")
    block = fetch_bsv_block(args.api, args.height)
    txids: list[str] = block.get("tx") or []
    merkleroot: str = block["merkleroot"]
    print(f"  block hash : {block['hash']}")
    print(f"  merkleroot : {merkleroot}")
    print(f"  tx count   : {len(txids)}")
    if not txids:
        raise SystemExit(
            "BSV API returned no tx list (this block may be pruned at the public endpoint). "
            "Try a different height or a non-pruned endpoint."
        )

    workdir = Path(tempfile.mkdtemp(prefix="vaa-block-"))
    leaves_path = workdir / "leaves.json"
    leaves_path.write_text(json.dumps({"leaves_display_be": txids}, indent=2))
    print(f"  wrote {leaves_path}")

    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    computed_root: str | None = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("root (display)"):
            computed_root = s.split(":", 1)[1].strip()
            break
    if computed_root is None:
        raise SystemExit("could not parse computed root from `vaa anchor` output")

    if computed_root != merkleroot:
        raise SystemExit(
            f"MERKLE-ROOT MISMATCH\n"
            f"  computed by vaa : {computed_root}\n"
            f"  header value    : {merkleroot}\n"
            f"This means the leaves we fed to vaa do not match the canonical "
            f"tx-order of the block. Check the tx list ordering and byte order."
        )
    print()
    print(
        f"BSV block verify OK: vaa-computed root == published header merkleroot for block {args.height}"
    )
    print(f"  working files preserved in {workdir}")
    return 0


# --------------------------------------------------------------------------
# from-settlement: ingest a settlement-ledger JSON
# --------------------------------------------------------------------------


SETTLEMENT_LEDGER_SCHEMA = """
A JSON object with at minimum:

  {
    "settlement_id": "<string>",
    "settlement_txid_display_be": "<64-char big-endian hex>",
    "parties": ["<party>", ...],            // optional, informational
    "balances_minor_units": { ... }         // optional, informational
  }
"""


def cmd_from_settlement(args: argparse.Namespace) -> int:
    try:
        ledger = json.loads(args.ledger.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"could not read/parse {args.ledger}: {e}")
    txid = ledger.get("settlement_txid_display_be")
    if not isinstance(txid, str) or len(txid) != 64:
        raise SystemExit(
            "ledger is missing 'settlement_txid_display_be' (a 64-char big-endian hex string).\n\n"
            + "Expected schema:" + SETTLEMENT_LEDGER_SCHEMA
        )

    print(f"settlement ledger : {args.ledger}")
    print(f"  settlement_id    : {ledger.get('settlement_id', '(unset)')}")
    print(f"  settlement txid  : {txid}")
    print(f"  bsv block height : {args.bsv_block_height}")

    block = fetch_bsv_block(args.api, args.bsv_block_height)
    txids = block.get("tx") or []
    if not txids:
        raise SystemExit("BSV API returned no tx list (block may be pruned at this endpoint)")
    if txid not in txids:
        raise SystemExit(
            f"settlement txid {txid} not found in block {args.bsv_block_height} "
            f"({len(txids)} txs). The ledger's block_height may be wrong."
        )
    leaf_index = txids.index(txid)
    print(f"  found at index   : {leaf_index} of {len(txids)}")

    workdir = Path(tempfile.mkdtemp(prefix="vaa-set-"))
    leaves_path = workdir / "leaves.json"
    leaves_path.write_text(json.dumps({"leaves_display_be": txids}, indent=2))

    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    computed_root: str | None = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("root (display)"):
            computed_root = s.split(":", 1)[1].strip()
            break
    if computed_root != block["merkleroot"]:
        raise SystemExit(
            f"merkleroot mismatch:\n"
            f"  computed : {computed_root}\n  header   : {block['merkleroot']}"
        )
    print(f"  header check OK (computed root == block {args.bsv_block_height} merkleroot)")

    # Build a records.json for the txid (record = the raw txid bytes).
    records_path = workdir / "records.json"
    records_path.write_text(
        json.dumps({"records_hex": [t for t in txids]}, indent=2)
    )
    bundle_path = workdir / "settlement_inclusion.json"
    run_vaa(
        args.vaa,
        [
            "prove",
            "--records", str(records_path),
            "--index", str(leaf_index),
            "--out", str(bundle_path),
        ],
    )
    print(f"--- vaa prove ---  bundle: {bundle_path}")

    out = run_vaa(args.vaa, ["verify", "--bundle", str(bundle_path)])
    print("--- vaa verify ---")
    print(out.rstrip())

    print()
    print(
        f"settlement-ledger → vaa OK. Settlement txid is provably included in BSV block "
        f"{args.bsv_block_height} at index {leaf_index}."
    )
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--vaa",
        default=os.environ.get("VAA", "vaa"),
        help="path to the vaa binary (default: vaa on PATH, override with $VAA)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser(
        "anchor-records", help="anchor a batch of synthetic accounting records and verify one"
    )
    p_rec.add_argument(
        "--records-count", type=int, default=16, help="number of synthetic records (default 16)"
    )
    p_rec.add_argument("--index", type=int, default=3, help="record index to prove (default 3)")
    p_rec.set_defaults(func=cmd_anchor_records)

    p_blk = sub.add_parser(
        "verify-bsv-block",
        help="fetch a BSV mainnet block and verify its merkleroot is reconstructed from the canonical tx list",
    )
    p_blk.add_argument("height", type=int, help="BSV mainnet block height to verify")
    p_blk.add_argument(
        "--api",
        default="https://api.whatsonchain.com",
        help="BSV REST API base URL (default: a public BSV explorer)",
    )
    p_blk.set_defaults(func=cmd_verify_bsv_block)

    p_set = sub.add_parser(
        "from-settlement",
        help="ingest a settlement-ledger JSON and produce an inclusion proof for its settlement txid",
    )
    p_set.add_argument("ledger", type=Path, help="path to the settlement-ledger JSON")
    p_set.add_argument(
        "--bsv-block-height", type=int, required=True,
        help="BSV mainnet block height the settlement landed in",
    )
    p_set.add_argument(
        "--api",
        default="https://api.whatsonchain.com",
        help="BSV REST API base URL (default: a public BSV explorer)",
    )
    p_set.set_defaults(func=cmd_from_settlement)

    args = parser.parse_args(list(argv))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
