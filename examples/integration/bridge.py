#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Craig Wright

"""Runnable integration bridge for the two sister repositories.

Demonstrates two end-to-end flows that use the `vaa` CLI as the BSV-anchoring
+ Merkle + Pedersen layer underneath:

    1. triple-entry-evidence  ->  vaa
       Take a batch of TEA-style note bodies, hash each to a leaf, build the
       Merkle root via `vaa anchor`, then produce + verify a proof bundle for
       one note via `vaa prove` + `vaa verify`.

    2. bonded-subsat-channel  ->  vaa
       Take an ordered list of BSV txids for a block that contains a channel
       settlement transaction, build the BSV-canonical Merkle root via
       `vaa anchor`, and verify the published header's `merkleroot` matches.

Both flows are self-contained: they shell out to the `vaa` binary and parse
its stdout / written JSON files. No native Rust binding is required; the
sister repositories stay independent of this workspace's language choice.

USAGE
    python bridge.py demo-tea
    python bridge.py demo-channel <block-height>

The TEA demo uses synthetic note bodies (so the script runs offline). The
channel demo fetches block data live from the WhatsOnChain BSV API (default
endpoint, override with --api=<url>).

REQUIREMENTS
    - python 3.10+
    - the `vaa` binary on PATH (or pass --vaa=<path>)
    - for `demo-channel`: outbound HTTPS to the BSV API
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
    """Convert internal little-endian Bitcoin/BSV bytes to display big-endian hex."""
    return internal_le[::-1].hex()


def from_display_be(display_be_hex: str) -> bytes:
    """Convert display big-endian hex to internal little-endian bytes."""
    return bytes.fromhex(display_be_hex.strip())[::-1]


def run_vaa(vaa: str, args: list[str], cwd: Path | None = None) -> str:
    """Invoke the vaa CLI and return its stdout. Raises on non-zero exit."""
    proc = subprocess.run(
        [vaa, *args], capture_output=True, text=True, cwd=cwd, check=False
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"vaa {args[0]} failed (exit {proc.returncode})")
    return proc.stdout


# --------------------------------------------------------------------------
# demo-tea: triple-entry-evidence -> vaa
# --------------------------------------------------------------------------


def synthetic_tea_notes(n: int) -> list[bytes]:
    """Produce n deterministic synthetic TEA note bodies.

    A real bridge would parse the JSON output of triple-entry-evidence's
    refimpl.py and extract the canonical serialised note bodies. Here we
    use a deterministic stand-in so the script runs without that repo
    installed: each note is `b"TEA-note-{i}"` padded to a stable length.
    """
    return [(f"TEA-note-body-{i:05d}").encode("ascii").ljust(64, b"\x00") for i in range(n)]


def cmd_demo_tea(args: argparse.Namespace) -> int:
    notes = synthetic_tea_notes(args.notes)
    # Step 1 — hash each note to a leaf (display BE form for vaa).
    leaves_display_be = [to_display_be(double_sha256(n)) for n in notes]
    print(f"TEA bridge: {len(notes)} notes hashed to leaves")

    workdir = Path(tempfile.mkdtemp(prefix="vaa-tea-"))
    leaves_path = workdir / "leaves.json"
    leaves_path.write_text(json.dumps({"leaves_display_be": leaves_display_be}, indent=2))
    print(f"  wrote {leaves_path}")

    # Step 2 — anchor (build the root via vaa).
    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    # Step 3 — prove inclusion of a chosen note + commit a value.
    chosen_index = args.index
    if chosen_index >= len(notes):
        raise SystemExit(f"--index {chosen_index} out of range for {len(notes)} notes")
    value = args.value
    blinding = secrets.token_bytes(32)
    # Reject zero blinding (vanishingly unlikely from token_bytes but the
    # contract is explicit).
    while blinding == b"\x00" * 32:
        blinding = secrets.token_bytes(32)
    bundle_path = workdir / "bundle.json"
    run_vaa(
        args.vaa,
        [
            "prove",
            "--leaves", str(leaves_path),
            "--index", str(chosen_index),
            "--value", str(value),
            "--blinding-hex", blinding.hex(),
            "--out", str(bundle_path),
        ],
    )
    print(f"--- vaa prove ---")
    print(f"  wrote {bundle_path} (value={value}, leaf #{chosen_index})")

    # Step 4 — verify the bundle.
    out = run_vaa(args.vaa, ["verify", "--bundle", str(bundle_path)])
    print("--- vaa verify ---")
    print(out.rstrip())

    print()
    print(f"TEA bridge demo OK. Working files preserved in {workdir}")
    return 0


# --------------------------------------------------------------------------
# demo-channel: bonded-subsat-channel -> vaa
# --------------------------------------------------------------------------


def fetch_bsv_block(api: str, height: int) -> dict:
    """Fetch the block header + tx list for a BSV mainnet block by height.

    Uses the WhatsOnChain BSV API by default. The script sends a project
    User-Agent so the API does not treat it as an unknown bot.
    """
    url = f"{api.rstrip('/')}/v1/bsv/main/block/height/{height}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "verifiable-accounting/0.2.0 (+github.com/prof-faustus/verifiable-accounting) bridge.py",
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


def cmd_demo_channel(args: argparse.Namespace) -> int:
    print(f"channel bridge: fetching BSV mainnet block height {args.height} from {args.api}")
    block = fetch_bsv_block(args.api, args.height)
    txids: list[str] = block.get("tx") or []
    merkleroot: str = block["merkleroot"]
    print(f"  block hash    : {block['hash']}")
    print(f"  merkleroot    : {merkleroot}")
    print(f"  tx count      : {len(txids)}")
    if not txids:
        raise SystemExit(
            "The API returned no tx list (block may be pruned for the public endpoint). "
            "Try a different height or a non-pruned endpoint."
        )

    workdir = Path(tempfile.mkdtemp(prefix="vaa-chan-"))
    leaves_path = workdir / "leaves.json"
    leaves_path.write_text(json.dumps({"leaves_display_be": txids}, indent=2))
    print(f"  wrote {leaves_path}")

    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    # Extract the computed root (display form) from `vaa anchor` output.
    computed_root: str | None = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("root (display):"):
            computed_root = line.split(":", 1)[1].strip()
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
        f"channel bridge OK: vaa-computed root == published header merkleroot for block {args.height}"
    )
    print(f"  working files preserved in {workdir}")
    return 0


# --------------------------------------------------------------------------
# from-channel-ledger: ingest a real bonded-subsat-channel JSON record
# --------------------------------------------------------------------------


CHANNEL_LEDGER_SCHEMA = """
A JSON object with at minimum:

  {
    "channel_id": "<string>",
    "settlement_txid_display_be": "<64-char big-endian hex>",
    "parties": ["<party>", ...],            // optional, informational
    "final_balances_q": { ... }             // optional, informational
  }

The settlement_txid_display_be field is the on-chain settlement transaction
id emitted by `channel close` / `channel contested`. Everything else is
informational and not required by the bridge.
"""


def cmd_from_channel_ledger(args: argparse.Namespace) -> int:
    try:
        ledger = json.loads(args.ledger.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"could not read/parse {args.ledger}: {e}")
    txid = ledger.get("settlement_txid_display_be")
    if not isinstance(txid, str) or len(txid) != 64:
        raise SystemExit(
            "channel ledger is missing 'settlement_txid_display_be' (a 64-char "
            "big-endian hex string).\n\nExpected schema:" + CHANNEL_LEDGER_SCHEMA
        )

    print(f"channel ledger: {args.ledger}")
    print(f"  channel_id     : {ledger.get('channel_id', '(unset)')}")
    print(f"  settlement txid: {txid}")
    print(f"  block height   : {args.bsv_block_height}")

    block = fetch_bsv_block(args.api, args.bsv_block_height)
    txids = block.get("tx") or []
    if not txids:
        raise SystemExit("BSV API returned no tx list (block may be pruned at this endpoint)")
    if txid not in txids:
        raise SystemExit(
            f"settlement txid {txid} not found in block {args.bsv_block_height} "
            f"({len(txids)} txs). The channel ledger's block_height may be wrong."
        )
    leaf_index = txids.index(txid)
    print(f"  found at index : {leaf_index} (of {len(txids)})")

    workdir = Path(tempfile.mkdtemp(prefix="vaa-chl-"))
    leaves_path = workdir / "leaves.json"
    leaves_path.write_text(json.dumps({"leaves_display_be": txids}, indent=2))

    out = run_vaa(args.vaa, ["anchor", "--leaves", str(leaves_path)])
    print("--- vaa anchor ---")
    print(out.rstrip())

    # Confirm root matches block header so the verifier knows the leaf list is canonical.
    computed_root: str | None = None
    for line in out.splitlines():
        if line.strip().startswith("root (display):"):
            computed_root = line.split(":", 1)[1].strip()
            break
    if computed_root != block["merkleroot"]:
        raise SystemExit(
            f"merkleroot mismatch (block tx list does not reconstruct to header root):\n"
            f"  computed : {computed_root}\n  header   : {block['merkleroot']}"
        )
    print(f"  header check OK (computed root == block {args.bsv_block_height} merkleroot)")

    # Produce a real inclusion proof bundle for the settlement tx.
    bundle_path = workdir / "settlement_inclusion.json"
    # The value/blinding fields are placeholders for inclusion-only mode.
    placeholder_blinding = secrets.token_bytes(32)
    while placeholder_blinding == b"\x00" * 32:
        placeholder_blinding = secrets.token_bytes(32)
    run_vaa(
        args.vaa,
        [
            "prove",
            "--leaves", str(leaves_path),
            "--index", str(leaf_index),
            "--value", "0",
            "--blinding-hex", placeholder_blinding.hex(),
            "--out", str(bundle_path),
        ],
    )
    print(f"--- vaa prove ---  bundle: {bundle_path}")

    out = run_vaa(args.vaa, ["verify", "--bundle", str(bundle_path)])
    print("--- vaa verify ---")
    print(out.rstrip())

    print()
    print(
        f"channel-ledger -> vaa OK. Settlement tx is provably included in BSV block "
        f"{args.bsv_block_height} at index {leaf_index}."
    )
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--vaa",
        default=os.environ.get("VAA", "vaa"),
        help="path to the vaa binary (default: vaa on PATH, override with $VAA)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_tea = sub.add_parser("demo-tea", help="triple-entry-evidence -> vaa anchoring round-trip")
    p_tea.add_argument("--notes", type=int, default=16, help="number of synthetic notes (default 16)")
    p_tea.add_argument("--index", type=int, default=3, help="leaf index to prove (default 3)")
    p_tea.add_argument("--value", type=int, default=12100, help="value to commit in the bundle (default 12100)")
    p_tea.set_defaults(func=cmd_demo_tea)

    p_chan = sub.add_parser(
        "demo-channel", help="bonded-subsat-channel -> vaa block-merkle verification"
    )
    p_chan.add_argument("height", type=int, help="BSV mainnet block height to verify")
    p_chan.add_argument(
        "--api",
        default="https://api.whatsonchain.com",
        help="BSV REST API base URL (default: WhatsOnChain). Override for a private/pruned endpoint.",
    )
    p_chan.set_defaults(func=cmd_demo_channel)

    p_fcl = sub.add_parser(
        "from-channel-ledger",
        help="Take a bonded-subsat-channel JSON ledger and produce a vaa inclusion proof for its settlement tx",
    )
    p_fcl.add_argument("ledger", type=Path, help="Path to the channel-ledger JSON (see schema in docstring)")
    p_fcl.add_argument("--bsv-block-height", type=int, required=True,
                       help="Block height the settlement landed in (used to fetch the canonical tx list)")
    p_fcl.add_argument("--api", default="https://api.whatsonchain.com")
    p_fcl.set_defaults(func=cmd_from_channel_ledger)

    args = parser.parse_args(list(argv))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
