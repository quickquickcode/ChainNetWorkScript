#!/usr/bin/env python3
"""Summarize visibility metrics from detect_visibility JSONL output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, Optional


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize malicious visibility JSONL logs")
    parser.add_argument("path", help="Path to visibility.jsonl produced by detect_visibility.py")
    parser.add_argument(
        "--window",
        type=float,
        default=None,
        help="Optional maximum age (seconds) of records to include; defaults to all",
    )
    return parser.parse_args()


def load_records(path: Path, window: Optional[float]) -> Dict[str, dict]:
    records: Dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            tx_hash = data.get("tx_hash")
            if not tx_hash:
                continue
            if window is not None:
                timestamp = data.get("timestamp")
                if timestamp is not None and data.get("flag_time") is not None:
                    if timestamp - data["flag_time"] > window:
                        continue
            records[tx_hash] = data
    return records


def summarize(records: Iterable[dict]) -> None:
    total = 0
    rejected = 0
    with_reason = 0
    accum_delay = 0.0
    delay_samples = 0

    for record in records:
        total += 1
        status = record.get("status")
        if status == "rejected" or status == "mined_failed":
            rejected += 1
        reason = record.get("reason")
        if reason:
            with_reason += 1
        flag_time = record.get("flag_time")
        first_seen = record.get("first_seen")
        if flag_time is not None and first_seen is not None:
            accum_delay += flag_time - first_seen
            delay_samples += 1

    if total == 0:
        print("No records found.")
        return

    vr = rejected / total if total else 0.0
    fr = with_reason / rejected if rejected else 0.0
    ar = accum_delay / delay_samples if delay_samples else 0.0

    print(f"Total malicious tx: {total}")
    print(f"Rejections (including mined_failed): {rejected} -> VR={vr:.4f}")
    print(f"Rejections with explicit reason: {with_reason} -> FR={fr:.4f}")
    print(f"Average response time (s): {ar:.3f}")


def main() -> None:
    args = parse_args()
    path = Path(args.path)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    records = load_records(path, args.window)
    summarize(records.values())


if __name__ == "__main__":
    main()
