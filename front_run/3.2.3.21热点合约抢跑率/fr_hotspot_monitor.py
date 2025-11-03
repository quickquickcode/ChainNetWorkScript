#!/usr/bin/env python3
"""Monitor hot-contract front-running rate based on trigger output."""

from __future__ import annotations

import argparse
import json
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

PIPE_SCHEMA = "fr-trigger-tx-v1"
GROUND_TRUTH_SCHEMA = "fr-trigger-event-v1"


@dataclass
class EventInfo:
    pair_id: int
    event_id: Optional[str] = None
    target_address: Optional[str] = None
    first_seen: Optional[float] = None
    is_hot: Optional[bool] = None
    counted: bool = False


class GroundTruthFollower:
    def __init__(self, path: Path):
        self.path = path
        self.position = 0

    def read_new(self) -> List[Dict[str, object]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            handle.seek(self.position)
            lines = handle.readlines()
            self.position = handle.tell()
        payloads: List[Dict[str, object]] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                payloads.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return payloads


class HotList:
    def __init__(self, path: Path):
        self.path = path
        self.addresses: set[str] = set()
        self.mtime: Optional[float] = None
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        if not self.path:
            return
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            if force:
                print(f"[WARN] hot list file {self.path} not found; using empty set")
            self.addresses = set()
            self.mtime = None
            return
        if not force and self.mtime == mtime:
            return
        entries: set[str] = set()
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entries.add(stripped.lower())
        self.addresses = entries
        self.mtime = mtime
        print(f"[INFO] loaded {len(entries)} hot addresses from {self.path}")

    def is_hot(self, address: Optional[str]) -> Optional[bool]:
        if not address:
            return None
        return address.lower() in self.addresses


def pipe_listener(pipe_path: Path, sink: queue.Queue, stop_flag: threading.Event) -> None:
    while not stop_flag.is_set():
        try:
            with pipe_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if stop_flag.is_set():
                        return
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if payload.get("schema") != PIPE_SCHEMA:
                        continue
                    sink.put(payload)
        except FileNotFoundError:
            time.sleep(1)
        except OSError:
            time.sleep(0.5)


def apply_ground_truth(payloads: Iterable[Dict[str, object]], states: Dict[int, EventInfo]) -> None:
    for payload in payloads:
        if payload.get("schema") != GROUND_TRUTH_SCHEMA:
            continue
        try:
            pair_id = int(payload.get("pair_id", 0))
        except (ValueError, TypeError):
            continue
        if pair_id <= 0:
            continue
        state = states.setdefault(pair_id, EventInfo(pair_id=pair_id))
        state.event_id = payload.get("event_id", state.event_id)
        state.target_address = payload.get("target_address", state.target_address)


def apply_pipe(payload: Dict[str, object], states: Dict[int, EventInfo]) -> None:
    try:
        pair_id = int(payload.get("pair_id", 0))
    except (ValueError, TypeError):
        return
    if pair_id <= 0:
        return
    state = states.setdefault(pair_id, EventInfo(pair_id=pair_id))
    state.first_seen = state.first_seen or float(payload.get("timestamp", time.time()))
    role = payload.get("role")
    if role == "victim" or role == "runner":
        to_address = payload.get("to")
        if to_address:
            state.target_address = to_address


def ensure_output(path: Optional[Path]):
    if not path:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor hot contract front-running rate")
    parser.add_argument("--pipe", type=Path, required=True, help="FIFO path emitted by trigger")
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground-truth JSONL file")
    parser.add_argument("--hot-contracts", type=Path, required=True, help="Hot contract address list")
    parser.add_argument("--list-version", default="unknown", help="Hot list version identifier")
    parser.add_argument("--status-interval", type=float, default=10.0, help="Seconds between status logs")
    parser.add_argument("--output", type=Path, help="Per-event JSONL output path")
    parser.add_argument("--refresh-interval", type=float, default=30.0, help="Seconds between hot list reloads")
    args = parser.parse_args()

    hot_list = HotList(args.hot_contracts)
    gt_follower = GroundTruthFollower(args.ground_truth)
    states: Dict[int, EventInfo] = {}
    totals = {"total": 0, "hot": 0}
    per_target: Dict[str, int] = {}

    output_fp = ensure_output(args.output)

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    last_status = 0.0
    last_refresh = 0.0

    def record_state(state: EventInfo) -> None:
        if state.counted or state.is_hot is None:
            return
        state.counted = True
        totals["total"] += 1
        if state.is_hot:
            totals["hot"] += 1
        target = (state.target_address or "0x").lower()
        per_target[target] = per_target.get(target, 0) + 1
        if output_fp:
            payload = {
                "pair_id": state.pair_id,
                "event_id": state.event_id,
                "target_address": state.target_address,
                "is_hot": state.is_hot,
                "list_version": args.list_version,
                "first_seen": state.first_seen,
                "timestamp": time.time(),
            }
            output_fp.write(json.dumps(payload, ensure_ascii=True) + "\n")
            output_fp.flush()

    try:
        # Prime with existing ground truth data
        apply_ground_truth(gt_follower.read_new(), states)
        while True:
            # FIFO events
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                apply_pipe(payload, states)
            # Ground truth tail
            apply_ground_truth(gt_follower.read_new(), states)

            now = time.time()
            # Maybe refresh hot list
            if now - last_refresh >= args.refresh_interval:
                hot_list.reload()
                last_refresh = now

            for state in list(states.values()):
                if state.is_hot is None and state.target_address:
                    state.is_hot = hot_list.is_hot(state.target_address)
                record_state(state)

            if now - last_status >= args.status_interval:
                last_status = now
                total = totals["total"]
                hot = totals["hot"]
                rate = hot / total if total else 0.0
                print(f"[STATUS] total={total} hot={hot} rate={rate:.3f} version={args.list_version}")
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        if output_fp:
            output_fp.close()
        total = totals["total"]
        hot = totals["hot"]
        rate = hot / total if total else 0.0
        print(f"[SUMMARY] total={total} hot={hot} rate={rate:.3f} version={args.list_version}")
        top_items = sorted(per_target.items(), key=lambda kv: kv[1], reverse=True)[:10]
        for address, count in top_items:
            print(f"  - {address}: {count}")


if __name__ == "__main__":
    main()
