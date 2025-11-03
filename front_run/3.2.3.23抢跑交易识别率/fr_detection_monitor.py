#!/usr/bin/env python3
"""Compute detection coverage for front-running events."""

from __future__ import annotations

import argparse
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

PIPE_SCHEMA = "fr-trigger-tx-v1"
GROUND_TRUTH_SCHEMA = "fr-trigger-event-v1"
DETECTION_SCHEMA = "fr-detector-event-v1"


@dataclass
class EventRecord:
    pair_id: int
    event_id: Optional[str] = None
    victim_hash: Optional[str] = None
    runner_hash: Optional[str] = None
    target_address: Optional[str] = None
    detected: bool = False
    detected_at: Optional[float] = None
    first_seen: Optional[float] = None


@dataclass
class DetectionEntry:
    raw: Dict[str, object]
    received_at: float = field(default_factory=time.time)

    @property
    def pair_id(self) -> Optional[int]:
        value = self.raw.get("pair_id")
        try:
            return int(value) if value is not None else None
        except (ValueError, TypeError):
            return None

    @property
    def event_id(self) -> Optional[str]:
        event_id = self.raw.get("event_id")
        return str(event_id) if event_id else None

    @property
    def victim_hash(self) -> Optional[str]:
        victim = self.raw.get("victim_hash")
        return str(victim) if victim else None

    @property
    def runner_hash(self) -> Optional[str]:
        runner = self.raw.get("runner_hash")
        return str(runner) if runner else None


class JsonlFollower:
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


def apply_pipe(payload: Dict[str, object], states: Dict[int, EventRecord]) -> None:
    try:
        pair_id = int(payload.get("pair_id", 0))
    except (ValueError, TypeError):
        return
    if pair_id <= 0:
        return
    state = states.setdefault(pair_id, EventRecord(pair_id=pair_id))
    state.first_seen = state.first_seen or float(payload.get("timestamp", time.time()))
    if payload.get("role") == "victim":
        state.victim_hash = payload.get("tx_hash", state.victim_hash)
    elif payload.get("role") == "runner":
        state.runner_hash = payload.get("tx_hash", state.runner_hash)
    state.target_address = payload.get("to", state.target_address)


def apply_ground_truth(payloads: Iterable[Dict[str, object]], states: Dict[int, EventRecord]) -> None:
    for payload in payloads:
        if payload.get("schema") != GROUND_TRUTH_SCHEMA:
            continue
        try:
            pair_id = int(payload.get("pair_id", 0))
        except (ValueError, TypeError):
            continue
        if pair_id <= 0:
            continue
        state = states.setdefault(pair_id, EventRecord(pair_id=pair_id))
        state.event_id = payload.get("event_id", state.event_id)
        state.victim_hash = payload.get("victim_hash", state.victim_hash)
        state.runner_hash = payload.get("runner_hash", state.runner_hash)
        state.target_address = payload.get("target_address", state.target_address)


def apply_detection(
    detections: Iterable[Dict[str, object]],
    pending: List[DetectionEntry],
    states: Dict[int, EventRecord],
    allow_partial: bool,
) -> None:
    for payload in detections:
        if payload.get("schema") != DETECTION_SCHEMA:
            continue
        entry = DetectionEntry(raw=payload)
        if not attempt_match(entry, states, allow_partial):
            pending.append(entry)


def attempt_match(entry: DetectionEntry, states: Dict[int, EventRecord], allow_partial: bool) -> bool:
    match = None
    if entry.pair_id and entry.pair_id in states:
        match = states[entry.pair_id]
    if not match and entry.event_id:
        match = next((state for state in states.values() if state.event_id == entry.event_id), None)
    if not match and entry.victim_hash and entry.runner_hash:
        match = next(
            (
                state
                for state in states.values()
                if state.victim_hash == entry.victim_hash and state.runner_hash == entry.runner_hash
            ),
            None,
        )
    if allow_partial and not match and entry.victim_hash:
        candidates = [state for state in states.values() if state.victim_hash == entry.victim_hash]
        if len(candidates) == 1:
            match = candidates[0]
    if match and not match.detected:
        match.detected = True
        match.detected_at = entry.received_at
        return True
    return False


def retry_pending(pending: List[DetectionEntry], states: Dict[int, EventRecord], allow_partial: bool) -> None:
    remaining: List[DetectionEntry] = []
    for entry in pending:
        if not attempt_match(entry, states, allow_partial):
            remaining.append(entry)
    pending[:] = remaining


def ensure_output(path: Optional[Path]):
    if not path:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor detection coverage for front-running")
    parser.add_argument("--pipe", type=Path, required=True, help="FIFO path emitted by trigger")
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground-truth JSONL file")
    parser.add_argument("--detections", type=Path, required=True, help="Detection engine JSONL output")
    parser.add_argument("--allow-partial", action="store_true", help="Allow victim-only matches when unique")
    parser.add_argument("--status-interval", type=float, default=10.0, help="Seconds between status prints")
    parser.add_argument("--output", type=Path, help="JSONL file for unmatched events")
    args = parser.parse_args()

    states: Dict[int, EventRecord] = {}
    gt_follower = JsonlFollower(args.ground_truth)
    det_follower = JsonlFollower(args.detections)
    pending: List[DetectionEntry] = []

    output_fp = ensure_output(args.output)

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    last_status = 0.0

    try:
        apply_ground_truth(gt_follower.read_new(), states)
        apply_detection(det_follower.read_new(), pending, states, args.allow_partial)
        retry_pending(pending, states, args.allow_partial)
        while True:
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                apply_pipe(payload, states)
            apply_ground_truth(gt_follower.read_new(), states)
            apply_detection(det_follower.read_new(), pending, states, args.allow_partial)
            retry_pending(pending, states, args.allow_partial)

            now = time.time()
            if now - last_status >= args.status_interval:
                last_status = now
                truth_states = [state for state in states.values() if state.event_id]
                total = len(truth_states)
                detected = sum(1 for state in truth_states if state.detected)
                coverage = detected / total if total else 0.0
                print(
                    f"[STATUS] total={total} detected={detected} coverage={coverage:.3f} pending={len(pending)}"
                )
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        truth_states = [state for state in states.values() if state.event_id]
        total = len(truth_states)
        detected = sum(1 for state in truth_states if state.detected)
        coverage = detected / total if total else 0.0
        print(f"[SUMMARY] total={total} detected={detected} coverage={coverage:.3f}")

        missed = [state for state in truth_states if not state.detected]
        if output_fp and missed:
            for state in missed:
                payload = {
                    "pair_id": state.pair_id,
                    "event_id": state.event_id,
                    "victim_hash": state.victim_hash,
                    "runner_hash": state.runner_hash,
                    "target_address": state.target_address,
                    "first_seen": state.first_seen,
                    "timestamp": time.time(),
                }
                output_fp.write(json.dumps(payload, ensure_ascii=True) + "\n")
            output_fp.flush()
            output_fp.close()
        elif output_fp:
            output_fp.close()

        if pending:
            print(f"[WARN] {len(pending)} detection entries unmatched; treat as false positives")
            for entry in pending[:10]:
                print(f"  - raw={entry.raw}")


if __name__ == "__main__":
    main()
