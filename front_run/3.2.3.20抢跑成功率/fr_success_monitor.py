#!/usr/bin/env python3
"""Monitor front-running success rate using ground-truth events and FIFO stream."""

from __future__ import annotations

import argparse
import json
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from web3 import Web3
from web3.exceptions import TransactionNotFound

PIPE_SCHEMA = "fr-trigger-tx-v1"
GROUND_TRUTH_SCHEMA = "fr-trigger-event-v1"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ReceiptInfo:
    status: Optional[int]
    block_number: Optional[int]
    tx_index: Optional[int]


@dataclass
class EventState:
    pair_id: int
    victim_hash: Optional[str] = None
    runner_hash: Optional[str] = None
    event_id: Optional[str] = None
    target_address: Optional[str] = None
    victim_seen: Optional[float] = None
    runner_seen: Optional[float] = None
    victim_receipt: Optional[ReceiptInfo] = None
    runner_receipt: Optional[ReceiptInfo] = None
    result: Optional[str] = None
    reason: Optional[str] = None
    last_polled: float = field(default_factory=lambda: 0.0)

    def ready_for_summary(self) -> bool:
        return self.result is not None


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def load_rpc_endpoints(args: argparse.Namespace) -> List[str]:
    endpoints: List[str] = []
    if args.hosts:
        with open(args.hosts, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    endpoints.append(stripped)
    endpoints.extend(args.rpc)
    if not endpoints:
        raise SystemExit("at least one RPC endpoint must be provided via --rpc or --hosts")
    return endpoints


def build_provider_pool(endpoints: List[str]) -> Iterable[Web3]:
    providers: List[Web3] = []
    for url in endpoints:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise SystemExit(f"failed to connect to RPC endpoint {url}")
        providers.append(w3)
    while True:
        for provider in providers:
            yield provider


def ensure_output(path: Optional[Path]):
    if not path:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


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
        events: List[Dict[str, object]] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(payload)
        return events


def apply_ground_truth(payloads: Iterable[Dict[str, object]], states: Dict[int, EventState]) -> None:
    for payload in payloads:
        if payload.get("schema") != GROUND_TRUTH_SCHEMA:
            continue
        try:
            pair_id = int(payload.get("pair_id", 0))
        except (ValueError, TypeError):
            continue
        if pair_id <= 0:
            continue
        state = states.setdefault(pair_id, EventState(pair_id=pair_id))
        state.event_id = payload.get("event_id")
        state.victim_hash = payload.get("victim_hash", state.victim_hash)
        state.runner_hash = payload.get("runner_hash", state.runner_hash)
        state.target_address = payload.get("target_address", state.target_address)


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


def apply_pipe_event(payload: Dict[str, object], states: Dict[int, EventState]) -> None:
    try:
        pair_id = int(payload.get("pair_id", 0))
    except (ValueError, TypeError):
        return
    if pair_id <= 0:
        return
    state = states.setdefault(pair_id, EventState(pair_id=pair_id))
    role = payload.get("role")
    timestamp = float(payload.get("timestamp", time.time()))
    if role == "victim":
        state.victim_hash = payload.get("tx_hash", state.victim_hash)
        state.victim_seen = state.victim_seen or timestamp
        state.target_address = payload.get("to", state.target_address)
    elif role == "runner":
        state.runner_hash = payload.get("tx_hash", state.runner_hash)
        state.runner_seen = state.runner_seen or timestamp
        state.target_address = payload.get("to", state.target_address)


def fetch_receipt(provider: Web3, tx_hash: str) -> Optional[ReceiptInfo]:
    try:
        receipt = provider.eth.get_transaction_receipt(tx_hash)
    except TransactionNotFound:
        return None
    except ValueError:
        return None
    status = receipt.get("status")
    block_number = receipt.get("blockNumber")
    tx_index = receipt.get("transactionIndex")
    return ReceiptInfo(status=status, block_number=block_number, tx_index=tx_index)


def classify_event(state: EventState, reject_delay: float) -> None:
    if not state.runner_receipt:
        return
    if state.runner_receipt.status != 1:
        state.result = "failure"
        state.reason = "runner_failed"
        return
    # Victim missing beyond reject delay => success
    now = time.time()
    if not state.victim_receipt:
        if state.runner_seen and now - state.runner_seen >= reject_delay:
            state.result = "success"
            state.reason = "victim_missing"
        return
    # Victim receipt exists; compare ordering
    victim = state.victim_receipt
    runner = state.runner_receipt
    if victim.block_number is None:
        state.result = "success"
        state.reason = "victim_pending"
        return
    if runner.block_number is None:
        return
    if victim.status != 1:
        state.result = "success"
        state.reason = "victim_failed"
        return
    if runner.block_number < victim.block_number:
        state.result = "success"
        state.reason = "runner_block_priority"
        return
    if runner.block_number > victim.block_number:
        state.result = "failure"
        state.reason = "victim_block_priority"
        return
    # Same block, compare transaction index
    if runner.tx_index is not None and victim.tx_index is not None:
        if runner.tx_index < victim.tx_index:
            state.result = "success"
            state.reason = "runner_tx_index"
        else:
            state.result = "failure"
            state.reason = "victim_tx_index"
    else:
        # Without transaction index, fall back to failure to avoid false positives
        state.result = "failure"
        state.reason = "tie_without_index"


def summary_snapshot(states: Dict[int, EventState]) -> Tuple[int, int, Dict[str, int]]:
    total = 0
    success = 0
    reasons: Dict[str, int] = {}
    for state in states.values():
        if not state.ready_for_summary():
            continue
        total += 1
        if state.result == "success":
            success += 1
        reasons[state.reason or "unknown"] = reasons.get(state.reason or "unknown", 0) + 1
    return total, success, reasons


def write_event(output, state: EventState) -> None:
    if not output or not state.ready_for_summary():
        return
    payload = {
        "pair_id": state.pair_id,
        "event_id": state.event_id,
        "victim_hash": state.victim_hash,
        "runner_hash": state.runner_hash,
        "target_address": state.target_address,
        "victim_seen": state.victim_seen,
        "runner_seen": state.runner_seen,
        "victim_receipt": state.victim_receipt.__dict__ if state.victim_receipt else None,
        "runner_receipt": state.runner_receipt.__dict__ if state.runner_receipt else None,
        "result": state.result,
        "reason": state.reason,
        "timestamp": time.time(),
    }
    output.write(json.dumps(payload, ensure_ascii=True) + "\n")
    output.flush()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor front-running success rate")
    parser.add_argument("--rpc", action="append", default=[], help="HTTP RPC endpoint; repeatable")
    parser.add_argument("--hosts", help="File containing RPC endpoints (one per line)")
    parser.add_argument("--pipe", type=Path, help="FIFO path generated by fr_trigger.py", required=True)
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground-truth JSONL file")
    parser.add_argument("--output", type=Path, help="Success events JSONL output")
    parser.add_argument("--poll-interval", type=float, default=2.5, help="Polling interval for receipts (seconds)")
    parser.add_argument("--reject-delay", type=float, default=20.0, help="Seconds to wait before marking victim missing")
    args = parser.parse_args()

    endpoints = load_rpc_endpoints(args)
    provider_cycle = build_provider_pool(endpoints)
    states: Dict[int, EventState] = {}

    gt_follower = GroundTruthFollower(args.ground_truth)
    apply_ground_truth(gt_follower.read_new(), states)

    output_fp = ensure_output(args.output)

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    try:
        while True:
            # Drain pipe events quickly
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                apply_pipe_event(payload, states)
            # Refresh ground truth (append-only)
            apply_ground_truth(gt_follower.read_new(), states)

            now = time.time()
            for state in list(states.values()):
                if state.ready_for_summary():
                    continue
                if state.runner_hash:
                    provider = next(provider_cycle)
                    if state.runner_receipt is None or (now - state.last_polled >= args.poll_interval):
                        if state.runner_hash:
                            receipt = fetch_receipt(provider, state.runner_hash)
                            if receipt:
                                state.runner_receipt = receipt
                        if state.victim_hash:
                            receipt = fetch_receipt(provider, state.victim_hash)
                            if receipt:
                                state.victim_receipt = receipt
                        state.last_polled = now
                    classify_event(state, args.reject_delay)
                    if state.ready_for_summary():
                        write_event(output_fp, state)

            total, success, reasons = summary_snapshot(states)
            if total:
                rate = success / total if total else 0.0
                print(
                    f"[STATUS] processed={total} success={success} rate={rate:.3f} reasons={reasons}"
                )
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        if output_fp:
            output_fp.close()
        total, success, reasons = summary_snapshot(states)
        if total:
            rate = success / total if total else 0.0
            print(f"[SUMMARY] processed={total} success={success} rate={rate:.3f}")
            for reason, count in reasons.items():
                print(f"  - {reason}: {count}")
        else:
            print("[SUMMARY] no completed events")


if __name__ == "__main__":
    main()
