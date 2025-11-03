#!/usr/bin/env python3
"""Compute average gas premium for front-running events."""

from __future__ import annotations

import argparse
import json
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from eth_utils import to_int as eth_to_int
from web3 import Web3
from web3.exceptions import TransactionNotFound

PIPE_SCHEMA = "fr-trigger-tx-v1"
GROUND_TRUTH_SCHEMA = "fr-trigger-event-v1"


@dataclass
class ReceiptInfo:
    effective_gas_price: Optional[int]


@dataclass
class EventState:
    pair_id: int
    event_id: Optional[str] = None
    target_address: Optional[str] = None
    victim_hash: Optional[str] = None
    runner_hash: Optional[str] = None
    victim_tx: Optional[Dict[str, object]] = None
    runner_tx: Optional[Dict[str, object]] = None
    victim_receipt: Optional[ReceiptInfo] = None
    runner_receipt: Optional[ReceiptInfo] = None
    recorded: bool = False
    last_polled: float = field(default_factory=lambda: 0.0)


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
        raise SystemExit("at least one RPC endpoint must be provided")
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
        state.event_id = payload.get("event_id", state.event_id)
        state.victim_hash = payload.get("victim_hash", state.victim_hash)
        state.runner_hash = payload.get("runner_hash", state.runner_hash)
        state.target_address = payload.get("target_address", state.target_address)


def apply_pipe(payload: Dict[str, object], states: Dict[int, EventState]) -> None:
    try:
        pair_id = int(payload.get("pair_id", 0))
    except (ValueError, TypeError):
        return
    if pair_id <= 0:
        return
    state = states.setdefault(pair_id, EventState(pair_id=pair_id))
    role = payload.get("role")
    if role == "victim":
        state.victim_hash = payload.get("tx_hash", state.victim_hash)
    elif role == "runner":
        state.runner_hash = payload.get("tx_hash", state.runner_hash)
    state.target_address = payload.get("to", state.target_address)


def ensure_output(path: Optional[Path]):
    if not path:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.open("a", encoding="utf-8")


def fetch_transaction(provider: Web3, tx_hash: str) -> Optional[Dict[str, object]]:
    try:
        tx = provider.eth.get_transaction(tx_hash)
    except TransactionNotFound:
        return None
    except ValueError:
        return None
    return dict(tx)


def fetch_receipt(provider: Web3, tx_hash: str) -> Optional[ReceiptInfo]:
    try:
        receipt = provider.eth.get_transaction_receipt(tx_hash)
    except TransactionNotFound:
        return None
    except ValueError:
        return None
    effective = receipt.get("effectiveGasPrice")
    try:
        effective_int = eth_to_int(effective) if effective is not None else None
    except (TypeError, ValueError):
        effective_int = None
    return ReceiptInfo(effective_gas_price=effective_int)


def as_int(value: Optional[object]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return eth_to_int(value)
    except (TypeError, ValueError):
        return None


def compute_premium(state: EventState) -> Optional[Dict[str, object]]:
    if not state.runner_receipt or not state.victim_receipt:
        return None
    runner_eff = state.runner_receipt.effective_gas_price
    victim_eff = state.victim_receipt.effective_gas_price
    runner_tx = state.runner_tx or {}
    victim_tx = state.victim_tx or {}
    runner_prio = as_int(runner_tx.get("maxPriorityFeePerGas"))
    victim_prio = as_int(victim_tx.get("maxPriorityFeePerGas"))
    runner_max = as_int(runner_tx.get("maxFeePerGas"))
    victim_max = as_int(victim_tx.get("maxFeePerGas"))
    if runner_eff is None:
        runner_eff = as_int(runner_tx.get("gasPrice"))
    if victim_eff is None:
        victim_eff = as_int(victim_tx.get("gasPrice"))
    if runner_eff is None or victim_eff is None:
        return None
    premium = runner_eff - victim_eff
    payload = {
        "runner_effective": runner_eff,
        "victim_effective": victim_eff,
        "premium": premium,
        "runner_priority": runner_prio,
        "victim_priority": victim_prio,
        "priority_delta": (runner_prio - victim_prio) if runner_prio is not None and victim_prio is not None else None,
        "runner_max_fee": runner_max,
        "victim_max_fee": victim_max,
        "max_fee_delta": (runner_max - victim_max) if runner_max is not None and victim_max is not None else None,
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor average gas premium")
    parser.add_argument("--rpc", action="append", default=[], help="HTTP RPC endpoint; repeatable")
    parser.add_argument("--hosts", help="File containing HTTP RPC endpoints")
    parser.add_argument("--pipe", type=Path, required=True, help="FIFO path published by trigger")
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground-truth JSONL file")
    parser.add_argument("--output", type=Path, help="Per-event JSONL output")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between RPC polls")
    parser.add_argument("--status-interval", type=float, default=10.0, help="Seconds between status logs")
    args = parser.parse_args()

    endpoints = load_rpc_endpoints(args)
    provider_cycle = build_provider_pool(endpoints)

    states: Dict[int, EventState] = {}
    gt_follower = GroundTruthFollower(args.ground_truth)
    output_fp = ensure_output(args.output)

    totals = {"count": 0, "premium_sum": 0}

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    last_status = 0.0

    try:
        apply_ground_truth(gt_follower.read_new(), states)
        while True:
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                apply_pipe(payload, states)
            apply_ground_truth(gt_follower.read_new(), states)

            now = time.time()
            for state in list(states.values()):
                if state.recorded:
                    continue
                if not state.runner_hash or not state.victim_hash:
                    continue
                if now - state.last_polled < args.poll_interval:
                    continue
                provider = next(provider_cycle)
                if state.runner_tx is None:
                    tx = fetch_transaction(provider, state.runner_hash)
                    if tx:
                        state.runner_tx = tx
                if state.victim_tx is None:
                    tx = fetch_transaction(provider, state.victim_hash)
                    if tx:
                        state.victim_tx = tx
                if state.runner_receipt is None:
                    receipt = fetch_receipt(provider, state.runner_hash)
                    if receipt:
                        state.runner_receipt = receipt
                if state.victim_receipt is None:
                    receipt = fetch_receipt(provider, state.victim_hash)
                    if receipt:
                        state.victim_receipt = receipt
                state.last_polled = now
                metrics = compute_premium(state)
                if metrics is None:
                    continue
                state.recorded = True
                totals["count"] += 1
                totals["premium_sum"] += metrics["premium"]
                if output_fp:
                    payload = {
                        "pair_id": state.pair_id,
                        "event_id": state.event_id,
                        "target_address": state.target_address,
                        "metrics": metrics,
                        "timestamp": time.time(),
                    }
                    output_fp.write(json.dumps(payload, ensure_ascii=True) + "\n")
                    output_fp.flush()

            if now - last_status >= args.status_interval:
                last_status = now
                count = totals["count"]
                avg_premium = (totals["premium_sum"] / count) if count else 0.0
                print(
                    "[STATUS] samples={} avg_premium_wei={} avg_premium_gwei={:.6f}".format(
                        count, avg_premium, avg_premium / 1e9 if count else 0.0
                    )
                )
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        if output_fp:
            output_fp.close()
        count = totals["count"]
        avg_premium = (totals["premium_sum"] / count) if count else 0.0
        print(
            "[SUMMARY] samples={} avg_premium_wei={} avg_premium_gwei={:.6f}".format(
                count, avg_premium, avg_premium / 1e9 if count else 0.0
            )
        )


if __name__ == "__main__":
    main()
