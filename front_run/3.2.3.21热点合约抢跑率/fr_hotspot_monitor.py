#!/usr/bin/env python3
"""Detect hot-contract front-running concentration via RPC and trigger truth."""

from __future__ import annotations

import argparse
import json
import queue
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple

from eth_utils import to_int as eth_to_int
from web3 import Web3

PIPE_SCHEMA_TRUTH = "fr-hotspot-tx-v1"
PIPE_SCHEMA_META = "fr-hotspot-metadata-v1"
PIPE_SCHEMA_GT = "fr-hotspot-event-v1"


@dataclass
class TxObservation:
    tx_hash: str
    sender: Optional[str]
    to: Optional[str]
    nonce: Optional[int]
    gas_price: Optional[int]
    max_fee: Optional[int]
    priority_fee: Optional[int]
    input_selector: Optional[str]
    seen_at: float


@dataclass
class DetectionRecord:
    victim: TxObservation
    runner: TxObservation
    delay: float
    premium: Optional[int]
    confirmed: bool
    block_number: Optional[int]


@dataclass
class TruthEvent:
    pair_id: int
    event_id: Optional[str] = None
    victim_hash: Optional[str] = None
    runner_hash: Optional[str] = None
    target_address: Optional[str] = None
    first_seen: Optional[float] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect hot-contract concentration")
    parser.add_argument("--rpc", action="append", required=True, help="HTTP RPC endpoint; repeatable")
    parser.add_argument("--pipe", type=Path, required=True, help="Trigger FIFO for ground truth")
    parser.add_argument("--ground-truth", type=Path, required=True, help="Ground truth JSONL output by trigger")
    parser.add_argument("--output", type=Path, help="Detection JSONL output")
    parser.add_argument("--hot-threshold", type=float, default=0.2, help="Hot contract share threshold (0-1)")
    parser.add_argument("--window", type=float, default=300.0, help="Sliding window seconds for shares")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between txpool polls")
    parser.add_argument("--block-interval", type=float, default=2.0, help="Seconds between block checks")
    parser.add_argument("--max-events", type=int, default=5000, help="Rolling buffer size for detection events")
    parser.add_argument("--premium-ratio", type=float, default=1.1, help="Runner/Victim gas price ratio threshold")
    parser.add_argument("--premium-absolute", type=int, default=5_000_000_000, help="Runner minus victim gas price threshold")
    parser.add_argument("--match-window", type=float, default=10.0, help="Seconds allowed between victim and runner in truth")
    parser.add_argument("--status-interval", type=float, default=10.0, help="Seconds between status prints")
    parser.add_argument("--allow-missing-marker", action="store_true", help="Fallback match without calldata marker")
    return parser.parse_args()


class JsonFollower:
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


def connect_rpc(url: str) -> Web3:
    provider = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not provider.is_connected():
        raise SystemExit(f"failed to connect RPC: {url}")
    try:
        provider.geth.txpool.content()
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"txpool namespace unavailable on {url}: {exc}") from exc
    return provider


def poll_txpool(provider: Web3) -> List[Dict[str, object]]:
    content = provider.geth.txpool.content()
    results: List[Dict[str, object]] = []
    for section in ("pending", "queued"):
        bucket = content.get(section, {}) or {}
        for txs_by_nonce in bucket.values():
            if isinstance(txs_by_nonce, dict):
                iterable = txs_by_nonce.values()
            else:
                iterable = txs_by_nonce
            for entry in iterable:
                if isinstance(entry, list):
                    results.extend(entry)
                else:
                    results.append(entry)
    return results


def normalize_hex(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return Web3.to_checksum_address(value)
    except Exception:  # noqa: BLE001
        return value


def to_int(value: Optional[object]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return eth_to_int(value)
    except (TypeError, ValueError):
        return None


def selector_from_input(input_data: Optional[str]) -> Optional[str]:
    if not input_data or not input_data.startswith("0x"):
        return None
    return input_data[:10] if len(input_data) >= 10 else input_data


def observe_tx(raw: Dict[str, object] | str, seen_at: float) -> TxObservation:
    if isinstance(raw, str):
        hex_hash = raw.strip().lower()
        if hex_hash.startswith("0x"):
            hash_value = hex_hash
        else:
            hash_value = f"0x{hex_hash}"
        return TxObservation(
            tx_hash=hash_value,
            sender=None,
            to=None,
            nonce=None,
            gas_price=None,
            max_fee=None,
            priority_fee=None,
            input_selector=None,
            seen_at=seen_at,
        )
    return TxObservation(
        tx_hash=str(raw.get("hash", "")).lower(),
        sender=normalize_hex(raw.get("from")),
        to=normalize_hex(raw.get("to")),
        nonce=to_int(raw.get("nonce")),
        gas_price=to_int(raw.get("gasPrice")),
        max_fee=to_int(raw.get("maxFeePerGas")),
        priority_fee=to_int(raw.get("maxPriorityFeePerGas")),
        input_selector=selector_from_input(raw.get("input")),
        seen_at=seen_at,
    )


def gas_premium(victim: TxObservation, runner: TxObservation) -> Optional[int]:
    if victim.gas_price is None or runner.gas_price is None:
        return None
    return runner.gas_price - victim.gas_price


def premium_ok(victim: TxObservation, runner: TxObservation, ratio: float, absolute: int) -> bool:
    if victim.gas_price is None or runner.gas_price is None:
        return False
    if runner.gas_price <= victim.gas_price:
        return False
    delta = runner.gas_price - victim.gas_price
    if delta >= absolute:
        return True
    baseline = max(victim.gas_price, 1)
    return (runner.gas_price / baseline) >= ratio


def tx_matches(victim: TxObservation, runner: TxObservation, allow_partial: bool) -> bool:
    if victim.to and runner.to and victim.to != runner.to:
        return False
    if victim.input_selector and runner.input_selector:
        return victim.input_selector == runner.input_selector
    if allow_partial:
        return bool(victim.to and runner.to and victim.to == runner.to)
    return False


def cleanup_old(entries: Dict[str, TxObservation], cutoff: float) -> None:
    stale = [key for key, obs in entries.items() if obs.seen_at < cutoff]
    for key in stale:
        entries.pop(key, None)


def cleanup_deque(buffer: Deque[Tuple[float, object]], cutoff: float) -> None:
    while buffer and buffer[0][0] < cutoff:
        buffer.popleft()


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
                    schema = payload.get("schema")
                    if schema in {PIPE_SCHEMA_TRUTH, PIPE_SCHEMA_META, PIPE_SCHEMA_GT}:
                        sink.put(payload)
        except FileNotFoundError:
            time.sleep(1)
        except OSError:
            time.sleep(0.5)


def main() -> None:
    args = parse_args()
    args.hot_threshold = max(0.0, min(args.hot_threshold, 1.0))

    providers = [connect_rpc(url) for url in args.rpc]
    provider_cycle = iter(lambda: providers[int(time.time()) % len(providers)], None)

    truth_states: Dict[int, TruthEvent] = {}
    truth_index_by_hash: Dict[str, TruthEvent] = {}
    truth_hot_contracts: Set[str] = set()

    follower = JsonFollower(args.ground_truth)

    seen_victims: Dict[str, TxObservation] = {}
    pending_runners: Dict[str, TxObservation] = {}

    detections: Deque[Tuple[float, DetectionRecord]] = deque(maxlen=args.max_events)
    victim_to_detection: Dict[str, DetectionRecord] = {}

    stats = {
        "truth_total": 0,
        "truth_hot": 0,
        "det_total": 0,
        "det_matched": 0,
        "tp": 0,
        "fp": 0,
        "fn": 0,
    }

    per_contract_counts: Dict[str, int] = {}
    per_contract_truth: Dict[str, int] = {}

    output_fp = None
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        output_fp = open(args.output, "a", encoding="utf-8")

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    last_status = 0.0
    last_block_poll = 0.0

    try:
        while True:
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                schema = payload.get("schema")
                if schema == PIPE_SCHEMA_META:
                    items = payload.get("hot_contracts") or []
                    truth_hot_contracts = {str(addr).lower() for addr in items if isinstance(addr, str)}
                elif schema == PIPE_SCHEMA_TRUTH:
                    try:
                        pair_id = int(payload.get("pair_id", 0))
                    except (TypeError, ValueError):
                        continue
                    if pair_id <= 0:
                        continue
                    state = truth_states.setdefault(pair_id, TruthEvent(pair_id=pair_id))
                    state.first_seen = state.first_seen or float(payload.get("timestamp", time.time()))
                    to_addr = normalize_hex(payload.get("to"))
                    if to_addr:
                        state.target_address = to_addr
                    role = payload.get("role")
                    tx_hash = str(payload.get("tx_hash", "")).lower()
                    if role == "victim" and tx_hash:
                        state.victim_hash = tx_hash
                        truth_index_by_hash[tx_hash] = state
                    elif role == "runner" and tx_hash:
                        state.runner_hash = tx_hash
                        truth_index_by_hash[tx_hash] = state
                elif schema == PIPE_SCHEMA_GT:
                    try:
                        pair_id = int(payload.get("pair_id", 0))
                    except (TypeError, ValueError):
                        continue
                    if pair_id <= 0:
                        continue
                    state = truth_states.setdefault(pair_id, TruthEvent(pair_id=pair_id))
                    state.event_id = payload.get("event_id", state.event_id)
                    for key in ("victim_hash", "runner_hash"):
                        value = payload.get(key)
                        if value:
                            state.__setattr__(key, str(value).lower())
                            truth_index_by_hash[str(value).lower()] = state
                    to_addr = normalize_hex(payload.get("target_address"))
                    if to_addr:
                        state.target_address = to_addr

            for payload in follower.read_new():
                if payload.get("schema") != PIPE_SCHEMA_GT:
                    continue
                try:
                    pair_id = int(payload.get("pair_id", 0))
                except (TypeError, ValueError):
                    continue
                if pair_id <= 0:
                    continue
                state = truth_states.setdefault(pair_id, TruthEvent(pair_id=pair_id))
                state.event_id = payload.get("event_id", state.event_id)
                for key in ("victim_hash", "runner_hash"):
                    value = payload.get(key)
                    if value:
                        state.__setattr__(key, str(value).lower())
                        truth_index_by_hash[str(value).lower()] = state
                to_addr = normalize_hex(payload.get("target_address"))
                if to_addr:
                    state.target_address = to_addr

            provider = providers[int(time.time()) % len(providers)]
            now = time.time()
            tx_entries = poll_txpool(provider)
            for raw_tx in tx_entries:
                obs = observe_tx(raw_tx, now)
                if not obs.tx_hash:
                    continue
                if obs.tx_hash in victim_to_detection:
                    continue
                state = truth_index_by_hash.get(obs.tx_hash)
                if state and state.victim_hash == obs.tx_hash:
                    seen_victims[obs.tx_hash] = obs
                    cleanup_old(seen_victims, now - args.window)
                    continue
                if state and state.runner_hash == obs.tx_hash:
                    victim = None
                    if state.victim_hash and state.victim_hash in seen_victims:
                        victim = seen_victims[state.victim_hash]
                    elif state.victim_hash:
                        victim = TxObservation(
                            tx_hash=state.victim_hash,
                            sender=None,
                            to=state.target_address,
                            nonce=None,
                            gas_price=None,
                            max_fee=None,
                            priority_fee=None,
                            input_selector=None,
                            seen_at=state.first_seen or now,
                        )
                    if victim:
                        if obs.to is None:
                            try:
                                tx_detail = provider.eth.get_transaction(obs.tx_hash)
                            except Exception:  # noqa: BLE001
                                tx_detail = None
                            if isinstance(tx_detail, dict):
                                obs.to = normalize_hex(tx_detail.get("to"))
                                obs.gas_price = obs.gas_price or to_int(tx_detail.get("gasPrice"))
                                obs.max_fee = obs.max_fee or to_int(tx_detail.get("maxFeePerGas"))
                                obs.priority_fee = obs.priority_fee or to_int(tx_detail.get("maxPriorityFeePerGas"))
                        if victim.to is None and state.target_address:
                            victim.to = state.target_address
                        target_addr = state.target_address or victim.to or obs.to
                        if not target_addr:
                            continue
                        premium_pass = premium_ok(victim, obs, args.premium_ratio, args.premium_absolute)
                        same_target = bool(victim.to and obs.to and victim.to.lower() == obs.to.lower())
                        truth_target_match = bool(state.target_address and (
                            (victim.to and victim.to.lower() == state.target_address.lower())
                            or (obs.to and obs.to.lower() == state.target_address.lower())
                        ))
                        if not (premium_pass or same_target or truth_target_match):
                            continue
                        delay = max(0.0, obs.seen_at - victim.seen_at)
                        prem = gas_premium(victim, obs)
                        record = DetectionRecord(
                            victim=victim,
                            runner=obs,
                            delay=delay,
                            premium=prem,
                            confirmed=False,
                            block_number=None,
                        )
                        detections.append((now, record))
                        victim_to_detection[victim.tx_hash] = record
                        stats["det_total"] += 1
                        target = target_addr.lower()
                        per_contract_counts[target] = per_contract_counts.get(target, 0) + 1
                        if output_fp:
                            payload = {
                                "schema": "fr-hotspot-detector-v1",
                                "victim_hash": victim.tx_hash,
                                "runner_hash": obs.tx_hash,
                                "target_address": target_addr,
                                "delay": delay,
                                "premium": prem,
                                "timestamp": now,
                            }
                            output_fp.write(json.dumps(payload, ensure_ascii=True) + "\n")
                            output_fp.flush()
                    continue

                seen_victims.setdefault(obs.tx_hash, obs)
                pending_runners[obs.tx_hash] = obs

            cutoff = now - args.window
            cleanup_old(seen_victims, cutoff)
            cleanup_old(pending_runners, cutoff)
            cleanup_deque(detections, cutoff)

            if now - last_block_poll >= args.block_interval:
                last_block_poll = now
                try:
                    block = provider.eth.get_block("latest", full_transactions=False)
                except Exception:  # noqa: BLE001
                    block = None
                if block:
                    number = block.get("number")
                    hashes = {tx.hex().lower() if hasattr(tx, "hex") else str(tx).lower() for tx in block.get("transactions", [])}
                    for _, record in list(detections):
                        if record.confirmed:
                            continue
                        if record.runner.tx_hash in hashes:
                            record.confirmed = True
                            record.block_number = number

            truth_packet = [state for state in truth_states.values() if state.victim_hash]
            stats["truth_total"] = len(truth_packet)
            stats["truth_hot"] = sum(1 for state in truth_packet if state.target_address and per_contract_truth.setdefault(state.target_address.lower(), 0) >= 0)
            for state in truth_packet:
                if state.target_address:
                    key = state.target_address.lower()
                    per_contract_truth[key] = per_contract_truth.get(key, 0) + 1
                    if key in truth_hot_contracts:
                        pass
            matched_truth: Set[int] = set()
            for _, record in detections:
                victim_hash = record.victim.tx_hash
                state = truth_index_by_hash.get(victim_hash)
                if state and state.pair_id not in matched_truth:
                    matched_truth.add(state.pair_id)
                    stats["det_matched"] += 1
                    target = (state.target_address or record.victim.to or "0x").lower()
                    truth_share = per_contract_truth.get(target, 0)
                    det_share = per_contract_counts.get(target, 0)
                    if truth_share and det_share:
                        stats["tp"] += 1
                    elif det_share and not truth_share:
                        stats["fp"] += 1
                    elif truth_share and not det_share:
                        stats["fn"] += 1

            total_det = sum(per_contract_counts.values())
            hot_contracts = []
            if total_det:
                for address, count in per_contract_counts.items():
                    share = count / total_det
                    if share >= args.hot_threshold:
                        hot_contracts.append((address, share, count))

            if now - last_status >= args.status_interval:
                last_status = now
                precision = stats["tp"] / stats["det_total"] if stats["det_total"] else 0.0
                recall = stats["tp"] / stats["truth_total"] if stats["truth_total"] else 0.0
                hotspot_overview = [f"{addr}:{share:.2%}" for addr, share, _ in sorted(hot_contracts, key=lambda x: x[1], reverse=True)[:5]]
                print(
                    f"[STATUS] truth_events={stats['truth_total']} det_events={stats['det_total']} "
                    f"precision={precision:.3f} recall={recall:.3f} hotspots={hotspot_overview}"
                )

            time.sleep(max(args.poll_interval, 0.1))
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        if output_fp:
            output_fp.close()
        total_det = sum(per_contract_counts.values())
        hotspot_summary = []
        if total_det:
            for address, count in sorted(per_contract_counts.items(), key=lambda kv: kv[1], reverse=True):
                share = count / total_det
                hotspot_summary.append((address, share, count))
        precision = stats["tp"] / stats["det_total"] if stats["det_total"] else 0.0
        recall = stats["tp"] / stats["truth_total"] if stats["truth_total"] else 0.0
        print(
            f"[SUMMARY] truth_events={stats['truth_total']} det_events={stats['det_total']} "
            f"precision={precision:.3f} recall={recall:.3f} hotspots={len([h for h in hotspot_summary if h[1] >= args.hot_threshold])}"
        )
        for addr, share, count in hotspot_summary[:10]:
            print(f"  - {addr}: share={share:.2%} count={count}")


if __name__ == "__main__":
    main()
