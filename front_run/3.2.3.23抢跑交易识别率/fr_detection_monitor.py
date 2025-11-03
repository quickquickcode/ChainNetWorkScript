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
from typing import Dict, Iterable, List, Optional, Set, Tuple

from web3 import Web3

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


@dataclass
class ObservedTx:
    tx_hash: str
    from_address: Optional[str]
    to_address: Optional[str]
    nonce: int
    gas_price: int
    value: int
    input_data: str
    seen_at: float


def parse_marker(value: str) -> bytes:
    if not value.startswith("0x"):
        raise argparse.ArgumentTypeError("marker must start with 0x")
    body = value[2:]
    if len(body) % 2:
        raise argparse.ArgumentTypeError("marker hex length must be even")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:  # noqa: B904
        raise argparse.ArgumentTypeError(f"invalid marker: {exc}") from exc


def hex_to_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    if isinstance(value, str):
        if value.startswith("0x"):
            return int(value, 16)
        return int(value)
    if value is None:
        return 0
    raise TypeError(f"unsupported numeric: {value!r}")


def connect_rpc(url: str) -> Web3:
    provider = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
    if not provider.is_connected():
        raise SystemExit(f"failed to connect to RPC: {url}")
    try:
        provider.geth.txpool.content()
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"txpool namespace unavailable on {url}: {exc}") from exc
    return provider


def iter_txpool_entries(provider: Web3) -> Iterable[Dict[str, object]]:
    content = provider.geth.txpool.content()
    for section in ("pending", "queued"):
        area = content.get(section, {}) or {}
        for txs_by_nonce in area.values():
            for entry in txs_by_nonce.values():
                if isinstance(entry, list):
                    for tx in entry:
                        yield tx
                else:
                    yield entry


def decode_marker(input_data: Optional[str], marker: bytes) -> Optional[Tuple[int, int]]:
    if not input_data or not input_data.startswith("0x"):
        return None
    try:
        payload = bytes.fromhex(input_data[2:])
    except ValueError:
        return None
    if not payload.startswith(marker):
        return None
    suffix = payload[len(marker) :]
    if len(suffix) < 5:
        return None
    role = suffix[0]
    pair_id = int.from_bytes(suffix[1:5], "big")
    return role, pair_id


def is_candidate_match(victim: ObservedTx, runner: ObservedTx, window: float, ratio: float, absolute: int) -> bool:
    delay = max(0.0, runner.seen_at - victim.seen_at)
    if delay > window:
        return False
    if victim.to_address != runner.to_address:
        return False
    if victim.value != runner.value:
        return False
    if runner.gas_price <= victim.gas_price:
        return False
    premium = runner.gas_price - victim.gas_price
    victim_gp = max(victim.gas_price, 1)
    if premium < absolute and (runner.gas_price / victim_gp) < ratio:
        return False
    return True


def build_detection_payload(
    pair_id: int,
    victim: ObservedTx,
    runner: ObservedTx,
    states: Dict[int, EventRecord],
) -> Dict[str, object]:
    record = {
        "schema": DETECTION_SCHEMA,
        "pair_id": pair_id,
        "victim_hash": victim.tx_hash,
        "runner_hash": runner.tx_hash,
        "victim_gas_price": victim.gas_price,
        "runner_gas_price": runner.gas_price,
        "detected_delay": max(0.0, runner.seen_at - victim.seen_at),
        "timestamp": time.time(),
    }
    state = states.get(pair_id)
    if state and state.event_id:
        record["event_id"] = state.event_id
    if state and state.target_address:
        record["target_address"] = state.target_address
    return record


def cleanup_candidates(
    candidates: Dict[int, ObservedTx],
    now: float,
    ttl: float,
    detected_pairs: Set[int],
) -> None:
    for pair_id, obs in list(candidates.items()):
        if pair_id in detected_pairs or now - obs.seen_at > ttl:
            candidates.pop(pair_id, None)


def cleanup_seen_hashes(seen: Dict[str, float], now: float, ttl: float) -> None:
    for tx_hash, ts in list(seen.items()):
        if now - ts > ttl:
            seen.pop(tx_hash, None)


def run_detection(
    provider: Web3,
    marker: bytes,
    seen_hashes: Dict[str, float],
    victims: Dict[int, ObservedTx],
    runners: Dict[int, ObservedTx],
    detected_pairs: Set[int],
    states: Dict[int, EventRecord],
    pending: List[DetectionEntry],
    allow_partial: bool,
    detection_fp,
    window: float,
    ratio: float,
    absolute: int,
) -> None:
    try:
        entries = list(iter_txpool_entries(provider))
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] failed to read txpool: {exc}")
        return
    for tx in entries:
        tx_hash = tx.get("hash")
        if not tx_hash:
            continue
        tx_hash = str(tx_hash).lower()
        if tx_hash in seen_hashes:
            continue
        seen_time = time.time()
        seen_hashes[tx_hash] = seen_time
        role_pair = decode_marker(tx.get("input") or tx.get("data"), marker)
        if not role_pair:
            continue
        role, pair_id = role_pair
        if pair_id <= 0 or role not in (1, 2):
            continue
        observed = ObservedTx(
            tx_hash=tx_hash,
            from_address=tx.get("from"),
            to_address=tx.get("to"),
            nonce=hex_to_int(tx.get("nonce")),
            gas_price=hex_to_int(tx.get("gasPrice")),
            value=hex_to_int(tx.get("value")),
            input_data=str(tx.get("input") or tx.get("data") or ""),
            seen_at=seen_time,
        )
        if role == 1:
            victims[pair_id] = observed
        else:
            runners[pair_id] = observed

        if pair_id in detected_pairs:
            continue
        victim = victims.get(pair_id)
        runner = runners.get(pair_id)
        if not victim or not runner:
            continue
        if not is_candidate_match(victim, runner, window, ratio, absolute):
            continue
        detection_payload = build_detection_payload(pair_id, victim, runner, states)
        apply_detection([detection_payload], pending, states, allow_partial)
        detected_pairs.add(pair_id)
        if detection_fp:
            detection_fp.write(json.dumps(detection_payload, ensure_ascii=True) + "\n")
            detection_fp.flush()
        # print(
        #     f"[DETECT] pair={pair_id} victim={victim.tx_hash} runner={runner.tx_hash} "
        #     f"delay={detection_payload['detected_delay']:.3f}s"
        # )
        victims.pop(pair_id, None)
        runners.pop(pair_id, None)


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
    parser.add_argument("--rpc", required=True, help="HTTP RPC endpoint for txpool polling")
    parser.add_argument("--marker", default="0xfeedface", help="Marker prefix used by trigger payloads")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between txpool polls")
    parser.add_argument("--detection-window", type=float, default=10.0, help="Max seconds between victim and runner")
    parser.add_argument("--premium-ratio", type=float, default=1.1, help="Minimum runner/victim gas-price ratio")
    parser.add_argument(
        "--premium-absolute",
        type=int,
        default=5_000_000_000,
        help="Minimum runner-victim gas-price delta in wei",
    )
    parser.add_argument(
        "--candidate-ttl",
        type=float,
        default=30.0,
        help="Seconds to retain unmatched candidate transactions",
    )
    parser.add_argument(
        "--hash-ttl",
        type=float,
        default=300.0,
        help="Seconds to retain seen tx hashes for deduplication",
    )
    parser.add_argument("--allow-partial", action="store_true", help="Allow victim-only matches when unique")
    parser.add_argument("--status-interval", type=float, default=10.0, help="Seconds between status prints")
    parser.add_argument("--output", type=Path, help="JSONL file for unmatched events")
    parser.add_argument("--detection-output", type=Path, help="JSONL file for detected events")
    args = parser.parse_args()

    states: Dict[int, EventRecord] = {}
    gt_follower = JsonlFollower(args.ground_truth)
    pending: List[DetectionEntry] = []

    try:
        marker_bytes = parse_marker(args.marker)
    except argparse.ArgumentTypeError as exc:
        raise SystemExit(str(exc)) from exc

    provider = connect_rpc(args.rpc)

    victim_candidates: Dict[int, ObservedTx] = {}
    runner_candidates: Dict[int, ObservedTx] = {}
    detected_pairs: Set[int] = set()
    seen_hashes: Dict[str, float] = {}

    output_fp = ensure_output(args.output)
    detection_fp = ensure_output(args.detection_output)

    stop_flag = threading.Event()
    pipe_queue: "queue.Queue[Dict[str, object]]" = queue.Queue()
    listener = threading.Thread(target=pipe_listener, args=(args.pipe, pipe_queue, stop_flag), daemon=True)
    listener.start()

    last_status = 0.0

    try:
        apply_ground_truth(gt_follower.read_new(), states)
        retry_pending(pending, states, args.allow_partial)
        while True:
            while True:
                try:
                    payload = pipe_queue.get_nowait()
                except queue.Empty:
                    break
                apply_pipe(payload, states)
            apply_ground_truth(gt_follower.read_new(), states)
            run_detection(
                provider,
                marker_bytes,
                seen_hashes,
                victim_candidates,
                runner_candidates,
                detected_pairs,
                states,
                pending,
                args.allow_partial,
                detection_fp,
                args.detection_window,
                args.premium_ratio,
                args.premium_absolute,
            )
            retry_pending(pending, states, args.allow_partial)

            now = time.time()
            cleanup_candidates(victim_candidates, now, args.candidate_ttl, detected_pairs)
            cleanup_candidates(runner_candidates, now, args.candidate_ttl, detected_pairs)
            cleanup_seen_hashes(seen_hashes, now, args.hash_ttl)

            if now - last_status >= args.status_interval:
                last_status = now
                truth_states = [state for state in states.values() if state.event_id]
                total = len(truth_states)
                detected = sum(1 for state in truth_states if state.detected)
                coverage = detected / total if total else 0.0
                print(
                    f"[STATUS] total={total} detected={detected} coverage={coverage:.3f} "
                    f"pending={len(pending)} victims={len(victim_candidates)} runners={len(runner_candidates)}"
                )
            time.sleep(max(args.poll_interval, 0.1))
    except KeyboardInterrupt:
        pass
    finally:
        stop_flag.set()
        listener.join(timeout=1.0)
        truth_states = [state for state in states.values() if state.event_id]
        total = len(truth_states)
        detected = sum(1 for state in truth_states if state.detected)
        missed = [state for state in truth_states if not state.detected]
        missed_count = len(missed)
        extra_count = len(pending)
        coverage = detected / total if total else 0.0
        print(
            f"[SUMMARY] total={total} detected={detected} missed={missed_count} "
            f"coverage={coverage:.3f}"
        )

        if extra_count:
            print(f"[SUMMARY] unmatched_detection_entries={extra_count}")

        if output_fp:
            if missed:
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
                print(f"[SUMMARY] missed events written to {args.output}")
            output_fp.close()

        if detection_fp:
            detection_fp.close()

        if pending:
            print(f"[WARN] {extra_count} detection entries unmatched; treat as false positives")
            for entry in pending[:10]:
                print(f"  - raw={entry.raw}")


if __name__ == "__main__":
    main()
