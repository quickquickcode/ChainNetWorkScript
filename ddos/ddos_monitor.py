#!/usr/bin/env python3
"""Monitor txpool state to derive LTR/MTR without sender logs."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional, Set, Tuple

from web3 import Web3


@dataclass
class AddressState:
    """Track nonce progression for a single address."""

    min_nonce: Optional[int] = None
    max_nonce: Optional[int] = None
    forwarded: Dict[int, float] = field(default_factory=dict)  # nonce -> first seen timestamp
    pending: Dict[int, float] = field(default_factory=dict)  # nonce -> gap detected, awaiting timeout
    rejected: Dict[int, float] = field(default_factory=dict)  # nonce -> deemed rejected timestamp

    def totals(self) -> Tuple[int, int, int]:
        return (len(self.forwarded), len(self.pending), len(self.rejected))


@dataclass
class DenominatorState:
    """Track nonce coverage seen from denominator sources."""

    min_nonce: Optional[int] = None
    max_nonce: Optional[int] = None
    first_seen: Dict[int, float] = field(default_factory=dict)

    def update(self, observed: Set[int], timestamp: float) -> None:
        if not observed:
            return
        observed_min = min(observed)
        observed_max = max(observed)

        if self.min_nonce is None:
            self.min_nonce = observed_min
        else:
            self.min_nonce = min(self.min_nonce, observed_min)

        if self.max_nonce is None:
            self.max_nonce = observed_max
        else:
            self.max_nonce = max(self.max_nonce, observed_max)

        for nonce in observed:
            self.first_seen.setdefault(nonce, timestamp)

    def total(self) -> int:
        if self.min_nonce is None or self.max_nonce is None:
            return len(self.first_seen)
        return max(self.max_nonce - self.min_nonce + 1, len(self.first_seen))

    def window_total(self, window_threshold: float) -> int:
        return sum(1 for ts in self.first_seen.values() if ts >= window_threshold)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute LTR/MTR directly from txpool data")
    parser.add_argument("--ipc", required=True, help="Path to the local geth IPC endpoint")
    parser.add_argument("--remote-rpc", help="[Deprecated] Equivalent to --supplement-rpc")
    parser.add_argument("--legit-rpc", help="HTTP RPC URL of the legitimate traffic probe")
    parser.add_argument("--attack-rpc", help="HTTP RPC URL of the malicious traffic probe")
    parser.add_argument("--supplement-rpc", help="HTTP RPC URL of the supplemental probe for numerator coverage")
    parser.add_argument("--window", type=float, default=30.0, help="Sliding window size in seconds (default: 30)")
    parser.add_argument("--poll", type=float, default=5.0, help="Polling interval in seconds (default: 5)")
    parser.add_argument(
        "--reject-delay",
        type=float,
        default=10.0,
        help="Seconds to wait before treating a missing nonce as rejected (default: 10)",
    )
    parser.add_argument("--output", help="Optional JSONL file for metric snapshots")
    return parser.parse_args()


def connect_ipc(path: str) -> Web3:
    w3 = Web3(Web3.IPCProvider(path, timeout=30))
    if not w3.is_connected():
        raise SystemExit(f"Failed to connect to local IPC: {path}")
    return w3


def connect_remote(url: Optional[str]) -> Optional[Web3]:
    if not url:
        return None
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 10}))
    if not w3.is_connected():
        print(f"[MONITOR] Warning: remote RPC {url} not reachable", file=sys.stderr)
        return None
    return w3


def to_checksum(address: Optional[str]) -> Optional[str]:
    if not address:
        return None
    try:
        return Web3.to_checksum_address(address)
    except ValueError:
        return None


def collect_pending(provider: Web3) -> Dict[str, Set[int]]:
    """Return observed nonces per sender from txpool.content()."""

    observations: Dict[str, Set[int]] = defaultdict(set)
    try:
        content = provider.geth.txpool.content()
    except Exception as exc:  # noqa: BLE001
        print(f"[MONITOR] Failed to query txpool.content(): {exc}", file=sys.stderr)
        return observations

    pending = content.get("pending", {})
    for sender, nonce_dict in pending.items():
        checksum_sender = to_checksum(sender)
        if not checksum_sender:
            continue
        for nonce_str, entries in nonce_dict.items():
            try:
                base = 16 if nonce_str.lower().startswith("0x") else 10
                nonce = int(nonce_str, base)
            except ValueError:
                continue
            if entries:
                observations[checksum_sender].add(nonce)
    return observations


def merge_observations(partials: Iterable[Dict[str, Set[int]]]) -> Dict[str, Set[int]]:
    merged: Dict[str, Set[int]] = defaultdict(set)
    for partial in partials:
        for address, nonces in partial.items():
            merged[address].update(nonces)
    return merged


def ensure_state(states: Dict[str, AddressState], address: str) -> AddressState:
    state = states.get(address)
    if state is None:
        state = AddressState()
        states[address] = state
    return state


def ensure_denom_state(states: Dict[str, DenominatorState], address: str) -> DenominatorState:
    state = states.get(address)
    if state is None:
        state = DenominatorState()
        states[address] = state
    return state


def mark_forwarded(state: AddressState, nonce: int, timestamp: float) -> None:
    candidate_ts = state.pending.pop(nonce, None)
    rejected_ts = state.rejected.pop(nonce, None)
    current = state.forwarded.get(nonce)
    if current is None:
        state.forwarded[nonce] = candidate_ts or rejected_ts or timestamp
    else:
        if candidate_ts and candidate_ts < current:
            state.forwarded[nonce] = candidate_ts
        elif rejected_ts and rejected_ts < current:
            state.forwarded[nonce] = rejected_ts


def update_address_state(
    state: AddressState,
    observed: Set[int],
    now: float,
    reject_delay: float,
    expected_range: Optional[Tuple[int, int]] = None,
) -> None:
    if observed:
        observed_min = min(observed)
        observed_max = max(observed)
        if state.min_nonce is None:
            state.min_nonce = observed_min
        else:
            state.min_nonce = min(state.min_nonce, observed_min)
        if state.max_nonce is None or observed_max > state.max_nonce:
            state.max_nonce = observed_max

        for nonce in observed:
            mark_forwarded(state, nonce, now)

    if expected_range is not None:
        exp_min, exp_max = expected_range
        if exp_min is not None:
            if state.min_nonce is None:
                state.min_nonce = exp_min
            else:
                state.min_nonce = min(state.min_nonce, exp_min)
        if exp_max is not None:
            if state.max_nonce is None:
                state.max_nonce = exp_max
            else:
                state.max_nonce = max(state.max_nonce, exp_max)

    if state.min_nonce is None or state.max_nonce is None:
        return

    for nonce in range(state.min_nonce, state.max_nonce + 1):
        if nonce in state.forwarded or nonce in state.rejected or nonce in state.pending:
            continue
        state.pending[nonce] = now

    for nonce, ts in list(state.pending.items()):
        if nonce in state.forwarded:
            state.pending.pop(nonce, None)
            continue
        if now - ts >= reject_delay:
            state.rejected[nonce] = ts
            state.pending.pop(nonce, None)


def summarize_numerator(
    states: Dict[str, AddressState],
    attacker_accounts: Set[str],
    include_attackers: bool,
    window_threshold: float,
) -> Tuple[int, int, int, int, int, int]:
    forwarded_total = 0
    pending_total = 0
    rejected_total = 0
    forwarded_window = 0
    pending_window = 0
    rejected_window = 0

    for address, state in states.items():
        is_attacker = address in attacker_accounts
        if is_attacker != include_attackers:
            continue

        forwarded_count, pending_count, rejected_count = state.totals()
        attempts = forwarded_count + pending_count + rejected_count
        if attempts == 0:
            continue

        forwarded_total += forwarded_count
        pending_total += pending_count
        rejected_total += rejected_count

        forwarded_window += sum(1 for ts in state.forwarded.values() if ts >= window_threshold)
        pending_window += sum(1 for ts in state.pending.values() if ts >= window_threshold)
        rejected_window += sum(1 for ts in state.rejected.values() if ts >= window_threshold)

    return (
        forwarded_total,
        pending_total,
        rejected_total,
        forwarded_window,
        pending_window,
        rejected_window,
    )


def summarize_denominator(
    states: Dict[str, DenominatorState],
    attacker_accounts: Set[str],
    include_attackers: bool,
    window_threshold: float,
) -> Tuple[int, int]:
    total = 0
    window_total = 0

    for address, state in states.items():
        is_attacker = address in attacker_accounts
        if is_attacker != include_attackers:
            continue

        total += state.total()
        window_total += state.window_total(window_threshold)

    return total, window_total


def format_ratio(numerator: int, denominator: int) -> str:
    count_part = f"{numerator:04d}/{denominator:04d}"
    if denominator == 0:
        percent_part = "  N/A  "
    else:
        percent_part = f"{(numerator / denominator) * 100:7.2f}%"
    return f"{count_part} ({percent_part})"


def render_summary(
    label: str,
    legit_counts: Tuple[int, int, int],
    legit_denominator: int,
    attack_counts: Tuple[int, int, int],
    attack_denominator: int,
) -> str:
    legit_forwarded, _, _ = legit_counts
    _, _, attack_rejected = attack_counts

    legit_ratio = format_ratio(legit_forwarded, legit_denominator)
    attack_ratio = format_ratio(attack_rejected, attack_denominator)

    return f"{label} | 合法交易转发率(LTR)={legit_ratio} | 攻击交易拒绝率(MTR)={attack_ratio}"


def append_snapshot(
    output_path: Optional[Path],
    timestamp: float,
    legit_totals: Tuple[int, int, int],
    attack_totals: Tuple[int, int, int],
    legit_window: Tuple[int, int, int],
    attack_window: Tuple[int, int, int],
    legit_denominator: int,
    attack_denominator: int,
    legit_denominator_window: int,
    attack_denominator_window: int,
) -> None:
    if output_path is None:
        return
    payload = {
        "timestamp": timestamp,
        "legit_total": {
            "forwarded": legit_totals[0],
            "pending": legit_totals[1],
            "rejected": legit_totals[2],
            "denominator": legit_denominator,
        },
        "attack_total": {
            "forwarded": attack_totals[0],
            "pending": attack_totals[1],
            "rejected": attack_totals[2],
            "denominator": attack_denominator,
        },
        "legit_window": {
            "forwarded": legit_window[0],
            "pending": legit_window[1],
            "rejected": legit_window[2],
            "denominator": legit_denominator_window,
        },
        "attack_window": {
            "forwarded": attack_window[0],
            "pending": attack_window[1],
            "rejected": attack_window[2],
            "denominator": attack_denominator_window,
        },
    }
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


def main() -> None:
    args = parse_args()
    ipc_provider = connect_ipc(args.ipc)
    supplement_provider = connect_remote(args.supplement_rpc or args.remote_rpc)
    legit_provider = connect_remote(args.legit_rpc)
    attack_provider = connect_remote(args.attack_rpc)

    if not legit_provider:
        print("[MONITOR] Warning: --legit-rpc 未设置或不可达，将回退为本地统计合法分母", file=sys.stderr)
    if not attack_provider:
        print("[MONITOR] Warning: --attack-rpc 未设置或不可达，将回退为本地统计恶意分母", file=sys.stderr)

    numerator_providers = [ipc_provider]
    if supplement_provider:
        numerator_providers.append(supplement_provider)

    numerator_states: Dict[str, AddressState] = {}
    legit_denominator_states: Dict[str, DenominatorState] = {}
    attack_denominator_states: Dict[str, DenominatorState] = {}
    attacker_env = os.getenv("ATTACKER_ACCOUNTS", "")
    attacker_accounts = {
        addr for addr in (to_checksum(item) for item in attacker_env.replace(";", ",").split(",")) if addr
    }
    if not attacker_accounts:
        print("[MONITOR] ATTACKER_ACCOUNTS not set; all addresses treated as legitimate", file=sys.stderr)

    output_path = Path(args.output) if args.output else None

    try:
        while True:
            now = time.time()
            numerator_observation_sets = [collect_pending(provider) for provider in numerator_providers]
            numerator_observations = merge_observations(numerator_observation_sets)

            legit_observations = collect_pending(legit_provider) if legit_provider else {}
            attack_observations = collect_pending(attack_provider) if attack_provider else {}

            for address, nonces in legit_observations.items():
                ensure_denom_state(legit_denominator_states, address).update(nonces, now)
            for address, nonces in attack_observations.items():
                ensure_denom_state(attack_denominator_states, address).update(nonces, now)

            all_addresses = (
                set(numerator_states.keys())
                | set(numerator_observations.keys())
                | set(legit_denominator_states.keys())
                | set(attack_denominator_states.keys())
                | attacker_accounts
            )

            for address in all_addresses:
                state = ensure_state(numerator_states, address)
                observed_nonces = numerator_observations.get(address, set())

                denom_state = (
                    attack_denominator_states.get(address)
                    if address in attacker_accounts
                    else legit_denominator_states.get(address)
                )
                expected_range: Optional[Tuple[int, int]] = None
                if denom_state and denom_state.min_nonce is not None and denom_state.max_nonce is not None:
                    expected_range = (denom_state.min_nonce, denom_state.max_nonce)

                update_address_state(state, observed_nonces, now, args.reject_delay, expected_range)

            window_threshold = now - args.window
            legit_totals = summarize_numerator(
                numerator_states,
                attacker_accounts,
                include_attackers=False,
                window_threshold=window_threshold,
            )
            attack_totals = summarize_numerator(
                numerator_states,
                attacker_accounts,
                include_attackers=True,
                window_threshold=window_threshold,
            )

            legit_den_total, legit_den_window = summarize_denominator(
                legit_denominator_states,
                attacker_accounts,
                include_attackers=False,
                window_threshold=window_threshold,
            )
            attack_den_total, attack_den_window = summarize_denominator(
                attack_denominator_states,
                attacker_accounts,
                include_attackers=True,
                window_threshold=window_threshold,
            )

            if legit_den_total == 0:
                legit_den_total = sum(legit_totals[:3])
            if legit_den_window == 0:
                legit_den_window = sum(legit_totals[3:])
            if attack_den_total == 0:
                attack_den_total = sum(attack_totals[:3])
            if attack_den_window == 0:
                attack_den_window = sum(attack_totals[3:])

            timestamp = time.strftime("检测时间: %Y-%m-%d %H:%M:%S", time.localtime(now))
            print(timestamp, flush=True)
            print(
                render_summary(
                    "累计统计",
                    (legit_totals[0], legit_totals[1], legit_totals[2]),
                    legit_den_total,
                    (attack_totals[0], attack_totals[1], attack_totals[2]),
                    attack_den_total,
                ),
                flush=True,
            )
            print(
                render_summary(
                    "窗口统计",
                    (legit_totals[3], legit_totals[4], legit_totals[5]),
                    legit_den_window,
                    (attack_totals[3], attack_totals[4], attack_totals[5]),
                    attack_den_window,
                ),
                flush=True,
            )
            print(flush=True)

            append_snapshot(
                output_path,
                now,
                legit_totals[:3],
                attack_totals[:3],
                legit_totals[3:],
                attack_totals[3:],
                legit_den_total,
                attack_den_total,
                legit_den_window,
                attack_den_window,
            )

            time.sleep(max(args.poll, 0.5))
    except KeyboardInterrupt:
        print("[MONITOR] Stopped by user", file=sys.stderr)


if __name__ == "__main__":
    main()
