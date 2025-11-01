#!/usr/bin/env python3
"""Monitor tagged malicious transactions to derive visibility metrics."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxData


@dataclass
class TxRecord:
    tx_hash: str
    sender: str
    nonce: int
    first_seen: float
    last_seen: float
    status: str = "observed"
    reason: Optional[str] = None
    flag_time: Optional[float] = None
    receipt_status: Optional[int] = None
    sources: Set[str] = field(default_factory=set)
    last_write_version: int = 0
    version: int = 0

    def touch(self, timestamp: float, source: str) -> None:
        self.last_seen = timestamp
        self.sources.add(source)

    def mark_status(self, status: str, timestamp: float, reason: Optional[str] = None) -> None:
        if self.status == status and (reason is None or reason == self.reason):
            return
        self.status = status
        if reason is not None:
            self.reason = reason
        if status in {"rejected", "mined", "mined_failed"}:
            self.flag_time = timestamp
        self.version += 1

    def set_receipt(self, status: int, timestamp: float) -> None:
        if self.receipt_status == status:
            return
        self.receipt_status = status
        if status == 1:
            self.mark_status("mined", timestamp, self.reason)
        else:
            self.mark_status("mined_failed", timestamp, self.reason)

    def bump(self) -> None:
        self.version += 1

    def to_payload(self, timestamp: float) -> dict:
        return {
            "timestamp": timestamp,
            "tx_hash": self.tx_hash,
            "from": self.sender,
            "nonce": self.nonce,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
            "flag_time": self.flag_time,
            "receipt_status": self.receipt_status,
            "reason": self.reason,
            "sources": sorted(self.sources),
        }


class Provider:
    def __init__(self, label: str, w3: Web3) -> None:
        self.label = label
        self.w3 = w3

    def iter_txpool_transactions(self) -> Iterable[TxData]:
        raw = self.w3.geth.txpool.content()
        for section in ("pending", "queued"):
            bucket = raw.get(section, {})
            for _, nonce_map in bucket.items():
                for _, entries in nonce_map.items():
                    for entry in entries:
                        yield entry

    def get_inspect_reason(self, sender: str, nonce: int) -> Optional[str]:
        try:
            inspect = self.w3.geth.txpool.inspect()
        except Exception:  # noqa: BLE001
            return None
        bucket = inspect.get("queued", {}).get(sender.lower(), {})
        if not bucket:
            bucket = inspect.get("pending", {}).get(sender.lower(), {})
        if not bucket:
            return None
        key = hex(nonce)
        reason = bucket.get(key)
        if isinstance(reason, str):
            return reason
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect visibility of tagged malicious transactions")
    parser.add_argument("--marker", default="0xdeaddead", help="Hex prefix used to tag malicious transactions")
    parser.add_argument("--poll", type=float, default=2.0, help="Polling interval in seconds (default: 2.0)")
    parser.add_argument(
        "--reject-window",
        type=float,
        default=10.0,
        help="Seconds after last observation to treat a transaction as rejected (default: 10)",
    )
    parser.add_argument("--output", help="Optional JSONL path to record observations")
    parser.add_argument("--ipc", action="append", help="IPC endpoints to monitor (can be repeated)")
    parser.add_argument("--rpc", action="append", help="RPC endpoints to monitor (can be repeated)")
    parser.add_argument(
        "--summary-interval",
        type=int,
        default=30,
        help="Seconds between console summary outputs (default: 30)",
    )
    return parser.parse_args()


def connect_providers(args: argparse.Namespace) -> List[Provider]:
    endpoints: List[Provider] = []
    ipc_list = args.ipc or []
    rpc_list = args.rpc or []
    if not ipc_list and not rpc_list:
        raise SystemExit("At least one --ipc or --rpc endpoint is required")
    for path in ipc_list:
        w3 = Web3(Web3.IPCProvider(path, timeout=30))
        if not w3.is_connected():
            raise SystemExit(f"Failed to connect to IPC {path}")
        endpoints.append(Provider(label=f"ipc:{path}", w3=w3))
    for url in rpc_list:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise SystemExit(f"Failed to connect to RPC {url}")
        endpoints.append(Provider(label=f"rpc:{url}", w3=w3))
    return endpoints


def normalize_marker(marker: str) -> str:
    marker = marker.lower()
    if not marker.startswith("0x"):
        marker = "0x" + marker
    try:
        bytes.fromhex(marker[2:])
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"Marker must be valid hex: {exc}") from exc
    return marker


def marker_matches(marker: str, data: str) -> bool:
    try:
        return data.lower().startswith(marker)
    except AttributeError:
        return False


def ensure_output(path: Optional[str]):
    if not path:
        return None
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    return file_path.open("a", encoding="utf-8")


def log_summary(records: Dict[str, TxRecord]) -> None:
    total = len(records)
    rejected = sum(1 for rec in records.values() if rec.status == "rejected")
    mined = sum(1 for rec in records.values() if rec.status == "mined")
    failed = sum(1 for rec in records.values() if rec.status == "mined_failed")
    print(
        f"[VISIBILITY] total={total} rejected={rejected} mined={mined} mined_failed={failed}",
        flush=True,
    )


def main() -> None:
    args = parse_args()
    marker = normalize_marker(args.marker)
    providers = connect_providers(args)
    output_handle = ensure_output(args.output)
    records: Dict[str, TxRecord] = {}
    last_summary = time.time()

    try:
        while True:
            now = time.time()
            for provider in providers:
                try:
                    for tx in provider.iter_txpool_transactions():
                        data_field = tx.get("input") or tx.get("data") or "0x"
                        if not marker_matches(marker, data_field):
                            continue
                        tx_hash = tx.get("hash")
                        if not tx_hash:
                            continue
                        if isinstance(tx_hash, bytes):
                            tx_hash = Web3.to_hex(tx_hash)
                        sender = tx.get("from") or ""
                        sender = Web3.to_checksum_address(sender) if sender else sender
                        nonce = int(tx.get("nonce", 0))
                        record = records.get(tx_hash)
                        if record is None:
                            record = TxRecord(
                                tx_hash=tx_hash,
                                sender=sender,
                                nonce=nonce,
                                first_seen=now,
                                last_seen=now,
                            )
                            records[tx_hash] = record
                            record.version += 1
                        record.touch(now, provider.label)
                        record.mark_status("pool", now)
                        reason = provider.get_inspect_reason(sender, nonce)
                        if reason and reason != record.reason:
                            record.reason = reason
                            record.bump()
                except Exception as exc:  # noqa: BLE001
                    print(f"[VISIBILITY] Warning: failed to query {provider.label}: {exc}", file=sys.stderr)

            for record in records.values():
                if record.status in {"mined", "mined_failed", "rejected"}:
                    continue
                primary = providers[0]
                try:
                    receipt = primary.w3.eth.get_transaction_receipt(record.tx_hash)
                except TransactionNotFound:
                    receipt = None
                except Exception as exc:  # noqa: BLE001
                    print(f"[VISIBILITY] Warning: receipt lookup failed: {exc}", file=sys.stderr)
                    receipt = None
                if receipt is not None:
                    status = receipt.get("status")
                    record.set_receipt(status, now)
                    record.bump()
                    continue
                if now - record.last_seen >= args.reject_window:
                    reason = record.reason or "timeout"
                    record.mark_status("rejected", now, reason)

            for record in records.values():
                if record.version > record.last_write_version and output_handle:
                    payload = record.to_payload(time.time())
                    json.dump(payload, output_handle, ensure_ascii=False)
                    output_handle.write("\n")
                    output_handle.flush()
                    record.last_write_version = record.version

            if time.time() - last_summary >= args.summary_interval:
                log_summary(records)
                last_summary = time.time()

            time.sleep(max(args.poll, 0.5))
    except KeyboardInterrupt:
        log_summary(records)
    finally:
        if output_handle:
            output_handle.close()


if __name__ == "__main__":
    main()
