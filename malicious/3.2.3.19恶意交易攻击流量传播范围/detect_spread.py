#!/usr/bin/env python3
"""Measure malicious transaction retention across RPC nodes using a two-snapshot check."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from web3 import Web3


def parse_args() -> argparse.Namespace:
    default_hosts = Path(__file__).with_name("hosts.txt")
    parser = argparse.ArgumentParser(description="Detect retained malicious transactions across RPC nodes")
    parser.add_argument("--hosts", type=Path, default=default_hosts, help="Path to hosts.txt (default: same directory)")
    parser.add_argument(
        "--confirm-interval",
        type=float,
        default=10.0,
        help="Seconds to wait between the two snapshots (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="RPC request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--default-port",
        type=int,
        default=8545,
        help="Port appended to bare IP endpoints (default: 8545)",
    )
    return parser.parse_args()


def load_hosts(path: Path) -> List[str]:
    if not path.exists():
        raise SystemExit(f"hosts file not found: {path}")
    hosts: List[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        hosts.append(line)
    if not hosts:
        raise SystemExit("hosts file is empty after filtering comments")
    return hosts


def normalize_endpoint(entry: str, default_port: int) -> str:
    if "://" in entry:
        return entry
    # Allow ip or ip:port
    if ":" in entry:
        host, port = entry.rsplit(":", 1)
        if port:
            return f"http://{host}:{port}"
    return f"http://{entry}:{default_port}"


def build_provider(url: str, timeout: float) -> Optional[Web3]:
    provider = Web3.HTTPProvider(url, request_kwargs={"timeout": timeout})
    w3 = Web3(provider)
    try:
        connected = w3.is_connected()
    except Exception:  # noqa: BLE001
        return None
    if not connected:
        return None
    return w3


def collect_pending_hashes(w3: Web3) -> Set[str]:
    try:
        content = w3.geth.txpool.content()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"txpool.content failed: {exc}") from exc
    hashes: Set[str] = set()
    for section in ("pending", "queued"):
        bucket = content.get(section, {})
        for _, nonce_map in bucket.items():
            for _, entries in nonce_map.items():
                if isinstance(entries, dict):
                    iterator = entries.items()
                elif isinstance(entries, list):
                    iterator = ((None, tx) for tx in entries)
                else:
                    continue
                for key, tx in iterator:
                    tx_hash: Optional[str]
                    if isinstance(tx, dict):
                        raw_hash = tx.get("hash")
                        if isinstance(raw_hash, (bytes, str)):
                            tx_hash = raw_hash
                        else:
                            tx_hash = key
                    else:
                        tx_hash = key or (tx if isinstance(tx, str) else None)
                    if isinstance(tx_hash, bytes):
                        tx_hash = Web3.to_hex(tx_hash)
                    if isinstance(tx_hash, str):
                        hashes.add(tx_hash.lower())
    return hashes
def summarize(retained_map: Dict[str, int]) -> None:
    if not retained_map:
        print("[SPREAD] 未能连接任何节点，无法计算指标。")
        return
    nodes = sorted(retained_map.items())
    print("[SPREAD] 节点留存详情：")
    for url, count in nodes:
        print(f"  - {url}: 留存恶意交易 {count}")
    values = [count for _, count in nodes]
    average = sum(values) / len(values)
    variance = sum((value - average) ** 2 for value in values) / len(values)
    max_value = max(values)
    max_nodes = [url for url, value in nodes if value == max_value]
    joined_max = ", ".join(max_nodes)
    print("[SPREAD] 汇总指标：")
    print(f"  - 平均恶意留存量: {average:.2f}")
    print(f"  - 恶意留存方差: {variance:.2f}")
    print(f"  - 最大恶意留存量: {max_value} (节点: {joined_max})")


def main() -> None:
    args = parse_args()
    hosts = load_hosts(args.hosts)
    retained_map: Dict[str, int] = {}
    node_states: Dict[str, Tuple[Web3, Set[str], float]] = {}
    total_hosts = len(hosts)

    for index, entry in enumerate(hosts, start=1):
        url = normalize_endpoint(entry, args.default_port)
        print(f"[SPREAD] 节点 {index}/{total_hosts}: {url}", flush=True)
        w3 = build_provider(url, args.timeout)
        if not w3:
            print(f"[SPREAD] 警告：无法连接 {url}，跳过该节点。", file=sys.stderr)
            continue
        try:
            snapshot = collect_pending_hashes(w3)
        except RuntimeError as exc:
            print(f"[SPREAD] 警告：{url} 查询失败：{exc}", file=sys.stderr)
            continue
        if not snapshot:
            retained_map[url] = 0
            print(f"[SPREAD] {url} 初次抓取交易数=0，跳过复查。", flush=True)
            continue
        node_states[url] = (w3, snapshot, time.time())
        print(f"[SPREAD] {url} 初次抓取交易数={len(snapshot)}", flush=True)

    for url, (w3, first_snapshot, first_time) in node_states.items():
        elapsed = time.time() - first_time
        wait_time = args.confirm_interval - elapsed
        if wait_time > 0:
            time.sleep(wait_time)
        try:
            second_snapshot = collect_pending_hashes(w3)
        except RuntimeError as exc:
            print(f"[SPREAD] 警告：{url} 第二次抓取失败：{exc}", file=sys.stderr)
            continue
        retained = first_snapshot.intersection(second_snapshot)
        retained_map[url] = len(retained)
        print(
            f"[SPREAD] {url} 复查交易数={len(second_snapshot)} 留存={len(retained)}",
            flush=True,
        )

    summarize(retained_map)


if __name__ == "__main__":
    main()
