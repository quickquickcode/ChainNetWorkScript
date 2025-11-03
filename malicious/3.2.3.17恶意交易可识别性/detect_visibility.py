#!/usr/bin/env python3
"""基于 input 标记统计恶意交易识别指标。"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from web3 import Web3
from web3.types import TxData


class Provider:
    """封装 RPC/IPC 访问，优先使用 pending 块获取交易。"""

    def __init__(self, label: str, w3: Web3) -> None:
        self.label = label
        self.w3 = w3

    def iter_pending_transactions(self) -> Iterable[TxData]:
        yielded: Set[str] = set()
        # 1) 尝试调用 eth_pendingTransactions（部分节点支持）
        try:
            pending_list = self.w3.manager.request_blocking("eth_pendingTransactions", [])
        except Exception:  # noqa: BLE001
            pending_list = []
        for tx in pending_list or []:
            payload = dict(tx)
            tx_hash = payload.get("hash")
            if not tx_hash:
                continue
            tx_hash = str(tx_hash).lower()
            if tx_hash in yielded:
                continue
            yielded.add(tx_hash)
            yield payload

        # 2) 回退到 pending block
        try:
            block = self.w3.eth.get_block("pending", full_transactions=True)
        except Exception:  # noqa: BLE001
            block = None
        if block:
            for tx in block.get("transactions", []):
                payload = dict(tx)
                tx_hash = payload.get("hash")
                if not tx_hash:
                    continue
                tx_hash = str(tx_hash).lower()
                if tx_hash in yielded:
                    continue
                yielded.add(tx_hash)
                yield payload

    def collect_pending(self) -> List[TxData]:
        return list(self.iter_pending_transactions())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="基于 input 标记统计恶意交易识别指标")
    parser.add_argument("--marker", default="0xdeaddead", help="恶意交易 input 标记前缀")
    parser.add_argument("--poll", type=float, default=2.0, help="轮询时间间隔，单位秒")
    parser.add_argument("--output", help="可选：JSONL 输出文件，用于记录观测事件")
    parser.add_argument("--ground-truth", help="可选：ground-truth 哈希文件（纯文本或 JSONL）")
    parser.add_argument("--ipc", action="append", help="IPC 端点，可重复指定")
    parser.add_argument("--rpc", action="append", help="HTTP RPC 端点，可重复指定")
    return parser.parse_args()


def normalize_marker(marker: str) -> str:
    marker = marker.lower()
    if not marker.startswith("0x"):
        marker = "0x" + marker
    try:
        bytes.fromhex(marker[2:])
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"标记必须是合法十六进制：{exc}") from exc
    return marker


def connect_providers(args: argparse.Namespace) -> List[Provider]:
    providers: List[Provider] = []
    ipc_list = args.ipc or []
    rpc_list = args.rpc or []
    if not ipc_list and not rpc_list:
        raise SystemExit("至少需要提供一个 --ipc 或 --rpc 端点")
    for ipc_path in ipc_list:
        w3 = Web3(Web3.IPCProvider(ipc_path, timeout=30))
        if not w3.is_connected():
            raise SystemExit(f"无法连接 IPC: {ipc_path}")
        providers.append(Provider(label=f"ipc:{ipc_path}", w3=w3))
    for rpc_url in rpc_list:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise SystemExit(f"无法连接 RPC: {rpc_url}")
        providers.append(Provider(label=f"rpc:{rpc_url}", w3=w3))
    return providers


def ensure_output(path: Optional[str]):
    if not path:
        return None
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target.open("a", encoding="utf-8")


TX_HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def load_ground_truth(path: Optional[str]) -> Optional[Set[str]]:
    if not path:
        return None
    hashes: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if not item:
                    continue
                if item.startswith("{"):
                    try:
                        info = json.loads(item)
                        item = info.get("tx_hash") or info.get("hash") or info.get("txHash")
                    except Exception:  # noqa: BLE001
                        item = None
                if isinstance(item, bytes):
                    try:
                        item = Web3.to_hex(item)
                    except Exception:  # noqa: BLE001
                        item = None
                if isinstance(item, str) and not item.startswith("0x"):
                    match = TX_HASH_RE.search(item)
                    item = match.group(0) if match else None
                if item:
                    hashes.add(str(item).lower())
    except Exception as exc:  # noqa: BLE001
        print(f"[VISIBILITY] Warning: ground-truth 读取失败：{exc}", file=sys.stderr)
    return hashes


def marker_matches(marker: str, data: str) -> bool:
    if data is None:
        return False
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = "0x" + bytes(data).hex()
    else:
        data = str(data)
    data = data.lower()
    return data.startswith(marker)


def write_event(handle, timestamp: float, tx_hash: str, kind: str, source: str) -> None:
    payload: Dict[str, object] = {
        "timestamp": timestamp,
        "tx_hash": tx_hash,
        "event": kind,
        "source": source,
    }
    json.dump(payload, handle, ensure_ascii=False)
    handle.write("\n")
    handle.flush()


def compute_metrics(
    ground_truth: Optional[Set[str]],
    observed_all: Set[str],
    observed_marked: Set[str],
) -> Dict[str, Optional[float]]:
    if ground_truth is not None and ground_truth:
        T_n = len(ground_truth)
        A_n = sum(1 for h in ground_truth if h in observed_marked)
        N_n = T_n - A_n
        P_n = sum(1 for h in observed_marked if h not in ground_truth)
    else:
        ground_truth = None  # 方便后续判断
        T_n = len(observed_marked)
        A_n = T_n
        N_n = 0
        P_n = 0
    C_n = len([h for h in observed_all if h not in observed_marked])

    DC = (A_n / T_n) if T_n else None
    AFP = (P_n / C_n) if C_n else None
    AFN = (N_n / T_n) if T_n else None

    return {
        "ground_truth": ground_truth is not None,
        "T_n": T_n,
        "A_n": A_n,
        "N_n": N_n,
        "P_n": P_n,
        "C_n": C_n,
        "DC": DC,
        "AFP": AFP,
        "AFN": AFN,
    }


def format_ratio(value: Optional[float]) -> str:
    return f"{value:.4f}" if isinstance(value, float) else "-"


def main() -> None:
    args = parse_args()
    marker = normalize_marker(args.marker)
    providers = connect_providers(args)
    output_handle = ensure_output(args.output)
    observed_all: Set[str] = set()
    observed_marked: Set[str] = set()
    written_observed: Set[str] = set()
    written_marked: Set[str] = set()

    try:
        with ThreadPoolExecutor(max_workers=len(providers)) as pool:
            while True:
                now = time.time()
                future_map = {pool.submit(provider.collect_pending): provider for provider in providers}
                for future in as_completed(future_map):
                    provider = future_map[future]
                    try:
                        transactions = future.result()
                    except Exception as exc:  # noqa: BLE001
                        print(f"[VISIBILITY] Warning: 查询 {provider.label} 失败：{exc}", file=sys.stderr)
                        continue

                    for tx in transactions:
                        tx_hash = tx.get("hash")
                        if isinstance(tx_hash, bytes):
                            tx_hash = Web3.to_hex(tx_hash)
                        if not tx_hash:
                            continue
                        tx_hash = str(tx_hash).lower()
                        if tx_hash not in observed_all:
                            observed_all.add(tx_hash)
                            if output_handle and tx_hash not in written_observed:
                                write_event(output_handle, now, tx_hash, "observed", provider.label)
                                written_observed.add(tx_hash)

                        data_field = tx.get("input") or tx.get("data") or "0x"
                        if marker_matches(marker, data_field):
                            if tx_hash not in observed_marked:
                                observed_marked.add(tx_hash)
                                if output_handle and tx_hash not in written_marked:
                                    write_event(output_handle, now, tx_hash, "marked", provider.label)
                                    written_marked.add(tx_hash)

                time.sleep(max(args.poll, 0.5))
    except KeyboardInterrupt:
        ground_truth = load_ground_truth(args.ground_truth)
        metrics = compute_metrics(ground_truth, observed_all, observed_marked)
        print("[METRICS] 指标统计：")
        if not metrics["ground_truth"]:
            print("  * 未提供 ground-truth，指标为下限估计")
        print(f"  T_n = {metrics['T_n']} (真实恶意交易数)")
        print(f"  A_n = {metrics['A_n']} (识别出的恶意交易数)")
        print(f"  N_n = {metrics['N_n']} (未识别的恶意交易数)")
        print(f"  P_n = {metrics['P_n']} (误报的正常交易数)")
        print(f"  C_n = {metrics['C_n']} (观测到的正常交易数)")
        print(f"  DC  = {format_ratio(metrics['DC'])}")
        print(f"  AFP = {format_ratio(metrics['AFP'])}")
        print(f"  AFN = {format_ratio(metrics['AFN'])}")
        if output_handle:
            snapshot = {
                "timestamp": time.time(),
                "metrics": metrics,
            }
            json.dump(snapshot, output_handle, ensure_ascii=False)
            output_handle.write("\n")
            output_handle.flush()
    finally:
        if output_handle:
            output_handle.close()


if __name__ == "__main__":
    main()
