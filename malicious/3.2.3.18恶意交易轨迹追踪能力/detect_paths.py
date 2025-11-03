#!/usr/bin/env python3
"""并行观测各节点 pending 交易以重建恶意交易传播路径。"""

from __future__ import annotations

import argparse
import asyncio
import inspect
from typing import Any, Dict, List, Optional, Tuple, Set
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
import aiohttp
from urllib.parse import urlparse, urlunparse

from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import TransactionNotFound
from web3.types import TxData

# 支持从普通日志中抽取交易哈希
TX_HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")


def normalize_marker(marker: str) -> str:
    marker = marker.lower()
    if not marker.startswith("0x"):
        marker = "0x" + marker
    try:
        bytes.fromhex(marker[2:])
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"标记必须是合法十六进制：{exc}") from exc
    return marker


def normalize_url(raw: str, default_scheme: str = "http", default_port: int = 8545) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("空的节点地址")
    if "://" not in raw:
        raw = f"{default_scheme}://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        raise ValueError(f"不支持的协议：{parsed.scheme}")
    # aiohttp 要求 http/https，如需 WebSocket 另行实现
    if parsed.scheme in {"ws", "wss"}:
        raise ValueError("暂不支持 WebSocket 地址，请提供 HTTP/HTTPS 节点")
    netloc = parsed.netloc
    if ":" not in netloc:
        netloc = f"{netloc}:{default_port}"
    normalized = parsed._replace(netloc=netloc)
    return urlunparse(normalized)


def marker_matches(marker: str, data: object) -> bool:
    if data is None:
        return False
    if isinstance(data, (bytes, bytearray, memoryview)):
        payload = "0x" + bytes(data).hex()
    else:
        payload = str(data)
    return payload.lower().startswith(marker)


def extract_tx_hash(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = "0x" + bytes(value).hex()
    value = str(value)
    if value.startswith("0x") and len(value) == 66:
        return value.lower()
    match = TX_HASH_RE.search(value)
    if match:
        return match.group(0).lower()
    return None


def normalize_address(value: object) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = "0x" + bytes(value).hex()
    value = str(value)
    if not value.startswith("0x"):
        return None
    if len(value) == 42:
        return value.lower()
    return None


@dataclass
class NodeObservation:
    first_seen: float
    last_seen: float


@dataclass
class TxRecord:
    tx_hash: str
    sender: Optional[str]
    observations: Dict[str, NodeObservation] = field(default_factory=dict)
    receipt_status: Optional[int] = None
    receipt_block: Optional[int] = None
    receipt_timestamp: Optional[int] = None
    last_receipt_check: float = 0.0

    def register_observation(self, node: str, when: float) -> bool:
        obs = self.observations.get(node)
        if obs is None:
            self.observations[node] = NodeObservation(first_seen=when, last_seen=when)
            return True
        obs.last_seen = when
        return False

    def first_seen_global(self) -> float:
        return min(obs.first_seen for obs in self.observations.values())

    def detection_spread(self) -> float:
        times = [obs.first_seen for obs in self.observations.values()]
        if not times:
            return 0.0
        return max(times) - min(times)


class Provider:
    """包装单个 RPC 节点，负责拉取 pending 交易。"""

    def __init__(self, label: str, w3: AsyncWeb3) -> None:
        self.label = label
        self.w3 = w3
        self.failures = 0
        self.successes = 0
        self.last_error: Optional[str] = None
        self.last_success: Optional[float] = None
        self._closed = False

    async def fetch_pending(self) -> List[TxData]:
        seen: Dict[str, TxData] = {}
        # 1) eth_pendingTransactions（若节点支持）
        try:
            result = await self.w3.manager.coro_request("eth_pendingTransactions", [])
        except Exception:  # noqa: BLE001
            result = []
        for item in result or []:
            tx = dict(item)
            tx_hash = extract_tx_hash(tx.get("hash"))
            if not tx_hash or tx_hash in seen:
                continue
            seen[tx_hash] = tx
        # 2) fallback: pending block
        if not seen:
            try:
                block = await self.w3.eth.get_block("pending", full_transactions=True)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001
                block = None
            if block:
                for entry in block.get("transactions", []) or []:
                    tx = dict(entry)
                    tx_hash = extract_tx_hash(tx.get("hash"))
                    if not tx_hash or tx_hash in seen:
                        continue
                    seen[tx_hash] = tx
        return list(seen.values())

    async def close(self) -> None:
        if self._closed:
            return
        provider = self.w3.provider
        await close_provider_session(provider)
        self._closed = True


async def close_provider_session(provider: Any) -> None:
    visited: Set[int] = set()

    async def _close_candidates(obj: Any) -> None:
        if obj is None:
            return
        obj_id = id(obj)
        if obj_id in visited:
            return
        visited.add(obj_id)
        if isinstance(obj, aiohttp.ClientSession):
            if not obj.closed:
                try:
                    await obj.close()
                except Exception as exc:  # noqa: BLE001
                    print(f"[PATH] Warning: 关闭 ClientSession 失败：{exc}", file=sys.stderr)
            return
        close_fn = getattr(obj, "close", None)
        if callable(close_fn):
            try:
                result = close_fn()
                if inspect.isawaitable(result):
                    await result
            except Exception:  # noqa: BLE001
                pass
        for attr in dir(obj):
            if "session" not in attr.lower():
                continue
            try:
                candidate = getattr(obj, attr)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(candidate, (list, tuple, set)):
                for item in candidate:
                    await _close_candidates(item)
                continue
            await _close_candidates(candidate)

    await _close_candidates(provider)
    for attr in ("_request_manager", "request_manager", "manager"):
        try:
            await _close_candidates(getattr(provider, attr))
        except Exception:  # noqa: BLE001
            continue


async def fetch_for_provider(provider: Provider) -> Tuple[Provider, List[TxData], Optional[Exception]]:
    try:
        txs = await provider.fetch_pending()
        return provider, txs, None
    except Exception as exc:  # noqa: BLE001
        return provider, [], exc


def load_hosts(path: Path) -> List[str]:
    if not path.exists():
        raise SystemExit(f"找不到 hosts 文件：{path}")
    hosts: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            try:
                hosts.append(normalize_url(raw))
            except ValueError as exc:  # noqa: NIV001
                raise SystemExit(f"hosts 文件第 {idx} 行无效：{exc}") from exc
    if not hosts:
        raise SystemExit("hosts 文件为空")
    return hosts


def ensure_output(path: Optional[str]):
    if not path:
        return None
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target.open("a", encoding="utf-8")


def write_event(handle, payload: Dict[str, object]) -> None:
    json.dump(payload, handle, ensure_ascii=False)
    handle.write("\n")
    handle.flush()


async def resolve_receipts(
    records: Dict[str, TxRecord],
    providers: List[Provider],
    now: float,
    receipt_interval: float,
    output_handle,
) -> None:
    if not providers:
        return
    primary = providers[0]
    for record in records.values():
        if len(record.observations) < 2:
            continue
        if record.receipt_status is not None and record.receipt_block is not None:
            continue
        if now - record.last_receipt_check < receipt_interval:
            continue
        record.last_receipt_check = now
        try:
            receipt = await primary.w3.eth.get_transaction_receipt(record.tx_hash)
        except TransactionNotFound:
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"[PATH] Warning: receipt 查询失败 {record.tx_hash}: {exc}", file=sys.stderr)
            continue
        if receipt is None:
            continue
        status = receipt.get("status")
        record.receipt_status = int(status) if status is not None else None
        record.receipt_block = receipt.get("blockNumber")
        record.receipt_timestamp = receipt.get("blockTimestamp") or receipt.get("timestamp")
        if output_handle:
            write_event(
                output_handle,
                {
                    "timestamp": now,
                    "event": "receipt",
                    "tx_hash": record.tx_hash,
                    "status": record.receipt_status,
                    "blockNumber": record.receipt_block,
                    "blockTimestamp": record.receipt_timestamp,
                },
            )


def compute_metrics(records: Dict[str, TxRecord]) -> Dict[str, object]:
    total = len(records)
    reconstructable = [rec for rec in records.values() if len(rec.observations) >= 2]
    n_path = len(reconstructable)
    if n_path:
        spreads = [rec.detection_spread() for rec in reconstructable]
        ads = sum(spreads) / n_path
        max_idx = max(range(n_path), key=lambda idx: spreads[idx])
        max_record = reconstructable[max_idx]
        mds = spreads[max_idx]
        sequence = sorted(
            ((node, obs.first_seen) for node, obs in max_record.observations.items()),
            key=lambda item: item[1],
        )
    else:
        ads = None
        mds = None
        sequence = []
    return {
        "N_total": total,
        "N_path": n_path,
        "RPR": (n_path / total) if total else None,
        "ADS": ads,
        "MDS": mds,
        "MDS_sequence": sequence,
    }


async def run(args: argparse.Namespace) -> None:
    marker = normalize_marker(args.marker)
    hosts = load_hosts(Path(args.hosts))
    providers = [
        Provider(
            label=url,
            w3=AsyncWeb3(
                AsyncHTTPProvider(
                    url,
                    request_kwargs={"timeout": args.request_timeout},
                )
            ),
        )
        for url in hosts
    ]
    output_handle = ensure_output(args.output)
    records: Dict[str, TxRecord] = {}
    last_new_sample = time.time()
    last_status = 0.0
    seen_any = False

    try:
        while True:
            loop_started = time.time()
            results = await asyncio.gather(*(fetch_for_provider(p) for p in providers))
            new_sample = False
            now = time.time()
            for provider, txs, error in results:
                label = provider.label
                if error:
                    provider.failures += 1
                    err_text = str(error)
                    if len(err_text) > 200:
                        err_text = err_text[:197] + "..."
                    provider.last_error = err_text
                    print(f"[PATH] Warning: 查询 {label} 失败：{err_text}", file=sys.stderr)
                    continue
                provider.successes += 1
                provider.last_success = now
                for tx in txs:
                    data_field = tx.get("input") or tx.get("data") or "0x"
                    if not marker_matches(marker, data_field):
                        continue
                    tx_hash = extract_tx_hash(tx.get("hash"))
                    if not tx_hash:
                        continue
                    sender = normalize_address(tx.get("from"))
                    record = records.get(tx_hash)
                    if record is None:
                        record = TxRecord(tx_hash=tx_hash, sender=sender)
                        records[tx_hash] = record
                    first_on_node = record.register_observation(label, now)
                    if first_on_node:
                        new_sample = True
                        seen_any = True
                        if output_handle:
                            write_event(
                                output_handle,
                                {
                                    "timestamp": now,
                                    "event": "first_seen",
                                    "tx_hash": tx_hash,
                                    "node": label,
                                    "from": sender,
                                },
                            )
                    # 非首次观测不重复写入，避免日志暴涨
            if new_sample:
                last_new_sample = time.time()
            await resolve_receipts(
                records=records,
                providers=providers,
                now=time.time(),
                receipt_interval=args.receipt_interval,
                output_handle=output_handle,
            )
            now_after = time.time()
            if seen_any and (now_after - last_new_sample) >= args.idle_timeout:
                print("[PATH] Idle timeout reached, stopping ...", flush=True)
                break
            if (now_after - last_status) >= args.status_interval:
                last_status = now_after
                print(
                    f"[PATH] 状态：记录 {len(records)} 条，最近成功轮询次数 {sum(p.successes for p in providers)}，"
                    f"失败次数 {sum(p.failures for p in providers)}",
                    flush=True,
                )
                unhealthy = [
                    p
                    for p in providers
                    if p.failures and (p.last_success is None or (now_after - p.last_success) > args.status_interval)
                ]
                for p in unhealthy:
                    err = p.last_error or "未知错误"
                    print(f"[PATH]   {p.label} 最近失败：{err}", file=sys.stderr)
            sleep_for = max(args.poll - (time.time() - loop_started), 0.0)
            await asyncio.sleep(sleep_for)
    except KeyboardInterrupt:
        print("[PATH] 捕获到 Ctrl-C，准备收尾", flush=True)
    finally:
        metrics = compute_metrics(records)
        print("[PATH] 统计指标：")
        print(f"  N_total = {metrics['N_total']}")
        print(f"  N_path  = {metrics['N_path']}")
        rpr = metrics["RPR"]
        print(f"  RPR     = {rpr:.4f}" if isinstance(rpr, float) else "  RPR     = -")
        ads = metrics["ADS"]
        print(f"  ADS     = {ads:.4f} 秒" if isinstance(ads, float) else "  ADS     = -")
        mds = metrics["MDS"]
        if isinstance(mds, float):
            print(f"  MDS     = {mds:.4f} 秒")
            sequence = metrics["MDS_sequence"]
            if sequence:
                print("  MDS 对应节点顺序：")
                for node, ts in sequence:
                    print(f"    - {node} @ {ts:.6f}")
        else:
            print("  MDS     = -")
        if output_handle:
            write_event(
                output_handle,
                {
                    "timestamp": time.time(),
                    "event": "metrics",
                    "metrics": metrics,
                },
            )
            output_handle.close()
        await asyncio.gather(*(provider.close() for provider in providers), return_exceptions=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="检测恶意交易传播路径，并行轮询所有节点")
    parser.add_argument("--marker", default="0xdeaddead", help="恶意交易 input 标记前缀")
    parser.add_argument("--hosts", default="hosts_s.txt", help="包含 RPC 节点列表的文件路径")
    parser.add_argument("--poll", type=float, default=2.0, help="轮询间隔（秒）")
    parser.add_argument("--request-timeout", type=float, default=30.0, help="单次 RPC 请求超时（秒）")
    parser.add_argument("--idle-timeout", type=float, default=5.0, help="无新样本后的自动退出等待时间（秒）")
    parser.add_argument("--receipt-interval", type=float, default=5.0, help="同一交易回执查询的最小间隔（秒）")
    parser.add_argument("--status-interval", type=float, default=10.0, help="状态输出间隔（秒）")
    parser.add_argument("--output", help="可选：JSONL 输出文件")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
