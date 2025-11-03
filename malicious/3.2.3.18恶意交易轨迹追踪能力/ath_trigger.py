#!/usr/bin/env python3
"""向多个 RPC 节点广播带标记的正常交易，用于 3.2.3.18 传播路径测量。"""

from __future__ import annotations

import argparse
import json
import os
import time
from getpass import getpass
from typing import Iterable, List, Optional

from eth_account import Account
from web3 import Web3
from web3.types import TxParams


def positive_int(value: str) -> int:
    ivalue = int(value, 0)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return ivalue


def non_negative_int(value: str) -> int:
    ivalue = int(value, 0)
    if ivalue < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return ivalue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="向指定 RPC 节点批量发送带标记的普通交易")
    parser.add_argument(
        "--rpc",
        action="append",
        dest="rpc_list",
        required=True,
        help="HTTP RPC 节点地址，可多次指定实现轮询 (http://127.0.0.1:8545)",
    )
    parser.add_argument("--marker", default="0xdeaddead", help="交易 input 的十六进制前缀标识")
    parser.add_argument("--count", type=positive_int, default=200, help="总交易数 (默认 200)")
    parser.add_argument("--value-wei", type=non_negative_int, default=0, help="每笔交易附带的转账金额，单位 wei")
    parser.add_argument("--gas-limit", type=positive_int, default=90000, help="交易 gas limit (默认 90000)")
    parser.add_argument(
        "--gas-price-wei",
        type=positive_int,
        help="显式指定 gas price (wei)。若未提供则按节点建议值乘以倍数",
    )
    parser.add_argument(
        "--gas-price-multiplier",
        type=float,
        default=1.5,
        help="在节点返回的 gas price 上乘以的倍数 (默认 1.5)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.05,
        help="连续交易之间的等待秒数 (默认 0.05)",
    )
    parser.add_argument(
        "--to",
        help="目标地址；缺省时使用发送账户自身 (自发送)",
    )
    parser.add_argument(
        "--keystore-env",
        default="ATTACKER_KEYSTORE",
        help="包含 keystore JSON 的环境变量名称 (默认 ATTACKER_KEYSTORE)",
    )
    parser.add_argument("--passphrase", help="解锁 keystore 的口令；缺省时交互式输入")
    parser.add_argument(
        "--output",
        help="可选：将发送详情以 JSONL 追加写入此文件",
    )
    parser.add_argument(
        "--chain-id",
        type=positive_int,
        help="覆盖链 ID；未提供时按节点返回值设置",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅读取 nonce 和 gas 设置，不真正广播交易",
    )
    return parser.parse_args()


def load_keystore(env_name: str, passphrase: Optional[str]) -> tuple[str, bytes]:
    raw = os.getenv(env_name, "").strip()
    if not raw:
        raise SystemExit(f"环境变量 {env_name} 未提供 keystore JSON")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:  # noqa: NIV001
        raise SystemExit(f"无法解析 {env_name} 中的 keystore JSON: {exc}") from exc
    phrase = passphrase or getpass("Keystore passphrase: ")
    try:
        private_key = Account.decrypt(payload, phrase)
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"无法解密 keystore: {exc}") from exc
    address = Account.from_key(private_key).address
    return Web3.to_checksum_address(address), private_key


def connect_rpc(urls: List[str]) -> List[Web3]:
    providers: List[Web3] = []
    for url in urls:
        provider = Web3.HTTPProvider(url, request_kwargs={"timeout": 30})
        w3 = Web3(provider)
        if not w3.is_connected():
            raise SystemExit(f"无法连接到 RPC {url}")
        providers.append(w3)
    return providers


def ensure_gas_price(
    w3_list: List[Web3],
    user_price: Optional[int],
    multiplier: float,
) -> int:
    if user_price is not None:
        return user_price
    suggestions: List[int] = []
    for w3 in w3_list:
        try:
            suggestions.append(w3.eth.gas_price)
        except Exception:  # noqa: BLE001
            continue
    if not suggestions:
        raise SystemExit("无法从任何节点获取 gas price，请显式指定 --gas-price-wei")
    base = max(suggestions)
    adjusted = int(base * max(multiplier, 1.0))
    return max(adjusted, base)


def build_payload(marker: str) -> str:
    marker = marker.lower()
    if not marker.startswith("0x"):
        marker = "0x" + marker
    try:
        marker_bytes = bytes.fromhex(marker[2:])
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"Marker 必须是合法十六进制: {exc}") from exc
    suffix = os.urandom(16)
    return Web3.to_hex(marker_bytes + suffix)


def resolve_chain_id(w3: Web3, override: Optional[int]) -> int:
    if override:
        return override
    return w3.eth.chain_id


def fetch_start_nonce(w3: Web3, address: str) -> int:
    return w3.eth.get_transaction_count(Web3.to_checksum_address(address), "pending")


def append_log(handle, payload: dict) -> None:
    if handle is None:
        return
    json.dump(payload, handle, ensure_ascii=False)
    handle.write("\n")
    handle.flush()


def cycle(iterable: Iterable[Web3]):
    items = list(iterable)
    while True:
        for item in items:
            yield item


def main() -> None:
    args = parse_args()
    if args.gas_price_multiplier <= 0:
        raise SystemExit("--gas-price-multiplier 必须大于 0")
    if args.interval < 0:
        raise SystemExit("--interval 不能为负数")
    sender_address, private_key = load_keystore(args.keystore_env, args.passphrase)
    target_address = Web3.to_checksum_address(args.to) if args.to else sender_address

    w3_list = connect_rpc(args.rpc_list)
    gas_price = ensure_gas_price(w3_list, args.gas_price_wei, args.gas_price_multiplier)

    base_chain_id = resolve_chain_id(w3_list[0], args.chain_id)
    next_nonce = fetch_start_nonce(w3_list[0], sender_address)

    for extra_w3 in w3_list[1:]:
        chain_id = resolve_chain_id(extra_w3, args.chain_id)
        if chain_id != base_chain_id:
            endpoint = getattr(extra_w3.provider, "endpoint_uri", getattr(extra_w3.provider, "_endpoint_uri", "<unknown>"))
            raise SystemExit(
                f"节点 {endpoint} 的 chainId={chain_id} 与首个节点 chainId={base_chain_id} 不一致"
            )
    providers_cycle = cycle(w3_list)
    output_handle = open(args.output, "a", encoding="utf-8") if args.output else None

    print(
        f"[ATH] 将通过 {len(w3_list)} 个 RPC 节点发送 {args.count} 笔交易，sender={sender_address} target={target_address}",
        flush=True,
    )
    print(f"[ATH] gasPrice={gas_price} wei, gasLimit={args.gas_limit}, value={args.value_wei} wei", flush=True)

    try:
        for idx in range(args.count):
            w3 = next(providers_cycle)
            w3_id = getattr(w3.provider, "endpoint_uri", getattr(w3.provider, "_endpoint_uri", "unknown"))

            tx: TxParams = {
                "to": target_address,
                "value": args.value_wei,
                "gas": args.gas_limit,
                "gasPrice": gas_price,
                "nonce": next_nonce,
                "data": build_payload(args.marker),
                "chainId": base_chain_id,
            }

            log_payload = {
                "index": idx + 1,
                "total": args.count,
                "rpc": w3_id,
                "from": sender_address,
                "to": target_address,
                "nonce": next_nonce,
                "gas": args.gas_limit,
                "gasPrice": gas_price,
                "value": args.value_wei,
            }

            if args.dry_run:
                print(f"[ATH][{idx + 1}/{args.count}] dry-run nonce={next_nonce} rpc={w3_id}", flush=True)
                append_log(output_handle, log_payload)
                next_nonce += 1
                time.sleep(max(args.interval, 0.0))
                continue

            signed = Account.sign_transaction(tx, private_key)
            tx_hash_hex = signed.hash.hex()

            try:
                w3.eth.send_raw_transaction(signed.raw_transaction)
            except Exception as exc:  # noqa: BLE001
                err_text = str(exc)
                log_payload["error"] = err_text
                normalized = err_text.lower()
                if "already known" in normalized or "known transaction" in normalized:
                    # 交易已在节点中，视为成功
                    next_nonce += 1
                    log_payload["hash"] = tx_hash_hex
                    append_log(output_handle, log_payload)
                    print(
                        f"[ATH][{idx + 1}/{args.count}] 已存在 nonce={tx['nonce']} rpc={w3_id} hash={tx_hash_hex}",
                        flush=True,
                    )
                    time.sleep(max(args.interval, 0.0))
                    continue
                if "nonce too low" in normalized or "replacement transaction underpriced" in normalized:
                    refreshed = fetch_start_nonce(w3, sender_address)
                    if refreshed > next_nonce:
                        next_nonce = refreshed
                print(
                    f"[ATH][{idx + 1}/{args.count}] 发送失败 nonce={tx['nonce']} rpc={w3_id}: {err_text}",
                    flush=True,
                )
                append_log(output_handle, log_payload)
                time.sleep(max(args.interval, 0.0))
                continue

            next_nonce += 1
            log_payload["hash"] = tx_hash_hex
            append_log(output_handle, log_payload)
            print(
                f"[ATH][{idx + 1}/{args.count}] hash={tx_hash_hex} nonce={tx['nonce']} rpc={w3_id}",
                flush=True,
            )

            time.sleep(max(args.interval, 0.0))

    except KeyboardInterrupt:
        print("[ATH] 捕获到 Ctrl-C，提前停止", flush=True)
    finally:
        if output_handle:
            output_handle.close()


if __name__ == "__main__":
    main()
