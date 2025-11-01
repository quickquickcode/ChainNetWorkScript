#!/usr/bin/env python3
"""Emit marked malicious transactions against a remote RPC/IPC endpoint."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from getpass import getpass
from typing import Dict, Iterable, List, Optional

from eth_account import Account
from web3 import Web3
from web3.types import TxParams


@dataclass
class SenderState:
    base_nonce: int
    next_nonce: int
    last_gas_price: int


REJECTION_MODES = ("dup_nonce", "insufficient_funds", "low_gas_limit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send tagged malicious transactions.")
    location = parser.add_mutually_exclusive_group(required=True)
    location.add_argument("--ipc", help="Path to local geth IPC endpoint")
    location.add_argument("--rpc", help="HTTP RPC endpoint, e.g. http://127.0.0.1:8545")
    parser.add_argument(
        "--marker",
        default="0xdeaddead",
        help="Hex prefix tagged onto tx input for downstream identification (default: 0xdeaddead)",
    )
    parser.add_argument("--count", type=int, default=200, help="Total transactions to emit (default: 200)")
    parser.add_argument(
        "--reject-ratio",
        type=float,
        default=0.2,
        help="Fraction of transactions that intentionally trigger validation failures (default: 0.2)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.05,
        help="Delay between consecutive sends in seconds (default: 0.05)",
    )
    parser.add_argument(
        "--value-wei",
        type=int,
        default=0,
        help="Base transfer value for flood transactions (default: 0)",
    )
    parser.add_argument(
        "--gas",
        type=int,
        default=60000,
        help="Gas limit for standard flood transactions (default: 60000; allows non-empty data)",
    )
    parser.add_argument(
        "--gas-price-wei",
        type=int,
        help="Explicit gas price in wei; defaults to node suggested gas price",
    )
    parser.add_argument(
        "--passphrase",
        help="Passphrase for unlocking local accounts or decrypting keystore; prompts when omitted",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=3600,
        help="Account unlock duration in seconds when using personal API (default: 3600)",
    )
    parser.add_argument(
        "--from-index",
        type=int,
        help="Limit sender selection to a single account index; defaults to using all local accounts",
    )
    parser.add_argument(
        "--target",
        help="Optional fixed recipient address; when omitted recipients rotate across available accounts",
    )
    parser.add_argument(
        "--keystore-env",
        default="ATTACKER_KEYSTORE",
        help="Environment variable that stores keystore JSON for raw-signed mode (default: ATTACKER_KEYSTORE)",
    )
    parser.add_argument(
        "--output",
        help="Optional path to append detailed send logs (JSONL) for offline correlation",
    )
    return parser


def to_checksum(address: str | None) -> Optional[str]:
    if not address:
        return None
    try:
        return Web3.to_checksum_address(address)
    except ValueError:
        return None


def ensure_accounts(
    w3: Web3,
    from_index: Optional[int],
    keystore_env: str,
    passphrase: Optional[str],
    duration: int,
) -> tuple[List[str], Dict[str, bytes], str]:
    keystore_raw = os.getenv(keystore_env, "").strip()
    private_keys: Dict[str, bytes] = {}
    if keystore_raw:
        try:
            keystore = json.loads(keystore_raw)
        except json.JSONDecodeError as exc:  # noqa: NIV001
            raise SystemExit(f"Failed to parse keystore from {keystore_env}: {exc}") from exc
        phrase = passphrase or getpass("Keystore passphrase: ")
        try:
            key_bytes = Account.decrypt(keystore, phrase)
        except ValueError as exc:  # noqa: NIV001
            raise SystemExit(f"Failed to decrypt keystore: {exc}") from exc
        account = Account.from_key(key_bytes).address
        checksum = Web3.to_checksum_address(account)
        private_keys[checksum] = key_bytes
        return [checksum], private_keys, phrase

    accounts = [Web3.to_checksum_address(acc) for acc in w3.eth.accounts]
    if not accounts:
        raise SystemExit("No accounts available on the connected node")

    if from_index is not None:
        if from_index < 0 or from_index >= len(accounts):
            raise SystemExit(f"from-index {from_index} out of range; available accounts: {len(accounts)}")
        selected = [accounts[from_index]]
    else:
        selected = accounts

    phrase = passphrase or getpass("Passphrase for attacker accounts: ")
    personal = getattr(getattr(w3, "geth", None), "personal", None)
    if not personal or not hasattr(personal, "unlock_account"):
        raise SystemExit("personal API unavailable; provide keystore via ATTACKER_KEYSTORE")
    for address in selected:
        if not personal.unlock_account(address, phrase, duration):
            raise SystemExit(f"Failed to unlock account {address}")
    return selected, private_keys, phrase


def resolve_provider(args: argparse.Namespace) -> Web3:
    if args.ipc:
        provider = Web3.IPCProvider(args.ipc, timeout=30)
    else:
        provider = Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 30})
    w3 = Web3(provider)
    if not w3.is_connected():
        raise SystemExit("Unable to connect to the specified endpoint")
    return w3


def select_recipient(sender: str, candidates: List[str], fixed: Optional[str], state: Dict[str, int]) -> str:
    if fixed:
        if fixed != sender:
            return fixed
        if sender not in state:
            raise SystemExit("Fixed recipient matches sender and no alternates available")
    if sender not in state:
        state[sender] = 0
    pos = state[sender]
    recipients = [acct for acct in candidates if acct != sender]
    if not recipients:
        raise SystemExit("No valid recipient accounts available; specify --target")
    choice = recipients[pos % len(recipients)]
    state[sender] = (pos + 1) % len(recipients)
    return choice


def build_marker_payload(marker: str) -> str:
    marker = marker.lower()
    if not marker.startswith("0x"):
        marker = "0x" + marker
    try:
        marker_bytes = bytes.fromhex(marker[2:])
    except ValueError as exc:  # noqa: NIV001
        raise SystemExit(f"Marker must be valid hex: {exc}") from exc
    random_suffix = os.urandom(12)
    payload = marker_bytes + random_suffix
    return Web3.to_hex(payload)


def prepare_sender_state(w3: Web3, accounts: Iterable[str], base_gas_price: int) -> Dict[str, SenderState]:
    state: Dict[str, SenderState] = {}
    for address in accounts:
        nonce = w3.eth.get_transaction_count(address, "pending")
        state[address] = SenderState(base_nonce=nonce, next_nonce=nonce, last_gas_price=base_gas_price)
    return state


def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{timestamp}] {message}", flush=True)


def append_output(handle, payload: dict) -> None:
    if handle is None:
        return
    json.dump(payload, handle, ensure_ascii=False)
    handle.write("\n")
    handle.flush()


def choose_mode(reject_ratio: float) -> str:
    if reject_ratio <= 0:
        return "flood"
    if random.random() < reject_ratio:
        return random.choice(REJECTION_MODES)
    return "flood"


def adjust_for_mode(
    mode: str,
    tx: TxParams,
    sender_state: SenderState,
    w3: Web3,
    sender: str,
) -> None:
    if mode == "flood":
        return

    if mode == "low_gas_limit":
        tx["gas"] = max(20000, tx.get("gas", 21000) - random.randint(2000, 8000))
        return

    if mode == "insufficient_funds":
        balance = w3.eth.get_balance(sender)
        increment = w3.to_wei(random.uniform(0.1, 1.0), "ether")
        tx["value"] = balance + int(increment)
        return

    if mode == "dup_nonce":
        prior_nonce = max(sender_state.base_nonce, sender_state.next_nonce - 1)
        tx["nonce"] = prior_nonce
        prior_gas_price = sender_state.last_gas_price
        reduced = max(1, prior_gas_price // (2 + random.randint(0, 2)))
        tx["gasPrice"] = min(prior_gas_price - 1, reduced)
        return


def send_transaction(
    w3: Web3,
    tx: TxParams,
    private_keys: Dict[str, bytes],
) -> str:
    sender = tx["from"]
    if sender in private_keys:
        raw_tx = dict(tx)
        raw_tx.setdefault("chainId", w3.eth.chain_id)
        signed = Account.sign_transaction(raw_tx, private_keys[sender])
        return w3.eth.send_raw_transaction(signed.raw_transaction).hex()
    return w3.eth.send_transaction(tx).hex()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be positive")
    if not (0.0 <= args.reject_ratio < 1.0):
        raise SystemExit("--reject-ratio must be in [0, 1)")

    w3 = resolve_provider(args)
    accounts, private_keys, phrase = ensure_accounts(w3, args.from_index, args.keystore_env, args.passphrase, args.duration)
    recipients = accounts if not args.target else accounts + [Web3.to_checksum_address(args.target)]
    recipient_positions: Dict[str, int] = {}
    target_addr = to_checksum(args.target)

    gas_price = args.gas_price_wei or w3.eth.gas_price
    sender_states = prepare_sender_state(w3, accounts, gas_price)

    export_cmd = "export ATTACKER_ACCOUNTS=" + ",".join(accounts)
    log(f"Attacker accounts: {', '.join(accounts)}")
    log(export_cmd)

    output_handle = open(args.output, "a", encoding="utf-8") if args.output else None
    payload_marker = args.marker

    try:
        for index in range(args.count):
            sender = accounts[index % len(accounts)]
            mode = choose_mode(args.reject_ratio)
            sender_state = sender_states[sender]

            tx: TxParams = {
                "from": sender,
                "to": select_recipient(sender, recipients, target_addr, recipient_positions),
                "value": args.value_wei,
                "gas": args.gas,
                "gasPrice": gas_price,
                "nonce": sender_state.next_nonce,
                "data": build_marker_payload(payload_marker),
            }

            adjust_for_mode(mode, tx, sender_state, w3, sender)

            log_payload = {
                "index": index + 1,
                "total": args.count,
                "mode": mode,
                "from": tx["from"],
                "to": tx["to"],
                "nonce": tx["nonce"],
                "gas": tx["gas"],
                "gasPrice": tx["gasPrice"],
                "value": tx["value"],
            }

            try:
                tx_hash = send_transaction(w3, tx, private_keys)
            except Exception as exc:  # noqa: BLE001
                log(f"[TRIGGER][{index + 1}/{args.count}] error mode={mode} sender={sender} nonce={tx['nonce']}: {exc}")
                log_payload["error"] = str(exc)
                append_output(output_handle, log_payload)
                time.sleep(max(args.interval, 0.0))
                continue

            sender_state.last_gas_price = tx["gasPrice"]
            if mode != "dup_nonce":
                sender_state.next_nonce += 1

            log(f"[TRIGGER][{index + 1}/{args.count}] hash={tx_hash} mode={mode} sender={sender} nonce={tx['nonce']}")
            log_payload["hash"] = tx_hash
            append_output(output_handle, log_payload)

            time.sleep(max(args.interval, 0.0))

    except KeyboardInterrupt:
        log("Interrupted by user")
    finally:
        if output_handle:
            output_handle.close()
        if not private_keys:
            log("Locking attacker accounts")
            personal = getattr(getattr(w3, "geth", None), "personal", None)
            if personal and hasattr(personal, "lock_account"):
                for address in accounts:
                    try:
                        personal.lock_account(address)
                    except Exception:  # noqa: BLE001
                        pass


if __name__ == "__main__":
    main()
