#!/usr/bin/env python3
"""Send background transactions over a Geth IPC connection."""

from __future__ import annotations

import argparse
import sys
import time
from getpass import getpass
from pathlib import Path

from web3 import Web3


def positive_int(value: str) -> int:
    ivalue = int(value, 0)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return ivalue


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send background (legitimate) transactions via IPC.")
    parser.add_argument("--ipc", required=True, help="Path to the geth IPC endpoint, e.g. /root/Work/PraviteChain/geth.ipc")
    parser.add_argument(
        "--from-index",
        type=int,
        help="Index of eth.accounts used as sender; auto round-robin across accounts when omitted",
    )
    parser.add_argument(
        "--to",
        help="Recipient address; auto rotates through available accounts when omitted",
    )
    parser.add_argument("--count", type=positive_int, default=100, help="Number of transactions to send")
    parser.add_argument("--value-wei", type=positive_int, default=10**1, help="Transfer value per tx in wei (default: 1e15)")
    parser.add_argument("--gas", type=positive_int, default=21000, help="Gas limit per transaction (default: 21000)")
    parser.add_argument("--gas-price-wei", type=positive_int, help="Explicit gas price in wei; falls back to node suggestion")
    parser.add_argument("--passphrase", help="Passphrase applied to all selected accounts; prompts if omitted")
    parser.add_argument("--duration", type=positive_int, default=3600, help="Account unlock duration in seconds (default: 3600)")
    parser.add_argument("--interval", type=float, default=0.2, help="Delay between sends in seconds (default: 0.2)")
    return parser.parse_args()


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
    w3 = Web3(Web3.IPCProvider(args.ipc, timeout=30))
    ensure_connected(w3)

    accounts = w3.eth.accounts
    if not accounts:
        raise SystemExit("No accounts available on the connected node")
    checksum_accounts = [Web3.to_checksum_address(acct) for acct in accounts]

    if args.from_index is not None:
        if args.from_index < 0 or args.from_index >= len(checksum_accounts):
            raise SystemExit(f"from-index {args.from_index} out of range; accounts available: {len(checksum_accounts)}")
        sender_cycle = [checksum_accounts[args.from_index]]
    else:
        sender_cycle = checksum_accounts[:]

    if not sender_cycle:
        raise SystemExit("No sender accounts available after applying from-index filter")

    candidate_map = {}
    candidate_positions = {}
    if len(checksum_accounts) >= 2:
        for sender_addr in set(sender_cycle):
            candidates = [acct for acct in checksum_accounts if acct != sender_addr]
            if candidates:
                candidate_map[sender_addr] = candidates
                candidate_positions[sender_addr] = 0

    fixed_recipient = Web3.to_checksum_address(args.to) if args.to else None
    if not fixed_recipient and len(checksum_accounts) < 2:
        raise SystemExit("Need at least two accounts or provide --to to ensure sender and recipient differ")

    unique_senders = sorted(set(sender_cycle))
    if not fixed_recipient:
        for sender_addr in unique_senders:
            if sender_addr not in candidate_map:
                raise SystemExit(
                    f"Sender {sender_addr} has no alternate recipient; specify --to or add more accounts"
                )
    else:
        for sender_addr in unique_senders:
            if fixed_recipient == sender_addr and sender_addr not in candidate_map:
                raise SystemExit(
                    f"Sender {sender_addr} matches fixed recipient {fixed_recipient}; add more accounts or choose a different --to"
                )

    gas_price = args.gas_price_wei or w3.eth.gas_price

    passphrase = args.passphrase or getpass("Passphrase for background sender accounts: ")
    for sender_addr in unique_senders:
        if not unlock_account(w3, sender_addr, passphrase, args.duration):
            raise SystemExit(f"Failed to unlock sender account {sender_addr}")

    for idx in range(args.count):
        timestamp = time.time()
        try:
            sender = sender_cycle[idx % len(sender_cycle)]

            if fixed_recipient:
                recipient = fixed_recipient
                if recipient == sender:
                    fallback = candidate_map.get(sender)
                    if not fallback:
                        raise SystemExit(
                            f"Sender {sender} has no alternative recipient; specify --to or add more accounts"
                        )
                    pos = candidate_positions[sender]
                    recipient = fallback[pos % len(fallback)]
                    candidate_positions[sender] = (pos + 1) % len(fallback)
            else:
                fallback = candidate_map.get(sender)
                if not fallback:
                    raise SystemExit(
                        f"Sender {sender} has no alternative recipient; specify --to or add more accounts"
                    )
                pos = candidate_positions[sender]
                recipient = fallback[pos % len(fallback)]
                candidate_positions[sender] = (pos + 1) % len(fallback)

            nonce = w3.eth.get_transaction_count(sender, "pending")
            tx = {
                "from": sender,
                "to": recipient,
                "value": args.value_wei,
                "gas": args.gas,
                "gasPrice": gas_price,
                "nonce": nonce,
            }
            tx_hash = w3.eth.send_transaction(tx)
            print(
                f"[BACKGROUND] tx {idx + 1}/{args.count} hash={tx_hash.hex()} from={sender} to={recipient} nonce={nonce}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[BACKGROUND] error sending tx {idx + 1}/{args.count}: {exc}", file=sys.stderr)
        if idx + 1 < args.count:
            time.sleep(max(args.interval, 0.0))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
