#!/usr/bin/env python3
"""Unified front-running trigger with JSONL ground truth and optional FIFO streaming."""

from __future__ import annotations

import argparse
import errno
import hashlib
import itertools
import json
import os
import sys
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.types import TxParams

DEFAULT_BYTECODE = (
    "0x6080604052348015600f57600080fd5b5060c58061001e6000396000f3fe6080604052"
    "6004361060455760003560e01c8063c0e317fb14604a575b600080fd5b606a600480360360"
    "20811015605e57600080fd5b50356088565b60408051918252519081900360200190f35b60"
    "006000546001600160a01b03168156fea2646970667358221220645c41fbbf21ceae5fa18c"
    "f6d2d4c2de142c8f869f4f6fee577e0722b8aaabf364736f6c63430008160033"
)

GROUND_TRUTH_SCHEMA = "fr-trigger-event-v1"
PIPE_SCHEMA = "fr-trigger-tx-v1"


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------


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


def parse_wei(value: str) -> int:
    text = value.strip().lower()
    if text.endswith("eth"):
        amount = Decimal(text[:-3]) * Decimal(10**18)
    elif text.endswith("gwei"):
        amount = Decimal(text[:-4]) * Decimal(10**9)
    elif text.endswith("wei"):
        amount = Decimal(text[:-3])
    else:
        amount = Decimal(text)
    result = int(amount)
    if result < 0:
        raise argparse.ArgumentTypeError("amount must be non-negative")
    return result


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


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass
class ManagedAccount:
    label: str
    signer: LocalAccount
    nonce: Optional[int] = None

    @property
    def address(self) -> str:
        return Web3.to_checksum_address(self.signer.address)

    def next_nonce(self, provider: Web3) -> int:
        if self.nonce is None:
            self.nonce = provider.eth.get_transaction_count(self.address, "pending")
        value = self.nonce
        self.nonce += 1
        return value


class OutputChannels:
    def __init__(self, table_path: Optional[Path], pipe_path: Optional[Path]):
        self._table_fp = None
        self._pipe_fp = None
        if table_path:
            table_path.parent.mkdir(parents=True, exist_ok=True)
            self._table_fp = table_path.open("a", encoding="utf-8")
        if pipe_path:
            self._pipe_fp = self._open_fifo(pipe_path)

    def close(self) -> None:
        if self._table_fp:
            self._table_fp.close()
            self._table_fp = None
        if self._pipe_fp:
            self._pipe_fp.close()
            self._pipe_fp = None

    def write_ground_truth(self, record: Dict[str, object]) -> None:
        line = json.dumps(record, ensure_ascii=True)
        if self._table_fp:
            self._table_fp.write(line + "\n")
            self._table_fp.flush()
        else:
            print(line)

    def write_pipe(self, record: Dict[str, object]) -> None:
        if not self._pipe_fp:
            return
        line = json.dumps(record, ensure_ascii=True)
        try:
            self._pipe_fp.write(line + "\n")
            self._pipe_fp.flush()
        except BrokenPipeError:
            print("[PIPE] consumer disconnected; disable pipe output", file=sys.stderr)
            self._pipe_fp.close()
            self._pipe_fp = None

    @staticmethod
    def _open_fifo(pipe_path: Path):
        if os.name == "nt":  # pragma: no cover
            raise SystemExit("Named pipe streaming requires POSIX platforms")
        if pipe_path.exists() and not pipe_path.is_fifo():
            raise SystemExit(f"target {pipe_path} exists but is not FIFO")
        if not pipe_path.exists():
            os.mkfifo(pipe_path, 0o660)
        deadline = time.time() + 10
        while True:
            try:
                fd = os.open(str(pipe_path), os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError as exc:  # noqa: PERF203
                if exc.errno != errno.ENXIO:
                    raise
                if time.time() >= deadline:
                    raise SystemExit("Timed out waiting for pipe consumer") from exc
                time.sleep(0.5)
        return os.fdopen(fd, "w", buffering=1, encoding="utf-8")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def cycle_providers(providers: Sequence[Web3]) -> Iterable[Web3]:
    return itertools.cycle(providers)


def load_master(args: argparse.Namespace) -> ManagedAccount:
    raw = os.getenv("ATTACKER_KEYSTORE")
    if not raw:
        raise SystemExit("ATTACKER_KEYSTORE environment variable not set")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:  # noqa: B904
        raise SystemExit(f"failed to parse ATTACKER_KEYSTORE JSON: {exc}") from exc

    passphrase = args.passphrase
    if passphrase is None:
        from getpass import getpass

        passphrase = getpass("Keystore passphrase: ")
    try:
        key = Account.decrypt(payload, passphrase)
    except ValueError as exc:  # noqa: B904
        raise SystemExit(f"keystore decryption failed: {exc}") from exc
    acct = Account.from_key(key)
    return ManagedAccount(label="master", signer=acct)


def generate_children(quantity: int) -> List[ManagedAccount]:
    result: List[ManagedAccount] = []
    for idx in range(quantity):
        child = Account.create()
        result.append(ManagedAccount(label=f"child-{idx + 1}", signer=child))
    return result


def connect_rpcs(urls: Sequence[str]) -> Tuple[List[Web3], int]:
    if not urls:
        raise SystemExit("at least one --rpc endpoint required")
    providers: List[Web3] = []
    for url in urls:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise SystemExit(f"failed to connect to RPC: {url}")
        providers.append(w3)
    chain_id = providers[0].eth.chain_id
    for w3 in providers[1:]:
        if w3.eth.chain_id != chain_id:
            raise SystemExit("all RPC endpoints must belong to the same chain")
    return providers, chain_id


def ensure_balance(provider: Web3, address: str, minimum: int) -> None:
    balance = provider.eth.get_balance(address)
    if balance < minimum:
        raise SystemExit(
            f"master balance {balance} wei insufficient (< {minimum} wei)"
        )


def send_signed(provider: Web3, sender: ManagedAccount, tx: TxParams, dry_run: bool) -> Tuple[str, Optional[bytes]]:
    if dry_run:
        digest = hashlib.sha1(repr(tx).encode("ascii")).hexdigest()
        fake_hash = "0xDRY" + digest[:32]
        return fake_hash, None
    signed = sender.signer.sign_transaction(tx)
    raw_tx = getattr(signed, "rawTransaction", None)
    if raw_tx is None:
        raw_tx = getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raise RuntimeError("signed transaction missing raw bytes")
    tx_hash = provider.eth.send_raw_transaction(raw_tx)
    return Web3.to_hex(tx_hash), raw_tx


def wait_for_balance(provider: Web3, address: str, amount: int, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if provider.eth.get_balance(address) >= amount:
            return True
        time.sleep(2)
    return False


def deploy_helpers(
    providers: Sequence[Web3],
    master: ManagedAccount,
    chain_id: int,
    args: argparse.Namespace,
) -> List[str]:
    if args.contracts <= 0:
        return []
    rotation = cycle_providers(providers)
    deployed: List[str] = []
    print(f"[DEPLOY] deploying {args.contracts} helper contract(s)")
    for idx in range(args.contracts):
        provider = next(rotation)
        nonce = master.next_nonce(provider)
        tx: TxParams = {
            "chainId": chain_id,
            "nonce": nonce,
            "to": None,
            "value": 0,
            "gas": args.contract_gas,
            "gasPrice": args.victim_gas_price,
            "data": DEFAULT_BYTECODE,
        }
        tx_hash, _ = send_signed(provider, master, tx, args.dry_run)
        if args.dry_run:
            contract_address = f"0xDRYCONTRACT{idx:04d}"[:42]
        else:
            receipt = provider.eth.wait_for_transaction_receipt(tx_hash, timeout=args.receipt_timeout)
            contract_address = Web3.to_checksum_address(receipt["contractAddress"])
        deployed.append(contract_address)
        print(f"[DEPLOY] idx={idx + 1}/{args.contracts} addr={contract_address} hash={tx_hash}")
        if idx + 1 < args.contracts:
            time.sleep(max(args.interval, 0.0))
    return deployed


def fund_children(
    providers: Sequence[Web3],
    master: ManagedAccount,
    children: Sequence[ManagedAccount],
    chain_id: int,
    args: argparse.Namespace,
) -> None:
    if not children or args.fund_amount == 0:
        return
    rotation = cycle_providers(providers)
    for child in children:
        provider = next(rotation)
        nonce = master.next_nonce(provider)
        tx: TxParams = {
            "chainId": chain_id,
            "nonce": nonce,
            "to": child.address,
            "value": args.fund_amount,
            "gas": args.fund_gas,
            "gasPrice": args.victim_gas_price,
        }
        tx_hash, _ = send_signed(provider, master, tx, args.dry_run)
        print(f"[FUND] child={child.address} value={args.fund_amount} hash={tx_hash}")
        if not args.dry_run:
            provider.eth.wait_for_transaction_receipt(tx_hash, timeout=args.receipt_timeout)
            if not wait_for_balance(provider, child.address, args.fund_amount, args.balance_timeout):
                raise SystemExit(f"timed out waiting for {child.address} balance")
        if args.interval > 0:
            time.sleep(args.interval)


def marker_payload(marker: bytes, role_tag: int, pair_id: int) -> bytes:
    return marker + role_tag.to_bytes(1, "big") + pair_id.to_bytes(4, "big")


def choose_accounts(accounts: Sequence[ManagedAccount], index: int) -> Tuple[ManagedAccount, ManagedAccount]:
    victim = accounts[index % len(accounts)]
    runner = accounts[(index + 1) % len(accounts)]
    if victim.address == runner.address:
        runner = accounts[(index + 2) % len(accounts)]
    return victim, runner


# ---------------------------------------------------------------------------
# Core routines
# ---------------------------------------------------------------------------


def stream_prefill(
    providers: Sequence[Web3],
    accounts: Sequence[ManagedAccount],
    args: argparse.Namespace,
    channels: OutputChannels,
    chain_id: int,
) -> None:
    if args.skip_prefill or args.prefill_normal <= 0:
        return
    marker_bytes = parse_marker(args.prefill_marker)
    rotation = cycle_providers(providers)
    print(f"[PREFILL] sending {args.prefill_normal} warm-up transaction(s)")
    for idx in range(args.prefill_normal):
        sender = accounts[idx % len(accounts)]
        provider = next(rotation)
        nonce = sender.next_nonce(provider)
        payload = marker_bytes + b"\x00" + (idx + 1).to_bytes(4, "big")
        tx: TxParams = {
            "chainId": chain_id,
            "nonce": nonce,
            "to": accounts[0].address,
            "value": 0,
            "gas": args.prefill_gas,
            "gasPrice": args.victim_gas_price,
            "data": payload,
        }
        tx_hash, _ = send_signed(provider, sender, tx, args.dry_run)
        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA,
                "role": "prefill",
                "prefill_id": idx + 1,
                "tx_hash": tx_hash,
                "from": sender.address,
                "to": accounts[0].address,
                "gas": args.prefill_gas,
                "gas_price": args.victim_gas_price,
                "input_marker": args.prefill_marker,
                "timestamp": time.time(),
            }
        )
        print(f"[PREFILL] idx={idx + 1}/{args.prefill_normal} hash={tx_hash} nonce={nonce}")
        if idx + 1 < args.prefill_normal:
            time.sleep(max(args.interval, 0.0))
    if args.prefill_only:
        print("[DONE] prefill stage complete (prefill-only)")


def run_pairs(
    providers: Sequence[Web3],
    accounts: Sequence[ManagedAccount],
    contracts: Sequence[str],
    args: argparse.Namespace,
    channels: OutputChannels,
    chain_id: int,
) -> None:
    marker_bytes = parse_marker(args.marker)
    provider_cycle = cycle_providers(providers)
    contract_cycle = itertools.cycle(contracts) if contracts else None

    for pair_id in range(1, args.count + 1):
        victim_acct, runner_acct = choose_accounts(accounts, pair_id - 1)
        victim_provider = next(provider_cycle)
        runner_provider = next(provider_cycle)
        victim_nonce = victim_acct.next_nonce(victim_provider)
        runner_nonce = runner_acct.next_nonce(runner_provider)

        if args.victim_contract:
            target = Web3.to_checksum_address(args.victim_contract)
        elif contract_cycle:
            target = Web3.to_checksum_address(next(contract_cycle))
        else:
            target = victim_acct.address

        victim_payload = marker_payload(marker_bytes, 1, pair_id)
        runner_payload = marker_payload(marker_bytes, 2, pair_id)

        victim_tx: TxParams = {
            "chainId": chain_id,
            "nonce": victim_nonce,
            "to": target,
            "value": args.transfer_amount,
            "gas": args.victim_gas,
            "gasPrice": args.victim_gas_price,
            "data": victim_payload,
        }
        runner_tx: TxParams = {
            "chainId": chain_id,
            "nonce": runner_nonce,
            "to": target,
            "value": args.transfer_amount,
            "gas": args.runner_gas,
            "gasPrice": args.victim_gas_price + args.runner_premium,
            "data": runner_payload,
        }

        victim_hash, _ = send_signed(victim_provider, victim_acct, victim_tx, args.dry_run)
        runner_hash, _ = send_signed(runner_provider, runner_acct, runner_tx, args.dry_run)

        event_id = hashlib.sha1((victim_hash + runner_hash).encode("ascii")).hexdigest()[:16]
        timestamp = time.time()

        channels.write_ground_truth(
            {
                "schema": GROUND_TRUTH_SCHEMA,
                "event_id": event_id,
                "pair_id": pair_id,
                "victim_hash": victim_hash,
                "runner_hash": runner_hash,
                "victim_address": victim_acct.address,
                "runner_address": runner_acct.address,
                "target_address": target,
                "victim_nonce": victim_nonce,
                "runner_nonce": runner_nonce,
                "victim_gas_price": args.victim_gas_price,
                "runner_gas_price": args.victim_gas_price + args.runner_premium,
                "marker": args.marker,
                "pattern": "single",
                "timestamp": timestamp,
            }
        )

        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA,
                "pair_id": pair_id,
                "role": "victim",
                "tx_hash": victim_hash,
                "from": victim_acct.address,
                "to": target,
                "nonce": victim_nonce,
                "gas": args.victim_gas,
                "gas_price": args.victim_gas_price,
                "input_marker": args.marker,
                "timestamp": timestamp,
            }
        )
        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA,
                "pair_id": pair_id,
                "role": "runner",
                "tx_hash": runner_hash,
                "from": runner_acct.address,
                "to": target,
                "nonce": runner_nonce,
                "gas": args.runner_gas,
                "gas_price": args.victim_gas_price + args.runner_premium,
                "input_marker": args.marker,
                "timestamp": timestamp,
            }
        )

        print(
            "[PAIR] id={}/{} victim_hash={} runner_hash={} victim={} runner={}".format(
                pair_id,
                args.count,
                victim_hash,
                runner_hash,
                victim_acct.address,
                runner_acct.address,
            )
        )
        if pair_id < args.count and args.interval > 0:
            time.sleep(args.interval)


# ---------------------------------------------------------------------------
# CLI / entry-point
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate controlled front-running pairs")
    parser.add_argument("--rpc", action="append", required=True, help="HTTP RPC endpoint; repeatable")
    parser.add_argument("--count", type=positive_int, default=100, help="Number of victim/runner pairs")
    parser.add_argument("--marker", default="0xfeedface", help="Marker prefix for calldata")
    parser.add_argument("--runner-premium", type=parse_wei, default="30gwei", help="Runner gas price premium over victim")
    parser.add_argument("--victim-gas-price", type=parse_wei, default="0", help="Baseline gas price for victim (0 => suggest from node)")
    parser.add_argument("--victim-gas", type=positive_int, default=120000, help="Gas limit for victim tx")
    parser.add_argument("--runner-gas", type=positive_int, default=120000, help="Gas limit for runner tx")
    parser.add_argument("--transfer-amount", type=parse_wei, default="0", help="ETH value (wei) attached to each tx")
    parser.add_argument("--accounts", type=positive_int, default=2, help="Total sending accounts including master")
    parser.add_argument("--fund-amount", type=parse_wei, default="0.05eth", help="Funding amount per generated child account")
    parser.add_argument("--fund-gas", type=positive_int, default=21000, help="Gas limit for funding transfers")
    parser.add_argument("--contracts", type=non_negative_int, default=0, help="Number of helper contracts to deploy")
    parser.add_argument("--contract-gas", type=positive_int, default=550000, help="Gas limit for helper contract deployment")
    parser.add_argument("--victim-contract", help="Override victim target address")
    parser.add_argument("--prefill-normal", type=non_negative_int, default=100, help="Number of warm-up transactions")
    parser.add_argument("--prefill-marker", default="0x00000000", help="Calldata prefix for warm-up transactions")
    parser.add_argument("--prefill-gas", type=positive_int, default=60000, help="Gas limit per warm-up transaction")
    parser.add_argument("--skip-prefill", action="store_true", help="Skip warm-up stage")
    parser.add_argument("--prefill-only", action="store_true", help="Run only warm-up stage and exit")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between consecutive sends")
    parser.add_argument("--output", help="Ground-truth JSONL output path")
    parser.add_argument("--pipe", help="Named pipe path for realtime streaming")
    parser.add_argument("--dry-run", action="store_true", help="Do not broadcast transactions")
    parser.add_argument("--chain-id", type=positive_int, help="Override detected chain id")
    parser.add_argument("--passphrase", help="Passphrase for ATTACKER_KEYSTORE")
    parser.add_argument("--receipt-timeout", type=positive_int, default=120, help="Seconds to wait for deployment receipts")
    parser.add_argument("--balance-timeout", type=positive_int, default=120, help="Seconds to wait for funding balances")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    providers, detected_chain_id = connect_rpcs(args.rpc)
    chain_id = args.chain_id or detected_chain_id

    master = load_master(args)
    print(f"[MASTER] loaded {master.address}")

    if args.victim_gas_price == 0:
        args.victim_gas_price = providers[0].eth.gas_price
        print(f"[GAS] victim gas price set to node suggestion {args.victim_gas_price} wei")

    required_balance = args.fund_amount * max(args.accounts - 1, 0) + 10**15
    ensure_balance(providers[0], master.address, required_balance)

    total_accounts = max(args.accounts, 2)
    children = generate_children(total_accounts - 1)
    accounts: List[ManagedAccount] = [master] + children

    ground_truth_path = Path(args.output) if args.output else None
    pipe_path = Path(args.pipe) if args.pipe else None
    channels = OutputChannels(ground_truth_path, pipe_path)

    try:
        fund_children(providers, master, children, chain_id, args)
        stream_prefill(providers, accounts, args, channels, chain_id)
        if args.prefill_only:
            return
        helper_contracts = deploy_helpers(providers, master, chain_id, args)
        run_pairs(providers, accounts, helper_contracts, args, channels, chain_id)
        print(f"[DONE] emitted {args.count} victim/runner pair(s)")
    finally:
        channels.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        sys.exit(130)
