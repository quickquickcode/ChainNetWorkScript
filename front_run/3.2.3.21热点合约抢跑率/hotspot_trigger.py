#!/usr/bin/env python3
"""Lightweight trigger for hotspot metric emitting truth over pipe/JSONL."""

from __future__ import annotations

import argparse
import errno
import hashlib
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

PIPE_SCHEMA_TX = "fr-hotspot-tx-v1"
PIPE_SCHEMA_META = "fr-hotspot-metadata-v1"
GROUND_TRUTH_SCHEMA = "fr-hotspot-event-v1"
DEFAULT_MARKER = "0xfeedface"


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

    def write_truth(self, payload: Dict[str, object]) -> None:
        line = json.dumps(payload, ensure_ascii=True)
        if self._table_fp:
            self._table_fp.write(line + "\n")
            self._table_fp.flush()
        else:
            print(line)

    def write_pipe(self, payload: Dict[str, object]) -> None:
        if not self._pipe_fp:
            return
        line = json.dumps(payload, ensure_ascii=True)
        try:
            self._pipe_fp.write(line + "\n")
            self._pipe_fp.flush()
        except BrokenPipeError:
            print("[PIPE] consumer disconnected; stop streaming", file=sys.stderr)
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit hotspot front-running ground truth")
    parser.add_argument("--rpc", action="append", required=True, help="HTTP RPC endpoint; repeatable")
    parser.add_argument("--count", type=positive_int, default=60, help="Number of victim/runner pairs")
    parser.add_argument("--marker", default=DEFAULT_MARKER, help="Marker prefix for calldata")
    parser.add_argument("--runner-premium", type=parse_wei, default="30gwei", help="Runner gas price premium")
    parser.add_argument("--victim-gas-price", type=parse_wei, default="0", help="Baseline victim gas price (0 => node suggest)")
    parser.add_argument("--victim-gas", type=positive_int, default=120000, help="Gas limit for victim tx")
    parser.add_argument("--runner-gas", type=positive_int, default=120000, help="Gas limit for runner tx")
    parser.add_argument("--transfer-amount", type=parse_wei, default="0", help="ETH value per tx")
    parser.add_argument("--accounts", type=positive_int, default=3, help="Total accounts including master")
    parser.add_argument("--fund-amount", type=parse_wei, default="0.05eth", help="Funding amount per child account")
    parser.add_argument("--fund-gas", type=positive_int, default=21000, help="Gas limit for funding transfers")
    parser.add_argument("--target", action="append", help="External contract address; repeatable")
    parser.add_argument("--hot-contract", action="append", help="Explicit hot contract address; repeatable")
    parser.add_argument("--hot-share", type=float, default=0.5, help="Fraction of pairs targeting hot contracts (0-1)")
    parser.add_argument("--interval", type=float, default=0.1, help="Delay between pairs (seconds)")
    parser.add_argument("--pipe", type=Path, help="Named pipe for realtime streaming")
    parser.add_argument("--output", type=Path, help="Ground-truth JSONL output path")
    parser.add_argument("--dry-run", action="store_true", help="Do not broadcast transactions")
    parser.add_argument("--chain-id", type=positive_int, help="Override detected chain id")
    parser.add_argument("--passphrase", help="Passphrase for ATTACKER_KEYSTORE")
    parser.add_argument("--receipt-timeout", type=positive_int, default=120, help="Seconds to wait for tx receipts")
    parser.add_argument("--balance-timeout", type=positive_int, default=120, help="Seconds to wait for child balance")
    return parser.parse_args()


def cycle(items: Sequence[Web3]) -> Iterable[Web3]:
    while True:
        for item in items:
            yield item


def connect_rpcs(urls: Sequence[str]) -> Tuple[List[Web3], int]:
    providers: List[Web3] = []
    for url in urls:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            raise SystemExit(f"failed to connect to RPC: {url}")
        providers.append(w3)
    chain_id = providers[0].eth.chain_id
    for w3 in providers[1:]:
        if w3.eth.chain_id != chain_id:
            raise SystemExit("all RPC endpoints must share the same chain")
    return providers, chain_id


def load_master(args: argparse.Namespace) -> ManagedAccount:
    raw = os.getenv("ATTACKER_KEYSTORE")
    if not raw:
        raise SystemExit("ATTACKER_KEYSTORE not set")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:  # noqa: B904
        raise SystemExit(f"failed to parse ATTACKER_KEYSTORE: {exc}") from exc
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
    children: List[ManagedAccount] = []
    for idx in range(quantity):
        acct = Account.create()
        children.append(ManagedAccount(label=f"child-{idx+1}", signer=acct))
    return children


def ensure_balance(provider: Web3, address: str, minimum: int) -> None:
    balance = provider.eth.get_balance(address)
    if balance < minimum:
        raise SystemExit(f"master balance {balance} wei insufficient (< {minimum} wei)")


def send_signed(provider: Web3, sender: ManagedAccount, tx: TxParams, dry_run: bool) -> str:
    if dry_run:
        digest = hashlib.sha1(repr(tx).encode("ascii")).hexdigest()
        return "0xDRY" + digest[:32]
    signed = sender.signer.sign_transaction(tx)
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raise RuntimeError("signed tx missing raw bytes")
    tx_hash = provider.eth.send_raw_transaction(raw_tx)
    return Web3.to_hex(tx_hash)


def fund_children(
    provider: Web3,
    master: ManagedAccount,
    children: Sequence[ManagedAccount],
    chain_id: int,
    args: argparse.Namespace,
) -> None:
    if not children or args.fund_amount == 0:
        return
    for child in children:
        nonce = master.next_nonce(provider)
        tx: TxParams = {
            "chainId": chain_id,
            "nonce": nonce,
            "to": child.address,
            "value": args.fund_amount,
            "gas": args.fund_gas,
            "gasPrice": max(args.victim_gas_price, 1),
        }
        tx_hash = send_signed(provider, master, tx, args.dry_run)
        print(f"[FUND] child={child.address} hash={tx_hash}")
        if not args.dry_run:
            provider.eth.wait_for_transaction_receipt(tx_hash, timeout=args.receipt_timeout)
            deadline = time.time() + args.balance_timeout
            while time.time() < deadline:
                if provider.eth.get_balance(child.address) >= args.fund_amount:
                    break
                time.sleep(2)
            else:
                raise SystemExit(f"timed out waiting for {child.address} balance")
        if args.interval > 0:
            time.sleep(args.interval)


def normalize_addresses(addresses: Iterable[str]) -> List[str]:
    result: List[str] = []
    for addr in addresses:
        try:
            result.append(Web3.to_checksum_address(addr))
        except Exception:  # noqa: BLE001
            print(f"[WARN] skip invalid address {addr}")
    return result


def build_targets(args: argparse.Namespace, deployed: List[str]) -> Tuple[List[str], List[str]]:
    targets = normalize_addresses(args.target or [])
    for addr in deployed:
        if addr not in targets:
            targets.append(addr)
    if not targets:
        raise SystemExit("no target contracts available; deploy or specify --target")
    hot_candidates = normalize_addresses(args.hot_contract or [])
    if not hot_candidates:
        hot_candidates = targets[:1]
    for addr in hot_candidates:
        if addr not in targets:
            targets.append(addr)
    return targets, hot_candidates


def build_plan(count: int, targets: List[str], hot_targets: List[str], hot_share: float) -> List[str]:
    total = max(count, 0)
    hot_share = max(0.0, min(hot_share, 1.0))
    if not targets:
        raise SystemExit("empty target list")
    hot_targets = hot_targets or targets
    hot_lower = {addr.lower() for addr in hot_targets}
    cold = [addr for addr in targets if addr.lower() not in hot_lower]
    hot_cycle = cycle(hot_targets)
    cold_cycle = cycle(cold or targets)
    hot_quota = int(round(total * hot_share))
    plan: List[str] = []
    for _ in range(hot_quota):
        plan.append(next(hot_cycle))
    for _ in range(total - hot_quota):
        plan.append(next(cold_cycle))
    return plan


def marker_payload(marker: bytes, role_tag: int, pair_id: int) -> bytes:
    return marker + role_tag.to_bytes(1, "big") + pair_id.to_bytes(4, "big")


def run_pairs(
    providers: Sequence[Web3],
    accounts: Sequence[ManagedAccount],
    targets: List[str],
    hot_targets: List[str],
    args: argparse.Namespace,
    channels: OutputChannels,
    chain_id: int,
) -> None:
    marker_bytes = parse_marker(args.marker)
    rotation = cycle(providers)
    plan = build_plan(args.count, targets, hot_targets, args.hot_share)

    def choose_accounts(index: int) -> Tuple[ManagedAccount, ManagedAccount]:
        victim = accounts[index % len(accounts)]
        runner = accounts[(index + 1) % len(accounts)]
        if victim.address == runner.address:
            runner = accounts[(index + 2) % len(accounts)]
        return victim, runner

    for idx, target in enumerate(plan, start=1):
        victim_acct, runner_acct = choose_accounts(idx - 1)
        provider = next(rotation)
        victim_nonce = victim_acct.next_nonce(provider)
        runner_nonce = runner_acct.next_nonce(provider)
        victim_payload = marker_payload(marker_bytes, 1, idx)
        runner_payload = marker_payload(marker_bytes, 2, idx)

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

        victim_hash = send_signed(provider, victim_acct, victim_tx, args.dry_run)
        runner_hash = send_signed(provider, runner_acct, runner_tx, args.dry_run)
        timestamp = time.time()
        is_hot = target.lower() in {addr.lower() for addr in hot_targets}
        event_id = hashlib.sha1((victim_hash + runner_hash).encode("ascii")).hexdigest()[:16]

        channels.write_truth(
            {
                "schema": GROUND_TRUTH_SCHEMA,
                "pair_id": idx,
                "event_id": event_id,
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
                "is_hot_truth": is_hot,
                "timestamp": timestamp,
            }
        )

        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA_TX,
                "pair_id": idx,
                "role": "victim",
                "tx_hash": victim_hash,
                "from": victim_acct.address,
                "to": target,
                "gas": args.victim_gas,
                "gas_price": args.victim_gas_price,
                "is_hot_truth": is_hot,
                "timestamp": timestamp,
            }
        )
        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA_TX,
                "pair_id": idx,
                "role": "runner",
                "tx_hash": runner_hash,
                "from": runner_acct.address,
                "to": target,
                "gas": args.runner_gas,
                "gas_price": args.victim_gas_price + args.runner_premium,
                "is_hot_truth": is_hot,
                "timestamp": timestamp,
            }
        )

        print(
            f"[PAIR] id={idx}/{args.count} target={target} hot={is_hot} victim={victim_hash} runner={runner_hash}"
        )
        if idx < args.count and args.interval > 0:
            time.sleep(args.interval)


def main() -> None:
    args = parse_args()
    args.hot_share = max(0.0, min(args.hot_share, 1.0))

    providers, detected_chain_id = connect_rpcs(args.rpc)
    chain_id = args.chain_id or detected_chain_id
    base_provider = providers[0]

    master = load_master(args)
    print(f"[MASTER] loaded {master.address}")

    if args.victim_gas_price == 0:
        args.victim_gas_price = base_provider.eth.gas_price
        print(f"[GAS] victim gas price set to {args.victim_gas_price}")

    total_accounts = max(args.accounts, 2)
    children = generate_children(total_accounts - 1)
    accounts: List[ManagedAccount] = [master] + children

    required_balance = args.fund_amount * max(total_accounts - 1, 0) + 10**15
    ensure_balance(base_provider, master.address, required_balance)

    ground_truth_path = Path(args.output) if args.output else None
    pipe_path = Path(args.pipe) if args.pipe else None
    channels = OutputChannels(ground_truth_path, pipe_path)

    try:
        fund_children(base_provider, master, children, chain_id, args)
        helper_contracts: List[str] = []
        targets, hot_targets = build_targets(args, helper_contracts)
        channels.write_pipe(
            {
                "schema": PIPE_SCHEMA_META,
                "hot_contracts": [addr.lower() for addr in hot_targets],
                "targets": targets,
                "timestamp": time.time(),
            }
        )
        run_pairs(providers, accounts, targets, hot_targets, args, channels, chain_id)
        print(f"[DONE] emitted {args.count} pairs")
    finally:
        channels.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)