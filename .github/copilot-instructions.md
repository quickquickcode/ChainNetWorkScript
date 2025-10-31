# Copilot Instructions

## Project Overview
- Goal: scripts under `ddos/` orchestrate Ethereum DDoS/malicious-transaction experiments to populate metrics described in `doc/参考.md`.
- Runtime environment documented in `环境.md`; baseline is Python 3.12 with `web3`, `eth-account`, and networking tools (`tcpdump`, `iptables`).
- Operational runbooks and expected manual steps live in `现有实现/命令.md`; treat missing scripts there as external dependencies, not repository bugs.

## Key Components
- `ddos/background_traffic_sender.py`: CLI that rotates unlocked accounts to emit legitimate transfers; expects IPC access (`--ipc`) and enforces non-zero positive integers via `positive_int` helper.
- `ddos/ddos_attack_sender.py`: attack injector supporting IPC or HTTP RPC; can decrypt a keystore supplied through `ATTACKER_KEYSTORE` and always prints `export ATTACKER_ACCOUNTS=...` for downstream monitoring.
- `ddos/ddos_monitor.py`: central monitor aggregating `txpool.content()` from local IPC and optional remote probes (`--legit-rpc`, `--attack-rpc`, `--supplement-rpc`); tracks nonce coverage per address to compute LTR/MTR in cumulative and sliding-window modes.
- Metric formulas, terminology, and acceptance criteria are mirrored from the Chinese spec in `ddos/ddos评估.md` and `doc/参考.md`; keep console strings in Chinese when updating the monitor output.

## Workflow Expectations
- Typical sequence: start background sender ➜ start attack sender (capture and export attacker accounts) ➜ export `ATTACKER_ACCOUNTS` on monitoring node ➜ launch `ddos_monitor.py` with consistent window/poll settings ➜ optionally stream metrics to JSONL via `--output`.
- `ddos_monitor.py` assumes attacker addresses come from `ATTACKER_ACCOUNTS`; when unset it treats every address as legitimate and prints a warning.
- The monitor’s fallback logic replaces missing denominators with observed totals; preserve this to avoid zero-division crashes in air-gapped tests.
- When adding new scripts, follow existing pattern: `argparse`-driven CLI, `Web3` provider selection, explicit account unlock flow with legacy fallback, and per-transaction logging of nonce/hash.

## Developer Notes
- Use IPC paths rooted at `/root/Work/PraviteChain`; commands in `环境.md` show how nodes are launched (geth 1.10.19) and which APIs must be enabled (`personal`, `txpool`, `miner`).
- Network troubleshooting steps (port checks, tcpdump filters) are spelled out in `环境.md`; reference them instead of inventing new diagnostics.
- No automated tests; manual validation relies on live nodes plus the JSONL snapshots from the monitor.
- Keep files ASCII by default; existing Chinese prose is acceptable in user-facing strings and docs but avoid introducing other encodings.
