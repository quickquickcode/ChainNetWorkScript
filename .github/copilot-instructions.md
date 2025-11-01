# Copilot Instructions

## Overview
- Project measures Ethereum node resilience (DDoS forwarding, malicious visibility) via Python CLIs; metric formulas live in `doc/参考.md`, `ddos/ddos评估.md`, and operational notes in `ddos/全新10.md`.
- Scripts expect Geth 1.10.19 nodes under `/root/Work/PraviteChain`; setup, package baselines, and network diagnostics are documented in `环境.md`.

## Components & Patterns
- `ddos/background_traffic_sender.py` rotates local accounts over IPC, enforces positive integers, unlocks upfront via personal API fallback, and logs `[BACKGROUND]` lines per send.
- `ddos/ddos_attack_sender.py` drives attack bursts through IPC/HTTP, supports `ATTACKER_KEYSTORE` raw signing, prints `export ATTACKER_ACCOUNTS=...` (with a brief pause) before broadcasting, and defaults gas price to `max(gas_price/20, 1)`.
- `ddos/ddos_monitor.py` polls `txpool.content()` locally plus optional probes (`--legit-rpc`, `--attack-rpc`, `--supplement-rpc`) to derive LTR/MTR; it keys off `ATTACKER_ACCOUNTS`, maintains sliding windows via `--window`, applies `--reject-delay`, and falls back to numerator totals to avoid zero-division. Preserve existing中文输出.
- `malicious/malicious_trigger.py` mirrors the attack sender with tagged payloads (`--marker`), rejection modes (`dup_nonce` / `insufficient_funds` / `low_gas_limit`), optional JSONL logging, and the same keystore/unlock conventions.
- `malicious/3.2.3.17恶意交易可识别性/detect_visibility.py` inspects txpool pending/queued across multiple providers, tracks per-transaction state transitions, and writes JSONL deltas consumed by `summarize_visibility.py` for VR/FR reporting.

## Workflows
- DDoS measurement: run `background_traffic_sender.py` ➜ run `ddos_attack_sender.py` (capture its `ATTACKER_ACCOUNTS` export) ➜ export the variable on the monitoring host ➜ launch `ddos_monitor.py` with aligned `--window`/`--poll` and optional `--output` JSONL.
- Malicious visibility: execute `malicious_trigger.py` to emit tagged traffic, then `detect_visibility.py` with the same marker and chosen IPC/RPC endpoints; optionally run `summarize_visibility.py visibility.jsonl` to aggregate VR/FR metrics.
- Remote keystore workflow: keep JSON single-line in `ATTACKER_KEYSTORE`, supply passphrase via `--passphrase` (or prompt), and ensure geth exposes `personal` namespace as shown in `环境.md`.

## Conventions & Ops
- All CLIs use `argparse`, helper validators (`positive_int`, `non_negative_int`), and per-transaction hash/nonce logging; mirror this structure for new tooling.
- Web3 providers default to `IPCProvider(..., timeout=30)` or `HTTPProvider(..., request_kwargs={"timeout": 30})`; only adjust timeouts when following `环境.md` guidance.
- Operational runbooks live in `现有实现/命令.md`; referenced scripts missing from the repo are external dependencies rather than defects.
- There are no automated tests; validate changes against live nodes and JSONL snapshots, and keep files ASCII except where existing Chinese user strings appear.
