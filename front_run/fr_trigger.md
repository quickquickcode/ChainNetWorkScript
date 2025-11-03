# fr_trigger.py 使用说明




统一触发器 `fr_trigger.py` 负责在指定 RPC 节点上生成可控的抢跑事件，同时产出真值数据供各项指标复用。脚本实现“预热正常交易 + victim/runner 组合”两阶段流程，并在最新版本中支持：
- 从环境变量 `ATTACKER_KEYSTORE`（示例已在 README 给出）解锁金主账户；
- 自动生成多个子账户、批量转账注资；
- 在同一 RPC 上部署若干简单合约（内置字节码）；
- 将每笔预热、受害、抢跑交易实时写入命名管道（FIFO），供监测脚本秒级消费，同时继续落盘 JSONL 真值集。

## 功能概览
- **预热阶段**：先发送指定数量的普通交易（默认 100 笔），使用低 gas price 和固定 marker（默认 `0x00000000`），确保账户 nonce 与 mempool 状态稳定，避免后续抢跑交易立即被打包。支持 `--prefill-only` 仅执行此阶段；若传入 `--skip-prefill` 则跳过。
**抢跑阶段**：按照 `--count` 生成 victim 与 runner 配对交易。Victim 先发送，runner 以更高 gas 单价和附加 payload 插队。若指定 `--accounts N`，脚本会创建 `N-1` 个子账户（连同金主共 `N` 个发送者）并自动注资；若指定 `--contracts M`，会部署 `M` 份内置合约并循环作为 `to` 地址。
- **事件记录**：双轨输出：
  - Ground truth JSONL 将每对交易聚合为一条（`fr-trigger-event-v1`）；
  - 命名管道（可选）逐笔推送交易（`fr-trigger-tx-v1`），字段含 `pair_id`、`role`（victim/runner/prefill）、`tx_hash`、`from`、`to`、`nonce`、`gas_price`、`input_marker` 等。

## 常用参数
| 参数 | 说明 |
| ---- | ---- |
| `--rpc` | 目标 HTTP RPC 地址，可多次指定实现轮询发送。
| 参数 | 说明 |
| ---- | ---- |
| `--count` | 需要生成的抢跑事件数，默认 100。
| `--marker` | victim/runner `data` 前缀，默认 `0xfeedface`。
| `--runner-premium` | runner 相对 victim 的 gas 单价溢价，支持 `N`/`Nwei`/`Ngwei`/`Neth`。
| `--victim-gas-price` | victim 基础 gas 单价；默认为节点建议值。
| `--victim-gas` / `--runner-gas` | victim/runner 交易 gas 上限，默认各 120000。
| `--transfer-amount` | 每笔交易附带的 wei 数量，默认 0。
| `--prefill-normal` / `--prefill-marker` / `--prefill-gas` | 预热交易数量、payload 前缀与 gas 上限。
| `--skip-prefill` / `--prefill-only` | 跳过预热或仅执行预热阶段。
| `--accounts` | 总发送账户数（含金主），默认 2，至少保证 victim 与 runner 不同账户。
| `--fund-amount` | 每个新子账户的注资额度，默认 0.05 ETH。
| `--contracts` | 需部署的辅助合约数量；部署成功后地址写入日志。
| `--pipe` | 命名管道路径。存在时按行推送 `fr-trigger-tx-v1` 记录。
| `--output` | Ground truth JSONL 路径；未提供时打印至终端。
| `--interval` | 每批交易之间的休眠秒数，默认 0.05。
| `--dry-run` | 计划模式：不广播交易，依旧生成虚拟哈希、ground truth 与命名管道输出。
| 其他 | `--passphrase`、`--receipt-timeout`、`--balance-timeout`、`--chain-id` 等用于 keystore 与等待控制。

## 使用示例
### 1. 仅预热正常交易
```sh
python3 fr_trigger.py \
  --rpc http://202.118.14.15:8545 \
  --prefill-normal 100 \
  --prefill-marker 0x00000000 \
  --prefill-only
```
脚本会输出预热交易的哈希列表，并在终端提示“prefill 完成”。

### 2. 一键执行预热 + 抢跑 + 资金注入 + 合约部署
```sh
python3 fr_trigger.py \
  --rpc http://202.118.14.15:8545 \
  --count 200 \
  --marker 0xfeedface \
  --runner-premium 30gwei \
  --prefill-normal 100 \
  --accounts 5 \
  --contracts 3 \
  --output front_run/events_ground_truth.jsonl
```
金主账户会向 5 个子账户转入资金，在同一 RPC 上部署 3 份示例合约，然后开始发送 victim/runner 对。所有事件会写入 `events_ground_truth.jsonl`，并通过 `/tmp/fr_events.pipe` 推送实时交易行。

### 3. 同时输出到 JSONL 与管道
```sh
mkfifo /tmp/fr_events.pipe  # 监测脚本先阻塞打开
python3 fr_trigger.py \
  --rpc http://202.118.14.15:8545 \
  --count 50 \
  --marker 0xfeedface \
  --pipe /tmp/fr_events.pipe \
  --output front_run/events_ground_truth.jsonl
```
务必在触发脚本启动前，先让监测脚本打开并读取 `/tmp/fr_events.pipe`（可先 `touch` ground-truth 路径避免缺失）。触发器仅在检测脚本就位后再启动。若消费者断开，触发器会检测到 `BrokenPipe` 并停止写入。

## 输出文件格式
每行 JSON 包含以下键：
```json
{
  "event_id": "18d4f...",
  "victim_hash": "0xabc...",
  "runner_hash": "0xdef...",
  "victim_nonce": 123,
  "runner_nonce": 124,
  "target_address": "0x9ab...",
  "victim_gas_price": 25000000000,
  "runner_gas_price": 28000000000,
  "marker": "0xfeedface",
  "pattern": "single",
  "timestamp": 1730611200
}
```
当前仅支持单腿抢跑，`pattern` 字段恒为 `single`；`target_address` 用于热点合约指标的匹配。

## 实时事件流格式
命名管道输出遵循 `fr-trigger-tx-v1`，示例：
```json
{"schema":"fr-trigger-tx-v1","pair_id":42,"role":"victim","tx_hash":"0xabc...","from":"0x123...","to":"0x9ab...","nonce":15,"gas":120000,"gas_price":25000000000,"input_marker":"0xfeedface","timestamp":1730611200.123}
{"schema":"fr-trigger-tx-v1","pair_id":42,"role":"runner","tx_hash":"0xdef...","from":"0x456...","to":"0x9ab...","nonce":28,"gas":120000,"gas_price":32000000000,"input_marker":"0xfeedface","timestamp":1730611200.456}
```
不同 `role` 通过 `input_marker` 与 `pair_id` 对齐；预热阶段会输出 `role=prefill`，并以 `prefill_id` 标识顺序。监测脚本可用以下流程消费：
- 监测端先 `open(pipe_path, "r")` 并进入逐行解析循环；
- 根据 `pair_id` 聚合 victim/runner；
- 对于 JSON 解析失败或 schema 不匹配的行，直接丢弃或单独记录。

## 运行注意
- 脚本必须从环境变量 `ATTACKER_KEYSTORE` 读取金主 keystore（示例：`export ATTACKER_KEYSTORE='{"address":"5631d0d3..."}'`），解密失败会立即退出。
- 若指定 `--accounts`，脚本会生成子账户并使用金主账户转账，请确认金主余额充足且 RPC 支持连续发送多笔转账。
- 预热阶段默认只在第一次运行时执行；如需再次预热，可单独运行 `--prefill-only`。
- 为避免 nonce 冲突，脚本提供 `--dry-run` 预览交易计划；正式执行前建议确认 pending 状态。
- 若 RPC 连接不稳定，可重复指定 `--rpc` 参数以提供备用节点，脚本会轮询发送。
- 命名管道仅在类 Unix 平台可用；Windows 调试场景请使用 WSL 或关闭 `--pipe`。
- 所有日志输出均为 ASCII，时间戳以本地时间为准。

## 伪代码
```
参数 = 解析命令行()
主账户地址, 主账户私钥 = 从环境变量 ATTACKER_KEYSTORE 解密()
RPC连接池 = 建立到所有 --rpc 节点的连接()

如果 参数.合约数量 > 0:
    重复 参数.合约数量 次:
        构造部署交易(SIMPLE_CONTRACT_BYTECODE)
        使用主账户签名并发送
        等待回执并记录合约地址

子账户列表 = [主账户地址]
如果 参数.子账户数量 > 1:
    子账户列表 = 生成 参数.子账户数量 个临时账户()
    对于每个子账户:
        构造主账户 -> 子账户 的转账交易
        使用主账户签名并发送
    等待子账户余额到位

如果 没有指定 --skip-prefill:
    执行预热交易(子账户列表, 数量=参数.prefill_normal, 标记=参数.prefill_marker)
    如果 指定 --prefill-only:
        正常退出

循环 参数.count 次:
    选择当前发送账户 = 从子账户列表中轮询()
    构造 victim 交易(带 marker, 可选择已部署合约)
    构造 runner 交易(提升 gas 单价)
    victim_hash = 使用对应私钥签名并发送 victim
    runner_hash = 使用另一私钥签名并发送 runner
    将事件写入 ground truth(JSONL)

输出统计摘要()
```
