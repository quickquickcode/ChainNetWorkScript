# Front-running 指标与实验说明

## 目录概览
- 3.2.3.20 抢跑成功率
- 3.2.3.21 热点合约抢跑率
- 3.2.3.22 抢跑平均 Gas 溢价
- 3.2.3.23 抢跑交易识别率

所有指标共用统一触发器 `fr_trigger.py` 生成可控的抢跑事件（victim + runner），并使用多个独立监测脚本进行统计。触发器会将聚合的真值写入 JSONL，同时可通过命名管道实时推送每笔交易，便于监测脚本秒级获取 ground truth。为了避免触发器刚启动时暴露异常特征，本目录在正式发起抢跑事件前，会先发送一组正常交易用于“暖场” mempool。

## 统一实验流程

1. **预热正常流量（可独立/合并执行）**
   - 默认先发送 100 笔普通交易，使网络对发起账户产生顺序 nonce，减少抢跑交易立即被打包的几率：
     ```sh
     python3 fr_trigger.py \
       --rpc http://202.118.14.15:8545 \
       --prefill-normal 100 \
       --prefill-marker 0x00000000
     ```
     若只想预热可加 `--prefill-only`；若要跳过预热可在抢跑阶段传 `--skip-prefill`。

2. **执行抢跑触发器**
   - 使用 `fr_trigger.py` 生成 victim/runner 对，并在必要时自动部署示例合约、创建多账户及资金注入：
     ```sh
     python3 fr_trigger.py \
       --rpc http://202.118.14.15:8545 \
       --count 200 \
       --marker 0xfeedface \
       --runner-premium 30gwei \
       --contracts 3 \
       --accounts 5 \
       --pipe /tmp/fr_events.pipe \
       --output front_run/events_ground_truth.jsonl
     ```
     - 监测脚本需在触发器启动前先 `mkfifo /tmp/fr_events.pipe` 并打开读取，以免触发器阻塞。
     - `--contracts` 指定需要部署的测试合约数量（脚本内置自签合约字节码，部署在同一 RPC 上）。
     - `--accounts` 控制参与发送的账户总数（包含金主账号）；子账户由环境变量 `ATTACKER_KEYSTORE` 对应的金主注资。
     - 若希望一次性执行“预热 + 抢跑”，省略 `--prefill-only` 与 `--skip-prefill` 即可。

3. **按指标启动监测脚本**
   - 根据各指标文档运行对应脚本，例如：
     - `fr_success_monitor.py` 输出成功率；
     - `fr_hotspot_monitor.py` 判断热点合约；
     - `fr_premium_monitor.py` 计算 Gas 溢价；
     - `fr_detection_monitor.py` 与 `fr_detection_coverage.py` 评估识别率。

4. **汇总与追溯**
  - 每个脚本都支持 `--output front_run/*.jsonl`，在终端打印指标同时持久化原始事件。
  - 建议同时保存管道消费日志，以便复现实时对齐过程；Ground truth 与各监测结果文件建议一并归档，便于日后复盘。

## 注意事项
- 触发器与监测脚本默认使用 HTTP RPC；如需使用 IPC，请另行在文档中扩展说明。
- 若前置 100 笔交易长时间未全部打包，可适当提高 gas price 或放宽间隔。
- 统一 marker（如 `0xfeedface`）仅用于事件关联；正式部署时可改为其它前缀，保证与线上流量区分。
- 命名管道仅适用于类 Unix 环境；在 Windows 调试可关闭 `--pipe` 或通过 WSL 运行触发器。
- 所有脚本遵循 ASCII 输出规范，JSONL 文件推荐使用 `utf-8` 编码。
