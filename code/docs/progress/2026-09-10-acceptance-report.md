# 2026-09-10 全链路验收报告（T20/T21/T22）

范围：基于本地 compose 栈（PostgreSQL/Redis/API/Dispatcher/analysis-worker/Sandbox Runner/Web 全部为最新分支镜像）的端到端验收。分支 `feat/sprint-final-closeout`。

## 1. 链路与证据

| 环节 | 结果 | 证据 |
|---|---|---|
| API Proof Job 投递 | `POST /api/findings/finding:e2e/proof` 返回 202，Job 入库 | jobs 表 `job:proof:…` |
| Dispatcher → Worker | 事件经 Outbox 发布到 Redis Streams，Worker 认领执行 | worker 日志 `httpx POST http://sandbox-runner:8080/v1/sandbox/runs 200` |
| Sandbox Runner 隔离执行 | digest 钉住镜像、禁网、非 root、只读输入、资源限制下运行无害脚本 | `{"status":"succeeded","exit_code":0}`，stdout/result.json 写回 CAS |
| Poc 落库 | `completed / exploitable`，`findings.poc_ids` 更新 | pocs 表 |
| 任务聚合 | task:e2e `reviewing → verifying → completed`，事件带结构化载荷 | task_events / 事件时间线 |
| 报告 Markdown/SARIF/PDF | 三个报告 Job `succeeded`，派生工件登记 CAS | artifacts `artifact:report:task:e2e:{markdown,sarif,pdf}` |
| API 下载 | Markdown（Proof runs: 1）、SARIF 2.1.0、PDF `%PDF` 9.3KB | `GET /api/artifacts/{id}/content` 200 |
| Web 浏览器链路 | 登录 → 项目 → 任务页 → Finding 详情（位置/POC 1 个/复现记录 EXPLOITABLE/Proof·Exploit 按钮）→ 下载报告点击触发下载 | 浏览器自动化截图与 DOM 快照 |

## 2. 本轮修复的缺陷

1. `apps/analysis-worker` 包缺 `vulnweaver-proof` 依赖声明，新镜像无法启动。
2. runner 镜像缺 `docker` CLI（Debian 13 将 CLI 拆为 `docker-cli` 包）。
3. `DockerCliRuntime` 未传 `--entrypoint`，与镜像自带 ENTRYPOINT 重复导致参数错误。
4. worker 镜像缺 WeasyPrint 所需 pango/harfbuzz/字体，PDF Job 失败。
5. 报告渲染未纳入 Poc 数据，Proof runs 恒为 0。

## 3. 已知限制与遗留

- Q-008：越阶段 Job 触发任务聚合非法迁移会形成毒消息重试（正常管线不触发）。
- 容器内单条 Redis 流消息畸形会导致 worker 崩溃重启，且崩溃时消费者组偏移前移可能跳过消息（本次以 `XGROUP SETID 0` 恢复）；流消息批解码的容错性待改进。
- T16/T18/T19 真实工具（Ghidra、DIE/UPX、AFL++/CASR）镜像动态验收未执行；P2 四语言真实 REVIEW 模型端到端待模型接入。

## 4. 测试

Dev Container 全量门禁：`pnpm run check` 通过，329 passed、1 skipped（Docker runtime opt-in），覆盖率 81%+（门槛 80%），Ruff/Pyright/svelte-check 0 错误。新增 `tests/proof/test_http_replay.py`（4 个 live Runner 用例）与 reporting 回归测试。
