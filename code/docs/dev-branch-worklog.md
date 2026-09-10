# dev 分支工作记录

本文件记录暂不进入 `main` 的额外优化线（`dev/*` 分支），与 `DEVELOPMENT_STATUS.md`（main 集成状态）分离。每条线一个章节，合并入 `main` 后对应章节归档至 `code/docs/progress/` 并在本文件删除。

分支命名说明：项目惯例为 `feat/*`；`dev/*` 前缀是项目负责人 2026-09-10 明确要求的额外优化线标识，语义为"已设计、在推进、合并时机由负责人决定"。

---

## 线 1：dev/settings-deployment-ui —— 部署配置迁入前端设置页

**Worktree**：主仓（`课设 - codex`）｜**负责人**：ZCode｜**状态**：进行中

### 目标

用户只需 `docker compose up` 拉起镜像，其余部署配置（工具镜像摘要登记、沙箱资源预算、fuzz 预算、超时、angr 开关）在前端设置页完成。设置页分两级：核心设置一级常显，沙箱预算类折叠进二级"高级"区。

### 已确认决策（2026-09-10，负责人拍板）

1. **Runner 读数据库**：sandbox-runner 新增只读 `DATABASE_URL`（compose analysis-plane 网络已可达 postgres），从 `product_settings` 表读配置。
2. **worker 热生效**：每次领取任务前重读设置，按内容指纹（`updated_at` + values 哈希）变化才重建模型网关/工具规格，改配置不用重启。
3. **Runner 同步刷新**：每次执行沙箱请求前重读设置（单行 select），指纹变化才重建 ToolSpec/profile，避免与 worker 热生效不一致。
4. **优先级**：设置页 > 环境变量 > 代码默认/本地镜像自动解析；设置留空 = 保持自动发现行为。
5. **红线不变**：镜像登记是管理员显式动作，未登记镜像仍被拒绝；不做 Runner 侧自动拉镜像。

### 留在 .env 不迁移（引导类配置）

DATABASE_URL、REDIS_URL、SANDBOX_RUNNER_URL/TOKEN、worker consumer/并发/租约、存储根路径、DOCKER_HOST_SANDBOX_ROOT。前端只读展示 Runner 连接状态。

### 实施清单

- [x] API Schema（`schemas.py`）：`ProductSettingsBody`/`Response` 新增 `tool_image_digests`（3 个 sha256 可空）、`sandbox_budgets`（afl/proof/binary × cpu_millis/memory_bytes/disk_bytes/timeout_seconds）、`fuzz_budgets`（max_executions/max_duration_seconds/max_crashes）、`sandbox_runner_timeout_seconds`、`fuzz_runner_timeout_seconds`、`angr_enabled`；同步公共契约 `ProductSettings` 定义并 `generate_contracts.py` 重新生成。（59168f1）
- [x] 合并模块：`vulnweaver_domain.deployment_config.resolve_deployment_config(settings_values, environ)` 三级合并（设置页 > env > 代码默认），worker/Runner 共用。（83a4dc6）
- [x] Runner：`apps/sandbox-runner` 新增只读 `DATABASE_URL`（compose 注入，`SANDBOX_RUNNER_DATABASE_URL` 可覆盖），`SettingsReader` 指纹比较 + `ReconfigurableRunner` 重建 ToolSpec/profile；`create_sandbox_app` 支持 runner 工厂（async），每个请求经工厂解析当前 runner。数据库不可达时降级沿用上次配置。（d3a1777）
- [x] Worker：新增 `hot_reload.py`（`ReconfigurableAssembly` + `HotReloadExecutor`/`HotReloadSettlementHook`），`main.py` 装配改为 `_build_assembly(settings)`——模型执行器/proof/fuzz/binary/hooks/调度器全部按设置指纹重建，旧 model gateway 在重建后关闭；`ReliableWorker` 与 settlement hook 面向稳定 facade。（58daee5）
- [x] 前端（`App.svelte`）：一级=模型设置+工具镜像登记（sha256 校验、留空=自动发现）+ 执行能力状态徽标（二进制/Proof/模糊测试/模型）；二级折叠"高级：沙箱资源与预算"（三工具 × 4 资源项、fuzz 预算、双 Runner 超时、angr 开关）。保存提示改为"Worker 下一次任务时自动生效"。（f6f207b）
- [x] 测试：`test_deployment_config.py`（6 项合并语义）、`test_http.py` 新增 runner 工厂热切换、`test_hot_reload.py`（4 项：指纹不变不重建/变化重建+退休/DB 故障保持旧 assembly/facade 委派）、`test_api.py` 新增 digest 正常保存回显 + 格式与数值负向（真实 PostgreSQL 集成环境）。
- [x] 验证：Dev Container（`vulnweaver-dev-1`，PostgreSQL/Redis 集成环境）：全量 **447 passed、5 skipped、覆盖率门禁 ≥80% 通过**；ruff/pyright 全仓 0 错误；`generate_contracts.py --check` 无漂移；svelte-check 与 contracts tsc 0 错误。（358b8d4 收口）

### 进展日志

- 2026-09-10：分支建立（自 main `10a8936`）；当日曾直接在 review 档位上加字段的临时方案已回退（见线 2 说明），本线按完整方案重新实施。
- 2026-09-10：全链路实现完成并全量门禁通过（提交 59168f1→358b8d4）；等待 PR 评审。注意：`vulnweaver-dev-1` 容器 venv 手动装了 `asyncpg` 用于集成测试，该容器镜像不含此包属环境侧操作。

---

## 线 2：dev/model-gateway —— 模型网关现代化

**Worktree**：`E:\project\homework\vulnweaver-model-gateway`｜**负责人**：ZCode｜**状态**：设计已定，待实施

### 目标

把模型网关升级为现代化配置面：多协议、每档位独立端点、上下文窗口、思考模式。

### 已确认决策（2026-09-10，负责人拍板）

1. **粒度**：每档位（planning/audit/review/report）完全独立配置——各自 base_url、协议、API Key、模型名、上下文窗口、思考模式。
2. **协议**：OpenAI 兼容（现默认）+ Anthropic Messages（`/v1/messages`、`x-api-key` 头、system/messages 拆分）。
3. **思考模式**：分档位三选——关闭 / 开启（供应商默认预算）/ 自定义预算 token 数；OpenAI 协议映射 `reasoning_effort`，Anthropic 映射 `thinking.budget_tokens`。
4. **上下文窗口**：每档位可配上下文窗口大小（token），网关侧用于输入预算控制与截断保护。

### 现状要点（调研结论）

- 网关 `packages/model-gateway`：`ModelEndpoint` 仅 OpenAI `/chat/completions` + `response_format: json_object` 硬编码；`ModelTier` 四档位映射模型名共用单端点单 Key。
- 产品设置现仅 review 档位字段（`review_model_base_url/name/api_key/...`），worker 启动读一次；AUDIT/PLANNING 暂共用 review 配置。
- 产品设置落 `product_settings` 表单行 JSONB，扩展无需数据库迁移。

### 实施清单

- [x] 契约与 API：`ProductSettings` 新增 `model_tiers`（planning/audit/review/report 各自 protocol/base_url/model_name/context_window_tokens/thinking_mode/thinking_budget_tokens/timeout_seconds/max_attempts）、`tier_api_keys`（写 only，不回显，响应只含 `tier_api_keys_configured` 布尔表）、`clear_tier_api_keys`。成对校验与 thinking 预算下限（custom ≥1024）在 PUT 服务端校验。
- [x] 网关协议层：`ModelEndpoint` 增加 `protocol`/`context_window_tokens`/`thinking`（`ThinkingConfig` 三选）；新增 Anthropic Messages 适配（`/v1/messages` URL、x-api-key + anthropic-version 头、system 抽取、JSON 指令附加到末尾 user 轮、thinking 块跳过、usage 从 input/output_tokens 映射）。
- [x] 思考模式映射：OpenAI → `reasoning_effort`（预算 ≤4096 low / ≤16384 medium / 其余 high；default=medium）；Anthropic → `thinking.budget_tokens`；关闭不发字段。
- [x] 上下文窗口：`_check_context_budget` 以 4 字符/token 粗估输入，加输出预留超窗即结构化失败（不重试）；无 tokenizer 依赖的确定性守卫。
- [x] worker：`_model_executors` 按档位独立解析 endpoint（tier 配置 > 旧 review 字段回退——旧字段继续服务 REVIEW/AUDIT），未配置档位无路由、调用结构化失败；修复了此前 PLANNING 档无路由导致的关键逻辑确认必然降级问题。
- [x] 前端：设置页新增"分档位模型"折叠分组（协议下拉、端点、模型、独立 Key、上下文窗口、思考三选、超时/尝试覆写），档位状态徽标显示"协议 · 模型名"或"未配置（回退）"。
- [x] 测试：`test_protocols.py` 17 项（Anthropic wire 格式/鉴权/usage、thinking 预算到 payload、reasoning_effort 映射、非法模式/预算/窗口关系拒绝、上下文守卫、messages URL、协议白名单）；API `test_product_settings_tier_models_and_api_key_isolation`（保存回显、Key 不回显、跨请求保留、清除、预算下限 422、成对校验 422）。
- [x] 与线 1 的衔接：本线基于 `dev/settings-deployment-ui`（9fb4db0）快进合入后开发，天然包含部署字段；两线合并顺序已解决——先合 #45，本线 PR 只含增量提交。

### 进展日志

- 2026-09-10：worktree 建立（自 main `10a8936`）；三决策定型；曾误在主工作树做的临时改动已回退，未污染任何分支历史。
- 2026-09-10：按负责人指示改为基于 `dev/settings-deployment-ui` 开发（fast-forward 合入 9fb4db0）；全链路实现完成（980e53e→bca0dd9），为该 worktree 启动专用一次性 Dev 容器 `vulnweaver-mg-dev`（挂载本目录、接入 t30 PostgreSQL/Redis 网络）；静态门禁全绿、定向测试通过。
- 2026-09-10：全量门禁通过（PostgreSQL/Redis 集成环境）：**456 passed、5 skipped、覆盖率门禁 ≥80% 通过**；ruff/pyright 全仓 0 错误；契约 --check 无漂移；svelte-check 与 contracts tsc 0 错误。等待 PR 评审。
