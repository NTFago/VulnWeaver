# ADR-033：模型接入重构为供应商注册表与每智能体绑定

- 状态：已接受
- 日期：2026-09-30
- 相关：ADR-025（资源预算惰性簿记）、ADR-027（智能体驱动审计）、ADR-029（审计检查点续跑）

## 背景

旧的模型接入是"4 个固定档位（planning/audit/review/report）× 每档位一个端点+一个模型"的平面配置（`model_tiers` + `tier_api_keys`），外加一组成都早已存在的 legacy `review_model_*` 字段。它无法表达用户对模型接入的核心诉求：

1. **多个供应商并存**：同一部署要能同时登记 DeepSeek、智谱、Kimi、中转站等多个供应商，各自持有 Base URL、API 格式、API Key 与启停开关；一个档位一个端点的模型无法承载。
2. **供应商下挂模型列表**：一个供应商提供多个模型，每个模型有自己的上下文窗口、最大输出 token 与思考（reasoning）配置——这正是 cc-switch、dsh（DeepSeek Harness）与 ZCode 供应商设置页的共同形态（Base URL / API 格式 / API Key / 模型列表+元数据 / 启用开关 / 智能配置）。
3. **每个智能体独立选型**：规划、审计、复核、报告各自绑定一个"供应商+模型"组合，可另配备用模型，而不是档位间的隐式回退。
4. **长线作战不被人为截断**：审计 deadline 曾定在 2 小时（对真实世界样本已显吃紧，ADR-029 校准过一次），且调用方仍在把惰性的 `resource_budget.max_model_tokens` 透传为单次输出上限（harness 生成还硬编码 8192）。任何任务级 token 配额或过紧的墙钟都会直接削弱审计能力。

调研对齐（cc-switch、dsh）：两者都以"供应商（连接+密钥+协议）+ 模型列表（元数据）"组织接入，支持多协议（Anthropic Messages / OpenAI Chat Completions / OpenAI Responses），dsh 另有模型列表探测与每模型 compat 覆盖；本系统的网关因此补齐同构能力，但保持应用内库形态（ADR-025/《技术选型》的"不引入独立网关服务"决策不变——红线与信任边界不依赖独立进程）。

## 决策

### 1. 供应商注册表 + 智能体绑定（新主配置）

产品设置新增三段（`contracts.schema.json` 的 `ProductSettings`）：

- `model_providers[]`：`id`（小写 slug，创建后不变）、`name`、`base_url`、`api_format`（`openai-chat` / `anthropic-messages` / `openai-responses`）、`enabled` 开关、可选 `timeout_seconds` / `max_attempts`、`models[]`（`model_id`、`display_name`、`context_window_tokens`、`max_output_tokens`、`thinking_mode` / `thinking_budget_tokens`）。
- `agent_model_bindings`：四个角色各绑定 `{provider_id, model_id}`，可带 `fallback_*` 备用对。
- `provider_api_keys`：按 provider 的写only密钥，与既有 tier 密钥同一套"请求体可写、响应只回 configured 标志"的合并/清除语义；删除供应商时密钥一并修剪。

解析在 `packages/model-gateway/registry.py`：`ModelAccessConfig.from_settings()` 宽容地接受缺省段、严格拒绝坏形状（形状坏了 fail-fast，而不是静默丢弃配置）；`resolve_routes()` 把每个绑定解析为一条 `ModelRoute`，引用不存在/已停用的供应商或未登记的模型**在构建时报错**——API 在保存时已校验，运行期再遇到即说明存储被绕过修改，宁可让该智能体显式失败也不允许悄悄掉到别的模型。设置加载顺序：注册表有绑定 → 注册表；否则回落 `model_tiers`；再回落 legacy `review_model_*` 字段（两代旧配置继续可用，现有部署不受影响）。

### 2. 网关补齐三种线格式与每模型元数据

- `ModelEndpoint` 新增 `max_output_tokens`（0=供应商默认）：决定 Anthropic `max_tokens` 缺省与上下文裁剪的输出预留，**它只是"这个模型物理上能输出多少"的配置，从来不是任务配额**。
- 协议别名规范化（`openai-chat`→`openai`、`anthropic-messages`→`anthropic`），新增 **OpenAI Responses**（`/responses`：`instructions`/`input`/`text.format=json_object`/`reasoning.effort`；`status=incomplete` 视为不可重试的协议错误）。
- 单次 HTTP 请求超时上限 600s → **3600s**：长思考模型单次调用常超十分钟；上限约束的是悬挂连接，不是任务（循环有自己的墙钟 deadline）。

### 3. 取消任务级输出限制，放宽墙钟默认

- 全部调用方不再把 `resource_budget.max_model_tokens` 透传为 `max_output_tokens`（review_jobs、semantic_audit、readable_pseudocode、auto_exploit；harness 生成删除 8192 硬编码）。输出上限只来自模型配置；`complete_structured` 的显式参数保留给未来确有必要的单点覆盖。`resource_budget` 维持 ADR-025 的惰性簿记身份。
- 审计循环默认 deadline 7200s → **28800s（8 小时）**；逆向规划 900s → **7200s（2 小时）**；设置接口上限 86400s → **604800s（7 天）**。墙钟是唯一兜底（ADR-027），兜底高度让位于真实样本的调研时长。

### 4. 智能配置与模型探测

- API 新增 `POST /api/settings/model-probe`：按 Base URL+协议拉取供应商模型列表（OpenAI 系 GET `/models`、Anthropic 系带 `x-api-key`/`anthropic-version` 的 GET `/models`），10s 超时、响应上限与凭据无关的错误消息；前端"获取模型列表"合并进供应商模型列表。
- 前端预设目录（`providers.ts`）扩展为带协议与模型元数据的一键建供应商（DeepSeek/智谱/Kimi/Anthropic/OpenAI），即"智能配置"的数据源。

### 5. Web 设置页重做

"独立复核模型 + 分档位模型"两个面板替换为**模型供应商**（供应商卡片：启用开关、Base URL、API 格式、API Key、超时/尝试、模型行内编辑：ID/上下文/最大输出/思考）与**智能体模型绑定**（每角色主/备下拉）两个分区。legacy 字段不再有 UI，但保存时原样透传，旧配置继续生效直至迁移。

## 后果

- **正向**：模型接入能力对齐主流工具的供应商管理形态；多供应商、多模型、每智能体选型、备用链、密钥轮换都成为一等配置；审计时长与输出不再被课设时代的校准值束缚。
- **代价**：`ProductSettings` 契约与前端类型变宽（旧字段保留，读取方需理解三段回退）；Responses 协议只覆盖 JSON 结构化输出所需的子集，流式、工具调用等高级面未接（`ChatTransport` 口子保留了将来换 SDK 实现的可能）。
- **风险**：绑定指向已停用供应商会在 worker 构建网关时显式失败（有意的 fail-fast）；API 校验已把这类状态挡在保存时。
