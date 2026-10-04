# ADR-037：协议适配器、原生思考控制与模型用量

- 状态：已接受
- 日期：2026-10-04
- 相关：ADR-033、ADR-025

## 背景

ADR-033 把供应商和模型登记分开，但请求构造、响应解析仍集中在 `gateway.py`。旧 `thinking_budget_tokens` 会被猜成 OpenAI 的 low/medium/high；Anthropic 默认思考请求缺少有效预算；响应内容校验失败时供应商已返回的用量被丢弃。仅记录 input/output 两项也不能解释缓存和思考 token。用户明确要求取消本系统设置的思考 token 预算与回答 token 限制。

## 决策

1. `model-gateway/protocols.py` 注册 OpenAI Chat、OpenAI Responses、Anthropic Messages 三个适配器。供应商连接和模型绑定仍在 `registry.py`，重试、回退、AgentRun 记录仍在 `gateway.py`。结构化 `ActionPlan` 是当前智能体的工具边界，协议适配器不直接执行模型原生工具调用。
2. `thinking_effort` 是显式枚举，原样传给支持它的协议，不再从 token 数推断。Claude 使用 `thinking: adaptive` 与 `output_config.effort`；DeepSeek Chat 使用 `thinking` 开关与 `reasoning_effort`；Kimi K3 使用顶层 `reasoning_effort`，K2.6 使用 `thinking` 开关，K2.7 Code 始终思考。官方未确认的组合在保存或路由构建时拒绝。
3. 新设置页不提供思考预算或回答上限。历史 `thinking_mode=custom`、`thinking_budget_tokens` 仍可读取，旧档位配置不再要求预算下限；路由将其规范化为自适应思考，不发送预算。显式 `complete_structured(max_output_tokens=...)` 拒绝调用，避免旧调用者重新施加限额。
4. OpenAI Responses 和普通 Chat 不发送输出截断参数。DeepSeek Chat 的 API 默认只有 8K/64K 输出，因此发送其官方物理最大值 393216，忽略可能较低的旧模型元数据。Anthropic Messages 强制要求 `max_tokens`，使用模型登记的物理最大输出能力，未登记时使用当前 Claude 家族的 128000；这是协议必填字段，不是任务预算。Kimi Chat 不发送输出长度参数，由供应商默认值决定。供应商本身仍可能有物理窗口、默认值或账户限制；网关不能消除它们。
5. `TokenUsage` v1 扩展可选的缓存读取、缓存写入、思考输出、缺失用量响应次数。输入/输出总数以供应商用量字段为准，缓存和思考只是其子集，不重复相加；Anthropic 的输入总数须加上缓存创建与读取。非 2xx 响应若带用量、重试、回退、JSON 修复和已截断响应均计入已报告用量。供应商未报告用量时记录 `missing_usage_responses`，不把零显示成精确结果。传输中断后服务商是否计费不可由本地精确判定。
6. HTTP 错误的原始响应体不进入结构化失败详情，避免把供应商返回的敏感数据写入审计记录。

## 官方依据（2026-10-04 核查）

- [OpenAI reasoning](https://developers.openai.com/api/docs/guides/reasoning)：`reasoning.effort` 是离散强度，`output_tokens_details.reasoning_tokens` 属于输出总数。
- [Claude Messages API](https://platform.claude.com/docs/en/api/messages/create)、[Claude 思考模式](https://platform.claude.com/docs/en/build-with-claude/adaptive-thinking)：自适应思考、`output_config.effort`、必填 `max_tokens`，以及缓存 token 的输入总量规则。
- [DeepSeek 思考模式](https://api-docs.deepseek.com/guides/thinking_mode/)、[Chat API](https://api-docs.deepseek.com/api/create-chat-completion/)：思考开关、强度和默认/物理输出长度。
- [Kimi 强度](https://platform.kimi.com/docs/guide/use-reasoning-effort)、[Kimi Chat API](https://platform.kimi.com/docs/api/chat)：K3 与 K2.x 的不同开关、缓存明细和默认输出行为。

## 后果与验证边界

配置形状向后兼容，新增字段是可选字段，旧 AgentRun 仍合法。无真实 API Key 的测试只验证固定官方格式响应和负例；供应商变更模型参数时，应更新模型能力登记和契约测试，再做真实端点验收。原生工具调用、流式增量、跨模型推理状态迁移仍需单独设计，不由本次结构化 JSON 接口宣称支持。
