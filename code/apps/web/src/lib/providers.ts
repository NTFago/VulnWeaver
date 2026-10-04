// 预置模型供应商目录：一键创建带完整模型元数据的供应商（智能配置）。
// 模型 ID 与规格于 2026-09-30 自各家官方文档核实：
//   DeepSeek  https://api-docs.deepseek.com（deepseek-flash / deepseek-v4-pro，1M 上下文）
//   智谱      https://docs.bigmodel.cn（glm-5.3 系列，1M 上下文 / 128K 输出）
//   Kimi      https://platform.kimi.com/docs/models（kimi-k3 / kimi-k2.6 / kimi-k2.7-code）
//   Anthropic https://platform.claude.com/docs（claude-sonnet-5-5 等，1M / 128K）
//   OpenAI    https://developers.openai.com/api/docs/models（gpt-6.1-sol 等，1.05M / 128K）
// 上下文窗口用于网关的粗粒度（约 4 字符/token）上下文裁剪估计；最大输出
// token 只登记模型的物理输出能力，供 Anthropic 必填 max_tokens 等协议字段使用；
// 0 表示交由供应商默认决定。所有字段保存后均可手工修改。

export interface PresetModel {
  model_id: string;
  context_window_tokens: number;
  max_output_tokens: number;
  note: string;
}

export interface ProviderPreset {
  id: string;
  label: string;
  base_url: string;
  api_format: "openai-chat" | "anthropic-messages" | "openai-responses";
  models: PresetModel[];
  hint: string;
}

export const PROVIDER_PRESETS: ProviderPreset[] = [
  {
    id: "deepseek",
    label: "DeepSeek 官方",
    base_url: "https://api.deepseek.com",
    api_format: "openai-chat",
    models: [
      { model_id: "deepseek-flash", context_window_tokens: 1000000, max_output_tokens: 393216, note: "DeepSeek-V4.1-Flash，性价比主力，默认开启思考" },
      { model_id: "deepseek-v4-pro", context_window_tokens: 1000000, max_output_tokens: 393216, note: "DeepSeek-V4-Pro-0813，能力上限更高" },
    ],
    hint: "OpenAI 兼容端点（无 /v1 后缀）；API Key 在 https://platform.deepseek.com 创建。",
  },
  {
    id: "glm",
    label: "智谱 GLM 官方",
    base_url: "https://open.bigmodel.cn/api/paas/v4",
    api_format: "openai-chat",
    models: [
      { model_id: "glm-5.3", context_window_tokens: 1000000, max_output_tokens: 128000, note: "旗舰文本模型，1M 上下文" },
      { model_id: "glm-5.3-flash", context_window_tokens: 1000000, max_output_tokens: 128000, note: "本系统端到端验收已验证可用" },
      { model_id: "glm-5.3-flashx", context_window_tokens: 1000000, max_output_tokens: 128000, note: "Flash 加速版" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://open.bigmodel.cn 创建。",
  },
  {
    id: "moonshot",
    label: "月之暗面 Kimi",
    base_url: "https://api.moonshot.cn/v1",
    api_format: "openai-chat",
    models: [
      { model_id: "kimi-k3", context_window_tokens: 1000000, max_output_tokens: 0, note: "旗舰，长程编程与端到端知识工作，原生视觉" },
      { model_id: "kimi-k2.6", context_window_tokens: 256000, max_output_tokens: 0, note: "文本+图片+视频输入，思考/非思考可切换" },
      { model_id: "kimi-k2.7-code", context_window_tokens: 256000, max_output_tokens: 0, note: "编程特化" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://platform.kimi.com 创建。最大输出未公开，0=供应商默认。",
  },
  {
    id: "anthropic",
    label: "Anthropic 官方",
    base_url: "https://api.anthropic.com/v1",
    api_format: "anthropic-messages",
    models: [
      { model_id: "claude-sonnet-5-5", context_window_tokens: 1000000, max_output_tokens: 128000, note: "均衡旗舰，1M 上下文" },
      { model_id: "claude-opus-5-5", context_window_tokens: 1000000, max_output_tokens: 128000, note: "最强推理，1M 上下文" },
      { model_id: "claude-haiku-4-5", context_window_tokens: 200000, max_output_tokens: 64000, note: "轻量快速" },
    ],
    hint: "Anthropic Messages（/v1/messages）端点；API Key 在 Anthropic 控制台创建。",
  },
  {
    id: "openai",
    label: "OpenAI 官方",
    base_url: "https://api.openai.com/v1",
    api_format: "openai-chat",
    models: [
      { model_id: "gpt-6.1-sol", context_window_tokens: 1050000, max_output_tokens: 128000, note: "均衡旗舰" },
      { model_id: "gpt-6-luna", context_window_tokens: 1050000, max_output_tokens: 128000, note: "高速低价档" },
      { model_id: "gpt-6-astra", context_window_tokens: 1050000, max_output_tokens: 128000, note: "能力上限档" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 OpenAI 平台创建。",
  },
];

// 全部预置模型的平铺目录，供"添加模型"弹窗的智能配置下拉使用。
export function presetModelCatalog(): Array<{ provider: string; model: PresetModel }> {
  return PROVIDER_PRESETS.flatMap((preset) =>
    preset.models.map((model) => ({ provider: preset.label, model })),
  );
}
