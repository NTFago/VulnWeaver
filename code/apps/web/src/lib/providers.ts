// 预置模型供应商目录：一键创建带完整模型元数据的供应商（智能配置）。
// 上下文窗口用于网关的粗粒度（约 4 字符/token）上下文裁剪估计；最大输出
// token 作为该模型的输出上限默认值（Anthropic 的 max_tokens 等）；均可在
// 保存后手工修改。0 表示交由供应商默认值决定。

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
    base_url: "https://api.deepseek.com/v1",
    api_format: "openai-chat",
    models: [
      { model_id: "deepseek-chat", context_window_tokens: 131072, max_output_tokens: 8192, note: "通用对话，指向最新 V 系列模型" },
      { model_id: "deepseek-reasoner", context_window_tokens: 131072, max_output_tokens: 65536, note: "深度推理，指向最新 R 系列模型" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://platform.deepseek.com 创建。",
  },
  {
    id: "glm",
    label: "智谱 GLM 官方",
    base_url: "https://open.bigmodel.cn/api/paas/v4",
    api_format: "openai-chat",
    models: [
      { model_id: "glm-5.3-flash", context_window_tokens: 204800, max_output_tokens: 16384, note: "本系统端到端验收已验证可用" },
      { model_id: "glm-4.6", context_window_tokens: 204800, max_output_tokens: 16384, note: "上一代旗舰，200K 上下文" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://open.bigmodel.cn 创建。",
  },
  {
    id: "moonshot",
    label: "月之暗面 Kimi",
    base_url: "https://api.moonshot.cn/v1",
    api_format: "openai-chat",
    models: [
      { model_id: "kimi-k2-0905-preview", context_window_tokens: 262144, max_output_tokens: 16384, note: "长上下文旗舰" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://platform.moonshot.cn 创建。",
  },
  {
    id: "anthropic",
    label: "Anthropic 官方",
    base_url: "https://api.anthropic.com/v1",
    api_format: "anthropic-messages",
    models: [
      { model_id: "claude-sonnet-4-5", context_window_tokens: 200000, max_output_tokens: 64000, note: "均衡旗舰，支持扩展思考" },
      { model_id: "claude-opus-4-1", context_window_tokens: 200000, max_output_tokens: 32000, note: "最强推理" },
    ],
    hint: "Anthropic Messages（/v1/messages）端点；API Key 在 https://console.anthropic.com 创建。",
  },
  {
    id: "openai",
    label: "OpenAI 官方",
    base_url: "https://api.openai.com/v1",
    api_format: "openai-chat",
    models: [
      { model_id: "gpt-4o", context_window_tokens: 128000, max_output_tokens: 16384, note: "多模态旗舰" },
      { model_id: "o4-mini", context_window_tokens: 200000, max_output_tokens: 100000, note: "推理模型" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://platform.openai.com 创建。",
  },
];

export const CUSTOM_PRESET_ID = "custom";

// 全部预置模型的平铺目录，供"添加模型"的智能配置下拉使用。
export function presetModelCatalog(): Array<{ provider: string; model: PresetModel }> {
  return PROVIDER_PRESETS.flatMap((preset) =>
    preset.models.map((model) => ({ provider: preset.label, model })),
  );
}
