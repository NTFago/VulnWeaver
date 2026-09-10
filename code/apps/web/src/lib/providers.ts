// 预置模型提供商配置：一键填充端点、默认模型与上下文窗口。
// 上下文窗口用于网关的粗粒度（约 4 字符/token）上下文裁剪估计；
// 0 表示不限制。所有字段保存后均可手工修改。

export interface ProviderModelPreset {
  name: string;
  note: string;
}

export interface ProviderPreset {
  id: string;
  label: string;
  base_url: string;
  context_window_tokens: number;
  models: ProviderModelPreset[];
  hint: string;
}

export const PROVIDER_PRESETS: ProviderPreset[] = [
  {
    id: "deepseek",
    label: "DeepSeek 官方",
    base_url: "https://api.deepseek.com/v1",
    context_window_tokens: 131072,
    models: [
      { name: "deepseek-chat", note: "通用对话，指向最新 V 系列模型" },
      { name: "deepseek-reasoner", note: "深度推理，指向最新 R 系列模型" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://platform.deepseek.com 创建。",
  },
  {
    id: "glm",
    label: "智谱 GLM 官方",
    base_url: "https://open.bigmodel.cn/api/paas/v4",
    context_window_tokens: 204800,
    models: [
      { name: "glm-5.3-flash", note: "本系统端到端验收已验证可用" },
      { name: "glm-4.6", note: "上一代旗舰，200K 上下文" },
    ],
    hint: "OpenAI 兼容端点；API Key 在 https://open.bigmodel.cn 创建。",
  },
];

export const CUSTOM_PRESET_ID = "custom";
