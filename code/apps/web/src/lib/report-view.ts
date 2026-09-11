import type { ArtifactVersion, Finding, Job, PairFunction } from "@vulnweaver/contracts";
export const reportFormats = ["pdf", "markdown", "sarif"] as const;
export type ReportFormat = typeof reportFormats[number];
export const reportLabels: Record<ReportFormat, { name: string; description: string; extension: string }> = {
  pdf: { name: "专业审计报告", description: "中文排版 · 代码与证据 · 适合交付", extension: "pdf" },
  markdown: { name: "结构化审计记录", description: "中文正文 · 便于阅读和整理", extension: "md" },
  sarif: { name: "工具交换结果", description: "SARIF 2.1.0 · 供分析工具导入", extension: "sarif" },
};
export function reportView(format: ReportFormat, jobs: Job[], versions: ArtifactVersion[]) {
  return {
    jobs: jobs.filter(job => job.kind === "report" && (job.arguments?.format ?? "markdown") === format),
    versions: versions.filter(version => version.generation_config.format === format),
    active: jobs.some(job => job.kind === "report" && (job.arguments?.format ?? "markdown") === format && ["pending", "queued", "running", "waiting_permission"].includes(job.status)),
  };
}
export function pseudocodeText(fn: PairFunction): string | null {
  const value = fn.attributes?.pseudocode;
  if (typeof value === "string") return value.trim() ? value : null;
  if (!Array.isArray(value)) return null;
  const texts = value.flatMap(item => item && typeof item === "object" && "text" in item && typeof item.text === "string" && item.text.trim() ? [item.text] : []);
  return texts.length ? texts.join("\n\n") : null;
}
export function findingCounts(findings: Finding[]) {
  const active = findings.filter(finding => finding.status !== "false_positive");
  return { total: findings.length, active, confirmed: active.filter(finding => finding.status === "confirmed").length, pending: active.filter(finding => finding.status !== "confirmed").length, falsePositive: findings.length - active.length };
}
