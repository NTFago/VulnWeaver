/**
 * 函数工作台的渲染封顶。
 * 列表由服务端分页（每页 300 条），但"加载更多"叠加的页数也要封顶，
 * 防止用户连续翻页把 DOM 再推回数万节点的状态；此时应继续用名称过滤收敛。
 */

import type { PairFunction } from "@vulnweaver/contracts";

export const FUNCTION_PAGE_SIZE = 300;
export const FUNCTION_RENDER_CAP = 900;

export function renderablePairFunctions(
  functions: PairFunction[],
  cap: number = FUNCTION_RENDER_CAP,
): PairFunction[] {
  return functions.slice(0, Math.max(0, cap));
}
