# Tool runtime

This package owns the version-pinned Tool Registry and the Policy Engine boundary.

- `ToolRegistry` registers immutable `ToolSpec` values by exact `name` + `version`.
- `PolicyEngine` accepts only a schema-valid `ActionPlan` and returns structured decisions.
- Policy checks cover registered tools, command arguments, artifact kinds, paths, network hosts,
  resource budgets, and approval mode.
- Approved output is a `ScheduledToolCall`; it contains structured arguments and references,
  never an arbitrary shell command or container invocation.
- Every evaluated step is appended to the injected audit log. The default in-memory sink is
  suitable for the MVP; orchestration can provide a durable implementation.

`FULL_ACCESS` only skips an approval wait. It does not bypass the ToolSpec allowlists,
filesystem invariants, network policy, resource budget, or argument restrictions.
