# VulnWeaver contracts

`src/vulnweaver_contracts/schemas/v1/contracts.schema.json` is the canonical public
contract source. It freezes the v1 entity, API, queue, worker, `ActionPlan`, `ToolSpec`
and `CapabilityProfile` shapes.

Regenerate the Python and TypeScript views after changing the schema:

```shell
uv run python packages/contracts/scripts/generate_contracts.py
```

CI and local verification use `--check` to reject generated-file drift. Breaking
changes require a new schema major version; historical versions remain available for
task replay.
