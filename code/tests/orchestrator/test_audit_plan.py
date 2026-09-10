import pytest
from vulnweaver_orchestrator.audit_plan import build_baseline_plan, complete_baselines


def test_audit_plan_blocks_no_findings_until_required_baselines_complete() -> None:
    plan = build_baseline_plan("source-import", "static-rules")
    assert plan.coverage() == 0
    assert plan.allows_no_findings() is False
    complete = complete_baselines(plan, ["source-import", "static-rules", "unknown"])
    assert complete.coverage() == 1
    assert complete.allows_no_findings() is True


def test_audit_plan_rejects_duplicate_or_empty_baselines() -> None:
    with pytest.raises(ValueError):
        build_baseline_plan("", " ")
    with pytest.raises(ValueError):
        build_baseline_plan("static", "static")
