from vulnweaver_fuzzing import harness_loop


def test_compile_repair_loop_is_bounded_and_repairs_diagnostics() -> None:
    attempts: list[str] = []

    def compile_once(source: str) -> harness_loop.HarnessDiagnostic:
        attempts.append(source)
        return harness_loop.HarnessDiagnostic(
            source == "fixed", "ok" if source == "fixed" else "missing include"
        )

    result = harness_loop.compile_repair_loop(
        "broken",
        compile_once,
        lambda _source, _diagnostic: "fixed",
        max_repairs=2,
    )
    assert result.status == "compiled"
    assert attempts == ["broken", "fixed"]


def test_compile_repair_loop_reports_budget_exhaustion() -> None:
    result = harness_loop.compile_repair_loop(
        "broken",
        lambda _source: harness_loop.HarnessDiagnostic(False, "still broken"),
        lambda source, _diagnostic: source + "x",
        max_repairs=1,
    )
    assert result.status == "failed"
    assert len(result.diagnostics) == 2
