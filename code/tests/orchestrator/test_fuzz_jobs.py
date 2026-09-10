import pytest
from vulnweaver_orchestrator.fuzz_jobs import link_fuzz_evidence, persist_crash_evidence


class Findings:
    def __init__(self):
        self.relations = []

    async def link_evidence(self, relation):
        self.relations.append(relation)
        return relation


class Repositories:
    def __init__(self):
        self.findings = Findings()
        self.evidence = Evidence()


class Evidence:
    def __init__(self):
        self.items = []

    async def create(self, evidence):
        self.items.append(evidence)
        return evidence


@pytest.mark.anyio
async def test_link_fuzz_evidence_is_deduplicated_and_supporting():
    repos = Repositories()
    linked = await link_fuzz_evidence(repos, finding_id="f", evidence_ids=["e2", "e1", "e2"],
                                      created_by="job", created_at="2026-01-01T00:00:00Z")
    assert linked == ("e1", "e2")
    assert [r["relation"] for r in repos.findings.relations] == ["supports", "supports"]


@pytest.mark.anyio
async def test_link_fuzz_evidence_rejects_invalid_weight():
    with pytest.raises(ValueError):
        await link_fuzz_evidence(Repositories(), finding_id="f", evidence_ids=[],
                                 created_by="job", created_at="now", weight=2)


@pytest.mark.anyio
async def test_persist_crash_evidence_stores_replayable_minimized_input():
    repos = Repositories()
    crash = {
        "schema_version": "1.0.0", "id": "crash", "artifact_version_id": "version",
        "input_ref": "cas://input", "input_digest": "sha256:" + "a" * 64,
        "signal": "SIGSEGV", "exit_code": 11, "stack_frames": [],
        "stack_hash": "sha256:" + "b" * 64, "stderr_ref": None,
        "fuzz_tool": {"name": "afl-casr", "version": "1", "image_digest": "sha256:" + "c" * 64},
        "tool": {"name": "casr", "version": "1", "image_digest": "sha256:" + "c" * 64},
        "created_at": "2026-01-01T00:00:00Z",
    }
    linked = await persist_crash_evidence(repos, finding_id="f", crashes=[crash], created_by="job")
    assert len(linked) == 1
    assert repos.evidence.items[0]["type"] == "crash_record"
    assert repos.evidence.items[0]["replay_recipe"]["reproducible"] is True
