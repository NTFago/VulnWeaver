import pytest

from vulnweaver_orchestrator.fuzz_jobs import link_fuzz_evidence


class Findings:
    def __init__(self):
        self.relations = []

    async def link_evidence(self, relation):
        self.relations.append(relation)
        return relation


class Repositories:
    def __init__(self):
        self.findings = Findings()


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
