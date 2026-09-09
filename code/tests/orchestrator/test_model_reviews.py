from __future__ import annotations

import asyncio
import io
import json
import zipfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import (
    EvidenceStrength,
    EvidenceType,
    FindingStatus,
    JsonObject,
    RunStatus,
    ToolIdentity,
)
from vulnweaver_model_gateway import (
    ModelEndpoint,
    ModelGateway,
    ModelGatewaySettings,
    ModelRoute,
    ModelTier,
    RedactionPolicy,
    TransportResponse,
)
from vulnweaver_orchestrator import FindingReviewGate, IndependentModelReviewer
from vulnweaver_persistence import Database, DatabaseSettings

from tests.model_gateway.test_model_gateway import FakeTransport, response
from tests.orchestrator.test_finding_reviews import _evidence, _finding, _relation, _review
from tests.persistence.factories import artifact, artifact_version, project, task


async def seed(
    database: Database, *, store: LocalContentAddressedStore, strong: bool = False
) -> str:
    suffix = uuid4().hex
    finding_id = f"finding:{suffix}"
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("src/app.py", "def greet(name):\n    return 'Hello ' + name\n")
    payload.seek(0)
    stored = store.put_stream(payload, max_bytes=4096)
    async with database.transaction() as repositories:
        await repositories.projects.add(project(f"project:{suffix}"))
        await repositories.artifacts.add(
            artifact(
                f"artifact:{suffix}",
                project_id=f"project:{suffix}",
                current_version_id=f"artifact-version:{suffix}",
            )
        )
        version = artifact_version(
            f"artifact-version:{suffix}", artifact_id=f"artifact:{suffix}", digest_character="a"
        )
        version["digest"] = stored.digest
        version["object_ref"] = stored.object_ref
        await repositories.artifacts.add_version(version)
        await repositories.tasks.create(
            task(
                f"task:{suffix}",
                project_id=f"project:{suffix}",
                artifact_version_ids=[f"artifact-version:{suffix}"],
            )
        )
        evidence = _evidence(
            f"evidence:{suffix}",
            evidence_type=EvidenceType.TOOL_OUTPUT,
            strength=EvidenceStrength.STRONG if strong else EvidenceStrength.SUPPORTING,
            replay_recipe={
                "kind": "static_analysis_diagnostic",
                "reproducible": strong,
                "reasoning": "AUDIT_NARRATIVE_MUST_NOT_LEAK",
            },
            tool=cast(
                ToolIdentity,
                {"name": "semgrep", "version": "1", "image_digest": "sha256:" + "b" * 64},
            ),
        )
        await repositories.evidence.create(evidence)
        finding = _finding(finding_id, [evidence["id"]])
        finding["task_id"] = f"task:{suffix}"
        finding["location"]["artifact_version_id"] = f"artifact-version:{suffix}"
        await repositories.findings.create(finding)
        await repositories.findings.link_evidence(_relation(finding_id, evidence["id"]))
    return finding_id


def model(transport: FakeTransport, *, redaction: RedactionPolicy | None = None) -> ModelGateway:
    endpoint = ModelEndpoint(
        name="test",
        base_url="https://models.example/v1",
        models={ModelTier.REVIEW: "independent-review"},
        max_attempts=1,
    )
    return ModelGateway(
        ModelGatewaySettings(
            routes={ModelTier.REVIEW: ModelRoute(endpoint)}, max_repair_attempts=0
        ),
        transport=transport,
        redaction=redaction,
    )


@pytest.mark.parametrize(
    "strong,outcome,expected",
    [
        (False, FindingStatus.CONFIRMED, FindingStatus.UNVERIFIABLE),
        (True, FindingStatus.CONFIRMED, FindingStatus.CONFIRMED),
        (False, FindingStatus.FALSE_POSITIVE, FindingStatus.FALSE_POSITIVE),
        (False, FindingStatus.DISPUTED, FindingStatus.DISPUTED),
    ],
)
def test_model_review_settlement_and_replay(
    persistence_database_url: str,
    tmp_path: Path,
    strong: bool,
    outcome: FindingStatus,
    expected: FindingStatus,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=strong
            )
            proposal = _review("finding:other-project")
            proposal["outcome"] = outcome
            transport = FakeTransport([response(json.dumps(proposal))])
            gateway = model(transport)
            store = LocalContentAddressedStore(tmp_path)
            reviewer = IndependentModelReviewer(database, gateway, store)
            result = await reviewer.review(finding_id, attempt_key="attempt-1")
            assert result.review is not None
            assert result.review["finding_id"] == finding_id
            assert result.review["model"] == "test/independent-review"
            assert result.review["outcome"] is expected
            assert result.review["id"] != proposal["id"]
            assert result.run["status"] is RunStatus.SUCCEEDED
            # A new service instance must use PostgreSQL, not gateway memory, for replay.
            again = await IndependentModelReviewer(database, gateway, store).review(
                finding_id, attempt_key="attempt-1"
            )
            assert again == result
            assert len(transport.requests) == 1
            assert transport.requests[0][2]["model"] == "independent-review"
            assert "AUDIT_NARRATIVE_MUST_NOT_LEAK" not in json.dumps(transport.requests)
            async with database.transaction() as repositories:
                finding = await repositories.findings.get(finding_id)
                assert finding["status"] is expected
                assert len(await repositories.findings.list_reviews(finding_id)) == 1
                assert len(await repositories.agent_runs.list_for_task(finding["task_id"])) == 1
                relations = await repositories.findings.list_evidence_relations(finding_id)
                conclusion = await repositories.evidence.get(
                    next(
                        item["evidence_id"]
                        for item in relations
                        if item["evidence_id"].startswith("evidence:review:")
                    )
                )
                assert conclusion["type"] is EvidenceType.REVIEW_CONCLUSION
                assert conclusion["strength"] is EvidenceStrength.CONTEXTUAL
                with store.open(conclusion["artifact_ref"]) as source:
                    saved = json.load(source)
                assert saved["proposal"]["outcome"] == outcome
                assert store.verify(conclusion["artifact_ref"]).digest == conclusion["digest"]
            facts = await FindingReviewGate(database).build_fact_context(finding_id)
            assert len(facts.evidence) == 1
            assert facts.review_ids == (result.review["id"],)
        finally:
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("content", ["not json", json.dumps({"outcome": "confirmed"})])
def test_invalid_review_is_audited_without_finding_mutation(
    persistence_database_url: str,
    tmp_path: Path,
    content: str,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(database, store=LocalContentAddressedStore(tmp_path))
            transport = FakeTransport([response(content)])
            reviewer = IndependentModelReviewer(
                database, model(transport), LocalContentAddressedStore(tmp_path)
            )
            result = await reviewer.review(finding_id, attempt_key="invalid")
            assert result.review is None
            assert result.run["status"] is RunStatus.FAILED
            assert result.run["failure"] is not None
            assert await reviewer.review(finding_id, attempt_key="invalid") == result
            async with database.transaction() as repositories:
                assert (await repositories.findings.get(finding_id))[
                    "status"
                ] is FindingStatus.CANDIDATE
                assert await repositories.findings.list_reviews(finding_id) == []
                assert len(await repositories.findings.list_evidence_relations(finding_id)) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


class ChangingTransport(FakeTransport):
    def __init__(self, change: Callable[[], Awaitable[None]]) -> None:
        super().__init__([response(json.dumps(_review("finding:ignored")))])
        self.change = change

    async def post_json(self, *args: object, **kwargs: object) -> TransportResponse:
        await self.change()
        self.requests.append(("changed", {}, cast(JsonObject, {})))
        return cast(TransportResponse, self.responses.pop(0))


def test_changed_facts_cannot_be_confirmed(persistence_database_url: str, tmp_path: Path) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )

            async def change() -> None:
                review = _review(finding_id)
                review["id"] = f"review:{uuid4().hex}"
                review["outcome"] = FindingStatus.DISPUTED
                await FindingReviewGate(database).submit(review)

            reviewer = IndependentModelReviewer(
                database, model(ChangingTransport(change)), LocalContentAddressedStore(tmp_path)
            )
            result = await reviewer.review(finding_id, attempt_key="stale")
            assert result.review is None
            assert result.run["failure"]["code"] == "review_context_changed"
            async with database.transaction() as repositories:
                assert (await repositories.findings.get(finding_id))[
                    "status"
                ] is FindingStatus.DISPUTED
                assert len(await repositories.findings.list_reviews(finding_id)) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_timeout_is_persisted(persistence_database_url: str, tmp_path: Path) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(database, store=LocalContentAddressedStore(tmp_path))
            reviewer = IndependentModelReviewer(
                database,
                model(FakeTransport([TimeoutError()])),
                LocalContentAddressedStore(tmp_path),
            )
            result = await reviewer.review(finding_id, attempt_key="timeout")
            assert result.review is None
            assert result.run["status"] is RunStatus.FAILED
            assert result.run["failure"]["retryable"] is True
            assert await reviewer.review(finding_id, attempt_key="timeout") == result
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_atomic_rollback_can_retry_same_service(
    persistence_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnweaver_persistence.repositories import AgentRunRepository

    original = AgentRunRepository.add

    async def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated database outage")

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )
            transport = FakeTransport([response(json.dumps(_review(finding_id))) for _ in range(2)])
            reviewer = IndependentModelReviewer(
                database, model(transport), LocalContentAddressedStore(tmp_path)
            )
            monkeypatch.setattr(AgentRunRepository, "add", fail)
            with pytest.raises(RuntimeError, match="simulated database outage"):
                await reviewer.review(finding_id, attempt_key="rollback")
            async with database.transaction() as repositories:
                assert await repositories.findings.list_reviews(finding_id) == []
                assert len(await repositories.findings.list_evidence_relations(finding_id)) == 1
                assert (await repositories.findings.get(finding_id))[
                    "status"
                ] is FindingStatus.CANDIDATE
            monkeypatch.setattr(AgentRunRepository, "add", original)
            result = await reviewer.review(finding_id, attempt_key="rollback")
            assert result.review["outcome"] is FindingStatus.CONFIRMED
            assert len(transport.requests) == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_artifact_failure_does_not_publish_review(
    persistence_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vulnweaver_artifact_store import ArtifactStoreIOError

    def fail(*args: object, **kwargs: object) -> None:
        raise ArtifactStoreIOError("sensitive storage diagnostic")

    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )
            store = LocalContentAddressedStore(tmp_path)
            monkeypatch.setattr(store, "put_stream", fail)
            reviewer = IndependentModelReviewer(
                database, model(FakeTransport([response(json.dumps(_review(finding_id)))])), store
            )
            result = await reviewer.review(finding_id, attempt_key="storage")
            assert result.review is None
            assert result.run["failure"]["code"] == "review_artifact_unavailable"
            assert "sensitive" not in json.dumps(result.run)
            async with database.transaction() as repositories:
                assert await repositories.findings.list_reviews(finding_id) == []
                assert len(await repositories.findings.list_evidence_relations(finding_id)) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_concurrent_attempt_settles_once(persistence_database_url: str, tmp_path: Path) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )
            ready = asyncio.Event()
            count = 0

            async def synchronize() -> None:
                nonlocal count
                count += 1
                if count == 2:
                    ready.set()
                await asyncio.wait_for(ready.wait(), timeout=5)

            store = LocalContentAddressedStore(tmp_path)
            reviewers = [
                IndependentModelReviewer(database, model(ChangingTransport(synchronize)), store)
                for _ in range(2)
            ]
            results = await asyncio.gather(
                *[reviewer.review(finding_id, attempt_key="concurrent") for reviewer in reviewers]
            )
            assert results[0] == results[1]
            async with database.transaction() as repositories:
                assert len(await repositories.findings.list_reviews(finding_id)) == 1
                finding = await repositories.findings.get(finding_id)
                assert len(await repositories.agent_runs.list_for_task(finding["task_id"])) == 1
                assert len(await repositories.findings.list_evidence_relations(finding_id)) == 2
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_cancel_during_model_call_preserves_finding(
    persistence_database_url: str,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )

            async def cancel() -> None:
                async with database.transaction() as repositories:
                    finding = await repositories.findings.get(finding_id)
                    await repositories.tasks.cancel(finding["task_id"])

            reviewer = IndependentModelReviewer(
                database, model(ChangingTransport(cancel)), LocalContentAddressedStore(tmp_path)
            )
            result = await reviewer.review(finding_id, attempt_key="cancel")
            assert result.review is None
            assert result.run["failure"]["code"] == "review_context_changed"
            async with database.transaction() as repositories:
                assert await repositories.findings.list_reviews(finding_id) == []
                assert (await repositories.findings.get(finding_id))[
                    "status"
                ] is FindingStatus.CANDIDATE
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_model_cannot_overturn_confirmed_finding(
    persistence_database_url: str,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        try:
            finding_id = await seed(
                database, store=LocalContentAddressedStore(tmp_path), strong=True
            )
            first = _review(finding_id)
            first["id"] = f"review:{uuid4().hex}"
            await FindingReviewGate(database).submit(first)
            proposal = _review(finding_id)
            proposal["outcome"] = FindingStatus.FALSE_POSITIVE
            reviewer = IndependentModelReviewer(
                database,
                model(FakeTransport([response(json.dumps(proposal))])),
                LocalContentAddressedStore(tmp_path),
            )
            result = await reviewer.review(finding_id, attempt_key="invalid-transition")
            assert result.review is None
            assert result.run["failure"]["code"] == "review_transition_denied"
            async with database.transaction() as repositories:
                assert (await repositories.findings.get(finding_id))[
                    "status"
                ] is FindingStatus.CONFIRMED
                assert len(await repositories.findings.list_reviews(finding_id)) == 1
        finally:
            await database.dispose()

    asyncio.run(scenario())
