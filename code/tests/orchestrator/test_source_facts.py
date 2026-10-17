from __future__ import annotations

import asyncio
import io
import json
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import FindingStatus, JsonObject
from vulnweaver_model_gateway import RedactionPolicy
from vulnweaver_orchestrator import IndependentModelReviewer
from vulnweaver_orchestrator.source_facts import SourceReviewFactLoader
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_source_analysis import ExcerptLimits, SourceExcerptReader

from tests.model_gateway.test_model_gateway import FakeTransport, response
from tests.orchestrator.test_finding_reviews import _review
from tests.orchestrator.test_model_reviews import model, seed
from tests.persistence.factories import artifact, artifact_version, project, task


def test_source_loader_enforces_task_and_project_boundary(
    persistence_database_url: str,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        loader = SourceReviewFactLoader(database, store)
        try:
            finding_id = await seed(database, store=store)
            async with database.transaction() as repositories:
                finding = await repositories.findings.get(finding_id)
            location = cast(JsonObject, dict(finding["location"]))
            result = await loader.load(finding["task_id"], location)
            assert result.available
            assert "Hello" in result.excerpt.text
            changed = dict(location)
            changed["artifact_version_id"] = "artifact-version:foreign"
            assert (
                await loader.load(finding["task_id"], changed)
            ).reason_code == "source_outside_task_inputs"

            suffix = uuid4().hex
            async with database.transaction() as repositories:
                await repositories.projects.add(project(f"project:{suffix}"))
                await repositories.tasks.create(
                    task(
                        f"task:{suffix}",
                        project_id=f"project:{suffix}",
                        artifact_version_ids=[str(location["artifact_version_id"])],
                    )
                )
            denied = await loader.load(f"task:{suffix}", location)
            assert denied.reason_code == "source_project_mismatch"
            assert denied.excerpt is None
            assert "Hello" not in json.dumps(asdict(denied))
            assert (
                await loader.load(finding["task_id"], {})
            ).reason_code == "source_location_unsupported"
        finally:
            await database.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", [FindingStatus.CONFIRMED, FindingStatus.FALSE_POSITIVE])
def test_truncated_source_cannot_resolve_finding(
    persistence_database_url: str,
    tmp_path: Path,
    outcome: FindingStatus,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            finding_id = await seed(database, store=store, strong=True)
            proposal = _review(finding_id)
            proposal["outcome"] = outcome
            transport = FakeTransport([response(json.dumps(proposal))])
            loader = SourceReviewFactLoader(
                database,
                store,
                reader=SourceExcerptReader(store, limits=ExcerptLimits(text_bytes=4)),
            )
            reviewer = IndependentModelReviewer(
                database, model(transport), store, source_loader=loader
            )
            result = await reviewer.review(finding_id, attempt_key="truncated")
            assert result.review["outcome"] is FindingStatus.UNVERIFIABLE
            assert "source_excerpt_truncated" in result.review["rationale"]
            prompt = json.dumps(transport.requests)
            assert "source_facts" in prompt and "truncated" in prompt
            with store.open(result.run["result_refs"][0]) as source:
                saved = json.load(source)
            assert saved["source_facts"]["excerpt"]["truncated"] is True
            assert saved["proposal"]["outcome"] == outcome
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_source_text_reaches_gateway_and_is_auditable(
    persistence_database_url: str,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            finding_id = await seed(database, store=store)
            transport = FakeTransport([response(json.dumps(_review(finding_id)))])
            result = await IndependentModelReviewer(database, model(transport), store).review(
                finding_id, attempt_key="source-audit"
            )
            assert "return 'Hello ' + name" in json.dumps(transport.requests)
            with store.open(result.run["result_refs"][0]) as source:
                saved = json.load(source)
            excerpt = saved["source_facts"]["excerpt"]
            assert excerpt["archive_ref"] in result.run["input_refs"]
            assert excerpt["file_digest"].startswith("sha256:")
            assert excerpt["start_line"] == 1 and excerpt["end_line"] == 2
            assert "AUDIT_NARRATIVE_MUST_NOT_LEAK" not in json.dumps(saved)
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_source_text_uses_configured_redaction(
    persistence_database_url: str, tmp_path: Path
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        try:
            finding_id = await seed(database, store=store)
            transport = FakeTransport([response(json.dumps(_review(finding_id)))])
            gateway = model(transport, redaction=RedactionPolicy(patterns=("Hello",)))
            await IndependentModelReviewer(database, gateway, store).review(
                finding_id, attempt_key="redacted"
            )
            request = json.dumps(transport.requests)
            assert "Hello" not in request
            assert "<redacted>" in request
        finally:
            await database.dispose()

    asyncio.run(scenario())


def test_default_review_reader_covers_spans_wider_than_the_audit_window(
    persistence_database_url: str,
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path)
        loader = SourceReviewFactLoader(database, store)
        suffix = uuid4().hex
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            body = "".join(f"line {n}\n" for n in range(1, 300)).encode()
            archive.writestr("src/parse.c", body)
        payload.seek(0)
        stored = store.put_stream(payload, max_bytes=1024 * 1024)
        try:
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
                    f"artifact-version:{suffix}",
                    artifact_id=f"artifact:{suffix}",
                    digest_character="a",
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
            result = await loader.load(
                f"task:{suffix}",
                cast(
                    JsonObject,
                    {
                        "artifact_version_id": f"artifact-version:{suffix}",
                        "path": "src/parse.c",
                        "start_line": 1,
                        "start_column": 1,
                        "end_line": 299,
                        "end_column": 1,
                    },
                ),
            )
            assert result.available and result.excerpt is not None
            # The 299-line span exceeds the audit's 220-line window; the
            # one-shot review must still see the reported span end to end.
            assert result.excerpt.truncated is False
            assert result.excerpt.start_line == 1 and result.excerpt.end_line == 299
            assert result.excerpt.text.endswith("line 299\n")
        finally:
            await database.dispose()

    asyncio.run(scenario())
