"""Real PostgreSQL/CAS coverage for version scoping and report code extraction."""

from __future__ import annotations

import asyncio
import io
import json
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from vulnweaver_analysis_worker.report_excerpts import ReportSourceExcerptReader
from vulnweaver_artifact_store import ArtifactRegistrationService, LocalContentAddressedStore
from vulnweaver_contracts import ArtifactKind, JobKind, JobStatus, PairFunction, ToolIdentity
from vulnweaver_persistence import Database, DatabaseSettings
from vulnweaver_reporting.excerpts import collect_excerpts
from vulnweaver_reporting.executor import ReportJobExecutor, _sample_summaries

from tests.persistence.factories import artifact, artifact_version, job, project, task
from tests.reporting.test_markdown import make_finding


def test_report_reads_selected_version_and_rejects_other_project_inputs(
    persistence_database_url: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:10]
        db = Database(DatabaseSettings(persistence_database_url))
        store = LocalContentAddressedStore(tmp_path / "cas")
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(
                "app.py", 'def read_config():\n    password = "private-value"\n    return 1\n'
            )
        archive.seek(0)
        stored = store.put_stream(archive, max_bytes=1024 * 1024)
        proj = project(f"project:report-{suffix}")
        other = project(f"project:other-{suffix}")
        original = artifact_version(f"version:old-{suffix}", artifact_id=f"artifact:a-{suffix}")
        original.update(digest=stored.digest, object_ref=stored.object_ref)
        original["generation_config"] = {"filename": "selected.zip"}
        latest = artifact_version(
            f"version:new-{suffix}", artifact_id=original["artifact_id"], digest_character="b"
        )
        latest["generation_config"] = {"filename": "unselected-new.zip"}
        other_version = artifact_version(
            f"version:other-{suffix}", artifact_id=f"artifact:b-{suffix}"
        )
        selected = task(
            f"task:report-{suffix}", project_id=proj["id"], artifact_version_ids=[original["id"]]
        )
        source_finding = make_finding(
            task_id=selected["id"],
            status="candidate",
            cwe_id="CWE-78",
            location={
                "artifact_version_id": original["id"],
                "path": "app.py",
                "start_line": 1,
                "end_line": 3,
                "start_column": 1,
                "end_column": 1,
            },
        )
        try:
            async with db.transaction() as repos:
                await repos.projects.add(proj)
                await repos.projects.add(other)
                await repos.artifacts.add(
                    artifact(
                        original["artifact_id"],
                        project_id=proj["id"],
                        current_version_id=latest["id"],
                    )
                )
                await repos.artifacts.add_version(original)
                await repos.artifacts.add_version(latest)
                await repos.artifacts.add(
                    artifact(
                        other_version["artifact_id"],
                        project_id=other["id"],
                        current_version_id=other_version["id"],
                    )
                )
                await repos.artifacts.add_version(other_version)
                await repos.tasks.create(selected)
                await repos.findings.create(source_finding)
                samples = await _sample_summaries(repos, selected)
                assert [s["name"] for s in samples] == ["selected.zip"]
                assert samples[0]["digest"] == stored.digest
            excerpts, errors = await collect_excerpts(
                db, selected, [source_finding], ReportSourceExcerptReader(store)
            )
            assert not errors
            assert "def read_config" in excerpts["finding:1"]["text"]
            assert "private-value" not in excerpts["finding:1"]["text"]
            assert "已脱敏" in excerpts["finding:1"]["text"]
            assert original["id"] in excerpts["finding:1"]["source"]
            executor = ReportJobExecutor(
                db,
                ArtifactRegistrationService(store, db),
                tool=ToolIdentity(name="vulnweaver-report", version="1.0.0", image_digest=None),
                source_excerpt_reader=ReportSourceExcerptReader(store),
            )
            for report_format in ("markdown", "pdf", "sarif"):
                report_version = f"version:report-{report_format}-{suffix}"
                target = artifact(
                    f"artifact:report-{report_format}-{suffix}",
                    project_id=proj["id"],
                    current_version_id=report_version,
                )
                target["kind"] = ArtifactKind.DERIVED
                async with db.transaction() as repos:
                    await repos.artifacts.add(target)
                request = job(f"job:report-{suffix}", task_id=selected["id"], kind=JobKind.REPORT)
                request["arguments"] = {
                    "task_id": selected["id"],
                    "artifact_id": target["id"],
                    "version_id": report_version,
                    "parent_version_id": original["id"],
                    "format": report_format,
                }
                result = await executor.execute(request, asyncio.Event())
                assert result["status"] is JobStatus.SUCCEEDED, result
                assert result["produced_artifact_version_ids"] == [report_version]
                async with db.transaction() as repos:
                    published = await repos.artifacts.get_version(report_version)
                assert published["parent_version_id"] == original["id"]
                assert published["generation_config"]["template_version"] == "2"
                with store.open(published["object_ref"]) as stream:
                    content = stream.read()
                if report_format == "markdown":
                    assert "def read_config" in content.decode()
                    assert "private-value" not in content.decode()
                elif report_format == "pdf":
                    assert content.startswith(b"%PDF-")
                else:
                    assert json.loads(content)["version"] == "2.1.0"
                # A completed immutable report is reused even if later rendering fails.
                with monkeypatch.context() as patch:

                    async def fail_excerpts(*args: object, **kwargs: object) -> None:
                        raise AssertionError("completed report must not be rendered twice")

                    patch.setattr("vulnweaver_reporting.executor.collect_excerpts", fail_excerpts)
                    assert await executor.execute(request, asyncio.Event()) == result
                request["arguments"]["task_id"] = "task:unrelated"
                rejected = await executor.execute(request, asyncio.Event())
                assert rejected["failure"]["code"] == "report.task_mismatch"
            # Even a real, registered version in another project cannot be read.
            source_finding["location"]["artifact_version_id"] = other_version["id"]
            with pytest.raises(ValueError, match="source_outside_task"):
                await collect_excerpts(
                    db, selected, [source_finding], ReportSourceExcerptReader(store)
                )
        finally:
            await db.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("unpacked", [False, True])
def test_binary_report_reads_pair_pseudocode_list(
    persistence_database_url: str, unpacked: bool
) -> None:
    async def scenario() -> None:
        suffix = uuid.uuid4().hex[:10]
        db = Database(DatabaseSettings(persistence_database_url))
        proj = project(f"project:binary-report-{suffix}")
        version = artifact_version(
            f"version:binary-{suffix}", artifact_id=f"artifact:binary-{suffix}"
        )
        selected = task(
            f"task:binary-{suffix}", project_id=proj["id"], artifact_version_ids=[version["id"]]
        )
        analyzed = (
            artifact_version(
                f"version:unpacked-{suffix}",
                artifact_id=version["artifact_id"],
                digest_character="b",
            )
            if unpacked
            else version
        )
        if unpacked:
            analyzed["parent_version_id"] = version["id"]
        location = {
            "artifact_version_id": analyzed["id"],
            "virtual_address": 0x401000,
            "file_offset": None,
        }
        finding = make_finding(location=location)
        function = cast(
            PairFunction,
            {
                "schema_version": "1.0.0",
                "id": f"function:{suffix}",
                "artifact_version_id": version["id"],
                "name": "save_note",
                "symbol": None,
                "language": "c",
                "source_location": None,
                "binary_location": location,
                "signature": None,
                "attributes": {
                    "analyzed_artifact_version_id": analyzed["id"],
                    "pseudocode": [
                        {
                            "text": "void save_note(char *s) { strcpy(buf, s); }",
                            "tool_name": "ghidra",
                            "address": 0x401000,
                        }
                    ],
                },
            },
        )
        try:
            async with db.transaction() as repos:
                await repos.projects.add(proj)
                await repos.artifacts.add(
                    artifact(
                        version["artifact_id"],
                        project_id=proj["id"],
                        current_version_id=version["id"],
                    )
                )
                await repos.artifacts.add_version(version)
                if unpacked:
                    await repos.artifacts.add_version(analyzed)
                await repos.pair.import_graph(
                    [function], [], [], None, created_at=datetime.now(UTC)
                )
            excerpts, errors = await collect_excerpts(db, selected, [finding], None)
            assert not errors
            assert "strcpy(buf, s)" in excerpts["finding:1"]["text"]
            assert "ghidra" in excerpts["finding:1"]["source"]
            assert "非原始源码" in excerpts["finding:1"]["label"]
            assert analyzed["id"] in excerpts["finding:1"]["source"]
            if unpacked:
                # The same address in the packed input is not that code's origin.
                finding["location"]["artifact_version_id"] = version["id"]
                excerpts, errors = await collect_excerpts(db, selected, [finding], None)
                assert not excerpts
                assert "没有已登记" in errors["finding:1"]
        finally:
            await db.dispose()

    asyncio.run(scenario())
