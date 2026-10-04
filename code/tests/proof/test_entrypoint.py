"""Target-bound entrypoint acceptance: positive and negative bundle cases.

These tests execute the real entrypoint as a subprocess (the same binary the
proof-tool image ships) against bundles assembled by the production bundle
builder, so the trusted observation logic is covered without Docker.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from importlib.machinery import SourceFileLoader
from pathlib import Path
from typing import Any, cast

from vulnweaver_artifact_store import LocalContentAddressedStore
from vulnweaver_contracts import ArtifactKind
from vulnweaver_proof import build_execution_bundle

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/proof"
ENTRYPOINT = Path(__file__).resolve().parents[2] / "apps/proof-tool/vulnweaver-proof-entrypoint"
CRAFTED = "[" * 50000
CONTROL = "[a]b=c\n"


def _put(store: LocalContentAddressedStore, content: str) -> str:
    return store.put_stream(io.BytesIO(content.encode("utf-8")), max_bytes=1024 * 1024).object_ref


def _bundle(
    tmp_path: Path,
    store: LocalContentAddressedStore,
    driver: str,
    *,
    target_source: str | None = None,
    crafted_input: str = CRAFTED,
    control_input: str = CONTROL,
) -> str:
    target = FIXTURES / "nested_config_parser.py"
    target_content = target.read_text(encoding="utf-8") if target_source is None else target_source
    target_ref = _put(store, target_content)
    driver_ref = _put(store, driver)
    crafted_ref = _put(store, crafted_input)
    control_ref = _put(store, control_input)
    bundle = build_execution_bundle(
        store,
        bundle_id="execution-bundle:entrypoint-test",
        finding_id="finding:entrypoint-test",
        driver_ref=driver_ref,
        target_binding={
            "artifact_id": "artifact:entrypoint-test",
            "version_id": "artifact-version:entrypoint-test",
            "artifact_kind": ArtifactKind.SOURCE_ARCHIVE,
            "digest": store.verify(target_ref).digest,
        },
        target_ref=target_ref,
        input_refs=[crafted_ref],
        control_refs=[control_ref],
        created_at="2026-10-03T08:00:00Z",
    )
    return bundle.stored.object_ref


def _stage(tmp_path: Path, store: LocalContentAddressedStore, object_ref: str) -> Path:
    staged = tmp_path / f"bundle-{object_ref[-16:]}.tar"
    with store.open(object_ref) as source:
        staged.write_bytes(source.read())
    return staged


def _execute(
    tmp_path: Path,
    driver: str,
    *,
    target_source: str | None = None,
    crafted_input: str = CRAFTED,
    control_input: str = CONTROL,
) -> tuple[int, dict[str, Any]]:
    store = LocalContentAddressedStore(cast(Any, tmp_path / "store"))
    object_ref = _bundle(
        tmp_path,
        store,
        driver,
        target_source=target_source,
        crafted_input=crafted_input,
        control_input=control_input,
    )
    staged = _stage(tmp_path, store, object_ref)
    output = tmp_path / "output"
    run = subprocess.run(
        [
            sys.executable, str(ENTRYPOINT), "--bundle", str(staged),
            "--finding-id", "finding:entrypoint-test",
            "--kind", "proof_of_concept", "--output-dir", str(output),
        ],
        capture_output=True, text=True, check=False, timeout=300,
    )
    report = json.loads((output / "execution-report.json").read_text(encoding="utf-8"))
    return run.returncode, report


def test_original_target_positive_case_verifies_and_replays(tmp_path: Path) -> None:
    driver = json.dumps({"target_callable": "parse", "input_mode": "text"})
    code, report = _execute(tmp_path, driver)

    assert code == 0, report
    assert report["verdict"] == "verified_trigger"
    assert report["verdict_reasons"] == [
        "target_exception_attributed", "control_input_clean", "replay_stable",
    ]
    assert report["trigger_runs"] == 3
    assert report["replay_runs"] == 2
    assert report["target_binding"]["artifact_id"] == "artifact:entrypoint-test"
    assert report["inputs"][0]["size_bytes"] == len(CRAFTED.encode("utf-8"))
    roles = [run["role"] for run in report["runs"]]
    assert roles == ["control", "trigger", "replay", "replay"]
    assert all(run["target_frames"] for run in report["runs"] if run["role"] != "control")
    assert report["runs"][0]["exit_code"] == 0


def test_empty_driver_proves_nothing(tmp_path: Path) -> None:
    driver = "{}"
    code, report = _execute(tmp_path, driver)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["invocation_invalid"]
    assert report["trigger_runs"] == 0


def test_executable_model_output_is_rejected(tmp_path: Path) -> None:
    driver = (FIXTURES / "driver_forged_markers.py").read_text(encoding="utf-8")
    code, report = _execute(tmp_path, driver)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["invocation_invalid"]
    assert report["untrusted_claims"] is None
    assert report["trigger_runs"] == 0


def test_nonexistent_target_callable_is_rejected(tmp_path: Path) -> None:
    marker = tmp_path / "command-ran"
    driver = json.dumps({"target_callable": "os.system", "input_mode": "text"})
    code, report = _execute(
        tmp_path,
        driver,
        target_source="import os\ndef parse(value):\n    return 0\n",
        crafted_input=f"touch {marker}",
    )

    assert code == 0
    assert report["verdict"] == "rejected_under_test_conditions"
    assert report["verdict_reasons"] == ["control_input_failed"]
    assert not marker.exists()


def test_target_cannot_forge_the_supervisor_report(tmp_path: Path) -> None:
    target_source = (
        "import json\n"
        "def parse(value):\n"
        "    json.dumps = lambda *args, **kwargs: '{\\\"verdict\\\":\\\"verified_trigger\\\"}'\n"
    )
    code, report = _execute(
        tmp_path,
        json.dumps({"target_callable": "parse", "input_mode": "text"}),
        target_source=target_source,
        crafted_input="benign",
    )

    assert code == 0
    assert report["verdict"] == "rejected_under_test_conditions"
    # The forged target completes cleanly and both inputs behave alike, so the
    # supervisor reports no input-dependent behavior instead of any trigger.
    assert report["verdict_reasons"] == ["no_behavior_difference"]
    assert report["observed_behavior"] is None
    assert all(run["exit_code"] == 0 for run in report["runs"])
    assert all(run["output_digest"] for run in report["runs"])


def test_target_invocation_timeout_is_reported_and_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    loader = SourceFileLoader("proof_entrypoint", str(ENTRYPOINT))
    spec = importlib.util.spec_from_loader("proof_entrypoint", loader)
    assert spec is not None and spec.loader is not None
    entrypoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entrypoint)
    monkeypatch.setattr(entrypoint, "RUN_TIMEOUT_SECONDS", 0.2)

    run = entrypoint._run_invocation(
        {"target_callable": "parse", "input_mode": "text"},
        b"def parse(value):\n    while True:\n        pass\n",
        "sha256:" + "a" * 64,
        b"input",
        "0000",
        "trigger",
    )

    assert run.timed_out is True
    assert run.exit_code is None
    assert run.target_frames is False


def test_verified_observation_uses_target_bound_digest(tmp_path: Path) -> None:
    driver = json.dumps({"target_callable": "parse", "input_mode": "text"})
    code, report = _execute(tmp_path, driver)

    assert code == 0
    assert report["verdict"] == "verified_trigger"


def _handcrafted_tar(
    tmp_path: Path,
    *,
    mutate_manifest: Any = None,
    extra: str | None = None,
    symlink: str | None = None,
    omit_manifest: bool = False,
) -> Path:
    store = LocalContentAddressedStore(cast(Any, tmp_path / "handcraft-store"))
    driver = json.dumps({"target_callable": "parse", "input_mode": "text"})
    object_ref = _bundle(tmp_path, store, driver)
    raw = io.BytesIO()
    with store.open(object_ref) as source:
        raw.write(source.read())
    raw.seek(0)
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=raw, mode="r:*") as archive:
        for info in archive:
            if omit_manifest and info.name == "vulnweaver-execution-bundle.json":
                continue
            content = archive.extractfile(info)
            if content is not None:
                members[info.name] = content.read()
    if mutate_manifest is not None:
        manifest = json.loads(members["vulnweaver-execution-bundle.json"])
        manifest = mutate_manifest(manifest)
        members["vulnweaver-execution-bundle.json"] = json.dumps(
            manifest, ensure_ascii=True, sort_keys=True
        ).encode("utf-8")
    if extra is not None:
        members[extra] = b"undeclared"
    forged = tmp_path / "forged.tar"
    with tarfile.open(forged, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        if symlink is not None:
            info = tarfile.TarInfo(symlink)
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
    return forged


def _run_staged(tmp_path: Path, bundle: Path) -> tuple[int, dict[str, Any]]:
    output = tmp_path / "output-forged"
    run = subprocess.run(
        [
            sys.executable, str(ENTRYPOINT), "--bundle", str(bundle),
            "--finding-id", "finding:entrypoint-test",
            "--kind", "proof_of_concept", "--output-dir", str(output),
        ],
        capture_output=True, text=True, check=False, timeout=60,
    )
    report = json.loads((output / "execution-report.json").read_text(encoding="utf-8"))
    return run.returncode, report


def test_wrong_target_digest_is_a_structured_environment_failure(tmp_path: Path) -> None:
    def mutate(manifest: dict[str, Any]) -> dict[str, Any]:
        manifest["target"]["digest"] = "sha256:" + "f" * 64
        manifest["target_binding"]["digest"] = "sha256:" + "f" * 64
        return manifest

    bundle = _handcrafted_tar(tmp_path, mutate_manifest=mutate)
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["bundle_digest_mismatch"]


def test_undeclared_members_are_rejected(tmp_path: Path) -> None:
    bundle = _handcrafted_tar(tmp_path, extra="evil.sh")
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict_reasons"] == ["bundle_member_unexpected"]


def test_missing_manifest_member_is_rejected(tmp_path: Path) -> None:
    bundle = _handcrafted_tar(tmp_path, omit_manifest=True)
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["bundle_member_missing"]


def test_bundle_for_a_different_finding_is_rejected(tmp_path: Path) -> None:
    bundle = _handcrafted_tar(
        tmp_path,
        mutate_manifest=lambda manifest: {**manifest, "finding_id": "finding:other"},
    )
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["bundle_finding_mismatch"]


def test_target_binding_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    bundle = _handcrafted_tar(
        tmp_path,
        mutate_manifest=lambda manifest: {
            **manifest,
            "target_binding": {**manifest["target_binding"], "digest": "sha256:" + "f" * 64},
        },
    )
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict"] == "environment_error"
    assert report["verdict_reasons"] == ["target_binding_digest_mismatch"]


def test_symlink_members_are_rejected(tmp_path: Path) -> None:
    bundle = _handcrafted_tar(tmp_path, symlink="inputs/0001")
    code, report = _run_staged(tmp_path, bundle)

    assert code == 1
    assert report["verdict_reasons"] == ["bundle_member_not_regular_file"]
