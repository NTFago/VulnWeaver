"""CR-08: aggregate truncation must be explicit, not silent.

A collection capped by its configured limit has to say so — with the offered
count, the retained count, the limit and a reason — so downstream agents and
reports can tell "complete analysis" from "the tool stopped early".
"""

from __future__ import annotations

from typing import cast

from vulnweaver_binary_analysis.headers import StringExtraction
from vulnweaver_binary_analysis.types import (
    BinaryAnalysisAggregate,
    BinaryAnalysisLimits,
    BinaryMetadata,
    ToolContribution,
)
from vulnweaver_contracts import (
    BinaryFormat,
    BinaryToolRun,
    validate_contract,
)

from tests.binary_analysis.samples import elf64_sample
from tests.binary_analysis.samples import metadata as _metadata


def _run(name: str) -> BinaryToolRun:
    return BinaryToolRun(
        tool_name=cast(str, name),
        tool_version="1.0.0",
        status="succeeded",
        exit_code=0,
        reason=None,
        raw_output=None,
    )


def _function(address: int, name: str):
    return {
        "name": name,
        "address": address,
        "size": 16,
        "file_offset": None,
        "attributes": {},
    }


def _contribution(name: str, functions: list, imports: list | None = None) -> ToolContribution:
    return ToolContribution(
        run=_run(name),
        functions=tuple(functions),
        imports=tuple(imports or []),
    )


def test_merge_records_truncation_per_collection() -> None:
    aggregate = BinaryAnalysisAggregate(_metadata())
    limits = BinaryAnalysisLimits(max_functions=2, max_imports=1)
    first = _contribution(
        "tool-a",
        [_function(0x1000, "a"), _function(0x2000, "b")],
        [{"library": "libc", "name": "open", "ordinal": None, "address": None}],
    )
    aggregate.merge(first, limits)

    second = _contribution(
        "tool-b",
        [_function(0x3000, "c"), _function(0x4000, "d")],
        [{"library": "libc", "name": "read", "ordinal": None, "address": None}],
    )
    aggregate.merge(second, limits)

    coverage = aggregate.coverage()
    functions = coverage["functions"]
    assert functions["offered"] == 4
    assert functions["retained"] == 2
    assert functions["limit"] == 2
    assert functions["truncated"] is True
    assert "2 unique items dropped" in functions["reason"]
    imports = coverage["imports"]
    assert imports["offered"] == 2
    assert imports["retained"] == 1
    assert imports["limit"] == 1
    assert imports["truncated"] is True
    assert coverage["complete"] is False


def test_merge_deduplication_is_not_truncation() -> None:
    aggregate = BinaryAnalysisAggregate(_metadata())
    limits = BinaryAnalysisLimits(max_functions=8)
    aggregate.merge(_contribution("tool-a", [_function(0x1000, "a")]), limits)
    # Same function offered again by another tool: a dedup drop, not data loss.
    aggregate.merge(_contribution("tool-b", [_function(0x1000, "a")]), limits)

    coverage = aggregate.coverage()
    assert coverage["functions"]["offered"] == 2
    assert coverage["functions"]["retained"] == 1
    assert coverage["functions"]["truncated"] is False
    assert coverage["functions"]["reason"] is None
    assert coverage["complete"] is True


def test_string_extraction_reports_where_it_stopped(tmp_path) -> None:
    """Reaching the cap is the truncation signal, not a count of what was left.

    The extractor stops as soon as the cap is full, so `offered` is what it
    examined; counting the whole input instead would mean scanning every byte of
    both encodings for a number nothing acts on.
    """
    from vulnweaver_binary_analysis.headers import extract_strings

    sample = tmp_path / "strings.bin"
    sample.write_bytes(b"".join(b"string-%04d\x00" % index for index in range(10)))
    extraction = extract_strings(
        sample,
        _metadata(),
        BinaryAnalysisLimits(max_strings=3, min_string_chars=6),
    )
    assert isinstance(extraction, StringExtraction)
    assert len(extraction.strings) == 3
    assert extraction.offered == 3, "the walk ended at the cap"
    assert extraction.limit == 3
    assert extraction.truncated is True

    # Below the cap the walk does finish, and then the count is a total.
    complete = extract_strings(
        sample,
        _metadata(),
        BinaryAnalysisLimits(max_strings=10, min_string_chars=6),
    )
    assert len(complete.strings) == 10
    assert complete.offered == 10
    assert complete.truncated is True, (
        "an input holding exactly `limit` candidates is indistinguishable from "
        "one holding more, which is the point of the conservative signal"
    )

    roomy = extract_strings(
        sample,
        _metadata(),
        BinaryAnalysisLimits(max_strings=64, min_string_chars=6),
    )
    assert roomy.offered == len(roomy.strings) == 10
    assert roomy.truncated is False


def test_build_result_carries_coverage_through_the_contract(tmp_path) -> None:
    """The persisted result document exposes coverage and validates cleanly."""
    import json

    from vulnweaver_binary_analysis.executor import _build_result

    aggregate = BinaryAnalysisAggregate(_metadata())
    aggregate.merge(
        _contribution("tool-a", [_function(0x1000, "a")]),
        BinaryAnalysisLimits(max_functions=1, max_imports=1),
    )
    aggregate.merge(
        _contribution("tool-b", [_function(0x2000, "b")]),
        BinaryAnalysisLimits(max_functions=1, max_imports=1),
    )
    result = _build_result(
        "artifact-version:1",
        "artifact-version:1",
        aggregate,
        created_at="2026-10-04T00:00:00Z",
    )
    document = json.loads(json.dumps(result))
    validate_contract("BinaryAnalysisResult", document)
    coverage = document["coverage"]
    assert coverage["functions"]["truncated"] is True
    assert coverage["functions"]["offered"] == 2
    assert coverage["functions"]["retained"] == 1
    assert coverage["complete"] is False


def test_sample_binary_round_trip_reports_complete_analysis(tmp_path) -> None:
    """A small sample under every limit must read as complete, not truncated."""
    from vulnweaver_binary_analysis.headers import extract_strings

    sample = tmp_path / "sample.elf"
    sample.write_bytes(elf64_sample())
    metadata = BinaryMetadata(
        format=BinaryFormat.ELF,
        architecture="x86_64",
        bits=64,
        endianness="little",
        image_base=0x400000,
        entry_point=0x1000,
        sections=(),
    )
    extraction = extract_strings(sample, metadata, BinaryAnalysisLimits())
    assert extraction.truncated is False
    assert extraction.offered == len(extraction.strings)
