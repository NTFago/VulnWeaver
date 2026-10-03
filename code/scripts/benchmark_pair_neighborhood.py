"""CR-07 baseline: PAIR neighborhood and full-function-load cost on a big graph.

Seeds a synthetic but realistically shaped PAIR version (functions with
instruction nodes and call/control-flow edges, like a Ghidra pass over a real
binary), then measures what one agent investigation actually pays:

* ``PairRepository.neighborhood`` (per diagnostic/call-path step),
* ``PairRepository.list_functions`` (the full load both the audit entry point
  and the agent workspace used to repeat).

Run inside the dev container against the stack database:

    uv run --no-sync python scripts/benchmark_pair_neighborhood.py [--functions 2000]

The script creates its own throwaway database (``vulnweaver_bench_<hex>``),
migrates it, prints the measured medians, and drops the database.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import create_engine
from vulnweaver_contracts import PairEdge, PairFunction, PairNode, PairRaw
from vulnweaver_persistence import Database, DatabaseSettings, upgrade_database

NOW = datetime.now(UTC)
TIMESTAMP = NOW.isoformat().replace("+00:00", "Z")


def _function(identifier: str, version_id: str, index: int) -> PairFunction:
    return PairFunction(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        name=f"fn_{index:06d}",
        symbol=f"fn_{index:06d}",
        language="x86_64",
        source_location=None,
        binary_location={
            "artifact_version_id": version_id,
            "image_base": 0x400000,
            "virtual_address": 0x1000 + index * 64,
            "file_offset": 0x1000 + index * 64,
            "instruction_end": 0x1000 + index * 64 + 64,
        },
        signature=None,
        attributes={},
    )


def _node(identifier: str, version_id: str, function_id: str, index: int) -> PairNode:
    return PairNode(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        function_id=function_id,
        kind="instruction",
        location={
            "artifact_version_id": version_id,
            "image_base": 0x400000,
            "virtual_address": 0x1000 + index,
            "file_offset": 0x1000 + index,
        },
        attributes={"mnemonic": "mov"},
    )


def _edge(identifier: str, version_id: str, source: str, target: str) -> PairEdge:
    return PairEdge(
        schema_version="1.0.0",
        id=identifier,
        artifact_version_id=version_id,
        source_node_id=source,
        target_node_id=target,
        type="call",
        scope="binary-call",
        confidence=1.0,
        evidence_id=None,
        attributes={},
    )


def build_graph(function_count: int) -> tuple[list[PairFunction], list[PairNode], list[PairEdge]]:
    """1 function node + 9 instruction nodes per function; intra-function flow
    edges plus a call edge into the next function (call-graph shape)."""

    functions: list[PairFunction] = []
    nodes: list[PairNode] = []
    edges: list[PairEdge] = []
    for index in range(function_count):
        version_id = "artifact-version:bench"
        function_id = f"pair-function:bench:{index:06d}"
        functions.append(_function(function_id, version_id, index))
        function_node = f"pair-node:bench:fn:{index:06d}"
        nodes.append(
            PairNode(
                schema_version="1.0.0",
                id=function_node,
                artifact_version_id=version_id,
                function_id=function_id,
                kind="function",
                location={
                    "artifact_version_id": version_id,
                    "image_base": 0x400000,
                    "virtual_address": 0x1000 + index * 64,
                    "file_offset": 0x1000 + index * 64,
                },
                attributes={"name": f"fn_{index:06d}"},
            )
        )
        previous_instruction = None
        for offset in range(9):
            node_id = f"pair-node:bench:ins:{index:06d}:{offset}"
            nodes.append(_node(node_id, version_id, function_id, index * 64 + offset))
            if previous_instruction is not None:
                edges.append(
                    _edge(
                        f"pair-edge:bench:flow:{index:06d}:{offset}",
                        version_id,
                        previous_instruction,
                        node_id,
                    )
                )
            previous_instruction = node_id
        if index + 1 < function_count:
            edges.append(
                _edge(
                    f"pair-edge:bench:call:{index:06d}",
                    version_id,
                    function_node,
                    f"pair-node:bench:fn:{index + 1:06d}",
                )
            )
    return functions, nodes, edges


def _median(values: list[float]) -> float:
    return statistics.median(values)


async def measure(function_count: int, repeats: int) -> dict[str, float]:
    admin_url = "postgresql+psycopg://vulnweaver:vulnweaver_dev_only@postgres:5432/postgres"
    database_name = f"vulnweaver_bench_{uuid.uuid4().hex[:12]}"
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as connection:
        connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
    url = f"postgresql+psycopg://vulnweaver:vulnweaver_dev_only@postgres:5432/{database_name}"
    try:
        upgrade_database(url)
        database = Database(DatabaseSettings(url))
        functions, nodes, edges = build_graph(function_count)
        raw = PairRaw(
            schema_version="1.0.0",
            id="pair-raw:bench",
            artifact_version_id="artifact-version:bench",
            tool={"name": "bench", "version": "1.0.0", "image_digest": None},
            format="binary-analysis-result",
            object_ref="cas://bench",
            created_at=TIMESTAMP,
        )
        seed_start = time.perf_counter()
        async with database.transaction() as repositories:
            from tests.persistence.factories import artifact, artifact_version, project, task

            await repositories.projects.add(project("project:bench"))
            await repositories.artifacts.add(
                artifact(
                    "artifact:bench",
                    project_id="project:bench",
                    current_version_id="artifact-version:bench",
                )
            )
            await repositories.artifacts.add_version(
                artifact_version("artifact-version:bench", artifact_id="artifact:bench")
            )
            await repositories.tasks.create(
                task(
                    "task:bench",
                    project_id="project:bench",
                    artifact_version_ids=["artifact-version:bench"],
                )
            )
            await repositories.pair.import_graph(functions, nodes, edges, raw, created_at=NOW)
        seed_seconds = time.perf_counter() - seed_start

        anchor_id = functions[len(functions) // 2]["id"]
        neighborhood_seconds: list[float] = []
        neighborhood_rows: list[int] = []
        for _ in range(repeats):
            start = time.perf_counter()
            async with database.transaction() as repositories:
                result = await repositories.pair.neighborhood(
                    "artifact-version:bench", anchor_id, depth=1
                )
            neighborhood_seconds.append(time.perf_counter() - start)
            neighborhood_rows.append(
                len(result["functions"]) + len(result["nodes"]) + len(result["edges"])
            )

        list_seconds: list[float] = []
        list_rows: list[int] = []
        for _ in range(repeats):
            start = time.perf_counter()
            async with database.transaction() as repositories:
                loaded = await repositories.pair.list_functions("artifact-version:bench")
            list_seconds.append(time.perf_counter() - start)
            list_rows.append(len(loaded))
        await database.dispose()
        return {
            "seed_seconds": seed_seconds,
            "neighborhood_seconds": _median(neighborhood_seconds),
            "neighborhood_rows": _median([float(value) for value in neighborhood_rows]),
            "list_functions_seconds": _median(list_seconds),
            "list_functions_rows": _median([float(value) for value in list_rows]),
        }
    finally:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE "{database_name}" WITH (FORCE)')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--functions", type=int, default=2000)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    results = asyncio.run(measure(args.functions, args.repeats))
    print(f"functions={args.functions} repeats={args.repeats}")
    for key, value in results.items():
        label = key.removesuffix("_seconds").replace("_", " ")
        if key.endswith("_seconds"):
            print(f"  {label}: {value * 1000:.1f} ms")
        else:
            print(f"  {label}: {value:.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
