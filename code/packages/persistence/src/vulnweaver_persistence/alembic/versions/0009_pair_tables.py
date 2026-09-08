"""Create PAIR source/binary graph relation tables."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009_pair_tables"
down_revision: str | None = "0008_job_tool_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _schema_check() -> sa.CheckConstraint:
    return sa.CheckConstraint("schema_version = '1.0.0'", name="schema_version_v1")


def upgrade() -> None:
    op.create_table(
        "pair_functions",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("artifact_version_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(2048), nullable=False),
        sa.Column("symbol", sa.String(2048), nullable=True),
        sa.Column("language", sa.String(128), nullable=False),
        sa.Column("source_location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("binary_location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        _schema_check(),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_pair_functions"),
        sa.UniqueConstraint("artifact_version_id", "id", name="uq_pair_functions_version_id"),
    )
    op.create_index(
        "ix_pair_functions_artifact_version_id",
        "pair_functions",
        ["artifact_version_id"],
    )
    op.create_index(
        "ix_pair_functions_source_path",
        "pair_functions",
        [sa.text("((source_location ->> 'path'))")],
        postgresql_using="btree",
    )

    op.create_table(
        "pair_nodes",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("artifact_version_id", sa.String(128), nullable=False),
        sa.Column("function_id", sa.String(128), nullable=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("location", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        _schema_check(),
        sa.CheckConstraint(
            "kind IN ('function', 'basic_block', 'instruction', 'parameter', "
            "'variable', 'memory_object', 'source_location')",
            name="kind",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["function_id"], ["pair_functions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_pair_nodes"),
        sa.UniqueConstraint("artifact_version_id", "id", name="uq_pair_nodes_version_id"),
    )
    op.create_index("ix_pair_nodes_function_id", "pair_nodes", ["function_id"])
    op.create_index("ix_pair_nodes_artifact_version_id", "pair_nodes", ["artifact_version_id"])

    op.create_table(
        "pair_edges",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("artifact_version_id", sa.String(128), nullable=False),
        sa.Column("source_node_id", sa.String(128), nullable=False),
        sa.Column("target_node_id", sa.String(128), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("scope", sa.String(128), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_id", sa.String(128), nullable=True),
        sa.Column("attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        _schema_check(),
        sa.CheckConstraint(
            "type IN ('call', 'control_flow', 'def_use', 'data_flow', 'taint', 'xref')",
            name="type",
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["source_node_id"], ["pair_nodes.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_node_id"], ["pair_nodes.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id", name="pk_pair_edges"),
        sa.UniqueConstraint(
            "artifact_version_id",
            "source_node_id",
            "target_node_id",
            "type",
            "scope",
            name="uq_pair_edges_identity",
        ),
    )
    op.create_index("ix_pair_edges_source_node_id", "pair_edges", ["source_node_id"])
    op.create_index("ix_pair_edges_target_node_id", "pair_edges", ["target_node_id"])

    op.create_table(
        "pair_raw",
        sa.Column("id", sa.String(128), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False),
        sa.Column("artifact_version_id", sa.String(128), nullable=False),
        sa.Column("tool", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("format", sa.String(128), nullable=False),
        sa.Column("object_ref", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        _schema_check(),
        sa.ForeignKeyConstraint(
            ["artifact_version_id"], ["artifact_versions.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_pair_raw"),
        sa.UniqueConstraint(
            "artifact_version_id", "tool", "format", "object_ref", name="uq_pair_raw_identity"
        ),
    )
    op.create_index("ix_pair_raw_artifact_version_id", "pair_raw", ["artifact_version_id"])


def downgrade() -> None:
    op.drop_index("ix_pair_raw_artifact_version_id", table_name="pair_raw")
    op.drop_table("pair_raw")
    op.drop_index("ix_pair_edges_target_node_id", table_name="pair_edges")
    op.drop_index("ix_pair_edges_source_node_id", table_name="pair_edges")
    op.drop_table("pair_edges")
    op.drop_index("ix_pair_nodes_artifact_version_id", table_name="pair_nodes")
    op.drop_index("ix_pair_nodes_function_id", table_name="pair_nodes")
    op.drop_table("pair_nodes")
    op.drop_index("ix_pair_functions_source_path", table_name="pair_functions")
    op.drop_index("ix_pair_functions_artifact_version_id", table_name="pair_functions")
    op.drop_table("pair_functions")
