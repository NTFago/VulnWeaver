# VulnWeaver Source Analysis Worker

The worker consumes only structured `job.requested` messages. It reads the immutable
content-addressed source archive, extracts it with bounded safe-archive rules, indexes
C/C++/Python/Java functions and calls with tree-sitter, and stores the resulting
`SourceImportResult` as a derived immutable artifact with parent/tool lineage.

It has no Docker Socket and does not run build systems, package managers, Git hooks,
submodules, or arbitrary commands. Its root filesystem is read-only in Compose; only
the service-owned artifact volume and temporary scratch space are writable.
