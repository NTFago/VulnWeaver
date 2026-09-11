"""Connect the existing safe archive reader to report code blocks."""

from vulnweaver_artifact_store import ArtifactStore, ArtifactStoreError
from vulnweaver_contracts import ArtifactVersion, SourceLocation
from vulnweaver_reporting import CodeExcerpt
from vulnweaver_source_analysis import SourceExcerptReader, SourceImportError


class ReportSourceExcerptReader:
    def __init__(self, store: ArtifactStore) -> None:
        self._reader = SourceExcerptReader(store)

    def __call__(self, version: ArtifactVersion, location: SourceLocation) -> CodeExcerpt:
        try:
            excerpt = self._reader.read(version, location)
        except (SourceImportError, ArtifactStoreError) as error:
            raise ValueError("report source excerpt unavailable") from error
        return CodeExcerpt(
            text=excerpt.text,
            label="原始源码",
            source=(
                f"{version['id']} · {excerpt.path}:{excerpt.start_line}-{excerpt.end_line}"
                f" · {excerpt.file_digest}"
            ),
            first_line=excerpt.start_line,
            truncated=excerpt.truncated,
        )
