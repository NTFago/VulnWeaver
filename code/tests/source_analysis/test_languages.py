"""Registry invariants for supported source languages."""

from __future__ import annotations

from vulnweaver_source_analysis import LANGUAGES, static_tool_languages
from vulnweaver_source_analysis.languages import build_system_for


def test_every_language_has_unique_extensions() -> None:
    seen: dict[str, str] = {}
    for name, spec in LANGUAGES.items():
        assert spec.extensions, f"language {name} has no file extensions"
        for extension in spec.extensions:
            lowered = extension.casefold()
            assert lowered.startswith("."), (
                f"extension {extension!r} of {name} must include its leading dot"
            )
            owner = seen.get(lowered)
            assert owner is None, f"extension {lowered} claimed by both {owner} and {name}"
            seen[lowered] = name


def test_grammar_modules_resolve_and_expose_entry() -> None:
    import importlib

    for name, spec in LANGUAGES.items():
        module = importlib.import_module(spec.grammar_module)
        assert callable(getattr(module, spec.grammar_entry, None)), (
            f"grammar module {spec.grammar_module} of {name} lacks {spec.grammar_entry}()"
        )


def test_static_tool_language_coverage() -> None:
    assert static_tool_languages("cppcheck") == {"c", "cpp"}
    assert static_tool_languages("semgrep") == set(LANGUAGES)
    assert static_tool_languages("unknown-tool") == set()


def test_build_system_detection() -> None:
    assert build_system_for("go.mod") == "go-modules"
    assert build_system_for("Cargo.toml") == "cargo"
    assert build_system_for("package.json") == "npm"
    assert build_system_for("Gemfile") == "bundler"
    assert build_system_for("composer.json") == "composer"
    assert build_system_for("Shop.csproj") == "dotnet"
    assert build_system_for("Shop.sln") == "dotnet-solution"
    assert build_system_for("MAKEFILE") == "make"
    assert build_system_for("README.md") is None
