"""Supported source languages: extensions, grammars, node tables, tool coverage.

Single source of truth for language handling across source indexing and static
tool dispatch.  Adding a language means one ``LanguageSpec`` entry here, its
tree-sitter grammar dependency in ``pyproject.toml``, and - when the language is
covered - rules in ``deploy/tool-specs/semgrep-rules.yml``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    """One supported language and how the pipeline treats it.

    ``*_types`` name tree-sitter node kinds for the grammar named by
    ``grammar_module``; ``callee_fields`` is the ordered list of tree-sitter
    fields tried when extracting a call's callee expression.
    """

    name: str
    extensions: tuple[str, ...]
    grammar_module: str
    function_types: frozenset[str]
    call_types: frozenset[str]
    class_types: frozenset[str]
    # Some grammars (kotlin, swift) give the call node no callee field at all;
    # the indexer then falls back to the first named child that is not an
    # argument container.
    callee_fields: tuple[str, ...] = ("function", "name", "type")
    # Module attribute returning the language PyCapsule.  Most grammar packages
    # expose ``language()``; the multi-grammar ones (typescript, php) do not.
    grammar_entry: str = "language"
    static_tools: frozenset[str] = frozenset({"semgrep"})


_LANGUAGES: tuple[LanguageSpec, ...] = (
    LanguageSpec(
        name="c",
        extensions=(".c", ".h"),
        grammar_module="tree_sitter_c",
        function_types=frozenset({"function_definition"}),
        call_types=frozenset({"call_expression"}),
        class_types=frozenset({"struct_specifier", "union_specifier"}),
        callee_fields=("function",),
        static_tools=frozenset({"semgrep", "cppcheck"}),
    ),
    LanguageSpec(
        name="cpp",
        extensions=(".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"),
        grammar_module="tree_sitter_cpp",
        function_types=frozenset({"function_definition"}),
        call_types=frozenset({"call_expression"}),
        class_types=frozenset({"class_specifier", "struct_specifier", "namespace_definition"}),
        callee_fields=("function",),
        static_tools=frozenset({"semgrep", "cppcheck"}),
    ),
    LanguageSpec(
        name="python",
        extensions=(".py", ".pyi"),
        grammar_module="tree_sitter_python",
        function_types=frozenset({"function_definition"}),
        call_types=frozenset({"call"}),
        class_types=frozenset({"class_definition"}),
        callee_fields=("function",),
    ),
    LanguageSpec(
        name="java",
        extensions=(".java",),
        grammar_module="tree_sitter_java",
        function_types=frozenset({"method_declaration", "constructor_declaration"}),
        call_types=frozenset({"method_invocation", "object_creation_expression"}),
        class_types=frozenset({"class_declaration", "interface_declaration", "enum_declaration"}),
        callee_fields=("name", "type"),
    ),
    LanguageSpec(
        name="javascript",
        extensions=(".js", ".jsx", ".mjs", ".cjs"),
        grammar_module="tree_sitter_javascript",
        function_types=frozenset(
            {"function_declaration", "generator_function_declaration", "method_definition"}
        ),
        call_types=frozenset({"call_expression", "new_expression"}),
        class_types=frozenset({"class_declaration"}),
        callee_fields=("function", "constructor"),
    ),
    LanguageSpec(
        name="typescript",
        extensions=(".ts", ".tsx", ".mts", ".cts"),
        grammar_module="tree_sitter_typescript",
        grammar_entry="language_typescript",
        function_types=frozenset(
            {"function_declaration", "generator_function_declaration", "method_definition"}
        ),
        call_types=frozenset({"call_expression", "new_expression"}),
        class_types=frozenset({"class_declaration", "abstract_class_declaration"}),
        callee_fields=("function", "constructor"),
    ),
    LanguageSpec(
        name="go",
        extensions=(".go",),
        grammar_module="tree_sitter_go",
        function_types=frozenset({"function_declaration", "method_declaration"}),
        call_types=frozenset({"call_expression"}),
        class_types=frozenset(),
        callee_fields=("function",),
    ),
    LanguageSpec(
        name="rust",
        extensions=(".rs",),
        grammar_module="tree_sitter_rust",
        function_types=frozenset({"function_item"}),
        call_types=frozenset({"call_expression", "macro_invocation"}),
        # impl_item scopes methods to their implementing type; it has no name
        # field, so the indexer reads its "type" field for the scope name.
        class_types=frozenset({"struct_item", "enum_item", "trait_item", "impl_item"}),
        callee_fields=("function", "macro"),
    ),
    LanguageSpec(
        name="csharp",
        extensions=(".cs",),
        grammar_module="tree_sitter_c_sharp",
        function_types=frozenset(
            {"method_declaration", "constructor_declaration", "local_function_statement"}
        ),
        call_types=frozenset({"invocation_expression", "object_creation_expression"}),
        class_types=frozenset(
            {
                "class_declaration",
                "interface_declaration",
                "struct_declaration",
                "record_declaration",
            }
        ),
        callee_fields=("function", "type"),
    ),
    LanguageSpec(
        name="php",
        extensions=(".php", ".phtml"),
        grammar_module="tree_sitter_php",
        grammar_entry="language_php",
        function_types=frozenset({"function_definition", "method_declaration"}),
        call_types=frozenset(
            {
                "function_call_expression",
                "call_expression",
                "member_call_expression",
                "nullsafe_member_call_expression",
                "scoped_call_expression",
                "object_creation_expression",
            }
        ),
        class_types=frozenset({"class_declaration", "interface_declaration", "trait_declaration"}),
        callee_fields=("function", "name"),
    ),
    LanguageSpec(
        name="ruby",
        extensions=(".rb", ".rake", ".gemspec"),
        grammar_module="tree_sitter_ruby",
        function_types=frozenset({"method", "singleton_method"}),
        call_types=frozenset({"call"}),
        class_types=frozenset({"class", "module", "singleton_class"}),
        callee_fields=("method", "name"),
    ),
    LanguageSpec(
        name="kotlin",
        extensions=(".kt", ".kts"),
        grammar_module="tree_sitter_kotlin",
        function_types=frozenset({"function_declaration"}),
        call_types=frozenset({"call_expression"}),
        class_types=frozenset({"class_declaration", "object_declaration"}),
        callee_fields=(),
    ),
    LanguageSpec(
        name="swift",
        extensions=(".swift",),
        grammar_module="tree_sitter_swift",
        function_types=frozenset({"function_declaration"}),
        call_types=frozenset({"call_expression"}),
        class_types=frozenset({"class_declaration", "struct_declaration", "protocol_declaration"}),
        callee_fields=(),
    ),
)

#: Registry order also drives capability-profile ordering (stable languages
#: first, then languages added over time).
LANGUAGES: dict[str, LanguageSpec] = {spec.name: spec for spec in _LANGUAGES}

EXTENSION_LANGUAGES: dict[str, str] = {
    extension.casefold(): spec.name
    for spec in _LANGUAGES
    for extension in spec.extensions
}

BUILD_FILES: dict[str, str] = {
    "cmakelists.txt": "cmake",
    "makefile": "make",
    "meson.build": "meson",
    "configure.ac": "autotools",
    "pyproject.toml": "python-pyproject",
    "setup.py": "python-setuptools",
    "requirements.txt": "python-requirements",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "go.mod": "go-modules",
    "cargo.toml": "cargo",
    "package.json": "npm",
    "composer.json": "composer",
    "gemfile": "bundler",
}

# Project files whose names embed the product name ("Shop.csproj") cannot be
# matched by exact filename and are detected by suffix instead.
BUILD_FILE_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".csproj", "dotnet"),
    (".sln", "dotnet-solution"),
    (".fsproj", "dotnet"),
)


def build_system_for(file_name: str) -> str | None:
    lowered = file_name.casefold()
    system = BUILD_FILES.get(lowered)
    if system is not None:
        return system
    for suffix, suffix_system in BUILD_FILE_SUFFIXES:
        if lowered.endswith(suffix):
            return suffix_system
    return None


def static_tool_languages(tool: str) -> frozenset[str]:
    """Languages a static tool can meaningfully scan."""
    return frozenset(
        spec.name for spec in _LANGUAGES if tool in spec.static_tools
    )
