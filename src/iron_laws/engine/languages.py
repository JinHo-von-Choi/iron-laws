"""
오철칙 언어 식별과 tree-sitter 파서 관리
작성자: 최진호
작성일: 2026-10-04
"""

from enum import StrEnum
from functools import cache
from pathlib import Path

from tree_sitter import Language, Parser


class Lang(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    JAVA = "java"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    C = "c"
    CPP = "cpp"


JS_FAMILY = frozenset({Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.TSX})
TS_FAMILY = frozenset({Lang.TYPESCRIPT, Lang.TSX})
C_FAMILY = frozenset({Lang.C, Lang.CPP})
ALL_LANGS = frozenset(Lang)

EXTENSION_TO_LANG: dict[str, Lang] = {
    ".py": Lang.PYTHON,
    ".js": Lang.JAVASCRIPT,
    ".jsx": Lang.JAVASCRIPT,
    ".mjs": Lang.JAVASCRIPT,
    ".cjs": Lang.JAVASCRIPT,
    ".ts": Lang.TYPESCRIPT,
    ".mts": Lang.TYPESCRIPT,
    ".cts": Lang.TYPESCRIPT,
    ".tsx": Lang.TSX,
    ".java": Lang.JAVA,
    ".cs": Lang.CSHARP,
    ".go": Lang.GO,
    ".rs": Lang.RUST,
    ".php": Lang.PHP,
    ".c": Lang.C,
    ".h": Lang.C,
    ".cpp": Lang.CPP,
    ".cc": Lang.CPP,
    ".cxx": Lang.CPP,
    ".hpp": Lang.CPP,
    ".hh": Lang.CPP,
}


def detect_language(path: Path) -> Lang | None:
    return EXTENSION_TO_LANG.get(path.suffix.lower())


@cache
def get_parser(lang: Lang) -> Parser:
    import tree_sitter_c
    import tree_sitter_c_sharp
    import tree_sitter_cpp
    import tree_sitter_go
    import tree_sitter_java
    import tree_sitter_javascript
    import tree_sitter_php
    import tree_sitter_python
    import tree_sitter_rust
    import tree_sitter_typescript

    factories = {
        Lang.PYTHON: tree_sitter_python.language,
        Lang.JAVASCRIPT: tree_sitter_javascript.language,
        Lang.TYPESCRIPT: tree_sitter_typescript.language_typescript,
        Lang.TSX: tree_sitter_typescript.language_tsx,
        Lang.JAVA: tree_sitter_java.language,
        Lang.CSHARP: tree_sitter_c_sharp.language,
        Lang.GO: tree_sitter_go.language,
        Lang.RUST: tree_sitter_rust.language,
        Lang.PHP: tree_sitter_php.language_php,
        Lang.C: tree_sitter_c.language,
        Lang.CPP: tree_sitter_cpp.language,
    }
    return Parser(Language(factories[lang]()))
