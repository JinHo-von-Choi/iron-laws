"""
오철칙 경로 판정 도구: 테스트 경로와 제3자 코드 구분
작성자: 최진호
작성일: 2026-10-04
"""

import fnmatch
import re
from pathlib import Path

TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs"}
TEST_FILE_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "*_test.go",
    "*_test.rs",
    "*Test.cs",
    "*Test.java",
    "*Tests.java",
    "*Tests.cs",
    "*.test.*",
    "*.spec.*",
)


def is_test_path(rel_path: Path) -> bool:
    if any(part in TEST_DIR_NAMES for part in rel_path.parts[:-1]):
        return True
    return any(fnmatch.fnmatch(rel_path.name, pat) for pat in TEST_FILE_PATTERNS)

VENDOR_BANNER_RE = re.compile(r"@license|Copyright\s*\(c\)|Licensed under|MIT License|\bv\d+\.\d+\.\d+|@version|\bjQuery\b|\bBootstrap\b", re.IGNORECASE)
VENDOR_NAME_RE = re.compile(r"(?i)^(jquery[\w.\-]*|bootstrap[\w.\-]*|ace|angular[\w.\-]*|d3[\w.\-]*|lodash[\w.\-]*|moment[\w.\-]*|popper[\w.\-]*|highlight[\w.\-]*)\.js$")


def looks_vendored_js(rel_path: Path, content: str) -> bool:
    """제3자 라이브러리를 복사해 둔 JS 파일로 보이는지 판정한다."""
    if rel_path.suffix.lower() not in (".js", ".mjs", ".css"):
        return False
    if VENDOR_NAME_RE.match(rel_path.name):
        return True
    return len(content) >= 15_000 and bool(VENDOR_BANNER_RE.search(content[:800]))
