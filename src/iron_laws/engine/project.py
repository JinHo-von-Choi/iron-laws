"""
오철칙 프로젝트 단위 분석 문맥
작성자: 최진호
작성일: 2026-10-04
"""

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.config import IronLawsConfig
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile


def matches_gitignore(patterns: list[str], rel_path: str) -> bool:
    """단순화한 .gitignore 일치 판정. 부정(!) 패턴과 중첩 규칙은 지원하지 않는다."""
    name = Path(rel_path).name
    for raw in patterns:
        pattern = raw.strip().rstrip("/")
        if not pattern or pattern.startswith(("#", "!")):
            continue
        pattern = pattern.lstrip("/")
        if (
            fnmatch.fnmatch(rel_path, pattern)
            or fnmatch.fnmatch(name, pattern)
            or fnmatch.fnmatch(rel_path, f"{pattern}/*")
            or fnmatch.fnmatch(rel_path, f"*/{pattern}")
        ):
            return True
    return False


@dataclass
class ProjectContext:
    root: Path
    files: list[SourceFile]
    config: IronLawsConfig
    all_paths: set[str] = field(default_factory=set)
    gitignore_patterns: list[str] = field(default_factory=list)

    def by_lang(self, *langs: Lang) -> list[SourceFile]:
        return [f for f in self.files if f.lang in langs]

    def by_kind(self, *kinds: str) -> list[SourceFile]:
        return [f for f in self.files if f.kind in kinds]

    def source_files(self, include_tests: bool = False) -> list[SourceFile]:
        return [f for f in self.files if f.lang is not None and (include_tests or not f.is_test)]

    def has_path(self, *names: str) -> bool:
        wanted = set(names)
        return any(p in wanted or Path(p).name in wanted for p in self.all_paths)

    def is_gitignored(self, rel_path: str) -> bool:
        return matches_gitignore(self.gitignore_patterns, rel_path)
