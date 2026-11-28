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
    baseline_routes: list | None = None  # --baseline으로 준 기준선의 라우트 목록(없으면 공격 표면 비교를 하지 않는다)
    _routes: list | None = field(default=None, repr=False)
    _mappers: object = field(default=None, repr=False)
    cache: dict = field(default_factory=dict, repr=False)  # 여러 규칙이 함께 쓰는 프로젝트 단위 판정 결과

    def by_lang(self, *langs: Lang) -> list[SourceFile]:
        return [f for f in self.files if f.lang in langs]

    def by_kind(self, *kinds: str) -> list[SourceFile]:
        return [f for f in self.files if f.kind in kinds]

    def source_files(self, include_tests: bool = False) -> list[SourceFile]:
        return [f for f in self.files if f.lang is not None and (include_tests or not f.is_test)]

    def routes(self) -> list:
        """라우트 접근통제 행렬. 규칙 활성화와 관계없이 한 번만 계산해 규칙·보고서가 함께 쓴다(시험 파일 제외)."""
        if self._routes is None:
            from iron_laws.engine.routes import discover_routes

            self._routes = discover_routes(self.source_files(), self.config.auth, self.config.tenancy.keys)
        return self._routes

    def mappers(self):
        """MyBatis 매퍼 색인(engine/mybatis.py). XML 파일마다 한 번 읽는다."""
        if self._mappers is None:
            from iron_laws.engine.mybatis import MapperIndex

            self._mappers = MapperIndex.build([f for f in self.files if not f.is_test])
            self.cache["mappers_built"] = True
        return self._mappers

    def has_path(self, *names: str) -> bool:
        wanted = set(names)
        return any(p in wanted or Path(p).name in wanted for p in self.all_paths)

    def is_gitignored(self, rel_path: str) -> bool:
        return matches_gitignore(self.gitignore_patterns, rel_path)
