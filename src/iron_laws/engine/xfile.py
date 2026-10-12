"""
오철칙 파일 간 호출 해석
언어별 해석기(xfile_python, xfile_js, xfile_java)가 import·export를 따라 다른 파일의 함수를 찾고, 이 모듈은 예산·캐시·통계를 함께 관리한다.
해석 횟수의 상한은 관심 지점(호출 하나의 판정)마다 따로 두어, 어느 작업 프로세스에서 어떤 순서로 분석해도 같은 지점은 같은 예산을 쓴다.
넘으면 해석을 멈추고 기록한다. 프로젝트 안의 대상으로 보이는데 정할 수 없는 호출은 해석 공백으로 따로 센다.
작성자: 최진호
작성일: 2026-10-04
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from iron_laws.engine import xfile_go, xfile_java, xfile_js, xfile_php, xfile_python
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

DEFAULT_LOOKUP_BUDGET = 20000


class ResolveResult(NamedTuple):
    targets: list  # [(SourceFile, Func)]
    gap: str | None = None  # 프로젝트 안의 대상으로 보이지만 정할 수 없을 때의 사유


RESOLVERS = {Lang.PYTHON: xfile_python, Lang.JAVA: xfile_java, Lang.GO: xfile_go, Lang.PHP: xfile_php, **{lang: xfile_js for lang in JS_FAMILY}}


@dataclass
class ProjectIndex:
    files: dict[str, SourceFile]  # 해석기가 있는 언어의 모든 파일
    budget: int = DEFAULT_LOOKUP_BUDGET  # 관심 지점 하나가 쓸 수 있는 해석 횟수
    modules: dict[str, list[str]] = field(default_factory=dict)  # Python 모듈 이름 → 파일
    js_aliases: list[tuple[str, str, list[str]]] = field(default_factory=list)  # tsconfig paths: (기준 폴더, 패턴, 대상)
    java_classes: dict[str, list[str]] = field(default_factory=dict)  # Java 정규 클래스 이름 → 파일
    java_impls: dict[str, list[tuple[str, frozenset[str]]]] = field(default_factory=dict)  # 상위 형식 단순 이름 → (구현 클래스, 애너테이션)
    config_errors: list[str] = field(default_factory=list)  # 읽지 못한 해석 설정 파일(tsconfig 등)
    go_dirs: dict[str, list[str]] = field(default_factory=dict)  # Go 폴더 → 파일
    go_import_paths: dict[str, str] = field(default_factory=dict)  # Go 폴더 → go.mod의 모듈 경로로 만든 import 경로
    root: Path | None = None  # 점검 루트(go.mod 같은 비소스 설정 파일을 읽는 데 쓴다)
    php_functions: dict[str, list[str]] = field(default_factory=dict)  # PHP 전역 함수 이름(소문자) → 파일
    php_classes: dict[str, list[str]] = field(default_factory=dict)  # PHP 클래스 이름(소문자) → 파일
    limit_hits: int = 0  # 한도 도달 사건 수. 관심 지점별 판정(장부)이 앞뒤 차이로 쓴다
    limit_keys: set[tuple[str, int, str]] = field(default_factory=set)  # 한도에 걸린 서로 다른 곳(파일, 위치, 사유). 진단 건수로 쓴다
    _collectors: list[set] = field(default_factory=list)
    _pending: set[tuple[str, int, str]] | None = None  # 관심 지점 안에서 걸린 곳. 지점이 예산 소진으로 끝나면 버린다
    resolved_keys: set[tuple[str, str, int]] = field(default_factory=set)
    gap_keys: set[tuple[str, str, int, str]] = field(default_factory=set)
    # 함수 노드가 아니라 (파일, 함수 시작 위치)를 캐시한다. 구문 트리는 메모리 절약을 위해 버렸다가 다시 만들므로
    # 노드를 그대로 두면 버린 트리를 해석하게 된다
    _resolve_cache: dict[tuple[str, str, int], tuple[list[tuple[str, int]], str | None]] = field(default_factory=dict)
    _remaining: int | None = None  # None이면 진행 중인 관심 지점이 없다
    exhausted: bool = False
    charged: int = 0  # 관심 지점 안에서 쓴 해석 횟수의 누계(캐시 재사용 시 같은 비용을 다시 치르는 데 쓴다)

    @property
    def resolved(self) -> int:
        return len(self.resolved_keys)

    @property
    def java_files(self) -> dict[str, SourceFile]:
        return {p: s for p, s in self.files.items() if s.lang is Lang.JAVA}

    @property
    def metering(self) -> bool:
        return self._remaining is not None

    def note(self, key: tuple[str, int, str]) -> None:
        self.limit_hits += 1
        (self._pending if self._pending is not None else self.limit_keys).add(key)
        for collector in self._collectors:
            collector.add(key)

    def begin_point(self) -> None:
        self._remaining = self.budget
        self.exhausted = False
        self._pending = set()

    def end_point(self) -> None:
        if self._pending is not None and not self.exhausted:
            self.limit_keys |= self._pending
        self._pending = None
        self._remaining = None
        self.exhausted = False

    def spend(self, cost: int = 1, where: tuple[str, int, str] = ("", 0, "budget")) -> bool:
        """해석 비용을 치른다. 관심 지점 밖의 단건 해석은 상한이 0이 아닌 한 허용한다."""
        if self._remaining is None:
            if self.budget > 0:
                return True
            self.note(where)
            return False
        if self.exhausted:
            return False
        if cost > self._remaining:
            self._remaining = 0
            self.exhausted = True
            return False
        self._remaining -= cost
        self.charged += cost
        return True

    @classmethod
    def build(cls, sources: list[SourceFile], budget: int = DEFAULT_LOOKUP_BUDGET, root: Path | None = None) -> "ProjectIndex":
        index = cls({s.path.as_posix(): s for s in sources if s.lang in RESOLVERS}, budget)
        index.root = root if root is not None and root.is_dir() else None
        for resolver in (xfile_python, xfile_js, xfile_java, xfile_go, xfile_php):
            resolver.build(index, sources)
        return index

    def lookup_module(self, name: str, from_path: str) -> str | None:
        return xfile_python.lookup_module(self, name, from_path)

    def resolve_java_static(self, src: SourceFile, callee: str, argc: int):
        """프로젝트 클래스의 static 메서드 호출 대상. 정할 수 없으면 빈 목록"""
        if src.lang is not Lang.JAVA:
            return []
        return self.resolve(src, callee, argc)

    def resolve(self, src: SourceFile, callee: str, argc: int) -> list[tuple[SourceFile, object]]:
        resolver = RESOLVERS.get(src.lang) if src.lang else None
        if resolver is None:
            return []
        # 캐시에 있어도 비용을 치른다. 그래야 앞서 다른 파일을 분석했는지와 무관하게 같은 지점이 같은 예산을 쓴다
        if not self.spend(where=(src.path.as_posix(), argc, "budget:" + callee)):
            return []
        key = (src.path.as_posix(), callee, argc)
        if key in self._resolve_cache:
            entries, _gap = self._resolve_cache[key]
            return _materialize(self.files, entries)
        result = resolver.resolve(self, src, callee, argc)
        targets, gap = (result.targets, result.gap) if isinstance(result, ResolveResult) else (result, None)
        if targets:
            self.resolved_keys.add(key)
        elif gap:
            self.gap_keys.add((*key, gap))
        self._resolve_cache[key] = ([(s.path.as_posix(), fn.node.start_byte) for s, fn in targets], gap)
        return targets


def _materialize(files: dict[str, SourceFile], entries: list[tuple[str, int]]) -> list[tuple[SourceFile, object]]:
    from iron_laws.engine.ast_tools import iter_functions

    found = []
    for rel, start in entries:
        source = files[rel]
        found.extend((source, fn) for fn in iter_functions(source) if fn.node.start_byte == start)
    return found


def imported_names(src: SourceFile) -> set[str]:
    """import로 이 파일에 묶인 지역 이름(Python)"""
    return xfile_python.imported_names(src)


# 전역 색인: 점검이 시작될 때 한 번 만들고, 규칙은 읽기만 한다. (병렬 처리는 fork라서 작업 프로세스가 그대로 물려받는다)
_INDEX: ProjectIndex | None = None


def set_index(index: ProjectIndex | None) -> None:
    global _INDEX
    _INDEX = index


def get_index() -> ProjectIndex | None:
    return _INDEX


def resolve_external(src: SourceFile, callee: str, argc: int) -> list[tuple[SourceFile, object]]:
    if _INDEX is None or src.lang not in RESOLVERS:
        return []
    return _INDEX.resolve(src, callee, argc)


def note_limit(path: str = "", position: int = 0, reason: str = "depth") -> None:
    if _INDEX is not None:
        _INDEX.note((path, position, reason))
