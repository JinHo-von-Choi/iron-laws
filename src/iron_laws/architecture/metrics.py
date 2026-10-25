"""
구조 중립 계측: 파일·함수·모듈 의존의 원시 통계를 한 번 계산한다. 규칙 임계(ARC-201 등)와 무관하게 분모를 가진다.
순환·쏠림은 ARC-203이 쓰는 모듈 의존 그래프(Python·JS·TS·Java)를, 계층 위반·중복은 해당 ARC 규칙의 지적 수를 분자로 쓴다.
작성자: 최진호
작성일: 2026-10-05
"""

import ast
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.scanner import AuditScanner
from iron_laws.engine.ast_tools import iter_functions
from iron_laws.engine.languages import Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.architecture import (
    CircularDependencyRule,
    DuplicateHelperRule,
    LayerDirectionRule,
    LayeringRule,
)

MIN_FILES = 10  # 소스 파일이 이보다 적으면 구간을 판정하지 않는다
HOTSPOT_COMMITS = 100  # 변경 빈도를 볼 때 최근 커밋 몇 개를 본다


@dataclass
class Hotspot:
    path: str
    changes: int
    lines: int
    score: int


@dataclass
class ModuleStat:
    path: str
    fan_in: int
    fan_out: int


@dataclass
class Metrics:
    root: str
    files: int
    functions: int
    lines: int
    cycles: list[list[str]] = field(default_factory=list)
    files_in_cycles: int = 0
    largest_cycle: int = 0
    top_fan_in: list[ModuleStat] = field(default_factory=list)
    top_fan_out: list[ModuleStat] = field(default_factory=list)
    hubs: list[ModuleStat] = field(default_factory=list)  # 많이 불리면서 동시에 많이 부르는 모듈(fan_in × fan_out 상위)
    large_functions: list[str] = field(default_factory=list)  # "경로:줄"
    large_files: list[str] = field(default_factory=list)
    layering_violations: int = 0
    layering_files: list[str] = field(default_factory=list)
    duplicate_findings: int = 0
    duplicate_files: list[str] = field(default_factory=list)
    modules_with_tests: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    hotspots: list[Hotspot] = field(default_factory=list)  # 자주 바뀌면서 큰 파일
    duplicate_patterns: list[str] = field(default_factory=list)  # 두 모듈 이상에 같은 모양으로 정의된 정규식
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _count(rule_cls, project: ProjectContext, sources: list[SourceFile]):
    rule = rule_cls()
    rule.configure(project.config)
    found = []
    for src in sources:
        if rule.applies_to(src):
            found.extend(rule.check(src))
    found.extend(rule.check_project(project))
    return found


def _has_test(module: SourceFile, tests: list[SourceFile], test_names: set[str]) -> bool:
    stem = Path(module.path.name).stem.lower()
    if stem in ("__init__", "index"):
        stem = module.path.parent.name.lower()
    if any(stem in name for name in test_names):
        return True
    token = re.compile(rf"\b{re.escape(stem)}\b")
    return any(token.search(t.text) for t in tests[:400])


def _git_change_counts(root: Path, commits: int) -> Counter:
    """최근 커밋에서 파일이 몇 번 바뀌었는지 센다. git 이력이 없으면 빈 결과를 낸다."""
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "log", f"-{commits}", "--name-only", "--pretty=format:"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # iron-laws: ignore[IL-301] git이 없거나 실패하면 변경 빈도 없이 진단하며, 빈 집계가 곧 정보 없음을 뜻한다
        return Counter()
    if out.returncode != 0:
        return Counter()
    return Counter(line.strip() for line in out.stdout.splitlines() if line.strip())


def _hotspots(root: Path, sources: list[SourceFile]) -> list[Hotspot]:
    """자주 바뀌면서 큰 파일을 앞세운다. 고쳐야 할 곳이 반복해서 망가지는 곳을 찾는 지표다."""
    counts = _git_change_counts(root, HOTSPOT_COMMITS)
    if not counts:
        return []
    found: list[Hotspot] = []
    for src in sources:
        rel = src.path.as_posix()
        changes = 0
        for name, count in counts.items():
            if name.endswith(rel) or rel.endswith(name):
                changes = max(changes, count)
        if not changes:
            continue
        lines = len([ln for ln in src.lines if ln.strip()])
        found.append(Hotspot(path=rel, changes=changes, lines=lines, score=changes * lines))
    found.sort(key=lambda h: (-h.score, h.path))
    return found[:10]


def _duplicate_patterns(sources: list[SourceFile]) -> list[str]:
    """두 모듈 이상에 같은 모양으로 정의된 정규식. 한 곳을 고쳐도 다른 곳이 남아 규칙이 어긋난다."""
    by_pattern: dict[str, set[str]] = {}
    for src in sources:
        if src.lang is not Lang.PYTHON:
            continue
        try:
            tree = ast.parse(src.text)
        except SyntaxError:  # iron-laws: ignore[IL-301] 구문 분석이 안 되는 파일은 import 집계에서 빼고, 같은 파일은 아래 함수 구조 단계에서 notes로 알린다
            continue
        module = src.path.parent.as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "compile"):
                continue
            target = func.value
            if not (isinstance(target, ast.Name) and target.id == "re"):
                continue
            pattern = node.args[0]
            if not (isinstance(pattern, ast.Constant) and isinstance(pattern.value, str)):
                continue
            if len(pattern.value) < 12:
                continue  # 짧은 패턴은 우연히 겹친다
            by_pattern.setdefault(pattern.value, set()).add(module)
    return sorted(pattern for pattern, modules in by_pattern.items() if len(modules) > 1)


def collect(root: Path, config: IronLawsConfig | None = None) -> Metrics:
    scanner = AuditScanner(root, config=config) if config is not None else AuditScanner(root)
    files = scanner._read_sources()
    project = ProjectContext(scanner.root_path, files, scanner.config, set(scanner._all_paths))
    sources = project.source_files()
    tests = [f for f in project.files if f.lang is not None and f.is_test]
    m = Metrics(root=str(root), files=len(sources), functions=0, lines=0)
    m.languages = dict(Counter(f.lang.value for f in sources if f.lang))
    limits = scanner.config.limits
    for src in sources:
        lines = [ln for ln in src.lines if ln.strip()]
        m.lines += len(lines)
        if len(src.lines) > limits.max_file_lines:
            m.large_files.append(f"{src.path.as_posix()}:1")
        try:
            for fn in iter_functions(src):
                m.functions += 1
                length = fn.node.end_point[0] - fn.node.start_point[0] + 1
                if length > limits.max_function_lines:
                    m.large_functions.append(f"{src.path.as_posix()}:{fn.node.start_point[0] + 1}")
        except Exception:  # noqa: BLE001 - 구문 분석이 안 되는 파일 하나가 전체 진단을 막지 않게 하되 아래에서 알린다  # iron-laws: ignore[IL-304] 구문 분석이 안 되는 파일 하나가 전체 진단을 막지 않게 하고 notes로 알린다
            m.notes.append(f"{src.path.as_posix()}: 함수 구조를 읽지 못했습니다.")
    graph_rule = CircularDependencyRule()
    graph, _lines = graph_rule._build_graph(project)
    for comp in graph_rule._sccs(graph):
        if len(comp) >= 2:
            m.cycles.append(sorted(comp))
    m.cycles.sort(key=lambda c: (-len(c), c[0]))
    m.files_in_cycles = sum(len(c) for c in m.cycles)
    m.largest_cycle = max((len(c) for c in m.cycles), default=0)
    fan_in: Counter[str] = Counter()
    for targets in graph.values():
        for target in targets:
            fan_in[target] += 1
    stats = [ModuleStat(p, fan_in.get(p, 0), len(graph.get(p, ()))) for p in graph]
    m.top_fan_in = sorted(stats, key=lambda s: (-s.fan_in, s.path))[:3]
    m.top_fan_out = sorted(stats, key=lambda s: (-s.fan_out, s.path))[:3]
    m.hubs = sorted((s for s in stats if s.fan_in and s.fan_out), key=lambda s: (-(s.fan_in * s.fan_out), s.path))[:5]
    layering = _count(LayeringRule, project, sources) + _count(LayerDirectionRule, project, sources)
    m.layering_violations = len(layering)
    m.layering_files = sorted({v.file_path.as_posix() for v in layering})
    duplicates = _count(DuplicateHelperRule, project, sources)
    m.duplicate_findings = len(duplicates)
    m.duplicate_files = sorted({v.file_path.as_posix() for v in duplicates})
    test_names = {t.path.name.lower() for t in tests}
    m.modules_with_tests = sum(1 for s in sources if _has_test(s, tests, test_names)) if tests else 0
    if not tests:
        m.notes.append("시험 파일을 찾지 못했습니다.")
    m.hotspots = _hotspots(root, sources)
    if not m.hotspots:
        m.notes.append("git 이력을 읽지 못해 변경 빈도를 보지 못했습니다.")
    m.duplicate_patterns = _duplicate_patterns(sources)
    return m
