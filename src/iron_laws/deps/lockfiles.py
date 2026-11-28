"""
락 파일·매니페스트 해석: 고정된 패키지 버전과, 가능한 형식에서는 직접·전이 구분과 의존 그래프를 읽는다.
형식마다 알 수 있는 것이 다르다. 알 수 없으면 직접·전이를 None(불명)으로 둔다. 추정하지 않는다.
- uv.lock, poetry.lock(+pyproject.toml), package-lock.json(v1~v3), pnpm-lock.yaml: 버전 + 직접·전이 + 그래프
- requirements*.txt(`==`로 고정한 줄): 버전만(그래프 없음)
- pom.xml, build.gradle(.kts), gradle/libs.versions.toml: Maven 직접 의존성의 버전만(잠금 파일이 없어 전이 의존성은 알 수 없다)
작성자: 최진호
작성일: 2026-10-05
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.deps.graph import build_graph
from iron_laws.deps.manifests import (
    REQ_LINE,
    parse_gradle,
    parse_pom,
    parse_version_catalog,
    pyproject_direct,
)
from iron_laws.deps.versions import normalize_name

LOCK_FILE_NAMES = ("uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml")


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    direct: bool | None = None  # None이면 이 형식으로는 알 수 없다
    dev: bool | None = None
    source_file: str = ""
    parents: set[str] = field(default_factory=set)  # 이 패키지를 의존으로 가진 패키지 이름


@dataclass
class LockInfo:
    path: str
    kind: str
    ecosystem: str
    packages: list[Package]
    capabilities: dict[str, bool]  # versions / direct_transitive / graph
    notes: list[str] = field(default_factory=list)


def _mark_parents(packages: dict[str, Package], edges: dict[str, set[str]]) -> None:
    for parent, children in edges.items():
        for child in children:
            if child in packages and parent in packages:
                packages[child].parents.add(parent)


def parse_uv_lock(path: Path) -> LockInfo:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages: dict[str, Package] = {}
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    for item in data.get("package") or []:
        name = normalize_name("PyPI", str(item.get("name")))
        source = item.get("source") or {}
        deps = {normalize_name("PyPI", d["name"]) for d in item.get("dependencies") or [] if isinstance(d, dict) and d.get("name")}
        optional = [d for group in (item.get("optional-dependencies") or {}).values() for d in group]
        dev = [d for group in (item.get("dev-dependencies") or {}).values() for d in group]
        extra = {normalize_name("PyPI", d["name"]) for d in [*optional, *dev] if isinstance(d, dict) and d.get("name")}
        if source.get("virtual") == "." or source.get("editable") == ".":
            direct |= deps | extra
            continue
        packages[name] = Package("PyPI", name, str(item.get("version") or ""), source_file=path.name)
        edges[name] = deps
    _mark_parents(packages, edges)
    for pkg in packages.values():
        pkg.direct = pkg.name in direct
    return LockInfo(path.as_posix(), "uv.lock", "PyPI", [p for p in packages.values() if p.version], {"versions": True, "direct_transitive": True, "graph": True})


def parse_poetry_lock(path: Path) -> LockInfo:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages: dict[str, Package] = {}
    edges: dict[str, set[str]] = {}
    for item in data.get("package") or []:
        name = normalize_name("PyPI", str(item.get("name")))
        packages[name] = Package("PyPI", name, str(item.get("version") or ""), source_file=path.name)
        edges[name] = {normalize_name("PyPI", d) for d in (item.get("dependencies") or {})}
    _mark_parents(packages, edges)
    root = pyproject_direct(path.parent / "pyproject.toml")
    has_root = bool(root)
    for pkg in packages.values():
        pkg.direct = (pkg.name in root) if has_root else None
    notes = [] if has_root else ["pyproject.toml이 없거나 직접 의존이 적혀 있지 않아 직접·전이를 알 수 없습니다."]
    return LockInfo(path.as_posix(), "poetry.lock", "PyPI", list(packages.values()), {"versions": True, "direct_transitive": has_root, "graph": True}, notes)


def parse_requirements(path: Path) -> LockInfo:
    packages: dict[str, Package] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = REQ_LINE.match(line.split("#", 1)[0].split(";", 1)[0])
        if m:
            name = normalize_name("PyPI", m.group(1))
            packages[name] = Package("PyPI", name, m.group(2), source_file=path.name)
    return LockInfo(path.as_posix(), "requirements", "PyPI", list(packages.values()), {"versions": True, "direct_transitive": False, "graph": False}, ["requirements 파일에는 의존 관계가 없어 직접·전이를 알 수 없습니다."])


MAVEN_NOTE = "직접 의존성만 확인했습니다. 전이 의존성은 확인하지 않았습니다(Maven·Gradle은 잠금 파일이 없습니다)."
MAVEN_MANIFESTS = ("pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml")


def parse_maven_manifest(path: Path) -> LockInfo:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "pom.xml":
        parent, deps = parse_pom(text)
        if parent is not None:
            deps = [parent, *deps]
    elif path.name == "libs.versions.toml":
        deps = parse_version_catalog(text)
    else:
        deps = parse_gradle(text)
    packages: dict[str, Package] = {}
    skipped = 0
    for d in deps:
        if not d.version:
            skipped += 1
            continue
        packages.setdefault(f"{d.coordinate}@{d.version}", Package("Maven", d.coordinate, d.version, direct=True, dev=d.scope == "test", source_file=path.name))
    notes = [MAVEN_NOTE] + ([f"버전을 정하지 못한 의존성 {skipped}개는 점검하지 않았습니다(BOM·플러그인이 관리하는 버전)."] if skipped else [])
    return LockInfo(path.as_posix(), path.name, "Maven", list(packages.values()), {"versions": True, "direct_transitive": False, "graph": False}, notes)


def _from_graph(path: Path, kind: str, caps: dict[str, bool], notes: list[str] | None = None) -> LockInfo:
    """버전 단위 그래프(graph.py)로 패키지 목록과 부모(이 패키지를 의존으로 가진 패키지 이름)를 만든다. 같은 이름의 여러 버전은 각각 둔다."""
    graph = build_graph(path)
    parents: dict[str, set[str]] = {}
    for parent, children in graph.edges.items():
        for child in children:
            parents.setdefault(child, set()).add(graph.nodes[parent].name)
    packages = []
    for node in graph.nodes.values():
        direct = node.direct if node.direct is not None else (False if caps["direct_transitive"] else None)
        packages.append(Package(node.ecosystem, node.name, node.version, direct=direct, dev=node.dev, source_file=path.name, parents=parents.get(node.id, set())))
    return LockInfo(path.as_posix(), kind, graph.ecosystem, packages, caps, notes or [])


def parse_package_lock(path: Path) -> LockInfo:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data.get("packages"), dict):  # lockfileVersion 2·3
        return _from_graph(path, "package-lock.json", {"versions": True, "direct_transitive": True, "graph": True})
    manifest = path.parent / "package.json"
    known = manifest.is_file() and any(json.loads(manifest.read_text(encoding="utf-8")).get(s) for s in ("dependencies", "devDependencies", "optionalDependencies"))
    return _from_graph(path, "package-lock.json", {"versions": True, "direct_transitive": bool(known), "graph": True})


def parse_pnpm_lock(path: Path) -> LockInfo:
    return _from_graph(path, "pnpm-lock.yaml", {"versions": True, "direct_transitive": True, "graph": True})


PARSERS = {"uv.lock": parse_uv_lock, "poetry.lock": parse_poetry_lock, "package-lock.json": parse_package_lock, "pnpm-lock.yaml": parse_pnpm_lock}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}


def find_lock_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]) or not path.is_file():
            continue
        if path.name in PARSERS or path.name in MAVEN_MANIFESTS or re.fullmatch(r"requirements.*\.txt", path.name):
            found.append(path)
    return found


def parse_lock(path: Path) -> LockInfo:
    if path.name in PARSERS:
        return PARSERS[path.name](path)
    if re.fullmatch(r"requirements.*\.txt", path.name):
        return parse_requirements(path)
    if path.name in MAVEN_MANIFESTS:
        return parse_maven_manifest(path)
    raise ValueError(f"지원하지 않는 파일입니다: {path.name}")
