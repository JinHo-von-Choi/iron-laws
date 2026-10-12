"""
오철칙 버전 단위 의존 그래프: 잠금 파일에서 (이름@버전) 노드와 그 사이의 간선을 만든다

- package-lock.json v2·3: 설치 위치(`node_modules/a/node_modules/b`)마다 항목이 있으므로, 의존 이름을 npm의 실제 해석 순서
  (자기 아래 node_modules → 상위 폴더 → 최상위)로 찾아 그 위치의 버전에 잇는다. v1은 중첩 dependencies 구조로 같은 순서를 따른다.
- pnpm-lock.yaml v6·v9: 항목 키가 이름@버전이고 dependencies가 버전을 적으므로 그대로 잇는다(피어 접미사 `(…)`는 뗀다).
- uv.lock: 의존 항목에 버전이 있으면 그 버전, 없고 그 이름의 버전이 하나면 그것에 잇는다. 여럿이면 잇지 않고 기록한다.
- poetry.lock: 이름의 버전이 하나일 때만 잇는다.
- requirements*.txt: 관계 정보가 없으므로 간선을 만들지 않는다(추정하지 않는다).
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from iron_laws.deps.lockfiles import REQ_LINE, _pyproject_direct
from iron_laws.deps.versions import normalize_name


@dataclass
class Node:
    ecosystem: str  # npm / PyPI
    name: str
    version: str
    direct: bool | None = None
    dev: bool | None = None
    locations: set[str] = field(default_factory=set)

    @property
    def id(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class DependencyGraph:
    source: str
    ecosystem: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=dict)
    has_graph: bool = True
    notes: list[str] = field(default_factory=list)

    def add(self, ecosystem: str, name: str, version: str, location: str = "", dev: bool | None = None) -> Node:
        node = self.nodes.get(f"{name}@{version}")
        if node is None:
            node = self.nodes[f"{name}@{version}"] = Node(ecosystem, name, version, dev=dev)
        if location:
            node.locations.add(location)
        if dev is False:
            node.dev = False
        return node

    def link(self, parent: str, child: str) -> None:
        if parent != child:
            self.edges.setdefault(parent, set()).add(child)

    def roots(self) -> list[str]:
        return sorted(n.id for n in self.nodes.values() if n.direct)


def _npm_resolve(entries: dict, from_key: str, dep: str) -> str | None:
    """npm 해석 순서: from_key/node_modules/dep → 상위 위치의 node_modules/dep → node_modules/dep"""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in entries:
            return candidate
        if not base:
            return None
        cut = base.rfind("node_modules/")
        base = base[:cut].rstrip("/") if cut > 0 else ""


def _package_lock(path: Path) -> DependencyGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    graph = DependencyGraph(path.as_posix(), "npm")
    entries = data.get("packages")
    if isinstance(entries, dict):
        root = entries.get("") or {}
        direct = {name for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies") for name in (root.get(section) or {})}
        live = {k: v for k, v in entries.items() if k and isinstance(v, dict) and v.get("version") and not v.get("link")}
        ids: dict[str, str] = {}
        for key, item in live.items():
            name = item.get("name") or key.rsplit("node_modules/", 1)[-1]
            node = graph.add("npm", name, str(item["version"]), key, dev=bool(item.get("dev")))
            ids[key] = node.id
            if key == f"node_modules/{name}":
                node.direct = name in direct
        for key, item in live.items():
            for dep in {**(item.get("dependencies") or {}), **(item.get("optionalDependencies") or {})}:
                target = _npm_resolve(live, key, dep)
                if target is not None:
                    graph.link(ids[key], ids[target])
        return graph
    graph.notes.append("lockfileVersion 1: 중첩 dependencies 구조로 해석했다")

    def walk(deps: dict, scope: list[dict], parent_key: str) -> None:
        for name, item in deps.items():
            if not isinstance(item, dict) or not item.get("version"):
                continue
            key = f"{parent_key}/node_modules/{name}" if parent_key else f"node_modules/{name}"
            node = graph.add("npm", name, str(item["version"]), key, dev=bool(item.get("dev")))
            if isinstance(item.get("dependencies"), dict):
                walk(item["dependencies"], [item["dependencies"], *scope], key)
            for req in item.get("requires") or {}:
                for level in [item.get("dependencies") or {}, *scope]:
                    found = level.get(req)
                    if isinstance(found, dict) and found.get("version"):
                        graph.link(node.id, f"{req}@{found['version']}")
                        break

    top = data.get("dependencies") or {}
    walk(top, [top], "")
    manifest = path.parent / "package.json"
    if manifest.is_file():
        pj = json.loads(manifest.read_text(encoding="utf-8"))
        direct = {n for s in ("dependencies", "devDependencies", "optionalDependencies") for n in (pj.get(s) or {})}
        for name, item in top.items():
            if isinstance(item, dict) and item.get("version"):
                graph.nodes[f"{name}@{item['version']}"].direct = name in direct
    return graph


def _pnpm_key(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/").split("(", 1)[0]
    if "@" not in key[1:]:
        return None
    name, version = key.rsplit("@", 1)
    return (name, version) if name and version else None


def _pnpm(path: Path) -> DependencyGraph:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    graph = DependencyGraph(path.as_posix(), "npm")
    importers = data.get("importers") or {".": {k: data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")}}
    direct: set[tuple[str, str]] = set()
    for importer in importers.values():
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in ((importer or {}).get(section) or {}).items():
                version = spec.get("version") if isinstance(spec, dict) else spec
                direct.add((name, str(version).split("(", 1)[0]))
    blocks = [data.get("packages") or {}, data.get("snapshots") or {}]
    for block in blocks:
        for key, item in block.items():
            parsed = _pnpm_key(str(key))
            if parsed is None:
                continue
            node = graph.add("npm", *parsed, dev=bool((item or {}).get("dev")) if (item or {}).get("dev") is not None else None)
            node.direct = parsed in direct
    for block in blocks:
        for key, item in block.items():
            parsed = _pnpm_key(str(key))
            if parsed is None:
                continue
            for section in ("dependencies", "optionalDependencies"):
                for dep, spec in ((item or {}).get(section) or {}).items():
                    version = str(spec).split("(", 1)[0]
                    if f"{dep}@{version}" in graph.nodes:
                        graph.link(f"{parsed[0]}@{parsed[1]}", f"{dep}@{version}")
    return graph


def _by_name(graph: DependencyGraph) -> dict[str, list[str]]:
    names: dict[str, list[str]] = {}
    for node in graph.nodes.values():
        names.setdefault(node.name, []).append(node.id)
    return names


def _uv(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph = DependencyGraph(path.as_posix(), "PyPI")
    direct: set[str] = set()
    pending: list[tuple[str, dict]] = []
    for item in data.get("package") or []:
        name = normalize_name("PyPI", str(item.get("name")))
        source = item.get("source") or {}
        deps = [d for d in item.get("dependencies") or [] if isinstance(d, dict) and d.get("name")]
        extras = [d for group in {**(item.get("optional-dependencies") or {}), **(item.get("dev-dependencies") or {})}.values() for d in group if isinstance(d, dict)]
        if source.get("virtual") == "." or source.get("editable") == ".":
            direct |= {normalize_name("PyPI", d["name"]) for d in [*deps, *extras] if d.get("name")}
            continue
        node = graph.add("PyPI", name, str(item.get("version") or ""))
        pending += [(node.id, d) for d in deps]
    names = _by_name(graph)
    ambiguous = 0
    for parent, dep in pending:
        dep_name = normalize_name("PyPI", dep["name"])
        if dep.get("version"):
            target = f"{dep_name}@{dep['version']}"
        elif len(names.get(dep_name, [])) == 1:
            target = names[dep_name][0]
        else:
            ambiguous += 1
            continue
        if target in graph.nodes:
            graph.link(parent, target)
    for node in graph.nodes.values():
        node.direct = node.name in direct
    if ambiguous:
        graph.notes.append(f"버전을 정할 수 없는 의존 {ambiguous}건은 잇지 않았다")
    return graph


def _poetry(path: Path) -> DependencyGraph:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    graph = DependencyGraph(path.as_posix(), "PyPI")
    pending = []
    for item in data.get("package") or []:
        node = graph.add("PyPI", normalize_name("PyPI", str(item.get("name"))), str(item.get("version") or ""))
        pending += [(node.id, normalize_name("PyPI", d)) for d in item.get("dependencies") or {}]
    names = _by_name(graph)
    ambiguous = 0
    for parent, dep in pending:
        targets = names.get(dep, [])
        if len(targets) == 1:
            graph.link(parent, targets[0])
        elif len(targets) > 1:
            ambiguous += 1
    root = _pyproject_direct(path.parent / "pyproject.toml")
    for node in graph.nodes.values():
        node.direct = (node.name in root) if root else None
    if ambiguous:
        graph.notes.append(f"같은 이름의 버전이 여럿이라 잇지 않은 의존 {ambiguous}건")
    return graph


def _requirements(path: Path) -> DependencyGraph:
    graph = DependencyGraph(path.as_posix(), "PyPI", has_graph=False, notes=["requirements 파일에는 의존 관계가 없어 간선을 만들지 않았다"])
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = REQ_LINE.match(line.split("#", 1)[0].split(";", 1)[0])
        if m:
            graph.add("PyPI", normalize_name("PyPI", m.group(1)), m.group(2))
    return graph


BUILDERS = {"package-lock.json": _package_lock, "npm-shrinkwrap.json": _package_lock, "pnpm-lock.yaml": _pnpm, "uv.lock": _uv, "poetry.lock": _poetry}


def build_graph(path: Path) -> DependencyGraph:
    name = PurePosixPath(path.as_posix()).name
    if name in BUILDERS:
        return BUILDERS[name](path)
    if re.fullmatch(r"requirements.*\.txt", name):
        return _requirements(path)
    raise ValueError(f"지원하지 않는 파일입니다: {name}")
