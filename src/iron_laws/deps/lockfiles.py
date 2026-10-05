"""
락 파일·매니페스트 해석: 고정된 패키지 버전과, 가능한 형식에서는 직접·전이 구분과 의존 그래프를 읽는다.
형식마다 알 수 있는 것이 다르다. 알 수 없으면 직접·전이를 None(불명)으로 둔다. 추정하지 않는다.
- uv.lock, poetry.lock(+pyproject.toml), package-lock.json(v1~v3), pnpm-lock.yaml: 버전 + 직접·전이 + 그래프
- requirements*.txt(`==`로 고정한 줄): 버전만(그래프 없음)
작성자: 최진호
작성일: 2026-10-05
"""

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from iron_laws.deps.versions import normalize_name

LOCK_FILE_NAMES = ("uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml")
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)")


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


def _pyproject_direct(path: Path) -> set[str]:
    names: set[str] = set()
    if not path.is_file():
        return names
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for req in (data.get("project") or {}).get("dependencies") or []:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(req))
        if m:
            names.add(normalize_name("PyPI", m.group(1)))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name in (poetry.get(section) or {}):
            if name.lower() != "python":
                names.add(normalize_name("PyPI", name))
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            names.add(normalize_name("PyPI", name))
    return names


def parse_poetry_lock(path: Path) -> LockInfo:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    packages: dict[str, Package] = {}
    edges: dict[str, set[str]] = {}
    for item in data.get("package") or []:
        name = normalize_name("PyPI", str(item.get("name")))
        packages[name] = Package("PyPI", name, str(item.get("version") or ""), source_file=path.name)
        edges[name] = {normalize_name("PyPI", d) for d in (item.get("dependencies") or {})}
    _mark_parents(packages, edges)
    root = _pyproject_direct(path.parent / "pyproject.toml")
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


def _npm_name(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def parse_package_lock(path: Path) -> LockInfo:
    data = json.loads(path.read_text(encoding="utf-8"))
    packages: dict[str, Package] = {}
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    entries = data.get("packages")
    if isinstance(entries, dict):  # lockfileVersion 2·3
        root = entries.get("") or {}
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            direct |= set(root.get(section) or {})
        for key, item in entries.items():
            if key == "" or not isinstance(item, dict) or not item.get("version") or item.get("link"):
                continue
            name = item.get("name") or _npm_name(key)
            pkg = packages.setdefault(name, Package("npm", name, str(item["version"]), dev=bool(item.get("dev")), source_file=path.name))
            if str(item["version"]) != pkg.version:  # 같은 이름의 여러 버전(중첩 설치)은 가장 먼저 만난 것을 대표로 두고 나머지는 별도 항목으로 둔다
                packages[f"{name}@{item['version']}"] = Package("npm", name, str(item["version"]), dev=bool(item.get("dev")), source_file=path.name)
            edges.setdefault(name, set()).update((item.get("dependencies") or {}).keys())
        caps = {"versions": True, "direct_transitive": True, "graph": True}
    else:  # lockfileVersion 1
        def walk(deps: dict, parent: str | None) -> None:
            for name, item in deps.items():
                if not isinstance(item, dict) or not item.get("version"):
                    continue
                packages.setdefault(name, Package("npm", name, str(item["version"]), dev=bool(item.get("dev")), source_file=path.name))
                edges.setdefault(name, set()).update((item.get("requires") or {}).keys())
                if isinstance(item.get("dependencies"), dict):
                    walk(item["dependencies"], name)

        walk(data.get("dependencies") or {}, None)
        manifest = path.parent / "package.json"
        if manifest.is_file():
            pj = json.loads(manifest.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                direct |= set(pj.get(section) or {})
        caps = {"versions": True, "direct_transitive": bool(direct), "graph": True}
    by_name = {k: v for k, v in packages.items() if "@" not in k[1:]}
    _mark_parents(by_name, edges)
    for pkg in packages.values():
        pkg.direct = (pkg.name in direct) if caps["direct_transitive"] else None
    return LockInfo(path.as_posix(), "package-lock.json", "npm", list(packages.values()), caps)


def _pnpm_key(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/").split("(", 1)[0]
    if "@" not in key[1:]:
        return None
    name, version = key.rsplit("@", 1)
    return (name, version) if name and version else None


def parse_pnpm_lock(path: Path) -> LockInfo:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    packages: dict[str, Package] = {}
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    importers = data.get("importers") or {".": {k: data.get(k) for k in ("dependencies", "devDependencies", "optionalDependencies")}}
    for importer in importers.values():
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            direct |= set((importer or {}).get(section) or {})
    for key, item in (data.get("packages") or {}).items():
        parsed = _pnpm_key(str(key))
        if parsed is None:
            continue
        name, version = parsed
        packages.setdefault(name, Package("npm", name, version, dev=bool((item or {}).get("dev")), source_file=path.name))
        edges.setdefault(name, set()).update(((item or {}).get("dependencies") or {}).keys())
    for key, item in (data.get("snapshots") or {}).items():
        parsed = _pnpm_key(str(key))
        if parsed:
            edges.setdefault(parsed[0], set()).update(((item or {}).get("dependencies") or {}).keys())
    _mark_parents(packages, edges)
    for pkg in packages.values():
        pkg.direct = pkg.name in direct
    return LockInfo(path.as_posix(), "pnpm-lock.yaml", "npm", list(packages.values()), {"versions": True, "direct_transitive": True, "graph": True})


PARSERS = {"uv.lock": parse_uv_lock, "poetry.lock": parse_poetry_lock, "package-lock.json": parse_package_lock, "pnpm-lock.yaml": parse_pnpm_lock}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}


def find_lock_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]) or not path.is_file():
            continue
        if path.name in PARSERS or re.fullmatch(r"requirements.*\.txt", path.name):
            found.append(path)
    return found


def parse_lock(path: Path) -> LockInfo:
    if path.name in PARSERS:
        return PARSERS[path.name](path)
    if re.fullmatch(r"requirements.*\.txt", path.name):
        return parse_requirements(path)
    raise ValueError(f"지원하지 않는 파일입니다: {path.name}")
