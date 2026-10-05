"""
OSV 권고 해석: OSV 스키마의 영향 구간(introduced·fixed·last_affected·limit)과 명시 버전 목록으로 버전이 영향 아래인지 판정한다.
- 판정할 수 없는 경우(GIT 범위만 있거나 버전을 해석할 수 없음)는 거짓으로 단정하지 않고 None을 돌려준다.
- 철회된 권고는 제외한다. 별칭(aliases)이 겹치는 권고는 한 건으로 합쳐 보여 준다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iron_laws.deps.versions import normalize_name, parse_version

SUPPORTED_ECOSYSTEMS = ("PyPI", "npm")


@dataclass
class Range:
    kind: str  # SEMVER / ECOSYSTEM / GIT
    events: list[tuple[str, str]]  # (introduced|fixed|last_affected|limit, 값)


@dataclass
class Affected:
    ecosystem: str
    name: str
    versions: set[str]
    ranges: list[Range]


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    severity: str  # LOW / MODERATE / HIGH / CRITICAL / 미상
    modified: str
    affected: list[Affected] = field(default_factory=list)


def _severity(raw: dict[str, Any]) -> str:
    for source in (raw.get("database_specific") or {}, *(a.get("ecosystem_specific") or {} for a in raw.get("affected") or [])):
        value = str(source.get("severity") or "").upper()
        if value in ("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"):
            return "MODERATE" if value == "MEDIUM" else value
    return "미상"


def parse_advisory(raw: dict[str, Any]) -> Advisory | None:
    if raw.get("withdrawn"):
        return None
    affected: list[Affected] = []
    for item in raw.get("affected") or []:
        package = item.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "").split(":")[0]
        if ecosystem not in SUPPORTED_ECOSYSTEMS or not package.get("name"):
            continue
        ranges: list[Range] = []
        for r in item.get("ranges") or []:
            events: list[tuple[str, str]] = []
            for event in r.get("events") or []:
                for kind in ("introduced", "fixed", "last_affected", "limit"):
                    if kind in event:
                        events.append((kind, str(event[kind])))
            ranges.append(Range(str(r.get("type") or ""), events))
        affected.append(Affected(ecosystem, normalize_name(ecosystem, package["name"]), {str(v) for v in item.get("versions") or []}, ranges))
    if not affected:
        return None
    return Advisory(str(raw.get("id") or ""), [str(a) for a in raw.get("aliases") or []], str(raw.get("summary") or ""), _severity(raw), str(raw.get("modified") or ""), affected)


class AdvisoryDb:
    def __init__(self) -> None:
        self.by_package: dict[tuple[str, str], list[tuple[Advisory, Affected]]] = {}
        self.count = 0
        self.newest = ""

    def add(self, advisory: Advisory) -> None:
        self.count += 1
        self.newest = max(self.newest, advisory.modified)
        for affected in advisory.affected:
            self.by_package.setdefault((affected.ecosystem, affected.name), []).append((advisory, affected))

    def for_package(self, ecosystem: str, name: str) -> list[tuple[Advisory, Affected]]:
        return self.by_package.get((ecosystem, normalize_name(ecosystem, name)), [])


def load_db(path: Path) -> AdvisoryDb:
    """폴더(OSV JSON 파일 또는 `<에코시스템>/all.zip`)나 zip 파일 하나에서 권고를 읽는다."""
    db = AdvisoryDb()
    if not path.exists():
        raise FileNotFoundError(f"권고 DB가 없습니다: {path}")
    zips = [path] if path.is_file() and path.suffix == ".zip" else sorted(path.rglob("*.zip")) if path.is_dir() else []
    for archive in zips:
        with zipfile.ZipFile(archive) as z:
            for name in z.namelist():
                if name.endswith(".json"):
                    _add(db, json.loads(z.read(name)))
    if path.is_dir():
        for file in sorted(path.rglob("*.json")):
            _add(db, json.loads(file.read_text(encoding="utf-8")))
    elif path.is_file() and path.suffix == ".json":
        _add(db, json.loads(path.read_text(encoding="utf-8")))
    return db


def _add(db: AdvisoryDb, raw: Any) -> None:
    if isinstance(raw, dict) and raw.get("id"):
        advisory = parse_advisory(raw)
        if advisory is not None:
            db.add(advisory)


def is_affected(affected: Affected, version_text: str) -> bool | None:
    """version_text가 이 영향 항목에 드는가. 판정할 수 없으면 None"""
    if version_text in affected.versions:
        return True
    version = parse_version(affected.ecosystem, version_text)
    usable = [r for r in affected.ranges if r.kind in ("SEMVER", "ECOSYSTEM")]
    if version is None:
        return None if (usable or affected.versions) else False
    if not usable:
        return None if any(r.kind == "GIT" for r in affected.ranges) else False
    for r in usable:
        if _in_range(affected.ecosystem, r, version):
            return True
    return False


def _in_range(ecosystem: str, r: Range, version) -> bool:
    """OSV 규칙: 이벤트를 버전순으로 훑어 introduced 이후 fixed·last_affected·limit 전까지가 영향 구간이다."""

    def key(event: tuple[str, str]):
        parsed = parse_version(ecosystem, event[1]) if event[1] != "0" else None
        return (0, 0) if event[1] == "0" else (1, parsed) if parsed is not None else (2, 0)

    events = [e for e in r.events if event_version_ok(ecosystem, e)]
    events.sort(key=lambda e: (key(e)[0], key(e)[1] if key(e)[0] == 1 else 0))
    affected = False
    for kind, value in events:
        bound = None if value == "0" else parse_version(ecosystem, value)
        if kind == "introduced":
            if bound is None or version >= bound:
                affected = True
        elif kind == "fixed":
            if bound is not None and version >= bound:
                affected = False
        elif kind == "last_affected":
            if bound is not None and version > bound:
                affected = False
        elif kind == "limit":
            if bound is not None and version >= bound:
                affected = False
    return affected


def event_version_ok(ecosystem: str, event: tuple[str, str]) -> bool:
    return event[1] == "0" or parse_version(ecosystem, event[1]) is not None
