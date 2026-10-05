"""
의존성 권고 계산: 락 파일의 패키지마다 알려진 권고와 겹치는지 보고, 권고의 영향 구간을 벗어나는 알려진 수정 경계를 계산한다.
- "알려진 수정 경계"는 권고 DB에 적힌 fixed 버전 가운데 설치 버전보다 높고 같은 패키지의 모든 알려진 권고에서 벗어나는 가장 낮은 버전이다.
  그 버전이 실제로 배포되었는지는 오프라인 DB만으로 알 수 없다.
- 설치 버전을 해석할 수 없거나 GIT 범위만 있어 판정할 수 없는 경우는 통과가 아니라 '판정 불가'로 따로 센다.
- 전이 의존은 의존 그래프로 거슬러 올라가 직접 의존 후보를 알려 준다. 락 파일만으로는 상위 패키지가 허용하는 버전 범위를 알 수 없다.
작성자: 최진호
작성일: 2026-10-05
"""

from dataclasses import dataclass, field

from iron_laws.deps.lockfiles import LockInfo, Package
from iron_laws.deps.osv import Advisory, AdvisoryDb, Affected, is_affected
from iron_laws.deps.versions import parse_version

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "미상": 0}


@dataclass
class AdvisoryHit:
    id: str
    aliases: list[str]
    severity: str
    summary: str
    fixed_in: list[str]  # 이 권고에서 설치 버전이 속한 구간을 닫는 fixed 버전(없으면 빈 목록)


@dataclass
class Finding:
    package: str
    ecosystem: str
    version: str
    direct: bool | None
    dev: bool | None
    lock_file: str
    hits: list[AdvisoryHit]
    severity: str
    fix_boundary: str | None
    fix_boundary_same_major: bool | None
    fix_note: str
    via_direct: list[str] = field(default_factory=list)


@dataclass
class Undetermined:
    package: str
    ecosystem: str
    version: str
    reason: str


def _covering_fixes(affected: Affected, version) -> list[str]:
    """설치 버전이 든 구간을 닫는 fixed 버전들(영향 구간마다 가장 낮은 fixed)"""
    result: list[str] = []
    for r in affected.ranges:
        if r.kind not in ("SEMVER", "ECOSYSTEM"):
            continue
        fixes = []
        for kind, value in r.events:
            if kind == "fixed":
                bound = parse_version(affected.ecosystem, value)
                if bound is not None and bound > version:
                    fixes.append((bound, value))
        if fixes:
            result.append(min(fixes, key=lambda x: x[0])[1])
    return result


def _merge(hits: list[tuple[Advisory, Affected]], version) -> list[AdvisoryHit]:
    """별칭이 겹치는 권고(GHSA·CVE·PYSEC)를 한 건으로 합친다."""
    groups: list[dict] = []
    for advisory, affected in hits:
        names = {advisory.id, *advisory.aliases}
        target = next((g for g in groups if g["names"] & names), None)
        if target is None:
            groups.append({"names": set(names), "items": [(advisory, affected)]})
        else:
            target["names"] |= names
            target["items"].append((advisory, affected))
    merged: list[AdvisoryHit] = []
    for g in groups:
        primary = sorted((a for a, _ in g["items"]), key=lambda a: (not a.id.startswith("GHSA"), a.id))[0]
        severity = max((a.severity for a, _ in g["items"]), key=lambda s: SEVERITY_RANK.get(s, 0))
        fixed: list[str] = []
        for _, affected in g["items"]:
            fixed.extend(_covering_fixes(affected, version))
        aliases = sorted(g["names"] - {primary.id})
        merged.append(AdvisoryHit(primary.id, aliases, severity, primary.summary, sorted(set(fixed), key=lambda v: parse_version(primary_ecosystem(g), v) or 0)))
    return merged


def primary_ecosystem(group: dict) -> str:
    return group["items"][0][1].ecosystem


def _boundary(package: Package, entries: list[tuple[Advisory, Affected]], version) -> tuple[str | None, bool | None, str]:
    candidates: dict = {}
    for _, affected in entries:
        for r in affected.ranges:
            if r.kind not in ("SEMVER", "ECOSYSTEM"):
                continue
            for kind, value in r.events:
                if kind == "fixed":
                    bound = parse_version(package.ecosystem, value)
                    if bound is not None and bound > version:
                        candidates[value] = bound
    unknown = False
    for value, _bound in sorted(candidates.items(), key=lambda kv: kv[1]):
        verdicts = [is_affected(affected, value) for _, affected in entries]
        if any(v is True for v in verdicts):
            continue
        if any(v is None for v in verdicts):
            unknown = True
            continue
        same_major = getattr(_bound, "major", None) == getattr(version, "major", None)
        return value, same_major, "알려진 수정 경계입니다. 이 버전이 실제로 배포되었는지는 확인하지 못했습니다."
    if unknown:
        return None, None, "일부 권고를 해석하지 못해 안전한 버전을 정할 수 없습니다."
    return None, None, "권고 DB에 수정 버전이 없습니다. 패키지를 바꾸거나 작성자의 대응을 확인하세요."


def _via_direct(lock: LockInfo, package: Package) -> list[str]:
    if not lock.capabilities.get("graph") or not lock.capabilities.get("direct_transitive"):
        return []
    by_name = {p.name: p for p in lock.packages}
    seen: set[str] = set()
    frontier = list(package.parents)
    result: list[str] = []
    while frontier and len(result) < 5:
        name = frontier.pop(0)
        if name in seen or name not in by_name:
            continue
        seen.add(name)
        parent = by_name[name]
        if parent.direct:
            result.append(name)
        else:
            frontier.extend(sorted(parent.parents))
    return sorted(result)


def analyze(lock: LockInfo, db: AdvisoryDb) -> tuple[list[Finding], list[Undetermined]]:
    findings: list[Finding] = []
    undetermined: list[Undetermined] = []
    for package in lock.packages:
        version = parse_version(package.ecosystem, package.version)
        entries = db.for_package(package.ecosystem, package.name)
        if not entries:
            continue
        if version is None:
            undetermined.append(Undetermined(package.name, package.ecosystem, package.version, "설치 버전을 해석할 수 없습니다."))
            continue
        verdicts = [(advisory, affected, is_affected(affected, package.version)) for advisory, affected in entries]
        hits = [(a, f) for a, f, v in verdicts if v is True]
        if any(v is None for _, _, v in verdicts):
            undetermined.append(Undetermined(package.name, package.ecosystem, package.version, "일부 권고가 GIT 범위만 있거나 해석할 수 없어 영향 여부를 판정하지 못했습니다."))
        if not hits:
            continue
        merged = _merge(hits, version)
        boundary, same_major, note = _boundary(package, entries, version)
        severity = max((h.severity for h in merged), key=lambda s: SEVERITY_RANK.get(s, 0))
        findings.append(
            Finding(package.name, package.ecosystem, package.version, package.direct, package.dev, lock.path, merged, severity, boundary, same_major, note, [] if package.direct else _via_direct(lock, package))
        )
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.package))
    return findings, undetermined
