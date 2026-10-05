"""
의존성 권고 보고서: 비전공자도 읽도록 용어를 풀어 쓰고 "먼저 할 일"을 한 단계씩 제시한다.
형식: json(기계용), markdown, prompt(코딩 AI에 붙여넣을 지시문). 콘솔 출력은 cli에서 markdown을 그대로 보여 준다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
from datetime import UTC, date, datetime
from typing import Any

from iron_laws.deps.advise import SEVERITY_RANK, Finding, Undetermined
from iron_laws.deps.lockfiles import LockInfo
from iron_laws.deps.osv import AdvisoryDb

SCHEMA = "iron-laws.deps/1"
STALE_DAYS = 30
GLOSSARY = (
    "- 락 파일: 지금 설치된 패키지의 정확한 버전을 적어 둔 파일입니다(`uv.lock`, `package-lock.json` 등).\n"
    "- OSV: 오픈소스 패키지의 알려진 취약점을 모아 둔 공개 목록입니다. 알려진 취약점만 찾을 수 있습니다.\n"
    "- 직접 의존: 내가 직접 설치한 패키지입니다. 전이 의존은 그 패키지가 따라 끌고 온 패키지입니다."
)
LIMITS = "알려진 권고와 버전이 겹친다는 뜻입니다. 이 취약점이 내 코드에서 실제로 악용되는지, 영향이 얼마나 큰지는 알 수 없습니다. 권고 목록에 없는 취약점은 찾지 못합니다."


def snapshot_age_days(db: AdvisoryDb, today: date | None = None) -> int | None:
    if not db.newest:
        return None
    try:
        newest = datetime.fromisoformat(db.newest.replace("Z", "+00:00")).date()
    except ValueError:  # iron-laws: ignore[IL-301] 해석할 수 없는 날짜는 기준 시각 없음(None)으로 알리는 것이 이 함수의 계약이다
        return None
    return ((today or datetime.now(UTC).date()) - newest).days


def build(locks: list[LockInfo], results: list[tuple[list[Finding], list[Undetermined]]], db: AdvisoryDb, today: date | None = None) -> dict[str, Any]:
    age = snapshot_age_days(db, today)
    return {
        "schema": SCHEMA,
        "rule": "DEP-401",
        "snapshot": {"advisories": db.count, "newest_modified": db.newest or None, "age_days": age, "stale": age is not None and age > STALE_DAYS},
        "limits": LIMITS,
        "locks": [
            {
                "path": lock.path,
                "kind": lock.kind,
                "ecosystem": lock.ecosystem,
                "packages": len(lock.packages),
                "capabilities": lock.capabilities,
                "notes": lock.notes,
                "findings": [_finding(f) for f in findings],
                "undetermined": [u.__dict__ for u in undetermined],
            }
            for lock, (findings, undetermined) in zip(locks, results, strict=True)
        ],
    }


def _finding(f: Finding) -> dict[str, Any]:
    return {
        "package": f.package,
        "version": f.version,
        "ecosystem": f.ecosystem,
        "direct": f.direct,
        "dev": f.dev,
        "severity": f.severity,
        "advisories": [h.__dict__ for h in f.hits],
        "fix_boundary": f.fix_boundary,
        "fix_boundary_same_major": f.fix_boundary_same_major,
        "fix_note": f.fix_note,
        "via_direct": f.via_direct,
    }


def all_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for lock in data["locks"] for f in lock["findings"]]


def exceeds(data: dict[str, Any], fail_on: str) -> bool:
    if fail_on == "never":
        return False
    floor = {"any": 0, "high": 3, "critical": 4}[fail_on]
    return any(SEVERITY_RANK.get(f["severity"], 0) >= floor for f in all_findings(data))


def _kind(f: dict[str, Any]) -> str:
    return {True: "직접", False: "전이", None: "불명"}[f["direct"]]


def _action(f: dict[str, Any]) -> str:
    name, version = f["package"], f["version"]
    if f["fix_boundary"]:
        target = f"`{name}`을(를) {f['fix_boundary']} 이상으로 올리세요"
        if f["fix_boundary_same_major"] is False:
            target += " (큰 버전이 바뀌므로 변경 내용을 먼저 확인하세요)"
        if f["direct"] is False and f["via_direct"]:
            return f"{', '.join(f'`{p}`' for p in f['via_direct'])}의 새 버전을 확인하세요. 그 패키지가 끌고 온 `{name}` {version}이 문제입니다. 직접 올릴 수 없으면 {target}"
        return target
    return f"`{name}` {version}: {f['fix_note']}"


def markdown(data: dict[str, Any]) -> str:
    snap = data["snapshot"]
    out = ["# 의존성 취약점 점검(DEP-401)", ""]
    out.append(f"권고 목록 {snap['advisories']}건, 가장 최근 갱신 {snap['newest_modified'] or '알 수 없음'}.")
    if snap["stale"]:
        out.append(f"> 권고 목록이 {snap['age_days']}일 전 자료입니다. 새로 받아서 다시 점검하세요.")
    out += ["", GLOSSARY, ""]
    findings = all_findings(data)
    if not data["locks"]:
        out.append("점검할 락 파일을 찾지 못했습니다. `uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`를 지원합니다.")
    for lock in data["locks"]:
        out.append(f"## {lock['path']} ({lock['kind']}, 패키지 {lock['packages']}개)")
        for note in lock["notes"]:
            out.append(f"- {note}")
        if not lock["findings"]:
            out.append("- 알려진 권고와 겹치는 버전이 없습니다.")
        else:
            out += ["", "| 패키지 | 설치 버전 | 구분 | 심각도 | 권고 | 할 일 |", "|---|---|---|---|---|---|"]
            for f in lock["findings"]:
                ids = ", ".join(h["id"] for h in f["advisories"][:3]) + (f" 외 {len(f['advisories']) - 3}건" if len(f["advisories"]) > 3 else "")
                out.append(f"| {f['package']} | {f['version']} | {_kind(f)} | {f['severity']} | {ids} | {_action(f)} |")
        for u in lock["undetermined"]:
            out.append(f"- 판정 불가: {u['package']} {u['version']} - {u['reason']}")
        out.append("")
    if findings:
        first = findings[0]
        out += ["## 먼저 할 일", "", f"1. {_action(first)}", "2. 올린 뒤 시험(테스트)을 돌려 동작이 그대로인지 확인하세요.", "3. 다음 패키지로 넘어가세요. 한 번에 한 패키지씩 올려야 문제가 생겼을 때 원인을 찾기 쉽습니다.", ""]
    out.append(f"> {LIMITS}")
    return "\n".join(out)


def prompt(data: dict[str, Any]) -> str:
    findings = all_findings(data)
    if not findings:
        return "알려진 취약 의존성이 없습니다."
    first = findings[0]
    return (
        "다음 의존성 취약점 하나만 고쳐 주세요. 다른 패키지는 건드리지 마세요.\n\n"
        f"- 패키지: {first['package']} {first['version']} ({first['ecosystem']}, {_kind(first)} 의존)\n"
        f"- 권고: {', '.join(h['id'] for h in first['advisories'])}\n"
        f"- 할 일: {_action(first)}\n\n"
        "규칙: 1) 락 파일을 수동으로 편집하지 말고 패키지 관리자 명령(uv, npm, pnpm)으로 올리세요. 2) 올린 뒤 기존 시험을 돌려 통과하는지 확인하세요. "
        "3) 시험이 실패하면 되돌리고 원인을 알려 주세요. 4) 큰 버전이 바뀌면 변경 내용을 먼저 요약해 주세요."
    )


def to_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)
