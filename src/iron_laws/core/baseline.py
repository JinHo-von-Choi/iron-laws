"""
오철칙 기준선(baseline): 이미 알려진 지적을 승인된 부채로 기록하고, 새로 생긴 지적만 걸러 낸다
지적의 지문은 줄 번호가 아니라 규칙·파일·함수·코드 모양으로 만든다. 줄이 밀려도 같은 지적으로 인식되고,
규칙의 판정 의미(version)가 바뀌면 기존 지적을 자동으로 승인하지 않고 다시 검토 대상으로 돌린다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from iron_laws.core.config import ConfigError
from iron_laws.core.models import AuditReport, BaselineStatus, Diagnostic, Violation

BASELINE_SCHEMA = 1
DEFAULT_BASELINE_FILE = ".iron-laws-baseline.json"


class BaselineEntry(BaseModel):
    fingerprint: str
    loose: str
    rule_id: str
    rule_version: int = 1
    path: str
    line: int
    severity: str


class Baseline(BaseModel):
    """기존 지적 관리 데이터(승인된 부채의 목록). 사람의 검토 승인이 아니다. 승인은 ApprovalRecord로 따로 기록한다."""

    schema_version: int = BASELINE_SCHEMA
    kind: str = "debt"
    migrated_from: str = ""
    tool_version: str = ""
    created: str = ""
    entries: list[BaselineEntry] = Field(default_factory=list)


def _digest(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:20]


def make_fingerprint(rule_id: str, rule_version: int, path: str, scope: str, shape: str, occurrence: int) -> str:
    return _digest(rule_id, rule_version, path, scope, shape, occurrence)


def shape_of(v: Violation) -> str:
    """지적 줄의 정규화한 코드 모양. 주석·공백이 바뀌어도 같다."""
    return v.shape or re.sub(r"\s+", " ", v.snippet).strip()


def loose_key(rule_id: str, scope: str, shape: str) -> str:
    """파일 이동이나 줄 이동에도 유지되는 느슨한 식별자 (경로와 발생 순번을 뺀다)"""
    return _digest(rule_id, scope, shape)


def build_baseline(report: AuditReport, tool_version: str) -> Baseline:
    entries = [
        BaselineEntry(
            fingerprint=v.fingerprint,
            loose=loose_key(v.rule_id, v.scope_name, shape_of(v)),
            rule_id=v.rule_id,
            rule_version=v.rule_version,
            path=v.file_path.as_posix(),
            line=v.line_number,
            severity=v.severity.value,
        )
        for v in report.violations
    ]
    entries.sort(key=lambda e: (e.path, e.line, e.rule_id))
    return Baseline(tool_version=tool_version, created=datetime.now(UTC).strftime("%Y-%m-%d"), entries=entries)


def save_baseline(baseline: Baseline, path: Path) -> None:
    path.write_text(json.dumps(baseline.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> Baseline:
    if not path.is_file():
        raise ConfigError(f"기준선 파일이 없습니다: {path} (`iron-laws baseline create`로 만드십시오)")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        baseline = Baseline(**data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError, TypeError) as e:
        raise ConfigError(f"기준선 파일을 읽을 수 없습니다: {path} ({e})") from e
    if baseline.schema_version != BASELINE_SCHEMA:
        raise ConfigError(f"지원하지 않는 기준선 형식입니다 (schema_version={baseline.schema_version}). 기준선을 다시 만드십시오")
    return baseline


@dataclass
class BaselineOutcome:
    diagnostics: list[Diagnostic] = field(default_factory=list)
    resolved: list[BaselineEntry] = field(default_factory=list)  # 파일은 점검했고 지적이 사라짐
    unobserved: list[BaselineEntry] = field(default_factory=list)  # 파일을 점검하지 못해 알 수 없음
    matched: dict[str, tuple[Violation, BaselineStatus]] = field(default_factory=dict)  # 기준선 항목 지문 → (대응된 지적, 상태)


def apply_baseline(
    violations: list[Violation],
    baseline: Baseline,
    current_versions: dict[str, int],
    scanned_paths: set[str],
    existing_paths: set[str],
) -> BaselineOutcome:
    """전체 지적 집합에서 기준선과 일대일로 대응시키고 각 지적에 상태를 붙인다. 표시 범위를 줄이는 일은 이 뒤에 한다.

    - 같은 지문은 먼저 일대일로 맺는다.
    - 지문이 달라졌어도 같은 파일에서 규칙 의미(version)만 바뀐 지적은 재검토 대상이다.
    - 파일 이동은 기준선의 옛 경로가 디스크에서 사라진 경우에만 인정한다. 원본이 남아 있는 복제본은 새 지적이다.
    - 대응이 모호하면 승인을 승계하지 않는다.
    - 파일을 읽지 못했거나 없어진 경우는 해소가 아니라 미확인이다.
    """
    outcome = BaselineOutcome()
    by_fingerprint = {e.fingerprint: e for e in baseline.entries}
    consumed: set[str] = set()

    leftovers: list[Violation] = []
    for v in sorted(violations, key=lambda x: (x.file_path.as_posix(), x.line_number, x.rule_id)):
        entry = by_fingerprint.get(v.fingerprint)
        if entry is not None and entry.fingerprint not in consumed:
            consumed.add(entry.fingerprint)
            v.baseline_status = BaselineStatus.EXISTING
            outcome.matched[entry.fingerprint] = (v, BaselineStatus.EXISTING)
        else:
            leftovers.append(v)

    def entries_with(loose: str, predicate) -> list[BaselineEntry]:
        return [e for e in baseline.entries if e.loose == loose and e.fingerprint not in consumed and predicate(e)]

    # 같은 파일에서 규칙 의미만 바뀐 지적
    still: list[Violation] = []
    for v in leftovers:
        loose = loose_key(v.rule_id, v.scope_name, shape_of(v))
        same_file = entries_with(loose, lambda e, v=v: e.path == v.file_path.as_posix() and e.rule_version != v.rule_version)
        if len(same_file) == 1:
            consumed.add(same_file[0].fingerprint)
            v.baseline_status = BaselineStatus.REVIEW
            outcome.matched[same_file[0].fingerprint] = (v, BaselineStatus.REVIEW)
        else:
            still.append(v)

    # 사라진 옛 경로에서 옮겨 온 지적: 일대일일 때만 승계
    groups: dict[str, list[Violation]] = {}
    for v in still:
        groups.setdefault(loose_key(v.rule_id, v.scope_name, shape_of(v)), []).append(v)
    for loose, vs in groups.items():
        moved = entries_with(loose, lambda e: e.path not in existing_paths)
        if len(vs) == 1 and len(moved) == 1:
            consumed.add(moved[0].fingerprint)
            vs[0].baseline_status = BaselineStatus.EXISTING if moved[0].rule_version == vs[0].rule_version else BaselineStatus.REVIEW
            outcome.matched[moved[0].fingerprint] = (vs[0], vs[0].baseline_status)
        else:
            if moved and vs:
                outcome.diagnostics.append(
                    Diagnostic(
                        kind="baseline",
                        severity="warning",
                        file_path=vs[0].file_path.as_posix(),
                        message=f"기준선과 대응이 모호해(옛 지적 {len(moved)}건, 현재 지적 {len(vs)}건) 승인을 승계하지 않았습니다.",
                    )
                )
            for v in vs:
                v.baseline_status = BaselineStatus.NEW

    for e in baseline.entries:
        if e.fingerprint in consumed:
            continue
        if e.path in scanned_paths:
            outcome.resolved.append(e)
        else:
            outcome.unobserved.append(e)  # 파일이 없거나 이번에 점검하지 못했다. 해소로 보지 않는다

    gone_rules = sorted({e.rule_id for e in outcome.resolved + outcome.unobserved if e.rule_id not in current_versions})
    for rule_id in gone_rules:
        outcome.diagnostics.append(
            Diagnostic(
                kind="baseline",
                severity="warning",
                message=f"기준선에 있는 규칙 {rule_id}가 삭제되었거나 이름이 바뀌었습니다. 해당 지적은 자동으로 승인되지 않으며 기준선을 다시 만들어야 합니다.",
            )
        )
    if outcome.unobserved:
        outcome.diagnostics.append(
            Diagnostic(
                kind="baseline",
                severity="warning",
                message=f"기준선의 지적 {len(outcome.unobserved)}건은 파일이 없거나 점검하지 못해 해소로 보지 않고 미확인으로 남겼습니다.",
            )
        )
    return outcome


@dataclass
class MigrationReport:
    baseline: Baseline
    migrated: list[tuple[BaselineEntry, Violation]] = field(default_factory=list)
    unmatched: list[BaselineEntry] = field(default_factory=list)  # 현재 지적과 맺지 못해 옮기지 않은 옛 항목


LINE_TOLERANCE = 5


def migrate_baseline(old: Baseline, violations: list[Violation], tool_version: str) -> MigrationReport:
    """옛 기준선의 항목을 현재 지문으로 옮긴다. 지문 계산 방식이 바뀌어(비밀 가림 등) 같은 지적이 다른 지문을 갖게 된 경우를 위한 것이다.
    항목은 '승인된 부채'로만 옮기며 사람의 검토 승인으로 승격하지 않는다. 일대일로 맺어지는 것만 옮긴다."""
    remaining = list(violations)
    migrated: list[tuple[BaselineEntry, Violation]] = []
    unmatched: list[BaselineEntry] = []
    for entry in old.entries:
        candidates = [v for v in remaining if v.rule_id == entry.rule_id and v.file_path.as_posix() == entry.path]
        exact = [v for v in candidates if v.fingerprint == entry.fingerprint]
        loose = [v for v in candidates if loose_key(v.rule_id, v.scope_name, shape_of(v)) == entry.loose]
        near = [v for v in candidates if abs(v.line_number - entry.line) <= LINE_TOLERANCE]
        pool = exact or loose or (near if len(near) == 1 else [])
        if len(pool) >= 1 and (exact or len(pool) == 1 or loose):
            chosen = pool[0]
            remaining.remove(chosen)
            migrated.append((entry, chosen))
        else:
            unmatched.append(entry)
    entries = [
        BaselineEntry(
            fingerprint=v.fingerprint,
            loose=loose_key(v.rule_id, v.scope_name, shape_of(v)),
            rule_id=v.rule_id,
            rule_version=v.rule_version,
            path=v.file_path.as_posix(),
            line=v.line_number,
            severity=v.severity.value,
        )
        for _e, v in migrated
    ]
    entries.sort(key=lambda e: (e.path, e.line, e.rule_id))
    new = Baseline(
        kind="debt",
        migrated_from=old.tool_version or "(알 수 없음)",
        tool_version=tool_version,
        created=datetime.now(UTC).strftime("%Y-%m-%d"),
        entries=entries,
    )
    return MigrationReport(new, migrated, unmatched)
