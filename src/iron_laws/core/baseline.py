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
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from iron_laws.core.config import ConfigError
from iron_laws.core.models import AuditReport, AuditSummary, BaselineStatus, Diagnostic, Violation

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
    schema_version: int = BASELINE_SCHEMA
    tool_version: str = ""
    created: str = ""
    entries: list[BaselineEntry] = Field(default_factory=list)


def _digest(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:20]


def make_fingerprint(rule_id: str, rule_version: int, path: str, scope: str, shape: str, occurrence: int) -> str:
    return _digest(rule_id, rule_version, path, scope, shape, occurrence)


def shape_of(v: Violation) -> str:
    return re.sub(r"\s+", " ", v.snippet).strip()


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


def apply_baseline(
    violations: list[Violation],
    baseline: Baseline,
    summary: AuditSummary,
    current_versions: dict[str, int],
) -> list[Diagnostic]:
    """각 지적에 기준선 대비 상태를 붙이고 요약 건수를 채운다."""
    diagnostics: list[Diagnostic] = []
    by_fingerprint = {e.fingerprint: e for e in baseline.entries}
    by_loose: dict[str, list[BaselineEntry]] = {}
    for e in baseline.entries:
        by_loose.setdefault(e.loose, []).append(e)
    consumed: set[str] = set()

    unmatched: list[Violation] = []
    for v in violations:
        entry = by_fingerprint.get(v.fingerprint)
        if entry is not None and entry.fingerprint not in consumed:
            consumed.add(entry.fingerprint)
            v.baseline_status = BaselineStatus.EXISTING
        else:
            unmatched.append(v)

    for v in unmatched:
        loose = loose_key(v.rule_id, v.scope_name, shape_of(v))
        candidates = [e for e in by_loose.get(loose, []) if e.fingerprint not in consumed]
        if not candidates:
            v.baseline_status = BaselineStatus.NEW
            continue
        entry = candidates[0]
        consumed.add(entry.fingerprint)
        # 규칙의 판정 의미가 바뀌었으면 승인된 지적으로 보지 않고 다시 검토한다
        v.baseline_status = BaselineStatus.EXISTING if entry.rule_version == v.rule_version else BaselineStatus.REVIEW

    resolved = [e for e in baseline.entries if e.fingerprint not in consumed]
    gone_rules = sorted({e.rule_id for e in resolved if e.rule_id not in current_versions})
    for rule_id in gone_rules:
        diagnostics.append(
            Diagnostic(
                kind="baseline",
                severity="warning",
                message=f"기준선에 있는 규칙 {rule_id}가 삭제되었거나 이름이 바뀌었습니다. 해당 지적은 자동으로 승인되지 않으며 기준선을 다시 만들어야 합니다.",
            )
        )
    summary.new_count = sum(1 for v in violations if v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW))
    summary.existing_count = sum(1 for v in violations if v.baseline_status is BaselineStatus.EXISTING)
    summary.resolved_count = len(resolved)
    return diagnostics
