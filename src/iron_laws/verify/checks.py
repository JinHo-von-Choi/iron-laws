"""검증 항목 생성·대상 선택·공백 집계의 공통 계약."""
from typing import Any

from iron_laws.core.config import ConfigError
from iron_laws.core.models import AuditReport, Violation
from iron_laws.verify.receipt import CheckResult, CheckState


class FindingSelectionError(ConfigError):
    """지적을 하나로 정하지 못했을 때"""


def resolve_finding(report: AuditReport, spec: str) -> Violation:
    """지문 접두사, `RULE@경로:줄`, `RULE@경로`로 원본 지적 하나를 고른다."""
    candidates: list[Violation]
    if "@" in spec:
        rule, _, location = spec.partition("@")
        path, _, line = location.partition(":")
        candidates = [
            v for v in report.violations if v.rule_id.upper() == rule.upper() and v.file_path.as_posix() == path and (not line or str(v.line_number) == line)
        ]
    else:
        candidates = [v for v in report.violations if v.fingerprint.startswith(spec)]
    if not candidates:
        raise FindingSelectionError(f"지정한 지적을 원본에서 찾지 못했습니다: {spec}")
    if len(candidates) > 1:
        shown = ", ".join(f"{v.rule_id}@{v.file_path.as_posix()}:{v.line_number}" for v in candidates[:5])
        raise FindingSelectionError(f"지적이 여럿이라 하나로 정하지 못했습니다({len(candidates)}건): {shown}")
    return candidates[0]


def _check(id_: str, title: str, result: CheckState, reason: str = "", required: bool = True, executed: bool = True, **evidence: Any) -> CheckResult:
    return CheckResult(id=id_, title=title, result=result, reason=reason, required=required, executed=executed, evidence=evidence)


def _gaps_by_location(report: AuditReport) -> dict[tuple[str, str, str], int]:
    gaps: dict[tuple[str, str, str], int] = {}
    if report.coverage_ledger is None:
        return gaps
    for p in report.coverage_ledger.points:
        if p.in_scope and p.state in ("unsupported", "unresolved", "budget_exceeded"):
            key = (p.family, p.path, p.state)
            gaps[key] = gaps.get(key, 0) + 1
    return gaps
