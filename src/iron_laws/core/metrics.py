"""
오철칙 최소 계측: 점검 한 번의 집계값만 로컬 파일에 한 줄로 남긴다(선택 기능, 기본은 꺼짐)
- 경로·코드·메시지·사용자 이름은 담지 않는다. 건수와 시간, 식별 해시만 담는다. 외부로 보내지 않는다.
- 관찰 모드(1~2주)에서 영향 계산 오류·unknown 비율·검토 대기열 크기·점검 시간을 보려는 용도다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from iron_laws.core.models import AuditReport

METRICS_SCHEMA = "iron-laws.metrics/1"
GAP_STATES = ("unsupported", "unresolved", "budget_exceeded")


def metrics_record(report: AuditReport, elapsed_s: float, command: str) -> dict[str, Any]:
    s = report.summary
    ledger = report.coverage_ledger
    states: dict[str, int] = {}
    if ledger is not None:
        for p in ledger.points:
            if p.in_scope:
                states[p.state] = states.get(p.state, 0) + 1
    review = sum(1 for v in report.violations if v.confidence.value == "REVIEW")
    queue = sum(1 for v in report.violations if v.confidence.value == "REVIEW" and v.approval_status in (None, "none", "expired", "revoked", "invalid"))
    queue += sum(1 for c in report.approval_checks if c.status in ("needs_review", "unobserved", "invalid"))
    return {
        "schema": METRICS_SCHEMA,
        "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": command,
        "tool_version": report.execution.tool_version if report.execution else "",
        "run_id": report.execution.run_id if report.execution else "",
        "elapsed_s": round(elapsed_s, 3),
        "scan_status": s.scan_status,
        "files_scanned": s.total_files_scanned,
        "findings": {"total": s.total_violations, "critical": s.critical_count, "high": s.high_count, "medium": s.medium_count, "low": s.low_count, "review_confidence": review},
        "contract": {"status": s.contract_status, "mode": s.contract_mode, "points_in_scope": sum(states.values()), "gaps": {k: states.get(k, 0) for k in GAP_STATES}, "unknown_rate": round(sum(states.get(k, 0) for k in GAP_STATES) / sum(states.values()), 3) if states else 0.0},
        "trust": {"analysis_unknown_rate": s.analysis_unknown_rate, "evaluated_rule_language_pairs": s.evaluated_rule_language_pairs, "unverified_rule_language_pairs": s.unverified_rule_language_pairs, "unverified_rule_language_rate": s.unverified_rule_language_rate, "gate_exceeded": len(s.gate_exceeded)},
        "approvals": {"valid": s.approvals_valid, "review": s.approvals_review, "unobserved": s.approvals_unobserved, "rows": {st: sum(1 for c in report.approval_checks if c.status == st) for st in ("valid", "needs_review", "invalid", "unobserved", "resolved", "revoked")}},
        "review_queue_size": queue,
        "diagnostics": {"errors": sum(1 for d in report.diagnostics if d.severity == "error"), "warnings": sum(1 for d in report.diagnostics if d.severity == "warning")},
        "passed": s.is_passed,
    }


def append_metrics(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
