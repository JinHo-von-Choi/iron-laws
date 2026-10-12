"""
오철칙 GitLab Code Quality 보고서(merge request 위젯용 JSON 배열)
지문은 기준선과 같은 지문(fingerprint)을 쓴다. 지문이 없으면 규칙·경로·줄로 만든다.
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import json

from iron_laws.core.models import AuditReport, Confidence, Severity

SEVERITY = {Severity.CRITICAL: "blocker", Severity.HIGH: "critical", Severity.MEDIUM: "major", Severity.LOW: "minor"}


def generate_gitlab_report(report: AuditReport) -> str:
    issues = []
    for v in report.violations:
        fingerprint = v.fingerprint or hashlib.sha256(f"{v.rule_id}|{v.file_path.as_posix()}|{v.line_number}".encode()).hexdigest()
        review = " (확인 필요)" if v.confidence is Confidence.REVIEW else ""
        issues.append({
            "description": f"{v.rule_id} {v.rule_name}{review}: {v.message}",
            "check_name": v.rule_id,
            "fingerprint": fingerprint,
            "severity": SEVERITY[v.severity],
            "location": {"path": v.file_path.as_posix(), "lines": {"begin": v.line_number}},
        })
    return json.dumps(issues, ensure_ascii=False, indent=2)
