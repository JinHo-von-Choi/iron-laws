"""
오철칙 SARIF 2.1.0 Reporter (GitHub Code Scanning 연동)
작성자: 최진호
작성일: 2026-10-04
"""

import json
from urllib.parse import quote

from iron_laws.core.models import AuditReport, BaselineStatus, Severity, Violation
from iron_laws.rules.base import BaseRule

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
}


def _uri(report: AuditReport, path: str) -> str:
    """결과 위치는 저장소 루트 기준 상대 경로로 쓴다. 하위 폴더만 점검해도 위치가 어긋나지 않게 접두 경로를 붙이고 각 구간을 인코딩한다."""
    prefix = str(report.metadata.get("repo_relative_prefix", "")).strip("/")
    full = f"{prefix}/{path}" if prefix else path
    return quote(full, safe="/")


def _code_flows(report: AuditReport, v: Violation) -> dict:
    """입력 유입 → 전파 → 싱크의 흐름을 SARIF codeFlows로 내보낸다. 위치와 변수 이름만 담는다."""
    if len(v.evidence) < 2:
        return {}
    locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(report, e.file_path), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(e.line, 1)},
                },
                "message": {"text": e.note},
            }
        }
        for e in v.evidence
    ]
    return {"codeFlows": [{"threadFlows": [{"locations": locations}]}]}


def _baseline_state(v: Violation) -> dict:
    if v.baseline_status is None:
        return {}
    return {"baselineState": "unchanged" if v.baseline_status is BaselineStatus.EXISTING else "new"}


def _ledger_properties(report: AuditReport) -> dict:
    ledger = report.coverage_ledger
    if ledger is None:
        return {}
    return {
        "status": ledger.status,
        "contractMode": ledger.contract_mode,
        "contractScope": ledger.contract_scope,
        "contractDigest": ledger.contract_digest,
        "digests": ledger.digests,
        "families": [t.model_dump() for t in ledger.families],
        "unclassifiedFiles": sum(1 for f in ledger.files if f.classification == "unclassified"),
        "unclassifiedChangedFiles": ledger.unclassified_changed_files,
        "limitations": ledger.limitations,
    }


def _invocation(report: AuditReport) -> dict:
    """점검이 끝까지 이루어졌는지와 검사 공백을 SARIF invocation에 남긴다. 소비 도구가 결과 0건을 '문제 없음'으로 오해하지 않게 한다."""
    notifications = []
    for d in report.diagnostics:
        if d.severity in ("error", "warning"):
            notifications.append(
                {
                    "level": "error" if d.severity == "error" else "warning",
                    "message": {"text": d.message},
                    "descriptor": {"id": f"diagnostic/{d.kind}"},
                    **({"locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(report, d.file_path), "uriBaseId": "%SRCROOT%"}}}]} if d.file_path else {}),
                }
            )
    ledger = report.coverage_ledger
    if ledger is not None:
        for p in ledger.points:
            if p.in_scope and p.state in ("unsupported", "unresolved", "budget_exceeded"):
                notifications.append(
                    {
                        "level": "warning",
                        "message": {"text": f"[{p.family}] {p.callee}() — {p.state}: {p.reason}"},
                        "descriptor": {"id": f"coverage/{p.state}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": _uri(report, p.path), "uriBaseId": "%SRCROOT%"},
                                    "region": {"startLine": max(p.line, 1)},
                                }
                            }
                        ],
                    }
                )
    scan_ok = report.summary.scan_status == "complete"
    return {
        "executionSuccessful": scan_ok,
        "toolExecutionNotifications": notifications,
        "properties": {
            "scanStatus": report.summary.scan_status,
            "contractStatus": report.summary.contract_status,
        },
    }


def generate_sarif_report(report: AuditReport, rules: list[BaseRule], version: str = "0.1.0") -> str:
    used = {v.rule_id for v in report.violations}
    rule_entries = []
    for rule in rules:
        if rule.rule_id not in used:
            continue
        help_text = rule.how_to_fix or rule.plain
        rule_entries.append(
            {
                "id": rule.rule_id,
                "name": rule.name,
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.plain or rule.name},
                "help": {"text": help_text, "markdown": help_text},
                "defaultConfiguration": {"level": LEVELS[rule.severity]},
                "properties": {
                    "tags": ["security", rule.layer.value]
                    + ([rule.gov_standard.clause_id] if rule.gov_standard else []),
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    results = []
    for v in report.violations:
        results.append(
            {
                "ruleId": v.rule_id,
                "level": LEVELS[v.severity],
                "message": {"text": v.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _uri(report, v.file_path.as_posix()), "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": v.line_number, "startColumn": v.column},
                        }
                    }
                ],
                **_code_flows(report, v),
                **_baseline_state(v),
                "partialFingerprints": {"ironLaws/v1": v.fingerprint} if v.fingerprint else {},
                "properties": {
                    "approvalStatus": v.approval_status,
                    "confidence": v.confidence.value,
                    "layer": v.layer.value,
                    "severity": v.severity.value,
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iron-laws",
                        "version": version,
                        "informationUri": "https://github.com/JinHo-von-Choi/iron-laws",
                        "rules": rule_entries,
                    }
                },
                "results": results,
                "invocations": [_invocation(report)],
                "properties": {"coverageLedger": _ledger_properties(report)},
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
