"""
오철칙 SARIF 2.1.0 Reporter (GitHub Code Scanning 연동)
작성자: 최진호
작성일: 2026-10-04
"""

import json

from iron_laws.core.models import AuditReport, Severity
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
                            "artifactLocation": {"uri": v.file_path.as_posix()},
                            "region": {"startLine": v.line_number, "startColumn": v.column},
                        }
                    }
                ],
                "properties": {
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
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
