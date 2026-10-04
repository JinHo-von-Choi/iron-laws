"""
오철칙 JSON Reporter (CI/CD Pipeline Machine-Readable)
작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.core.models import AuditReport


def generate_json_report(report: AuditReport) -> str:
    return report.model_dump_json(indent=2)
