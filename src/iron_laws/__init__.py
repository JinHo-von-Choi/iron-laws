"""
오철칙 (五鐵則 - Iron Laws)
SI 감리에서 자주 지적되는 항목을 정리한 소스코드 보안·품질 점검 CLI

작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.cli import app, main
from iron_laws.core.models import (
    AuditReport,
    AuditSummary,
    CodeFix,
    GovStandard,
    IronLaw,
    Severity,
    Violation,
)
from iron_laws.core.scanner import AuditScanner
from iron_laws.rules.catalog import ALL_RULES, get_active_rules

__version__ = "1.4.0"
__author__ = "최진호"

__all__ = [
    "ALL_RULES",
    "AuditReport",
    "AuditScanner",
    "AuditSummary",
    "CodeFix",
    "GovStandard",
    "IronLaw",
    "Severity",
    "Violation",
    "app",
    "get_active_rules",
    "main",
]
