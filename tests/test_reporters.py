"""
Tests for Reporters
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

from iron_laws.core.models import (
    AuditReport,
    AuditSummary,
    CodeFix,
    GovStandard,
    IronLaw,
    Severity,
    Violation,
)
from iron_laws.reporters.json_reporter import generate_json_report
from iron_laws.reporters.markdown import generate_markdown_report


def test_markdown_and_json_reporters():
    summary = AuditSummary(
        total_files_scanned=5,
        total_violations=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        is_passed=False,
        grade="F",
    )
    v = Violation(
        rule_id="IL-101",
        rule_name="Hardcoded Secret",
        iron_law=IronLaw.LAW_1,
        severity=Severity.CRITICAL,
        file_path=Path("test.py"),
        line_number=1,
        snippet="api_key = 'sk_test_12345'",
        message="시크릿 발견",
        gov_standard=GovStandard(
            standard_name="행안부 SW 개발보안 가이드",
            clause_id="행안부 2-4",
            description="비밀번호 하드코딩 금지",
        ),
        fix=CodeFix(
            before_snippet="api_key = 'sk_test_12345'",
            after_snippet="api_key = os.getenv('API_KEY')",
            rationale="환경변수 사용",
        ),
    )
    report = AuditReport(
        document_id="AUDIT-TEST",
        audit_date="2026-10-04",
        target_path=".",
        summary=summary,
        violations=[v],
    )

    md = generate_markdown_report(report)
    assert "# SW 개발보안 점검 보고서" in md
    assert "[공식]" not in md
    assert "AUDIT-TEST" in md
    assert "IL-101" in md
    assert "교정 예시 (AFTER)" in md

    json_str = generate_json_report(report)
    assert '"document_id": "AUDIT-TEST"' in json_str
