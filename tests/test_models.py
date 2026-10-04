"""
Tests for Core Models
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


def test_models_serialization():
    std = GovStandard(
        standard_name="행정안전부 SW 개발보안 가이드",
        clause_id="행안부 1-1",
        description="SQL 삽입 방지",
    )
    fix = CodeFix(
        before_snippet="select * from user where id = '${id}'",
        after_snippet="select * from user where id = #{id}",
        rationale="PreparedStatement 적용",
    )
    v = Violation(
        rule_id="IL-501",
        rule_name="SQL Injection",
        iron_law=IronLaw.LAW_5,
        severity=Severity.CRITICAL,
        file_path=Path("src/UserMapper.xml"),
        line_number=10,
        snippet="SELECT * FROM user WHERE id = '${id}'",
        message="SQLi 발견",
        gov_standard=std,
        fix=fix,
    )

    summary = AuditSummary(
        total_files_scanned=1,
        total_violations=1,
        critical_count=1,
        high_count=0,
        medium_count=0,
        low_count=0,
        is_passed=False,
        grade="F",
    )

    report = AuditReport(
        document_id="TEST-001",
        audit_date="2026-10-04",
        target_path=".",
        summary=summary,
        violations=[v],
    )

    json_str = report.model_dump_json()
    assert "TEST-001" in json_str
    assert "행안부 1-1" in json_str
    assert v.severity == Severity.CRITICAL
