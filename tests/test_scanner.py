"""
Tests for Audit Scanner
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-302] 탐지 대상 샘플 문자열

from pathlib import Path

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.models import IronLaw, Severity, Violation
from iron_laws.core.scanner import AuditScanner
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule


def test_scanner_with_clean_code(tmp_path: Path):
    clean_file = tmp_path / "clean_service.py"
    clean_file.write_text(
        "import os\n"
        "import hashlib\n\n"
        "def get_hash(data: str):\n"
        "    return hashlib.sha256(data.encode()).hexdigest()\n"
    )

    scanner = AuditScanner(tmp_path)
    report = scanner.scan()

    assert report.summary.is_passed is True
    assert report.summary.total_violations == 0
    assert report.summary.grade == "A+"


def test_scanner_detects_violations(tmp_path: Path):
    vulnerable_file = tmp_path / "vulnerable_service.py"
    vulnerable_file.write_text(
        "api_key = 'super_secret_token_12345'\ntry:\n    eval('1+1')\nexcept Exception: pass\n"
    )

    scanner = AuditScanner(tmp_path)
    report = scanner.scan()

    assert report.summary.is_passed is False
    assert report.summary.total_violations >= 2
    assert report.summary.critical_count >= 1
    assert report.summary.grade in ("D", "F")


def test_scanner_excludes_by_relative_path_not_absolute_location(tmp_path: Path):
    project = tmp_path / "build" / "env" / "proj"
    project.mkdir(parents=True)
    (project / "app.py").write_text("password = 'MyHardcodedPassword123!'\n")

    report = AuditScanner(project).scan()

    assert report.summary.total_files_scanned == 1
    assert report.summary.critical_count == 1


def test_scanner_still_excludes_configured_directories_inside_project(tmp_path: Path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("password = 'MyHardcodedPassword123!'\n")

    report = AuditScanner(tmp_path).scan()

    assert report.summary.total_files_scanned == 0


def test_scanner_applies_disabled_test_rule_inside_test_directories(tmp_path: Path):
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_pay.py").write_text(
        "import pytest\n\n@pytest.mark.skip\ndef test_pay():\n    pass\n"
        "password = 'MyHardcodedPassword123!'\n"
    )

    report = AuditScanner(tmp_path).scan()

    assert [v.rule_id for v in report.violations if v.rule_id == "IL-302"] == ["IL-302"]
    assert "IL-101" not in {v.rule_id for v in report.violations}


class _LowSeverityRule(BaseRule):
    rule_id = "IL-TEST-LOW"
    name = "low severity stub"
    iron_law = IronLaw.LAW_1
    severity = Severity.LOW
    gov_standard = None

    def check(self, src: SourceFile) -> list[Violation]:
        return [self.at_line(src, 1, "low finding")]


def _scan_with_low_rule(tmp_path: Path, fail_on: Severity):
    (tmp_path / "a.py").write_text("x = 1\n")
    scanner = AuditScanner(tmp_path, IronLawsConfig(fail_on=fail_on))
    scanner.rules = [_LowSeverityRule()]
    return scanner.scan()


def test_fail_on_low_fails_when_only_low_violations_exist(tmp_path: Path):
    report = _scan_with_low_rule(tmp_path, Severity.LOW)
    assert report.summary.is_passed is False
    assert report.summary.grade == "A-"


def test_fail_on_medium_passes_when_only_low_violations_exist(tmp_path: Path):
    report = _scan_with_low_rule(tmp_path, Severity.MEDIUM)
    assert report.summary.is_passed is True
