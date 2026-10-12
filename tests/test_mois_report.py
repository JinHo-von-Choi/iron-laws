"""
오철칙 감리 대응 보고서 시험: 항목별 지적·잔존 사유(억제 주석)·미점검 사유(장부 공백·미탑재)·docx 출력
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.contract import default_contract
from iron_laws.core.scanner import AuditScanner
from iron_laws.reporters.mois_report import build_rows, generate_mois_report

runner = CliRunner()
CODE = (
    "import os\nimport subprocess\nfrom flask import request\nfrom tools import pick\n\n"
    "def a():\n    os.system('ls ' + request.args['d'])\n\n"
    "def b():\n    os.system('ls ' + request.args['e'])  # iron-laws: ignore[IL-504] 관리자 전용 내부망 도구, 보안팀 검토 SEC-7 until=2099-01-01\n\n"
    "def c():\n    subprocess.run(pick(), shell=True)\n"
)


def _report(tmp_path: Path):
    (tmp_path / "app.py").write_text(CODE, encoding="utf-8")
    scanner = AuditScanner(tmp_path, contract=default_contract())
    return scanner.scan(), scanner.rules


def test_rows_carry_findings_remaining_reasons_and_gaps(tmp_path: Path):
    report, rules = _report(tmp_path)
    rows = {r.item_id: r for r in build_rows(report, rules)}
    cmd = rows["1-5"]
    assert cmd.status == "지적 있음" and any(v.line_number == 7 for v in cmd.findings)
    assert any("SEC-7" in line and "2099-01-01" in line for line in cmd.remaining)
    assert len(rows) == 49
    assert any(line.startswith("근거 공백") for line in cmd.unchecked)  # pick()의 출처를 정하지 못한 명령 실행 지점


def test_markdown_and_docx_outputs(tmp_path: Path):
    report, rules = _report(tmp_path)
    text = generate_mois_report(report, rules)
    assert "## 항목별 현황" in text and "| 1-5 |" in text and "취약점이 없다는 증명이 아닙니다" in text
    pytest.importorskip("docx")
    out = tmp_path / "report.docx"
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "mois-report", "-o", str(out)])
    assert out.is_file() and out.stat().st_size > 1000, result.output
    import docx

    body = "\n".join(p.text for p in docx.Document(str(out)).paragraphs)
    assert "감리 대응 보고서" in body
