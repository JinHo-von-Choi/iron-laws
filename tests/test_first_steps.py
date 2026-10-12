"""
오철칙 첫 실행 요약 시험: 지적이 30개를 넘으면 심각도·확정 순으로 3개와 다음 명령을 먼저 보인다
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.reporters.console import first_steps

runner = CliRunner()


def test_first_steps_only_when_many_findings(tmp_path: Path):
    (tmp_path / "small.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    assert first_steps(AuditScanner(tmp_path).scan()) == []
    many = "\n".join(f"password{i} = 'Zq9xKm2LpQw8RtYuVn4B{i:02d}'" for i in range(40)) + "\n"
    (tmp_path / "many.py").write_text(many, encoding="utf-8")
    report = AuditScanner(tmp_path).scan()
    assert report.summary.total_violations > 30
    picks = first_steps(report)
    assert len(picks) == 3 and all(v.severity.value == "CRITICAL" for v in picks)  # CRITICAL·확정이 먼저
    result = runner.invoke(app, ["check", str(tmp_path), "--limit", "1"])
    assert "먼저 할 일" in result.stdout and "fix-prompt" in result.stdout
