"""
오철칙 점검 비용 장부 시험: 점검에 쓴 시간과 메모리가 보고서에 남고, 시간 상한을 넘으면 통과가 아니라 점검 불완전이다.
- execution.cost: 경과 시간·CPU 시간·최대 메모리·초당 파일 수·단계별 시간·작업 프로세스 수
- limits.max_wall_seconds: 상한을 넘으면 scan_status가 incomplete가 되고 종료코드는 2
작성자: 최진호
작성일: 2026-10-22
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_report

cli = CliRunner()
APP = 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'
CLEAN = "def add(a, b):\n    return a + b\n"


def _project(root: Path, content: str = APP) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(content, encoding="utf-8")
    return root


def test_the_report_carries_the_scan_cost(tmp_path: Path):
    project = _project(tmp_path / "proj")
    report = AuditScanner(project).scan()
    cost = report.execution.cost
    assert cost is not None
    assert cost.wall_seconds >= 0
    assert cost.files_per_second > 0
    assert cost.workers >= 1
    assert cost.budget_seconds is None and cost.budget_exceeded is False
    assert "file_rules" in cost.phase_seconds


def test_the_independent_verifier_accepts_a_report_with_a_cost_block(tmp_path: Path):
    project = _project(tmp_path / "proj")
    report = AuditScanner(project).scan()
    result = verify_report(report.model_dump(mode="json"))
    assert result.ok, [str(p) for p in result.problems]


def test_exceeding_the_wall_clock_budget_makes_the_scan_incomplete(tmp_path: Path):
    project = _project(tmp_path / "proj")
    report = AuditScanner(project).scan()
    assert report.summary.scan_status == "complete"
    scanner = AuditScanner(project)
    scanner.config.limits.max_wall_seconds = 0.000001
    report = scanner.scan()
    assert report.summary.scan_status == "incomplete"
    assert report.summary.is_passed is False
    assert report.execution.cost is not None and report.execution.cost.budget_exceeded is True
    assert any(d.kind == "budget" and d.severity == "error" for d in report.diagnostics)


def test_the_wall_clock_budget_from_the_command_line_fails_the_run(tmp_path: Path):
    project = _project(tmp_path / "proj", CLEAN)
    ok = cli.invoke(app, ["check", str(project), "--max-wall-seconds", "600"])
    assert ok.exit_code == 0
    over = cli.invoke(app, ["check", str(project), "--max-wall-seconds", "0.000001"])
    assert over.exit_code == 2


def test_the_cost_block_survives_the_json_report(tmp_path: Path):
    project = _project(tmp_path / "proj", CLEAN)
    out = tmp_path / "report.json"
    result = cli.invoke(app, ["audit", str(project), "--format", "json", "-o", str(out)])
    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    cost = payload["execution"]["cost"]
    assert cost["wall_seconds"] >= 0
    assert cost["files_per_second"] > 0
    assert isinstance(cost["phase_seconds"], dict)
