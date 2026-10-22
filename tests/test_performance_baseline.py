"""
오철칙 성능 기준선 시험: 기준선은 지적뿐 아니라 점검 비용도 함께 남기고, 비용이 크게 늘면 비율로 알린다.
- 기준선 파일에 점검 비용(시간·초당 파일 수·작업 프로세스 수)이 함께 기록된다
- 기준선이 없거나 시간이 1초 미만이면 회귀를 말하지 않는다(비교할 수 없다)
- 2배 이상 늘었을 때만 회귀로 말한다
작성자: 최진호
작성일: 2026-10-22
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.baseline import BaselineCost, build_baseline
from iron_laws.core.models import AuditReport, AuditSummary, ExecutionRecord, ScanCost

cli = CliRunner()
SECRET = 'PASSWORD = "hunter2hunter2"\n'


def _report(wall_seconds: float) -> AuditReport:
    return AuditReport(
        document_id="AUDIT-1",
        audit_date="2026-10-22",
        target_path=".",
        summary=AuditSummary(total_files_scanned=10),
        execution=ExecutionRecord(
            run_id="R-1",
            tool_version="1.8.0",
            ruleset_hash="r",
            config_hash="c",
            contract_digest="d",
            code_digest="k",
            scan_status="complete",
            files_scanned=10,
            files_skipped=0,
            error_diagnostics=0,
            cost=ScanCost(
                wall_seconds=wall_seconds,
                cpu_seconds=wall_seconds,
                peak_rss_mb=10.0,
                files_per_second=10.0 / max(wall_seconds, 0.001),
                workers=8,
            ),
        ),
    )


def test_the_baseline_records_the_scan_cost():
    baseline = build_baseline(_report(2.5), "1.8.0")
    assert baseline.cost is not None
    assert baseline.cost.wall_seconds == 2.5
    assert baseline.cost.workers == 8
    assert baseline.cost.files_scanned == 10


def test_a_baseline_without_cost_still_loads():
    import tempfile

    from iron_laws.core.baseline import load_baseline

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "b.json"
        path.write_text(json.dumps({"schema_version": 1, "entries": []}), encoding="utf-8")
        baseline = load_baseline(path)
        assert baseline.cost is None


def test_the_cost_regression_is_reported_as_a_ratio(tmp_path: Path):
    from iron_laws.core.baseline import Baseline, BaselineEntry
    from iron_laws.core.scanner import AuditScanner

    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(SECRET, encoding="utf-8")
    baseline_path = tmp_path / "b.json"
    baseline = Baseline(
        schema_version=1,
        entries=[BaselineEntry(fingerprint="f", loose="l", rule_id="IL-101", path="app.py", line=1, severity="CRITICAL")],
        cost=BaselineCost(wall_seconds=0.2, files_per_second=50.0, files_scanned=10, workers=8),
    )
    baseline_path.write_text(json.dumps(baseline.model_dump(mode="json"), ensure_ascii=False), encoding="utf-8")

    scanner = AuditScanner(project)
    scanner.config.limits.max_wall_seconds = None
    report = scanner.scan()
    assert not [d for d in report.diagnostics if d.kind == "cost"], "1초 미만 기준선은 비교하지 않는다"


def test_a_cost_that_grew_by_twice_is_reported(tmp_path: Path):
    from iron_laws.core.baseline import Baseline
    from iron_laws.core.scanner import AuditScanner

    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(SECRET, encoding="utf-8")
    baseline = Baseline(
        schema_version=1,
        entries=[],
        cost=BaselineCost(wall_seconds=5.0, files_per_second=2.0, files_scanned=10, workers=8),
    )
    scanner = AuditScanner(project, baseline=baseline)
    scanner.scan()
    scanner._cost = ScanCost(
        wall_seconds=12.0, cpu_seconds=12.0, peak_rss_mb=10.0, files_per_second=0.8, workers=8
    )
    scanner._note_cost_regression(baseline)
    notes = [d for d in scanner._diagnostics if d.kind == "cost"]
    assert notes, "기준선보다 2배 넘게 늘었으면 알려야 한다"
    assert "2.4배" in notes[0].message


def test_the_baseline_cost_is_written_to_the_file(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(SECRET, encoding="utf-8")
    out = tmp_path / "baseline.json"
    result = cli.invoke(app, ["baseline", "create", str(project), "-o", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["cost"]["wall_seconds"] >= 0
    assert data["cost"]["files_scanned"] == 1
