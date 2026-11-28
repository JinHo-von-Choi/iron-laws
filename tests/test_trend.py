"""
오철칙 구조 추이(architecture --trend) 시험: 첫 기록, 직전 기록과 비교한 악화, 기록에 경로·코드가 없음
작성자: 최진호
작성일: 2026-11-28
"""

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_trend_records_and_reports_worsening(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "a")
    first = runner.invoke(app, ["architecture", str(tmp_path), "--trend"])
    assert first.exit_code == 0, first.output
    assert "첫 기록입니다" in first.output
    (tmp_path / "app" / "run.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    second = runner.invoke(app, ["architecture", str(tmp_path), "--trend"])
    assert "보안 기준 지적 0건 → 1건" in second.output
    rows = [json.loads(line) for line in (tmp_path / ".iron-laws-health.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2 and rows[1]["findings"].get("STANDARD") == 1
    assert "app/" not in (tmp_path / ".iron-laws-health.jsonl").read_text(encoding="utf-8")  # 경로를 기록하지 않는다
