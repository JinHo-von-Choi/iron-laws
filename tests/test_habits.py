"""
오철칙 AI 습관 시계열 시험
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def test_habit_history_records_and_trends(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    history = tmp_path / "h.jsonl"
    (project / "a.py").write_text("def f():\n    try:\n        g()\n    except Exception:\n        pass\n", encoding="utf-8")
    first = json.loads(runner.invoke(app, ["habits", str(project), "--history", str(history), "--format", "json"]).stdout)
    assert first["records"] == 1 and first["trend"]["swallowed_exception"]["latest"] > 0
    again = json.loads(runner.invoke(app, ["habits", str(project), "--history", str(history), "--format", "json"]).stdout)
    assert again["records"] == 1  # 같은 코드는 같은 점으로 기록한다
    (project / "a.py").write_text("def f():\n    g()\n", encoding="utf-8")
    third = json.loads(runner.invoke(app, ["habits", str(project), "--history", str(history), "--format", "json"]).stdout)
    assert third["records"] == 2 and third["trend"]["swallowed_exception"]["change"] < 0
    stored = history.read_text(encoding="utf-8")
    assert "def f" not in stored and "g()" not in stored and "/p/" not in stored  # 경로·코드는 기록하지 않는다
