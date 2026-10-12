"""
오철칙 코딩 에이전트 훅 시험(Claude Code PostToolUse 입력 형식)
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def _payload(root: Path, rel: str) -> str:
    return json.dumps({"tool_name": "Write", "cwd": str(root), "tool_input": {"file_path": rel}})


def test_hook_returns_2_with_findings_for_the_agent(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    result = runner.invoke(app, ["hook", "claude-code"], input=_payload(tmp_path, "app.py"))
    assert result.exit_code == 2
    assert "IL-504" in result.stderr and "app.py:5" in result.stderr


def test_hook_passes_clean_files_and_non_files(tmp_path: Path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert runner.invoke(app, ["hook", "claude-code"], input=_payload(tmp_path, "ok.py")).exit_code == 0
    assert runner.invoke(app, ["hook", "claude-code"], input=json.dumps({"tool_input": {}})).exit_code == 0
    assert runner.invoke(app, ["hook", "other"], input="{}").exit_code == 2
