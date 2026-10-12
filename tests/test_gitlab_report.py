"""
오철칙 GitLab Code Quality 출력 시험
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def test_gitlab_codequality_format(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "gitlab-codequality", "--limit", "0"])
    issues = json.loads(result.stdout)
    hit = next(i for i in issues if i["check_name"] == "IL-504")
    assert hit["location"] == {"path": "app.py", "lines": {"begin": 5}}
    assert hit["severity"] in ("blocker", "critical") and len(hit["fingerprint"]) >= 16
    assert {i["severity"] for i in issues} <= {"info", "minor", "major", "critical", "blocker"}
    assert len({i["fingerprint"] for i in issues}) == len(issues)
    again = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--format", "gitlab-codequality", "--limit", "0"]).stdout)
    assert [i["fingerprint"] for i in again] == [i["fingerprint"] for i in issues]  # 같은 코드면 같은 지문(merge request 비교의 기준)
