"""
오철칙 선택형 검토 의견 시험: 의견은 review_opinion에만 담기고 판정은 바뀌지 않는다. 보내는 코드에서 비밀값을 가린다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import sys
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()
CODE = "import os\nAPI_TOKEN = 'Zq9xKm2LpQw8RtYuVn4B77'\n\ndef run(cmd):\n    os.system('ls ' + cmd)\n"


def test_opinions_are_attached_without_changing_verdicts(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text(CODE, encoding="utf-8")
    seen = tmp_path / "seen.txt"
    fake = tmp_path / "llm.py"
    fake.write_text(
        "import sys, json\n"
        f"prompt = sys.stdin.read()\nopen({str(seen)!r}, 'w').write(prompt)\n"
        "print(json.dumps([{'index': 0, 'verdict': 'likely_false', 'reason': 'cmd는 내부 상수만 받는다'}, {'index': 99, 'verdict': 'x'}]))\n",
        encoding="utf-8",
    )
    plain = json.loads(runner.invoke(app, ["audit", str(project), "--format", "json", "--limit", "0"]).stdout)
    result = runner.invoke(app, ["audit", str(project), "--format", "json", "--limit", "0", "--triage-model", f"{sys.executable} {fake}"])
    data = json.loads(result.stdout)
    opinions = [v["review_opinion"] for v in data["violations"] if v.get("review_opinion")]
    assert opinions == [{"source": Path(sys.executable).name, "verdict": "likely_false", "reason": "cmd는 내부 상수만 받는다"}]
    strip = lambda d: [(v["rule_id"], v["line_number"], v["severity"], v["confidence"]) for v in d["violations"]]  # noqa: E731
    assert strip(data) == strip(plain) and data["summary"]["is_passed"] == plain["summary"]["is_passed"]
    assert "Zq9xKm2LpQw8RtYuVn4B77" not in seen.read_text(encoding="utf-8")


def test_malformed_opinion_items_are_dropped():
    from iron_laws.core.triage import parse_opinions

    text = json.dumps([{"index": 0, "verdict": []}, {"index": True, "verdict": "unsure"}, {"index": 1, "verdict": {"a": 1}}, {"index": 2, "verdict": "likely_true", "reason": "r"}])
    assert parse_opinions(text, 3) == {2: {"verdict": "likely_true", "reason": "r"}}
