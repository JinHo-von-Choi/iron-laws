"""
오철칙 선택형 검토 의견 시험: 의견은 review_opinion에만 담기고 판정은 바뀌지 않는다. 보내는 코드에서 비밀값을 가린다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import sys
from pathlib import Path

import pytest
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
    assert opinions == [{"source": Path(sys.executable).name, "verdict": "likely_false", "reason": "cmd는 내부 상수만 받는다",
                         "check": {"status": "unsupported", "why": "근거(basis)를 대지 않았다"}}]
    strip = lambda d: [(v["rule_id"], v["line_number"], v["severity"], v["confidence"]) for v in d["violations"]]  # noqa: E731
    assert strip(data) == strip(plain) and data["summary"]["is_passed"] == plain["summary"]["is_passed"]
    assert "Zq9xKm2LpQw8RtYuVn4B77" not in seen.read_text(encoding="utf-8")


def test_malformed_opinion_items_are_dropped():
    from iron_laws.core.triage import parse_opinions

    text = json.dumps([{"index": 0, "verdict": []}, {"index": True, "verdict": "unsure"}, {"index": 1, "verdict": {"a": 1}}, {"index": 2, "verdict": "likely_true", "reason": "r"}])
    assert parse_opinions(text, 3) == {2: {"verdict": "likely_true", "reason": "r"}}


def _violation(line: int, sources: list[int] = ()):
    from iron_laws.core.models import EvidenceStep, IronLaw, Severity, Violation

    return Violation(rule_id="IL-504", rule_name="명령", iron_law=IronLaw.LAW_5, severity=Severity.HIGH, file_path=Path("app.py"), line_number=line,
                     message="m", snippet="s", evidence=[EvidenceStep(role="source", file_path="app.py", line=n) for n in sources])


BASIS_CODE = [
    "import os",
    "def run(flag):",
    "    cmd = 'ls -l'",
    "    if False:",
    "        cmd = cmd + flag",
    "    safe = tidy_up(flag)",
    "    os.system(cmd)",
]


@pytest.mark.parametrize("basis, sources, status", [
    ({"kind": "constant", "line": 3, "name": "cmd"}, [], "unsupported"),  # 5번 줄에서 다시 넣는다
    ({"kind": "constant", "line": 3, "name": "cmd"}, [2], "contradicted"),
    ({"kind": "unreachable", "line": 4, "name": ""}, [], "corroborated"),
    ({"kind": "unreachable", "line": 2, "name": ""}, [], "unsupported"),
    ({"kind": "sanitized_by", "line": 6, "name": "tidy_up"}, [], "unsupported"),  # 오철칙이 아는 정제 함수가 아니다
    ({"kind": "not_external", "line": 2, "name": "flag"}, [2], "contradicted"),
    ({"kind": "not_external", "line": 2, "name": "flag"}, [], "unsupported"),
    ({"kind": "constant", "line": 99, "name": "cmd"}, [], "unsupported"),
])
def test_false_positive_claims_are_checked_against_code_and_engine_evidence(basis, sources, status):
    from iron_laws.core.triage import check_basis

    assert check_basis(BASIS_CODE, _violation(7, sources), basis)["status"] == status


def test_constant_and_known_sanitizer_claims_can_be_corroborated():
    from iron_laws.core.triage import check_basis

    code = ["def run(flag):", "    cmd = 'ls -l'", "    n = int(flag)", "    os.system(cmd + str(n))"]
    assert check_basis(code, _violation(4), {"kind": "constant", "line": 2, "name": "cmd"})["status"] == "corroborated"
    assert check_basis(code, _violation(4), {"kind": "sanitized_by", "line": 3, "name": "int"})["status"] == "corroborated"
    via_call = ["    String g = \"static\"; // 상수", "    String bar = thing.doSomething(g);", "    stmt.execute(\"x\" + bar);"]
    assert check_basis(via_call, _violation(3), {"kind": "constant", "line": 1, "name": "g"})["status"] == "unsupported"  # 다른 호출을 거친다
    direct = ["    String g = \"static\"; // 상수", "    stmt.execute(\"x\" + g);"]
    assert check_basis(direct, _violation(2), {"kind": "constant", "line": 1, "name": "g"})["status"] == "corroborated"
