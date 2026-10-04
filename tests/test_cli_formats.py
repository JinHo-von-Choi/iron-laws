"""
오철칙 CLI 출력 형식과 보조 명령 시험
작성자: 최진호
작성일: 2026-10-04
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()

VULNERABLE = (
    "import os\n"
    "def h():\n"
    '    os.system("ls " + request.args["d"])\n'
    "def g():\n"
    "    try:\n"
    "        x()\n"
    "    except ValueError:\n"
    "        pass\n"
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(VULNERABLE, encoding="utf-8")
    return tmp_path


def test_sarif_output_is_valid_and_has_rules(project: Path):
    result = runner.invoke(app, ["audit", str(project), "--format", "sarif"])
    assert result.exit_code == 1
    sarif = json.loads(result.stdout)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"IL-504", "IL-301"} <= rule_ids
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["IL-504"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_json_output_contains_layer_and_how_to_fix(project: Path):
    result = runner.invoke(app, ["audit", str(project), "--format", "json"])
    data = json.loads(result.stdout)
    sample = next(v for v in data["violations"] if v["rule_id"] == "IL-301")
    assert sample["layer"] == "STANDARD"
    assert sample["how_to_fix"]
    assert sample["plain"]


def test_markdown_report_has_item_coverage_section(project: Path):
    result = runner.invoke(app, ["audit", str(project), "--format", "markdown"])
    assert "구현단계 49개 항목 점검 현황" in result.stdout
    assert "| 1-5 | 운영체제 명령어 삽입 | IL-504 | 1 | 지적 있음 |" in result.stdout
    assert "수동 확인 필요" in result.stdout
    assert "설계단계 보안설계 기준 20개 항목 점검 현황" in result.stdout
    assert "| SR1-4 | 시스템 자원 접근 및 명령어 수행 입력값 검증 | IL-502, IL-504 |" in result.stdout


def test_fix_prompt_orders_by_severity_and_includes_guidance(project: Path):
    result = runner.invoke(app, ["fix-prompt", str(project)])
    text = result.stdout
    assert text.index("IL-504") < text.index("IL-301")
    assert "고치는 방법" in text
    assert "로그 없이 조용히 삼키지 않습니다" in text


def test_fix_prompt_limit(project: Path):
    result = runner.invoke(app, ["fix-prompt", str(project), "--limit", "1"])
    assert "나머지" in result.stdout


def test_fix_prompt_clean_project(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert "수정할 문제가 없습니다" in result.stdout


def test_coverage_command_reports_counts():
    result = runner.invoke(app, ["coverage"])
    assert result.exit_code == 0
    assert "전체 49개" in result.stdout
    assert "수동 확인 필요" in result.stdout
    assert "설계단계 보안설계 20개 항목" in result.stdout


def test_explain_command_known_and_unknown_rule():
    ok = runner.invoke(app, ["explain", "IL-501"])
    assert ok.exit_code == 0
    assert "왜 문제인가" in ok.stdout
    missing = runner.invoke(app, ["explain", "IL-999"])
    assert missing.exit_code == 2


def test_rules_command_lists_every_rule_with_basis():
    result = runner.invoke(app, ["rules"])
    assert "AI-101" in result.stdout
    assert "ARC-204" in result.stdout
    assert "TYP-301" in result.stdout


def test_audit_output_option_writes_file(project: Path, tmp_path: Path):
    out = tmp_path / "report.sarif"
    result = runner.invoke(app, ["audit", str(project), "--format", "sarif", "-o", str(out)])
    assert result.exit_code == 1
    assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_review_format_is_reviewer_style_draft(project: Path):
    result = runner.invoke(app, ["audit", str(project), "--format", "review"])
    text = result.stdout
    assert "코드 점검 검토 의견서 (초안)" in text
    assert "전수 점검한 결과가 아니라" in text
    assert "주시기 바랍니다" in text
    assert "사람이 직접 확인해야 하는 사항" in text
    assert text.index("### 보안") < text.index("### 오류 처리·로그·입력 검증")
