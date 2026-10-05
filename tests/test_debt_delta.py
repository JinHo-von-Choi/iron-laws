"""
오철칙 수정 부채 표시 시험: 원본과 후보의 습관 지적(하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피)을 해결·유지·신규·이동으로 나눈다.
표본은 구현자가 직접 만들고 분류했다. 독립 검토자의 분류가 아니므로 효과 주장의 근거가 아니라 회귀 방지에 쓴다.
표시는 판정에 연결하지 않는다. 부채가 새로 생긴 수정도 기존 검증 항목의 통과·실패는 바꾸지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.verify.debt_delta import HABIT_OF_RULE, HABITS, MAPPING_VERSION, compare
from tests.test_stage3_verify import APP, APP_FIXED, make_project, result_of, verify, write_patch

cli = CliRunner()

HEAD = "from flask import request\n\n"
SWALLOWED = HEAD + "def run():\n    try:\n        return int(request.args['n'])\n    except Exception:\n        pass\n"
TYPED = HEAD + "def run():\n    x: int = 'a'  # type: ignore\n    return x\n"


def _scan(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return AuditScanner(root).scan()


def _delta(tmp_path: Path, before: dict[str, str], after: dict[str, str]) -> dict:
    return compare(_scan(tmp_path / "before", before), _scan(tmp_path / "after", after)).to_dict()


def test_every_mapped_rule_exists_and_every_habit_has_a_rule():
    from iron_laws.rules.catalog import ALL_RULES

    known = {rule_cls.rule_id for rule_cls in ALL_RULES}
    assert set(HABIT_OF_RULE) <= known
    assert set(HABIT_OF_RULE.values()) == set(HABITS)


def test_a_legitimate_fix_creates_no_new_debt(tmp_path: Path):
    delta = _delta(tmp_path, {"app.py": APP}, {"app.py": APP_FIXED})
    assert delta["totals"]["new"] == 0 and delta["fix_adjacent_new"] == []
    assert delta["mapping_version"] == MAPPING_VERSION


@pytest.mark.parametrize(
    ("name", "fixed", "habit"),
    [
        ("swallowed-exception", "import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    try:\n        subprocess.run(['ls', d], check=True)\n    except Exception:\n        pass\n", "swallowed_exception"),
        ("type-ignore", "import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    subprocess.run(['ls', d], check=True)  # type: ignore\n", "typing"),
    ],
)
def test_a_fix_that_hides_instead_of_repairing_shows_new_debt_in_the_same_function(tmp_path: Path, name, fixed, habit):
    delta = _delta(tmp_path, {"app.py": APP}, {"app.py": fixed})
    assert delta["habits"][habit]["new"] >= 1
    assert delta["totals"]["new"] >= 1
    assert delta["fix_adjacent_new"] and all(row["habit"] == habit and row["scope"] == "run_tool" for row in delta["fix_adjacent_new"])


def test_debt_in_another_function_is_new_but_not_fix_adjacent(tmp_path: Path):
    other = APP_FIXED + "\ndef unrelated():\n    try:\n        return 1\n    except Exception:\n        pass\n"
    delta = _delta(tmp_path, {"app.py": APP}, {"app.py": other})
    assert delta["habits"]["swallowed_exception"]["new"] >= 1
    assert delta["fix_adjacent_new"] == []


def test_unchanged_debt_is_maintained_and_a_removed_one_is_resolved(tmp_path: Path):
    delta = _delta(tmp_path, {"a.py": SWALLOWED, "b.py": TYPED}, {"a.py": SWALLOWED, "b.py": HEAD + "def run():\n    return 1\n"})
    assert delta["habits"]["swallowed_exception"]["maintained"] >= 1
    assert delta["habits"]["typing"]["resolved"] >= 1 and delta["totals"]["new"] == 0


def test_a_pure_file_move_is_a_move_and_not_new_or_resolved(tmp_path: Path):
    delta = _delta(tmp_path, {"old/a.py": SWALLOWED}, {"new/a.py": SWALLOWED})
    assert delta["habits"]["swallowed_exception"]["moved"] >= 1
    assert delta["totals"]["new"] == 0 and delta["totals"]["resolved"] == 0
    assert delta["details"]["moved"][0]["from"] == "old/a.py"


def test_an_ambiguous_match_is_undetermined_rather_than_guessed(tmp_path: Path):
    before = {"a/x.py": SWALLOWED, "b/x.py": SWALLOWED}
    after = {"c/x.py": SWALLOWED, "d/x.py": SWALLOWED}
    delta = _delta(tmp_path, before, after)
    assert delta["habits"]["swallowed_exception"]["undetermined"] >= 4
    assert delta["totals"]["moved"] == 0 and delta["totals"]["new"] == 0 and delta["totals"]["resolved"] == 0


def test_the_delta_is_displayed_but_never_changes_the_verdict(tmp_path: Path):
    hiding = "import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    try:\n        subprocess.run(['ls', d], check=True)\n    except Exception:\n        pass\n"
    project = make_project(tmp_path / "proj")
    receipt = verify(project, write_patch(tmp_path, project, {"app.py": hiding}))
    assert receipt.debt_delta["habits"]["swallowed_exception"]["new"] >= 1
    assert receipt.debt_delta["fix_adjacent_new"]
    clean = verify(project, write_patch(tmp_path, project, {"app.py": APP_FIXED}, "q.diff"))
    assert clean.debt_delta["totals"]["new"] == 0
    assert result_of(clean, "no_new_findings") == "pass"


def test_the_receipt_cli_prints_the_delta_and_its_limits(tmp_path: Path):
    hiding = "import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    try:\n        subprocess.run(['ls', d], check=True)\n    except Exception:\n        pass\n"
    project = make_project(tmp_path / "proj")
    patch = write_patch(tmp_path, project, {"app.py": hiding})
    out = tmp_path / "receipt.json"
    result = cli.invoke(app, ["verify-patch", str(project), "--patch", str(patch), "--finding", "IL-504@app.py:6", "--runner", "none", "--no-require-tests", "-o", str(out)])
    assert result.exit_code in (0, 1, 2), result.stdout + result.stderr
    data = json.loads(out.read_text())
    assert data["debt_delta"]["totals"]["new"] >= 1
    assert "수정 지점" in result.stdout + result.stderr or "신규 부채" in result.stdout + result.stderr
