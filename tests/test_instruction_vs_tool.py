"""
지침·도구 정면 비교 측정기(benchmarks/instruction_vs_tool.py)의 판정 분류: 결함 유출과 정상 기능 손상과 판정 불가를 섞지 않는다
작성자: 최진호
작성일: 2026-10-26
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from instruction_vs_tool import classify_regression, judge_detect  # noqa: E402

from iron_laws.verify.receipt import CheckResult  # noqa: E402


def result(state: str, **evidence) -> CheckResult:
    return CheckResult(id="regression_test", title="t", result=state, required=True, executed=True, reason="", evidence=evidence)


@pytest.mark.parametrize("check, verdict", [
    (result("pass", candidate_attack=["passed"], candidate_control=["passed"]), "ok"),
    (result("fail", candidate_attack=["defect_reproduced"], candidate_control=["passed"]), "leaked"),
    (result("fail", candidate_attack=["passed"], candidate_control=["passed"], variants={"failed": 2}), "leaked"),
    (result("fail", candidate_attack=["passed"], candidate_control=["control_failed"]), "broken"),
    (result("unknown", candidate_attack=["error"], candidate_control=["error"]), "undetermined"),
])
def test_regression_results_are_split_into_four_verdicts(check, verdict):
    assert classify_regression(check) == verdict


def test_detection_answer_scoring():
    scored = judge_detect('설명 [{"file": "a.py", "line": 5}, {"file": "src/b.py", "line": 6}, {"file": "a.py", "line": 7}] 끝')
    assert scored["found"] == 3 and scored["hit"] == 2 and scored["precision"] == round(2 / 3, 3)
    assert judge_detect("목록 없음")["recall"] == 0.0


def test_detection_groups_accept_either_location():
    truth = [{("a.py", 1)}, {("helpers.py", 3), ("a.py", 9)}]
    scored = judge_detect('[{"file": "a.py", "line": 9}, {"file": "a.py", "line": 1}, {"file": "a.py", "line": 4}]', truth)
    assert scored["hit"] == 2 and scored["recall"] == 1.0 and scored["precision"] == round(2 / 3, 3)


def test_answer_passing_all_inputs_is_ok_even_when_mutants_are_inconclusive():
    check = CheckResult(id="regression_test", title="t", result="unknown", reason="보안 수정을 되돌린 유효한 mutant에서 시험이 다시 실패하는지 확인하지 못했다",
                        evidence={"candidate_attack": ["passed"], "candidate_control": ["passed"]})
    assert classify_regression(check) == "ok"
