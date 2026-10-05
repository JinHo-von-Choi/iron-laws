"""
오철칙 v1.3 3단계 회귀시험의 결함 구별력(실험 3): 시험 작성에 쓰지 않은 독립 변이와 반례
- 시험 입력 하나만 막는 수정(정확한 입력 차단, 한 글자 필터)을 후보로 넣어, 명세의 변형 입력이 그런 수정을 가려내는지 본다.
- 변형 입력이 없던 이전 명세로는 같은 수정이 통과한다는 것도 함께 보여, 이 시험이 무엇을 더 잡는지 드러낸다.
- 수집 0개·skip·timeout은 통과로 세지 않는다(기존 시험 항목의 시험이 담당한다. `test_stage3_verify.py`).
표본은 구현자가 직접 만들었다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다.
작성자: 최진호
작성일: 2026-10-05
"""

import pytest

from tests import test_stage4_regression as s4
from tests.regression_corpus import SUPPORTED, held_out_fixes

REQUEST_MARKERS = ("request.args", "request.form", "request.json")
CACHE: dict[tuple[str, str, bool], object] = {}


def _evaluate(tmp_path_factory, case, name: str, strip_variants: bool):
    key = (case.name, name, strip_variants)
    if key not in CACHE:
        root = tmp_path_factory.mktemp(f"{case.name}-{name}-{int(strip_variants)}"[:40])
        project = s4.write_project(root / "proj", case.vulnerable)
        spec = s4.propose(project, case)
        assert spec is not None and spec.input.variants, case.name  # 제안에 변형 입력이 들어 있다
        fixes = held_out_fixes(case, spec.target.function, spec.input.payload, spec.source.kind)
        if strip_variants:
            spec = spec.model_copy(update={"input": spec.input.model_copy(update={"variants": []})})
        CACHE[key] = s4.check(root, project, fixes[name], spec, patch_name=f"{name}.diff")
    return CACHE[key]


def _pairs():
    pairs = []
    for case in SUPPORTED:
        pairs.append((case, "exact-payload-block"))
        if not any(marker in case.vulnerable for marker in REQUEST_MARKERS):
            pairs.append(
                (case, "character-filter")
            )  # 입력을 바꿔 쓸 수 있는 매개변수 입력 표본에만 만든다
    return pairs


PAIRS = _pairs()


@pytest.mark.parametrize(("case", "name"), PAIRS, ids=[f"{c.name}:{n}" for c, n in PAIRS])
def test_held_out_wrong_fix_is_not_accepted(tmp_path_factory, case, name):
    result = _evaluate(tmp_path_factory, case, name, strip_variants=False)
    assert result.result == "fail", (case.name, name, result.result, result.reason)
    assert "다른 입력" in result.reason


def test_the_same_wrong_fixes_were_accepted_without_variant_inputs(tmp_path_factory):
    accepted = sum(
        _evaluate(tmp_path_factory, case, name, strip_variants=True).result == "pass"
        for case, name in PAIRS
    )
    # 변형 입력이 없던 명세에서는 이 수정들이 통과한다. 이 시험이 더 잡아내는 몫이다.
    assert accepted >= len(PAIRS) * 0.5, (accepted, len(PAIRS))


def test_correct_fixes_still_pass_with_variant_inputs(tmp_path_factory):
    for case in SUPPORTED:
        root = tmp_path_factory.mktemp("ok")
        project = s4.write_project(root / "proj", case.vulnerable)
        spec = s4.propose(project, case)
        result = s4.check(root, project, case.fix, spec, patch_name="fix.diff")
        assert result.result == "pass", (case.name, result.reason)
        variants = result.evidence["variants"]
        assert len(variants["checked"]) + len(variants["inapplicable"]) == len(spec.input.variants)
