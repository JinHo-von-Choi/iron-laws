"""
오철칙 v1.3 3단계(PR-07~08) 의미 변형 사례집과 분리 평가 수용시험
- 개발용 사례집: 위험 미탐 0, 정상 오차단 0, 의미 보존 변형의 판정 변화 0.
- 평가용(holdout): 위험 미탐 1건이라도 있으면 실패(해당 자동 면제 출시 보류), 정상 오차단은 10% 이하.
- 평가용은 개발용과 (유형, 스타일) 단위로 분리되어 있어야 하고, 평가용 실패로 옮겨 온 사례는 목록에 드러나야 한다.
표본의 정답은 구현자가 직접 정했다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다.
작성자: 최진호
작성일: 2026-10-05
"""

import pytest

from tests.semantic_corpus import DEV_APPROVAL, DEV_OUTPUT, DEV_SCAN, OPERATORS
from tests.semantic_eval import evaluate_approvals, evaluate_output, evaluate_scan
from tests.semantic_holdout import HOLDOUT_APPROVAL, HOLDOUT_OUTPUT, HOLDOUT_SCAN

# 평가용 실행에서 실패해 엔진을 고치고 개발용으로 옮긴 사례. 같은 유형의 새 평가용 사례로 바꿨으므로 그 유형은 독립 평가가 아니다.
MOVED_TO_DEV = {"approval-route-exposed-docstring"}


def pair(case) -> tuple[str, str]:
    return case.group, case.style


def test_corpus_size_and_shape():
    dev = [*DEV_SCAN, *DEV_APPROVAL, *DEV_OUTPUT]
    holdout = [*HOLDOUT_SCAN, *HOLDOUT_APPROVAL, *HOLDOUT_OUTPUT]
    ids = [c.id for c in dev + holdout]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 60  # 기본 사례 60개 이상(짝 하나를 하나로 센다)
    assert 4 <= len(OPERATORS) <= 6
    for case in [*DEV_SCAN, *HOLDOUT_SCAN]:
        assert case.benign.strip() and case.risky.strip() and case.benign != case.risky  # 모든 사례가 정상·위험 짝이다


def test_holdout_is_separated_from_dev_by_type_and_style():
    dev_pairs = {pair(c) for c in [*DEV_SCAN, *DEV_APPROVAL, *DEV_OUTPUT]}
    overlapping = {c.id for c in [*HOLDOUT_SCAN, *HOLDOUT_APPROVAL, *HOLDOUT_OUTPUT] if pair(c) in dev_pairs}
    moved_pairs = {pair(c) for c in DEV_APPROVAL if c.id in MOVED_TO_DEV}
    expected = {c.id for c in HOLDOUT_APPROVAL if pair(c) in moved_pairs}
    assert overlapping == expected, f"평가용과 개발용이 같은 (유형, 스타일)을 쓴다: {sorted(overlapping - expected)}"
    assert {c.style for c in DEV_SCAN}.isdisjoint({c.style for c in HOLDOUT_SCAN})


@pytest.fixture(scope="module")
def tmp_factory(tmp_path_factory):
    return lambda name: tmp_path_factory.mktemp(name[:40].replace(" ", "_"))


@pytest.fixture(scope="module")
def dev_metrics(tmp_factory):
    return evaluate_scan(DEV_SCAN, tmp_factory)


@pytest.fixture(scope="module")
def holdout_metrics(tmp_factory):
    return evaluate_scan(HOLDOUT_SCAN, tmp_factory)


def test_dev_scan_has_no_miss_no_false_block_and_no_flip(dev_metrics):
    summary = dev_metrics.summary()
    failures = [(o.case_id, o.form, o.operator, o.verdict) for o in dev_metrics.failures()]
    assert failures == [], failures
    assert summary["risk_miss"] == {"original": 0, "variant": 0}
    assert summary["benign_blocked"] == {"original": 0, "variant": 0}
    assert summary["verdict_flips"] == {"benign": 0, "risky": 0}
    assert summary["originals"] == {"risky": len(DEV_SCAN), "benign": len(DEV_SCAN)}
    assert summary["variants"]["risky"] == len(DEV_SCAN) * len(OPERATORS)


def test_holdout_scan_is_clean_on_risk_and_within_the_false_block_limit(holdout_metrics):
    summary = holdout_metrics.summary()
    failures = [(o.case_id, o.form, o.operator, o.verdict) for o in holdout_metrics.failures()]
    assert summary["risk_miss"] == {"original": 0, "variant": 0}, failures  # 한 건이라도 있으면 해당 자동 면제를 보류한다
    benign_total = summary["originals"]["benign"] + summary["variants"]["benign"]
    blocked = summary["benign_blocked"]["original"] + summary["benign_blocked"]["variant"]
    assert blocked / benign_total <= 0.10, failures
    assert summary["verdict_flips"] == {"benign": 0, "risky": 0}


def test_unknown_is_reported_separately_and_never_counted_as_detection(dev_metrics, holdout_metrics):
    for metrics in (dev_metrics, holdout_metrics):
        review_only_risky = [o for o in metrics.outcomes if o.form == "risky" and o.verdict == "review"]
        assert review_only_risky == []  # 위험 변형이 '확인 필요'로만 나오면 탐지로 세지 않는다(실패 목록에 들어간다)
        assert "unknown" in metrics.summary()


def test_approvals_keep_safe_changes_and_never_inherit_dangerous_ones(tmp_factory):
    for cases in (DEV_APPROVAL, HOLDOUT_APPROVAL):
        result = evaluate_approvals(cases, tmp_factory)
        assert result["dangerous_inheritance"] == 0, result["details"]
        assert result["unnecessary_re_review"] == 0, result["details"]


def test_suppression_and_masking_cases_hold_in_every_format(tmp_factory):
    for cases in (DEV_OUTPUT, HOLDOUT_OUTPUT):
        result = evaluate_output(cases, tmp_factory)
        assert result["mishandled"] == 0, result["details"]
