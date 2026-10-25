"""
실측 순환(benchmarks/realworld_loop.py)의 판 번호 확인: 지적이 달라진 규칙의 판 번호가 기록과 같으면 알린다
작성자: 최진호
작성일: 2026-10-26
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from realworld_loop import rule_versions, unbumped_rules  # noqa: E402

BEFORE = [["IL-501", "a.py", 3, "HIGH", "CONFIRMED"], ["IL-502", "b.py", 7, "HIGH", "CONFIRMED"]]


def test_changed_rule_with_same_version_is_reported():
    after = [["IL-501", "a.py", 3, "HIGH", "CONFIRMED"], ["IL-502", "b.py", 9, "HIGH", "CONFIRMED"]]
    assert unbumped_rules(BEFORE, after, {"IL-501": 1, "IL-502": 2}, {"IL-501": 1, "IL-502": 2}) == ["IL-502"]


def test_bumped_unrecorded_and_unchanged_rules_pass():
    after = [["IL-501", "a.py", 3, "HIGH", "REVIEW"]]
    assert unbumped_rules(BEFORE, after, {"IL-501": 1, "IL-502": 2}, {"IL-501": 2, "IL-502": 3}) == []
    assert unbumped_rules(BEFORE, after, {}, {"IL-501": 1, "IL-502": 2}) == []
    assert unbumped_rules(BEFORE, list(reversed(BEFORE)), {"IL-501": 1, "IL-502": 2}, {"IL-501": 1, "IL-502": 2}) == []


def test_duplicate_finding_counts_as_change():
    after = BEFORE + [BEFORE[0]]
    assert unbumped_rules(BEFORE, after, {"IL-501": 1}, {"IL-501": 1}) == ["IL-501"]


def test_recorded_versions_cover_security_rules_only():
    versions = rule_versions()
    assert "IL-501" in versions and "AI-101" in versions
    assert not any(rule.startswith(("ARC-", "PERF-", "TYP-")) for rule in versions)
