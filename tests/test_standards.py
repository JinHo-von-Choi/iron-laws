"""
Tests for Standards Registry
작성자: 최진호
작성일: 2026-10-04
"""

from collections import Counter

from iron_laws.rules.catalog import ALL_RULES
from iron_laws.standards import design_items, impl_items, leak_items, mois_ref


def test_impl_items_match_2021_guide_structure():
    items = impl_items()
    assert len(items) == 49
    per_category = Counter(i.category_no for i in items.values())
    assert [per_category[n] for n in range(1, 8)] == [17, 16, 2, 3, 5, 4, 2]


def test_impl_item_ids_are_sequential_within_each_category():
    items = impl_items()
    for category_no, count in {1: 17, 2: 16, 3: 2, 4: 3, 5: 5, 6: 4, 7: 2}.items():
        for n in range(1, count + 1):
            assert f"{category_no}-{n}" in items


def test_design_items_total_twenty():
    assert len(design_items()) == 20


def test_leak_items_total_eleven():
    assert sorted(leak_items()) == list(range(1, 12))


def test_every_standard_backed_rule_resolves_to_existing_items():
    for rule_cls in ALL_RULES:
        rule = rule_cls()
        if rule.gov_standard is not None:
            assert rule.gov_standard.clause_id
            assert "2021" in rule.gov_standard.standard_name


def test_known_clause_numbers_follow_2021_guide():
    assert "구현단계 2-6 하드코드된 중요정보" in mois_ref("2-6").clause_id
    assert "구현단계 2-4 취약한 암호화 알고리즘 사용" in mois_ref("2-4").clause_id
    assert "구현단계 1-3 경로 조작 및 자원 삽입" in mois_ref("1-3").clause_id
    assert "누출금지 대상정보 제3호" in mois_ref("2-6", leak_no=3).clause_id
