"""
오철칙 규칙 등록 시험: 규칙 클래스를 정의하면 자동으로 등록된다. 등록 목록을 따로 쓰지 않는다.
- iron_laws 패키지 어디에 정의된 규칙 클래스도 등록 목록에 없으면 시험이 실패한다
- 규칙 번호는 겹치지 않는다
- 계열 이름(계열 순서 표)에 없는 모듈의 규칙은 계열이 없는 것으로 표시된다
작성자: 최진호
작성일: 2026-10-22
"""

import importlib
import pkgutil

import pytest

from iron_laws.rules.base import BaseRule
from iron_laws.rules.catalog import ALL_RULES, FAMILY_ORDER


def _concrete_rule_classes() -> list[type[BaseRule]]:
    """패키지 전체에서 자기 규칙 번호를 가진 규칙 클래스를 모두 찾는다."""
    package = importlib.import_module("iron_laws")
    found: list[type[BaseRule]] = []
    for info in pkgutil.walk_packages(package.__path__, prefix="iron_laws."):
        try:
            module = importlib.import_module(info.name)
        except ImportError:  # pragma: no cover - 선택 의존성이 모듈을 못 읽는 경우
            continue
        for obj in vars(module).values():
            if not isinstance(obj, type) or not issubclass(obj, BaseRule):
                continue
            if "rule_id" not in obj.__dict__:
                continue  # 중간 기반 클래스는 등록 대상이 아니다
            if obj.__module__ != info.name:
                continue  # 정의된 모듈에서만 센다
            found.append(obj)
    return found


def test_every_rule_class_in_the_package_is_registered():
    registered = {cls.rule_id for cls in ALL_RULES}
    unregistered = sorted(
        f"{cls.__module__}.{cls.__name__}({cls.rule_id})"
        for cls in _concrete_rule_classes()
        if cls.rule_id not in registered
    )
    assert unregistered == [], f"등록되지 않은 규칙이 있습니다: {unregistered}"


def test_rule_ids_are_unique():
    ids = [cls.rule_id for cls in ALL_RULES]
    assert len(ids) == len(set(ids))
    assert len(ids) == len(_concrete_rule_classes())


def test_the_catalog_holds_every_rule():
    assert len(ALL_RULES) >= 100
    assert all(issubclass(cls, BaseRule) for cls in ALL_RULES)


@pytest.mark.parametrize("family", FAMILY_ORDER)
def test_each_family_name_is_used_by_at_least_one_rule(family: str):
    assert any(cls.__module__.rsplit(".", 1)[-1].startswith(family) for cls in ALL_RULES)
