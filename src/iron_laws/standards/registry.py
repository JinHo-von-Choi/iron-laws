"""
오철칙 기준 레지스트리: 행정안전부 개발보안 가이드(2021.11)와 국정원 누출금지 대상정보
작성자: 최진호
작성일: 2026-10-04
"""

from functools import cache
from importlib.resources import files
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from iron_laws.core.models import GovStandard


class StandardItem(BaseModel):
    id: str
    category_name: str
    name: str
    category_no: int | None = None
    cwe: list[int] = Field(default_factory=list)
    guide_example_languages: list[str] = Field(default_factory=list)
    static_detectability: Literal["A", "B", "C"] | None = None


class LeakItem(BaseModel):
    no: int
    text: str


def _load(filename: str) -> dict[str, Any]:
    raw = files("iron_laws.standards").joinpath("data", filename).read_text(encoding="utf-8")
    return yaml.safe_load(raw)


@cache
def _impl_doc() -> dict[str, Any]:
    return _load("mois_2021_impl.yml")


@cache
def impl_items() -> dict[str, StandardItem]:
    return {i["id"]: StandardItem(**i) for i in _impl_doc()["items"]}


@cache
def design_items() -> dict[str, StandardItem]:
    return {i["id"]: StandardItem(**i) for i in _load("mois_2021_design.yml")["items"]}


@cache
def leak_items() -> dict[int, LeakItem]:
    return {i["no"]: LeakItem(**i) for i in _load("nis_leak_items.yml")["items"]}


def mois_ref(*item_ids: str, leak_no: int | None = None) -> GovStandard:
    """구현단계 보안약점 항목(필요 시 누출금지 대상정보 호수 포함)을 가리키는 기준 근거 생성"""
    items = impl_items()
    parts = []
    descriptions = []
    for item_id in item_ids:
        item = items[item_id]
        cwe = ", ".join(f"CWE-{c}" for c in item.cwe)
        parts.append(f"구현단계 {item.id} {item.name}")
        descriptions.append(f"{item.name} ({cwe})" if cwe else item.name)
    if leak_no is not None:
        leak = leak_items()[leak_no]
        parts.append(f"누출금지 대상정보 제{leak.no}호")
        descriptions.append(leak.text)
    return GovStandard(
        standard_name=_impl_doc()["standard_name"],
        clause_id=" / ".join(parts),
        description=" · ".join(descriptions),
    )
