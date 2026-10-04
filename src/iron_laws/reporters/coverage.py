"""
오철칙 기준 항목별 점검 현황: 지적 없음, 미탑재, 수동 확인을 구분한다
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass, field

from iron_laws.core.models import AuditReport
from iron_laws.rules.base import BaseRule
from iron_laws.standards import StandardItem, design_items, impl_items

ITEM_REF_RE = re.compile(r"구현단계 (\d+-\d+)")

STATUS_FOUND = "지적 있음"
STATUS_CLEAN = "지적 없음"
STATUS_MANUAL = "수동 확인 필요"
STATUS_MISSING = "미탑재"


@dataclass
class ItemStatus:
    item: StandardItem
    rule_ids: list[str] = field(default_factory=list)
    findings: int = 0
    status: str = STATUS_MISSING


def rule_item_ids(rule: BaseRule) -> list[str]:
    if rule.gov_standard is None:
        return []
    return ITEM_REF_RE.findall(rule.gov_standard.clause_id)


def build_item_status(report: AuditReport, rules: list[BaseRule]) -> list[ItemStatus]:
    rules_by_item: dict[str, list[str]] = {}
    for rule in rules:
        for item_id in rule_item_ids(rule):
            rules_by_item.setdefault(item_id, []).append(rule.rule_id)

    findings_by_rule: dict[str, int] = {}
    for v in report.violations:
        findings_by_rule[v.rule_id] = findings_by_rule.get(v.rule_id, 0) + 1

    result = []
    for item_id, item in impl_items().items():
        rule_ids = rules_by_item.get(item_id, [])
        count = sum(findings_by_rule.get(r, 0) for r in rule_ids)
        if rule_ids:
            status = STATUS_FOUND if count else STATUS_CLEAN
        elif item.static_detectability == "C":
            status = STATUS_MANUAL
        else:
            status = STATUS_MISSING
        result.append(ItemStatus(item, rule_ids, count, status))
    return result


def summarize(statuses: list[ItemStatus]) -> dict[str, int]:
    summary = {STATUS_FOUND: 0, STATUS_CLEAN: 0, STATUS_MANUAL: 0, STATUS_MISSING: 0}
    for s in statuses:
        summary[s.status] += 1
    return summary


# 설계단계 보안설계 기준(SR)을 구현 단계 규칙이 어떻게 뒷받침하는지의 대응표 (오철칙 판단)
DESIGN_RULE_MAP: dict[str, tuple[str, ...]] = {
    "SR1-1": ("IL-501",),
    "SR1-2": ("IL-527", "IL-509"),
    "SR1-3": ("IL-508",),
    "SR1-4": ("IL-502", "IL-504"),
    "SR1-5": ("IL-505",),
    "SR1-6": ("IL-510",),
    "SR1-7": ("IL-511", "IL-507"),
    "SR1-8": ("IL-514",),
    "SR1-9": ("IL-512",),
    "SR1-10": ("IL-513",),
    "SR2-1": ("IL-525", "IL-303"),
    "SR2-2": ("IL-532",),
    "SR2-3": ("IL-110", "IL-107"),
    "SR2-4": ("IL-114", "AI-113", "IL-525"),
    "SR2-5": ("IL-101", "IL-103"),
    "SR2-6": ("IL-102", "IL-104"),
    "SR2-7": ("IL-101", "AI-108"),
    "SR2-8": ("IL-109", "IL-106"),
    "SR3-1": ("IL-301", "IL-304", "IL-305"),
    "SR4-1": ("IL-521", "AI-115", "IL-526"),
}


def build_design_status(report: AuditReport, rules: list[BaseRule]) -> list[ItemStatus]:
    active = {r.rule_id for r in rules}
    findings: dict[str, int] = {}
    for v in report.violations:
        findings[v.rule_id] = findings.get(v.rule_id, 0) + 1
    result = []
    for item_id, item in design_items().items():
        rule_ids = [r for r in DESIGN_RULE_MAP.get(item_id, ()) if r in active]
        count = sum(findings.get(r, 0) for r in rule_ids)
        if rule_ids:
            status = STATUS_FOUND if count else STATUS_CLEAN
        else:
            status = STATUS_MANUAL
        result.append(ItemStatus(item, rule_ids, count, status))
    return result
