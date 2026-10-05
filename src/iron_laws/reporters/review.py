"""
오철칙 검토 의견서 초안: 점검 결과를 발주사·검토자 어조의 개선 요청 문서로 만든다
작성자: 최진호
작성일: 2026-10-04
"""

import re
from collections import defaultdict

from iron_laws.core.models import AuditReport, Violation
from iron_laws.reporters.coverage import STATUS_MANUAL, build_design_status, build_item_status
from iron_laws.rules.base import BaseRule

GROUPS: list[tuple[str, re.Pattern[str]]] = [
    ("보안", re.compile(r"^(IL-1\d\d|IL-5(0\d|1[0-4]|2[5-9]|30)|IL-532|AI-10[789]|AI-11[3589]|AI-122)$")),
    ("오류 처리·로그·입력 검증", re.compile(r"^(IL-30\d|IL-531|AI-112|AI-120)$")),
    ("운영·설정·의존성·버전", re.compile(r"^(AI-10[1-6]|AI-110|AI-111|AI-114|AI-121)$")),
    ("구조·유지보수", re.compile(r"^(ARC-\d+|IL-51[5-9]|IL-52[0-4])$")),
    ("타입 안전성", re.compile(r"^TYP-\d+$")),
    ("AI 에이전트 공격면", re.compile(r"^AIA-\d+$")),
    ("성능", re.compile(r"^PERF-\d+$")),
]
SAMPLE_LOCATIONS = 3


def _group_of(rule_id: str) -> str:
    for name, pattern in GROUPS:
        if pattern.match(rule_id):
            return name
    return "기타"


def _request_sentence(how_to_fix: str) -> str:
    text = how_to_fix.strip()
    if not text:
        return "해당 사항을 확인하고 개선 방안을 제시해 주시기 바랍니다."
    return f"{text} 위 방향으로 조치하거나, 현행 방식을 유지하는 사유와 근거를 제시해 주시기 바랍니다."


def generate_review_report(report: AuditReport, rules: list[BaseRule], tool_version: str = "") -> str:
    by_rule: dict[str, list[Violation]] = defaultdict(list)
    for v in report.violations:
        by_rule[v.rule_id].append(v)

    grouped: dict[str, list[str]] = defaultdict(list)
    for rule_id, items in sorted(by_rule.items()):
        sample = items[0]
        places = ", ".join(f"`{v.file_path.as_posix()}:{v.line_number}`" for v in items[:SAMPLE_LOCATIONS])
        more = f" 외 {len(items) - SAMPLE_LOCATIONS}건" if len(items) > SAMPLE_LOCATIONS else ""
        lines = [f"#### {sample.rule_name} ({rule_id}) — {len(items)}건 · 최고 심각도 {max((v.severity for v in items), key=lambda s: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(s.value)).value}"]
        lines.append(f"- 현황: {sample.message}")
        lines.append(f"- 위치: {places}{more}")
        if sample.plain:
            lines.append(f"- 우려: {sample.plain}")
        lines.append(f"- 요청: {_request_sentence(sample.how_to_fix)}")
        grouped[_group_of(rule_id)].append("\n".join(lines))

    s = report.summary
    md = ["# 코드 점검 검토 의견서 (초안)\n"]
    md.append(f"- 점검 대상: `{report.target_path}`")
    md.append(f"- 점검일: {report.audit_date}")
    md.append(f"- 점검 도구: 오철칙 {tool_version}".rstrip())
    md.append(f"- 점검 파일 수: {s.total_files_scanned}개 / 지적 {s.total_violations}건 (치명 {s.critical_count}, 고위험 {s.high_count}, 중위험 {s.medium_count}, 저위험 {s.low_count})\n")
    md.append("> 이 문서는 전체 코드베이스를 전수 점검한 결과가 아니라, 도구가 코드에서 식별한 사항을 정리한 초안입니다. 아래 항목 외의 영역에도 같은 유형의 문제가 있을 수 있고, `확인 필요`로 분류된 사항은 사람의 판단이 필요합니다. 우선 아래 사항에 대한 조치 계획과 보완 방안을 마련해 주시고, 개선 후 나머지 영역에 대한 추가 검토를 이어가겠습니다.\n")
    md.append("## 1. 항목별 검토 의견\n")
    if not by_rule:
        md.append("탑재된 규칙 범위에서 지적 사항이 없습니다.\n")
    for name in [g for g, _ in GROUPS] + ["기타"]:
        if grouped.get(name):
            md.append(f"### {name}\n")
            md.append("\n\n".join(grouped[name]) + "\n")

    manual = [x for x in build_item_status(report, rules) if x.status == STATUS_MANUAL]
    manual += [x for x in build_design_status(report, rules) if x.status == STATUS_MANUAL]
    md.append("## 2. 도구로 판정할 수 없어 사람이 직접 확인해야 하는 사항\n")
    fixed = [
        "문서에 기재된 아키텍처·설계와 실제 구현의 의미상 일치 여부",
        "메서드 간 입력 검증 기준의 일관성(같은 계열 메서드의 검증 누락)",
        "트랜잭션 경계에서 카운터·이력 같은 부수 기록이 함께 롤백되는지 여부",
        "여러 단계의 외부 연동에서 각 단계의 완료·실패 지점을 추적할 수 있는지 여부",
        "이중화 환경에서 캐시·허용 목록 변경이 모든 인스턴스에 일관되게 반영되는지 여부",
    ]
    for item in fixed:
        md.append(f"- {item}")
    for x in manual:
        md.append(f"- 행안부 가이드 {x.item.id} {x.item.name}")
    md.append("")
    md.append("## 3. 점검 범위와 한계\n")
    md.append("- 한 파일 안의 흐름만 추적하며, 파일 사이 호출로 전달되는 입력은 놓칠 수 있습니다.")
    md.append("- 규칙은 SI 감리에서 자주 지적되는 항목을 정리한 것이며 공식 인증 도구나 감리 증빙이 아닙니다.")
    return "\n".join(md)
