"""
오철칙 Markdown Reporter
작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.core.models import AuditReport, Confidence, Violation
from iron_laws.reporters.coverage import (
    STATUS_MANUAL,
    build_design_status,
    build_item_status,
    summarize,
)
from iron_laws.rules.base import BaseRule

BASIS_NONE = "오철칙 자체 품질 규칙 (참고 가이드 항목 외)"
CONFIDENCE_LABEL = {Confidence.CONFIRMED: "확정", Confidence.REVIEW: "확인 필요"}


_ROLE = {"source": "입력", "propagation": "전파", "sink": "싱크"}
_BASELINE_LABEL = {"new": "신규", "existing": "기존(승인된 부채)", "review": "규칙 의미 변경으로 재검토 필요"}


_STATUS_LABEL = {"complete": "완료", "incomplete": "불완전 (일부를 점검하지 못함)", "empty": "점검한 파일 없음"}


def _basis(v: Violation) -> str:
    return v.gov_standard.clause_id if v.gov_standard else BASIS_NONE


def _detail(idx: int, v: Violation) -> list[str]:
    md = [f"### [지적-{idx:02d}] {v.rule_name} (`{v.rule_id}`)"]
    md.append(f"- **심각도**: {v.severity.value} ({CONFIDENCE_LABEL[v.confidence]})")
    if v.gov_standard:
        md.append(
            f"- **적용 기준**: {v.gov_standard.standard_name} - {v.gov_standard.clause_id} ({v.gov_standard.description})"
        )
    else:
        md.append(f"- **적용 기준**: {BASIS_NONE}")
    md.append(f"- **위치**: `{v.file_path}:{v.line_number}`")
    md.append(f"- **현황**: {v.message}")
    if v.evidence:
        flow = " → ".join(f"{_ROLE.get(e.role, e.role)} `{e.file_path}:{e.line}`" for e in v.evidence)
        md.append(f"- **판단 근거**: {flow}")
    if v.baseline_status is not None:
        md.append(f"- **기준선 대비**: {_BASELINE_LABEL[v.baseline_status.value]}")
    if v.plain:
        md.append(f"- **왜 문제인가**: {v.plain}")
    md.append("\n**[해당 코드]**")
    md.append("```")
    md.append(v.snippet)
    md.append("```")
    if v.how_to_fix:
        md.append(f"\n**[고치는 방법]** {v.how_to_fix}")
    if v.fix:
        md.append("\n**[교정 예시 (AFTER)]**")
        md.append("```")
        md.append(v.fix.after_snippet)
        md.append("```")
        md.append(f"- **교정 근거**: {v.fix.rationale}")
    md.append("\n---\n")
    return md


def _coverage_section(report: AuditReport, rules: list[BaseRule]) -> list[str]:
    statuses = build_item_status(report, rules)
    counts = summarize(statuses)
    md = ["## 5. 참고 가이드(행정안전부 SW 개발보안 가이드 2021) 구현단계 49개 항목 점검 현황\n"]
    md.append(
        f"지적 있음 {counts['지적 있음']}개 · 지적 없음 {counts['지적 없음']}개 · "
        f"수동 확인 필요 {counts['수동 확인 필요']}개 · 미탑재 {counts['미탑재']}개\n"
    )
    md.append("`지적 없음`은 탑재된 규칙 범위에서 발견되지 않았다는 뜻이며, `미탑재`와 `수동 확인 필요`는 이 도구가 점검하지 않았다는 뜻입니다.\n")
    md.append("| 항목 | 명칭 | 점검 규칙 | 지적 | 상태 |")
    md.append("|---|---|---|---|---|")
    for s in statuses:
        rule_text = ", ".join(s.rule_ids) if s.rule_ids else "-"
        md.append(f"| {s.item.id} | {s.item.name} | {rule_text} | {s.findings} | {s.status} |")
    return md


def _design_section(report: AuditReport, rules: list[BaseRule]) -> list[str]:
    md = ["\n## 6. 참고 가이드 설계단계 보안설계 기준 20개 항목 점검 현황\n"]
    md.append("설계 문서를 점검하는 것이 아니라, 설계 요구사항이 코드에 반영되었는지를 구현 규칙으로 확인한 결과입니다. 규칙이 없는 항목은 설계 문서와 운영 정책을 사람이 확인해야 합니다.\n")
    md.append("| 항목 | 명칭 | 확인 규칙 | 지적 | 상태 |")
    md.append("|---|---|---|---|---|")
    for s in build_design_status(report, rules):
        rule_text = ", ".join(s.rule_ids) if s.rule_ids else "-"
        md.append(f"| {s.item.id} | {s.item.name} | {rule_text} | {s.findings} | {s.status} |")
    return md


def generate_markdown_report(report: AuditReport, rules: list[BaseRule] | None = None) -> str:
    s = report.summary
    status_str = "통과 (PASS)" if s.is_passed else "미통과 (시정조치 필요 / FAIL)"

    md = [f"# {report.title}\n"]
    md.append(f"- **문서번호**: {report.document_id}")
    md.append(f"- **점검 대상 경로**: `{report.target_path}`")
    md.append(f"- **점검 주체**: {report.auditor}")
    md.append(f"- **점검일자**: {report.audit_date}")
    md.append(f"- **종합 등급**: **{s.grade}** ({status_str})")
    meta = report.metadata
    md.append(f"- **점검 완료 상태**: {_STATUS_LABEL.get(s.scan_status, s.scan_status)}")
    if meta.get("tool_version"):
        md.append(f"- **도구·규칙셋**: 오철칙 {meta['tool_version']} / 규칙 {meta.get('ruleset', {}).get('count', '?')}개 (해시 {meta.get('ruleset', {}).get('hash', '?')})")
    if meta.get("config_source"):
        md.append(f"- **설정**: {meta['config_source']} (설정 해시 {meta.get('config_hash', '?')})")
    md.append("")
    md.append("---\n")

    md.append("## 1. 점검 요약 통계\n")
    md.append("| 항목 | 결과 | 비고 |")
    md.append("|---|---|---|")
    md.append(f"| 점검 대상 파일 수 | {s.total_files_scanned}개 | 설정의 제외 대상을 뺀 전체 |")
    md.append(f"| 총 지적 건수 | {s.total_violations}건 | 억제된 지적 {s.suppressed_count}건 별도 |")
    md.append(f"| 치명적 (Critical) | {s.critical_count}건 | 배포 차단 사유 |")
    md.append(f"| 고위험 (High) | {s.high_count}건 | 시정조치 필요 |")
    md.append(f"| 중위험 (Medium) | {s.medium_count}건 | 개선 권고 |")
    md.append(f"| 저위험 (Low) | {s.low_count}건 | 참고 |")
    md.append(f"| 최종 판정 | **{status_str}** | 탑재된 규칙 기준 |\n")
    skipped = report.metadata.get("skipped_files") or []
    if skipped:
        md.append(f"> 점검에서 제외된 파일 {len(skipped)}개: " + ", ".join(f"`{x['path']}`({x['reason']})" for x in skipped[:5]) + "\n")
    problems = [d for d in report.diagnostics if d.severity in ("error", "warning")]
    if problems:
        md.append("### 점검 진단\n")
        for d in problems[:30]:
            where = f"`{d.file_path}`: " if d.file_path else ""
            md.append(f"- [{d.severity}] {where}{d.message}")
        if len(problems) > 30:
            md.append(f"- … 외 {len(problems) - 30}건")
        md.append("")
    scope = report.metadata.get("scope")
    if scope:
        md.append(f"> 범위 제한: {scope['ref']} 이후 바뀐 파일 {scope['changed_files']}개의 지적만 표시했습니다. {scope['note']}\n")
    if s.new_count is not None:
        md.append(f"> 기준선 대비: 신규·재검토 {s.new_count}건, 기존(승인) {s.existing_count}건, 해소 {s.resolved_count}건\n")
    md.append("---\n")

    md.append("## 2. 지적사항 총괄표\n")
    if not report.violations:
        md.append(
            "> [!NOTE]\n> 탑재된 규칙 범위에서 지적된 위반 사항이 없습니다. 탑재되지 않은 보안약점 항목은 점검되지 않았습니다.\n"
        )
    else:
        md.append("| 연번 | 규칙 ID | 규칙 명칭 | 심각도 | 위치 | 관련 기준 |")
        md.append("|---|---|---|---|---|---|")
        for idx, v in enumerate(report.violations, start=1):
            md.append(
                f"| {idx} | `{v.rule_id}` | {v.rule_name} | **{v.severity.value}** | `{v.file_path}:{v.line_number}` | {_basis(v)} |"
            )
        md.append("\n---\n")
        md.append("## 3. 지적사항별 상세\n")
        for idx, v in enumerate(report.violations, start=1):
            md.extend(_detail(idx, v))

    md.append("## 4. 총평 및 시정조치 요구사항\n")
    if s.is_passed:
        md.append("탑재된 규칙 기준으로 설정한 실패 기준 이상의 지적이 없습니다. 이 결과는 전체 보안약점 항목의 준수를 보증하지 않습니다.\n")
    else:
        md.append(
            "설정한 실패 기준 이상의 결함이 식별되어 **[미통과]**로 판정합니다. 상기 지적사항의 고치는 방법을 반영한 뒤 다시 점검하십시오.\n"
        )
    if rules is not None:
        md.extend(_coverage_section(report, rules))
        md.extend(_design_section(report, rules))
        manual = [x for x in build_item_status(report, rules) if x.status == STATUS_MANUAL]
        if manual:
            md.append("\n정적 분석으로 판정할 수 없어 사람이 직접 확인해야 하는 항목: " + ", ".join(f"{m.item.id} {m.item.name}" for m in manual))
    return "\n".join(md)
