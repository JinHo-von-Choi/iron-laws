"""
오철칙 감리 대응 보고서: 행안부 SW 개발보안 가이드(2021) 구현단계 49개 항목별로 지적·잔존과 사유·미점검 사유를 정리한다

- 잔존 사유는 억제 주석(사유·만료일)과 승인 기록(승인 ID·상태)에서 가져온다.
- 미점검 사유는 규칙 미탑재·수동 확인 항목, 그리고 근거 장부의 공백(지원하지 않음·해석 미확정·예산 초과)과 건너뛴 파일에서 가져온다.
- '지적 없음'은 탑재된 규칙 범위에서 발견되지 않았다는 뜻이며 취약점이 없다는 증명이 아니다.
- markdown이 기본이며, 출력 파일이 .docx면 python-docx(선택 의존성 iron-laws[docx])로 같은 내용을 문서로 쓴다.
작성자: 최진호
작성일: 2026-10-12
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.models import AuditReport
from iron_laws.reporters.coverage import rule_item_ids
from iron_laws.standards import impl_items

FAMILY_ITEM = {"sql": "1-1", "path": "1-3", "command": "1-5"}
GAP_LABEL = {"unsupported": "지원하지 않는 호출", "unresolved": "입력 출처 미확정", "budget_exceeded": "해석 한도 도달"}


@dataclass
class ItemRow:
    item_id: str
    name: str
    rules: list[str]
    status: str = ""
    findings: list = field(default_factory=list)
    remaining: list[str] = field(default_factory=list)
    unchecked: list[str] = field(default_factory=list)


def build_rows(report: AuditReport, rules) -> list[ItemRow]:
    rules_by_item: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        for item_id in rule_item_ids(rule):
            rules_by_item[item_id].append(rule.rule_id)
    meta = report.metadata or {}
    suppressions = meta.get("suppressions") or []
    gaps: dict[str, Counter] = defaultdict(Counter)
    ledger = report.coverage_ledger
    for point in (ledger.points if ledger is not None else []):
        if point.in_scope and point.state in GAP_LABEL and point.family in FAMILY_ITEM:
            gaps[FAMILY_ITEM[point.family]][point.state] += 1
    rows = []
    for item_id, item in impl_items().items():
        rule_ids = sorted(rules_by_item.get(item_id, []))
        row = ItemRow(item_id, item.name, rule_ids)
        row.findings = [v for v in report.violations if v.rule_id in rule_ids]
        for s in suppressions:
            if s["rule_id"] in rule_ids:
                until = f", {s['until']}까지" if s.get("until") else ""
                row.remaining.append(f"억제 {s['rule_id']} {s['path']}:{s['line']} — {s['reason'] or '(사유 없음)'}{until}")
        for v in row.findings:
            if v.approval_status == "approved":
                row.remaining.append(f"승인 {v.rule_id} {v.file_path.as_posix()}:{v.line_number} — 승인 {v.approval_id}")
        if not rule_ids:
            row.unchecked.append("수동 확인 필요(정적 점검으로 판단할 수 없는 항목)" if item.static_detectability == "C" else "점검 규칙 미탑재")
        for state, count in sorted(gaps.get(item_id, {}).items()):
            row.unchecked.append(f"근거 공백 {count}곳: {GAP_LABEL[state]}")
        open_findings = [v for v in row.findings if v.approval_status != "approved"]
        if not rule_ids:
            row.status = "미점검"
        elif open_findings:
            row.status = "지적 있음"
        elif row.remaining:
            row.status = "잔존(사유 기록)"
        elif row.unchecked:
            row.status = "지적 없음(공백 있음)"
        else:
            row.status = "지적 없음"
        rows.append(row)
    return rows


def _header(report: AuditReport) -> list[tuple[str, str]]:
    s = report.summary
    meta = report.metadata or {}
    execution = report.execution
    pairs = [
        ("점검 대상", report.target_path),
        ("점검일", report.audit_date),
        ("기준", "행정안전부 소프트웨어 개발보안 가이드(2021.11) 구현단계 보안약점 49개 항목"),
        ("도구", f"오철칙 {meta.get('tool_version', '')} · 규칙 집합 {((meta.get('ruleset') or {}).get('hash') or '')[:16]}"),
        ("점검 상태", f"{s.scan_status} · 파일 {s.total_files_scanned}개 · 지적 {s.total_violations}건(치명 {s.critical_count}, 고위험 {s.high_count}, 중위험 {s.medium_count}, 저위험 {s.low_count}) · 억제 {s.suppressed_count}건"),
    ]
    if execution is not None:
        pairs.append(("실행 식별자", f"{execution.run_id} · 코드 지문 {execution.code_digest}"))
    if s.resolved_count:
        pairs.append(("기준선 대비 해소", f"{s.resolved_count}건"))
    return pairs


def generate_mois_report(report: AuditReport, rules) -> str:
    rows = build_rows(report, rules)
    md = ["# 소프트웨어 개발보안 감리 대응 보고서", ""]
    md += [f"- **{k}**: {v}" for k, v in _header(report)]
    md += ["", "'지적 없음'은 탑재된 규칙 범위에서 발견되지 않았다는 뜻이며, 취약점이 없다는 증명이 아닙니다. 미점검 사유가 있는 항목은 사람이 확인해야 합니다.", ""]
    md += ["## 항목별 현황", "", "| 항목 | 명칭 | 점검 규칙 | 지적 | 잔존(사유 기록) | 상태 | 미점검 사유 |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r.item_id} | {r.name} | {', '.join(r.rules) or '-'} | {len(r.findings)} | {len(r.remaining)} | {r.status} | {'; '.join(r.unchecked) or '-'} |")
    counts = Counter(r.status for r in rows)
    md += ["", "상태별 항목 수: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), ""]
    md += ["## 항목별 상세", ""]
    for r in rows:
        if not r.findings and not r.remaining:
            continue
        md.append(f"### {r.item_id} {r.name}")
        for v in r.findings[:50]:
            md.append(f"- [{v.severity.value}·{'확정' if v.confidence.value == 'CONFIRMED' else '확인 필요'}] `{v.file_path.as_posix()}:{v.line_number}` {v.rule_id} {v.message}")
        if len(r.findings) > 50:
            md.append(f"- 외 {len(r.findings) - 50}건(전체 목록은 JSON 보고서)")
        for line in r.remaining:
            md.append(f"- 잔존: {line}")
        md.append("")
    skipped = (report.metadata or {}).get("skipped_files") or []
    if skipped:
        md += ["## 점검하지 못한 파일", ""]
        md += [f"- `{s.get('path')}`: {s.get('reason')}" for s in skipped[:100] if isinstance(s, dict)]
        md.append("")
    return "\n".join(md) + "\n"


def write_mois_docx(report: AuditReport, rules, path: Path) -> None:
    try:
        from docx import Document
    except ImportError as e:  # iron-laws: ignore[IL-301] 선택 의존성이 없을 때는 설치 방법을 알리는 오류로 바꿔 던진다
        raise RuntimeError("docx 출력에는 선택 의존성이 필요합니다: pip install 'iron-laws[docx]'") from e
    rows = build_rows(report, rules)
    doc = Document()
    doc.add_heading("소프트웨어 개발보안 감리 대응 보고서", 0)
    for key, value in _header(report):
        doc.add_paragraph(f"{key}: {value}")
    doc.add_paragraph("'지적 없음'은 탑재된 규칙 범위에서 발견되지 않았다는 뜻이며, 취약점이 없다는 증명이 아닙니다.")
    doc.add_heading("항목별 현황", 1)
    table = doc.add_table(rows=1, cols=6)
    for cell, title in zip(table.rows[0].cells, ("항목", "명칭", "점검 규칙", "지적", "상태", "미점검 사유"), strict=True):
        cell.text = title
    for r in rows:
        cells = table.add_row().cells
        for cell, value in zip(cells, (r.item_id, r.name, ", ".join(r.rules) or "-", str(len(r.findings)), r.status, "; ".join(r.unchecked) or "-"), strict=True):
            cell.text = value
    doc.add_heading("항목별 상세", 1)
    for r in rows:
        if not r.findings and not r.remaining:
            continue
        doc.add_heading(f"{r.item_id} {r.name}", 2)
        for v in r.findings[:50]:
            doc.add_paragraph(f"[{v.severity.value}] {v.file_path.as_posix()}:{v.line_number} {v.rule_id} {v.message}", style="List Bullet")
        for line in r.remaining:
            doc.add_paragraph(f"잔존: {line}", style="List Bullet")
    doc.save(str(path))
