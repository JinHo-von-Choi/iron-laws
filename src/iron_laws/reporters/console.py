"""
오철칙 Console Reporter (Rich Terminal Interface)
작성자: 최진호
작성일: 2026-10-04
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iron_laws.core.models import AuditReport, BaselineStatus, Confidence, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold magenta",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}
SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
BASIS_NONE = "오철칙 자체 품질 규칙 (참고 가이드 항목 외)"
DEFAULT_LIMIT = 50


_ROLE = {"source": "입력", "propagation": "전파", "sink": "싱크"}


def _print_diagnostics(report: AuditReport) -> None:
    """점검 과정의 문제는 숨기지 않는다. 오류는 점검이 불완전했다는 뜻이다."""
    shown = [d for d in report.diagnostics if d.severity in ("error", "warning")]
    if not shown:
        return
    errors = sum(1 for d in shown if d.severity == "error")
    console.print(Text(f"점검 진단: 오류 {errors}건 · 경고 {len(shown) - errors}건 (전체는 --format json의 diagnostics)", style="bold yellow" if not errors else "bold red"))
    for d in shown[:8]:
        where = f"{d.file_path}:{d.line}: " if d.file_path and d.line else (f"{d.file_path}: " if d.file_path else "")
        console.print(Text(f"  [{d.severity}] {where}{d.message}", style="red" if d.severity == "error" else "yellow"))
    if len(shown) > 8:
        console.print(Text(f"  … 외 {len(shown) - 8}건", style="dim"))


_STATE_LABEL = {
    "evidence_met": "근거 충족",
    "unsupported": "미지원",
    "unresolved": "해석 미확정",
    "budget_exceeded": "예산 초과",
    "policy_excluded": "정책 제외",
}
_CONTRACT_LABEL = {"met": "충족", "unmet": "미충족", "policy_change_review": "정책 변경 검토 필요", "not_applicable": "해당 없음"}


def _print_ledger(report: AuditReport) -> None:
    ledger = report.coverage_ledger
    if ledger is None:
        return
    console.print(
        Text(
            f"근거 계약: {_CONTRACT_LABEL.get(ledger.status, ledger.status)} (모드 {ledger.contract_mode}, 범위 {ledger.contract_scope}, 계약 {ledger.contract_source})",
            style="bold green" if ledger.status == "met" else "bold yellow",
        )
    )
    for tally in ledger.families:
        states = " · ".join(f"{_STATE_LABEL.get(k, k)} {v}" for k, v in sorted(tally.by_state.items())) or "관심 지점 없음"
        console.print(Text(f"  [{tally.family}] 지점 {tally.in_scope}개(범위 안) — {states}", style="dim"))
    unclassified = [f for f in ledger.files if f.classification == "unclassified"]
    if unclassified:
        console.print(Text(f"  분류하지 못한 파일 {len(unclassified)}개 (변경 파일 중 {len(ledger.unclassified_changed_files)}개)", style="yellow"))
    for blocker in ledger.blockers[:5]:
        console.print(Text(f"  - {blocker}", style="yellow"))
    if len(ledger.blockers) > 5:
        console.print(Text(f"  … 외 {len(ledger.blockers) - 5}건", style="dim"))


def print_console_report(report: AuditReport, limit: int = DEFAULT_LIMIT) -> None:
    console.print()
    title_text = Text("오철칙 (五鐵則) SW 개발보안 점검 리포트", style="bold white on blue", justify="center")
    console.print(Panel(title_text, subtitle=f"문서번호: {report.document_id} | 점검 주체: {report.auditor}"))
    console.print()

    s = report.summary
    summary_table = Table(title="[점검 통계 및 등급 판정]", expand=True)
    summary_table.add_column("스캔 파일 수", justify="center")
    summary_table.add_column("총 지적 건수", justify="center")
    summary_table.add_column("치명 (Critical)", justify="center", style="bold red")
    summary_table.add_column("고위험 (High)", justify="center", style="bold magenta")
    summary_table.add_column("중위험 (Medium)", justify="center", style="bold yellow")
    summary_table.add_column("저위험 (Low)", justify="center", style="bold cyan")
    summary_table.add_column("종합 판정 등급", justify="center", style="bold white")
    summary_table.add_column("검수 결과", justify="center")

    if s.total_files_scanned == 0:
        result_text = Text("점검 없음 (파일 0개)", style="bold yellow")
    elif s.is_passed:
        result_text = Text("합격 (PASS)", style="bold green")
    else:
        result_text = Text("불합격 (FAIL - 시정조치 필수)", style="bold red")
    summary_table.add_row(
        str(s.total_files_scanned),
        str(s.total_violations),
        str(s.critical_count),
        str(s.high_count),
        str(s.medium_count),
        str(s.low_count),
        f"등급: {s.grade}",
        result_text,
    )
    console.print(summary_table)
    meta = report.metadata
    if meta.get("config_source"):
        console.print(Text(f"설정: {meta['config_source']} (fail_on={meta.get('config', {}).get('fail_on', '?')}, 출처: {meta.get('fail_on_source', '기본값')})", style="dim"))
    scope = meta.get("scope")
    if scope:
        console.print(Text(f"범위 제한: {scope['ref']} 이후 바뀐 파일 {scope['changed_files']}개의 지적만 표시했습니다. {scope['note']}", style="yellow"))
    if s.new_count is not None:
        console.print(
            Text(f"기준선 대비: 신규·재검토 {s.new_count}건 · 기존(승인) {s.existing_count}건 · 해소 {s.resolved_count}건 · 미확인 {s.unobserved_count}건", style="bold")
        )
    _print_diagnostics(report)
    _print_ledger(report)
    if s.suppressed_count:
        console.print(f"[dim]사유와 함께 억제된 지적 {s.suppressed_count}건은 제외되었습니다.[/dim]")
    console.print()

    if not report.violations:
        console.print(
            Panel(
                "[bold green]탑재된 규칙 범위에서 위반 사항이 없습니다.[/bold green] 탑재되지 않은 보안약점 항목은 점검되지 않았습니다."
            )
        )
        return

    visible = report.violations
    if s.new_count is not None:
        visible = [v for v in report.violations if v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW)]
        if not visible:
            console.print(Panel("[bold green]기준선에 없던 새 지적이 없습니다.[/bold green]"))
            return
    ordered = sorted(
        visible,
        key=lambda v: (SEVERITY_ORDER[v.severity], str(v.file_path), v.line_number),
    )
    shown = ordered if limit <= 0 else ordered[:limit]
    console.print("[bold red]● 지적사항 목록 (심각도 순)[/bold red]")
    for idx, v in enumerate(shown, start=1):
        color = SEVERITY_COLORS.get(v.severity, "white")
        grid = Table(box=None, show_header=False, expand=True)
        grid.add_column("key", style="bold white", width=14)
        grid.add_column("val")
        label = "확인 필요" if v.confidence is Confidence.REVIEW else "확정"
        if v.baseline_status is BaselineStatus.REVIEW:
            label += " · 규칙 의미 변경으로 재검토"
        grid.add_row(
            "지적 항목", Text(f"[{v.rule_id}] {v.rule_name} ({v.severity.value} · {label})", style=color)
        )
        grid.add_row("위치", Text(f"{v.file_path}:{v.line_number}"))
        grid.add_row(
            "적용 기준",
            Text(f"{v.gov_standard.standard_name} ({v.gov_standard.clause_id})" if v.gov_standard else BASIS_NONE),
        )
        # 소스 코드와 경로는 데이터다. Rich 마크업으로 해석되지 않도록 Text로 넘긴다
        grid.add_row("코드", Text(v.snippet, style="dim red"))
        grid.add_row("진단", Text(v.message))
        if v.evidence:
            grid.add_row("판단 근거", Text(" → ".join(f"{_ROLE.get(e.role, e.role)} {e.file_path}:{e.line}" for e in v.evidence)))
        if v.plain:
            grid.add_row("왜 문제인가", Text(v.plain))
        if v.how_to_fix:
            grid.add_row("고치는 방법", Text(v.how_to_fix, style="green"))
        console.print(Panel(grid, title=f"지적 #{idx}", border_style=color.split()[-1]))
    if len(ordered) > len(shown):
        console.print(
            f"[yellow]나머지 {len(ordered) - len(shown)}건은 생략했습니다. 전체는 --limit 0 또는 --format markdown/json/sarif 로 확인하세요.[/yellow]"
        )
    console.print("[dim]AI 코딩 도구에 붙여넣을 수정 지시문은 `iron-laws fix-prompt` 로 만들 수 있습니다.[/dim]")
