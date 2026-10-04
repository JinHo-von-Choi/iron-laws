"""
오철칙 Console Reporter (Rich Terminal Interface)
작성자: 최진호
작성일: 2026-10-04
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from iron_laws.core.models import AuditReport, Confidence, Severity

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

    result_text = (
        Text("합격 (PASS)", style="bold green")
        if s.is_passed
        else Text("불합격 (FAIL - 시정조치 필수)", style="bold red")
    )
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

    ordered = sorted(
        report.violations,
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
        grid.add_row("지적 항목", f"[{color}][{v.rule_id}] {v.rule_name} ({v.severity.value} · {label})[/{color}]")
        grid.add_row("위치", f"{v.file_path}:{v.line_number}")
        grid.add_row(
            "적용 기준",
            f"{v.gov_standard.standard_name} ({v.gov_standard.clause_id})" if v.gov_standard else BASIS_NONE,
        )
        grid.add_row("코드", f"[dim red]{v.snippet}[/dim red]")
        grid.add_row("진단", v.message)
        if v.plain:
            grid.add_row("왜 문제인가", v.plain)
        if v.how_to_fix:
            grid.add_row("고치는 방법", f"[green]{v.how_to_fix}[/green]")
        console.print(Panel(grid, title=f"지적 #{idx}", border_style=color.split()[-1]))
    if len(ordered) > len(shown):
        console.print(
            f"[yellow]나머지 {len(ordered) - len(shown)}건은 생략했습니다. 전체는 --limit 0 또는 --format markdown/json/sarif 로 확인하세요.[/yellow]"
        )
    console.print("[dim]AI 코딩 도구에 붙여넣을 수정 지시문은 `iron-laws fix-prompt` 로 만들 수 있습니다.[/dim]")
