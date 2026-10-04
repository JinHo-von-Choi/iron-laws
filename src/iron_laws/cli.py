"""
오철칙 (Iron Laws) CLI Application
작성자: 최진호
작성일: 2026-10-04
"""

import sys
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from iron_laws.core.config import ConfigError, IronLawsConfig
from iron_laws.core.models import AuditReport, AuditSummary, Severity
from iron_laws.core.scanner import AuditScanner
from iron_laws.reporters.console import DEFAULT_LIMIT, print_console_report
from iron_laws.reporters.coverage import (
    build_design_status,
    build_item_status,
    rule_item_ids,
    summarize,
)
from iron_laws.reporters.json_reporter import generate_json_report
from iron_laws.reporters.markdown import generate_markdown_report
from iron_laws.reporters.prompt import generate_fix_prompt
from iron_laws.reporters.review import generate_review_report
from iron_laws.reporters.sarif import generate_sarif_report
from iron_laws.rules.catalog import ALL_RULES, get_active_rules

app = typer.Typer(
    name="iron-laws",
    help="오철칙 (五鐵則) - SI 감리에서 자주 지적되는 항목을 정리한 소스코드 보안·품질 점검 CLI",
    add_completion=False,
)
console = Console()

BASIS_NONE = "오철칙 자체 품질 규칙 (참고 가이드 항목 외)"
PathArg = typer.Argument(Path("."), help="점검할 프로젝트 디렉터리 또는 파일 경로")


class ReportFormat(StrEnum):
    CONSOLE = "console"
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"
    PROMPT = "prompt"
    REVIEW = "review"


def _tool_version() -> str:
    try:
        return version("iron-laws")
    except PackageNotFoundError:  # iron-laws: ignore[IL-301] 설치 메타데이터가 없는 소스 실행에서는 버전을 알 수 없다고 표기한다
        return "0.0.0"


def _build_scanner(path: Path) -> AuditScanner:
    try:
        return AuditScanner(path)
    except ConfigError as e:
        console.print(f"[bold red]설정 오류: {e}[/bold red]")
        raise typer.Exit(2) from e


def _write_or_print(content: str, output: Path | None, label: str) -> None:
    if output:
        output.write_text(content, encoding="utf-8")
        console.print(f"[bold green]{label} 저장 완료: {output}[/bold green]")
    else:
        sys.stdout.write(content + "\n")


@app.command("check")
def check_command(
    path: Path = PathArg,
    fail_on: Severity | None = typer.Option(
        None,
        "--fail-on",
        "-f",
        case_sensitive=False,
        help="CI 실패 임계치 (CRITICAL, HIGH, MEDIUM, LOW). 미지정 시 설정 파일의 fail_on, 그것도 없으면 HIGH",
    ),
    limit: int = typer.Option(DEFAULT_LIMIT, "--limit", help="화면에 표시할 최대 지적 수 (0이면 전부)"),
):
    """
    프로젝트의 보안 약점과 품질 결함을 신속 진단합니다. (CI/CD 적합)
    """
    scanner = _build_scanner(path)
    if fail_on is not None:
        scanner.config.fail_on = fail_on
    report = scanner.scan()

    print_console_report(report, limit)

    if not report.summary.is_passed:
        console.print(
            f"[bold red]오철칙 기준 미달 (등급: {report.summary.grade})로 인해 점검이 실패했습니다.[/bold red]"
        )
        sys.exit(1)
    sys.exit(0)


@app.command("audit")
def audit_command(
    path: Path = PathArg,
    output: Path | None = typer.Option(None, "--output", "-o", help="보고서 저장 파일 경로"),
    report_format: ReportFormat = typer.Option(
        ReportFormat.CONSOLE,
        "--format",
        case_sensitive=False,
        help="출력 형식 (console, markdown, json, sarif, prompt, review)",
    ),
    limit: int = typer.Option(DEFAULT_LIMIT, "--limit", help="console/prompt 형식의 최대 지적 수 (0이면 전부)"),
):
    """
    점검을 수행하고 보고서를 발행합니다. markdown 보고서에는 행안부 구현단계 49개 항목별 점검 현황이 포함됩니다.
    """
    scanner = _build_scanner(path)
    report = scanner.scan()
    _emit_report(report, scanner, report_format, output, limit)
    sys.exit(0 if report.summary.is_passed else 1)


def _emit_report(
    report: AuditReport,
    scanner: AuditScanner,
    report_format: ReportFormat,
    output: Path | None,
    limit: int,
) -> None:
    if report_format is ReportFormat.CONSOLE:
        print_console_report(report, limit)
        if output:
            output.write_text(generate_markdown_report(report, scanner.rules), encoding="utf-8")
            console.print(f"[bold green]보고서가 파일에 저장되었습니다: {output}[/bold green]")
    elif report_format is ReportFormat.MARKDOWN:
        _write_or_print(generate_markdown_report(report, scanner.rules), output, "보고서")
    elif report_format is ReportFormat.JSON:
        _write_or_print(generate_json_report(report), output, "JSON 보고서")
    elif report_format is ReportFormat.SARIF:
        _write_or_print(generate_sarif_report(report, scanner.rules, _tool_version()), output, "SARIF 보고서")
    elif report_format is ReportFormat.REVIEW:
        _write_or_print(generate_review_report(report, scanner.rules, _tool_version()), output, "검토 의견서")
    else:
        _write_or_print(generate_fix_prompt(report, limit if limit > 0 else 10_000), output, "수정 지시문")


@app.command("fix-prompt")
def fix_prompt_command(
    path: Path = PathArg,
    output: Path | None = typer.Option(None, "--output", "-o", help="지시문 저장 파일 경로"),
    limit: int = typer.Option(40, "--limit", help="지시문에 담을 최대 지적 수"),
):
    """
    점검 결과를 코딩 AI에게 그대로 붙여넣을 수정 지시문으로 만듭니다.
    """
    scanner = _build_scanner(path)
    report = scanner.scan()
    _write_or_print(generate_fix_prompt(report, limit), output, "수정 지시문")


@app.command("rules")
def rules_command():
    """
    오철칙(五鐵則) 5대 철칙과 탑재된 검증 규칙 목록을 확인합니다.
    """
    console.print()
    console.print(
        Panel(
            "[bold white on blue] 오철칙 (五鐵則) 5대 철칙 [/bold white on blue]\n\n"
            "1. [bold red]제1철칙[/bold red]: 타협과 묵인은 없다 (No Compromise) - 보안·품질 결함에 대한 변명 일체 배격\n"
            "2. [bold red]제2철칙[/bold red]: 근거 규정 없는 지적은 잡담이다 (Evidence-Backed) - 행안부 가이드 항목 번호와 결합, 기준 밖 규칙은 구분 표기\n"
            "3. [bold red]제3철칙[/bold red]: 병신같이 덮지 않는다 (Anti-Coverup) - 삼킨 예외, 꺼 둔 테스트, 가짜 통과, 타입 검사 회피 엄단\n"
            "4. [bold red]제4철칙[/bold red]: 대안 없는 비판은 직무유기다 (Actionable Alternatives) - 모든 지적에 고치는 방법 제시\n"
            "5. [bold red]제5철칙[/bold red]: 전수 검증의 원칙 (Exhaustive Verification) - 입력 경로 추적, 구조·중복·순환 의존까지 점검"
        )
    )
    console.print()

    table = Table(title=f"[내장 규칙 {len(ALL_RULES)}개]", expand=True)
    table.add_column("규칙 ID", style="bold cyan", width=9)
    table.add_column("철칙", width=7)
    table.add_column("규칙 명칭", style="bold white")
    table.add_column("심각도", justify="center", width=9)
    table.add_column("근거")

    for rule_cls in ALL_RULES:
        instance = rule_cls()
        std = instance.gov_standard
        basis = f"행안부 2021 {std.clause_id}" if std else BASIS_NONE
        table.add_row(
            instance.rule_id,
            f"제{instance.iron_law.value}철칙",
            instance.name,
            instance.severity.value,
            basis,
        )

    console.print(table)


@app.command("coverage")
def coverage_command():
    """
    행안부 SW 개발보안 가이드(2021) 구현단계 49개 항목 중 어떤 항목을 점검하는지 보여 줍니다.
    """
    rules = get_active_rules()
    empty = AuditReport(
        document_id="COVERAGE",
        audit_date="",
        target_path=".",
        summary=AuditSummary(),
    )
    statuses = build_item_status(empty, rules)
    counts = summarize(statuses)
    table = Table(title="[행안부 구현단계 보안약점 49개 항목 점검 현황]", expand=True)
    table.add_column("항목", style="bold cyan", width=6)
    table.add_column("명칭")
    table.add_column("점검 규칙")
    table.add_column("상태", width=14)
    for s in statuses:
        status_style = {"지적 없음": "green", "수동 확인 필요": "yellow", "미탑재": "red"}.get(s.status, "white")
        table.add_row(
            s.item.id,
            s.item.name,
            ", ".join(s.rule_ids) if s.rule_ids else "-",
            f"[{status_style}]{'탑재' if s.rule_ids else s.status}[/{status_style}]",
        )
    console.print(table)
    loaded = sum(1 for s in statuses if s.rule_ids)
    console.print(
        f"탑재 {loaded}개 · 수동 확인 필요 {counts['수동 확인 필요']}개 · 미탑재 {counts['미탑재']}개 (전체 {len(statuses)}개)"
    )
    console.print(f"[dim]규칙 {len(rules)}개 중 행안부 항목에 매핑된 규칙은 {sum(1 for r in rules if rule_item_ids(r))}개입니다.[/dim]")
    design = build_design_status(empty, rules)
    covered = sum(1 for d in design if d.rule_ids)
    console.print(
        f"설계단계 보안설계 20개 항목 중 구현 규칙으로 확인하는 항목 {covered}개, 사람이 확인해야 하는 항목 {len(design) - covered}개 "
        f"({', '.join(d.item.id for d in design if not d.rule_ids)})"
    )


@app.command("explain")
def explain_command(rule_id: str = typer.Argument(..., help="규칙 ID (예: IL-501)")):
    """
    규칙 하나를 쉬운 말로 설명하고, 고치는 방법을 보여 줍니다.
    """
    wanted = rule_id.upper()
    for rule in get_active_rules():
        if rule.rule_id.upper() == wanted:
            std = rule.gov_standard
            lines = [
                f"[bold cyan]{rule.rule_id}[/bold cyan] {rule.name}",
                f"심각도: {rule.severity.value} · 분류: {rule.layer.value}",
                f"근거: {std.standard_name} - {std.clause_id}" if std else f"근거: {BASIS_NONE}",
                "",
                f"[bold]왜 문제인가[/bold]\n{rule.plain}" if rule.plain else "",
                "",
                f"[bold]고치는 방법[/bold]\n{rule.how_to_fix}" if rule.how_to_fix else "",
            ]
            console.print(Panel("\n".join(lines)))
            return
    console.print(f"[bold red]규칙을 찾을 수 없습니다: {rule_id}[/bold red]")
    raise typer.Exit(2)


@app.command("init")
def init_command(target_dir: Path = typer.Argument(Path("."), help="설정 파일을 생성할 디렉터리")):
    """
    현재 디렉터리에 .iron-laws.yml 기본 설정 파일을 생성합니다.
    """
    config_path = target_dir / ".iron-laws.yml"
    if config_path.exists():
        console.print(f"[bold yellow]이미 설정 파일이 존재합니다: {config_path}[/bold yellow]")
        return

    body = yaml.safe_dump(
        IronLawsConfig().model_dump(mode="json"), allow_unicode=True, sort_keys=False
    )
    content = f"# 오철칙 (Iron Laws) 프로젝트 설정 파일\n{body}"
    config_path.write_text(content, encoding="utf-8")
    console.print(f"[bold green]기본 설정 파일이 생성되었습니다: {config_path}[/bold green]")


def main():
    app()


if __name__ == "__main__":
    main()
