"""catalog 명령군."""

import sys
from pathlib import Path

import typer
import yaml
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from iron_laws.commands.common import (
    BASIS_NONE,
    app,
    console,
    err,
    experience_lessons,
)
from iron_laws.core.config import IronLawsConfig
from iron_laws.core.models import AuditReport, AuditSummary
from iron_laws.reporters.coverage import (
    build_design_status,
    build_item_status,
    rule_item_ids,
    summarize,
)
from iron_laws.reporters.support import build_support_matrix, render_support_matrix
from iron_laws.rules.catalog import ALL_RULES, get_active_rules


@app.command("rules")
def rules_command() -> None:
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


@app.command("support")
def support_command(
    rule_id: str | None = typer.Argument(None, help="규칙 ID. 생략하면 전체 요약"),
):
    """
    언어별·규칙별로 무엇이 구현되어 있고 무엇이 시험으로 검증되었는지 보여 줍니다. '파서 있음'과 '검증됨'은 다릅니다.
    """
    matrix = build_support_matrix(get_active_rules())
    if rule_id is not None and rule_id.upper() not in {row.rule_id.upper() for row in matrix}:
        err.print(f"[bold red]규칙을 찾을 수 없습니다: {escape(rule_id)}[/bold red]")
        raise typer.Exit(2)
    sys.stdout.write(render_support_matrix(matrix, rule_id) + "\n")


@app.command("coverage")
def coverage_command(
    standard: str | None = typer.Option(None, "--standard", help="기준 팩 id(예: owasp-top10-2025, owasp-asi-2026, cwe-top25-2025). 생략하면 행안부 2021 구현단계"),
) -> None:
    """
    행안부 SW 개발보안 가이드(2021) 구현단계 49개 항목 중 어떤 항목을 점검하는지 보여 줍니다. --standard로 다른 기준 팩의 대응을 봅니다.
    """
    rules = get_active_rules()
    if standard is not None and standard != "mois-2021-impl":
        _pack_coverage(standard, rules)
        return
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
    err.print(f"[dim]규칙 {len(rules)}개 중 행안부 항목에 매핑된 규칙은 {sum(1 for r in rules if rule_item_ids(r))}개입니다.[/dim]")
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
            lessons = experience_lessons(rule_id=rule.rule_id)
            if lessons:
                lines += ["", "[bold]이 프로젝트에서 남긴 교훈[/bold]"]
                lines += [f"- {lesson}" for lesson in lessons]
            console.print(Panel("\n".join(lines)))
            return
    err.print(f"[bold red]규칙을 찾을 수 없습니다: {escape(rule_id)}[/bold red]")
    raise typer.Exit(2)


@app.command("init")
def init_command(target_dir: Path = typer.Argument(Path("."), help="설정 파일을 생성할 디렉터리")):
    """
    현재 디렉터리에 .iron-laws.yml 기본 설정 파일을 생성합니다.
    """
    config_path = target_dir / ".iron-laws.yml"
    if config_path.exists():
        err.print(f"[bold yellow]이미 설정 파일이 존재합니다: {config_path}[/bold yellow]")
        return

    body = yaml.safe_dump(
        IronLawsConfig().model_dump(mode="json"), allow_unicode=True, sort_keys=False
    )
    content = f"# 오철칙 (Iron Laws) 프로젝트 설정 파일\n{body}"
    config_path.write_text(content, encoding="utf-8")
    err.print(f"[bold green]기본 설정 파일이 생성되었습니다: {config_path}[/bold green]")


def _pack_coverage(pack_id: str, rules) -> None:
    from iron_laws.standards.pack_registry import all_packs

    pack = next((p for p in all_packs() if p.id == pack_id), None)
    if pack is None:
        err.print(f"[bold red]기준 팩을 찾을 수 없습니다: {escape(pack_id)} (있는 팩: {', '.join(p.id for p in all_packs())})[/bold red]")
        raise typer.Exit(2)
    active = {r.rule_id for r in rules}
    by_item: dict[str, list[str]] = {}
    for rule_id, item_ids in pack.mapping.items():
        if rule_id in active:
            for item_id in item_ids:
                by_item.setdefault(item_id, []).append(rule_id)
    table = Table(title=f"[{pack.title} ({pack.edition}) 항목별 대응 규칙]", expand=True)
    table.add_column("항목", style="bold cyan", width=8)
    table.add_column("명칭")
    table.add_column("대응 규칙")
    for item in pack.items:
        table.add_row(item.id, item.name, ", ".join(sorted(by_item.get(item.id, []))) or "-")
    console.print(table)
    covered = sum(1 for item in pack.items if by_item.get(item.id))
    state = "사람이 이 판본으로 확인함" if pack.mapping_verified else "미확인(오철칙이 정한 대응이며 사람이 이 판본으로 확인하지 않음)"
    console.print(f"대응 규칙이 있는 항목 {covered}개 / 전체 {len(pack.items)}개 · 대응표: {state}")
    console.print(f"[dim]출처 {pack.source_url} (수집 {pack.retrieved_at}) · 내용 해시 {pack.content_sha256()[:16]}[/dim]")
