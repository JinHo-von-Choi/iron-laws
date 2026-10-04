"""
오철칙 (Iron Laws) CLI Application
작성자: 최진호
작성일: 2026-10-04
"""

import json
import subprocess
import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from iron_laws.core.baseline import (
    DEFAULT_BASELINE_FILE,
    Baseline,
    build_baseline,
    load_baseline,
    save_baseline,
)
from iron_laws.core.config import ConfigError, InputPathError, IronLawsConfig
from iron_laws.core.models import AuditReport, AuditSummary, Severity
from iron_laws.core.scanner import AuditScanner, tool_version
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
from iron_laws.reporters.support import build_support_matrix, render_support_matrix
from iron_laws.rules.catalog import ALL_RULES, get_active_rules

app = typer.Typer(
    name="iron-laws",
    help="오철칙 (五鐵則) - SI 감리에서 자주 지적되는 항목을 정리한 소스코드 보안·품질 점검 CLI",
    add_completion=False,
)
baseline_app = typer.Typer(help="기준선(baseline): 이미 알려진 지적을 승인된 부채로 기록하고 새 지적만 걸러 냅니다")
feedback_app = typer.Typer(help="'확인 필요' 지적의 검토 결과(채택·오탐·소요 시간)를 기록하고 모아 봅니다")
app.add_typer(baseline_app, name="baseline")
app.add_typer(feedback_app, name="feedback")
console = Console()

BASIS_NONE = "오철칙 자체 품질 규칙 (참고 가이드 항목 외)"
FEEDBACK_FILE = ".iron-laws-feedback.jsonl"
PathArg = typer.Argument(Path("."), help="점검할 프로젝트 디렉터리 또는 파일 경로")
AllowEmptyOpt = typer.Option(
    False, "--allow-empty", help="점검할 파일이 하나도 없어도 오류로 보지 않습니다 (결과에는 '점검 없음'으로 표시)"
)
LimitOpt = typer.Option(DEFAULT_LIMIT, "--limit", min=0, help="화면에 표시할 최대 지적 수 (0이면 전부)")
ConfigOpt = typer.Option(None, "--config", help="사용할 설정 파일. 지정하면 점검 폴더의 .iron-laws.yml보다 우선합니다")
SearchParentsOpt = typer.Option(
    False, "--search-parents", help="점검 폴더에 설정 파일이 없으면 상위 폴더에서 찾습니다 (기본은 찾지 않음)"
)
BaselineOpt = typer.Option(
    None, "--baseline", help="기준선 파일. 지정하면 기준선에 없던 새 지적과 재검토 대상만 통과·실패에 반영합니다"
)
GitignoreOpt = typer.Option(
    False, "--respect-gitignore", help=".gitignore에 걸리는 파일과 폴더를 점검하지 않습니다 (기본은 점검). 설정의 respect_gitignore와 같습니다"
)
ChangedSinceOpt = typer.Option(
    None, "--changed-since", help="이 git 기준(브랜치·커밋)보다 바뀐 파일의 지적만 표시합니다. 전체 점검과 정기적으로 대조하십시오"
)


class ReportFormat(StrEnum):
    CONSOLE = "console"
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"
    PROMPT = "prompt"
    REVIEW = "review"


def _tool_version() -> str:
    return tool_version()


def _git(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise ConfigError(f"git 명령을 실행하지 못했습니다 (git {' '.join(args)}): {e}") from e
    return result.stdout


def _changed_files(root: Path, ref: str) -> set[str]:
    """ref 이후 바뀐 파일(추적 중인 변경과 새 파일)을 점검 루트 기준 상대 경로로 돌려준다."""
    folder = root if root.is_dir() else root.parent
    top = Path(_git(["rev-parse", "--show-toplevel"], folder).strip())
    names = _git(["diff", "--name-only", "--diff-filter=ACMRT", ref], folder).splitlines()
    names += _git(["ls-files", "--others", "--exclude-standard"], folder).splitlines()
    base = root.resolve() if root.is_dir() else root.resolve().parent
    changed: set[str] = set()
    for name in names:
        try:
            changed.add((top / name).resolve().relative_to(base).as_posix())
        except ValueError:  # 점검 폴더 밖의 변경은 이번 점검 대상이 아니다
            continue
    return changed


def _build_scanner(
    path: Path,
    config: Path | None = None,
    search_parents: bool = False,
    baseline: Path | None = None,
    changed_since: str | None = None,
    respect_gitignore: bool = False,
) -> AuditScanner:
    try:
        loaded: Baseline | None = load_baseline(baseline) if baseline else None
        changed = _changed_files(path, changed_since) if changed_since else None
        scanner = AuditScanner(
            path,
            config_path=config,
            search_parents=search_parents,
            baseline=loaded,
            changed_files=changed,
            changed_since=changed_since,
            respect_gitignore=respect_gitignore,
        )
        return scanner
    except ConfigError as e:
        label = "입력 오류" if isinstance(e, InputPathError) else "설정 오류"
        console.print(f"[bold red]{label}: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e


def _check_completion(report: AuditReport, allow_empty: bool) -> None:
    """점검이 끝까지 이루어지지 않았으면 통과로 보지 않는다. 경로 오타·제외 설정 실수·규칙 오류를 CI가 놓치지 않게 한다."""
    status = report.summary.scan_status
    if status == "empty":
        if allow_empty:
            report.summary.is_passed = True
            return
        console.print(
            "[bold red]점검한 파일이 없습니다. 경로, 제외 설정, 확장자 설정을 확인하세요. "
            "의도한 경우 --allow-empty를 붙이세요.[/bold red]"
        )
        raise typer.Exit(2)
    if status == "incomplete":
        errors = [d for d in report.diagnostics if d.severity == "error"]
        console.print(f"[bold red]점검이 끝까지 이루어지지 않았습니다 (오류 {len(errors)}건). 통과로 판정하지 않습니다.[/bold red]")
        for d in errors[:10]:
            where = f"{d.file_path}: " if d.file_path else ""
            console.print(f"  - {escape(where + d.message)}")
        raise typer.Exit(2)


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
        help="CI 실패 임계치 (CRITICAL, HIGH, MEDIUM, LOW). 우선순위: 이 옵션 > 설정 파일의 fail_on > HIGH",
    ),
    limit: int = LimitOpt,
    allow_empty: bool = AllowEmptyOpt,
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
    baseline: Path | None = BaselineOpt,
    changed_since: str | None = ChangedSinceOpt,
    respect_gitignore: bool = GitignoreOpt,
):
    """
    프로젝트의 보안 약점과 품질 결함을 신속 진단합니다. (CI/CD 적합)
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore)
    if fail_on is not None:
        scanner.config.fail_on = fail_on
        scanner.fail_on_source = "명령행 옵션"
    report = scanner.scan()
    print_console_report(report, limit)
    _check_completion(report, allow_empty)

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
    limit: int = typer.Option(DEFAULT_LIMIT, "--limit", min=0, help="console/prompt 형식의 최대 지적 수 (0이면 전부)"),
    allow_empty: bool = AllowEmptyOpt,
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
    baseline: Path | None = BaselineOpt,
    changed_since: str | None = ChangedSinceOpt,
    respect_gitignore: bool = GitignoreOpt,
):
    """
    점검을 수행하고 보고서를 발행합니다. markdown 보고서에는 행안부 구현단계 49개 항목별 점검 현황이 포함됩니다.
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore)
    report = scanner.scan()
    if report.summary.scan_status == "empty" and not allow_empty:
        _check_completion(report, allow_empty)
    _emit_report(report, scanner, report_format, output, limit)
    if report.summary.scan_status == "incomplete":
        _check_completion(report, allow_empty)
    if report.summary.scan_status == "empty" and allow_empty:
        sys.exit(0)
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
    limit: int = typer.Option(40, "--limit", min=1, help="지시문에 담을 최대 지적 수"),
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
    baseline: Path | None = BaselineOpt,
    changed_since: str | None = ChangedSinceOpt,
    respect_gitignore: bool = GitignoreOpt,
):
    """
    점검 결과를 코딩 AI에게 그대로 붙여넣을 수정 지시문으로 만듭니다. 지시문 생성이 목적이라 지적이 있어도 종료코드는 0입니다.
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore)
    report = scanner.scan()
    _write_or_print(generate_fix_prompt(report, limit), output, "수정 지시문")


@baseline_app.command("create")
def baseline_create_command(
    path: Path = PathArg,
    output: Path = typer.Option(Path(DEFAULT_BASELINE_FILE), "--output", "-o", help="기준선 파일 경로"),
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
):
    """
    현재 지적을 기준선으로 기록합니다. 점검이 끝까지 이루어지지 않았거나 파일이 없으면 만들지 않습니다.
    """
    scanner = _build_scanner(path, config, search_parents)
    report = scanner.scan()
    if report.summary.scan_status != "complete":
        console.print("[bold red]점검이 완전하지 않아 기준선을 만들지 않습니다. 분석 실패나 빈 점검은 기준선으로 면제할 수 없습니다.[/bold red]")
        for d in [d for d in report.diagnostics if d.severity == "error"][:10]:
            console.print(f"  - {escape(d.file_path + ': ' if d.file_path else '')}{escape(d.message)}")
        raise typer.Exit(2)
    baseline = build_baseline(report, _tool_version())
    save_baseline(baseline, output)
    console.print(f"[bold green]기준선 저장 완료: {output} (지적 {len(baseline.entries)}건)[/bold green]")
    console.print("[dim]기준선의 지적은 승인된 부채로 기록됩니다. 이후 `--baseline`으로 새로 생긴 지적만 판정하십시오.[/dim]")


@baseline_app.command("diff")
def baseline_diff_command(
    path: Path = PathArg,
    baseline: Path = typer.Option(Path(DEFAULT_BASELINE_FILE), "--baseline", help="기준선 파일"),
    config: Path | None = ConfigOpt,
):
    """
    기준선과 비교해 신규·기존·해소·재검토 건수를 보여 줍니다.
    """
    scanner = _build_scanner(path, config, False, baseline)
    report = scanner.scan()
    s = report.summary
    table = Table(title="[기준선 대비 현황]")
    for column in ("신규", "기존(승인)", "해소", "재검토(규칙 의미 변경)"):
        table.add_column(column, justify="center")
    review = sum(1 for v in report.violations if v.baseline_status and v.baseline_status.value == "review")
    table.add_row(str((s.new_count or 0) - review), str(s.existing_count or 0), str(s.resolved_count or 0), str(review))
    console.print(table)
    for d in report.diagnostics:
        if d.kind == "baseline":
            console.print(f"[yellow]{escape(d.message)}[/yellow]")


@feedback_app.command("add")
def feedback_add_command(
    rule_id: str = typer.Argument(..., help="규칙 ID (예: IL-501)"),
    location: str = typer.Argument(..., help="지적 위치 (예: src/app.py:42)"),
    verdict: str = typer.Option(..., "--verdict", help="accepted(고침) / false-positive(오탐) / deferred(보류)"),
    reason: str = typer.Option("", "--reason", help="판단 근거 한 줄"),
    minutes: int = typer.Option(0, "--minutes", min=0, help="검토에 든 시간(분)"),
    file: Path = typer.Option(Path(FEEDBACK_FILE), "--file", help="기록 파일"),
):
    """
    '확인 필요' 지적을 검토한 결과를 기록합니다. 규칙 개선과 오탐 줄이기에 쓸 자료입니다.
    """
    if verdict not in ("accepted", "false-positive", "deferred"):
        console.print("[bold red]--verdict는 accepted, false-positive, deferred 중 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    record = {
        "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule_id": rule_id.upper(),
        "location": location,
        "verdict": verdict,
        "reason": reason,
        "minutes": minutes,
    }
    with file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    console.print(f"[green]검토 기록을 추가했습니다: {file}[/green]")


@feedback_app.command("summary")
def feedback_summary_command(file: Path = typer.Option(Path(FEEDBACK_FILE), "--file", help="기록 파일")):
    """
    규칙별 채택률·오탐률·평균 검토 시간을 보여 줍니다.
    """
    if not file.is_file():
        console.print(f"[yellow]기록 파일이 없습니다: {file}[/yellow]")
        raise typer.Exit(2)
    stats: dict[str, dict[str, int]] = {}
    for raw in file.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            console.print(f"[yellow]읽을 수 없는 줄을 건너뜁니다: {escape(raw[:60])}[/yellow]")
            continue
        row = stats.setdefault(rec.get("rule_id", "?"), {"accepted": 0, "false-positive": 0, "deferred": 0, "minutes": 0, "n": 0})
        row[rec.get("verdict", "deferred")] = row.get(rec.get("verdict", "deferred"), 0) + 1
        row["minutes"] += int(rec.get("minutes", 0))
        row["n"] += 1
    table = Table(title="[검토 기록 요약]")
    for column in ("규칙", "검토", "채택", "오탐", "보류", "평균 시간(분)"):
        table.add_column(column, justify="center")
    for rule_id, row in sorted(stats.items()):
        table.add_row(rule_id, str(row["n"]), str(row["accepted"]), str(row["false-positive"]), str(row["deferred"]), f"{row['minutes'] / row['n']:.1f}")
    console.print(table)


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


@app.command("support")
def support_command(
    rule_id: str | None = typer.Argument(None, help="규칙 ID. 생략하면 전체 요약"),
):
    """
    언어별·규칙별로 무엇이 구현되어 있고 무엇이 시험으로 검증되었는지 보여 줍니다. '파서 있음'과 '검증됨'은 다릅니다.
    """
    matrix = build_support_matrix(get_active_rules())
    if rule_id is not None and rule_id.upper() not in {row.rule_id.upper() for row in matrix}:
        console.print(f"[bold red]규칙을 찾을 수 없습니다: {escape(rule_id)}[/bold red]")
        raise typer.Exit(2)
    sys.stdout.write(render_support_matrix(matrix, rule_id) + "\n")


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
    console.print(f"[bold red]규칙을 찾을 수 없습니다: {escape(rule_id)}[/bold red]")
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
