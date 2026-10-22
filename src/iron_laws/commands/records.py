"""records 명령군."""

import json
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from iron_laws.commands.common import (
    FEEDBACK_FILE,
    ConfigOpt,
    PathArg,
    SearchParentsOpt,
    _build_scanner,
    _check_completion,
    _tool_version,
    baseline_app,
    console,
    err,
    feedback_app,
)
from iron_laws.core.baseline import (
    DEFAULT_BASELINE_FILE,
    build_baseline,
    load_baseline,
    migrate_baseline,
    save_baseline,
)
from iron_laws.core.config import ConfigError


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
        err.print("[bold red]점검이 완전하지 않아 기준선을 만들지 않습니다. 분석 실패나 빈 점검은 기준선으로 면제할 수 없습니다.[/bold red]")
        for d in [d for d in report.diagnostics if d.severity == "error"][:10]:
            err.print(f"  - {escape(d.file_path + ': ' if d.file_path else '')}{escape(d.message)}")
        raise typer.Exit(2)
    baseline = build_baseline(report, _tool_version())
    save_baseline(baseline, output)
    err.print(f"[bold green]기준선 저장 완료: {output} (지적 {len(baseline.entries)}건)[/bold green]")
    err.print("[dim]기준선의 지적은 승인된 부채로 기록됩니다. 이후 `--baseline`으로 새로 생긴 지적만 판정하십시오.[/dim]")


@baseline_app.command("migrate")
def baseline_migrate_command(
    old: Path = typer.Argument(..., help="옛 기준선 파일"),
    path: Path = typer.Argument(Path("."), help="점검할 프로젝트"),
    output: Path = typer.Option(None, "--output", "-o", help="새 기준선 저장 경로(생략하면 옛 파일을 덮어쓰지 않고 `<옛 이름>.migrated.json`)"),
    config: Path | None = ConfigOpt,
):
    """
    옛 기준선을 현재 지문으로 옮깁니다. 옮긴 항목은 '승인된 부채'일 뿐이며 사람의 검토 승인으로 승격되지 않습니다.
    현재 지적과 일대일로 맺어지지 않는 항목은 옮기지 않고 목록으로 알립니다.
    """
    try:
        legacy = load_baseline(old)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    scanner = _build_scanner(path, config)
    report = scanner.scan()
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 완전하지 않아 기준선을 옮기지 않습니다.[/bold red]")
        raise typer.Exit(2)
    result = migrate_baseline(legacy, report.violations, _tool_version())
    target = output or old.with_suffix(".migrated.json")
    save_baseline(result.baseline, target)
    err.print(f"[green]옮김 {len(result.migrated)}건, 맺지 못해 옮기지 않음 {len(result.unmatched)}건 → {target}[/green]")
    for entry in result.unmatched[:10]:
        err.print(f"  - 옮기지 않음: {escape(entry.rule_id)} {escape(entry.path)}:{entry.line}")
    err.print("[dim]이 기준선은 기존 지적 관리 데이터입니다. 승인 기록(approvals)은 자동으로 만들지 않았습니다.[/dim]")


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
    _check_completion(report, False)
    s = report.summary
    table = Table(title="[기준선 대비 현황]")
    for column in ("신규", "기존(승인)", "해소", "미확인", "재검토(규칙 의미 변경)"):
        table.add_column(column, justify="center")
    review = sum(1 for v in report.violations if v.baseline_status and v.baseline_status.value == "review")
    table.add_row(
        str((s.new_count or 0) - review), str(s.existing_count or 0), str(s.resolved_count or 0), str(s.unobserved_count or 0), str(review)
    )
    console.print(table)
    for d in report.diagnostics:
        if d.kind == "baseline":
            err.print(f"[yellow]{escape(d.message)}[/yellow]")
    for d in report.diagnostics:
        if d.kind == "cost":
            err.print(f"[yellow]{escape(d.message)}[/yellow]")


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
        err.print("[bold red]--verdict는 accepted, false-positive, deferred 중 하나여야 합니다.[/bold red]")
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
    err.print(f"[green]검토 기록을 추가했습니다: {file}[/green]")


@feedback_app.command("summary")
def feedback_summary_command(file: Path = typer.Option(Path(FEEDBACK_FILE), "--file", help="기록 파일")):
    """
    규칙별 채택률·오탐률·평균 검토 시간을 보여 줍니다.
    """
    if not file.is_file():
        err.print(f"[yellow]기록 파일이 없습니다: {file}[/yellow]")
        raise typer.Exit(2)
    stats: dict[str, dict[str, int]] = {}
    for raw in file.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            err.print(f"[yellow]읽을 수 없는 줄을 건너뜁니다: {escape(raw[:60])}[/yellow]")
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
