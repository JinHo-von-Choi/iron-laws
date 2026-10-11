"""pilot 명령군."""

import json
import sys
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from iron_laws.commands.common import (
    console,
    err,
    pilot_app,
)
from iron_laws.core.config import ConfigError


def _pilot_store(path: Path | None):
    from iron_laws.core.pilot import PILOT_FILE, PilotStore

    return PilotStore(path or Path(PILOT_FILE))


def _pilot_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e


@pilot_app.command("assign")
def pilot_assign_command(
    pr: str = typer.Argument(..., help="PR 이름표(식별자). 코드·제목 원문을 넣지 마십시오"),
    team: str = typer.Option(..., "--team", help="팀 이름표"),
    stratum: str = typer.Option("medium", "--stratum", help="난도층(small·medium·large 등). 층 안에서 조건이 균형 있게 배정됩니다"),
    seed: int = typer.Option(1, "--seed", help="무작위 순서의 씨앗. 같은 씨앗이면 같은 배정이 재현됩니다"),
    reviewer: str = typer.Option("", "--reviewer", help="검토자 이름표(선택)"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    PR 하나를 조건(baseline 또는 bundle)에 한 번만 배정합니다. 같은 PR을 두 조건에 노출하지 않습니다.
    """
    from iron_laws.core.pilot import assign

    record = _pilot_call(assign, _pilot_store(store), team, pr, stratum, seed, reviewer)
    sys.stdout.write(record["arm"] + "\n")


@pilot_app.command("record")
def pilot_record_command(
    pr: str = typer.Argument(..., help="배정된 PR 이름표"),
    minutes: float = typer.Option(..., "--minutes", help="검토에 든 시간(분)"),
    setup_minutes: float = typer.Option(0.0, "--setup-minutes", help="이 팀이 도구를 설치·설정하는 데 든 시간(분). 첫 기록에만 적어도 됩니다"),
    overhead_minutes: float = typer.Option(0.0, "--overhead-minutes", help="선별·예외 처리·유지보수에 든 추가 시간(분)"),
    outcome: str = typer.Option("", "--outcome", help="결과 메모(accepted·changes·rejected 등)"),
    risk_accepted: bool = typer.Option(False, "--risk-accepted", help="나중에 위험한 변경을 받아들였다고 확인된 경우"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    배정된 PR의 검토 결과(시간·추가 시간·위험 수용 여부)를 기록합니다.
    """
    from iron_laws.core.pilot import record_review

    _pilot_call(record_review, _pilot_store(store), pr, minutes, setup_minutes, overhead_minutes, outcome, risk_accepted)
    err.print(f"[green]검토 결과 기록: {escape(pr)}[/green]")


@pilot_app.command("flag")
def pilot_flag_command(
    pr: str = typer.Argument(..., help="PR 이름표"),
    kind: str = typer.Option(..., "--kind", help="misaccept(오통과), dangerous_inheritance(위험한 승인 승계), legitimate_exception(정당한 예외 승인)"),
    note: str = typer.Option("", "--note", help="짧은 메모(코드 원문 금지)"),
    status: str = typer.Option("confirmed", "--status", help="confirmed(확인됨) 또는 investigating(조사 중, 조사가 끝나기 전에는 성과에 포함하지 않음)"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    오통과·위험한 승계를 기록합니다. bundle 조건에서 확인된 사건이 한 건이라도 기록되면 요약이 관련 자동 경로를 수동 검토로 돌리라고 표시합니다.
    """
    from iron_laws.core.pilot import flag_risk

    _pilot_call(flag_risk, _pilot_store(store), pr, kind, note, status)
    err.print(f"[yellow]위험 기록: {escape(pr)} ({escape(kind)}, {escape(status)})[/yellow]")


@pilot_app.command("close")
def pilot_close_command(
    pr: str = typer.Argument(..., help="PR 이름표"),
    kind: str = typer.Option(..., "--kind", help="조사 중이던 사건의 종류(misaccept 또는 dangerous_inheritance)"),
    confirmed: bool = typer.Option(..., "--confirmed/--dismissed", help="조사 결과: 확인됨(오승인 확정) 또는 기각(정당한 예외로 분류)"),
    note: str = typer.Option("", "--note", help="짧은 메모(코드 원문 금지)"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    조사 중이던 사건을 닫습니다. 기록은 지우지 않고 결과를 덧붙입니다.
    """
    from iron_laws.core.pilot import close_risk

    _pilot_call(close_risk, _pilot_store(store), pr, kind, confirmed, note)
    err.print(f"[yellow]조사 종료: {escape(pr)} ({'확인' if confirmed else '기각'})[/yellow]")


@pilot_app.command("dropout")
def pilot_dropout_command(
    team: str = typer.Argument(..., help="팀 이름표"),
    reason: str = typer.Option(..., "--reason", help="중도 포기 사유"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    팀의 중도 포기를 기록합니다(결과에서 지우지 않고 분모와 함께 보고합니다).
    """
    from iron_laws.core.pilot import record_dropout

    _pilot_call(record_dropout, _pilot_store(store), team, reason)


@pilot_app.command("summary")
def pilot_summary_command(
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
    json_output: bool = typer.Option(False, "--json", help="JSON으로 출력"),
):
    """
    조건별 검토 시간(중앙값·75백분위)·위험 수용·표본 충족 여부를 요약합니다. 표본이 부족하면 판정하지 않습니다.
    종료코드: 0 목표 충족 또는 표본 부족, 1 목표 미달.
    """
    from iron_laws.core.pilot import summarize

    result = _pilot_call(summarize, _pilot_store(store))
    if json_output:
        sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    else:
        table = Table(title="[파일럿 요약]")
        for column in ("조건", "검토 건수", "총 능동시간 중앙값(분)", "총 능동시간 75백분위(분)", "검토 시간 중앙값(분, 보조)", "확인된 오승인", "조사 중"):
            table.add_column(column)
        for arm, data in result["arms"].items():
            mis = data["confirmed_misaccepts"]
            table.add_row(arm, str(data["total_minutes"]["n"]), str(data["total_minutes"]["median"]), str(data["total_minutes"]["p75"]), str(data["review_minutes"]["median"]), f"{mis['count']}/{mis['of']}", str(data["investigating"]))
        console.print(table)
        console.print(f"판정: {result['verdict']} · 자동 경로: {result['automation']} · 중도 포기 {result['dropouts']}")
        for reason in result["sample"]["reasons"]:
            console.print(f"[yellow]표본 부족: {escape(reason)}[/yellow]")
        for note in result["notes"]:
            console.print(f"[dim]{escape(note)}[/dim]")
    raise typer.Exit(1 if result["verdict"] == "targets_not_met" else 0)
