"""
오철칙 시작 명령: 설정 파일 만들기(init)와 프로젝트 단계 미리보기(stage preview).
작성자: 최진호
작성일: 2026-11-28
"""

import sys
from pathlib import Path

import typer
import yaml
from rich.table import Table

from iron_laws.commands.common import app, console, err
from iron_laws.core.config import CONFIG_NAMES, IronLawsConfig
from iron_laws.core.gating import STAGE_QUESTIONS, STAGES, blocks, stage_policy

stage_app = typer.Typer(help="프로젝트 단계(prototype·launch·production): 단계에 따라 통과를 막는 지적이 달라집니다")
app.add_typer(stage_app, name="stage")
StageOpt = typer.Option(None, "--stage", help="프로젝트 단계: prototype(내 PC에서만), launch(링크 공유·시험 배포), production(실제 사용자·결제)")


def _ask_stage() -> str | None:
    """터미널에 연결됐을 때만 단계를 묻는다. 빈 답이면 단계 없이 만든다"""
    if not sys.stdin.isatty():
        return None
    console.print("프로젝트가 지금 어느 단계입니까? (비우면 단계 없이 fail_on만으로 판정합니다)")
    for i, stage in enumerate(STAGES, start=1):
        console.print(f"  {i}. {stage}: {STAGE_QUESTIONS[stage]}")
    answer = typer.prompt("번호", default="", show_default=False).strip()
    return STAGES[int(answer) - 1] if answer.isdigit() and 1 <= int(answer) <= len(STAGES) else None


@app.command("init")
def init_command(
    target_dir: Path = typer.Argument(Path("."), help="설정 파일을 생성할 디렉터리"),
    stage: str | None = StageOpt,
):
    """
    현재 디렉터리에 .iron-laws.yml 기본 설정 파일을 생성합니다. 이미 설정 파일(.iron-laws.yml·.iron-laws.yaml)이 있으면 덮어쓰지 않습니다.
    """
    existing = next((target_dir / name for name in CONFIG_NAMES if (target_dir / name).exists()), None)
    if existing is not None:
        err.print(f"[bold yellow]이미 설정 파일이 존재합니다: {existing}[/bold yellow]")
        return
    if stage is not None and stage not in STAGES:
        err.print(f"[bold red]--stage는 {', '.join(STAGES)} 가운데 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    stage = stage or _ask_stage()
    config = IronLawsConfig(stage=stage)
    body = yaml.safe_dump(config.report_dump(), allow_unicode=True, sort_keys=False)
    config_path = target_dir / CONFIG_NAMES[0]
    config_path.write_text(f"# 오철칙 (Iron Laws) 프로젝트 설정 파일\n{body}", encoding="utf-8")
    err.print(f"[bold green]기본 설정 파일이 생성되었습니다: {config_path}[/bold green]")
    if stage is not None:
        err.print(f"단계: {stage} ({STAGE_QUESTIONS[stage]}). 단계를 올리기 전에 `iron-laws stage preview <단계>`로 새로 막히는 지적을 확인하십시오.")


@stage_app.command("preview")
def stage_preview_command(
    target: str = typer.Argument(..., help="미리 볼 단계(prototype, launch, production)"),
    path: Path = typer.Argument(Path("."), help="점검할 프로젝트 디렉터리"),
):
    """
    설정의 단계를 TARGET으로 바꾸면 새로 막히는 지적과 더는 막지 않는 지적을 보여 줍니다. 설정 파일은 바꾸지 않습니다. 종료코드: 0 미리봄, 2 입력 오류.
    """
    from iron_laws.core.config import ConfigError
    from iron_laws.core.scanner import AuditScanner

    if target not in STAGES:
        err.print(f"[bold red]단계는 {', '.join(STAGES)} 가운데 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    try:
        scanner = AuditScanner(path)
    except ConfigError as e:
        err.print(f"[bold red]설정 오류: {e}[/bold red]")
        raise typer.Exit(2) from e
    report = scanner.scan()
    fail_on = scanner.config.fail_on.value
    now, then = stage_policy(scanner.config.stage, fail_on), stage_policy(target, fail_on)

    def blocked(v, policy) -> bool:
        return blocks(v.rule_id, v.severity.value, v.confidence.value, v.layer.value, policy, fail_on)

    gained = [v for v in report.violations if blocked(v, then) and not blocked(v, now)]
    lost = [v for v in report.violations if blocked(v, now) and not blocked(v, then)]
    current = scanner.config.stage or "(없음: fail_on만으로 판정)"
    console.print(f"지금 단계: {current} → 미리 볼 단계: {target} ({STAGE_QUESTIONS[target]})")
    console.print(f"새로 막히는 지적 {len(gained)}건, 더는 막지 않는 지적 {len(lost)}건")
    for title, rows in (("새로 막히는 지적", gained), ("더는 막지 않는 지적", lost)):
        if not rows:
            continue
        table = Table(title=title)
        for col in ("규칙", "심각도", "확정 여부", "위치", "내용"):
            table.add_column(col)
        for v in rows[:50]:
            table.add_row(v.rule_id, v.severity.value, v.confidence.value, f"{v.file_path.as_posix()}:{v.line_number}", v.message[:80])
        console.print(table)
