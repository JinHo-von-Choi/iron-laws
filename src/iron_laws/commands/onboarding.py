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


def _first_move(root: Path, key: str) -> None:
    """이미 코드가 있으면 틀의 구조 계약으로 점검해, 계약에 어긋나는 import 수와 지금 옮길 것 하나를 보여 준다"""
    from iron_laws.blueprints import BLUEPRINTS
    from iron_laws.core.scanner import AuditScanner

    config = IronLawsConfig(architecture=BLUEPRINTS[key].contract(), enabled_rules=["ARC-207"])
    report = AuditScanner(root, config=config).scan()
    found = sorted((v for v in report.violations if v.rule_id == "ARC-207"), key=lambda v: (v.file_path.as_posix(), v.line_number))
    if report.summary.total_files_scanned == 0:
        return
    if not found:
        console.print("지금 코드는 이 틀의 구조 계약에 어긋나는 import가 없습니다.")
        return
    first = found[0]
    console.print(f"지금 코드에 틀의 구조 계약과 어긋나는 import가 {len(found)}곳 있습니다. 한꺼번에 옮기지 말고 하나씩 고치십시오.")
    console.print(f"먼저 고칠 것: {first.file_path.as_posix()}:{first.line_number} — {first.message}")
    console.print(f"고친 뒤 확인: iron-laws check {root} (이 위치의 ARC-207 지적이 사라져야 합니다)")


def _stack(root: Path, stack: str, stage: str | None, write: bool) -> None:
    from iron_laws.blueprints import BLUEPRINTS, apply, contract_yaml, detect

    key = detect(root) if stack == "auto" else stack
    if key is None:
        err.print("[bold red]스택을 알아내지 못했습니다. --stack nextjs 또는 --stack fastapi로 정하십시오.[/bold red]")
        raise typer.Exit(2)
    if key not in BLUEPRINTS:
        err.print(f"[bold red]--stack은 {', '.join(BLUEPRINTS)}, auto 가운데 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    bp = BLUEPRINTS[key]
    if write:
        for line in apply(root, bp, stage):
            console.print(line)
    else:
        console.print(f"# 구조 틀 미리보기: {bp.title} (파일을 만들려면 --write)\n")
        console.print("## .iron-laws.yml에 들어갈 구조 계약\n")
        console.print(contract_yaml(bp), markup=False)
        console.print("## AGENTS.md·CLAUDE.md에 들어갈 절\n")
        console.print(bp.guideline_section(), markup=False)
        missing = [f for f in bp.folders if not (root / f).exists()]
        console.print("## 만들 폴더: " + (", ".join(missing) if missing else "없음(모두 있음)"))
    _first_move(root, key)


HOOK_GUIDE = (
    "Claude Code: `claude plugin marketplace add JinHo-von-Choi/iron-laws` 다음 `/plugin install iron-laws --marketplace JinHo-von-Choi/iron-laws`",
    "Codex CLI·Cursor: https://github.com/JinHo-von-Choi/iron-laws/blob/main/docs/AGENT_INTEGRATION.md 의 훅 설정 파일을 프로젝트에 넣기",
)


def _vibe(root: Path, stage: str | None) -> None:
    """처음 쓰는 사람을 위한 한 번에 시작: 설정 만들기 → 구조 틀 미리보기 → 에이전트 훅 연결 안내 → 첫 점검과 먼저 고칠 것 3개"""
    from iron_laws.blueprints import BLUEPRINTS, detect
    from iron_laws.core.scanner import AuditScanner
    from iron_laws.reporters.console import first_steps

    existing = next((root / name for name in CONFIG_NAMES if (root / name).exists()), None)
    console.print("1. 설정")
    if existing is None:
        stage = stage or _ask_stage()
        (root / CONFIG_NAMES[0]).write_text("# 오철칙 (Iron Laws) 프로젝트 설정 파일\n" + yaml.safe_dump(IronLawsConfig(stage=stage).report_dump(), allow_unicode=True, sort_keys=False), encoding="utf-8")
        console.print(f"   {CONFIG_NAMES[0]}를 만들었습니다." + (f" 단계: {stage}({STAGE_QUESTIONS[stage]})" if stage else " 단계는 정하지 않았습니다(--stage로 정할 수 있습니다)."))
    else:
        console.print(f"   이미 있는 {existing.name}를 그대로 씁니다.")
    key = detect(root)
    console.print("2. 구조 틀")
    if key is None:
        console.print("   스택을 알아내지 못했습니다. Next.js나 FastAPI면 `iron-laws init --stack nextjs`(또는 fastapi)로 틀을 미리 볼 수 있습니다.")
    else:
        console.print(f"   {BLUEPRINTS[key].title} 프로젝트로 보입니다. `iron-laws init --stack {key}`로 틀을 미리 보고, `--write`로 만드십시오.")
    console.print("3. 코딩 에이전트 연결(편집할 때마다 자동 점검)")
    for line in HOOK_GUIDE:
        console.print(f"   - {line}", markup=False)
    console.print("4. 첫 점검")
    report = AuditScanner(root).scan()
    picks = first_steps(report) or sorted(report.violations, key=lambda v: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(v.severity.value), v.confidence.value != "CONFIRMED"))[:3]
    if not picks:
        console.print("   지적이 없습니다." + ("" if report.summary.scan_status == "complete" else " 점검을 끝까지 하지 못했으니 `iron-laws check`로 이유를 보십시오."))
        return
    console.print(f"   지적 {report.summary.total_violations}건 가운데 먼저 고칠 것:")
    for i, v in enumerate(picks, start=1):
        console.print(f"   {i}. [{v.severity.value}] {v.rule_id} {v.file_path.as_posix()}:{v.line_number} {v.plain or v.message}", markup=False)
    console.print(f"   다음: `iron-laws fix-prompt {root} --limit 3`으로 AI에게 붙여 넣을 수정 지시문을 만들고, 고친 뒤 `iron-laws check {root}`로 확인하십시오.", markup=False)


@app.command("init")
def init_command(
    target_dir: Path = typer.Argument(Path("."), help="설정 파일을 생성할 디렉터리"),
    stage: str | None = StageOpt,
    stack: str | None = typer.Option(None, "--stack", help="구조 틀: nextjs, fastapi, auto(코드에서 알아냄). 기본은 미리보기이고 --write를 주면 파일을 만듭니다"),
    write: bool = typer.Option(False, "--write", help="--stack의 구조 계약·지침 절·폴더를 실제로 만듭니다. 기존 파일은 덮어쓰지 않고 지침 파일에는 표시한 절만 넣습니다"),
    vibe: bool = typer.Option(False, "--vibe", help="처음 쓰는 사람용: 설정 만들기, 구조 틀 안내, 에이전트 연결 안내, 첫 점검과 먼저 고칠 것 3개를 차례로 보여 줍니다"),
):
    """
    현재 디렉터리에 .iron-laws.yml 기본 설정 파일을 생성합니다. 이미 설정 파일(.iron-laws.yml·.iron-laws.yaml)이 있으면 덮어쓰지 않습니다.
    --stack을 주면 그 스택의 구조 틀(구조 계약, 에이전트 지침 절, 폴더)을 보여 주거나(--write면) 만듭니다.
    """
    if stage is not None and stage not in STAGES:
        err.print(f"[bold red]--stage는 {', '.join(STAGES)} 가운데 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    if vibe:
        _vibe(target_dir, stage)
        return
    if stack is not None:
        _stack(target_dir, stack, stage, write)
        return
    existing = next((target_dir / name for name in CONFIG_NAMES if (target_dir / name).exists()), None)
    if existing is not None:
        err.print(f"[bold yellow]이미 설정 파일이 존재합니다: {existing}[/bold yellow]")
        return
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
        return blocks(v.rule_id, v.severity.value, v.confidence.value, v.layer.value, policy, fail_on, v.tags)

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
