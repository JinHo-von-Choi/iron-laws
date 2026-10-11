"""inspect 명령군."""

import json
from pathlib import Path

import typer
from rich.markup import escape

from iron_laws.commands.common import (
    ConfigOpt,
    PathArg,
    _write_or_print,
    app,
    err,
)
from iron_laws.core.config import ConfigError, load_config


@app.command("architecture")
def architecture_command(
    path: Path = PathArg,
    config: Path | None = ConfigOpt,
    fmt: str = typer.Option("markdown", "--format", help="markdown, json, prompt(먼저 풀 문제 한 단계를 코딩 AI 지시문으로)"),
    compare: Path | None = typer.Option(None, "--compare", help="이전 진단(JSON) 파일. 지표가 나아졌는지 비교합니다"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
):
    """
    프로젝트 전체의 구조 상태(양호·주의·붕괴)와 먼저 풀 문제, 단계별 개선안을 보여 줍니다. 종료코드: 0 진단함, 2 입력 오류.
    지표는 구조의 한 단면이며 설계의 좋고 나쁨을 보증하지 않습니다.
    """
    from iron_laws.architecture import diagnose
    from iron_laws.architecture.metrics import collect

    if fmt not in ("markdown", "json", "prompt"):
        err.print("[bold red]--format은 markdown·json·prompt 중 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    try:
        loaded = load_config(path, config)[0] if config is not None else None
        data = diagnose.evaluate(collect(path, loaded))
        previous = json.loads(compare.read_text(encoding="utf-8")) if compare is not None else None
    except (ConfigError, OSError, ValueError) as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    text = {"markdown": diagnose.markdown, "json": lambda d: json.dumps(d, ensure_ascii=False, indent=2), "prompt": diagnose.prompt}[fmt](data)
    if previous is not None:
        text += "\n\n## 이전 진단과 비교\n\n" + "\n".join(diagnose.compare(previous, data)) if fmt == "markdown" else ""
    _write_or_print(text, output, "구조 진단")


@app.command("deps")
def deps_command(
    path: Path = PathArg,
    advisory_db: Path = typer.Option(..., "--advisory-db", help="OSV 권고 목록 폴더 또는 zip(에코시스템별 `all.zip`을 받아 둔 폴더). 네트워크를 쓰지 않습니다"),
    fmt: str = typer.Option("markdown", "--format", help="markdown, json, prompt"),
    fail_on: str = typer.Option("any", "--fail-on", help="any(권고가 하나라도 있으면 실패), high, critical, never"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
):
    """
    락 파일에 고정된 패키지 버전이 알려진 취약점 권고(OSV)와 겹치는지 점검하고, 알려진 수정 경계(어느 버전 이상으로 올릴지)를 알려 줍니다.
    코드나 의존성 정보를 외부로 보내지 않습니다. 종료코드: 0 권고 없음(또는 기준 미만), 1 권고 발견, 2 입력 오류.
    """
    from iron_laws.deps import report as dep_report
    from iron_laws.deps.advise import analyze
    from iron_laws.deps.lockfiles import find_lock_files, parse_lock
    from iron_laws.deps.osv import load_db

    if fmt not in ("markdown", "json", "prompt") or fail_on not in ("any", "high", "critical", "never"):
        err.print("[bold red]--format은 markdown·json·prompt, --fail-on은 any·high·critical·never 중 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)
    if not path.exists():
        err.print(f"[bold red]입력 오류: 경로가 없습니다: {escape(str(path))}[/bold red]")
        raise typer.Exit(2)
    try:
        db = load_db(advisory_db)
    except (OSError, ValueError) as e:
        err.print(f"[bold red]권고 목록을 읽지 못했습니다: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    if db.count == 0:
        err.print("[bold red]권고 목록이 비어 있습니다. OSV에서 받은 `all.zip`이 든 폴더를 지정하세요(비어 있는 목록을 '취약점 없음'으로 보지 않습니다).[/bold red]")
        raise typer.Exit(2)
    locks, results = [], []
    for file in find_lock_files(path):
        try:
            lock = parse_lock(file)
        except (OSError, ValueError, KeyError) as e:
            err.print(f"[bold red]락 파일을 읽지 못했습니다({escape(file.as_posix())}): {escape(str(e))}[/bold red]")
            raise typer.Exit(2) from e
        locks.append(lock)
        results.append(analyze(lock, db))
    data = dep_report.build(locks, results, db)
    text = {"markdown": dep_report.markdown, "json": dep_report.to_json, "prompt": dep_report.prompt}[fmt](data)
    _write_or_print(text, output, "의존성 점검 결과")
    raise typer.Exit(1 if dep_report.exceeds(data, fail_on) else 0)
