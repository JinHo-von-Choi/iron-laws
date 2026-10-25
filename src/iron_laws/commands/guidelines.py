"""지침 강제 대응표 명령군."""

import json
from pathlib import Path

import typer
from rich.markup import escape

from iron_laws.commands.common import err, guidelines_app
from iron_laws.core.guidelines import check_guidelines, export_guidelines, render_check
from iron_laws.core.models import Severity
from iron_laws.core.support_matrix import LANG_ORDER
from iron_laws.rules.catalog import ALL_RULES

LANGUAGE_NAMES = {lang.value for lang in LANG_ORDER}


def _options(fail_on: str, lang: str | None) -> tuple[Severity, set[str] | None]:
    try:
        threshold = Severity(fail_on.upper())
    except ValueError as e:
        err.print("[bold red]--fail-on은 CRITICAL, HIGH, MEDIUM, LOW 중 하나여야 합니다.[/bold red]")
        raise typer.Exit(2) from e
    languages = {name.strip().lower() for name in lang.split(",") if name.strip()} if lang else None
    unknown = sorted((languages or set()) - LANGUAGE_NAMES)
    if unknown:
        err.print(f"[bold red]알 수 없는 언어: {escape(', '.join(unknown))} (사용 가능: {', '.join(sorted(LANGUAGE_NAMES))})[/bold red]")
        raise typer.Exit(2)
    return threshold, languages


def _write(text: str, output: Path | None) -> None:
    if output is None:
        typer.echo(text, nl=False)
        return
    output.write_text(text, encoding="utf-8")
    err.print(f"[green]저장: {escape(str(output))}[/green]")


FailOnOpt = typer.Option("HIGH", "--fail-on", help="차단으로 볼 심각도 기준. hook·check에 쓰는 값과 같게 주십시오")
LangOpt = typer.Option(None, "--lang", help="쉼표로 구분한 언어(python,typescript,java …). 그 언어에 적용되는 규칙만 다룹니다")
OutputOpt = typer.Option(None, "--output", "-o", help="저장 파일")


@guidelines_app.command("export")
def guidelines_export_command(
    fail_on: str = FailOnOpt,
    lang: str | None = LangOpt,
    min_severity: str = typer.Option("LOW", "--min-severity", help="이 심각도 이상 규칙만 내보냅니다"),
    output: Path | None = OutputOpt,
):
    """
    규칙을 코딩 에이전트 지침(CLAUDE.md·AGENTS.md에 붙여 넣을 마크다운)으로 내보냅니다.
    줄마다 그 지침을 무엇이 확인하는지(차단·실행 검증·보고)와 시험으로 검증된 언어를 붙입니다.
    """
    threshold, languages = _options(fail_on, lang)
    floor, _ = _options(min_severity, None)
    _write(export_guidelines([cls() for cls in ALL_RULES], threshold, languages, floor), output)


@guidelines_app.command("check")
def guidelines_check_command(
    path: Path = typer.Argument(..., help="지침 파일(CLAUDE.md, AGENTS.md, .cursorrules 등)"),
    fail_on: str = FailOnOpt,
    lang: str | None = LangOpt,
    fmt: str = typer.Option("console", "--format", help="console 또는 json"),
    fail_on_unenforced: bool = typer.Option(False, "--fail-on-unenforced", help="강제 수단이 없는 지시 문장이 있으면 종료코드 1"),
    output: Path | None = OutputOpt,
):
    """
    지침 파일의 지시 문장마다 대응하는 오철칙 규칙과 강제 수단을 보여 줍니다.
    대응 규칙이 없는 문장은 모델이 읽고 따르기만 하는 문장입니다. 종료코드: 0 확인함, 1 --fail-on-unenforced에서 강제 수단 없는 문장 있음, 2 입력 오류.
    """
    if fmt not in ("console", "json"):
        err.print("[bold red]--format은 console 또는 json이어야 합니다.[/bold red]")
        raise typer.Exit(2)
    threshold, languages = _options(fail_on, lang)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        err.print(f"[bold red]지침 파일을 읽지 못했습니다: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    result = check_guidelines(text, [cls() for cls in ALL_RULES], threshold, languages)
    _write(json.dumps(result, ensure_ascii=False, indent=2) + "\n" if fmt == "json" else render_check(result), output)
    if fail_on_unenforced and result["counts"]["none"]:
        raise typer.Exit(1)
