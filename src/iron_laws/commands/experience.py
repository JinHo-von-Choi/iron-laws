"""교훈 저장소 명령군."""

import json
from pathlib import Path

import typer
from rich.markup import escape

from iron_laws.commands.common import err, experience_app
from iron_laws.core.config import ConfigError


@experience_app.command("add")
def experience_add_command(
    spec: Path | None = typer.Option(None, "--spec", help="채택한 명세 파일. 명세의 각 항목을 교훈으로 남깁니다"),
    rule: str | None = typer.Option(None, "--rule", help="규칙 ID (예: IL-504). 이 규칙에 붙은 교훈으로 남깁니다"),
    lesson: str = typer.Option(..., "--lesson", help="이 명세나 규칙을 무엇을 위해 넣었는지. 사람이 읽을 한 문장"),
    file: Path = typer.Option(Path(".iron-laws-experience.jsonl"), "--file", help="교훈 기록 파일"),
):
    """
    채택한 명세나 규칙에 대한 교훈을 남깁니다. 무엇을 왜 넣었는지와 근거를 함께 남겨 다음 명세와 검토에 씁니다.
    """
    from iron_laws.core.experience import ExperienceStore, rule_note, spec_fragment_entries
    from iron_laws.rules.catalog import get_active_rules

    if (spec is None) == (rule is None):
        err.print("[bold red]--spec과 --rule 중 하나만 주십시오.[/bold red]")
        raise typer.Exit(2)
    versions = {r.rule_id: r.version for r in get_active_rules()}
    try:
        store = ExperienceStore(file)
        if spec is not None:
            entries = spec_fragment_entries(spec, lesson, versions)
        else:
            entries = [rule_note(rule.upper(), lesson, versions)]
        for entry in entries:
            store.add(entry)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    err.print(f"[bold green]교훈 {len(entries)}건을 기록했습니다: {file}[/bold green]")


@experience_app.command("list")
def experience_list_command(
    rule: str | None = typer.Option(None, "--rule", help="규칙 ID로 거른다"),
    family: str | None = typer.Option(None, "--family", help="계열로 거른다 (command·path·sql·code)"),
    state: str | None = typer.Option(None, "--state", help="상태로 거른다 (active·stale·invalid·superseded)"),
    file: Path = typer.Option(Path(".iron-laws-experience.jsonl"), "--file", help="교훈 기록 파일"),
    as_json: bool = typer.Option(False, "--json", help="JSON으로 내보냅니다"),
):
    """
    남겨 둔 교훈을 보여 줍니다. 규칙 버전이나 명세 내용이 바뀌어 다시 볼 것이 된 교훈은 'stale'로 표시합니다.
    """
    from iron_laws.core.experience import ExperienceStore
    from iron_laws.rules.catalog import get_active_rules

    versions = {r.rule_id: r.version for r in get_active_rules()}
    try:
        store = ExperienceStore(file)
        items = store.entries(rule_versions=versions)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    if rule:
        items = [i for i in items if i.entry.rule_id == rule.upper()]
    if family:
        items = [i for i in items if i.entry.family == family]
    if state:
        items = [i for i in items if i.state == state]
    if as_json:
        print(json.dumps([{"id": i.entry.id, "state": i.state, "reason": i.reason, **i.entry.model_dump(mode="json")} for i in items], ensure_ascii=False, indent=2))
        return
    if not items:
        err.print("남은 교훈이 없습니다")
        return
    for item in items:
        label = {"active": "사용 중", "stale": "다시 볼 것", "invalid": "무효", "superseded": "대체됨"}[item.state]
        where = f" [{item.entry.rule_id}]" if item.entry.rule_id else ""
        err.print(f"[{item.entry.id}]{where} ({label}) {item.entry.lesson}")
        if item.reason and item.state != "active":
            err.print(f"    {escape(item.reason)}")


@experience_app.command("invalidate")
def experience_invalidate_command(
    entry_id: str = typer.Argument(..., help="무효로 만들 교훈 ID"),
    reason: str = typer.Option(..., "--reason", help="무효로 만드는 사유"),
    file: Path = typer.Option(Path(".iron-laws-experience.jsonl"), "--file", help="교훈 기록 파일"),
):
    """
    교훈을 무효로 만듭니다. 기록은 지우지 않고 사유만 덧붙입니다.
    """
    from iron_laws.core.experience import ExperienceStore

    try:
        store = ExperienceStore(file)
        known = {i.entry.id for i in store.entries()}
        if entry_id not in known:
            err.print(f"[bold red]교훈을 찾을 수 없습니다: {escape(entry_id)}[/bold red]")
            raise typer.Exit(2)
        store.invalidate(entry_id, reason)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    err.print(f"[bold green]{escape(entry_id)}를 무효로 만들었습니다[/bold green]")


@experience_app.command("verify")
def experience_verify_command(
    file: Path = typer.Option(Path(".iron-laws-experience.jsonl"), "--file", help="교훈 기록 파일"),
):
    """
    교훈 기록의 해시 연결이 끊겼는지 확인합니다.
    """
    from iron_laws.core.experience import ExperienceStore

    try:
        store = ExperienceStore(file)
        problems = store.verify_chain()
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    if problems:
        for problem in problems[:10]:
            err.print(f"[bold red]{escape(problem)}[/bold red]")
        raise typer.Exit(1)
    err.print(f"[bold green]기록 {len(store.records)}줄의 연결이 온전합니다[/bold green]")
