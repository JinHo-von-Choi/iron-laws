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
    experience_lessons,
    index_app,
    spec_app,
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
    fmt: str = typer.Option("markdown", "--format", help="markdown, json, prompt, openvex"),
    fail_on: str = typer.Option("any", "--fail-on", help="any(권고가 하나라도 있으면 실패), high, critical, never"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
    reachability: bool = typer.Option(False, "--reachability", help="권고에 영향 함수 정보가 있으면 코드가 그 함수를 부르는지 봅니다(reachable / no_evidence / undetermined)"),
    vex_decisions: Path | None = typer.Option(None, "--vex-decisions", help="사람이 남긴 VEX 판정 기록(JSON). not_affected는 이 기록에 justification이 있을 때만 씁니다"),
    timestamp: str | None = typer.Option(None, "--timestamp", help="openvex 문서 시각(ISO 8601). 생략하면 현재 시각"),
):
    """
    락 파일에 고정된 패키지 버전이 알려진 취약점 권고(OSV)와 겹치는지 점검하고, 알려진 수정 경계(어느 버전 이상으로 올릴지)를 알려 줍니다.
    코드나 의존성 정보를 외부로 보내지 않습니다. 종료코드: 0 권고 없음(또는 기준 미만), 1 권고 발견, 2 입력 오류.
    """
    from iron_laws.deps import report as dep_report
    from iron_laws.deps.advise import analyze
    from iron_laws.deps.lockfiles import find_lock_files, parse_lock
    from iron_laws.deps.osv import load_db

    if fmt not in ("markdown", "json", "prompt", "openvex") or fail_on not in ("any", "high", "critical", "never"):
        err.print("[bold red]--format은 markdown·json·prompt·openvex, --fail-on은 any·high·critical·never 중 하나여야 합니다.[/bold red]")
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
    if reachability or fmt == "openvex":
        from iron_laws.core.scanner import AuditScanner

        dep_report.attach_reachability(data, AuditScanner(path)._read_sources())
    if fmt == "openvex":
        from datetime import UTC, datetime

        from iron_laws.core.scanner import tool_version
        from iron_laws.deps.vex import VexDecisionError, load_decisions, openvex

        try:
            decisions = load_decisions(vex_decisions) if vex_decisions else []
        except VexDecisionError as e:
            err.print(f"[bold red]{escape(str(e))}[/bold red]")
            raise typer.Exit(2) from e
        when = timestamp or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        _write_or_print(json.dumps(openvex(data, decisions, tool_version(), when), ensure_ascii=False, indent=2), output, "OpenVEX 문서")
        raise typer.Exit(1 if dep_report.exceeds(data, fail_on) else 0)
    text = {"markdown": dep_report.markdown, "json": dep_report.to_json, "prompt": dep_report.prompt}[fmt](data)
    _write_or_print(text, output, "의존성 점검 결과")
    raise typer.Exit(1 if dep_report.exceeds(data, fail_on) else 0)


@index_app.command("build")
def index_build_command(
    ecosystem: str = typer.Option(..., "--ecosystem", help="npm 또는 pypi"),
    source: Path = typer.Option(..., "--source", help="받아 둔 원본 목록: JSON 배열(이름 또는 {name, created}) 또는 줄마다 `이름[ 날짜]`"),
    out: Path = typer.Option(..., "--out", help="색인 폴더(manifest.json과 압축 목록을 쓴다)"),
    source_name: str = typer.Option(..., "--source-name", help="원본 출처 설명(예: 레지스트리 전체 이름 목록 덤프 URL)"),
    collected_at: str = typer.Option(..., "--collected-at", help="원본을 수집한 시각(ISO 8601). 최근 게시 판정의 기준 시각이다"),
    complete: bool = typer.Option(False, "--complete", help="레지스트리의 모든 이름이 들어 있는 목록이면 지정한다. 지정하지 않으면 '없는 이름' 판정을 하지 않는다"),
):
    """
    사용자가 받아 둔 레지스트리 이름 목록을 의존성 이름 점검용 오프라인 색인으로 바꿉니다. 네트워크를 쓰지 않습니다.
    """
    from iron_laws.deps.package_index import PackageIndexError, build_index

    try:
        meta = build_index(ecosystem, source, out, source_name, collected_at, complete)
    except (OSError, ValueError, PackageIndexError) as e:
        err.print(f"[bold red]색인을 만들지 못했습니다: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    typer.echo(f"{ecosystem} 색인: 이름 {meta['count']}개, 완전한 목록 {'예' if meta['complete'] else '아니오'}, sha256 {meta['sha256'][:16]}")


@app.command("mcp")
def mcp_command(
    root: Path = typer.Option(..., "--root", help="도구 입력 경로를 허용할 기준 폴더. 이 밖을 가리키는 경로(심볼릭 링크 포함)는 거부합니다"),
    server_config: Path | None = typer.Option(None, "--server-config", help="서버 설정 파일(test_presets). 기준 폴더 밖에 두어야 합니다"),
):
    """
    코딩 에이전트용 MCP 서버(stdio)를 띄웁니다: check, explain, fix_prompt, verify_patch, deps.
    시험 명령은 서버 설정의 test_presets 이름으로만 받습니다. 선택 의존성이 필요합니다: pip install 'iron-laws[mcp]'
    """
    from iron_laws.mcp_server import load_settings, serve

    try:
        settings = load_settings(root, server_config)
        serve(settings)
    except ConfigError as e:
        err.print(f"[bold red]설정 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e


@app.command("routes")
def routes_command(
    path: Path = PathArg,
    fmt: str = typer.Option("table", "--format", help="table 또는 json"),
    sensitive_only: bool = typer.Option(False, "--sensitive", help="중요 기능 라우트(데이터 변경·관리·개인정보·결제)만 보입니다"),
    config: Path | None = ConfigOpt,
):
    """
    웹 라우트의 접근통제 행렬을 보여 줍니다: 프레임워크, 메서드, 경로, 인증(yes/no/unknown), 인가(yes/no/unknown/n/a)와 근거.
    unknown은 안전하다는 뜻이 아니라 전역 설정이 이 경로에 적용되는지 정할 수 없다는 뜻입니다.
    """
    from rich.table import Table

    from iron_laws.core.scanner import AuditScanner
    from iron_laws.engine.routes import discover_routes

    if fmt not in ("table", "json"):
        err.print("[bold red]--format은 table 또는 json이어야 합니다.[/bold red]")
        raise typer.Exit(2)
    try:
        scanner = AuditScanner(path, config_path=config) if config else AuditScanner(path)
    except ConfigError as e:
        err.print(f"[bold red]설정 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    rows = [r.as_row() for r in discover_routes(scanner._read_sources()) if r.sensitive or not sensitive_only]
    if fmt == "json":
        typer.echo(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    table = Table(title="[라우트 접근통제 행렬]", expand=True)
    for column in ("메서드", "경로", "위치", "중요", "인증", "인가", "근거"):
        table.add_column(column)
    style = {"yes": "green", "no": "red", "unknown": "yellow", "n/a": "dim"}
    for r in rows:
        table.add_row(r["method"], escape(r["path"]), f"{escape(r['file'])}:{r['line']}", "예" if r["sensitive"] else "",
                      f"[{style[r['auth']]}]{r['auth']}[/{style[r['auth']]}]", f"[{style[r['authz']]}]{r['authz']}[/{style[r['authz']]}]",
                      escape(r["auth_reason"] + " / " + r["authz_reason"]))
    from iron_laws.commands.common import console

    console.print(table)


@app.command("hook")
def hook_command(
    agent: str = typer.Argument(..., help="claude-code"),
    fail_on: str = typer.Option("HIGH", "--fail-on", help="이 심각도 이상 지적이 있으면 에이전트에게 되돌립니다(CRITICAL, HIGH, MEDIUM, LOW)"),
    limit: int = typer.Option(10, "--limit", min=1, help="되돌릴 최대 지적 수"),
):
    """
    코딩 에이전트 훅: 표준 입력으로 받은 편집 정보(Claude Code PostToolUse JSON)에서 바뀐 파일을 점검합니다.
    기준 이상 지적이 있으면 표준 오류로 지적을 쓰고 종료코드 2로 끝나 에이전트가 고치게 합니다. 점검 대상이 아니면 0입니다.
    """
    import sys

    from iron_laws.core.models import Severity
    from iron_laws.core.scanner import AuditScanner

    if agent != "claude-code":
        err.print("[bold red]지원하는 에이전트: claude-code[/bold red]")
        raise typer.Exit(2)
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        threshold = Severity(fail_on.upper())
    except ValueError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    tool_input = payload.get("tool_input") or {}
    raw = tool_input.get("file_path") or tool_input.get("path") or ""
    base = Path(payload.get("cwd") or ".")
    target = (base / raw) if raw and not Path(raw).is_absolute() else Path(raw) if raw else None
    if target is None or not target.is_file():
        raise typer.Exit(0)
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    report = AuditScanner(target).scan()
    blocking = [v for v in report.violations if order.index(v.severity) >= order.index(threshold)]
    if not blocking:
        raise typer.Exit(0)
    lines = [f"오철칙: {target.name}에 {fail_on.upper()} 이상 지적 {len(blocking)}건이 있습니다. 고친 뒤 다시 저장하십시오."]
    for v in blocking[:limit]:
        lines.append(f"- {v.rule_id} {v.severity.value} {v.file_path.as_posix()}:{v.line_number} {v.message}")
        if v.how_to_fix:
            lines.append(f"  고치는 방법: {v.how_to_fix}")
    sys.stderr.write("\n".join(lines) + "\n")
    raise typer.Exit(2)


@app.command("sbom")
def sbom_command(
    path: Path = PathArg,
    fmt: str = typer.Option("cyclonedx", "--format", help="cyclonedx(1.6 JSON) 또는 spdx(2.3 JSON)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
    timestamp: str | None = typer.Option(None, "--timestamp", help="문서 생성 시각(ISO 8601). 생략하면 현재 시각. 같은 입력·시각이면 같은 문서가 나옵니다"),
    name: str | None = typer.Option(None, "--name", help="SBOM의 최상위 구성요소 이름. 기본은 폴더 이름"),
):
    """
    잠금 파일(package-lock.json, pnpm-lock.yaml, uv.lock, poetry.lock, requirements*.txt)로 SBOM을 만듭니다.
    의존 관계는 잠금 파일의 버전 단위 관계만 쓰며, 관계 정보가 없는 입력은 관계를 추정하지 않습니다. 네트워크를 쓰지 않습니다.
    """
    from datetime import UTC, datetime

    from iron_laws.core.scanner import tool_version
    from iron_laws.deps.graph import BUILDERS, build_graph
    from iron_laws.deps.lockfiles import find_lock_files
    from iron_laws.deps.sbom import cyclonedx, spdx

    if fmt not in ("cyclonedx", "spdx"):
        err.print("[bold red]--format은 cyclonedx 또는 spdx여야 합니다.[/bold red]")
        raise typer.Exit(2)
    if not path.exists():
        err.print(f"[bold red]입력 오류: 경로가 없습니다: {escape(str(path))}[/bold red]")
        raise typer.Exit(2)
    files = [f for f in find_lock_files(path)] + ([] if path.is_file() else [p for p in sorted(path.rglob("npm-shrinkwrap.json")) if "node_modules" not in p.parts])
    files = [f for f in files if f.name in BUILDERS or f.name.startswith("requirements")]
    if not files:
        err.print("[bold red]잠금 파일이 없어 SBOM을 만들 수 없습니다(버전을 알 수 없는 목록으로 SBOM을 만들지 않습니다).[/bold red]")
        raise typer.Exit(2)
    try:
        graphs = [build_graph(f) for f in files]
    except (OSError, ValueError, KeyError, TypeError) as e:
        err.print(f"[bold red]잠금 파일을 읽지 못했습니다: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    when = timestamp or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    project = name or (path.resolve().name if path.is_dir() else path.resolve().parent.name)
    doc = (cyclonedx if fmt == "cyclonedx" else spdx)(graphs, project, tool_version(), when)
    _write_or_print(json.dumps(doc, ensure_ascii=False, indent=2), output, "SBOM")


@spec_app.command("draft")
def spec_draft_command(
    path: Path = PathArg,
    output: Path | None = typer.Option(None, "--output", "-o", help="초안 저장 파일(YAML)"),
    llm_cmd: str | None = typer.Option(None, "--llm-cmd", help="초안 보강에 쓸 LLM 명령(표준 입력으로 지시문을 받아 YAML을 출력). 예: \"claude -p\". 지정하지 않으면 코드 분석 후보만 씁니다"),
):
    """
    코드에서 소스·싱크·정제 함수 후보를 찾아 명세 초안을 만듭니다. 코드에서 찾은 후보의 예제(positive·negative)는 비어 있으며,
    사람이 검토해 채우고 `iron-laws spec check`가 통과해야 설정 policies.custom_spec으로 불러올 수 있습니다.
    --llm-cmd의 제안은 LLM이 낸 예제로 바로 판정해, 어긋나면 rejected로 빼고 정제 함수는 예제가 맞아도 사람 확인을 남깁니다.
    """
    import shlex
    import subprocess

    import yaml

    from iron_laws.core.scanner import AuditScanner
    from iron_laws.core.spec_draft import build_draft, check_llm_entries, llm_prompt, merge_llm

    sources = AuditScanner(path)._read_sources()
    draft = build_draft(sources)
    if llm_cmd:
        lessons = experience_lessons(families={"command", "path", "sql", "code"})
        try:
            done = subprocess.run(shlex.split(llm_cmd), input=llm_prompt(draft, sources, lessons=lessons), capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as e:
            err.print(f"[bold red]LLM 명령을 실행하지 못했습니다: {escape(str(e))}[/bold red]")
            raise typer.Exit(2) from e
        added = merge_llm(draft, done.stdout)
        checked = check_llm_entries(draft)
        err.print(
            f"[dim]LLM 제안 {added}건: 예제 통과 {checked['passed']}, 정제 함수라 사람 확인 필요 {checked['needs_review']}, "
            f"예제 불일치로 제외 {checked['rejected']}(rejected 목록). 통과한 항목도 사람이 검토해야 합니다.[/dim]"
        )
    text = "# 오철칙 사용자 명세 초안: 각 항목을 검토하고 positive(지적되어야 하는 코드)·negative(지적되지 않아야 하는 코드)를 채우십시오.\n"
    text += yaml.safe_dump(draft, allow_unicode=True, sort_keys=False)
    _write_or_print(text, output, "명세 초안")


@spec_app.command("check")
def spec_check_command(
    spec: Path = typer.Argument(..., help="명세 파일(YAML)"),
    against: Path | None = typer.Option(None, "--against", help="비교할 저장소 경로. 주면 명세를 적용하기 전과 후를 같은 조건에서 두 번 돌려 탐지가 줄어드는지 봅니다"),
    config: Path | None = ConfigOpt,
    contract: Path | None = typer.Option(None, "--contract", help="근거 계약 파일(YAML)"),
    fmt: str = typer.Option("console", "--format", help="대조 결과 형식: console, markdown, json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
):
    """
    명세의 모든 항목이 양성·음성 예제대로 판정되는지 확인합니다. 하나라도 어긋나면 종료코드 1이며 그 명세는 불러오지 않습니다.
    --against로 저장소를 주면 그 저장소에서 명세를 적용하기 전과 후를 비교해 탐지가 줄어드는지 봅니다.
    """
    from iron_laws.core.custom_spec import example_results

    try:
        results = example_results(spec)
    except ConfigError as e:
        err.print(f"[bold red]명세 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    for name, form, ok, why in results:
        mark = "[green]맞음[/green]" if ok else "[bold red]어긋남[/bold red]"
        err.print(f"{mark} {escape(name)} {form}: {escape(why)}")
    failed = sum(1 for r in results if not r[2])
    err.print(f"항목 예제 {len(results)}개 중 어긋남 {failed}개")
    if against is None:
        raise typer.Exit(1 if failed else 0)
    if fmt not in ("console", "markdown", "json"):
        err.print("[bold red]--format은 console·markdown·json 중 하나여야 합니다.[/bold red]")
        raise typer.Exit(2)

    from iron_laws.core.contract import load_contract
    from iron_laws.core.spec_review import render_markdown, review_spec

    try:
        loaded_contract = None
        if contract is not None:
            loaded_contract, _digest = load_contract(contract)
        review = review_spec(
            against,
            spec,
            config_path=config,
            contract=loaded_contract,
            contract_source=str(contract) if contract else "기본값",
        )
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e

    markdown = render_markdown(review)
    if fmt == "json":
        _write_or_print(json.dumps(review.to_dict(), ensure_ascii=False, indent=2), output, "명세 대조 결과")
    elif fmt == "markdown":
        _write_or_print(markdown, output, "명세 대조 결과")
    else:
        label = {"ok": "탐지 감소 없음", "review": "확인 필요", "blocked": "채택 보류"}[review.verdict]
        err.print(f"명세 대조: {label}")
        for item in review.blocking:
            err.print(f"  [bold red]채택 보류[/bold red] {escape(item)}")
        for item in review.review:
            err.print(f"  [yellow]확인 필요[/yellow] {escape(item)}")
        for item in review.limitations:
            err.print(f"  [dim]{escape(item)}[/dim]")
        if output:
            _write_or_print(markdown, output, "명세 대조 결과")
    if review.verdict != "ok":
        err.print("[bold red]이 명세는 적용하기 전에 확인해야 합니다.[/bold red]")
        raise typer.Exit(1)
    raise typer.Exit(1 if failed else 0)


@app.command("lsp")
def lsp_command():
    """
    편집기용 LSP 서버(표준 입출력)를 띄웁니다. 파일을 열거나 고치거나 저장하면 그 내용을 점검해 진단으로 보냅니다.
    """
    from iron_laws.lsp import serve

    raise typer.Exit(serve())


@app.command("habits")
def habits_command(
    path: Path = PathArg,
    history: Path = typer.Option(Path(".iron-laws-habits.jsonl"), "--history", help="습관 기록 파일(JSONL). 점검할 때마다 한 줄을 더합니다"),
    fmt: str = typer.Option("table", "--format", help="table 또는 json"),
):
    """
    AI 코드의 다섯 습관(하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피)의 지적 수를 기록하고 1천 줄당 추이를 보여 줍니다.
    기록에는 수치와 코드 지문만 담고 코드·경로는 담지 않습니다. 표시는 판정이 아닙니다.
    """
    from rich.table import Table

    from iron_laws.commands.common import console
    from iron_laws.core.habits import append, snapshot, trend
    from iron_laws.core.scanner import AuditScanner

    scanner = AuditScanner(path)
    sources = scanner._read_sources()
    lines = sum(len(s.lines) for s in sources if s.lang is not None)
    report = scanner.scan()
    rows = append(history, snapshot(report, lines))
    data = trend(rows)
    if fmt == "json":
        typer.echo(json.dumps({"records": len(rows), "trend": data}, ensure_ascii=False, indent=2))
        return
    labels = {"hardcoding": "하드코딩", "structure": "구조 붕괴", "swallowed_exception": "삼킨 예외", "duplicate_helper": "중복 헬퍼", "typing": "타입 회피"}
    table = Table(title=f"[AI 습관 추이: 기록 {len(rows)}회, 1천 줄당 지적 수]", expand=True)
    for column in ("습관", "처음", "직전", "최근", "변화"):
        table.add_column(column)
    for habit, row in data.items():
        style = "red" if row["change"] > 0 else "green" if row["change"] < 0 else "dim"
        table.add_row(labels[habit], str(row["first"]), str(row["previous"]), str(row["latest"]), f"[{style}]{row['change']:+}[/{style}]")
    console.print(table)
