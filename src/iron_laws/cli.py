"""
오철칙 (Iron Laws) CLI Application
작성자: 최진호
작성일: 2026-10-04
"""

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from iron_laws.core.approvals import (
    DEFAULT_APPROVALS_FILE,
    ApprovalStore,
    Record,
    approve_record,
)
from iron_laws.core.baseline import (
    DEFAULT_BASELINE_FILE,
    Baseline,
    build_baseline,
    load_baseline,
    migrate_baseline,
    save_baseline,
)
from iron_laws.core.config import ConfigError, InputPathError, IronLawsConfig
from iron_laws.core.contract import load_contract
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
regression_app = typer.Typer(help="결함을 구별하는 최소 회귀시험: 제안 → 사람이 확인 → 격리 환경에서 원본 실패·후보 통과·mutant 재실패 검증")
approvals_app = typer.Typer(help="사람의 검토 승인 기록: 사유·전제를 남기고, 코드가 승인 전제를 바꾸면 관련 승인만 다시 검토하게 합니다")
baseline_app = typer.Typer(help="기준선(baseline): 이미 알려진 지적을 승인된 부채로 기록하고 새 지적만 걸러 냅니다")
feedback_app = typer.Typer(help="'확인 필요' 지적의 검토 결과(채택·오탐·소요 시간)를 기록하고 모아 봅니다")
pilot_app = typer.Typer(help="파일럿 준비: 조건 교차 배정, 검토 시간·위험 수용 기록, 요약(로컬 파일만 쓰며 외부로 보내지 않습니다)")
evidence_app = typer.Typer(help="근거 검증: 점검 보고서·검증 기록이 서로 모순되지 않는지 엔진과 독립으로 확인하고, 이전 형식 기록을 옮깁니다")
app.add_typer(regression_app, name="regression")
app.add_typer(approvals_app, name="approvals")
app.add_typer(baseline_app, name="baseline")
app.add_typer(feedback_app, name="feedback")
app.add_typer(evidence_app, name="evidence")
app.add_typer(pilot_app, name="pilot")
console = Console()  # 사람이 읽는 본문(표·보고서)은 stdout
err = Console(stderr=True)  # 상태·오류 메시지는 stderr. JSON·SARIF 같은 기계용 stdout을 오염시키지 않는다

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
ContractOpt = typer.Option(
    None, "--contract", help="근거 계약 파일(신뢰 정책). 보안 관심 지점에 요구하는 분석 근거를 선언하며, 충족 여부가 보고서에 남습니다"
)
ContractModeOpt = typer.Option(
    None, "--contract-mode", help="계약 모드를 덮어씁니다: report(공백을 모으기만 함) 또는 block(필수 범위 미충족이면 실패)"
)
MetricsOpt = typer.Option(
    None, "--metrics", help="이번 점검의 집계값(건수·시간·식별 해시만)을 이 파일에 한 줄 남깁니다. 경로·코드·메시지는 담지 않으며 기본은 꺼짐입니다"
)
ApprovalsOpt = typer.Option(
    None, "--approvals", help="승인 기록 파일. 지정하면 전제가 유지되는 유효한 승인만 받아들이고, 전제가 바뀐 승인은 다시 검토 대상으로 셉니다"
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


def _git(args: list[str], cwd: Path) -> bytes:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise ConfigError(f"git 명령을 실행하지 못했습니다 (git {' '.join(args)}): {e}") from e
    return result.stdout


def _nul_paths(raw: bytes) -> list[str]:
    """`-z` 출력은 경로를 NUL로 구분하므로 한글·공백·탭·개행·인용부호가 들어 있어도 이스케이프 없이 온전하다."""
    return [chunk.decode("utf-8", errors="surrogateescape") for chunk in raw.split(b"\0") if chunk]


def _changed_files(root: Path, ref: str) -> set[str]:
    """ref 이후 바뀐 파일(추적 중인 변경, 스테이징된 파일, 새 파일)을 점검 루트 기준 상대 경로로 돌려준다."""
    if ref.startswith("-"):
        raise ConfigError(f"--changed-since 값이 옵션처럼 보입니다: {ref!r} (브랜치·커밋 이름을 지정하십시오)")
    folder = root if root.is_dir() else root.parent
    top = Path(_git(["rev-parse", "--show-toplevel"], folder).decode("utf-8", errors="surrogateescape").strip())
    names = _nul_paths(_git(["diff", "--name-only", "-z", "--diff-filter=ACMRT", ref, "--"], folder))
    names += _nul_paths(_git(["ls-files", "-z", "--full-name", "--others", "--exclude-standard"], folder))
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
    contract: Path | None = None,
    contract_mode: str | None = None,
    approvals: Path | None = None,
    collect_dependencies: bool = False,
) -> AuditScanner:
    try:
        loaded_contract = None
        if contract is not None:
            loaded_contract, _digest = load_contract(contract)
        if contract_mode is not None:
            if contract_mode not in ("report", "block"):
                raise ConfigError("--contract-mode는 report 또는 block이어야 합니다")
            from iron_laws.core.contract import default_contract

            loaded_contract = loaded_contract or default_contract()
            loaded_contract.mode = contract_mode  # type: ignore[assignment]
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
            contract=loaded_contract,
            contract_source=(str(contract) if contract else "기본값") + (f" (모드 {contract_mode}는 명령행)" if contract_mode else ""),
            contract_path=contract,
            approvals=ApprovalStore(approvals) if approvals else None,
            collect_dependencies=collect_dependencies,
        )
        return scanner
    except ConfigError as e:
        label = "입력 오류" if isinstance(e, InputPathError) else "설정 오류"
        err.print(f"[bold red]{label}: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e


def _check_completion(report: AuditReport, allow_empty: bool) -> None:
    """점검이 끝까지 이루어지지 않았으면 통과로 보지 않는다. 경로 오타·제외 설정 실수·규칙 오류를 CI가 놓치지 않게 한다."""
    status = report.summary.scan_status
    if status == "empty":
        if allow_empty:
            report.summary.is_passed = True
            return
        err.print(
            "[bold red]점검한 파일이 없습니다. 경로, 제외 설정, 확장자 설정을 확인하세요. "
            "의도한 경우 --allow-empty를 붙이세요.[/bold red]"
        )
        raise typer.Exit(2)
    if status == "incomplete":
        errors = [d for d in report.diagnostics if d.severity == "error"]
        err.print(f"[bold red]점검이 끝까지 이루어지지 않았습니다 (오류 {len(errors)}건). 통과로 판정하지 않습니다.[/bold red]")
        for d in errors[:10]:
            where = f"{d.file_path}: " if d.file_path else ""
            err.print(f"  - {escape(where + d.message)}")
        raise typer.Exit(2)


def _timed_scan(scanner: AuditScanner, metrics: Path | None, command: str) -> AuditReport:
    """점검을 실행하고, --metrics가 있으면 집계값 한 줄을 로컬 파일에 남긴다(경로·코드·메시지는 담지 않는다)."""
    started = time.monotonic()
    report = scanner.scan()
    if metrics is not None:
        from iron_laws.core.metrics import append_metrics, metrics_record

        try:
            append_metrics(metrics, metrics_record(report, time.monotonic() - started, command))
        except OSError as e:
            err.print(f"[yellow]계측 기록을 쓰지 못했습니다: {escape(str(e))}[/yellow]")
    return report


def _write_or_print(content: str, output: Path | None, label: str) -> None:
    if output:
        output.write_text(content, encoding="utf-8")
        err.print(f"[bold green]{label} 저장 완료: {output}[/bold green]")
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
    contract: Path | None = ContractOpt,
    contract_mode: str | None = ContractModeOpt,
    approvals: Path | None = ApprovalsOpt,
    metrics: Path | None = MetricsOpt,
):
    """
    프로젝트의 보안 약점과 품질 결함을 신속 진단합니다. (CI/CD 적합)
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore, contract, contract_mode, approvals)
    if fail_on is not None:
        scanner.config.fail_on = fail_on
        scanner.fail_on_source = "명령행 옵션"
    report = _timed_scan(scanner, metrics, "check")
    print_console_report(report, limit)
    _check_completion(report, allow_empty)

    if not report.summary.is_passed:
        if report.summary.contract_mode == "block" and report.summary.contract_status in ("unmet", "policy_change_review"):
            err.print("[bold red]근거 계약을 충족하지 못해 점검이 실패했습니다. 지적이 없어도 요구한 분석 근거가 없으면 통과가 아닙니다.[/bold red]")
        err.print(
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
    contract: Path | None = ContractOpt,
    contract_mode: str | None = ContractModeOpt,
    approvals: Path | None = ApprovalsOpt,
    metrics: Path | None = MetricsOpt,
):
    """
    점검을 수행하고 보고서를 발행합니다. markdown 보고서에는 행안부 구현단계 49개 항목별 점검 현황이 포함됩니다.
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore, contract, contract_mode, approvals)
    report = _timed_scan(scanner, metrics, "audit")
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
            err.print(f"[bold green]보고서가 파일에 저장되었습니다: {output}[/bold green]")
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
    contract: Path | None = ContractOpt,
    contract_mode: str | None = ContractModeOpt,
    approvals: Path | None = ApprovalsOpt,
):
    """
    점검 결과를 코딩 AI에게 그대로 붙여넣을 수정 지시문으로 만듭니다. 지시문 생성이 목적이라 지적이 있어도 종료코드는 0입니다.
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore, contract, contract_mode, approvals)
    report = scanner.scan()
    if report.summary.scan_status == "empty":
        _check_completion(report, False)
    _write_or_print(generate_fix_prompt(report, limit), output, "수정 지시문")
    if report.summary.scan_status == "incomplete":
        _check_completion(report, False)  # 지시문은 내보내되 불완전한 점검이었음을 종료코드로 알린다


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


@regression_app.command("propose")
def regression_propose_command(
    original: Path = typer.Argument(..., help="원본 프로젝트 폴더"),
    finding: str = typer.Option(..., "--finding", help="시험을 만들 지적: 지문 접두사, RULE@경로:줄, RULE@경로"),
    out: Path | None = typer.Option(None, "--out", "-o", help="명세 YAML 저장 경로(생략하면 stdout)"),
    config: Path | None = ConfigOpt,
):
    """
    지적의 입력·전파·싱크 근거에서 회귀시험 후보(명세)를 제안합니다. 제안은 검증 근거가 아닙니다.
    입력·기대 결과·가짜 sink를 직접 확인하고 `confirmed: true`로 바꾼 명세만 검증에 쓰입니다.
    첫 지원 범위: Python의 명령 실행(IL-504)·경로 접근(IL-502)·SQL 조립(IL-501), 모듈 수준 함수.
    """
    from iron_laws.verify.engine import resolve_finding
    from iron_laws.verify.regression import dump_spec, propose_spec

    scanner = _build_scanner(original, config)
    report = scanner.scan()
    try:
        violation = resolve_finding(report, finding)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    proposal = propose_spec(original.resolve(), violation)
    if proposal.spec is None:
        err.print(f"[bold yellow]회귀시험 후보를 만들 수 없습니다: {escape(proposal.reason)}[/bold yellow]")
        raise typer.Exit(2)
    _write_or_print(dump_spec(proposal.spec), out, "회귀시험 명세(확정 전)")
    err.print("[yellow]검토할 것: 입력(payload)·정상 대조군(benign)·기대 결과(expect)·가짜 sink(fake_sink). 확인한 뒤 confirmed: true로 바꾸십시오.[/yellow]")
    for note in proposal.spec.review_notes:
        err.print(f"  - {escape(note)}")


@regression_app.command("check")
def regression_check_command(
    original: Path = typer.Argument(..., help="원본 프로젝트 폴더"),
    patch: Path = typer.Option(..., "--patch", help="후보 patch(unified diff)"),
    spec: Path = typer.Option(..., "--spec", help="확정된 회귀시험 명세"),
    runner: str = typer.Option("auto", "--runner", help="격리 실행기: auto, docker, bwrap, none"),
    image: str | None = typer.Option(None, "--image", help="격리 실행에 쓸 docker 이미지(로컬에 미리 받아 둠)"),
    timeout: int = typer.Option(60, "--timeout", min=1, help="실행 한 번의 시간 상한(초)"),
):
    """
    확정된 명세로 원본에서 결함이 재현되는지, 후보에서 통과하는지, 수정을 되돌린 mutant에서 다시 실패하는지를 격리 환경에서 확인합니다.
    종료코드: 0 통과, 1 실패, 2 판정 불가.
    """
    from iron_laws.verify.engine import regression_only
    from iron_laws.verify.receipt import STATE_LABEL
    from iron_laws.verify.runner import RunLimits

    try:
        result = regression_only(original, patch, spec, runner, image, RunLimits(timeout_s=timeout))
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    sys.stdout.write(json.dumps({"result": result.result, "label": STATE_LABEL[result.result], "reason": result.reason, "evidence": result.evidence}, ensure_ascii=False, indent=2) + "\n")
    raise typer.Exit({"pass": 0, "fail": 1}.get(result.result, 2))


@app.command("verify-patch")
def verify_patch_command(
    original: Path = typer.Argument(..., help="원본 프로젝트 폴더 (읽기만 합니다. 수정·커밋하지 않습니다)"),
    patch: Path = typer.Option(..., "--patch", help="외부 AI가 만든 unified diff 파일"),
    finding: str | None = typer.Option(None, "--finding", help="고치려는 지적: 지문 접두사, RULE@경로:줄, RULE@경로"),
    config: Path | None = ConfigOpt,
    contract: Path | None = typer.Option(None, "--contract", help="근거 계약 파일(신뢰 정책)"),
    test_cmd: list[str] = typer.Option([], "--test-cmd", help="기존 시험 명령의 각 인자(여러 번 지정). 예: --test-cmd python --test-cmd -m --test-cmd pytest"),
    runner: str = typer.Option("auto", "--runner", help="격리 실행기: auto, docker, bwrap, none. 격리를 얻지 못하면 시험을 실행하지 않고 판정 불가로 남깁니다"),
    image: str | None = typer.Option(None, "--image", help="격리 실행에 쓸 docker 이미지(로컬에 미리 받아 두어야 함). 기본은 실행 정책 또는 python:3.13-slim"),
    timeout: int = typer.Option(180, "--timeout", min=1, help="후보당 시험 시간 상한(초)"),
    max_files: int = typer.Option(5, "--max-files", min=1, help="patch가 바꿀 수 있는 파일 수 상한"),
    allow_path: list[str] = typer.Option([], "--allow-path", help="patch가 바꿀 수 있는 경로 패턴(여러 번 지정). 지정하면 그 밖은 범위 위반"),
    no_require_tests: bool = typer.Option(False, "--no-require-tests", help="시험 미실행을 판정 불가로 보지 않습니다(기본은 시험이 필수)"),
    regression: Path | None = typer.Option(None, "--regression", help="결함을 구별하는 회귀시험 명세(검토·확정된 것)"),
    out: Path | None = typer.Option(None, "--out", "-o", help="검증 기록(Receipt) JSON 저장 경로"),
    replay: Path | None = typer.Option(None, "--replay", help="이전 Receipt를 같은 입력·조건으로 깨끗한 작업영역에서 다시 실행해 결과가 재현되는지 확인"),
):
    """
    AI가 만든 patch를 원본과 같은 정책·조건으로 검증하고 승인 근거(Receipt)를 남깁니다.
    종료코드: 0 검증 항목 통과, 1 검증 실패, 2 판정 불가 또는 입력 오류.
    통과는 지정된 검사 계약을 충족했다는 뜻이며 안전성이나 완전한 기능 동등성을 증명하지 않습니다.
    """
    from iron_laws.verify.engine import VerifyOptions, verify_patch
    from iron_laws.verify.receipt import STATE_LABEL, Receipt
    from iron_laws.verify.replay import replay_receipt
    from iron_laws.verify.runner import RunLimits

    options = VerifyOptions(
        finding=finding,
        config_path=config,
        contract_path=contract,
        test_cmd=list(test_cmd) or None,
        runner=runner,
        image=image,
        limits=RunLimits(timeout_s=timeout),
        require_tests=not no_require_tests,
        max_files=max_files,
        allow_paths=tuple(allow_path),
        regression_spec=regression,
    )
    try:
        if replay is not None:
            recorded = Receipt.model_validate_json(replay.read_text(encoding="utf-8"))
            outcome = replay_receipt(recorded, original, patch)
            err.print(f"[bold]재실행: {'재현됨' if outcome.reproduced else '재현되지 않음'}[/bold]")
            for line in outcome.differences:
                err.print(f"  - {escape(line)}")
            _write_or_print(outcome.receipt.model_dump_json(indent=2), out, "재실행 기록")
            raise typer.Exit(0 if outcome.reproduced else 1)
        receipt = verify_patch(original, patch, options)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    table = Table(title="[패치 검증 결과]", expand=True)
    table.add_column("항목")
    table.add_column("결과", width=12)
    table.add_column("근거·사유")
    for c in receipt.checks:
        style = {"pass": "green", "fail": "red", "not_run": "yellow", "unknown": "yellow"}[c.result]
        table.add_row(c.title, f"[{style}]{STATE_LABEL[c.result]}[/{style}]", escape(c.reason)[:160])
    console.print(table)
    if receipt.bypass_changes:
        console.print("[bold yellow]우회 변경 (경고가 사라졌더라도 수정으로 인정하지 않음)[/bold yellow]")
        for b in receipt.bypass_changes:
            console.print(f"  - {escape(b['kind'])} {escape(b['path'])}: {escape(b['detail'])}")
    console.print(f"[bold]종합: {receipt.verdict.label}[/bold]  (기록 해시 {receipt.receipt_digest})")
    console.print(f"[dim]{receipt.verdict.caveat}[/dim]")
    if out:
        out.write_text(receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")
        err.print(f"[green]검증 기록 저장: {out}[/green]")
    raise typer.Exit({"verified": 0, "failed": 1, "undeterminable": 2}[receipt.verdict.overall])


# ---------------------------------------------------------------------------
# 승인 기록
# ---------------------------------------------------------------------------


def _store(path: Path | None) -> ApprovalStore:
    try:
        return ApprovalStore(path or Path(DEFAULT_APPROVALS_FILE))
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e


@approvals_app.command("add")
def approvals_add_command(
    path: Path = PathArg,
    finding: str = typer.Option(..., "--finding", help="승인할 지적: 지문 접두사, RULE@경로:줄, RULE@경로"),
    reason: str = typer.Option(..., "--reason", help="승인 사유(3자 이상). 무엇을 확인했고 왜 받아들이는지"),
    reviewer: str = typer.Option("", "--reviewer", help="검토자 표기. 인증되지 않은 이름표이며 누가 승인했는지 증명하지 않습니다"),
    expires: str | None = typer.Option(None, "--expires", help="승인 유효기간(YYYY-MM-DD). 지나면 다시 검토 대상이 됩니다"),
    receipt: Path | None = typer.Option(None, "--receipt", help="이 승인의 근거가 된 패치 검증 기록(Receipt) 파일"),
    minutes: int = typer.Option(0, "--minutes", min=0, help="검토에 든 시간(분). 검토 계측용"),
    store: Path | None = typer.Option(None, "--store", help=f"승인 기록 파일(기본 {DEFAULT_APPROVALS_FILE}). 후보 변경이 쓸 수 없는 위치를 권장합니다"),
    config: Path | None = ConfigOpt,
    contract: Path | None = ContractOpt,
):
    """
    지적 하나를 사람의 검토 결과로 승인하고, 승인 당시의 전제(흐름·호출자·정제 함수·접근 범위·정책)를 함께 기록합니다.
    기록은 추가 전용이며 해시로 이어집니다. 해시는 변조 탐지용이고 승인자의 진위를 증명하지 않습니다.
    """
    from datetime import date as _date

    from iron_laws.verify.engine import resolve_finding
    from iron_laws.verify.receipt import Receipt

    approvals_store = _store(store)
    scanner = _build_scanner(path, config, False, None, None, False, contract, None, None, True)
    report = scanner.scan()
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 끝까지 이루어지지 않아 승인을 기록하지 않습니다(불완전한 분석 위에 승인을 쌓지 않습니다).[/bold red]")
        raise typer.Exit(2)
    try:
        violation = resolve_finding(report, finding)
        expiry = _date.fromisoformat(expires) if expires else None
        receipt_digest = None
        if receipt is not None:
            loaded = Receipt.model_validate_json(receipt.read_text(encoding="utf-8"))
            if not loaded.verify_seal():
                raise ConfigError("검증 기록(Receipt)의 내용 해시가 맞지 않습니다")
            receipt_digest = loaded.receipt_digest
        existing = [a for a in approvals_store.approvals() if not a.revoked and a.record.finding and a.record.finding.fingerprint == violation.fingerprint]
        if existing:
            raise ConfigError(f"이미 같은 지적에 대한 승인이 있습니다: {existing[0].id}")
        record = approve_record(violation, reason, reviewer, scanner._approval_policy(), expiry, receipt_digest, minutes)
        approvals_store.append(record)
    except (ConfigError, ValueError) as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    err.print(f"[green]승인 기록 추가: {record.id} ({violation.rule_id} {violation.file_path.as_posix()}:{violation.line_number})[/green]")
    err.print("[dim]이 승인은 기록된 전제가 유지되는 동안만 유효합니다. 승인 기록 파일은 후보 변경이 바꿀 수 없는 곳에 두십시오.[/dim]")
    sys.stdout.write(record.id + "\n")


@approvals_app.command("list")
def approvals_list_command(store: Path | None = typer.Option(None, "--store", help="승인 기록 파일")):
    """
    기록된 승인을 보여 줍니다(점검 없이 기록만 읽습니다. 현재 유효성은 `approvals status`).
    """
    items = _store(store).approvals()
    table = Table(title="[승인 기록]", expand=True)
    for column in ("ID", "규칙", "위치", "사유", "검토자", "만료", "상태"):
        table.add_column(column, no_wrap=(column == "ID"))
    for a in items:
        f = a.record.finding
        table.add_row(a.id, f.rule_id if f else "", f"{f.path}::{f.scope_name}" if f else "", escape(a.record.reason)[:40], escape(a.record.reviewer), a.record.expires or "-", "철회됨" if a.revoked else "기록됨")
    console.print(table)


@approvals_app.command("status")
def approvals_status_command(
    path: Path = PathArg,
    store: Path | None = typer.Option(None, "--store", help="승인 기록 파일"),
    config: Path | None = ConfigOpt,
    contract: Path | None = ContractOpt,
    json_output: bool = typer.Option(False, "--json", help="JSON으로 출력"),
):
    """
    현재 코드에서 각 승인이 아직 유효한지 확인합니다. 종료코드: 0 모두 유효, 1 다시 검토할 승인이 있음, 2 점검 불가.
    """
    approvals_store = _store(store)
    scanner = _build_scanner(path, config, False, None, None, False, contract, None, store or Path(DEFAULT_APPROVALS_FILE))
    report = scanner.scan()
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 끝까지 이루어지지 않아 승인 유효성을 판단할 수 없습니다.[/bold red]")
        raise typer.Exit(2)
    rows = scanner.approval_rows
    label = {"valid": "유효", "needs_review": "재검토 필요", "revoked": "철회됨", "resolved": "해소됨", "unobserved": "미확인", "invalid": "검증 실패"}
    if json_output:
        payload = [{"id": r.approval.id, "status": r.status, "reasons": r.reasons, "finding": r.approval.record.finding.model_dump() if r.approval.record.finding else None} for r in rows]
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        table = Table(title="[승인 유효성]", expand=True)
        for column in ("ID", "지적", "상태", "이유"):
            table.add_column(column, no_wrap=(column == "ID"))
        for r in rows:
            f = r.approval.record.finding
            style = {"valid": "green", "needs_review": "yellow", "unobserved": "yellow"}.get(r.status, "white")
            table.add_row(r.approval.id, f"{f.rule_id} {f.path}::{f.scope_name}" if f else "", f"[{style}]{label.get(r.status, r.status)}[/{style}]", escape("; ".join(r.reasons))[:100])
        console.print(table)
    problems = approvals_store.integrity().lines()
    for p in problems:
        err.print(f"[bold red]기록 무결성: {escape(p)}[/bold red]")
    raise typer.Exit(1 if problems or any(r.status in ("needs_review", "unobserved", "invalid") for r in rows) else 0)


@approvals_app.command("revoke")
def approvals_revoke_command(
    approval_id: str = typer.Argument(..., help="철회할 승인 ID"),
    reason: str = typer.Option(..., "--reason", help="철회 사유"),
    store: Path | None = typer.Option(None, "--store", help="승인 기록 파일"),
):
    """
    승인을 철회합니다(철회 기록을 추가하며 이전 기록은 지우지 않습니다).
    """
    approvals_store = _store(store)
    if approval_id not in {a.id for a in approvals_store.approvals()}:
        err.print(f"[bold red]승인을 찾을 수 없습니다: {escape(approval_id)}[/bold red]")
        raise typer.Exit(2)
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        approvals_store.append(Record(seq=0, kind="revoke", id=f"RV-{approval_id[3:]}", created=created, target=approval_id, reason=reason.strip()))
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    err.print(f"[green]철회 기록 추가: {approval_id}[/green]")


@approvals_app.command("verify")
def approvals_verify_command(store: Path | None = typer.Option(None, "--store", help="승인 기록 파일")):
    """
    기록의 해시 연결(삭제·재배열·내용 변경 의심)을 확인합니다. 변조 탐지용이며 진위 인증이 아닙니다.
    """
    problems = _store(store).integrity().lines()
    for p in problems:
        err.print(f"[bold red]{escape(p)}[/bold red]")
    if problems:
        raise typer.Exit(1)
    err.print("[green]기록 해시 연결과 기록 형식에 이상 없음 (변조 탐지 근거일 뿐 진위·안전성의 증명이 아닙니다)[/green]")


@approvals_app.command("forget")
def approvals_forget_command(
    approval_id: str = typer.Argument(..., help="삭제 표시할 승인 ID"),
    yes: bool = typer.Option(False, "--yes", help="확인했습니다"),
    store: Path | None = typer.Option(None, "--store", help="승인 기록 파일"),
):
    """
    승인을 현재 목록에서 지우는 삭제 표시를 추가합니다. 원본 줄은 `approvals prune`을 해야 파일에서 사라집니다.
    """
    if not yes:
        err.print("[bold red]삭제 표시는 --yes로 확인해야 합니다.[/bold red]")
        raise typer.Exit(2)
    approvals_store = _store(store)
    if approval_id not in {a.id for a in approvals_store.approvals()}:
        err.print(f"[bold red]승인을 찾을 수 없습니다: {escape(approval_id)}[/bold red]")
        raise typer.Exit(2)
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    approvals_store.append(Record(seq=0, kind="forget", id=f"FG-{approval_id[3:]}", created=created, target=approval_id))
    err.print(f"[green]삭제 표시 추가: {approval_id}[/green]")


@approvals_app.command("prune")
def approvals_prune_command(
    before: str = typer.Option(..., "--before", help="이 날짜(YYYY-MM-DD) 이전에 만들어진 만료·철회·삭제 표시된 승인을 파일에서 지웁니다"),
    yes: bool = typer.Option(False, "--yes", help="되돌릴 수 없는 작업임을 확인했습니다"),
    store: Path | None = typer.Option(None, "--store", help="승인 기록 파일"),
):
    """
    보존기간이 지난 기록을 지우고 해시 연결을 새로 만듭니다. 추가 전용 이력을 깨는 되돌릴 수 없는 작업입니다.
    """
    from datetime import date as _date

    if not yes:
        err.print("[bold red]이 작업은 되돌릴 수 없습니다. --yes로 확인하십시오.[/bold red]")
        raise typer.Exit(2)
    try:
        cutoff = _date.fromisoformat(before)
    except ValueError as e:
        err.print("[bold red]--before는 YYYY-MM-DD 형식이어야 합니다.[/bold red]")
        raise typer.Exit(2) from e
    try:
        removed = _store(store).prune(cutoff)
    except ConfigError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    err.print(f"[green]지운 기록 {removed}건[/green]")


@approvals_app.command("queue")
def approvals_queue_command(
    path: Path = PathArg,
    store: Path | None = typer.Option(None, "--store", help="승인 기록 파일"),
    config: Path | None = ConfigOpt,
    contract: Path | None = ContractOpt,
    json_output: bool = typer.Option(False, "--json", help="JSON으로 출력"),
):
    """
    검토 대기열: 사람이 판단해야 하는 항목(승인 전제가 바뀐 승인, 승인 없는 '확인 필요' 지적)을 심각도 순으로 보여 줍니다.
    """
    scanner = _build_scanner(path, config, False, None, None, False, contract, None, store or Path(DEFAULT_APPROVALS_FILE))
    report = scanner.scan()
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 끝까지 이루어지지 않아 대기열이 불완전할 수 있습니다.[/bold red]")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items: list[dict] = []
    for r in scanner.approval_rows:
        if r.status in ("needs_review", "unobserved", "invalid") and r.violation is not None:
            items.append({"kind": "재검토 필요한 승인", "id": r.approval.id, "rule": r.violation.rule_id, "location": f"{r.violation.file_path.as_posix()}:{r.violation.line_number}", "severity": r.violation.severity.value, "why": "; ".join(r.reasons)})
    for v in report.violations:
        if v.confidence.value == "REVIEW" and v.approval_status in (None, "none", "expired", "revoked"):
            items.append({"kind": "승인 없는 확인 필요 지적", "id": v.fingerprint[:10], "rule": v.rule_id, "location": f"{v.file_path.as_posix()}:{v.line_number}", "severity": v.severity.value, "why": v.message[:80]})
    items.sort(key=lambda i: (order[i["severity"]], i["location"]))
    if json_output:
        sys.stdout.write(json.dumps(items, ensure_ascii=False, indent=2) + "\n")
        return
    table = Table(title=f"[검토 대기열 {len(items)}건]", expand=True)
    for column in ("종류", "ID", "규칙", "위치", "심각도", "사유"):
        table.add_column(column)
    for i in items[:50]:
        table.add_row(i["kind"], i["id"], i["rule"], escape(i["location"]), i["severity"], escape(i["why"]))
    console.print(table)


@approvals_app.command("stats")
def approvals_stats_command(store: Path | None = typer.Option(None, "--store", help="승인 기록 파일")):
    """
    검토 계측: 승인·철회 건수, 규칙별 건수, 검토 시간(평균·중앙값). 기록에 든 식별자만 집계하며 외부로 보내지 않습니다.
    """
    from statistics import mean, median

    items = _store(store).approvals()
    minutes = [a.record.minutes for a in items if a.record.minutes]
    by_rule: dict[str, int] = {}
    for a in items:
        if a.record.finding:
            by_rule[a.record.finding.rule_id] = by_rule.get(a.record.finding.rule_id, 0) + 1
    table = Table(title="[검토 계측]")
    table.add_column("항목")
    table.add_column("값", justify="right")
    table.add_row("승인 기록", str(len(items)))
    table.add_row("철회됨", str(sum(1 for a in items if a.revoked)))
    table.add_row("검토 시간 기록이 있는 승인", str(len(minutes)))
    table.add_row("검토 시간 평균(분)", f"{mean(minutes):.1f}" if minutes else "-")
    table.add_row("검토 시간 중앙값(분)", f"{median(minutes):.1f}" if minutes else "-")
    for rule_id, count in sorted(by_rule.items()):
        table.add_row(f"규칙 {rule_id}", str(count))
    console.print(table)


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
    kind: str = typer.Option(..., "--kind", help="misaccept(오통과) 또는 dangerous_inheritance(위험한 승인 승계)"),
    note: str = typer.Option("", "--note", help="짧은 메모(코드 원문 금지)"),
    store: Path | None = typer.Option(None, "--store", help="파일럿 기록 파일"),
):
    """
    오통과·위험한 승계를 기록합니다. bundle 조건에서 한 건이라도 기록되면 요약이 관련 자동 경로를 수동 검토로 돌리라고 표시합니다.
    """
    from iron_laws.core.pilot import flag_risk

    _pilot_call(flag_risk, _pilot_store(store), pr, kind, note)
    err.print(f"[yellow]위험 기록: {escape(pr)} ({escape(kind)})[/yellow]")


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
        for column in ("조건", "검토 건수", "중앙값(분)", "75백분위(분)", "총 시간 중앙값(분)", "위험 수용"):
            table.add_column(column)
        for arm, data in result["arms"].items():
            table.add_row(arm, str(data["review_minutes"]["n"]), str(data["review_minutes"]["median"]), str(data["review_minutes"]["p75"]), str(data["total_minutes"]["median"]), str(data["risk_accepted"]))
        console.print(table)
        console.print(f"판정: {result['verdict']} · 자동 경로: {result['automation']} · 중도 포기 {result['dropouts']}")
        for reason in result["sample"]["reasons"]:
            console.print(f"[yellow]표본 부족: {escape(reason)}[/yellow]")
        for note in result["notes"]:
            console.print(f"[dim]{escape(note)}[/dim]")
    raise typer.Exit(1 if result["verdict"] == "targets_not_met" else 0)


@app.command("review-bundle")
def review_bundle_command(
    path: Path = PathArg,
    approvals: Path | None = typer.Option(None, "--approvals", help="승인 기록 파일(기본 .iron-laws-approvals.jsonl)"),
    config: Path | None = ConfigOpt,
    contract: Path | None = ContractOpt,
    changed_since: str | None = ChangedSinceOpt,
    fmt: str = typer.Option("markdown", "--format", help="markdown 또는 json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
    metrics: Path | None = MetricsOpt,
):
    """
    검토자에게 줄 한 묶음: 바뀐 전제, 기존 승인의 유지·무효화·판정 불가와 각 근거, 필수 행동, 남은 공백, 재현 정보.
    구조화된 근거에서 결정적으로 만들며 AI 요약을 판정 근거로 쓰지 않습니다. 종료코드: 0 필수 행동 없음, 1 필수 행동 있음, 2 점검 불완전·입력 오류.
    """
    from iron_laws.core.review_bundle import build_bundle, render_markdown

    if fmt not in ("markdown", "json"):
        err.print("[bold red]--format은 markdown 또는 json이어야 합니다.[/bold red]")
        raise typer.Exit(2)
    store_path = approvals or Path(DEFAULT_APPROVALS_FILE)
    scanner = _build_scanner(path, config, False, None, changed_since, False, contract, None, store_path, True)
    report = _timed_scan(scanner, metrics, "review-bundle")
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 끝까지 이루어지지 않아 검토 묶음이 불완전합니다(미확인을 유지로 보지 않습니다).[/bold red]")
        raise typer.Exit(2)
    command = f"iron-laws review-bundle {path.as_posix()}" + (f" --approvals {store_path.as_posix()}" if approvals else "") + (f" --contract {contract.as_posix()}" if contract else "") + (f" --changed-since {changed_since}" if changed_since else "")
    bundle = build_bundle(report, scanner.approval_rows, changed_files=scanner.changed_files, command=command, approvals_path=store_path.as_posix() if store_path.exists() else None)
    text = json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2) + "\n" if fmt == "json" else render_markdown(bundle)
    _write_or_print(text.rstrip("\n"), output, "검토 묶음")
    raise typer.Exit(1 if bundle.actions else 0)


@evidence_app.command("verify")
def evidence_verify_command(
    target: Path = typer.Argument(..., help="점검 보고서(audit --format json) 또는 검증 기록(verify-patch --out) 파일"),
    report: Path | None = typer.Option(None, "--report", help="검증 기록을 검증할 때 함께 대조할 점검 보고서"),
    checkout: Path | None = typer.Option(None, "--checkout", help="다른 checkout 폴더. 주면 그 코드의 지문이 보고서가 점검한 코드와 같은지 다시 계산합니다"),
    as_of: str | None = typer.Option(None, "--as-of", help="승인 만료 판단 기준일(YYYY-MM-DD). 기본은 오늘"),
    json_output: bool = typer.Option(False, "--json", help="JSON으로 출력"),
):
    """
    보고서·검증 기록의 구조적 모순(없는 지적을 가리킴, 근거 없는 충족, 차단 사유와 상태 불일치, 설명할 수 없는 통과, 만료·다른 코드의 승인 재사용)을 찾습니다.
    종료코드: 0 모순 없음, 1 모순 발견, 2 확인할 수 없음(지원하지 않는 버전·누락·읽기 오류). 엔진이 일관되게 만든 의미 오류는 잡지 못합니다.
    """
    from datetime import date as _date

    from iron_laws.evidence.verifier import load_json, verify_receipt, verify_report

    try:
        data = load_json(target)
        base = load_json(report) if report is not None else None
        when = _date.fromisoformat(as_of) if as_of else None
    except ValueError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    if "checks" in data and "verdict" in data:
        result = verify_receipt(data, report=base)
        kind = "검증 기록"
    else:
        result = verify_report(data, as_of=when, checkout=checkout)
        kind = "점검 보고서"
    if json_output:
        payload = {
            "kind": kind,
            "ok": result.ok,
            "undeterminable": result.undeterminable,
            "checked": result.checked,
            "problems": [{"code": p.code, "message": p.message, "where": p.where} for p in result.problems],
            "notes": result.notes,
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        for p in result.problems:
            err.print(f"[bold red]{escape(str(p))}[/bold red]")
        for note in result.notes:
            err.print(f"[yellow]{escape(note)}[/yellow]")
        if result.ok:
            err.print(f"[green]{kind}의 불변식 {result.checked}개를 확인했고 모순이 없습니다. (구조의 일관성이며 코드의 안전성이 아닙니다)[/green]")
    raise typer.Exit(2 if result.undeterminable else 1 if result.problems else 0)


@evidence_app.command("upgrade")
def evidence_upgrade_command(
    source: Path = typer.Argument(..., help="이전 형식(1.0~1.2) 점검 보고서 JSON"),
    output: Path = typer.Option(..., "--output", "-o", help="1.3 형식으로 저장할 파일"),
    limit: float = typer.Option(0.20, "--limit", min=0.0, max=1.0, help="근거를 복원할 수 없는 지점의 비율이 이 값 이상이면 옮기지 않고 다시 점검하게 합니다"),
):
    """
    이전 형식의 보고서를 현재 형식으로 옮깁니다. 지적 없이 '근거 충족'이던 지점은 근거 종류를 복원할 수 없으므로,
    그런 지점이 한도 이상이면 자동으로 옮기지 않고 다시 점검(명시적 재검토)하도록 종료코드 1로 멈춥니다.
    """
    from iron_laws.evidence.verifier import load_json, upgrade_report

    try:
        data = load_json(source)
    except ValueError as e:
        err.print(f"[bold red]입력 오류: {escape(str(e))}[/bold red]")
        raise typer.Exit(2) from e
    result = upgrade_report(data, limit=limit)
    for reason in result.reasons:
        err.print(f"[yellow]{escape(reason)}[/yellow]")
    if not result.ok or result.data is None:
        err.print("[bold red]옮기지 않았습니다. 같은 코드를 다시 점검해 새 보고서를 만드십시오.[/bold red]")
        raise typer.Exit(1)
    output.write_text(json.dumps(result.data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    err.print(f"[green]옮겼습니다: 복원 {result.restored}개, 복원 불가 {result.unrestorable}개 → {output}[/green]")
    err.print("[dim]execution(실행 식별)은 이전 형식에 없어 비어 있으므로 `evidence verify`는 판정 불가로 끝납니다. 근거 확인에는 다시 점검한 보고서를 쓰십시오.[/dim]")


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
        err.print(f"[bold red]규칙을 찾을 수 없습니다: {escape(rule_id)}[/bold red]")
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


def _ensure_utf8_output() -> None:
    """Windows 등 UTF-8이 아닌 출력 인코딩(cp1252·cp949)에서 한글 출력이 UnicodeEncodeError로 죽지 않게 한다."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main():
    _ensure_utf8_output()
    app()


if __name__ == "__main__":
    main()
