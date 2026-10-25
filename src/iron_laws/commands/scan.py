"""scan 명령군."""

import json
import sys
from pathlib import Path

import typer
from rich.markup import escape

from iron_laws.commands.common import (
    AllowedSignersOpt,
    AllowEmptyOpt,
    ApprovalsOpt,
    BaselineOpt,
    BuildManifestOpt,
    ChangedSinceOpt,
    ConfigOpt,
    ContractModeOpt,
    ContractOpt,
    FullCoverageOpt,
    GitignoreOpt,
    LimitOpt,
    MaxUnknownOpt,
    MaxUnverifiedOpt,
    MaxWallSecondsOpt,
    MetricsOpt,
    PackageIndexOpt,
    PathArg,
    ReportFormat,
    RequireSignedOpt,
    SearchParentsOpt,
    TriageOpt,
    _build_scanner,
    _check_completion,
    _emit_report,
    _gates,
    _timed_scan,
    _write_or_print,
    app,
    err,
)
from iron_laws.commands.pilot import _pilot_call, _pilot_store
from iron_laws.core.approvals import (
    DEFAULT_APPROVALS_FILE,
)
from iron_laws.core.models import Severity
from iron_laws.reporters.console import DEFAULT_LIMIT, print_console_report
from iron_laws.reporters.prompt import generate_fix_prompt


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
    respect_gitignore: bool | None = GitignoreOpt,
    contract: Path | None = ContractOpt,
    contract_mode: str | None = ContractModeOpt,
    approvals: Path | None = ApprovalsOpt,
    allowed_signers: Path | None = AllowedSignersOpt,
    require_signed_approvals: bool = RequireSignedOpt,
    build_manifest: str | None = BuildManifestOpt,
    require_full_coverage: bool = FullCoverageOpt,
    metrics: Path | None = MetricsOpt,
    max_unknown: float | None = MaxUnknownOpt,
    max_unverified: float | None = MaxUnverifiedOpt,
    max_wall_seconds: float | None = MaxWallSecondsOpt,
    package_index: Path | None = PackageIndexOpt,
    triage_model: str | None = TriageOpt,
):
    """
    프로젝트의 보안 약점과 품질 결함을 신속 진단합니다. (CI/CD 적합)
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore, contract, contract_mode, approvals, gates=_gates(max_unknown, max_unverified), package_index=package_index, max_wall_seconds=max_wall_seconds, allowed_signers=allowed_signers, require_signed_approvals=require_signed_approvals, build_manifest=build_manifest, require_full_coverage=require_full_coverage)
    if fail_on is not None:
        scanner.config.fail_on = fail_on
        scanner.fail_on_source = "명령행 옵션"
    report = _timed_scan(scanner, metrics, "check")
    if triage_model:
        from iron_laws.core.triage import TriageError, apply_triage

        try:
            attached = apply_triage(report, path, triage_model, getattr(scanner, "_secrets", set()))
            err.print(f"[dim]LLM 검토 의견 {attached}건을 붙였습니다(판정은 바꾸지 않았습니다).[/dim]")
        except TriageError as e:
            err.print(f"[yellow]{escape(str(e))} 검토 의견 없이 계속합니다.[/yellow]")
    print_console_report(report, limit)
    _check_completion(report, allow_empty)

    if not report.summary.is_passed:
        if report.summary.contract_mode == "block" and report.summary.contract_status in ("unmet", "policy_change_review"):
            err.print("[bold red]근거 계약을 충족하지 못해 점검이 실패했습니다. 지적이 없어도 요구한 분석 근거가 없으면 통과가 아닙니다.[/bold red]")
        for item in report.summary.gate_exceeded:
            err.print(f"[bold red]신뢰 지표 상한 초과: {escape(item)}. 통과로 세지 않고 사람이 재검토해야 합니다.[/bold red]")
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
        help="출력 형식 (console, markdown, json, sarif, prompt, review, gitlab-codequality, mois-report)",
    ),
    limit: int = typer.Option(DEFAULT_LIMIT, "--limit", min=0, help="console/prompt 형식의 최대 지적 수 (0이면 전부)"),
    allow_empty: bool = AllowEmptyOpt,
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
    baseline: Path | None = BaselineOpt,
    changed_since: str | None = ChangedSinceOpt,
    respect_gitignore: bool | None = GitignoreOpt,
    contract: Path | None = ContractOpt,
    contract_mode: str | None = ContractModeOpt,
    approvals: Path | None = ApprovalsOpt,
    allowed_signers: Path | None = AllowedSignersOpt,
    require_signed_approvals: bool = RequireSignedOpt,
    build_manifest: str | None = BuildManifestOpt,
    require_full_coverage: bool = FullCoverageOpt,
    metrics: Path | None = MetricsOpt,
    max_unknown: float | None = MaxUnknownOpt,
    max_unverified: float | None = MaxUnverifiedOpt,
    max_wall_seconds: float | None = MaxWallSecondsOpt,
    package_index: Path | None = PackageIndexOpt,
    triage_model: str | None = TriageOpt,
):
    """
    점검을 수행하고 보고서를 발행합니다. markdown 보고서에는 행안부 구현단계 49개 항목별 점검 현황이 포함됩니다.
    """
    scanner = _build_scanner(path, config, search_parents, baseline, changed_since, respect_gitignore, contract, contract_mode, approvals, gates=_gates(max_unknown, max_unverified), package_index=package_index, max_wall_seconds=max_wall_seconds, allowed_signers=allowed_signers, require_signed_approvals=require_signed_approvals, build_manifest=build_manifest, require_full_coverage=require_full_coverage)
    report = _timed_scan(scanner, metrics, "audit")
    if triage_model:
        from iron_laws.core.triage import TriageError, apply_triage

        try:
            attached = apply_triage(report, path, triage_model, getattr(scanner, "_secrets", set()))
            err.print(f"[dim]LLM 검토 의견 {attached}건을 붙였습니다(판정은 바꾸지 않았습니다).[/dim]")
        except TriageError as e:
            err.print(f"[yellow]{escape(str(e))} 검토 의견 없이 계속합니다.[/yellow]")
    if report.summary.scan_status == "empty" and not allow_empty:
        _check_completion(report, allow_empty)
    _emit_report(report, scanner, report_format, output, limit)
    if report.summary.scan_status == "incomplete":
        _check_completion(report, allow_empty)
    if report.summary.scan_status == "empty" and allow_empty:
        sys.exit(0)
    sys.exit(0 if report.summary.is_passed else 1)


@app.command("fix-prompt")
def fix_prompt_command(
    path: Path = PathArg,
    output: Path | None = typer.Option(None, "--output", "-o", help="지시문 저장 파일 경로"),
    limit: int = typer.Option(40, "--limit", min=1, help="지시문에 담을 최대 지적 수"),
    config: Path | None = ConfigOpt,
    search_parents: bool = SearchParentsOpt,
    baseline: Path | None = BaselineOpt,
    changed_since: str | None = ChangedSinceOpt,
    respect_gitignore: bool | None = GitignoreOpt,
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


@app.command("review-bundle")
def review_bundle_command(
    path: Path = PathArg,
    approvals: Path | None = typer.Option(None, "--approvals", help="승인 기록 파일(기본 .iron-laws-approvals.jsonl)"),
    allowed_signers: Path | None = AllowedSignersOpt,
    require_signed_approvals: bool = RequireSignedOpt,
    config: Path | None = ConfigOpt,
    contract: Path | None = ContractOpt,
    changed_since: str | None = ChangedSinceOpt,
    fmt: str = typer.Option("markdown", "--format", help="markdown 또는 json"),
    output: Path | None = typer.Option(None, "--output", "-o", help="저장 파일"),
    metrics: Path | None = MetricsOpt,
    pilot_store: Path | None = typer.Option(None, "--pilot-store", help="파일럿 기록 파일. 주면 확인된 오승인·조사 중인 사건이 있을 때 자동 판정 경로를 닫고 필수 행동(종료코드 1)으로 돌립니다"),
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
    scanner = _build_scanner(path, config, False, None, changed_since, None, contract, None, store_path, True, allowed_signers=allowed_signers, require_signed_approvals=require_signed_approvals)
    report = _timed_scan(scanner, metrics, "review-bundle")
    if report.summary.scan_status != "complete":
        err.print("[bold red]점검이 끝까지 이루어지지 않아 검토 묶음이 불완전합니다(미확인을 유지로 보지 않습니다).[/bold red]")
        raise typer.Exit(2)
    command = f"iron-laws review-bundle {path.as_posix()}" + (f" --approvals {store_path.as_posix()}" if approvals else "") + (f" --contract {contract.as_posix()}" if contract else "") + (f" --changed-since {changed_since}" if changed_since else "") + (f" --allowed-signers {allowed_signers.as_posix()}" if allowed_signers else "") + (" --require-signed-approvals" if require_signed_approvals else "")
    bundle = build_bundle(report, scanner.approval_rows, changed_files=scanner.changed_files, command=command, approvals_path=store_path.as_posix() if store_path.exists() else None)
    if pilot_store is not None:
        from iron_laws.core.pilot import summarize

        automation = _pilot_call(summarize, _pilot_store(pilot_store))["automation"]
        if automation != "allowed":
            reason = "파일럿에서 확인된 오승인·위험한 승인 승계가 기록되어" if automation == "manual_review_only" else "파일럿에서 조사 중인 오승인 사건이 있어"
            bundle.actions.append({"kind": "manual_review_required", "target": f"pilot:{automation}", "text": f"{reason} 자동 판정 경로를 수동 검토로 전환하십시오"})
    text = json.dumps(bundle.to_dict(), ensure_ascii=False, indent=2) + "\n" if fmt == "json" else render_markdown(bundle)
    _write_or_print(text.rstrip("\n"), output, "검토 묶음")
    raise typer.Exit(1 if bundle.actions else 0)
