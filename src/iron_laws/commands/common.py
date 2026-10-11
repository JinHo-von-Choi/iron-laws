"""
오철칙 (Iron Laws) CLI Application
작성자: 최진호
작성일: 2026-10-04
"""

import subprocess
import sys
import time
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from iron_laws.core.approvals import (
    ApprovalStore,
)
from iron_laws.core.baseline import (
    Baseline,
    load_baseline,
)
from iron_laws.core.config import ConfigError, InputPathError
from iron_laws.core.contract import load_contract
from iron_laws.core.models import AuditReport
from iron_laws.core.scan_options import ScanOptions
from iron_laws.core.scanner import AuditScanner, tool_version
from iron_laws.reporters.console import DEFAULT_LIMIT, print_console_report
from iron_laws.reporters.json_reporter import generate_json_report
from iron_laws.reporters.markdown import generate_markdown_report
from iron_laws.reporters.prompt import generate_fix_prompt
from iron_laws.reporters.review import generate_review_report
from iron_laws.reporters.sarif import generate_sarif_report

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


MaxUnknownOpt = typer.Option(
    None,
    "--max-analysis-unknown-rate",
    min=0.0,
    max=1.0,
    help="계약 범위 안 보안 관심 지점 중 해석 미확정·미지원·예산 초과 비율의 상한(0~1). 넘으면 통과가 아니라 재검토로 판정합니다",
)
MaxUnverifiedOpt = typer.Option(
    None,
    "--max-unverified-rule-language-rate",
    min=0.0,
    max=1.0,
    help="이번 점검에 적용된 (규칙, 언어) 조합 중 양성·음성 시험이 모두 있지 않은 조합 비율의 상한(0~1). 넘으면 통과가 아니라 재검토로 판정합니다",
)


def _gates(max_unknown: float | None, max_unverified: float | None) -> dict[str, float] | None:
    gates = {k: v for k, v in (("max_analysis_unknown_rate", max_unknown), ("max_unverified_rule_language_rate", max_unverified)) if v is not None}
    return gates or None


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


def _renamed_paths(root: Path, ref: str) -> list[tuple[str, str]]:
    """ref 이후 이름이 바뀐(옮겨진) 파일의 (이전 경로, 새 경로). 점검 루트 기준 상대 경로이며, 둘 다 루트 안에 있을 때만 돌려준다.
    승인·보고서·검토 묶음이 같은 범위 계약을 쓰도록 변경 파일 목록과 함께 보고서에 남긴다."""
    folder = root if root.is_dir() else root.parent
    top = Path(_git(["rev-parse", "--show-toplevel"], folder).decode("utf-8", errors="surrogateescape").strip())
    fields = _nul_paths(_git(["diff", "--name-status", "-z", "-M", "--diff-filter=R", ref, "--"], folder))
    base = root.resolve() if root.is_dir() else root.resolve().parent
    pairs: list[tuple[str, str]] = []
    for index in range(0, len(fields) - 2, 3):  # `R100 이전 새` 세 칸이 한 항목이다
        try:
            old = (top / fields[index + 1]).resolve().relative_to(base).as_posix()
            new = (top / fields[index + 2]).resolve().relative_to(base).as_posix()
        except ValueError:
            continue
        pairs.append((old, new))
    return sorted(pairs)


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
    gates: dict[str, float] | None = None,
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
            loaded_contract.mode = "block" if contract_mode == "block" else "report"
        loaded: Baseline | None = load_baseline(baseline) if baseline else None
        changed = _changed_files(path, changed_since) if changed_since else None
        renames = _renamed_paths(path, changed_since) if changed_since else None
        options = ScanOptions(
            root_path=path,
            config_path=config,
            search_parents=search_parents,
            baseline=loaded,
            changed_files=changed,
            changed_since=changed_since,
            renames=renames,
            gates=gates,
            respect_gitignore=respect_gitignore,
            contract=loaded_contract,
            contract_source=(str(contract) if contract else "기본값") + (f" (모드 {contract_mode}는 명령행)" if contract_mode else ""),
            contract_path=contract,
            approvals=ApprovalStore(approvals) if approvals else None,
            collect_dependencies=collect_dependencies,
        )
        return AuditScanner.from_options(options)
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
