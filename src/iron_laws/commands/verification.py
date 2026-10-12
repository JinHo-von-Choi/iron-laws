"""verification 명령군."""

import json
import sys
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from iron_laws.commands.common import (
    ConfigOpt,
    _build_scanner,
    _write_or_print,
    app,
    console,
    err,
    evidence_app,
    regression_app,
)
from iron_laws.core.config import ConfigError


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
    sign: str | None = typer.Option(None, "--sign", help="검증 기록에 서명합니다: ssh:<개인키 경로>. --out 파일 옆에 .sig를 남깁니다"),
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
    delta = receipt.debt_delta
    if delta.get("status") == "compared":
        totals = delta["totals"]
        console.print(f"[bold]수정이 만든 부채(다섯 습관, 표시만 하며 판정에 쓰지 않음)[/bold] 해결 {totals['resolved']} · 유지 {totals['maintained']} · 신규 {totals['new']} · 이동 {totals['moved']} · 판정 불가 {totals['undetermined']}")
        for row in delta["fix_adjacent_new"]:
            console.print(f"  - [yellow]수정 지점과 같은 함수에 새 부채[/yellow] {escape(row['habit'])} {escape(row['rule'])} {escape(row['path'])}:{row['line']} ({escape(row['scope'])})")
    cleanup = receipt.environment.get("workspace_cleanup", {})
    if cleanup.get("complete") is False:
        err.print("[bold yellow]작업영역 정리 경고[/bold yellow]")
        for note in cleanup.get("notes", []):
            err.print(f"  - {escape(note)}")
    for check in receipt.checks:
        for side in ("original", "candidate"):
            for note in check.evidence.get(side, {}).get("notes", []):
                err.print(f"[yellow]{escape(side)} 실행 경고: {escape(note)}[/yellow]")
    console.print(f"[bold]종합: {receipt.verdict.label}[/bold]  (기록 해시 {receipt.receipt_digest})")
    console.print(f"[dim]{receipt.verdict.caveat}[/dim]")
    if out:
        out.write_text(receipt.model_dump_json(indent=2) + "\n", encoding="utf-8")
        err.print(f"[green]검증 기록 저장: {out}[/green]")
        if sign:
            from iron_laws.evidence.signing import SigningError, sign_file

            try:
                sig = sign_file(out, Path(sign.removeprefix("ssh:")))
            except SigningError as e:
                err.print(f"[bold red]서명 오류: {escape(str(e))}[/bold red]")
                raise typer.Exit(2) from e
            err.print(f"[green]서명 저장: {sig}[/green]")
    elif sign:
        err.print("[bold red]--sign은 --out으로 기록 파일을 남길 때만 쓸 수 있습니다.[/bold red]")
        raise typer.Exit(2)
    raise typer.Exit({"verified": 0, "failed": 1, "undeterminable": 2}[receipt.verdict.overall])


@evidence_app.command("verify")
def evidence_verify_command(
    target: Path = typer.Argument(..., help="점검 보고서(audit --format json) 또는 검증 기록(verify-patch --out) 파일"),
    report: Path | None = typer.Option(None, "--report", help="검증 기록을 검증할 때 함께 대조할 점검 보고서"),
    checkout: Path | None = typer.Option(None, "--checkout", help="다른 checkout 폴더. 주면 그 코드의 지문이 보고서가 점검한 코드와 같은지 다시 계산합니다"),
    as_of: str | None = typer.Option(None, "--as-of", help="승인 만료 판단 기준일(YYYY-MM-DD). 기본은 오늘"),
    json_output: bool = typer.Option(False, "--json", help="JSON으로 출력"),
    allowed_signers: Path | None = typer.Option(None, "--allowed-signers", help="OpenSSH 허용 서명자 목록. 주면 대상 파일 옆의 .sig 서명도 확인합니다(없거나 맞지 않으면 모순으로 셉니다)"),
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
    if allowed_signers is not None:
        from iron_laws.evidence.signing import SigningError, verify_file
        from iron_laws.evidence.verifier import Problem

        try:
            signer = verify_file(target, allowed_signers)
            result.notes.append(f"서명 확인: {signer}")
        except SigningError as e:
            result.problems.append(Problem("signature.invalid", str(e)))
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
