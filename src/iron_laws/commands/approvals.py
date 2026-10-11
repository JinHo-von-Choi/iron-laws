"""approvals 명령군."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.markup import escape
from rich.table import Table

from iron_laws.commands.common import (
    ConfigOpt,
    ContractOpt,
    PathArg,
    _build_scanner,
    approvals_app,
    console,
    err,
)
from iron_laws.core.approvals import (
    DEFAULT_APPROVALS_FILE,
    ApprovalStore,
    Record,
    approve_record,
)
from iron_laws.core.config import ConfigError


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
