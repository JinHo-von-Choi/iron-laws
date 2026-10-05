"""
v1.4 실증 측정의 탐침: 표준 입력으로 작업을 받아 지금 경로의 오철칙(PYTHONPATH가 가리키는 소스)으로 실행하고 JSON을 돌려준다.
같은 탐침을 v1.3.0 소스와 현재 소스에 각각 붙여 같은 표본의 결과를 비교한다. 두 버전에 공통인 공개 API만 쓴다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode("utf-8"))


def job_ledger(job: dict) -> dict:
    from iron_laws.core.scanner import AuditScanner
    from iron_laws.evidence.verifier import verify_report

    root = Path(tempfile.mkdtemp(prefix="il-probe-"))
    _write(root, job["files"])
    report = AuditScanner(root).scan()
    points = [{"line": p.line, "column": p.column, "family": p.family, "state": p.state, "findings": len(p.finding_ids)} for p in report.coverage_ledger.points]
    verification = verify_report(report.model_dump(mode="json"))
    return {"points": points, "findings": len(report.violations), "verifier_ok": verification.ok, "status": report.summary.scan_status}


def job_suppress(job: dict) -> dict:
    from iron_laws.core.suppress import parse_suppressions
    from iron_laws.engine.source import SourceFile

    return {"directives": len(parse_suppressions(SourceFile(Path(job["filename"]), job["text"])).directives)}


def job_scan_rules(job: dict) -> dict:
    from iron_laws.core.scanner import AuditScanner

    root = Path(tempfile.mkdtemp(prefix="il-probe-"))
    _write(root, job["files"])
    report = AuditScanner(root).scan()
    return {"findings": [[v.rule_id, v.confidence.value] for v in report.violations]}


def job_leak(job: dict) -> dict:
    from typer.testing import CliRunner

    from iron_laws.cli import app

    root = Path(tempfile.mkdtemp(prefix="il-probe-"))
    _write(root, job["files"])
    runner = CliRunner()
    leaked: dict[str, list[str]] = {}
    for fmt in job["formats"]:
        result = runner.invoke(app, ["audit", str(root), "--format", fmt, "--limit", "0"])
        text = result.stdout + result.stderr
        leaked[fmt] = [f for f in job["fragments"] if f in text]
    return {"leaked": leaked}


def _git(root: Path, *args: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True, env=env)


def job_scope(job: dict) -> dict:
    """승인한 뒤 변경(이동·이동과 수정·복제)을 커밋하고 전체 점검·변경 점검·검토 묶음의 종료코드를 돌려준다."""
    from typer.testing import CliRunner

    from iron_laws.cli import app
    from iron_laws.core.approvals import ApprovalStore, approve_record
    from iron_laws.core.scanner import AuditScanner
    from iron_laws.verify.engine import resolve_finding

    base = Path(tempfile.mkdtemp(prefix="il-probe-"))
    root = base / "proj"
    root.mkdir()
    _write(root, job["files"])
    _git(root, "init", "-q")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    store = base / "ap.jsonl"
    scanner = AuditScanner(root, collect_dependencies=True)
    report = scanner.scan()
    violation = resolve_finding(report, job["finding"])
    ApprovalStore(store).append(approve_record(violation, "내부 관리자 화면이며 입력이 사전 검증된다", "tester", scanner._approval_policy(), None, None, 5))
    for step in job["changes"]:
        if step["op"] == "mv":
            (root / step["to"]).parent.mkdir(parents=True, exist_ok=True)
            _git(root, "mv", step["from"], step["to"])
        elif step["op"] == "write":
            _write(root, {step["path"]: step["text"]})
        elif step["op"] == "replace":
            path = root / step["path"]
            path.write_text(path.read_text().replace(step["old"], step["new"]))
        _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    runner = CliRunner()
    codes = {}
    for label, args in (
        ("full", ["check", str(root), "--approvals", str(store)]),
        ("changed", ["check", str(root), "--approvals", str(store), "--changed-since", "HEAD~1"]),
        ("bundle_full", ["review-bundle", str(root), "--approvals", str(store), "--format", "json"]),
        ("bundle_changed", ["review-bundle", str(root), "--approvals", str(store), "--changed-since", "HEAD~1", "--format", "json"]),
    ):
        codes[label] = runner.invoke(app, args).exit_code
    return {"exit_codes": codes}


def job_pilot(job: dict) -> dict:
    from iron_laws.core.pilot import PilotStore, assign, record_review, summarize

    store = PilotStore(Path(tempfile.mkdtemp(prefix="il-probe-")) / "p.jsonl")
    for team in ("a", "b", "c"):
        for i in range(job["per_team"]):
            arm = assign(store, team, f"{team}-{i}", "medium", 1)["arm"]
            minutes, overhead = job["baseline"] if arm == "baseline" else job["bundle"]
            record_review(store, f"{team}-{i}", minutes, setup_minutes=10 if i == 0 else 0, overhead_minutes=overhead)
    result = summarize(store)
    return {"verdict": result["verdict"], "checks": result["checks"]}


JOBS = {"ledger": job_ledger, "suppress": job_suppress, "scan_rules": job_scan_rules, "leak": job_leak, "scope": job_scope, "pilot": job_pilot}


def main() -> None:
    job = json.load(sys.stdin)
    out = [JOBS[item["kind"]](item) for item in job["items"]]
    sys.stdout.write(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()
