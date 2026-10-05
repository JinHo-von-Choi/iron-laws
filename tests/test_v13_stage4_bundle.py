"""
오철칙 v1.3 4단계(PR-09) 변경 이유와 검토 묶음 수용시험
- 승인 5개 중 2개만 영향을 받으면 재검토 이유 2개와 유지 이유 3개를 모두 볼 수 있어야 한다.
- 해석하지 못한 경계·점검하지 못한 파일·분석 한도는 영향 없음으로 처리하지 않고 공백과 넓힌 재검토 범위로 드러낸다.
- 같은 입력이면 같은 묶음이 나온다(AI 요약을 판정 근거로 쓰지 않는다).
표본은 구현자가 직접 만들었다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.approvals import ApprovalStore, approve_record
from iron_laws.core.config import IronLawsConfig, Limits
from iron_laws.core.review_bundle import build_bundle, render_markdown
from iron_laws.core.scanner import AuditScanner
from iron_laws.verify.engine import resolve_finding

cli = CliRunner()

TOOLS = ("alpha", "beta", "gamma", "delta", "epsilon")


def tool_source(name: str, prefix: str = "ls") -> str:
    return f'import os\nfrom flask import request\n\ndef run_{name}():\n    d = request.args["d"]\n    os.system("{prefix} " + d)\n'


def five(root: Path) -> dict[str, str]:
    files = {f"{name}.py": tool_source(name) for name in TOOLS}
    for rel, text in files.items():
        (root / rel).write_text(text)
    return files


def approve_all(project: Path, store: Path) -> None:
    for name in TOOLS:
        scanner = AuditScanner(project, collect_dependencies=True)
        report = scanner.scan()
        violation = resolve_finding(report, f"IL-504@{name}.py")
        ApprovalStore(store).append(approve_record(violation, f"{name} 도구는 관리자 전용이다", "tester", scanner._approval_policy(), None, None, 3))


def bundle_for(project: Path, store: Path, changed: set[str] | None = None, config=None):
    scanner = AuditScanner(project, approvals=ApprovalStore(store), changed_files=changed, changed_since="HEAD" if changed is not None else None, config=config)
    report = scanner.scan()
    return build_bundle(report, scanner.approval_rows, changed_files=scanner.changed_files, command="iron-laws review-bundle .", approvals_path=store.as_posix()), report


def test_two_of_five_approvals_affected_shows_every_reason(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    (project / "alpha.py").write_text(tool_source("alpha", "ls -R /"))  # 접근 범위가 바뀐다
    (project / "beta.py").write_text(tool_source("beta") + "\ndef helper():\n    return 1\n\ndef extra():\n    return helper()\n")  # 무관한 추가
    (project / "gamma.py").write_text(tool_source("gamma", "find /"))
    bundle, _ = bundle_for(project, store, {"alpha.py", "gamma.py", "beta.py"})
    counts = bundle.counts()
    assert counts["invalidate"] == 2 and counts["keep"] == 3 and counts["undeterminable"] == 0
    changed = {a.location.split(":")[0] for a in bundle.approvals if a.decision == "invalidate"}
    assert changed == {"alpha.py", "gamma.py"}
    for approval in bundle.approvals:
        if approval.decision == "invalidate":
            assert approval.why_changed and any("문자열 상수" in r for r in approval.why_changed)
        else:
            assert len(approval.why_kept) >= 5  # 유지 이유가 전제별로 모두 열려 있다
            assert approval.evidence["finding_id"] and approval.evidence["approved_fingerprint"]
    text = render_markdown(bundle)
    assert "무효화(재검토) (2)" in text and "유지 (3)" in text
    assert text.count("  - 이유:") >= 2 and text.count("  - 유지 근거:") >= 15
    assert any(a["kind"] == "re_review" for a in bundle.actions) and len([a for a in bundle.actions if a["kind"] == "re_review"]) == 2


def test_bundle_is_deterministic(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    (project / "alpha.py").write_text(tool_source("alpha", "ls -R /"))
    first, _ = bundle_for(project, store, {"alpha.py"})
    second, _ = bundle_for(project, store, {"alpha.py"})
    assert json.dumps(first.to_dict(), sort_keys=True, ensure_ascii=False) == json.dumps(second.to_dict(), sort_keys=True, ensure_ascii=False)
    assert render_markdown(first) == render_markdown(second)


def test_no_change_means_no_required_action_and_all_kept(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    bundle, _ = bundle_for(project, store)
    assert bundle.counts()["keep"] == 5 and bundle.actions == []
    assert all(g["kind"] == "unreviewed_findings" for g in bundle.gaps)  # 변경과 무관하게 남은 '확인 필요' 지적만 있다


DISPATCH = (
    "import os\nfrom flask import request\n\nHANDLERS = {}\n\n"
    "def run_dispatch():\n    d = request.args['d']\n    HANDLERS['x'](d)\n    os.system('ls ' + d)\n"
)


def test_dynamic_dispatch_boundary_widens_the_review_scope_when_other_files_change(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    (project / "dispatch.py").write_text(DISPATCH)
    scanner = AuditScanner(project, collect_dependencies=True)
    violation = resolve_finding(scanner.scan(), "IL-504@dispatch.py")
    assert violation.dependencies["dynamic_boundaries"]
    ApprovalStore(store).append(approve_record(violation, "관리자 전용이다", "tester", scanner._approval_policy(), None, None, 3))
    # 변경이 없으면 승인은 유지되지만, 알 수 없는 경계가 남은 공백으로 드러난다
    bundle, _ = bundle_for(project, store)
    assert bundle.counts()["keep"] == 1
    assert any(g["kind"] == "dynamic_boundary" for g in bundle.gaps)
    # 호출 대상이 될 수 있는 다른 파일이 바뀌면 영향 없음으로 보지 않고 재검토 범위를 넓힌다
    (project / "handlers.py").write_text("def h(x):\n    return x\n")
    bundle, _ = bundle_for(project, store, {"handlers.py"})
    assert bundle.counts()["invalidate"] == 1
    assert any("정적으로 알 수 없는" in r for a in bundle.approvals for r in a.why_changed)


def test_unclassified_changed_file_is_a_gap_and_a_required_action_not_no_impact(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    (project / "big.py").write_text("y = 2\n" * 200)
    config = IronLawsConfig(limits=Limits(max_file_bytes=500))
    bundle, report = bundle_for(project, store, {"big.py"}, config=config)
    assert any("big.py" in g["text"] for g in bundle.gaps)
    assert any(a["kind"] == "new_evidence" and "big.py" in a["text"] for a in bundle.actions)
    assert report.coverage_ledger.status == "unmet"


def test_missing_target_file_is_undeterminable_not_resolved(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    (project / "delta.py").unlink()
    bundle, _ = bundle_for(project, store, {"delta.py"})
    decision = next(a for a in bundle.approvals if a.location.startswith("delta.py"))
    assert decision.decision in ("undeterminable", "resolved")
    if decision.decision == "undeterminable":
        assert any(a["kind"] == "confirm_target" for a in bundle.actions)


def test_policy_change_is_listed_as_a_changed_premise(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    (project / ".iron-laws.yml").write_text("fail_on: CRITICAL\n")
    bundle, _ = bundle_for(project, store)
    assert any(c["kind"] == "policy" and "점검 설정" in c["subject"] for c in bundle.changed_premises)
    assert bundle.counts()["invalidate"] == 5  # 정책이 바뀌면 모든 승인이 다시 검토 대상이다


def test_cli_exit_codes_and_json(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    store = tmp_path / "s.jsonl"
    five(project)
    approve_all(project, store)
    ok = cli.invoke(app, ["review-bundle", str(project), "--approvals", str(store), "--format", "json"])
    assert ok.exit_code == 0
    payload = json.loads(ok.stdout)
    assert payload["schema"] == "iron-laws.review-bundle/1" and payload["counts"]["keep"] == 5
    (project / "alpha.py").write_text(tool_source("alpha", "ls -R /"))
    needs = cli.invoke(app, ["review-bundle", str(project), "--approvals", str(store)])
    assert needs.exit_code == 1 and "무효화(재검토) (1)" in needs.stdout
    out = tmp_path / "bundle.md"
    saved = cli.invoke(app, ["review-bundle", str(project), "--approvals", str(store), "-o", str(out)])
    assert saved.exit_code == 1 and out.read_text().startswith("# 검토 묶음")
    assert cli.invoke(app, ["review-bundle", str(project), "--format", "yaml"]).exit_code == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.invoke(app, ["review-bundle", str(empty), "--approvals", str(store)]).exit_code == 2  # 점검 대상이 없으면 불완전


def test_baseline_findings_are_not_counted_as_approvals(tmp_path: Path):
    from iron_laws.core.baseline import build_baseline

    project = tmp_path / "proj"
    project.mkdir()
    five(project)
    report = AuditScanner(project).scan()
    baseline = build_baseline(report, "1.3.0")
    scanner = AuditScanner(project, baseline=baseline, approvals=ApprovalStore(tmp_path / "empty.jsonl"))
    result = scanner.scan()
    assert result.summary.approvals_valid == 0
    assert all(v.approval_status != "approved" for v in result.violations)
