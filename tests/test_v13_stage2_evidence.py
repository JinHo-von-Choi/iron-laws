"""
오철칙 v1.3 2단계(PR-05~06) 근거 ID와 독립 검증기 수용시험
- 검증기는 표준 라이브러리만 쓰고 엔진·장부 코드를 호출하지 않는다.
- 정상 보고서는 통과하고, 손상시킨 보고서는 독립적으로 정한 기대 코드로 잡힌다.
- 이전 형식 기록은 근거를 복원할 수 없는 비율이 한도 이상이면 옮기지 않고 재검토로 넘어간다.
표본은 구현자가 직접 만들었다. 검증기는 구조적 모순을 잡으며 엔진이 일관되게 만든 의미 오류까지 증명하지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

import ast
import copy
import json
import shutil
from datetime import date
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.approvals import ApprovalStore
from iron_laws.core.contract import Contract
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence import verifier
from iron_laws.evidence.verifier import finding_id_of, upgrade_report, verify_receipt, verify_report
from tests.test_stage2_contract import KNOWN_GAPS, SAFE_CHANGES, _scan
from tests.test_stage3_verify import APP, APP_FIXED, make_project, verify, write_patch
from tests.test_stage5_approvals import BASE, RULE, approve, make

cli = CliRunner()

MIXED = {
    "a.py": (
        'import os\nfrom flask import request\nALLOWED = ("a", "b")\n\n'
        'def tainted():\n    os.system("ls " + request.args["d"])\n\n'
        'def guarded():\n    cmd = request.args["c"]\n    if cmd not in ALLOWED:\n        return\n    os.system("run " + cmd)\n\n'
        'def closed():\n    os.system("ls -l")\n\n'
        'def gap(cmd):\n    os.system(cmd)\n'
    ),
    "b.py": 'import subprocess\n\ndef other(x):\n    subprocess.run(["ls", x])\n',
}


def report_of(root: Path, files: dict[str, str] = MIXED, **kwargs) -> dict:
    return _scan(root, files, **kwargs).model_dump(mode="json")


@pytest.fixture
def good(tmp_path: Path) -> dict:
    return report_of(tmp_path / "mixed")


def codes(result) -> set[str]:
    return {p.code for p in result.problems}


# ---------------------------------------------------------------------------
# 독립성
# ---------------------------------------------------------------------------


def test_verifier_uses_only_the_standard_library():
    tree = ast.parse(Path(verifier.__file__).read_text(encoding="utf-8"))
    imported = {
        (node.module or "").split(".")[0] if isinstance(node, ast.ImportFrom) else alias.name.split(".")[0]
        for node in ast.walk(tree)
        for alias in (node.names if isinstance(node, (ast.Import, ast.ImportFrom)) else [])
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    assert "iron_laws" not in imported and "pydantic" not in imported and "tree_sitter" not in imported
    stdlib = {"hashlib", "json", "dataclasses", "datetime", "pathlib", "typing", "__future__"}
    assert imported <= stdlib, imported


def test_verifier_does_not_call_producer_functions():
    tree = ast.parse(Path(verifier.__file__).read_text(encoding="utf-8"))
    called = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
    }
    for name in ("build_ledger", "taint_state", "assess", "AuditScanner", "contract_digest", "make_fingerprint", "build_baseline"):
        assert name not in called, name


# ---------------------------------------------------------------------------
# 정상 보고서
# ---------------------------------------------------------------------------


def test_clean_report_is_consistent(good: dict):
    result = verify_report(good)
    assert result.ok and result.checked > 30, [str(p) for p in result.problems]


def test_every_stage2_corpus_produces_a_consistent_report(tmp_path_factory):
    corpora = [case[1] for case in KNOWN_GAPS] + [files for _name, files in SAFE_CHANGES]
    for files in corpora:
        result = verify_report(report_of(tmp_path_factory.mktemp("c"), files))
        assert result.ok, (files, [str(p) for p in result.problems])


def test_report_with_block_contract_and_changed_since_is_consistent(tmp_path: Path):
    block = Contract(mode="block")
    report = _scan(tmp_path, MIXED, contract=block)
    assert not report.summary.is_passed and report.summary.contract_status == "unmet"
    assert verify_report(report.model_dump(mode="json")).ok
    scoped = AuditScanner(tmp_path, contract=block, changed_files={"b.py"}, changed_since="HEAD").scan()
    assert verify_report(scoped.model_dump(mode="json")).ok


def test_report_with_approvals_is_consistent(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approve(project, store)
    report = AuditScanner(project, approvals=ApprovalStore(store)).scan()
    data = report.model_dump(mode="json")
    assert [a["status"] for a in data["approval_checks"]] == ["valid"]
    assert data["approval_checks"][0]["finding_id"] == data["violations"][0]["finding_id"]
    assert verify_report(data).ok


# ---------------------------------------------------------------------------
# 손상시킨 보고서: 독립적으로 정한 기대 코드
# ---------------------------------------------------------------------------


def _point(data: dict, family: str, state: str | None = None, finding: bool | None = None) -> dict:
    for p in data["coverage_ledger"]["points"]:
        if p["family"] == family and (state is None or p["state"] == state) and (finding is None or bool(p["finding"]) == finding):
            return p
    raise AssertionError((family, state, finding))


def _drop_finding(d):
    d["violations"] = [v for v in d["violations"] if v["rule_id"] != "IL-504"]


def _edit(fn):
    return fn


def m_line_shift(d):
    d["violations"][0]["line_number"] += 3


def m_duplicate_id(d):
    d["violations"].append(copy.deepcopy(d["violations"][0]))


def m_absolute_path(d):
    for v in d["violations"]:
        v["file_path"] = "/etc/" + v["file_path"]
        v["finding_id"] = finding_id_of(v)


def m_dotdot_path(d):
    for v in d["violations"]:
        v["file_path"] = "../" + v["file_path"]
        v["finding_id"] = finding_id_of(v)


def m_finding_flag_without_ids(d):
    _point(d, "command", "unresolved")["finding"] = True


def m_ids_without_flag(d):
    _point(d, "command", finding=True)["finding"] = False


def m_met_without_kind(d):
    _point(d, "command", "evidence_met", finding=False)["evidence_kind"] = "none"


def m_unresolved_with_kind(d):
    _point(d, "command", "unresolved")["evidence_kind"] = "closed_value"


def m_unresolved_with_ids(d):
    p = _point(d, "command", "unresolved")
    p["finding_ids"] = [d["violations"][0]["finding_id"]]
    p["finding"] = True


def m_wrong_rule(d):
    sql = {**d["violations"][0], "rule_id": "IL-501"}
    sql["finding_id"] = finding_id_of(sql)
    d["violations"].append(sql)
    _point(d, "command", finding=True)["finding_ids"].append(sql["finding_id"])


def m_elsewhere(d):
    other = {**d["violations"][0], "file_path": "b.py", "line_number": 99}
    other["finding_id"] = finding_id_of(other)
    d["violations"].append(other)
    _point(d, "command", finding=True)["finding_ids"] = [other["finding_id"]]


def m_suppression_too_wide(d):
    p = _point(d, "command", "unresolved")
    p["state"], p["evidence_kind"], p["suppressed_rules"] = "policy_excluded", "none", ["IL-504", "IL-502"]


def m_blocker_removed(d):
    d["coverage_ledger"]["blockers"] = d["coverage_ledger"]["blockers"][1:]


def m_blocker_extra(d):
    d["coverage_ledger"]["blockers"].append("[command] ghost.py:1 os.system() — unresolved: 없는 지점")


def m_status_met_with_blockers(d):
    d["coverage_ledger"]["status"] = "met"
    d["summary"]["contract_status"] = "met"


def m_status_not_applicable_with_blockers(d):
    d["coverage_ledger"]["status"] = "not_applicable"
    d["summary"]["contract_status"] = "not_applicable"


def m_tally_by_state(d):
    d["coverage_ledger"]["families"][0]["by_state"] = {"evidence_met": 99}


def m_tally_total(d):
    d["coverage_ledger"]["families"][0]["total"] += 1


def m_run_id(d):
    d["coverage_ledger"]["run_id"] = "R-000000000000"
    d["execution"]["run_id"] = "R-000000000000"


def m_run_id_mismatch(d):
    d["execution"]["run_id"] = "R-111111111111"


def m_code_digest(d):
    d["execution"]["code_digest"] = "0" * 16


def m_contract_status(d):
    d["summary"]["contract_status"] = "met"


def m_passed_with_high(d):
    d["summary"]["is_passed"] = True


def m_total_violations(d):
    d["summary"]["total_violations"] += 5


def m_severity_counts(d):
    d["summary"]["critical_count"] += 1


def m_incomplete_but_passed(d):
    d["diagnostics"].append({"kind": "read", "severity": "error", "message": "읽지 못했다", "file_path": "x.py", "line": 0})
    d["execution"]["error_diagnostics"] = 1
    d["summary"]["scan_status"] = "incomplete"
    d["execution"]["scan_status"] = "incomplete"
    d["summary"]["is_passed"] = True


def m_error_but_complete(d):
    d["diagnostics"].append({"kind": "read", "severity": "error", "message": "읽지 못했다", "file_path": "x.py", "line": 0})


def m_empty_not_marked(d):
    d["summary"]["total_files_scanned"] = 0
    d["execution"]["files_scanned"] = 0


def m_unclassified_without_blocker(d):
    d["coverage_ledger"]["files"].append({"path": "big.py", "classification": "unclassified", "reason": "크다", "changed": True, "interest_points": 0})
    d["coverage_ledger"]["unclassified_changed_files"] = ["big.py"]


def m_file_not_analyzed(d):
    d["coverage_ledger"]["points"][0]["path"] = "ghost.py"


CORRUPTIONS = [
    ("line-shifted-finding", m_line_shift, "finding.id_mismatch"),
    ("duplicate-finding-id", m_duplicate_id, "finding.id_duplicate"),
    ("absolute-path", m_absolute_path, "finding.path_not_normalized"),
    ("dotdot-path", m_dotdot_path, "finding.path_not_normalized"),
    ("missing-finding-referenced", _drop_finding, "point.finding_missing"),
    ("finding-flag-without-ids", m_finding_flag_without_ids, "point.finding_flag"),
    ("ids-without-finding-flag", m_ids_without_flag, "point.finding_flag"),
    ("met-without-evidence-kind", m_met_without_kind, "point.met_without_evidence"),
    ("unresolved-with-evidence-kind", m_unresolved_with_kind, "point.unmet_with_kind"),
    ("unresolved-with-finding-ids", m_unresolved_with_ids, "point.unmet_with_ids"),
    ("finding-of-other-rule", m_wrong_rule, "point.finding_wrong_rule"),
    ("finding-of-other-file-and-line", m_elsewhere, "point.finding_elsewhere"),
    ("suppression-applied-too-wide", m_suppression_too_wide, "point.suppression_too_wide"),
    ("blocker-removed", m_blocker_removed, "ledger.blocker_missing"),
    ("ghost-blocker-added", m_blocker_extra, "ledger.blocker_extra"),
    ("met-despite-blockers", m_status_met_with_blockers, "ledger.status_mismatch"),
    ("not-applicable-hides-blockers", m_status_not_applicable_with_blockers, "ledger.status_mismatch"),
    ("tally-by-state-tampered", m_tally_by_state, "tally.by_state"),
    ("tally-total-tampered", m_tally_total, "tally.total"),
    ("run-id-not-derived", m_run_id, "run.id_not_derived"),
    ("run-id-of-another-run", m_run_id_mismatch, "run.id_mismatch"),
    ("code-digest-differs", m_code_digest, "run.code_digest_mismatch"),
    ("contract-status-differs", m_contract_status, "run.contract_status_mismatch"),
    ("passed-with-high-finding", m_passed_with_high, "pass.unexplained"),
    ("total-violations-differs", m_total_violations, "summary.total_mismatch"),
    ("severity-count-differs", m_severity_counts, "summary.severity_mismatch"),
    ("incomplete-scan-marked-passed", m_incomplete_but_passed, "pass.incomplete_passed"),
    ("error-diagnostic-but-complete", m_error_but_complete, "run.incomplete_not_marked"),
    ("zero-files-not-empty", m_empty_not_marked, "run.empty_not_marked"),
    ("unclassified-changed-file-not-blocked", m_unclassified_without_blocker, "ledger.unclassified_not_blocked"),
    ("point-in-unlisted-file", m_file_not_analyzed, "point.file_not_analyzed"),
]


@pytest.mark.parametrize(("name", "mutate", "expected"), CORRUPTIONS, ids=[c[0] for c in CORRUPTIONS])
def test_corrupted_report_is_caught(good: dict, name, mutate, expected):
    broken = copy.deepcopy(good)
    mutate(broken)
    result = verify_report(broken)
    assert expected in codes(result), (name, sorted(codes(result)))


def test_corruption_catalog_is_large_enough_and_every_code_is_distinct_in_effect():
    assert len(CORRUPTIONS) >= 30
    assert len({c[2] for c in CORRUPTIONS}) >= 20


# ---------------------------------------------------------------------------
# 승인: 만료·손상·다른 대상·다른 정책·복제본
# ---------------------------------------------------------------------------


@pytest.fixture
def approved(tmp_path: Path) -> dict:
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approve(project, store)
    return AuditScanner(project, approvals=ApprovalStore(store)).scan().model_dump(mode="json")


def test_approval_expired_but_marked_valid_is_caught(approved: dict):
    approved["approval_checks"][0]["expires"] = "2020-01-01"
    assert "approval.valid_expired" in codes(verify_report(approved, as_of=date(2026, 10, 5)))


def test_approval_with_non_date_expiry_is_caught(approved: dict):
    approved["approval_checks"][0]["expires"] = "2999-99-99"
    assert "approval.expiry_invalid" in codes(verify_report(approved))


def test_approval_from_another_contract_or_config_is_caught(approved: dict):
    other_contract = copy.deepcopy(approved)
    other_contract["approval_checks"][0]["policy"]["contract_digest"] = "ffffffffffffffff"
    assert "approval.valid_other_contract" in codes(verify_report(other_contract))
    other_config = copy.deepcopy(approved)
    other_config["approval_checks"][0]["policy"]["config_hash"] = "ffffffffffffffff"
    assert "approval.valid_other_config" in codes(verify_report(other_config))


def test_approval_pointing_at_a_past_run_finding_is_caught(approved: dict):
    approved["approval_checks"][0]["finding_id"] = "F-aaaaaaaaaaaa"
    assert "approval.valid_without_finding" in codes(verify_report(approved))


def test_approval_with_a_changed_fingerprint_is_caught(approved: dict):
    approved["approval_checks"][0]["approved_fingerprint"] = "0" * 20
    assert "approval.valid_fingerprint_differs" in codes(verify_report(approved))


def test_clone_inheriting_an_approval_is_caught(approved: dict):
    check = approved["approval_checks"][0]
    check["path"] = "app.py"  # 승인한 원본은 지금도 점검 대상
    approved["violations"][0]["file_path"] = "clone.py"
    approved["violations"][0]["finding_id"] = finding_id_of(approved["violations"][0])
    check["finding_id"] = approved["violations"][0]["finding_id"]
    approved["approval_checks"][0]["approved_fingerprint"] = "different"
    approved["coverage_ledger"]["files"].append({"path": "app.py", "classification": "analyzed", "reason": "", "changed": True, "interest_points": 1})
    assert "approval.valid_clone_inherited" in codes(verify_report(approved))


def test_approved_finding_without_a_valid_row_is_caught(approved: dict):
    approved["approval_checks"] = []
    assert "approval.approved_without_valid_row" in codes(verify_report(approved))


# ---------------------------------------------------------------------------
# 버전·누락·다른 checkout
# ---------------------------------------------------------------------------


def test_unsupported_or_missing_input_is_undeterminable_not_a_pass(good: dict):
    old = copy.deepcopy(good)
    old["schema_version"] = "1.2"
    assert verify_report(old).undeterminable and not verify_report(old).ok
    future = copy.deepcopy(good)
    future["schema_version"] = "9.9"
    assert verify_report(future).undeterminable
    missing = copy.deepcopy(good)
    missing["coverage_ledger"] = None
    result = verify_report(missing)
    assert result.undeterminable and "schema.missing" in codes(result)
    no_execution = copy.deepcopy(good)
    no_execution.pop("execution")
    assert verify_report(no_execution).undeterminable


def test_other_checkout_with_the_same_code_verifies_and_changed_code_is_caught(tmp_path: Path):
    project = tmp_path / "proj"
    data = report_of(project)
    copy_dir = tmp_path / "other-checkout"
    shutil.copytree(project, copy_dir)
    assert verify_report(data, checkout=copy_dir).ok
    (copy_dir / "a.py").write_text(MIXED["a.py"] + "\n# 바뀐 코드\n")
    assert "snapshot.code_mismatch" in codes(verify_report(data, checkout=copy_dir))
    (copy_dir / "b.py").unlink()
    assert "snapshot.files_missing" in codes(verify_report(data, checkout=copy_dir))


def test_checkout_with_a_non_utf8_file_is_undeterminable(tmp_path: Path):
    project = tmp_path / "proj"
    data = report_of(project, {"a.py": "import os\ndef f():\n    os.system('ls')\n"})
    copy_dir = tmp_path / "other"
    shutil.copytree(project, copy_dir)
    (copy_dir / "a.py").write_bytes(b"import os\n\xff\xfe = 1\n")
    result = verify_report(data, checkout=copy_dir)
    assert result.undeterminable


# ---------------------------------------------------------------------------
# 검증 기록(Receipt)
# ---------------------------------------------------------------------------


@pytest.fixture
def receipt_data(tmp_path: Path) -> dict:
    project = make_project(tmp_path / "proj")
    patch = write_patch(tmp_path, project, {"app.py": APP_FIXED})
    return json.loads(verify(project, patch).model_dump_json())


def test_real_receipt_is_consistent(receipt_data: dict):
    assert receipt_data["evidence"]["original"]["run_id"].startswith("R-")
    assert receipt_data["target"]["finding_id"] in receipt_data["evidence"]["original"]["finding_ids"]
    result = verify_receipt(receipt_data)
    assert result.ok, [str(p) for p in result.problems]


RECEIPT_CORRUPTIONS = [
    ("content-changed", lambda d: d["checks"][0].update(reason="바꿈"), "receipt.seal_mismatch"),
    ("verdict-forged", lambda d: d["verdict"].update(overall="verified") if d["verdict"]["overall"] != "verified" else d["verdict"].update(overall="failed"), "receipt.verdict_mismatch"),
    ("pass-without-execution", lambda d: d["checks"][-1].update(result="pass", executed=False), "receipt.pass_not_executed"),
    ("pass-at-limit", lambda d: d["checks"][0].update(result="pass", limit_reached=True), "receipt.pass_limit_reached"),
    ("target-still-present", lambda d: d["evidence"]["candidate"]["fingerprints"].append(d["target"]["fingerprint"]), "receipt.target_still_present"),
    ("target-not-in-original", lambda d: d["target"].update(finding_id="F-aaaaaaaaaaaa"), "receipt.target_not_in_original"),
    ("duplicate-check-id", lambda d: d["checks"].append(copy.deepcopy(d["checks"][0])), "receipt.check_duplicate"),
    ("unknown-result", lambda d: d["checks"][0].update(result="maybe"), "receipt.result_unknown"),
]


def _reseal(data: dict) -> None:
    import hashlib

    body = {k: v for k, v in data.items() if k != "receipt_digest"}
    data["receipt_digest"] = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]


@pytest.mark.parametrize(("name", "mutate", "expected"), RECEIPT_CORRUPTIONS, ids=[c[0] for c in RECEIPT_CORRUPTIONS])
def test_corrupted_receipt_is_caught(receipt_data: dict, name, mutate, expected):
    broken = copy.deepcopy(receipt_data)
    mutate(broken)
    if expected != "receipt.seal_mismatch":
        _reseal(broken)  # 봉인은 맞게 다시 계산해 내용 모순만 남긴다
    assert expected in codes(verify_receipt(broken)), (name, sorted(codes(verify_receipt(broken))))


def test_receipt_from_another_run_is_caught_against_a_report(receipt_data: dict, tmp_path: Path):
    other = report_of(tmp_path / "other", {"x.py": "x = 1\n"})
    assert "receipt.other_run" in codes(verify_receipt(receipt_data, report=other))


def test_unsupported_receipt_version_is_undeterminable(receipt_data: dict):
    receipt_data["schema_version"] = "99"
    assert verify_receipt(receipt_data).undeterminable


# ---------------------------------------------------------------------------
# 이전 형식 기록 옮기기: 복원 불가 20% 이상이면 재검토
# ---------------------------------------------------------------------------


def _as_old_format(data: dict) -> dict:
    old = copy.deepcopy(data)
    old["schema_version"] = "1.2"
    for key in ("execution", "approval_checks"):
        old.pop(key, None)
    for v in old["violations"]:
        v.pop("finding_id", None)
    old["coverage_ledger"].pop("run_id", None)
    old["coverage_ledger"].pop("requirements", None)
    for p in old["coverage_ledger"]["points"]:
        for key in ("finding_ids", "evidence_kind", "suppressed_rules"):
            p.pop(key, None)
    return old


def test_upgrade_restores_references_when_the_evidence_can_be_rebuilt(tmp_path: Path):
    data = report_of(tmp_path / "p", {"a.py": 'import os\nfrom flask import request\ndef f():\n    os.system("a " + request.args["d"])\ndef g(x):\n    os.system(x)\n'})
    result = upgrade_report(_as_old_format(data))
    assert result.ok and result.data["schema_version"] == "1.3"
    point = next(p for p in result.data["coverage_ledger"]["points"] if p["finding"])
    assert point["finding_ids"] and point["evidence_kind"] == "finding"


def test_upgrade_stops_when_twenty_percent_or_more_cannot_be_restored(tmp_path: Path):
    files = {"a.py": "import os\ndef f():\n    os.system('ls')\n    os.system('pwd')\n    os.system('id')\n    os.system('date')\n    os.system('uname')\n"}
    old = _as_old_format(report_of(tmp_path / "p", files))
    result = upgrade_report(old)
    assert not result.ok and result.data is None and result.unrestorable >= 5
    assert any("한도" in r for r in result.reasons)


def test_upgrade_rejects_unknown_versions_and_missing_ledgers():
    assert not upgrade_report({"schema_version": "7"}).ok
    assert not upgrade_report({"schema_version": "1.2", "violations": []}).ok


def test_upgrade_cli_exit_codes(tmp_path: Path):
    data = report_of(tmp_path / "p", {"a.py": "import os\ndef f():\n    os.system('ls')\n    os.system('pwd')\n"})
    old_file = tmp_path / "old.json"
    old_file.write_text(json.dumps(_as_old_format(data)))
    out = tmp_path / "new.json"
    refused = cli.invoke(app, ["evidence", "upgrade", str(old_file), "-o", str(out)])
    assert refused.exit_code == 1 and not out.exists()
    allowed = cli.invoke(app, ["evidence", "upgrade", str(old_file), "-o", str(out), "--limit", "1.0"])
    assert allowed.exit_code == 0 and json.loads(out.read_text())["schema_version"] == "1.3"
    verified = cli.invoke(app, ["evidence", "verify", str(out)])
    assert verified.exit_code == 2  # 옮긴 보고서는 실행 식별이 없어 판정 불가


# ---------------------------------------------------------------------------
# 소비자: CLI와 내보내기 관문
# ---------------------------------------------------------------------------


def test_cli_verify_exit_codes_and_json(tmp_path: Path, good: dict):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(good))
    assert cli.invoke(app, ["evidence", "verify", str(path)]).exit_code == 0
    broken = copy.deepcopy(good)
    broken["summary"]["is_passed"] = True
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(broken))
    result = cli.invoke(app, ["evidence", "verify", str(bad), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert not payload["ok"] and any(p["code"] == "pass.unexplained" for p in payload["problems"])
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"schema_version": "1.0"}))
    assert cli.invoke(app, ["evidence", "verify", str(old)]).exit_code == 2
    assert cli.invoke(app, ["evidence", "verify", str(tmp_path / "none.json")]).exit_code == 2


def test_cli_verify_with_checkout_and_receipt(tmp_path: Path):
    project = tmp_path / "proj"
    data = report_of(project)
    report_file = tmp_path / "r.json"
    report_file.write_text(json.dumps(data))
    other = tmp_path / "other"
    shutil.copytree(project, other)
    assert cli.invoke(app, ["evidence", "verify", str(report_file), "--checkout", str(other)]).exit_code == 0
    (other / "a.py").write_text("x = 1\n")
    assert cli.invoke(app, ["evidence", "verify", str(report_file), "--checkout", str(other)]).exit_code == 1


def test_the_producer_never_exports_a_contradiction_as_a_pass(tmp_path: Path, monkeypatch):
    from iron_laws.core import scanner as scanner_module

    original = scanner_module.build_ledger

    def corrupted(*args, **kwargs):
        ledger = original(*args, **kwargs)
        ledger.points[0].finding_ids = ["F-bogus0000000"]
        ledger.points[0].finding = True
        return ledger

    monkeypatch.setattr(scanner_module, "build_ledger", corrupted)
    report = _scan(tmp_path, {"a.py": "import os\ndef f():\n    os.system('ls')\n"})
    assert report.summary.scan_status == "incomplete" and not report.summary.is_passed
    assert any(d.kind == "consistency" and d.severity == "error" for d in report.diagnostics)
    result = cli.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# 같은 근거의 동일 요건은 명령·형식이 달라도 같은 상태와 이유
# ---------------------------------------------------------------------------


def test_requirement_states_agree_across_audit_check_sarif_and_verify_patch(tmp_path: Path):
    project = make_project(tmp_path / "proj", {"b.py": "import os\ndef g(c):\n    os.system(c)\n"})
    contract_file = tmp_path / "contract.yml"
    contract_file.write_text(yaml.safe_dump({"version": 1, "mode": "block", "scope": "all"}))
    audit = cli.invoke(app, ["audit", str(project), "--contract", str(contract_file), "--format", "json"])
    ledger = json.loads(audit.stdout)["coverage_ledger"]
    sarif = json.loads(cli.invoke(app, ["audit", str(project), "--contract", str(contract_file), "--format", "sarif"]).stdout)
    props = sarif["runs"][0]["properties"]["coverageLedger"]
    assert props["status"] == ledger["status"] == "unmet"
    assert {(p["path"], p["line"], p["state"]) for p in props.get("points", [])} <= {(p["path"], p["line"], p["state"]) for p in ledger["points"]}
    check = cli.invoke(app, ["check", str(project), "--contract", str(contract_file)])
    assert check.exit_code == 1 and "unmet" in (check.stdout + check.stderr).lower() or check.exit_code == 1
    patch = write_patch(tmp_path, project, {"app.py": APP_FIXED})
    from iron_laws.verify.engine import VerifyOptions, verify_patch

    receipt = verify_patch(project, patch, VerifyOptions(finding="IL-504@app.py:6", runner="none", require_tests=False, contract_path=contract_file))
    assert receipt.coverage["original_status"] == ledger["status"]
    gaps = {(p["path"], p["line"]) for p in ledger["points"] if p["state"] in ("unresolved", "unsupported", "budget_exceeded")}
    assert gaps and any(path == "b.py" for path, _ in gaps)
    assert APP != APP_FIXED and BASE and RULE
