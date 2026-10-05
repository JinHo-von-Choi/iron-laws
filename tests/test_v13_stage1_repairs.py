"""
오철칙 v1.3 1단계(PR-01~04) 신뢰성 수리 수용시험
- 알려진 오통과·미탐(위험)과 대응하는 정상 사례를 짝으로 고정한다(`tests/repair_cases.py`).
- 장부·승인·출력 결함은 실제 입력으로 재현한 뒤 고친 동작을 확인한다.
표본은 구현자가 직접 만들고 분류했다. 독립 검토자의 분류가 아니므로 효과 주장의 근거가 아니라 회귀 방지에 쓴다.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import random
import string
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.approvals import GENESIS, ApprovalStore, Record
from iron_laws.core.config import IronLawsConfig, Limits
from iron_laws.core.models import Confidence
from iron_laws.core.scanner import AuditScanner
from tests.helpers import scan_files
from tests.repair_cases import REPAIR_CASES
from tests.test_stage2_contract import KNOWN_GAPS, SAFE_CHANGES, _scan
from tests.test_stage5_approvals import BASE, RULE, approve, make, status

cli = CliRunner()


# ---------------------------------------------------------------------------
# PR-01: 값·guard·객체·보간
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("group", "name", "ext", "code", "rule", "risky"),
    REPAIR_CASES,
    ids=[f"{c[0]}:{c[1]}:{'risky' if c[5] else 'benign'}" for c in REPAIR_CASES],
)
def test_repair_case(tmp_path: Path, group, name, ext, code, rule, risky):
    # 확정 지적(CONFIRMED)만 센다. '확인 필요'는 판정 보류이며 위험 변형의 탐지로도, 정상 사례의 오탐으로도 세지 않는다
    found = [v for v in scan_files(tmp_path, {f"app{ext}": code}) if v.rule_id == rule and v.confidence is Confidence.CONFIRMED]
    assert bool(found) is risky, (group, name, [(v.rule_id, v.line_number) for v in found])


def test_repair_corpus_keeps_a_benign_counterpart_for_every_group():
    groups: dict[str, set[bool]] = {}
    for group, _name, _ext, _code, _rule, risky in REPAIR_CASES:
        groups.setdefault(group, set()).add(risky)
    assert all(kinds == {True, False} for kinds in groups.values()), groups


# ---------------------------------------------------------------------------
# PR-02: 장부는 실제 검출에만 근거한다
# ---------------------------------------------------------------------------

ALLOWLISTED = 'import os\nfrom flask import request\nALLOWED = ("a", "b")\n\ndef f():\n    cmd = request.args["c"]\n    if cmd not in ALLOWED:\n        return\n    os.system("run " + cmd)\n'


def test_ledger_does_not_claim_a_finding_the_rule_did_not_report(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": ALLOWLISTED})
    assert [v for v in report.violations if v.rule_id == "IL-504"] == []
    point = next(p for p in report.coverage_ledger.points if p.family == "command")
    assert not point.finding and point.finding_ids == []
    assert point.state == "evidence_met" and point.evidence_kind == "guard"


def test_ledger_flags_a_tainted_flow_the_rule_did_not_report_as_unresolved(tmp_path: Path):
    # 오염 흐름은 보이지만 규칙이 인정한 안전 조건이 없고 지적도 없다면 근거 충족으로 세지 않는다
    scanned = _scan(
        tmp_path,
        {"a.py": 'import os\nfrom flask import request\ndef f():\n    cmd = request.args["c"]\n    os.system("run " + cmd)  # iron-laws: ignore[IL-504] 내부 관리 도구라서 허용한다\n'},
    )
    point = next(p for p in scanned.coverage_ledger.points if p.family == "command")
    assert point.state == "policy_excluded" and point.suppressed_rules == ["IL-504"]


def test_every_met_point_has_an_evidence_kind_and_finding_ids_resolve(tmp_path_factory):
    corpora = [case[1] for case in KNOWN_GAPS]
    corpora += [files for _name, files in SAFE_CHANGES]
    corpora.append({"a.py": ALLOWLISTED})
    corpora.append({"a.py": 'import os\nfrom flask import request\ndef f():\n    os.system("ls " + request.args["d"])\n'})
    for files in corpora:
        report = _scan(tmp_path_factory.mktemp("ev"), files)
        ledger = report.coverage_ledger
        ids = {v.finding_id: v for v in report.violations}
        for point in ledger.points:
            if point.state == "evidence_met":
                assert point.evidence_kind in ("finding", "closed_value", "guard"), (files, point)
            else:
                assert point.evidence_kind == "none", (files, point)
            assert point.finding == bool(point.finding_ids)
            for finding_id in point.finding_ids:
                violation = ids[finding_id]  # 존재하지 않는 지적을 가리키면 KeyError
                assert violation.file_path.as_posix() == point.path and violation.line_number == point.line


def test_finding_ids_are_unique_and_stable_across_runs(tmp_path: Path):
    files = {"a.py": 'import os\nfrom flask import request\ndef f():\n    os.system("a " + request.args["d"])\n    os.system("b " + request.args["e"])\n'}
    first = _scan(tmp_path, files)
    second = AuditScanner(tmp_path).scan()
    ids = [v.finding_id for v in first.violations]
    assert len(ids) == len(set(ids)) >= 2 and all(i.startswith("F-") for i in ids)
    assert ids == [v.finding_id for v in second.violations]
    assert first.coverage_ledger.run_id == second.coverage_ledger.run_id and first.coverage_ledger.run_id.startswith("R-")


def test_same_line_suppression_does_not_extend_to_other_families(tmp_path: Path):
    code = 'import os\nfrom flask import request\n\ndef f():\n    os.system("cat " + open(request.args["f"]).read())  # iron-laws: ignore[IL-504] 내부 관리 도구라서 허용한다\n'
    report = _scan(tmp_path, {"a.py": code})
    assert [(v.rule_id, v.line_number) for v in report.violations] == [("IL-502", 5)]
    command = next(p for p in report.coverage_ledger.points if p.family == "command")
    path = next(p for p in report.coverage_ledger.points if p.family == "path")
    assert command.state == "policy_excluded" and command.suppressed_rules == ["IL-504"]
    assert path.state == "evidence_met" and path.finding and path.suppressed_rules == []


def test_required_blocker_is_not_hidden_by_not_applicable(tmp_path: Path):
    # 분석한 파일이 하나도 없고 변경된 파일이 점검되지 못한 경우: 비적용이 아니라 미충족이어야 한다
    (tmp_path / "big.py").write_text("y = 2\n" * 50)
    config = IronLawsConfig(limits=Limits(max_file_bytes=100))
    report = AuditScanner(tmp_path, config=config, changed_files={"big.py"}, changed_since="HEAD").scan()
    assert report.coverage_ledger.status == "unmet"
    assert any("big.py" in b for b in report.coverage_ledger.blockers)


def test_safe_anchor_does_not_clear_an_existing_required_blocker(tmp_path: Path):
    (tmp_path / "big.py").write_text("y = 2\n" * 50)
    (tmp_path / "safe.py").write_text("import os\ndef f():\n    os.system('ls')\n")
    config = IronLawsConfig(limits=Limits(max_file_bytes=100))
    report = AuditScanner(tmp_path, config=config, changed_files={"big.py", "safe.py"}, changed_since="HEAD").scan()
    assert report.coverage_ledger.status == "unmet"
    assert any("big.py" in b for b in report.coverage_ledger.blockers)


# ---------------------------------------------------------------------------
# PR-03: 승인 검증을 하나의 입구로
# ---------------------------------------------------------------------------


def _rewrite_store(path: Path, edit) -> None:
    """기록을 고치고 해시 연결을 새로 만든다(내용은 손상됐지만 해시는 맞는 경우를 만든다)."""
    records = [json.loads(line) for line in path.read_text().splitlines()]
    previous = GENESIS
    out = []
    for index, raw in enumerate(records, start=1):
        edit(raw)
        record = Record(**{**raw, "seq": index, "prev": previous, "hash": ""})
        record.hash = record.compute_hash()
        previous = record.hash
        out.append(record.model_dump(mode="json"))
    path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in out))


@pytest.mark.parametrize("rehash", [False, True], ids=["tampered-hash", "valid-hash-bad-value"])
def test_corrupted_expiry_is_never_consumed_as_a_valid_approval(tmp_path: Path, rehash: bool):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    if rehash:
        _rewrite_store(store, lambda raw: raw.update(expires="2999-99-99"))
    else:
        raw = json.loads(store.read_text().splitlines()[0])
        raw["expires"] = "2999-99-99"
        store.write_text(json.dumps(raw, ensure_ascii=False, sort_keys=True) + "\n")
    # verify: 오류
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store)]).exit_code == 1
    # status: 검증 실패이며 재검토 필요로 종료
    assert status(project, store)[approval_id][0] == "invalid"
    assert cli.invoke(app, ["approvals", "status", str(project), "--store", str(store)]).exit_code == 1
    # check/audit: 승인으로 소비하지 않는다
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    report = scanner.scan()
    target = next(v for v in report.violations if v.rule_id == "IL-504")
    assert target.approval_status == "invalid" and not report.summary.is_passed
    assert cli.invoke(app, ["check", str(project), "--approvals", str(store)]).exit_code == 1


def test_valid_store_is_still_consumed(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store)]).exit_code == 0
    assert status(project, store)[approval_id][0] == "valid"
    assert cli.invoke(app, ["check", str(project), "--approvals", str(store)]).exit_code == 0


def test_same_named_caller_in_another_file_requires_review(tmp_path: Path):
    files = {
        "app.py": BASE["app.py"],
        "routes_a.py": "from app import run_tool\n\ndef handle():\n    return run_tool()\n",
    }
    project = make(tmp_path / "proj", files)
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    assert status(project, store)[approval_id][0] == "valid"
    (project / "routes_b.py").write_text("from app import run_tool\n\ndef handle():\n    return run_tool()\n")
    state, reasons = status(project, store)[approval_id]
    assert state == "needs_review" and any("호출자" in r for r in reasons), (state, reasons)


def test_same_named_callee_in_another_file_is_a_different_target(tmp_path: Path):
    files = {
        "app.py": 'import os\nfrom flask import request\nfrom helpers_a import clean\n\ndef run_tool():\n    d = clean(request.args["d"])\n    os.system("ls " + d)\n',
        "helpers_a.py": "def clean(x):\n    if not x.isalnum():\n        raise ValueError('bad')\n    return x\n",
        "helpers_b.py": "def clean(x):\n    return x\n",
    }
    project = make(tmp_path / "proj", files)
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    assert status(project, store)[approval_id][0] == "valid"
    (project / "app.py").write_text(files["app.py"].replace("helpers_a", "helpers_b"))  # 같은 이름이지만 검증이 없는 다른 함수
    state, reasons = status(project, store)[approval_id]
    assert state == "needs_review", (state, reasons)


def _contract_file(path: Path) -> Path:
    path.write_text(yaml.safe_dump({"version": 1, "mode": "report", "scope": "all", "include_tests": True}))
    return path


def test_queue_uses_the_selected_contract(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    contract = _contract_file(tmp_path / "contract.yml")
    added = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "내부 관리자 화면이다", "--store", str(store), "--contract", str(contract)])
    assert added.exit_code == 0, added.output
    with_contract = cli.invoke(app, ["approvals", "queue", str(project), "--store", str(store), "--contract", str(contract), "--json"])
    without_contract = cli.invoke(app, ["approvals", "queue", str(project), "--store", str(store), "--json"])
    assert json.loads(with_contract.stdout) == []  # 승인할 때와 같은 계약이므로 재검토 항목이 없다
    assert any("계약" in item["why"] for item in json.loads(without_contract.stdout))  # 계약이 다르면 재검토 이유로 드러난다


def _add_with_dates(store: Path, rows: list[dict]) -> None:
    previous = GENESIS
    lines = []
    for index, raw in enumerate(rows, start=1):
        record = Record(**{**raw, "seq": index, "prev": previous})
        record.hash = record.compute_hash()
        previous = record.hash
        lines.append(json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
    store.write_text("\n".join(lines) + "\n")


def _approve_row(approval_id: str, created: str, expires: str | None = None) -> dict:
    return {
        "kind": "approve",
        "id": approval_id,
        "created": created,
        "finding": {"rule_id": "IL-504", "rule_version": 1, "path": "a.py", "fingerprint": approval_id.lower(), "loose": "x", "severity": "HIGH"},
        "reason": "검토 완료",
        "policy": {},
        "expires": expires,
    }


def test_prune_follows_the_time_condition_for_every_removal_kind(tmp_path: Path):
    store = tmp_path / "s.jsonl"
    rows = [
        _approve_row("AP-OLDREVOKED", "2025-01-01T00:00:00Z"),
        {"kind": "revoke", "id": "RV-OLDREVOKED", "created": "2025-01-02T00:00:00Z", "target": "AP-OLDREVOKED"},
        _approve_row("AP-NEWREVOKED", "2026-09-01T00:00:00Z"),
        {"kind": "revoke", "id": "RV-NEWREVOKED", "created": "2026-09-02T00:00:00Z", "target": "AP-NEWREVOKED"},
        _approve_row("AP-OLDFORGOT", "2025-02-01T00:00:00Z"),
        {"kind": "forget", "id": "FG-OLDFORGOT", "created": "2025-02-02T00:00:00Z", "target": "AP-OLDFORGOT"},
        _approve_row("AP-NEWFORGOT", "2026-09-03T00:00:00Z"),
        {"kind": "forget", "id": "FG-NEWFORGOT", "created": "2026-09-04T00:00:00Z", "target": "AP-NEWFORGOT"},
        _approve_row("AP-OLDEXPIRED", "2025-03-01T00:00:00Z", expires="2025-04-01"),
        _approve_row("AP-NEWEXPIRED", "2026-09-05T00:00:00Z", expires="2026-09-06"),
        _approve_row("AP-OLDACTIVE", "2025-05-01T00:00:00Z"),
    ]
    _add_with_dates(store, rows)
    assert ApprovalStore(store).verify_chain() == []
    removed = ApprovalStore(store).prune(__import__("datetime").date(2026, 1, 1), today=__import__("datetime").date(2026, 10, 5))
    after = ApprovalStore(store)
    kept_ids = {r.id for r in after.records}
    assert kept_ids == {"AP-NEWREVOKED", "RV-NEWREVOKED", "AP-NEWFORGOT", "FG-NEWFORGOT", "AP-NEWEXPIRED", "AP-OLDACTIVE"}, kept_ids
    assert removed == len(rows) - len(kept_ids)
    assert after.verify_chain() == []


def test_prune_refuses_a_broken_store(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approve(project, store)
    raw = json.loads(store.read_text().splitlines()[0])
    raw["reason"] = "바꾼 사유입니다"
    store.write_text(json.dumps(raw, ensure_ascii=False, sort_keys=True) + "\n")
    result = cli.invoke(app, ["approvals", "prune", "--before", "2999-01-01", "--yes", "--store", str(store)])
    assert result.exit_code == 2 and store.read_text().count("\n") == 1


# ---------------------------------------------------------------------------
# PR-04: 주석과 공통 가림
# ---------------------------------------------------------------------------

DIRECTIVE = "# iron-laws: ignore[IL-101] 사유가 충분하다"
SUPPRESSION_CASES = [
    ("yaml-escaped-quote", "a.yml", 'key: "a \\" ' + DIRECTIVE + '"\n', 0),
    ("yaml-multiline-double-quoted", "a.yml", 'key: "line one\n' + DIRECTIVE + '\n  end"\nother: 1\n', 0),
    ("yaml-single-quoted-inner", "a.yml", "key: 'a " + DIRECTIVE + "'\n", 0),
    ("yaml-escaped-single-quote", "a.yml", "key: 'it''s " + DIRECTIVE + "'\n", 0),
    ("yaml-escaped-single-quote-then-comment", "a.yml", "key: 'it''s' " + DIRECTIVE + "\n", 1),
    ("yaml-escaped-single-quote-at-end", "a.yml", "key: 'a''' " + DIRECTIVE + "\n", 1),
    ("yaml-real-comment", "a.yml", 'key: "value" ' + DIRECTIVE + "\n", 1),
    ("yaml-apostrophe-in-plain-scalar", "a.yml", "desc: it's fine " + DIRECTIVE + "\n", 1),
    ("yaml-hash-inside-quotes-then-comment", "a.yml", "key: 'a # b ' " + DIRECTIVE + "\n", 1),
    ("shell-ansi-c-quoting", "a.sh", "echo $'it\\'s " + DIRECTIVE + "'\n", 0),
    ("shell-multiline-double-quoted", "a.sh", 'echo "first\n' + DIRECTIVE + '"\n', 0),
    ("shell-multiline-single-quoted", "a.sh", "echo 'one\n" + DIRECTIVE + "'\n", 0),
    ("shell-heredoc-body", "a.sh", "cat <<EOF\n" + DIRECTIVE + "\nEOF\n", 0),
    ("shell-two-heredocs", "a.sh", "cat <<A <<B\n" + DIRECTIVE + "\nA\n" + DIRECTIVE + "\nB\n", 0),
    ("shell-comment-after-two-heredocs", "a.sh", "cat <<A <<B\nx\nA\ny\nB\necho ok " + DIRECTIVE + "\n", 1),
    ("shell-heredoc-quoted-tag", "a.sh", "cat <<'EOF'\n" + DIRECTIVE + "\nEOF\n", 0),
    ("shell-heredoc-hyphen-tag", "a.sh", "cat <<'END-X'\n" + DIRECTIVE + "\nEND-X\n", 0),
    ("shell-heredoc-dotted-tag", "a.sh", "cat <<EOT.1\n" + DIRECTIVE + "\nEOT.1\n", 0),
    ("yaml-sequence-quoted", "a.yml", "- '값 " + DIRECTIVE + "'\n", 0),
    ("shell-real-comment", "a.sh", 'echo "x" ' + DIRECTIVE + "\n", 1),
    ("shell-escaped-quote-then-comment", "a.sh", "echo \\\" " + DIRECTIVE + "\n", 1),
    ("env-quoted-value", "a.env", 'KEY="v ' + DIRECTIVE + '"\n', 0),
]


@pytest.mark.parametrize(("name", "filename", "text", "expected"), SUPPRESSION_CASES, ids=[c[0] for c in SUPPRESSION_CASES])
def test_directive_is_a_comment_only_when_it_really_is(name, filename, text, expected):
    from iron_laws.core.suppress import parse_suppressions
    from iron_laws.engine.source import SourceFile

    assert len(parse_suppressions(SourceFile(Path(filename), text)).directives) == expected


def _long_secret_project(root: Path, letters_only: bool = False) -> tuple[Path, list[str]]:
    alphabet = string.ascii_letters if letters_only else string.ascii_letters + string.digits
    rng = random.Random(20261005 + int(letters_only))  # 시험이 실행마다 달라지지 않게 씨앗을 고정한다
    long_secret = "Yw" + "".join(rng.choice(alphabet) for _ in range(500))
    token = "Zq" + "".join(rng.choice(alphabet) for _ in range(40)) + "ABCDEFGH"
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(
        "import os\nfrom flask import request\n"
        f'def f(cur):\n    PAD = "{"x" * 250}"; password = "{long_secret}"; cur.execute("SELECT * FROM t WHERE a=" + request.args["a"])\n'
        f'    os.system("echo " + request.args["c"]); token = "{token}"\n'
    )
    fragments = [long_secret[:12], long_secret[100:112], long_secret[-12:], token[:12], token[-12:]]
    return root, fragments


@pytest.mark.parametrize("letters_only", [False, True], ids=["alnum", "letters-only"])
@pytest.mark.parametrize("fmt", ["console", "markdown", "json", "sarif", "prompt", "review"])
def test_long_secret_leaves_no_fragment_in_any_output_format(tmp_path: Path, fmt: str, letters_only: bool):
    project, fragments = _long_secret_project(tmp_path / "proj", letters_only)
    result = cli.invoke(app, ["audit", str(project), "--format", fmt, "--limit", "0"])
    text = result.stdout + result.stderr
    assert result.exit_code in (0, 1)
    assert [f for f in fragments if f in text] == []


def test_secret_collection_precedes_truncation_for_other_rules_on_the_same_line(tmp_path: Path):
    project, fragments = _long_secret_project(tmp_path / "proj")
    report = AuditScanner(project).scan()
    blob = report.model_dump_json()
    assert [f for f in fragments if f in blob] == []
    assert all(len(v.snippet) <= 300 for v in report.violations)


# ---------------------------------------------------------------------------
# 실제 프로젝트 재점검에서 드러난 결함: 같은 줄의 같은 호출, 실행마다 달라지는 결과
# ---------------------------------------------------------------------------


def test_two_identical_calls_on_one_line_get_distinct_ledger_points(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": "import os\n\ndef f(a, b):\n    return open(os.path.join(a, 'x')).read() + open(os.path.join(b, 'y')).read()\n"})
    ids = [p.id for p in report.coverage_ledger.points]
    assert len(ids) == len(set(ids)) >= 2
    assert len({(p.line, p.column) for p in report.coverage_ledger.points}) == len(ids)
    from iron_laws.evidence.verifier import verify_report

    assert verify_report(report.model_dump(mode="json")).ok


def test_results_do_not_depend_on_the_python_hash_seed(tmp_path: Path):
    """문자열 hash()는 실행마다 달라진다. 같은 코드의 점검 결과가 실행에 따라 달라지면 승인·기준선 대응이 흔들린다."""
    import os
    import subprocess
    import sys

    source = Path(__file__).resolve().parent.parent / "src" / "iron_laws" / "rules"
    results = []
    for seed in ("3", "9"):
        run = subprocess.run(
            [sys.executable, "-c", "import sys; from iron_laws.cli import app; sys.exit(app())", "audit", str(source), "--format", "json", "--limit", "0", "--allow-empty"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
            timeout=300,
        )
        data = json.loads(run.stdout)
        results.append(sorted((v["rule_id"], v["file_path"], v["line_number"], v["confidence"], v["message"]) for v in data["violations"]))
        assert data["summary"]["scan_status"] == "complete", data["diagnostics"][:2]
    assert results[0] == results[1]


def test_violation_paths_are_serialized_with_forward_slashes_on_every_platform(tmp_path: Path):
    from pathlib import PureWindowsPath

    report = _scan(tmp_path, {"pkg/한글 폴더/a.py": "import os\nfrom flask import request\ndef f():\n    os.system('ls ' + request.args['d'])\n"})
    assert report.model_dump(mode="json")["violations"][0]["file_path"] == "pkg/한글 폴더/a.py"
    violation = report.violations[0]
    # Windows의 역슬래시 경로도 같은 값으로 나가야 지문·finding_id·독립 검증기가 운영체제와 무관하게 같다
    assert type(violation)._serialize_path(violation, PureWindowsPath("pkg\\한글 폴더\\a.py")) == "pkg/한글 폴더/a.py"


# ---------------------------------------------------------------------------
# 동일 줄 근거 대여: 같은 줄의 다른 호출은 한 호출의 지적을 근거로 쓰지 못한다
# ---------------------------------------------------------------------------

SAME_LINE_HEAD = "import os\nimport subprocess\nfrom flask import request\n\ndef f():\n    a = request.args['a']\n"


@pytest.mark.parametrize(
    ("name", "line", "expected"),
    [
        ("risky-then-closed", "    os.system('echo ' + a); os.system('ok')\n", [("evidence_met", True), ("evidence_met", False)]),
        ("closed-then-risky", "    os.system('ok'); os.system('echo ' + a)\n", [("evidence_met", False), ("evidence_met", True)]),
        ("two-risky-calls", "    os.system('echo ' + a); os.system('x ' + a)\n", [("evidence_met", True), ("unresolved", False)]),
        ("risky-between-closed", "    os.system('a'); os.system('echo ' + a); os.system('b')\n", [("evidence_met", False), ("evidence_met", True), ("evidence_met", False)]),
        ("mixed-families-on-one-line", "    open(a); os.system('echo ' + a)\n", None),
    ],
)
def test_finding_is_not_lent_to_another_call_on_the_same_line(tmp_path: Path, name, line, expected):
    report = _scan(tmp_path, {"a.py": SAME_LINE_HEAD + line})
    points = sorted((p for p in report.coverage_ledger.points if p.family == "command"), key=lambda p: p.column)
    if expected is None:
        assert all(p.finding_ids == [] or p.callee == "os.system" for p in points)
        return
    assert [(p.state, bool(p.finding_ids)) for p in points] == expected
    assert len({fid for p in points for fid in p.finding_ids}) == sum(1 for _, has in expected if has)
    from iron_laws.evidence.verifier import verify_report

    assert verify_report(report.model_dump(mode="json")).ok


def test_a_second_sibling_risky_call_on_a_line_stays_unresolved_and_blocks_the_contract(tmp_path: Path):
    """한 줄의 두 위험 호출은 규칙이 한 지적으로 합쳐 보고한다. 나란한 두 번째 호출은 자기 지적이 없으므로 사람이 따로 확인할 대상으로 남는다."""
    report = _scan(tmp_path, {"a.py": SAME_LINE_HEAD + "    os.system('echo ' + a); os.system('x ' + a)\n"})
    states = sorted(p.state for p in report.coverage_ledger.points if p.family == "command")
    assert "unresolved" in states and report.coverage_ledger.status == "unmet"


def test_nested_calls_in_one_flow_share_one_finding(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": "import os\nfrom flask import request\n\ndef h():\n    n = request.args.get('n')\n    return open(os.path.join('/srv', n)).read()\n"})
    path_points = [p for p in report.coverage_ledger.points if p.family == "path"]
    assert len(report.violations) == 1 and path_points
    assert all(report.violations[0].finding_id in p.finding_ids for p in path_points if p.state == "evidence_met")




# ---------------------------------------------------------------------------
# 타입 지정이 붙은 비밀 이름 대입: 다른 규칙이 같은 줄을 지적해도 값 조각이 어떤 출력에도 남지 않는다
# ---------------------------------------------------------------------------

TYPED_SECRET_LINES = [
    ("ts-typed-const", "a.ts", 'const token: string = "{s}"; console.log(eval(req.query.x));\n'),
    ("py-annotation", "a.py", 'api_token: str = "{s}"; exec(input())\n'),
    ("py-generic-annotation", "a.py", 'secret_key: Optional[str] = "{s}"; exec(input())\n'),
    ("py-annotated-with-quoted-metadata", "a.py", 'api_token: Annotated[str, "credential"] = "{s}"; exec(input())\n'),
    ("rust-typed-let", "a.rs", 'let password: &str = "{s}"; unsafe { std::ptr::null::<u8>().read(); }\n'),
    ("js-quoted-key", "a.js", 'const cfg = { "token": "{s}", mode: eval(userInput) };\n'),
]


@pytest.mark.parametrize(("name", "filename", "template"), TYPED_SECRET_LINES, ids=[c[0] for c in TYPED_SECRET_LINES])
@pytest.mark.parametrize("fmt", ["console", "markdown", "json", "sarif", "prompt", "review"])
def test_typed_secret_assignment_leaves_no_fragment_in_any_output(tmp_path: Path, name, filename, template, fmt):
    secret = "Zq9xKm2LpQw8RtYuVn4B"  # 시험용 무효 합성 값
    project = tmp_path / "proj"
    project.mkdir()
    (project / filename).write_text(template.replace("{s}", secret), encoding="utf-8")
    result = cli.invoke(app, ["audit", str(project), "--format", fmt, "--limit", "0"])
    text = result.stdout + result.stderr
    assert result.exit_code in (0, 1)
    assert [f for f in (secret[:8], secret[6:14], secret[-8:]) if f in text] == []


# ---------------------------------------------------------------------------
# 승인된 파일 이동과 변경 범위: 전체 점검·변경 점검·검토 묶음이 같은 판정을 낸다
# ---------------------------------------------------------------------------


def _git_project(root: Path):
    import os
    import subprocess

    from tests.test_stage5_approvals import BASE, make

    root.mkdir(parents=True)
    make(root, BASE)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True, env=env)

    git("init", "-q")
    git("add", "-A")
    git("commit", "-qm", "init")
    return git


def _verdicts(project: Path, store: Path) -> dict[str, tuple[int, dict | None]]:
    out: dict[str, tuple[int, dict | None]] = {}
    for label, args in [
        ("full", ["check", str(project), "--approvals", str(store)]),
        ("changed", ["check", str(project), "--approvals", str(store), "--changed-since", "HEAD~1"]),
        ("bundle-full", ["review-bundle", str(project), "--approvals", str(store), "--format", "json"]),
        ("bundle-changed", ["review-bundle", str(project), "--approvals", str(store), "--changed-since", "HEAD~1", "--format", "json"]),
    ]:
        result = cli.invoke(app, args)
        out[label] = (result.exit_code, json.loads(result.stdout) if label.startswith("bundle") and result.exit_code in (0, 1) else None)
    return out


def test_an_approved_file_move_is_judged_the_same_by_every_command(tmp_path: Path):
    from tests.test_stage5_approvals import approve

    project = tmp_path / "proj"
    git = _git_project(project)
    store = tmp_path / "ap.jsonl"
    approve(project, store)
    git("mv", "app.py", "tools.py")
    git("commit", "-qam", "move")
    verdicts = _verdicts(project, store)
    assert {k: v[0] for k, v in verdicts.items()} == {"full": 0, "changed": 0, "bundle-full": 0, "bundle-changed": 0}
    assert verdicts["bundle-full"][1]["counts"]["keep"] == verdicts["bundle-changed"][1]["counts"]["keep"] == 1
    report = json.loads(cli.invoke(app, ["audit", str(project), "--approvals", str(store), "--changed-since", "HEAD~1", "--format", "json"]).stdout)
    assert report["metadata"]["scope"]["renames"] == [{"from": "app.py", "to": "tools.py"}]


def test_a_move_that_also_changes_the_approved_premise_is_not_inherited_by_any_command(tmp_path: Path):
    from tests.test_stage5_approvals import approve

    project = tmp_path / "proj"
    git = _git_project(project)
    store = tmp_path / "ap.jsonl"
    approve(project, store)
    git("mv", "app.py", "tools.py")
    (project / "tools.py").write_text((project / "tools.py").read_text().replace('os.system("ls " + d)', 'os.system("rm -rf " + d)'))
    git("commit", "-qam", "move and change")
    verdicts = _verdicts(project, store)
    assert verdicts["full"][0] == verdicts["changed"][0] == 1
    assert verdicts["bundle-full"][0] == verdicts["bundle-changed"][0] == 1


def test_a_copy_of_an_approved_file_does_not_inherit_the_approval_in_any_scope(tmp_path: Path):
    from tests.test_stage5_approvals import approve

    project = tmp_path / "proj"
    git = _git_project(project)
    store = tmp_path / "ap.jsonl"
    approve(project, store)
    (project / "copy.py").write_text((project / "app.py").read_text())
    git("add", "-A")
    git("commit", "-qm", "copy")
    verdicts = _verdicts(project, store)
    assert verdicts["full"][0] == verdicts["changed"][0] == 1
    # 검토 묶음은 기존 승인의 전제만 판정한다. 복제본은 승인을 물려받지 않아 점검이 실패하고, 원본의 승인은 두 범위에서 똑같이 유지된다
    assert verdicts["bundle-full"][0] == verdicts["bundle-changed"][0]
    assert verdicts["bundle-full"][1]["counts"] == verdicts["bundle-changed"][1]["counts"]
