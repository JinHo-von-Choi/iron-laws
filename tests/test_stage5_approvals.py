"""
오철칙 경쟁력 강화 계획 5단계(PR-12~13) 승인 기록과 변경 유효성 추적 시험
- 안전한 이동·리팩터링 30개는 승인이 유지되고, 위험한 전제 변경·복제 30개는 자동으로 승계되지 않아야 한다.
- 표본은 구현자가 직접 분류했다. 독립 검토자의 분류가 아니므로 효과 주장의 근거로 쓰지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.approvals import ApprovalStore, approve_record
from iron_laws.core.baseline import (
    BaselineStatus,
    build_baseline,
    load_baseline,
    migrate_baseline,
    save_baseline,
)
from iron_laws.core.config import ConfigError, IronLawsConfig
from iron_laws.core.contract import Contract
from iron_laws.core.scanner import AuditScanner
from iron_laws.verify.engine import VerifyOptions, resolve_finding, verify_patch
from tests.test_stage3_verify import APP, APP_FIXED, make_diff

cli = CliRunner()

BASE = {
    "app.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n\ndef other():\n    return 1\n',
    "util.py": "def helper(x):\n    return x + 1\n",
}
RULE = "IL-504@app.py"


def make(root: Path, files: dict[str, str] | None = None) -> Path:
    for rel, content in (files or BASE).items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def approve(project: Path, store: Path, finding: str = RULE, scanner_kwargs: dict | None = None, **overrides) -> str:
    scanner = AuditScanner(project, collect_dependencies=True, **(scanner_kwargs or {}))
    report = scanner.scan()
    assert report.summary.scan_status == "complete"
    violation = resolve_finding(report, finding)
    record = approve_record(violation, overrides.get("reason", "내부 관리자 화면이며 입력이 사전 검증된다"), "tester", scanner._approval_policy(), overrides.get("expires"), None, overrides.get("minutes", 5))
    ApprovalStore(store).append(record)
    return record.id


def status(project: Path, store: Path, scanner_kwargs: dict | None = None) -> dict[str, tuple[str, list[str]]]:
    scanner = AuditScanner(project, approvals=ApprovalStore(store), **(scanner_kwargs or {}))
    report = scanner.scan()
    assert report.summary.scan_status in ("complete", "incomplete")
    return {r.approval.id: (r.status, r.reasons) for r in scanner.approval_rows}


# ---------------------------------------------------------------------------
# 승인 기록: 필수 내용, 추가 전용, 해시 연결, 비밀 없음
# ---------------------------------------------------------------------------


def test_record_contains_reason_target_expiry_policy_flow_dependencies_receipt(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    scanner = AuditScanner(project, collect_dependencies=True)
    violation = resolve_finding(scanner.scan(), RULE)
    record = approve_record(violation, "관리자 전용 화면", "홍길동", scanner._approval_policy(), date(2030, 1, 1), "r" * 24, 15)
    ApprovalStore(store).append(record)
    saved = ApprovalStore(store).records[0]
    assert saved.reason == "관리자 전용 화면" and saved.reviewer == "홍길동"
    assert saved.expires == "2030-01-01" and saved.receipt_digest == "r" * 24 and saved.minutes == 15
    assert saved.finding.rule_id == "IL-504" and saved.finding.path == "app.py" and saved.finding.scope_name == "run_tool"
    assert saved.policy.ruleset_hash and saved.policy.config_hash and saved.policy.contract_digest and saved.policy.tool_version
    assert [e["role"] for e in saved.flow] == ["source", "propagation", "sink"]
    assert saved.dependencies["chain"][0]["name"] == "run_tool" and saved.dependencies["literals"]


def test_record_never_stores_code_or_secrets(tmp_path: Path):
    project = make(tmp_path / "proj", {"app.py": BASE["app.py"] + '\nTOKEN = "ActualHardcodedPassword123!"\n'})
    store = tmp_path / "s.jsonl"
    approve(project, store)
    text = store.read_text()
    assert "ActualHardcodedPassword123" not in text
    assert 'os.system("ls "' not in text and "request.args" not in text  # 코드 원문은 담지 않는다


def test_reason_must_be_meaningful_and_unanalyzable_findings_cannot_be_approved(tmp_path: Path):
    project = make(tmp_path / "proj")
    scanner = AuditScanner(project, collect_dependencies=True)
    violation = resolve_finding(scanner.scan(), RULE)
    with pytest.raises(ConfigError):
        approve_record(violation, "  ", "x", scanner._approval_policy(), None, None, 0)
    config_project = make(tmp_path / "cfg", {".env": 'API_KEY="ActualHardcodedPassword123!"\n'})
    cfg_scanner = AuditScanner(config_project, collect_dependencies=True)
    secret = next(v for v in cfg_scanner.scan().violations if v.rule_id.startswith(("IL-101", "AI-104")))
    with pytest.raises(ConfigError):
        approve_record(secret, "시험용 값", "x", cfg_scanner._approval_policy(), None, None, 0)


def test_store_is_append_only_and_hash_chained(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    first = approve(project, store)
    store_obj = ApprovalStore(store)
    assert store_obj.verify_chain() == []
    lines = store.read_text().splitlines()
    assert json.loads(lines[0])["prev"] == "0" * 24
    # 내용 변경 탐지
    forged = json.loads(lines[0])
    forged["reason"] = "다른 사유로 바꿨다"
    store.write_text(json.dumps(forged, ensure_ascii=False, sort_keys=True) + "\n")
    assert any("내용 해시" in p for p in ApprovalStore(store).verify_chain())
    with pytest.raises(ConfigError):
        approve(project, store, finding="IL-504@app.py", reason="추가 시도")  # 깨진 기록 위에 추가하지 않는다
    # 삭제·재배열 탐지
    store.write_text("\n".join(lines) + "\n")
    second_project = make(tmp_path / "proj2", {"app.py": BASE["app.py"].replace("run_tool", "second_tool"), "util.py": BASE["util.py"]})
    approve(second_project, store)
    chain = store.read_text().splitlines()
    store.write_text(chain[1] + "\n")
    assert any("앞 기록과 이어지지 않는다" in p for p in ApprovalStore(store).verify_chain())
    assert first.startswith("AP-")


def test_revoked_and_forgotten_approvals(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    result = cli.invoke(app, ["approvals", "revoke", approval_id, "--reason", "재검토 결과 철회", "--store", str(store)])
    assert result.exit_code == 0
    assert status(project, store)[approval_id][0] == "revoked"
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    report = scanner.scan()
    assert not report.summary.is_passed  # 철회된 승인은 받아들이지 않는다
    assert cli.invoke(app, ["approvals", "forget", approval_id, "--store", str(store)]).exit_code == 2  # --yes 없이는 안 됨
    assert cli.invoke(app, ["approvals", "forget", approval_id, "--yes", "--store", str(store)]).exit_code == 0
    assert approval_id not in {a.id for a in ApprovalStore(store).approvals()}


def test_prune_removes_only_expired_revoked_or_forgotten_and_rebuilds_the_chain(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    keep = approve(project, store)
    other = make(tmp_path / "proj2", {"app.py": BASE["app.py"].replace("run_tool", "second_tool"), "util.py": BASE["util.py"]})
    drop = approve(other, store)
    cli.invoke(app, ["approvals", "revoke", drop, "--reason", "더 이상 필요 없음", "--store", str(store)])
    assert cli.invoke(app, ["approvals", "prune", "--before", "2000-01-01", "--yes", "--store", str(store)]).exit_code == 0
    assert {a.id for a in ApprovalStore(store).approvals()} == {keep, drop}  # 날짜가 이르면 지우지 않는다
    future = (date.today() + timedelta(days=1)).isoformat()
    assert cli.invoke(app, ["approvals", "prune", "--before", future]).exit_code == 2  # --yes 없이는 안 됨
    assert cli.invoke(app, ["approvals", "prune", "--before", future, "--yes", "--store", str(store)]).exit_code == 0
    remaining = ApprovalStore(store)
    assert {a.id for a in remaining.approvals()} == {keep}
    assert remaining.verify_chain() == []


# ---------------------------------------------------------------------------
# 안전한 이동·리팩터링 30개: 승인이 유지된다
# ---------------------------------------------------------------------------

SAFE_APP = BASE["app.py"]
SAFE = [
    ("comment-above", {"app.py": "# 주석 하나\n# 주석 둘\n" + SAFE_APP}),
    ("blank-lines-above", {"app.py": "\n\n\n" + SAFE_APP}),
    ("blank-lines-between", {"app.py": SAFE_APP.replace("\n\ndef other", "\n\n\n\n\ndef other")}),
    ("trailing-spaces", {"app.py": SAFE_APP.replace('d = request.args["d"]', 'd = request.args["d"]   ')}),
    ("comment-inside-function", {"app.py": SAFE_APP.replace('    d = request.args["d"]', '    # 입력을 읽는다\n    d = request.args["d"]')}),
    ("trailing-comment", {"app.py": SAFE_APP.replace('os.system("ls " + d)', 'os.system("ls " + d)  # 관리자 전용')}),
    ("add-unrelated-function", {"app.py": SAFE_APP + "\ndef added():\n    return 2\n"}),
    ("rename-unrelated-function", {"app.py": SAFE_APP.replace("def other", "def renamed_other")}),
    ("modify-unrelated-body", {"app.py": SAFE_APP.replace("return 1", "return 1 + 41")}),
    ("add-import-at-top", {"app.py": SAFE_APP.replace("import os\n", "import os\nimport sys\n")}),
    ("add-module-constant", {"app.py": SAFE_APP.replace("\n\ndef run_tool", "\nVERSION = '1.0'\n\ndef run_tool", 1)}),
    ("docstring-module", {"app.py": '"""모듈 설명."""\n' + SAFE_APP}),
    ("reorder-functions", {"app.py": 'import os\nfrom flask import request\n\ndef other():\n    return 1\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'}),
    ("crlf-line-endings", {"app.py": SAFE_APP.replace("\n", "\r\n")}),
    ("tabs-instead-of-spaces", {"app.py": SAFE_APP.replace("    ", "\t")}),
    ("blank-line-inside-function", {"app.py": SAFE_APP.replace('    d = request.args["d"]\n', '    d = request.args["d"]\n\n')}),
    ("unicode-comment", {"app.py": "# 한글 주석 — 설명\n" + SAFE_APP}),
    ("other-file-modified", {"util.py": "def helper(x):\n    return x + 2\n"}),
    ("new-unrelated-file", {"extra.py": "def extra():\n    return 3\n"}),
    ("add-tests", {"tests/test_other.py": "def test_x():\n    assert True\n"}),
    ("add-readme", {"README.md": "# 설명\n"}),
    ("rename-file", {"__rename__": ("app.py", "renamed_app.py")}),
    ("move-file-to-package", {"__rename__": ("app.py", "pkg/app.py")}),
    ("move-file-and-comment", {"__rename__": ("app.py", "web/handlers.py"), "web/handlers.py": "# 이동함\n" + SAFE_APP}),
    ("unrelated-caller-added", {"util.py": "def helper(x):\n    return x + 1\n\ndef uses_other():\n    from app import other\n    return other()\n"}),
    ("unrelated-function-doc", {"app.py": SAFE_APP.replace("def other():\n    return 1", 'def other():\n    """다른 함수."""\n    return 1')}),
    ("trailing-newlines", {"app.py": SAFE_APP + "\n\n\n"}),
    ("future-import-comment", {"app.py": SAFE_APP.replace("import os\n", "import os  # 표준 라이브러리\n")}),
    ("string-quote-style-unrelated", {"app.py": SAFE_APP.replace("return 1", "return int('1')")}),
    ("add-config-file", {".iron-laws.yml": "fail_on: HIGH\n"}),
]


def apply_variant(project: Path, change: dict) -> None:
    for rel, content in change.items():
        if rel == "__rename__":
            old, new = content
            target = project / new
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(project / old, target)
        else:
            target = project / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)


@pytest.mark.parametrize(("name", "change"), SAFE, ids=[c[0] for c in SAFE])
def test_safe_change_keeps_the_approval(tmp_path: Path, name, change):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    apply_variant(project, change)
    state, reasons = status(project, store)[approval_id]
    assert state == "valid", (name, state, reasons)
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    assert scanner.scan().summary.is_passed  # 유효한 승인은 받아들인다


def test_unnecessary_re_review_rate_on_safe_changes(tmp_path_factory):
    rereviews = 0
    for name, change in SAFE:
        base = tmp_path_factory.mktemp(name.replace("-", "_"))
        project = make(base / "proj")
        store = base / "s.jsonl"
        approval_id = approve(project, store)
        apply_variant(project, change)
        rereviews += status(project, store)[approval_id][0] != "valid"
    assert len(SAFE) == 30
    assert rereviews / len(SAFE) <= 0.20


# ---------------------------------------------------------------------------
# 위험한 전제 변경·복제 30개: 자동 승계하지 않는다
# ---------------------------------------------------------------------------

SANITIZED = {
    "app.py": 'import os\nfrom flask import request\n\ndef validate(x):\n    if not x.isalnum():\n        raise ValueError("bad")\n    return x\n\ndef run_tool():\n    d = validate(request.args["d"])\n    os.system("ls " + d)\n',
}
PATHY = {
    "app.py": "from flask import request\n\ndef normalize_name(n):\n    return n.replace('..', '')\n\ndef read_it():\n    f = normalize_name(request.args['f'])\n    return open('/srv/uploads/' + f).read()\n",
}


def risky_cases():
    app_py = BASE["app.py"]
    return [
        ("new-caller-same-file", BASE, {"app.py": app_py + "\ndef api():\n    return run_tool()\n"}, "호출자"),
        ("new-caller-other-file", BASE, {"views.py": "from app import run_tool\n\ndef view():\n    return run_tool()\n"}, "호출자"),
        ("sink-body-edit", BASE, {"app.py": app_py.replace('"ls "', '"ls -la "')}, "흐름의 함수|코드가 바뀌었다"),
        ("sink-argument-added", BASE, {"app.py": app_py.replace('"ls " + d', '"ls " + d + " /tmp"')}, "흐름의 함수|코드가 바뀌었다"),
        ("source-changed", BASE, {"app.py": app_py.replace('request.args["d"]', 'request.form["d"]')}, "흐름의 함수|코드가 바뀌었다"),
        ("function-renamed", BASE, {"app.py": app_py.replace("run_tool", "run_everything")}, "승인한 코드가 바뀌었다|흐름의 함수|같은 지적인지 확인할 수 없다"),
        ("decorator-exposes-route", BASE, {"app.py": app_py.replace("def run_tool", "@app.route('/run')\ndef run_tool")}, "코드가 바뀌었다|흐름의 함수"),
        ("parameter-added", BASE, {"app.py": app_py.replace("def run_tool():", "def run_tool(extra=None):")}, "코드가 바뀌었다|흐름의 함수"),
        ("sanitizer-body-weakened", SANITIZED, {"app.py": SANITIZED["app.py"].replace("if not x.isalnum():\n        raise ValueError(\"bad\")\n    ", "")}, "정제|호출하는 함수|흐름의 함수|코드가 바뀌었다"),
        ("sanitizer-call-removed", SANITIZED, {"app.py": SANITIZED["app.py"].replace('validate(request.args["d"])', 'request.args["d"]')}, "정제|호출하는 함수|흐름의 함수|코드가 바뀌었다"),
        ("sanitizer-replaced-by-weaker", SANITIZED, {"app.py": SANITIZED["app.py"].replace("x.isalnum()", "len(x) > 0")}, "정제|호출하는 함수|흐름의 함수|코드가 바뀌었다"),
        ("access-scope-widened", PATHY, {"app.py": PATHY["app.py"].replace("/srv/uploads/", "/srv/")}, "문자열 상수|코드가 바뀌었다|흐름의 함수"),
        ("path-normalizer-weakened", PATHY, {"app.py": PATHY["app.py"].replace("return n.replace('..', '')", "return n")}, "정제|호출하는 함수|코드가 바뀌었다|흐름의 함수"),
        ("path-normalizer-call-removed", PATHY, {"app.py": PATHY["app.py"].replace("normalize_name(request.args['f'])", "request.args['f']")}, "정제|호출하는 함수|코드가 바뀌었다|흐름의 함수"),
        ("helper-added-to-chain", BASE, {"app.py": app_py.replace('d = request.args["d"]', 'd = transform(request.args["d"])') + "\ndef transform(x):\n    return x\n"}, "코드가 바뀌었다|흐름의 함수"),
        ("sink-moved-to-helper", BASE, {"app.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    _go(d)\n\ndef _go(d):\n    os.system("ls " + d)\n\ndef other():\n    return 1\n'}, "승인|코드가 바뀌었다|흐름의 함수|같은 지적인지 확인할 수 없다"),
        ("clone-in-same-file", BASE, {"app.py": app_py + "\ndef run_tool_copy():\n    d = request.args[\"d\"]\n    os.system(\"ls \" + d)\n"}, "__clone__"),
        ("clone-in-other-file", BASE, {"copy.py": app_py}, "__clone__"),
        ("clone-in-subpackage", BASE, {"pkg/handlers.py": app_py}, "__clone__"),
        ("rule-version-bumped", BASE, {}, "__rule_version__"),
        ("config-changed", BASE, {".iron-laws.yml": "fail_on: MEDIUM\n"}, "점검 설정"),
        ("config-excludes-changed", BASE, {".iron-laws.yml": "excludes: [docs]\nfail_on: HIGH\n"}, "점검 설정"),
        ("contract-changed", BASE, {}, "__contract__"),
        ("expired", BASE, {}, "__expired__"),
        ("file-deleted", BASE, {"__delete__": "app.py"}, "미확인"),
        ("tainted-second-source", BASE, {"app.py": app_py.replace('    d = request.args["d"]', '    d = request.args["d"] + request.args["e"]')}, "흐름의 함수|코드가 바뀌었다"),
        ("function-split", BASE, {"app.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    return _read()\n\ndef _read():\n    d = request.args["d"]\n    os.system("ls " + d)\n\ndef other():\n    return 1\n'}, "승인|코드가 바뀌었다|흐름의 함수|같은 지적인지 확인할 수 없다"),
        ("callers-in-two-files", BASE, {"a.py": "from app import run_tool\ndef a():\n    run_tool()\n", "b.py": "from app import run_tool\ndef b():\n    run_tool()\n"}, "호출자"),
        ("sink-in-conditional", BASE, {"app.py": app_py.replace('    os.system("ls " + d)', '    if d:\n        os.system("ls " + d)')}, "흐름의 함수|코드가 바뀌었다"),
        ("replace-os-system-with-popen", BASE, {"app.py": app_py.replace("os.system", "os.popen")}, "흐름의 함수|코드가 바뀌었다"),
    ]


RISKY = risky_cases()


@pytest.mark.parametrize(("name", "files", "change", "expected"), RISKY, ids=[c[0] for c in RISKY])
def test_risky_change_is_never_silently_inherited(tmp_path: Path, monkeypatch, name, files, change, expected):
    project = make(tmp_path / "proj", files)
    store = tmp_path / "s.jsonl"
    rule = "IL-502@app.py" if files is PATHY else "IL-504@app.py"
    approval_id = approve(project, store, rule, expires=(date.today() + timedelta(days=30)) if expected == "__expired__" else None)
    scanner_kwargs: dict = {}
    if expected == "__rule_version__":
        from iron_laws.rules.injection import CommandInjectionRule

        monkeypatch.setattr(CommandInjectionRule, "version", 2)
    elif expected == "__contract__":
        scanner_kwargs = {"contract": Contract(mode="block")}
    elif expected == "__expired__":
        record = ApprovalStore(store).records[0]
        record.expires = (date.today() - timedelta(days=1)).isoformat()
        record.hash = record.compute_hash()
        store.write_text(json.dumps(record.model_dump(mode="json"), ensure_ascii=False, sort_keys=True) + "\n")
    change = dict(change)  # 표본 정의를 바꾸지 않는다
    delete = change.pop("__delete__", None)
    apply_variant(project, change)
    if delete:
        (project / delete).unlink()
    scanner = AuditScanner(project, approvals=ApprovalStore(store), **scanner_kwargs)
    report = scanner.scan()
    rows = {r.approval.id: r for r in scanner.approval_rows}
    row = rows[approval_id]
    if expected == "__clone__":
        # 원본이 남아 있는 동안 복제본은 승인을 물려받지 않는다. 원본의 승인은 그대로 유효하고 복제본은 새 검토 대상이다.
        assert row.status == "valid", (name, row.status, row.reasons)
        cloned = [v for v in report.violations if v.rule_id == "IL-504" and v.approval_status != "approved"]
        assert cloned, f"{name}: 복제된 위험 코드가 승인 없이 남아 있어야 한다"
        assert not report.summary.is_passed
        return
    assert row.status != "valid", (name, "자동 승계되었다", row.status)
    if expected == "__rule_version__":
        assert any("규칙의 판정 의미" in r for r in row.reasons)
    elif expected == "__contract__":
        assert any("근거 계약" in r for r in row.reasons)
    elif expected == "__expired__":
        assert any("유효기간" in r for r in row.reasons)
    elif name == "file-deleted":
        assert row.status == "unobserved" and any("해소로 보지 않는다" in r for r in row.reasons)
    else:
        assert any(token in " ".join(row.reasons) for token in expected.split("|")), (name, row.reasons)
    assert not report.summary.is_passed or row.status == "unobserved"


def test_dangerous_inheritance_rate_is_zero_on_the_risky_sample(tmp_path_factory):
    inherited = 0
    for name, files, change, expected in RISKY:
        if expected in ("__rule_version__", "__contract__", "__expired__", "__clone__"):
            continue  # 별도 시험에서 각각 확인한다
        base = tmp_path_factory.mktemp(name.replace("-", "_"))
        project = make(base / "proj", files)
        store = base / "s.jsonl"
        approval_id = approve(project, store, "IL-502@app.py" if files is PATHY else "IL-504@app.py")
        change = dict(change)
        delete = change.pop("__delete__", None)
        apply_variant(project, change)
        if delete:
            (project / delete).unlink()
        inherited += status(project, store)[approval_id][0] == "valid"
    assert len(RISKY) == 30
    assert inherited == 0  # 표본에서 위험 승계 0건. 모집단 오류율 0을 뜻하지 않는다


# ---------------------------------------------------------------------------
# 일대일 대응, 읽기 실패, 복제
# ---------------------------------------------------------------------------


def test_clone_into_another_file_leaves_the_original_approval_and_flags_the_copy(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    (project / "copy.py").write_text(BASE["app.py"])
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    report = scanner.scan()
    statuses = {v.file_path.as_posix(): v.approval_status for v in report.violations if v.rule_id == "IL-504"}
    assert statuses == {"app.py": "approved", "copy.py": "none"}
    assert scanner.approval_rows[0].approval.id == approval_id


def test_moving_the_file_carries_the_approval_only_when_the_old_path_is_gone(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    (project / "pkg").mkdir()
    shutil.move(project / "app.py", project / "pkg" / "app.py")
    assert status(project, store)[approval_id][0] == "valid"
    shutil.copy(project / "pkg" / "app.py", project / "app.py")  # 옛 경로에 복제본이 생기면 모호하다
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    report = scanner.scan()
    assert sum(1 for v in report.violations if v.rule_id == "IL-504" and v.approval_status == "approved") == 1


def test_unreadable_file_is_unobserved_not_resolved(tmp_path: Path, monkeypatch):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    original = Path.read_bytes

    def locked(self):
        if self.name == "app.py":
            raise PermissionError(13, "Permission denied")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", locked)
    scanner = AuditScanner(project, approvals=ApprovalStore(store))
    report = scanner.scan()
    assert scanner.approval_rows[0].approval.id == approval_id and scanner.approval_rows[0].status == "unobserved"
    assert report.summary.approvals_unobserved == 1 and report.summary.scan_status == "incomplete"


def test_fixed_finding_resolves_the_approval(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approval_id = approve(project, store)
    (project / "app.py").write_text(APP_FIXED)
    assert status(project, store)[approval_id][0] == "resolved"


def test_two_approvals_in_one_function_do_not_cross_inherit(tmp_path: Path):
    code = 'import os\nfrom flask import request\n\ndef run_tool():\n    a = request.args["a"]\n    os.system("one " + a)\n    b = request.args["b"]\n    os.system("two " + b)\n'
    project = make(tmp_path / "proj", {"app.py": code})
    store = tmp_path / "s.jsonl"
    first = approve(project, store, "IL-504@app.py:6")
    second = approve(project, store, "IL-504@app.py:8")
    (project / "app.py").write_text(code.replace('"two "', '"two -v "'))  # 두 번째 지적의 코드만 바꾼다
    states = {k: v[0] for k, v in status(project, store).items()}
    assert states[first] in ("valid", "needs_review") and states[second] != "valid"


# ---------------------------------------------------------------------------
# baseline과 승인의 분리, 마이그레이션
# ---------------------------------------------------------------------------


def test_baseline_entries_are_never_promoted_to_approvals(tmp_path: Path):
    project = make(tmp_path / "proj")
    report = AuditScanner(project).scan()
    baseline = build_baseline(report, "1.1.1")
    base_path = tmp_path / "base.json"
    save_baseline(baseline, base_path)
    assert load_baseline(base_path).kind == "debt"
    migrated = tmp_path / "base.migrated.json"
    result = cli.invoke(app, ["baseline", "migrate", str(base_path), str(project), "-o", str(migrated)])
    assert result.exit_code == 0
    assert load_baseline(migrated).kind == "debt"
    assert not (tmp_path / ".iron-laws-approvals.jsonl").exists() and not (project / ".iron-laws-approvals.jsonl").exists()
    scanner = AuditScanner(project, baseline=load_baseline(migrated), approvals=ApprovalStore(tmp_path / "empty.jsonl"))
    out = scanner.scan()
    assert out.violations[0].baseline_status is BaselineStatus.EXISTING and out.violations[0].approval_status == "none"
    assert scanner.approval_rows == []


def test_baseline_migration_maps_old_fingerprints_one_to_one(tmp_path: Path):
    project = make(tmp_path / "proj")
    report = AuditScanner(project).scan()
    old = build_baseline(report, "1.0.0")
    for entry in old.entries:  # 옛 도구가 다른 방식으로 지문을 만들었다고 가정한다
        entry.fingerprint = "legacy-" + entry.fingerprint[:8]
        entry.loose = "legacy-loose"
    result = migrate_baseline(old, report.violations, "1.1.1")
    assert len(result.migrated) == len(old.entries) and result.unmatched == []
    assert result.baseline.entries[0].fingerprint == report.violations[0].fingerprint
    assert result.baseline.migrated_from == "1.0.0" and result.baseline.kind == "debt"
    gone = old.model_copy(deep=True)
    gone.entries[0].path = "missing.py"
    gone.entries[0].line = 999
    result = migrate_baseline(gone, report.violations, "1.1.1")
    assert result.unmatched and not result.migrated  # 맺지 못하면 옮기지 않는다


# ---------------------------------------------------------------------------
# 출력과 명령
# ---------------------------------------------------------------------------


def test_cli_add_status_queue_stats_roundtrip(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    added = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "관리자 전용 화면", "--reviewer", "홍", "--minutes", "12", "--store", str(store)])
    assert added.exit_code == 0, added.output
    approval_id = added.stdout.strip().splitlines()[-1]
    ok = cli.invoke(app, ["approvals", "status", str(project), "--store", str(store), "--json"])
    assert ok.exit_code == 0 and json.loads(ok.output)[0]["status"] == "valid"
    duplicate = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "중복", "--store", str(store)])
    assert duplicate.exit_code == 2
    (project / "app.py").write_text(BASE["app.py"] + "\ndef api():\n    return run_tool()\n")
    bad = cli.invoke(app, ["approvals", "status", str(project), "--store", str(store), "--json"])
    assert bad.exit_code == 1 and json.loads(bad.output)[0]["status"] == "needs_review"
    queue = cli.invoke(app, ["approvals", "queue", str(project), "--store", str(store), "--json"])
    items = json.loads(queue.output)
    assert items and items[0]["id"] == approval_id and "호출자" in items[0]["why"]
    stats = cli.invoke(app, ["approvals", "stats", "--store", str(store)])
    assert stats.exit_code == 0 and "12.0" in stats.output
    listing = cli.invoke(app, ["approvals", "list", "--store", str(store)])
    assert approval_id in listing.output
    assert cli.invoke(app, ["approvals", "verify", "--store", str(store)]).exit_code == 0


def test_check_with_approvals_option_gates_on_validity(tmp_path: Path):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    approve(project, store)
    assert cli.invoke(app, ["check", str(project)]).exit_code == 1
    assert cli.invoke(app, ["check", str(project), "--approvals", str(store)]).exit_code == 0
    (project / "app.py").write_text(BASE["app.py"].replace('"ls "', '"ls -l "'))
    assert cli.invoke(app, ["check", str(project), "--approvals", str(store)]).exit_code == 1


def test_add_refuses_incomplete_scan_and_unverifiable_receipt(tmp_path: Path, monkeypatch):
    project = make(tmp_path / "proj")
    store = tmp_path / "s.jsonl"
    receipt = tmp_path / "r.json"
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": APP_FIXED}))
    from tests.test_stage3_verify import make_project

    other = make_project(tmp_path / "other")
    patch2 = tmp_path / "p2.diff"
    patch2.write_text(make_diff(other, {"app.py": APP_FIXED}))
    data = verify_patch(other, patch2, VerifyOptions(finding="IL-504@app.py:6", runner="none", require_tests=False)).model_dump_json()
    receipt.write_text(data.replace('"verified"', '"failed"', 1))  # 변조
    result = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "관리자 전용", "--receipt", str(receipt), "--store", str(store)])
    assert result.exit_code == 2 and "해시가 맞지 않습니다" in result.output
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    monkeypatch.setattr(HardcodedSecretRule, "check", lambda self, src: (_ for _ in ()).throw(RuntimeError("x")))
    incomplete = cli.invoke(app, ["approvals", "add", str(project), "--finding", RULE, "--reason", "관리자 전용", "--store", str(store)])
    assert incomplete.exit_code == 2 and not store.exists()


def test_valid_receipt_digest_is_recorded(tmp_path: Path):
    from tests.test_stage3_verify import make_project

    project = make_project(tmp_path / "proj")
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": APP_FIXED}))
    receipt = verify_patch(project, patch, VerifyOptions(finding="IL-504@app.py:6", runner="none", require_tests=False))
    path = tmp_path / "r.json"
    path.write_text(receipt.model_dump_json())
    vulnerable = make(tmp_path / "vuln", {"app.py": APP})
    store = tmp_path / "s.jsonl"
    result = cli.invoke(app, ["approvals", "add", str(vulnerable), "--finding", "IL-504@app.py", "--reason", "검증 기록을 확인함", "--receipt", str(path), "--store", str(store)])
    assert result.exit_code == 0, result.output
    assert ApprovalStore(store).records[0].receipt_digest == receipt.receipt_digest


def test_approval_store_inside_the_repo_cannot_be_rewritten_by_a_patch(tmp_path: Path):
    from tests.test_stage3_verify import make_project

    project = make_project(tmp_path / "proj")
    approve(project, project / ".iron-laws-approvals.jsonl", "IL-504@app.py:6")
    forged = (project / ".iron-laws-approvals.jsonl").read_text().replace("관리자", "누구나")
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": APP_FIXED, ".iron-laws-approvals.jsonl": forged}))
    receipt = verify_patch(project, patch, VerifyOptions(finding="IL-504@app.py:6", runner="none", require_tests=False))
    assert "policy_changed" in {b["kind"] for b in receipt.bypass_changes}
    assert ".iron-laws-approvals.jsonl" in receipt.inputs["restored_trusted_files"]
    assert receipt.verdict.overall == "failed"


def test_default_config_object_is_unchanged_by_approvals(tmp_path: Path):
    assert IronLawsConfig().fail_on.value == "HIGH"
