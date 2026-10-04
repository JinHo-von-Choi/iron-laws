"""
오철칙 평가 보고서 실행계획(P0~P2) 구현 시험: 분기 합류 흐름 분석, 문맥별 정제, 파일 간 해석, 진단, 기준선, 억제 만료, 설정 선택, 지원 행렬
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import IronLawsConfig, Limits
from iron_laws.core.models import Confidence
from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of, scan_files

runner = CliRunner()
PY = "import os\nfrom flask import request\n"
SECRET = 'password = "ActualHardcodedPassword123!"\n'

# ---------------------------------------------------------------------------
# P2 B: 분기 합류와 반복을 따르는 흐름 분석 (규칙, 파일, 기대 줄)
# ---------------------------------------------------------------------------
BRANCH_CASES = [
    (
        "if-else-both-sanitize",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = request.args['d']\n    if c:\n        d = 'a'\n    else:\n        d = 'b'\n    os.system('ls ' + d)\n"},
        {},
    ),
    (
        "if-only-one-branch-sanitizes",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = request.args['d']\n    if c:\n        d = 'a'\n    os.system('ls ' + d)\n"},
        {"a.py": [7]},
    ),
    (
        "elif-chain-with-else-sanitizes-all",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = request.args['d']\n    if c == 1:\n        d = 'a'\n    elif c == 2:\n        d = 'b'\n    else:\n        d = 'c'\n    os.system('ls ' + d)\n"},
        {},
    ),
    (
        "elif-chain-without-else",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = request.args['d']\n    if c == 1:\n        d = 'a'\n    elif c == 2:\n        d = 'b'\n    os.system('ls ' + d)\n"},
        {"a.py": [9]},
    ),
    (
        "taint-added-in-branch",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = 'safe'\n    if c:\n        d = request.args['d']\n    os.system('ls ' + d)\n"},
        {"a.py": [7]},
    ),
    (
        "return-in-tainted-branch",
        "IL-504",
        {"a.py": PY + "def h(c):\n    d = 'safe'\n    if c:\n        d = request.args['d']\n        return d\n    os.system('ls ' + d)\n"},
        {},
    ),
    (
        "loop-carried-taint",
        "IL-504",
        {"a.py": PY + "def h(items):\n    prev = 'safe'\n    for i in items:\n        os.system('ls ' + prev)\n        prev = request.args['d']\n"},
        {"a.py": [6]},
    ),
    (
        "try-except-sanitizes",
        "IL-504",
        {"a.py": PY + "def h():\n    d = request.args['d']\n    try:\n        d = int(d)\n    except ValueError:\n        d = 0\n    os.system('ls ' + str(d))\n"},
        {},
    ),
    (
        "java-switch-with-default",
        "IL-501",
        {"A.java": 'class A {\n  void m(HttpServletRequest request, int k) throws Exception {\n    String s = request.getParameter("a");\n    switch (k) {\n      case 1: s = "x"; break;\n      default: s = "y";\n    }\n    stmt.executeQuery("SELECT * FROM t WHERE a=\'" + s + "\'");\n  }\n}\n'},
        {},
    ),
    (
        "java-switch-without-default",
        "IL-501",
        {"A.java": 'class A {\n  void m(HttpServletRequest request, int k) throws Exception {\n    String s = request.getParameter("a");\n    switch (k) {\n      case 1: s = "x"; break;\n    }\n    stmt.executeQuery("SELECT * FROM t WHERE a=\'" + s + "\'");\n  }\n}\n'},
        {"A.java": [7]},
    ),
    (
        "js-else-if-chain",
        "IL-504",
        {"a.js": "const {exec} = require('child_process');\napp.get('/x', (req, res) => {\n  let d = req.query.d;\n  if (a) { d = 'a'; } else if (b) { d = 'b'; } else { d = 'c'; }\n  exec('ls ' + d);\n});\n"},
        {},
    ),
    (
        "js-else-if-chain-no-final-else",
        "IL-504",
        {"a.js": "const {exec} = require('child_process');\napp.get('/x', (req, res) => {\n  let d = req.query.d;\n  if (a) { d = 'a'; } else if (b) { d = 'b'; }\n  exec('ls ' + d);\n});\n"},
        {"a.js": [5]},
    ),
    (
        "go-if-else-both-safe",
        "IL-501",
        {"a.go": 'package main\nimport ("database/sql";"net/http")\nfunc h(db *sql.DB, r *http.Request) {\n\tn := r.URL.Query().Get("n")\n\tif n == "" {\n\t\tn = "a"\n\t} else {\n\t\tn = "b"\n\t}\n\tdb.Query("SELECT * FROM t WHERE n=\'" + n + "\'")\n}\n'},
        {},
    ),
]

# ---------------------------------------------------------------------------
# P2 B: 정제는 자기가 막는 문맥에서만 유효하다
# ---------------------------------------------------------------------------
CONTEXT_CASES = [
    (
        "html-escape-does-not-sanitize-shell",
        "IL-504",
        {"a.py": PY + "import html\ndef h():\n    d = html.escape(request.args['d'])\n    os.system('ls ' + d)\n"},
        {"a.py": [6]},
    ),
    (
        "shlex-quote-sanitizes-shell",
        "IL-504",
        {"a.py": PY + "import shlex\ndef h():\n    d = shlex.quote(request.args['d'])\n    os.system('ls ' + d)\n"},
        {},
    ),
    (
        "html-escape-does-not-sanitize-sql",
        "IL-501",
        {"a.py": "import html\n" + PY + "def h(cur):\n    n = html.escape(request.args['n'])\n    cur.execute(\"SELECT * FROM t WHERE n = '\" + n + \"'\")\n"},
        {"a.py": [6]},
    ),
    (
        "int-cast-sanitizes-sql",
        "IL-501",
        {"a.py": PY + "def h(cur):\n    n = int(request.args['n'])\n    cur.execute('SELECT * FROM t WHERE n = ' + str(n))\n"},
        {},
    ),
    (
        "normalize-is-not-path-sanitizer",
        "IL-502",
        {"a.py": PY + "def h():\n    p = os.path.normpath(request.args['p'])\n    return open('/srv/' + p).read()\n"},
        {"a.py": [5]},
    ),
    (
        "secure-filename-sanitizes-path",
        "IL-502",
        {"a.py": PY + "from werkzeug.utils import secure_filename\ndef h():\n    p = secure_filename(request.args['p'])\n    return open('/srv/' + p).read()\n"},
        {},
    ),
]

# ---------------------------------------------------------------------------
# P2 B: 파일 간 호출 해석 (Python 시범)
# ---------------------------------------------------------------------------
UTIL = (
    "import os\n"
    "def read_file(path):\n    return open('/srv/' + path).read()\n"
    "def fixed(x):\n    return 'fixed'\n"
    "def passthru(x):\n    return x\n"
    "def run(cmd):\n    os.system(cmd)\n"
)
CROSS_CASES = [
    (
        "from-import-param-reaches-sink",
        "IL-502",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app.util import read_file\ndef a():\n    return read_file(request.args['f'])\n"},
        {"app/views.py": [5]},
    ),
    (
        "from-import-constant-argument",
        "IL-502",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": "from app.util import read_file\ndef a():\n    return read_file('readme.txt')\n"},
        {},
    ),
    (
        "module-alias-call",
        "IL-504",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app import util\ndef a():\n    util.run(request.args['x'])\n"},
        {"app/views.py": [5]},
    ),
    (
        "return-taint-through-other-file",
        "IL-504",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app.util import passthru, run\ndef a():\n    run(passthru(request.args['x']))\n"},
        {"app/views.py": [5]},
    ),
    (
        "other-file-helper-returns-constant",
        "IL-504",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app.util import fixed, run\ndef a():\n    run(fixed(request.args['x']))\n"},
        {},
    ),
    (
        "relative-import",
        "IL-502",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from .util import read_file\ndef a():\n    return read_file(request.args['f'])\n"},
        {"app/views.py": [5]},
    ),
    (
        "import-alias",
        "IL-502",
        {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "import app.util as u\ndef a():\n    return u.read_file(request.args['f'])\n"},
        {"app/views.py": [5]},
    ),
    (
        "circular-import-terminates",
        "IL-504",
        {
            "app/__init__.py": "",
            "app/a.py": "from app.b import g\ndef f(x):\n    return g(x)\n",
            "app/b.py": "from app.a import f\ndef g(x):\n    return f(x)\n",
            "app/views.py": PY + "from app.a import f\ndef h():\n    os.system(f(request.args['x']))\n",
        },
        {"app/views.py": [5]},
    ),
]


@pytest.mark.parametrize(
    ("name", "rule", "files", "expected"),
    [*BRANCH_CASES, *CONTEXT_CASES, *CROSS_CASES],
    ids=[c[0] for c in [*BRANCH_CASES, *CONTEXT_CASES, *CROSS_CASES]],
)
def test_flow_cases(tmp_path: Path, name, rule, files, expected):
    # 문자열 조합 자체를 의심하는 '확인 필요' 지적과 구분하려고 외부 입력 도달이 확정된 지적만 센다
    violations = [v for v in scan_files(tmp_path, files) if v.confidence is Confidence.CONFIRMED]
    for path in files:
        assert lines_of(violations, rule, path) == expected.get(path, []), name


def test_cross_file_finding_names_the_inner_sink_location(tmp_path: Path):
    files = {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app.util import read_file\ndef a():\n    return read_file(request.args['f'])\n"}
    violations = scan_files(tmp_path, files)
    hit = next(v for v in violations if v.rule_id == "IL-502")
    assert hit.file_path.as_posix() == "app/views.py"
    assert "app/util.py:3" in hit.message
    assert [e.role for e in hit.evidence][-1] == "sink"
    assert hit.evidence[-1].file_path == "app/util.py"


def test_cross_file_budget_exhaustion_is_reported_not_silent(tmp_path: Path):
    files = {"app/__init__.py": "", "app/util.py": UTIL, "app/views.py": PY + "from app.util import read_file\ndef a():\n    return read_file(request.args['f'])\n"}
    for rel, content in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(content)
    config = IronLawsConfig(limits=Limits(max_cross_file_lookups=0))
    report = AuditScanner(tmp_path, config).scan()
    assert not any(v.rule_id == "IL-502" and v.file_path.as_posix() == "app/views.py" for v in report.violations)
    assert any(d.kind == "analysis_limit" for d in report.diagnostics)


# ---------------------------------------------------------------------------
# P0 A: 불완전한 점검은 통과가 아니다
# ---------------------------------------------------------------------------


def test_rule_exception_makes_the_scan_incomplete(tmp_path: Path, monkeypatch):
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    def boom(self, src):
        raise RuntimeError("의도한 시험 오류")

    monkeypatch.setattr(HardcodedSecretRule, "check", boom)
    (tmp_path / "a.py").write_text("x = 1\n")
    report = AuditScanner(tmp_path).scan()
    assert report.summary.scan_status == "incomplete"
    assert report.summary.grade == "불완전"
    assert not report.summary.is_passed
    assert any(d.kind == "rule_error" and "IL-101" in d.message for d in report.diagnostics)
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
    assert json.loads(result.output[result.output.index("{") :].split("\n점검이")[0])["summary"]["scan_status"] == "incomplete"


def test_unreadable_file_is_reported_as_error(tmp_path: Path, monkeypatch):
    target = tmp_path / "locked.py"
    target.write_text("x = 1\n")
    (tmp_path / "ok.py").write_text("y = 2\n")
    original = Path.read_bytes

    def fail_for_locked(self):
        if self.name == "locked.py":
            raise PermissionError(13, "Permission denied")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", fail_for_locked)
    report = AuditScanner(tmp_path).scan()
    assert report.summary.scan_status == "incomplete"
    assert any(d.kind == "read" and d.file_path == "locked.py" for d in report.diagnostics)


def test_non_utf8_file_is_decoded_and_reported(tmp_path: Path):
    (tmp_path / "k.py").write_bytes('# 한글 주석\npassword = "ActualHardcodedPassword123!"\n'.encode("cp949"))
    report = AuditScanner(tmp_path).scan()
    assert any(d.kind == "encoding" for d in report.diagnostics)
    assert any(v.rule_id == "IL-101" for v in report.violations)
    assert report.summary.scan_status == "complete"


def test_binary_file_is_skipped_with_reason(tmp_path: Path):
    (tmp_path / "blob.py").write_bytes(b"\x00\x01\x02" * 100)
    (tmp_path / "ok.py").write_text("x = 1\n")
    report = AuditScanner(tmp_path).scan()
    assert any(s["path"] == "blob.py" and "이진" in s["reason"] for s in report.metadata["skipped_files"])


def test_syntax_error_file_is_a_warning_not_a_pass_claim(tmp_path: Path):
    (tmp_path / "bad.py").write_text("def f(:\n    pass\n")
    report = AuditScanner(tmp_path).scan()
    assert any(d.kind == "parse" and d.severity == "warning" for d in report.diagnostics)


def test_report_records_tool_ruleset_config_and_language_counts(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.js").write_text("const y = 2;\n")
    meta = AuditScanner(tmp_path).scan().metadata
    assert meta["tool_version"]
    assert meta["ruleset"]["count"] >= 90
    assert len(meta["ruleset"]["hash"]) == 16
    assert meta["files_by_language"] == {"javascript": 1, "python": 1}
    assert meta["config_source"] == "기본값"
    assert len(meta["config_hash"]) == 16


def test_excluded_and_unscanned_files_are_counted(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "m.js").write_text("1;\n")
    (tmp_path / "data.zip").write_bytes(b"PK")
    (tmp_path / "lib.min.js").write_text("1;\n")
    meta = AuditScanner(tmp_path).scan().metadata
    assert meta["excluded_summary"]["directories"].get("node_modules") == 1
    assert meta["excluded_summary"]["files"].get("*.min.js") == 1
    assert meta["unscanned_by_extension"].get(".zip") == 1


# ---------------------------------------------------------------------------
# P1 A: 설정 선택
# ---------------------------------------------------------------------------


def test_explicit_config_beats_folder_config(tmp_path: Path):
    (tmp_path / "a.py").write_text(SECRET)
    (tmp_path / ".iron-laws.yml").write_text("fail_on: LOW\n")
    other = tmp_path / "ci.yml"
    other.write_text("fail_on: CRITICAL\n")
    meta = AuditScanner(tmp_path, config_path=other).scan().metadata
    assert meta["config"]["fail_on"] == "CRITICAL"
    assert meta["config_source"].endswith("ci.yml")


def test_missing_explicit_config_is_an_error(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = runner.invoke(app, ["check", str(tmp_path), "--config", str(tmp_path / "nope.yml")])
    assert result.exit_code == 2


def test_parent_config_is_found_only_when_asked(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("fail_on: CRITICAL\n")
    sub = tmp_path / "pkg"
    sub.mkdir()
    (sub / "a.py").write_text("x = 1\n")
    assert AuditScanner(sub).scan().metadata["config_source"] == "기본값"
    found = AuditScanner(sub, search_parents=True).scan().metadata
    assert found["config"]["fail_on"] == "CRITICAL"
    assert found["config_source"].endswith(".iron-laws.yml")


def test_cli_option_overrides_config_fail_on_and_says_so(tmp_path: Path):
    (tmp_path / "a.py").write_text(SECRET)
    (tmp_path / ".iron-laws.yml").write_text("fail_on: CRITICAL\n")
    result = runner.invoke(app, ["check", str(tmp_path), "--fail-on", "LOW"])
    assert "명령행 옵션" in result.output


# ---------------------------------------------------------------------------
# P1 B: 억제 만료·미사용·미등록, 기준선
# ---------------------------------------------------------------------------


def _suppression_report(tmp_path: Path, comment: str):
    (tmp_path / "a.py").write_text(f"# {comment}\n" + SECRET)
    return AuditScanner(tmp_path).scan()


def test_expired_suppression_is_not_applied_and_is_reported(tmp_path: Path):
    past = (date.today() - timedelta(days=1)).isoformat()
    report = _suppression_report(tmp_path, f"iron-laws: ignore-file[IL-101] until={past} 임시 예외")
    assert any(v.rule_id == "IL-101" for v in report.violations)
    assert any("만료" in d.message for d in report.diagnostics)


def test_unexpired_suppression_applies(tmp_path: Path):
    future = (date.today() + timedelta(days=30)).isoformat()
    report = _suppression_report(tmp_path, f"iron-laws: ignore-file[IL-101] until={future} 임시 예외")
    assert not any(v.rule_id == "IL-101" for v in report.violations)
    assert report.summary.suppressed_count == 1


def test_invalid_expiry_date_is_reported(tmp_path: Path):
    report = _suppression_report(tmp_path, "iron-laws: ignore-file[IL-101] until=내일 임시 예외")
    assert any(v.rule_id == "IL-101" for v in report.violations)
    assert any("만료일 형식" in d.message for d in report.diagnostics)


def test_unused_and_unknown_suppressions_are_listed(tmp_path: Path):
    (tmp_path / "a.py").write_text("# iron-laws: ignore-file[IL-101] 불필요한 예외\nx = 1\n# iron-laws: ignore[IL-999] 없는 규칙\n")
    report = AuditScanner(tmp_path).scan()
    messages = [d.message for d in report.diagnostics if d.kind == "suppression"]
    assert any("사용되지 않은" in m for m in messages)
    assert any("IL-999" in m for m in messages)


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text(PY + "def h():\n    d = request.args['d']\n    os.system('ls ' + d)\n")
    (tmp_path / "b.py").write_text(SECRET)
    return tmp_path


def _create_baseline(path: Path) -> Path:
    out = path / "base.json"
    result = runner.invoke(app, ["baseline", "create", str(path), "--output", str(out)])
    assert result.exit_code == 0, result.output
    return out


def test_baseline_keeps_known_findings_and_fails_only_on_new(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    assert runner.invoke(app, ["check", str(project)]).exit_code == 1
    assert runner.invoke(app, ["check", str(project), "--baseline", str(base)]).exit_code == 0
    (project / "c.py").write_text(PY + "def g():\n    c = request.args['c']\n    os.system('echo ' + c)\n")
    result = runner.invoke(app, ["check", str(project), "--baseline", str(base)])
    assert result.exit_code == 1
    assert "신규·재검토 1건" in result.output


def test_baseline_survives_line_shifts(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    source = (project / "a.py").read_text()
    (project / "a.py").write_text("# 맨 위에 주석을 추가해 줄이 밀린다\n# 한 줄 더\n" + source)
    result = runner.invoke(app, ["check", str(project), "--baseline", str(base)])
    assert result.exit_code == 0
    assert "신규·재검토 0건" in result.output


def test_baseline_survives_file_move(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    (project / "pkg").mkdir()
    (project / "b.py").rename(project / "pkg" / "b.py")
    result = runner.invoke(app, ["check", str(project), "--baseline", str(base)])
    assert result.exit_code == 0


def test_baseline_counts_duplicate_findings_separately(tmp_path: Path):
    (tmp_path / "a.py").write_text(PY + "def h():\n    d = request.args['d']\n    os.system('ls ' + d)\n    os.system('ls ' + d)\n")
    base = _create_baseline(tmp_path)
    source = (tmp_path / "a.py").read_text()
    (tmp_path / "a.py").write_text(source + "    os.system('ls ' + d)\n")
    result = runner.invoke(app, ["check", str(tmp_path), "--baseline", str(base), "--limit", "0"])
    assert result.exit_code == 1


def test_changed_rule_version_requires_review(tmp_path: Path, monkeypatch):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    monkeypatch.setattr(HardcodedSecretRule, "version", 2)
    report = AuditScanner(project, baseline=json_baseline(base)).scan()
    review = [v for v in report.violations if v.rule_id == "IL-101"]
    assert review and all(v.baseline_status.value == "review" for v in review)
    assert not report.summary.is_passed


def json_baseline(path: Path):
    from iron_laws.core.baseline import load_baseline

    return load_baseline(path)


def test_removed_rule_in_baseline_is_not_auto_approved(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    data = json.loads(base.read_text())
    data["entries"].append({"fingerprint": "x" * 20, "loose": "y" * 20, "rule_id": "IL-777", "rule_version": 1, "path": "gone.py", "line": 1, "severity": "HIGH"})
    base.write_text(json.dumps(data))
    report = AuditScanner(project, baseline=json_baseline(base)).scan()
    assert any(d.kind == "baseline" and "IL-777" in d.message for d in report.diagnostics)


def test_baseline_cannot_be_created_from_incomplete_scan(tmp_path: Path, monkeypatch):
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    monkeypatch.setattr(HardcodedSecretRule, "check", lambda self, src: (_ for _ in ()).throw(RuntimeError("x")))
    (tmp_path / "a.py").write_text("x = 1\n")
    result = runner.invoke(app, ["baseline", "create", str(tmp_path), "--output", str(tmp_path / "b.json")])
    assert result.exit_code == 2
    assert not (tmp_path / "b.json").exists()


def test_baseline_cannot_be_created_from_empty_scan(tmp_path: Path):
    result = runner.invoke(app, ["baseline", "create", str(tmp_path), "--output", str(tmp_path / "b.json")])
    assert result.exit_code == 2


def test_invalid_baseline_file_is_a_config_error(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert runner.invoke(app, ["check", str(tmp_path), "--baseline", str(bad)]).exit_code == 2
    assert runner.invoke(app, ["check", str(tmp_path), "--baseline", str(tmp_path / "missing.json")]).exit_code == 2


def test_fix_prompt_with_baseline_lists_only_new_findings(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    (project / "c.py").write_text(PY + "def g():\n    c = request.args['c']\n    os.system('echo ' + c)\n")
    result = runner.invoke(app, ["fix-prompt", str(project), "--baseline", str(base)])
    assert "c.py" in result.output
    assert "b.py" not in result.output


def test_baseline_diff_command(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    result = runner.invoke(app, ["baseline", "diff", str(project), "--baseline", str(base)])
    assert result.exit_code == 0
    assert "기존" in result.output


def test_changed_since_filters_to_changed_files(tmp_path: Path):
    def git(*args):
        subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=n", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "old.py").write_text(SECRET)
    git("add", "-A")
    git("commit", "-qm", "base")
    (tmp_path / "new.py").write_text(SECRET)
    result = runner.invoke(app, ["audit", str(tmp_path), "--changed-since", "HEAD", "--format", "json"])
    report = json.loads(result.output)
    assert {v["file_path"] for v in report["violations"]} == {"new.py"}
    assert report["metadata"]["scope"]["mode"] == "changed-since"


def test_changed_since_with_bad_ref_is_an_error(tmp_path: Path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["check", str(tmp_path), "--changed-since", "no-such-ref"]).exit_code == 2


# ---------------------------------------------------------------------------
# P1 C: 근거(provenance), SARIF 코드 흐름, 마스킹
# ---------------------------------------------------------------------------


def test_violation_carries_source_propagation_sink_evidence(tmp_path: Path):
    violations = scan_files(tmp_path, {"a.py": PY + "def h():\n    d = request.args['d']\n    os.system('ls ' + d)\n"})
    hit = next(v for v in violations if v.rule_id == "IL-504")
    assert [e.role for e in hit.evidence] == ["source", "propagation", "sink"]
    assert [e.line for e in hit.evidence] == [4, 5, 5]
    assert "d" in hit.evidence[1].note


def test_evidence_never_contains_code_text(tmp_path: Path):
    violations = scan_files(tmp_path, {"a.py": PY + "def h():\n    secret_value = request.args['password_hunter2']\n    os.system('ls ' + secret_value)\n"})
    dumped = json.dumps([e.model_dump() for v in violations for e in v.evidence], ensure_ascii=False)
    assert "hunter2" not in dumped


def test_sarif_has_code_flows_and_fingerprints(tmp_path: Path):
    (tmp_path / "a.py").write_text(PY + "def h():\n    d = request.args['d']\n    os.system('ls ' + d)\n")
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "sarif"])
    sarif_result = next(r for r in json.loads(result.output)["runs"][0]["results"] if r["ruleId"] == "IL-504")
    flow = sarif_result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(flow) == 3
    assert sarif_result["partialFingerprints"]["ironLaws/v1"]


def test_sarif_marks_baseline_state(tmp_path: Path):
    project = _make_project(tmp_path)
    base = _create_baseline(project)
    result = runner.invoke(app, ["audit", str(project), "--format", "sarif", "--baseline", str(base)])
    states = {r["baselineState"] for r in json.loads(result.output)["runs"][0]["results"]}
    assert states == {"unchanged"}


def test_two_secrets_on_one_line_are_both_masked(tmp_path: Path):
    (tmp_path / "a.py").write_text('cfg = {"password": "FirstSecretValue123!", "api_key": "SecondSecretValue456!"}\n')
    for fmt in ("json", "markdown", "sarif", "review", "prompt"):
        out = runner.invoke(app, ["audit", str(tmp_path), "--format", fmt]).output
        assert "FirstSecretValue123" not in out, fmt
        assert "SecondSecretValue456" not in out, fmt


def test_multiline_secret_assignment_keeps_surrounding_code(tmp_path: Path):
    (tmp_path / "a.py").write_text('def connect():\n    password = "ActualHardcodedPassword123!"\n    return open_db(host="db", password=password)\n')
    out = runner.invoke(app, ["audit", str(tmp_path), "--format", "json"]).output
    data = json.loads(out)
    hit = next(v for v in data["violations"] if v["rule_id"] == "IL-101")
    assert hit["snippet"] == 'password = "****"'
    assert "ActualHardcodedPassword123" not in out


def test_report_json_has_schema_version(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    data = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--format", "json"]).output)
    assert data["schema_version"] == "1.1"
    assert "diagnostics" in data


# ---------------------------------------------------------------------------
# P2 A: 지원 행렬
# ---------------------------------------------------------------------------


def test_support_matrix_command_lists_rules_and_verification_counts():
    result = runner.invoke(app, ["support"])
    assert result.exit_code == 0
    assert "IL-501" in result.output
    assert "미검증" in result.output
    assert "양성·음성 시험이 모두 있는 칸" in result.output


def test_support_matrix_single_rule_shows_benchmark_only_for_java():
    result = runner.invoke(app, ["support", "IL-501"])
    java_line = next(line for line in result.output.splitlines() if line.startswith("| java |"))
    python_line = next(line for line in result.output.splitlines() if line.startswith("| python"))
    assert "OWASP Benchmark" in java_line
    assert "OWASP Benchmark" not in python_line


def test_support_matrix_unknown_rule_is_an_error():
    assert runner.invoke(app, ["support", "IL-999"]).exit_code == 2


def test_support_fixture_manifest_is_up_to_date():
    root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, str(root / "benchmarks" / "build_support_manifest.py"), "--check"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# P1 B: 검토 기록
# ---------------------------------------------------------------------------


def test_feedback_records_and_summarizes(tmp_path: Path):
    log = tmp_path / "fb.jsonl"
    for verdict, minutes in (("accepted", "10"), ("false-positive", "20"), ("false-positive", "30")):
        result = runner.invoke(
            app, ["feedback", "add", "IL-501", "src/a.py:3", "--verdict", verdict, "--minutes", minutes, "--reason", "시험", "--file", str(log)]
        )
        assert result.exit_code == 0
    summary = runner.invoke(app, ["feedback", "summary", "--file", str(log)])
    assert summary.exit_code == 0
    assert "IL-501" in summary.output
    assert "20.0" in summary.output


def test_feedback_rejects_unknown_verdict(tmp_path: Path):
    result = runner.invoke(app, ["feedback", "add", "IL-501", "a.py:1", "--verdict", "maybe", "--file", str(tmp_path / "f.jsonl")])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# 병렬 처리, .gitignore 선택 옵션, 단일 파일 SARIF
# ---------------------------------------------------------------------------


def _many_files(root: Path, count: int = 12) -> None:
    for i in range(count):
        (root / f"m{i}.py").write_text(SECRET if i % 3 == 0 else "x = 1\n")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="병렬 처리는 Linux에서만 쓴다")
def test_parallel_and_serial_scans_agree(tmp_path: Path, monkeypatch):
    import iron_laws.core.scanner as scanner_module

    _many_files(tmp_path)
    serial = AuditScanner(tmp_path).scan()
    monkeypatch.setattr(scanner_module, "PARALLEL_MIN_FILES", 1)
    parallel = AuditScanner(tmp_path).scan()
    key = lambda r: sorted((v.rule_id, v.file_path.as_posix(), v.line_number) for v in r.violations)  # noqa: E731
    assert key(serial) == key(parallel)
    assert parallel.summary.scan_status == "complete"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="병렬 처리는 Linux에서만 쓴다")
def test_parallel_rule_error_is_reported_from_workers(tmp_path: Path, monkeypatch):
    import iron_laws.core.scanner as scanner_module
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    _many_files(tmp_path)
    monkeypatch.setattr(scanner_module, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(HardcodedSecretRule, "check", lambda self, src: (_ for _ in ()).throw(RuntimeError("작업 프로세스 오류")))
    report = AuditScanner(tmp_path).scan()
    assert report.summary.scan_status == "incomplete"
    assert sum(1 for d in report.diagnostics if d.kind == "rule_error") == 12


def test_broken_worker_pool_is_retried_serially_and_recorded(tmp_path: Path, monkeypatch):
    from concurrent.futures.process import BrokenProcessPool

    import iron_laws.core.scanner as scanner_module

    class Broken:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def map(self, *args, **kwargs):
            raise BrokenProcessPool("시험용 중단")

    _many_files(tmp_path)
    monkeypatch.setattr(scanner_module, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(scanner_module, "ProcessPoolExecutor", Broken)
    monkeypatch.setattr(scanner_module.os, "cpu_count", lambda: 4)
    if not sys.platform.startswith("linux"):
        pytest.skip("병렬 처리는 Linux에서만 쓴다")
    report = AuditScanner(tmp_path).scan()
    assert any(d.kind == "worker" and "처음부터 다시" in d.message for d in report.diagnostics)
    assert report.summary.scan_status == "complete"  # 재시도로 모두 점검했으므로 불완전이 아니다
    assert sum(1 for v in report.violations if v.rule_id == "IL-101") == 4


def test_gitignore_is_applied_only_when_asked(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("secrets_dir/\n*.local.py\n")
    (tmp_path / "secrets_dir").mkdir()
    (tmp_path / "secrets_dir" / "a.py").write_text(SECRET)
    (tmp_path / "b.local.py").write_text(SECRET)
    (tmp_path / "c.py").write_text(SECRET)
    default = AuditScanner(tmp_path).scan()
    assert {v.file_path.as_posix() for v in default.violations if v.rule_id == "IL-101"} == {"secrets_dir/a.py", "b.local.py", "c.py"}
    respected = AuditScanner(tmp_path, respect_gitignore=True).scan()
    assert {v.file_path.as_posix() for v in respected.violations if v.rule_id == "IL-101"} == {"c.py"}
    assert respected.metadata["excluded_summary"]["files"].get("(.gitignore)") == 1
    assert respected.metadata["excluded_summary"]["directories"].get("(.gitignore)") == 1


def test_gitignore_option_from_cli_and_config(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("c.py\n")
    (tmp_path / "c.py").write_text(SECRET)
    (tmp_path / "d.py").write_text("x = 1\n")
    assert runner.invoke(app, ["check", str(tmp_path)]).exit_code == 1
    assert runner.invoke(app, ["check", str(tmp_path), "--respect-gitignore"]).exit_code == 0
    (tmp_path / ".iron-laws.yml").write_text("respect_gitignore: true\n")
    assert runner.invoke(app, ["check", str(tmp_path)]).exit_code == 0


def test_sarif_for_single_file_inside_subfolder(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pkg" / "한글 폴더").mkdir(parents=True)
    target = tmp_path / "pkg" / "한글 폴더" / "a b.py"
    target.write_text(SECRET)
    result = runner.invoke(app, ["audit", str(target), "--format", "sarif"])
    uri = json.loads(result.output)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "pkg/%ED%95%9C%EA%B8%80%20%ED%8F%B4%EB%8D%94/a%20b.py"
