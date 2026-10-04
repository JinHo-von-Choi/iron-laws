"""
오철칙 외부 평가 보고서(v1.0.0 평가)에서 재현된 결함의 회귀 시험
작성자: 최진호
작성일: 2026-10-04
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import DEFAULT_EXTENSIONS, IronLawsConfig
from iron_laws.engine.languages import EXTENSION_TO_LANG
from tests.helpers import lines_of, scan_files

runner = CliRunner()

PY_WEB = "from flask import request\n"

# (이름, 규칙, 파일들, 기대 줄). 기대 줄이 비어 있으면 지적이 없어야 한다.
FLOW_CASES = [
    # 싱크보다 뒤의 안전한 재대입이 앞선 위험한 접근을 지우면 안 된다
    (
        "later-assignment-keeps-sink",
        "IL-502",
        {"a.py": PY_WEB + "def h():\n    f = request.args['p']\n    c = open('/srv/' + f).read()\n    f = 'x'\n    return c\n"},
        {"a.py": [4]},
    ),
    (
        "earlier-safe-assignment-clears",
        "IL-502",
        {"a.py": PY_WEB + "def h():\n    f = request.args['p']\n    f = 'x'\n    return open('/srv/' + f).read()\n"},
        {},
    ),
    # 이름이 sanitize여도 같은 파일에 정의된 함수는 본문 동작을 따른다
    (
        "local-sanitize-is-identity",
        "IL-504",
        {"a.py": "import os\n" + PY_WEB + "def sanitize(x):\n    return x\ndef h():\n    c = sanitize(request.args['d'])\n    os.system('ls ' + c)\n"},
        {"a.py": [7]},
    ),
    (
        "local-sanitize-nested-in-concat",
        "IL-504",
        {"a.py": "import os\n" + PY_WEB + "def sanitize(x):\n    return x\ndef h():\n    os.system('ls ' + sanitize(request.args['d']))\n"},
        {"a.py": [6]},
    ),
    (
        "local-sanitize-really-sanitizes",
        "IL-504",
        {"a.py": "import os\n" + PY_WEB + "def sanitize(x):\n    return 'fixed'\ndef h():\n    c = sanitize(request.args['d'])\n    os.system(c)\n"},
        {},
    ),
    # 절대경로 변환은 접근 범위 검증이 아니다
    (
        "abspath-is-not-confinement",
        "IL-502",
        {"a.py": "import os\n" + PY_WEB + "def h():\n    p = os.path.abspath(request.args['p'])\n    return open(p).read()\n"},
        {"a.py": [5]},
    ),
    (
        "abspath-with-prefix-check",
        "IL-502",
        {"a.py": "import os\n" + PY_WEB + "def h():\n    p = os.path.abspath(os.path.join('/srv', request.args['p']))\n    if not p.startswith('/srv'):\n        abort(400)\n    return open(p).read()\n"},
        {},
    ),
    # SSRF는 접속 대상 인자만 본다
    (
        "ssrf-fixed-url-tainted-body-py",
        "IL-506",
        {"a.py": "import requests\n" + PY_WEB + "def h():\n    requests.post('https://api.example.com/e', json=request.json)\n"},
        {},
    ),
    (
        "ssrf-fixed-url-tainted-body-js",
        "IL-506",
        {"a.js": "app.post('/x', (req, res) => { fetch('https://api.example.com/e', {body: JSON.stringify(req.body)}); });\n"},
        {},
    ),
    (
        "ssrf-tainted-url-py",
        "IL-506",
        {"a.py": "import requests\n" + PY_WEB + "def h():\n    requests.get(request.args['u'])\n"},
        {"a.py": [4]},
    ),
    (
        "ssrf-tainted-url-keyword-py",
        "IL-506",
        {"a.py": "import requests\n" + PY_WEB + "def h():\n    requests.get(url=request.args['u'])\n"},
        {"a.py": [4]},
    ),
    (
        "ssrf-tainted-url-object-js",
        "IL-506",
        {"a.js": "app.get('/x', (req, res) => { axios({method: 'get', url: req.query.u}); });\n"},
        {"a.js": [1]},
    ),
    (
        "ssrf-go-new-request-url-position",
        "IL-506",
        {"a.go": 'package main\nimport "net/http"\nfunc h(r *http.Request) {\n\thttp.NewRequest("GET", r.URL.Query().Get("u"), nil)\n}\n'},
        {"a.go": [4]},
    ),
    # Go의 Context 계열 API는 둘째 인자가 쿼리다
    (
        "go-query-context-tainted",
        "IL-501",
        {"a.go": 'package main\nimport ("database/sql";"net/http")\nfunc h(db *sql.DB, r *http.Request) {\n\tq := "SELECT * FROM t WHERE n=\'" + r.URL.Query().Get("n") + "\'"\n\tdb.QueryContext(r.Context(), q)\n}\n'},
        {"a.go": [5]},
    ),
    (
        "go-query-context-bound",
        "IL-501",
        {"a.go": 'package main\nimport ("database/sql";"net/http")\nfunc h(db *sql.DB, r *http.Request) {\n\tdb.QueryContext(r.Context(), "SELECT * FROM t WHERE n = ?", r.URL.Query().Get("n"))\n}\n'},
        {},
    ),
    # 명시적으로 셸을 여는 인자 배열
    (
        "sh-c-array-py",
        "IL-504",
        {"a.py": "import subprocess\n" + PY_WEB + "def h():\n    subprocess.run(['sh', '-c', request.args['cmd']])\n"},
        {"a.py": [4]},
    ),
    (
        "sh-c-array-js",
        "IL-504",
        {"a.js": "const {spawn} = require('child_process');\napp.get('/x', (req, res) => { spawn('sh', ['-c', req.query.cmd]); });\n"},
        {"a.js": [2]},
    ),
    (
        "non-shell-array-py",
        "IL-504",
        {"a.py": "import subprocess\n" + PY_WEB + "def h():\n    subprocess.run(['ls', '-l', request.args['d']])\n"},
        {},
    ),
    (
        "non-shell-array-js",
        "IL-504",
        {"a.js": "const {spawn} = require('child_process');\napp.get('/x', (req, res) => { spawn('ls', ['-l', req.query.d]); });\n"},
        {},
    ),
    # XXE: 설정 값과 적용 대상 객체를 함께 본다
    (
        "xxe-feature-set-false",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A { void f() throws Exception {\n DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\n f.newDocumentBuilder();\n}}\n'},
        {"A.java": [3]},
    ),
    (
        "xxe-hardened-other-object",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A { void f() throws Exception {\n DocumentBuilderFactory safe = DocumentBuilderFactory.newInstance();\n safe.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n DocumentBuilderFactory unsafe = DocumentBuilderFactory.newInstance();\n unsafe.newDocumentBuilder();\n}}\n'},
        {"A.java": [5]},
    ),
    (
        "xxe-hardened-after-use",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A { void f() throws Exception {\n DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n f.newDocumentBuilder();\n f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n}}\n'},
        {"A.java": [3]},
    ),
    (
        "xxe-hardened-properly",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A { void f() throws Exception {\n DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n f.newDocumentBuilder();\n}}\n'},
        {},
    ),
    # 템플릿 파일은 템플릿 검사 경로로 연결된다
    ("template-html-safe", "IL-505", {"a.html": "<p>{{ user_input|safe }}</p>\n"}, {"a.html": [1]}),
    ("template-jinja-autoescape-off", "IL-505", {"b.jinja": "{% autoescape false %}{{ x }}{% endautoescape %}\n"}, {"b.jinja": [1]}),
    ("template-razor-raw", "IL-505", {"c.cshtml": "<div>@Html.Raw(Model.Comment)</div>\n"}, {"c.cshtml": [1]}),
    ("template-escaped", "IL-505", {"d.html": "<p>{{ user_input }}</p>\n"}, {}),
    # 주석은 실행된 인증이 아니다
    (
        "auth-in-comment-only",
        "IL-525",
        {"a.py": 'from flask import Flask\napp = Flask(__name__)\n@app.route("/admin/delete", methods=["POST"])\ndef admin_delete():\n    # TODO: require_auth here\n    db.execute("DELETE FROM users")\n'},
        {"a.py": [4]},
    ),
    (
        "auth-decorator-present",
        "IL-525",
        {"a.py": 'from flask import Flask\napp = Flask(__name__)\n@app.route("/admin/delete", methods=["POST"])\n@login_required\ndef admin_delete():\n    db.execute("DELETE FROM users")\n'},
        {},
    ),
    # 같은 파일의 도우미 함수 안에 있는 싱크
    (
        "helper-sink-tainted-argument",
        "IL-502",
        {"a.py": PY_WEB + "def read_file(path):\n    return open('/srv/' + path).read()\ndef h():\n    return read_file(request.args['f'])\n"},
        {"a.py": [3]},
    ),
    (
        "helper-sink-constant-argument",
        "IL-502",
        {"a.py": "def read_file(path):\n    return open('/srv/' + path).read()\ndef h():\n    return read_file('readme.txt')\n"},
        {},
    ),
    # .cts 파일은 디렉터리 점검에서도 읽힌다
    ("cts-directory-scan", "IL-101", {"app.cts": 'const password = "ActualHardcodedPassword123!";\n'}, {"app.cts": [1]}),
]


@pytest.mark.parametrize(("name", "rule", "files", "expected"), FLOW_CASES, ids=[c[0] for c in FLOW_CASES])
def test_reported_flow_cases(tmp_path: Path, name, rule, files, expected):
    violations = scan_files(tmp_path, files)
    for path in files:
        assert lines_of(violations, rule, path) == expected.get(path, []), name


def test_default_extensions_cover_every_language_extension():
    assert set(EXTENSION_TO_LANG) <= set(DEFAULT_EXTENSIONS)


# ---------------- 잘못된 입력이 통과로 끝나지 않는다 ----------------


def test_missing_target_path_is_an_input_error(tmp_path: Path):
    for command in ("check", "audit"):
        result = runner.invoke(app, [command, str(tmp_path / "nope")])
        assert result.exit_code == 2
        assert "입력 오류" in result.output


def test_empty_target_is_not_a_pass(tmp_path: Path):
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
    allowed = runner.invoke(app, ["audit", str(tmp_path), "--format", "json", "--allow-empty"])
    assert allowed.exit_code == 0
    assert json.loads(allowed.output)["summary"]["grade"] == "점검 없음"


@pytest.mark.parametrize(
    "config",
    [
        "enabled_rules: [IL-999]\n",
        "disabled_rules: [IL-999]\n",
        "enabled_rules: []\n",
        "limits:\n  max_file_bytes: -1\n",
        "limits:\n  max_function_lines: 0\n",
        "limits:\n  duplicate_similarity: 1.5\n",
        "false\n",
        "0\n",
        "[]\n",
    ],
)
def test_invalid_config_values_are_rejected(tmp_path: Path, config: str):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / ".iron-laws.yml").write_text(config)
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2, config


def test_empty_config_file_means_defaults(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / ".iron-laws.yml").write_text("")
    assert runner.invoke(app, ["check", str(tmp_path)]).exit_code == 0


def test_non_utf8_config_is_a_config_error(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / ".iron-laws.yml").write_bytes(b"fail_on: \xff\xfe\n")
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 2
    assert "설정 오류" in result.output


def test_negative_limits_are_rejected(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["fix-prompt", str(tmp_path), "--limit", "-3"]).exit_code != 0
    assert runner.invoke(app, ["audit", str(tmp_path), "--limit", "-1"]).exit_code != 0


# ---------------- 억제는 실제 주석에서만 ----------------

SECRET_LINE = 'password = "ActualHardcodedPassword123!"\n'


def test_suppression_text_inside_string_is_not_a_directive(tmp_path: Path):
    files = {"a.py": 'note = "iron-laws: ignore-file[IL-101] Just a string"\n' + SECRET_LINE}
    assert lines_of(scan_files(tmp_path, files), "IL-101") == [2]


def test_suppression_in_real_comment_with_reason_applies(tmp_path: Path):
    files = {"a.py": "# iron-laws: ignore-file[IL-101] 평가용 무효 합성값이다\n" + SECRET_LINE}
    assert lines_of(scan_files(tmp_path, files), "IL-101") == []


def test_suppression_comment_without_reason_is_ignored(tmp_path: Path):
    files = {"a.py": "# iron-laws: ignore-file[IL-101]\n" + SECRET_LINE}
    assert lines_of(scan_files(tmp_path, files), "IL-101") == [2]


def test_line_suppression_in_trailing_comment(tmp_path: Path):
    files = {"a.js": 'const password = "ActualHardcodedPassword123!"; // iron-laws: ignore[IL-101] 시험용 값이다\n'}
    assert lines_of(scan_files(tmp_path, files), "IL-101") == []


def test_suppression_text_in_javascript_string_is_not_a_directive(tmp_path: Path):
    files = {"a.js": 'const n = "iron-laws: ignore-file[IL-101] sample";\nconst password = "ActualHardcodedPassword123!";\n'}
    assert lines_of(scan_files(tmp_path, files), "IL-101") == [2]


# ---------------- 출력 안전성 ----------------


def test_fix_prompt_masks_secret_values(tmp_path: Path):
    (tmp_path / "a.py").write_text(SECRET_LINE)
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert "ActualHardcodedPassword123" not in result.output
    assert "password" in result.output


def test_every_report_format_masks_secret_values(tmp_path: Path):
    (tmp_path / "a.py").write_text(SECRET_LINE)
    for fmt in ("json", "markdown", "sarif", "review", "prompt"):
        result = runner.invoke(app, ["audit", str(tmp_path), "--format", fmt])
        assert "ActualHardcodedPassword123" not in result.output, fmt


def test_fix_prompt_keeps_review_status(tmp_path: Path):
    (tmp_path / "a.py").write_text("def q(conn, uid):\n    conn.execute(f'SELECT * FROM t WHERE id = {uid}')\n")
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert "확인 필요" in result.output


def test_console_survives_markup_like_text_in_code(tmp_path: Path):
    (tmp_path / "a.py").write_text('def f(conn, x):\n    conn.execute("SELECT [/oops] FROM t WHERE a = " + x)\n')
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert "MarkupError" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_console_survives_markup_like_text_in_path(tmp_path: Path):
    (tmp_path / "[bold]x[").mkdir()
    (tmp_path / "[bold]x[" / "a.py").write_text(SECRET_LINE)
    result = runner.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1
    assert "MarkupError" not in result.output


def test_sarif_uri_is_relative_to_repository_root_and_encoded(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "hash#name.py").write_text(SECRET_LINE)
    result = runner.invoke(app, ["audit", str(tmp_path / "src"), "--format", "sarif"])
    sarif = json.loads(result.output)
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "src/hash%23name.py"
    assert location["uriBaseId"] == "%SRCROOT%"


def test_sarif_uri_for_repository_root_scan(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(SECRET_LINE)
    result = runner.invoke(app, ["audit", str(tmp_path), "--format", "sarif"])
    location = json.loads(result.output)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "src/app.py"


def test_config_object_has_no_unknown_default_extension_gaps():
    assert ".cts" in IronLawsConfig().include_extensions
