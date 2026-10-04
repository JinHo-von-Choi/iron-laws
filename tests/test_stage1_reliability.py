"""
오철칙 경쟁력 강화 계획 1단계(PR-01~04) 신뢰성 수리 시험
재현된 결함: 변경 경로 이스케이프, 기준선의 표시 범위 먼저 적용·복제 승계·미확인 처리, 문자열 억제, 비밀 노출,
다단계 helper·경로 검증·XXE, 불완전 상태 전달, stdout 오염, 릴리스 게이트
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.baseline import load_baseline
from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of, scan_files

runner = CliRunner()
SECRET = 'password = "ActualHardcodedPassword123!"\n'
HANDLER = "import os\nfrom flask import request\ndef h():\n    d = request.args['d']\n    os.system('ls ' + d)\n"
ROOT = Path(__file__).resolve().parent.parent


def git(path: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=n", *args], cwd=path, check=True, capture_output=True)


def baseline_for(project: Path) -> Path:
    out = project / "base.json"
    result = runner.invoke(app, ["baseline", "create", str(project), "--output", str(out)])
    assert result.exit_code == 0, result.output
    return out


# ---------------------------------------------------------------------------
# PR-01: Git 경로
# ---------------------------------------------------------------------------

ODD_NAMES = ["한글 파일.py", "tab\tname.py", "new\nline.py", 'quote"name.py', "공백 있는 폴더/하위 폴더/a b.py", "it's.py"]


@pytest.mark.parametrize("name", ODD_NAMES)
def test_changed_since_handles_odd_path_names(tmp_path: Path, name: str):
    git(tmp_path, "init", "-q")
    git(tmp_path, "commit", "-q", "--allow-empty", "-m", "init")
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(SECRET)
    full = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--format", "json"]).output)
    changed = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--changed-since", "HEAD", "--format", "json"]).output)
    full_set = {v["fingerprint"] for v in full["violations"]}
    assert full_set, name
    assert {v["fingerprint"] for v in changed["violations"]} == full_set  # 변경 검사의 신규 판정이 전체 검사와 같다


def test_changed_since_staged_unstaged_untracked_and_subfolder(tmp_path: Path):
    git(tmp_path, "init", "-q")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "old.py").write_text("x = 1\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "base")
    (tmp_path / "pkg" / "old.py").write_text(SECRET)  # 수정(스테이징 안 됨)
    (tmp_path / "pkg" / "staged.py").write_text(SECRET)
    git(tmp_path, "add", "pkg/staged.py")  # 스테이징
    (tmp_path / "pkg" / "untracked.py").write_text(SECRET)  # 미추적
    (tmp_path / "unchanged.py").write_text("y = 2\n")
    for target in (tmp_path, tmp_path / "pkg"):
        report = json.loads(runner.invoke(app, ["audit", str(target), "--changed-since", "HEAD", "--format", "json"]).output)
        names = {Path(v["file_path"]).name for v in report["violations"]}
        assert names == {"old.py", "staged.py", "untracked.py"}, target


def test_changed_since_rejects_option_like_ref(tmp_path: Path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.py").write_text("x = 1\n")
    assert runner.invoke(app, ["check", str(tmp_path), "--changed-since", "--output=/tmp/x"]).exit_code != 0


# ---------------------------------------------------------------------------
# PR-01: 기준선 일대일 대응
# ---------------------------------------------------------------------------


def test_clone_does_not_inherit_approval_while_original_remains(tmp_path: Path):
    (tmp_path / "a.py").write_text(HANDLER)
    base = baseline_for(tmp_path)
    (tmp_path / "clone.py").write_text(HANDLER)
    report = AuditScanner(tmp_path, baseline=load_baseline(base)).scan()
    status = {v.file_path.as_posix(): v.baseline_status.value for v in report.violations if v.rule_id == "IL-504"}
    assert status == {"a.py": "existing", "clone.py": "new"}


def test_clone_is_new_even_when_original_is_outside_the_changed_view(tmp_path: Path):
    git(tmp_path, "init", "-q")
    (tmp_path / "a.py").write_text(HANDLER)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "base")
    base = baseline_for(tmp_path)
    (tmp_path / "clone.py").write_text(HANDLER)
    result = runner.invoke(app, ["audit", str(tmp_path), "--baseline", str(base), "--changed-since", "HEAD", "--format", "json"])
    report = json.loads(result.output)
    assert [(v["file_path"], v["baseline_status"]) for v in report["violations"]] == [("clone.py", "new")]
    assert report["summary"]["new_count"] == 1
    assert report["summary"]["resolved_count"] == 0  # 표시 범위 밖의 원본이 해소로 잡히지 않는다
    assert result.exit_code == 1


def test_file_move_is_inherited_one_to_one_only_when_the_old_path_is_gone(tmp_path: Path):
    (tmp_path / "a.py").write_text(HANDLER)
    base = baseline_for(tmp_path)
    (tmp_path / "pkg").mkdir()
    (tmp_path / "a.py").rename(tmp_path / "pkg" / "a.py")
    report = AuditScanner(tmp_path, baseline=load_baseline(base)).scan()
    assert [v.baseline_status.value for v in report.violations if v.rule_id == "IL-504"] == ["existing"]
    assert report.summary.unobserved_count == 0


def test_ambiguous_move_does_not_inherit(tmp_path: Path):
    (tmp_path / "a.py").write_text(HANDLER)
    (tmp_path / "b.py").write_text(HANDLER)
    base = baseline_for(tmp_path)
    (tmp_path / "a.py").unlink()
    (tmp_path / "b.py").unlink()
    (tmp_path / "c.py").write_text(HANDLER)
    report = AuditScanner(tmp_path, baseline=load_baseline(base)).scan()
    assert [v.baseline_status.value for v in report.violations if v.rule_id == "IL-504"] == ["new"]
    assert any(d.kind == "baseline" and "모호" in d.message for d in report.diagnostics)


def test_deleted_or_unreadable_file_is_unobserved_not_resolved(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text(HANDLER)
    (tmp_path / "b.py").write_text(HANDLER.replace("def h", "def g"))
    base = baseline_for(tmp_path)
    (tmp_path / "a.py").unlink()
    original = Path.read_bytes

    def locked(self):
        if self.name == "b.py":
            raise PermissionError(13, "Permission denied")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", locked)
    report = AuditScanner(tmp_path, baseline=load_baseline(base)).scan()
    assert report.summary.resolved_count == 0
    assert report.summary.unobserved_count == 2
    assert report.summary.scan_status == "incomplete"


def test_fixed_finding_in_a_scanned_file_is_resolved(tmp_path: Path):
    (tmp_path / "a.py").write_text(HANDLER)
    base = baseline_for(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n")
    report = AuditScanner(tmp_path, baseline=load_baseline(base)).scan()
    assert report.summary.resolved_count == 1
    assert report.summary.unobserved_count == 0


# ---------------------------------------------------------------------------
# PR-02: 억제는 주석에서만, 비밀은 어디서도 노출되지 않는다
# ---------------------------------------------------------------------------

STRING_SUPPRESSION_CASES = [
    ("yaml-string", "config.yml", 'note: "x # iron-laws: ignore-file[IL-101] sample"\nDB_PASSWORD: "SuperSecretValue123456"\n'),
    ("yaml-block-scalar", "config.yml", "note: |\n  # iron-laws: ignore-file[IL-101] sample\nDB_PASSWORD: \"SuperSecretValue123456\"\n"),
    ("shell-string", "run.sh", 'echo "a # iron-laws: ignore-file[IL-101] zz"\nexport DB_PASSWORD="SuperSecretValue123456"\n'),
    ("shell-single-quote", "run.sh", "echo 'a # iron-laws: ignore-file[IL-101] zz'\nexport DB_PASSWORD=\"SuperSecretValue123456\"\n"),
    ("shell-heredoc", "run.sh", "cat <<EOF\n# iron-laws: ignore-file[IL-101] zz\nEOF\nexport DB_PASSWORD=\"SuperSecretValue123456\"\n"),
    ("toml-string", "c.toml", 'note = "x # iron-laws: ignore-file[IL-101] sample"\npassword = "SuperSecretValue123456"\n'),
    ("toml-multiline", "c.toml", 'note = """\n# iron-laws: ignore-file[IL-101] sample\n"""\npassword = "SuperSecretValue123456"\n'),
    ("sql-string", "m.sql", "INSERT INTO t VALUES ('-- iron-laws: ignore-file[AI-108] zz');\nCREATE TABLE public.items (id int);\nALTER TABLE public.other ENABLE ROW LEVEL SECURITY;\n"),
    ("dockerfile-run", "Dockerfile", 'RUN echo "x # iron-laws: ignore-file[IL-101] zz"\nENV DB_PASSWORD="SuperSecretValue123456"\n'),
    ("env-quoted", ".env", 'NOTE="x # iron-laws: ignore-file[IL-101] zz"\nDB_PASSWORD=SuperSecretValue123456\n'),
]


@pytest.mark.parametrize(("name", "filename", "content"), STRING_SUPPRESSION_CASES, ids=[c[0] for c in STRING_SUPPRESSION_CASES])
def test_directive_text_inside_strings_does_not_suppress(tmp_path: Path, name, filename, content):
    (tmp_path / filename).write_text(content)
    report = AuditScanner(tmp_path).scan()
    assert report.summary.suppressed_count == 0, name
    assert report.violations, name


REAL_COMMENT_CASES = [
    ("yaml", "config.yml", '# iron-laws: ignore-file[IL-101] 시험용 무효값이다\nDB_PASSWORD: "SuperSecretValue123456"\n'),
    ("yaml-trailing", "config.yml", 'DB_PASSWORD: "SuperSecretValue123456"  # iron-laws: ignore[IL-101] 시험용 무효값이다\n'),
    ("shell", "run.sh", '# iron-laws: ignore-file[IL-101] 시험용 무효값이다\nexport DB_PASSWORD="SuperSecretValue123456"\n'),
    ("toml", "c.toml", '# iron-laws: ignore-file[IL-101] 시험용 무효값이다\npassword = "SuperSecretValue123456"\n'),
    ("sql-line", "m.sql", "-- iron-laws: ignore-file[AI-108] 시험용 테이블이다\nCREATE TABLE public.items (id int);\nALTER TABLE public.other ENABLE ROW LEVEL SECURITY;\n"),
    ("sql-block", "m.sql", "/* iron-laws: ignore-file[AI-108] 시험용 테이블이다 */\nCREATE TABLE public.items (id int);\nALTER TABLE public.other ENABLE ROW LEVEL SECURITY;\n"),
    ("dockerfile", "Dockerfile", '# iron-laws: ignore-file[IL-101] 시험용 무효값이다\nENV DB_PASSWORD="SuperSecretValue123456"\n'),
]


@pytest.mark.parametrize(("name", "filename", "content"), REAL_COMMENT_CASES, ids=[c[0] for c in REAL_COMMENT_CASES])
def test_directive_in_real_comment_still_suppresses(tmp_path: Path, name, filename, content):
    (tmp_path / filename).write_text(content)
    report = AuditScanner(tmp_path).scan()
    assert not any(v.rule_id in ("IL-101", "AI-108") for v in report.violations), name
    assert report.summary.suppressed_count >= 1, name


ALL_FORMATS = ("json", "markdown", "sarif", "review", "prompt")


def _assert_no_leak(project: Path, secret: str) -> None:
    for fmt in ALL_FORMATS:
        out = runner.invoke(app, ["audit", str(project), "--format", fmt]).output
        assert secret not in out, fmt
    console = runner.invoke(app, ["check", str(project)]).output
    assert secret not in console


def test_long_secret_is_masked_before_truncation(tmp_path: Path):
    secret = "A" * 340 + "SECRETTAILVALUE9999"
    (tmp_path / "a.py").write_text(f'TOKEN = "{secret}"\n')
    _assert_no_leak(tmp_path, "SECRETTAILVALUE9999")
    _assert_no_leak(tmp_path, "A" * 40)


def test_secret_is_masked_in_other_rules_on_the_same_line(tmp_path: Path):
    (tmp_path / "a.py").write_text(
        'import os\nfrom flask import request\n'
        'def h(): password = "ActualHardcodedPassword123!"; os.system("echo ActualHardcodedPassword123! | su; ls " + request.args["d"])\n'
    )
    _assert_no_leak(tmp_path, "ActualHardcodedPassword123")


@pytest.mark.parametrize(
    "line",
    [
        'import requests\nrequests.get("http://example.com/?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789")\n',
        'import requests\nrequests.get("https://admin:SuperSecretValue123456@internal.example.com/x")\n',
        'import requests\nrequests.get("https://x", headers={"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456"})\n',
        'import os\nfrom flask import request\ndef g():\n    os.system("mysql -pSuperSecretValue123456 -e " + request.args["q"])\n',
        'KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"\nprint(KEY)\n',
    ],
)
def test_known_token_shapes_are_masked_everywhere(tmp_path: Path, line: str):
    (tmp_path / "a.py").write_text(line)
    for secret in ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "SuperSecretValue123456", "abcdefghijklmnopqrstuvwxyz123456", "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"):
        _assert_no_leak(tmp_path, secret)


def test_secret_in_diagnostics_is_masked(tmp_path: Path, monkeypatch):
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    (tmp_path / "a.py").write_text(SECRET)

    def boom(self, src):
        raise RuntimeError("실패한 줄: " + src.lines[0])

    monkeypatch.setattr(HardcodedSecretRule, "check", boom)
    out = runner.invoke(app, ["audit", str(tmp_path), "--format", "json"]).output
    assert "ActualHardcodedPassword123" not in out


# ---------------------------------------------------------------------------
# PR-03: 다단계 helper, 경로 검증, XXE
# ---------------------------------------------------------------------------

ANALYSIS_CASES = [
    (
        "two-level-helper-chain",
        "IL-504",
        {"a.py": "import os\nfrom flask import request\ndef run(c):\n    os.system(c)\ndef mid(c):\n    run(c)\ndef top(c):\n    mid(c)\ndef h():\n    top(request.args['d'])\n"},
        {"a.py": [4]},
    ),
    (
        "two-level-chain-with-constant-at-top",
        "IL-504",
        {"a.py": "import os\ndef run(c):\n    os.system(c)\ndef mid(c):\n    run(c)\ndef top():\n    mid('ls')\n"},
        {},
    ),
    (
        "nested-return-chain",
        "IL-504",
        {"a.py": "import os\nfrom flask import request\ndef inner(y):\n    return y\ndef wrap(x):\n    return inner(x)\ndef outer(z):\n    return wrap(z)\ndef h():\n    os.system(outer(request.args['d']))\n"},
        {"a.py": [10]},
    ),
    (
        "nested-return-chain-cleaned",
        "IL-504",
        {"a.py": "import os\nfrom flask import request\ndef inner(y):\n    return 'fixed'\ndef wrap(x):\n    return inner(x)\ndef h():\n    c = wrap(request.args['d'])\n    os.system(c)\n"},
        {},
    ),
    (
        "chain-through-another-file",
        "IL-504",
        {
            "app/__init__.py": "",
            "app/low.py": "import os\ndef run(c):\n    os.system(c)\n",
            "app/mid.py": "from app.low import run\ndef relay(c):\n    run(c)\n",
            "app/views.py": "from flask import request\nfrom app.mid import relay\ndef h():\n    relay(request.args['d'])\n",
        },
        {"app/views.py": [4]},
    ),
    (
        "path-guard-on-other-variable",
        "IL-502",
        {"a.py": "import os\nfrom flask import request\ndef h():\n    p = os.path.abspath(request.args['p'])\n    q = os.path.abspath('/srv/x')\n    if not q.startswith('/srv'):\n        abort(400)\n    return open(p).read()\n"},
        {"a.py": [8]},
    ),
    (
        "path-guard-after-the-access",
        "IL-502",
        {"a.py": "import os\nfrom flask import request\ndef h():\n    p = os.path.abspath(request.args['p'])\n    data = open(p).read()\n    if not p.startswith('/srv'):\n        abort(400)\n    return data\n"},
        {"a.py": [5]},
    ),
    (
        "path-guard-without-normalization",
        "IL-502",
        {"a.py": "from flask import request\ndef h():\n    p = '/srv/' + request.args['p']\n    if not p.startswith('/srv'):\n        abort(400)\n    return open(p).read()\n"},
        {"a.py": [6]},
    ),
    (
        "path-guard-correct-early-exit",
        "IL-502",
        {"a.py": "import os\nfrom flask import request\ndef h():\n    p = os.path.abspath(request.args['p'])\n    if not p.startswith('/srv'):\n        abort(400)\n    return open(p).read()\n"},
        {},
    ),
    (
        "path-guard-correct-positive-branch",
        "IL-502",
        {"a.py": "import os\nfrom flask import request\ndef h():\n    p = os.path.abspath(request.args['p'])\n    if p.startswith('/srv'):\n        return open(p).read()\n    return ''\n"},
        {},
    ),
    (
        "path-guard-correct-assert",
        "IL-502",
        {"a.py": "import os\nfrom flask import request\ndef h():\n    p = os.path.abspath(request.args['p'])\n    assert p.startswith('/srv')\n    return open(p).read()\n"},
        {},
    ),
    (
        "xxe-hardening-in-another-method",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A {\n void safe() throws Exception {\n  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  f.newDocumentBuilder();\n }\n void other() throws Exception {\n  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n  f.newDocumentBuilder();\n }\n}\n'},
        {"A.java": [9]},
    ),
    (
        "xxe-final-state-relaxed",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A {\n void relaxed() throws Exception {\n  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\n  f.newDocumentBuilder();\n }\n}\n'},
        {"A.java": [4]},
    ),
    (
        "xxe-final-state-restored",
        "IL-509",
        {"A.java": 'import javax.xml.parsers.*;\nclass A {\n void ok() throws Exception {\n  DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);\n  f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  f.newDocumentBuilder();\n }\n}\n'},
        {},
    ),
]


@pytest.mark.parametrize(("name", "rule", "files", "expected"), ANALYSIS_CASES, ids=[c[0] for c in ANALYSIS_CASES])
def test_analysis_semantics(tmp_path: Path, name, rule, files, expected):
    from iron_laws.core.models import Confidence

    violations = [v for v in scan_files(tmp_path, files) if v.confidence is Confidence.CONFIRMED]
    for path in files:
        assert lines_of(violations, rule, path) == expected.get(path, []), name


# ---------------------------------------------------------------------------
# PR-04: 명령 계약
# ---------------------------------------------------------------------------


def _break_rule(monkeypatch):
    from iron_laws.rules.secrets_crypto import HardcodedSecretRule

    monkeypatch.setattr(HardcodedSecretRule, "check", lambda self, src: (_ for _ in ()).throw(RuntimeError("시험 오류")))


def test_fix_prompt_preserves_incomplete_state(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text(HANDLER)
    _break_rule(monkeypatch)
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert result.exit_code == 2
    assert "점검이 끝까지 이루어지지 않았습니다" in result.output
    assert "IL-504" in result.output  # 찾은 지적은 그대로 내보낸다


def test_fix_prompt_with_no_findings_but_incomplete_does_not_claim_clean(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n")
    _break_rule(monkeypatch)
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert result.exit_code == 2
    assert "문제가 없다는 뜻이 아닙니다" in result.output


def test_fix_prompt_on_empty_target_fails(tmp_path: Path):
    result = runner.invoke(app, ["fix-prompt", str(tmp_path)])
    assert result.exit_code == 2
    assert "수정할 문제가 없습니다" not in result.output.replace("판단할 수 없습니다", "")


def test_baseline_diff_propagates_incomplete_state(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text(HANDLER)
    base = baseline_for(tmp_path)
    _break_rule(monkeypatch)
    result = runner.invoke(app, ["baseline", "diff", str(tmp_path), "--baseline", str(base)])
    assert result.exit_code == 2


def test_machine_stdout_stays_parseable_when_scan_is_incomplete(tmp_path: Path, monkeypatch):
    (tmp_path / "a.py").write_text(SECRET)
    _break_rule(monkeypatch)
    proc = subprocess_run_cli(tmp_path, "audit", str(tmp_path), "--format", "json", monkeypatch=monkeypatch)
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["summary"]["scan_status"] == "incomplete"


def subprocess_run_cli(tmp_path: Path, *args: str, monkeypatch):
    """stdout과 stderr를 분리해서 확인하려고 실제 프로세스로 실행한다. 규칙 오류는 환경변수 훅으로 주입한다."""
    script = tmp_path / "_run.py"
    script.write_text(
        "import sys\n"
        "from iron_laws.rules.secrets_crypto import HardcodedSecretRule\n"
        "HardcodedSecretRule.check = lambda self, src: (_ for _ in ()).throw(RuntimeError('시험 오류'))\n"
        "from iron_laws.cli import main\n"
        "sys.argv = ['iron-laws', *sys.argv[1:]]\n"
        "main()\n"
    )
    return subprocess.run(["python", str(script), *args], capture_output=True, text=True, encoding="utf-8", cwd=ROOT)


def test_json_and_sarif_stdout_has_no_human_messages(tmp_path: Path):
    (tmp_path / "a.py").write_text(SECRET)
    for fmt in ("json", "sarif"):
        proc = subprocess.run(
            ["python", "-m", "iron_laws.cli", "audit", str(tmp_path), "--format", fmt], capture_output=True, text=True, encoding="utf-8", cwd=ROOT
        )
        assert proc.returncode == 1
        json.loads(proc.stdout)  # 사람이 읽는 메시지가 섞이면 여기서 실패한다
    proc = subprocess.run(
        ["python", "-m", "iron_laws.cli", "audit", str(tmp_path / "없는 경로"), "--format", "json"], capture_output=True, text=True, encoding="utf-8", cwd=ROOT
    )
    assert proc.returncode == 2
    assert proc.stdout.strip() == ""
    assert "입력 오류" in proc.stderr


def test_release_workflow_gates_publish_on_tests_and_smoke():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    jobs = workflow["jobs"]
    assert set(jobs["publish"]["needs"]) == {"verify", "smoke"}
    assert jobs["smoke"]["needs"] == "verify"
    verify_steps = " ".join(step.get("run", "") for step in jobs["verify"]["steps"])
    assert "pytest" in verify_steps and "ruff" in verify_steps and "iron-laws check" in verify_steps
    assert "GITHUB_REF_NAME" in verify_steps  # 태그와 패키지 버전 일치 확인
    assert set(jobs["smoke"]["strategy"]["matrix"]["os"]) == {"ubuntu-latest", "windows-latest", "macos-latest"}
