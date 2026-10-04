"""
오철칙 경쟁력 강화 계획 2단계(PR-05~06) 근거 계약과 검사 공백 장부 시험
알려진 공백 표본(모두 드러나야 한다)과 안전한 변경 표본(불필요한 차단 10% 이하)을 영구 fixture로 고정한다.
이 표본은 구현자가 직접 분류한 것이며 독립 검토자의 분류가 아니다. 효과 주장의 근거로 쓰지 않고 회귀 방지에 쓴다.
작성자: 최진호
작성일: 2026-10-04
"""

import json
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import IronLawsConfig, Limits
from iron_laws.core.contract import Contract, FamilyRequirement, PointState, load_contract
from iron_laws.core.scanner import AuditScanner

runner = CliRunner()
FLASK = "import os\nimport subprocess\nfrom flask import request\n"

# (이름, 파일들, 계열, 기대 지점 줄, 기대 상태). 모두 '근거 충족'이 아닌 상태로 드러나야 한다.
KNOWN_GAPS = [
    ("cmd-param-without-caller", {"a.py": "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"}, "command", 3, "unresolved"),
    ("path-param-without-caller", {"a.py": "def read(p):\n    return open(p).read()\n"}, "path", 2, "unresolved"),
    ("sql-param-without-caller", {"a.py": "def q(cur, sql):\n    cur.execute(sql)\n"}, "sql", 2, "unresolved"),
    ("cmd-unresolved-call", {"a.py": "import os\ndef f():\n    c = build_command()\n    os.system(c)\n"}, "command", 4, "unresolved"),
    ("path-unresolved-call", {"a.py": "def f():\n    p = compute_path()\n    return open(p)\n"}, "path", 3, "unresolved"),
    ("sql-unresolved-call", {"a.py": "def f(cur):\n    q = make_query()\n    cur.execute(q)\n"}, "sql", 3, "unresolved"),
    ("cmd-self-attribute", {"a.py": "import os\nclass A:\n    def f(self):\n        os.system(self.cmd)\n"}, "command", 4, "unresolved"),
    ("path-self-attribute", {"a.py": "class A:\n    def f(self):\n        return open(self.path)\n"}, "path", 3, "unresolved"),
    ("sql-self-attribute", {"a.py": "class A:\n    def f(self):\n        self.cur.execute(self.query)\n"}, "sql", 3, "unresolved"),
    ("path-imported-name", {"a.py": "from settings import DATA_DIR\ndef f():\n    return open(DATA_DIR)\n"}, "path", 3, "unresolved"),
    ("cmd-spawn-unsupported", {"a.py": "import os\ndef f():\n    os.spawnlp(os.P_WAIT, 'ls', 'ls', '-l')\n"}, "command", 3, "unsupported"),
    ("cmd-posix-spawn-unsupported", {"a.py": "import os\ndef f(x):\n    os.posix_spawn('/bin/ls', ['ls'], {})\n"}, "command", 3, "unsupported"),
    ("cmd-asyncio-shell-unsupported", {"a.py": "import asyncio\nasync def f(c):\n    await asyncio.create_subprocess_shell(c)\n"}, "command", 3, "unsupported"),
    ("path-symlink-unsupported", {"a.py": "import pathlib\ndef f():\n    pathlib.Path('x').symlink_to('y')\n"}, "path", 3, "unsupported"),
    ("path-zipfile-unsupported", {"a.py": "import zipfile\ndef f():\n    return zipfile.ZipFile('a.zip')\n"}, "path", 3, "unsupported"),
    ("path-tarfile-unsupported", {"a.py": "import tarfile\ndef f():\n    return tarfile.open('a.tar')\n"}, "path", 3, "unsupported"),
    ("path-chmod-unsupported", {"a.py": "import os\ndef f():\n    os.chmod('x', 0o600)\n"}, "path", 3, "unsupported"),
    ("sql-exec-driver-sql-unsupported", {"a.py": "def f(engine):\n    engine.exec_driver_sql('SELECT 1')\n"}, "sql", 2, "unsupported"),
    ("path-argv", {"a.py": "import sys\ndef f():\n    return open(sys.argv[1])\n"}, "path", 3, "unresolved"),
    ("cmd-input", {"a.py": "import os\ndef f():\n    os.system(input())\n"}, "command", 3, "unresolved"),
    ("path-loop-over-unresolved", {"a.py": "import os\ndef f(d):\n    for name in list_dir(d):\n        open(name)\n"}, "path", 4, "unresolved"),
    ("path-subscript-of-unresolved", {"a.py": "def f():\n    cfg = load_cfg()\n    return open(cfg['path'])\n"}, "path", 3, "unresolved"),
    ("path-comprehension", {"a.py": "def f(paths):\n    return [open(p) for p in paths]\n"}, "path", 2, "unresolved"),
    ("cmd-fstring-unresolved", {"a.py": "import os\ndef f():\n    n = lookup_name()\n    os.system(f'ls {n}')\n"}, "command", 4, "unresolved"),
    ("cmd-splat-param", {"a.py": "import subprocess\ndef f(cmd):\n    subprocess.run(*cmd)\n"}, "command", 3, "unresolved"),
    ("cmd-caller-passes-unresolved", {"a.py": "import os\ndef run(c):\n    os.system(c)\ndef top():\n    run(compute())\n"}, "command", 3, "unresolved"),
    ("path-lambda", {"a.py": "def f():\n    g = lambda p: open(p)\n    return g(1)\n"}, "path", 2, "unresolved"),
    ("sql-concat-unresolved-attr", {"a.py": "def f(cur, obj):\n    cur.execute('SELECT * FROM ' + obj.table)\n"}, "sql", 2, "unresolved"),
    ("cmd-two-callers-one-unresolved", {"a.py": "import os\ndef run(c):\n    os.system(c)\ndef a():\n    run('ls')\ndef b():\n    run(make())\n"}, "command", 3, "unresolved"),
    ("path-global-from-call", {"a.py": "BASE = get_base()\ndef f():\n    return open(BASE)\n"}, "path", 3, "unresolved"),
]

# 안전한 변경: 모든 입력이 닫혀 있어 근거 충족이어야 한다. 하나라도 차단되면 '불필요한 차단'이다.
SAFE_CHANGES = [
    ("literal-command", {"a.py": "import os\ndef f():\n    os.system('ls -l')\n"}),
    ("closed-local-command", {"a.py": "import os\ndef f():\n    c = 'ls' + ' -l'\n    os.system(c)\n"}),
    ("env-command", {"a.py": "import os\ndef f():\n    os.system(os.environ['TOOL'])\n"}),
    ("list-argv-no-shell", {"a.py": "import subprocess\ndef f(x):\n    subprocess.run(['ls', '-l', x])\n"}),
    ("command-with-closed-caller", {"a.py": "import os\ndef run(c):\n    os.system(c)\ndef top():\n    run('ls')\n"}),
    ("command-two-closed-callers", {"a.py": "import os\ndef run(c):\n    os.system(c)\ndef a():\n    run('ls')\ndef b():\n    run('pwd')\n"}),
    ("literal-path", {"a.py": "def f():\n    return open('/etc/hostname').read()\n"}),
    ("join-of-constants", {"a.py": "import os\nBASE = '/srv/data'\ndef f():\n    return open(os.path.join(BASE, 'x.txt'))\n"}),
    ("path-env-base", {"a.py": "import os\ndef f():\n    return open(os.path.join(os.environ['DATA_DIR'], 'x.txt'))\n"}),
    ("path-param-closed-caller", {"a.py": "def read(p):\n    return open(p).read()\ndef top():\n    return read('/etc/hostname')\n"}),
    ("path-guarded-normalized", {"a.py": "import os\nfrom flask import request\ndef f():\n    p = os.path.abspath(request.args['p'])\n    if not p.startswith('/srv'):\n        abort(400)\n    return open(p).read()\n"}),
    ("path-basename", {"a.py": "import os\nfrom flask import request\ndef f():\n    return open('/srv/' + os.path.basename(request.args['p']))\n"}),
    ("sql-literal", {"a.py": "def f(cur):\n    cur.execute('SELECT 1')\n"}),
    ("sql-bound", {"a.py": "def f(cur, uid):\n    cur.execute('SELECT * FROM t WHERE id = ?', (uid,))\n"}),
    ("sql-closed-concat", {"a.py": "TABLE = 'users'\ndef f(cur):\n    cur.execute('SELECT * FROM ' + TABLE)\n"}),
    ("sql-closed-caller", {"a.py": "def q(cur, sql):\n    cur.execute(sql)\ndef top(cur):\n    q(cur, 'SELECT 1')\n"}),
    ("no-interest-points", {"a.py": "def f(a, b):\n    return a + b\n"}),
    ("pure-function-chain", {"a.py": "import os\ndef name():\n    return 'ls'\ndef f():\n    os.system(name())\n"}),
    ("str-methods-on-closed", {"a.py": "import os\ndef f():\n    c = 'LS'.lower().strip()\n    os.system(c)\n"}),
    ("format-closed", {"a.py": "import os\ndef f():\n    os.system('ls {}'.format('-l'))\n"}),
    ("ternary-closed", {"a.py": "import os\ndef f(flag):\n    os.system('ls' if flag else 'pwd')\n"}),
    ("tuple-of-constants", {"a.py": "import subprocess\ndef f():\n    subprocess.run(('ls', '-l'))\n"}),
    ("module-constant-chain", {"a.py": "import os\nA = 'ls'\nB = A + ' -l'\ndef f():\n    os.system(B)\n"}),
    ("int-cast-query", {"a.py": "from flask import request\ndef f(cur):\n    uid = int(request.args['id'])\n    cur.execute('SELECT * FROM t WHERE id = ' + str(uid))\n"}),
    ("closed-multiline", {"a.py": "import os\ndef f():\n    parts = ['ls', '-l']\n    os.system(' '.join(parts))\n"}),
    ("test-file-only", {"tests/test_a.py": "import os\ndef test_x():\n    os.system(compute())\n"}),
    ("non-python-only", {"a.js": "const {exec} = require('child_process'); exec(cmd);\n"}),
    ("closed-nested-helper", {"a.py": "import os\ndef a():\n    return 'ls'\ndef b():\n    return a() + ' -l'\ndef f():\n    os.system(b())\n"}),
    ("path-default-literal-arg", {"a.py": "def f():\n    name = 'a.txt'\n    return open(name)\n"}),
    ("sql-fstring-closed", {"a.py": "T = 'users'\ndef f(cur):\n    cur.execute(f'SELECT * FROM {T}')\n"}),
]


def _scan(tmp_path: Path, files: dict[str, str], contract: Contract | None = None, config: IronLawsConfig | None = None):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return AuditScanner(tmp_path, config=config, contract=contract).scan()


@pytest.mark.parametrize(("name", "files", "family", "line", "state"), KNOWN_GAPS, ids=[c[0] for c in KNOWN_GAPS])
def test_known_gap_is_exposed(tmp_path: Path, name, files, family, line, state):
    report = _scan(tmp_path, files)
    ledger = report.coverage_ledger
    assert ledger is not None
    hits = [p for p in ledger.points if p.family == family and p.line == line]
    assert hits, f"{name}: 관심 지점이 발견되지 않았다 {[(p.family, p.line, p.state) for p in ledger.points]}"
    assert all(p.state == state for p in hits), (name, [(p.state, p.reason) for p in hits])
    assert ledger.status == "unmet"
    assert any(f"{family}] a.py:{line}" in b for b in ledger.blockers)


def test_all_known_gaps_are_exposed_in_aggregate(tmp_path_factory):
    exposed = 0
    for name, files, family, line, state in KNOWN_GAPS:
        report = _scan(tmp_path_factory.mktemp(name.replace("-", "_")), files)
        points = [p for p in report.coverage_ledger.points if p.family == family and p.line == line]
        exposed += bool(points) and all(p.state == state for p in points)
    assert exposed == len(KNOWN_GAPS) == 30


@pytest.mark.parametrize(("name", "files"), SAFE_CHANGES, ids=[c[0] for c in SAFE_CHANGES])
def test_safe_change_is_not_blocked(tmp_path: Path, name, files):
    report = _scan(tmp_path, files)
    assert report.coverage_ledger.blockers == [], (name, report.coverage_ledger.blockers)
    assert report.coverage_ledger.status in ("met", "not_applicable")


def test_unnecessary_block_rate_on_safe_changes_is_within_target(tmp_path_factory):
    blocked = 0
    for name, files in SAFE_CHANGES:
        report = _scan(tmp_path_factory.mktemp(name.replace("-", "_")), files)
        blocked += report.coverage_ledger.status == "unmet"
    assert len(SAFE_CHANGES) == 30
    assert blocked / len(SAFE_CHANGES) <= 0.10


def test_unknown_is_never_converted_to_clean(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": "import os\ndef f():\n    os.system(make())\n"})
    assert report.violations == []  # 지적은 없다
    assert report.summary.is_passed  # 보고 모드에서는 통과한다
    assert report.coverage_ledger.status == "unmet"  # 그러나 근거 계약은 미충족으로 남는다
    assert report.summary.contract_status == "unmet"


def test_tainted_flow_is_evidence_met_with_finding(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": FLASK + "def f():\n    os.system('ls ' + request.args['d'])\n"})
    point = next(p for p in report.coverage_ledger.points if p.family == "command")
    assert point.state == "evidence_met" and point.finding
    assert any(v.rule_id == "IL-504" for v in report.violations)


# ---------------------------------------------------------------------------
# 분모, 범위, 분류
# ---------------------------------------------------------------------------


def test_ledger_denominators_include_unsupported_and_out_of_scope_files(tmp_path: Path):
    report = _scan(
        tmp_path,
        {
            "a.py": "import os\ndef f():\n    os.system('ls')\n",
            "b.js": "const x = 1;\n",
            "notes.md": "# 문서\n",
            "config.yml": "a: 1\n",
        },
    )
    kinds = {f.path: f.classification for f in report.coverage_ledger.files}
    assert kinds["a.py"] == "analyzed"
    assert kinds["b.js"] == "unsupported_language"
    assert kinds["notes.md"] == "out_of_scope"
    assert kinds["config.yml"] == "out_of_scope"


def test_skipped_files_are_listed_as_unclassified_not_dropped(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "big.py").write_text("y = 2\n" * 10)
    config = IronLawsConfig(limits=Limits(max_file_bytes=20))
    report = AuditScanner(tmp_path, config=config).scan()
    unclassified = [f for f in report.coverage_ledger.files if f.classification == "unclassified"]
    assert [f.path for f in unclassified] == ["a.py", "big.py"] or "big.py" in [f.path for f in unclassified]


def test_changed_scope_only_judges_changed_files_but_counts_everything(tmp_path: Path):
    (tmp_path / "old.py").write_text("import os\ndef f():\n    os.system(make())\n")
    (tmp_path / "new.py").write_text("import os\ndef g():\n    os.system('ls')\n")
    contract = Contract(scope="changed")
    report = AuditScanner(tmp_path, contract=contract, changed_files={"new.py"}, changed_since="HEAD").scan()
    ledger = report.coverage_ledger
    by_path = {p.path: p for p in ledger.points}
    assert by_path["old.py"].in_scope is False and by_path["old.py"].state == "unresolved"
    assert by_path["new.py"].in_scope is True
    assert ledger.status == "met"  # 변경 범위 밖의 공백은 차단 사유가 아니다
    tally = next(t for t in ledger.families if t.family == "command")
    assert tally.total == 2 and tally.in_scope == 1  # 분모는 숨기지 않는다


def test_unclassified_changed_file_blocks(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "big.py").write_text("y = 2\n" * 50)
    config = IronLawsConfig(limits=Limits(max_file_bytes=100))
    contract = Contract(scope="changed")
    report = AuditScanner(tmp_path, config=config, contract=contract, changed_files={"big.py"}, changed_since="HEAD").scan()
    assert "big.py" in report.coverage_ledger.unclassified_changed_files
    assert report.coverage_ledger.status == "unmet"


def test_budget_exceeded_is_distinguished_from_unresolved(tmp_path: Path):
    files = {
        "app/__init__.py": "",
        "app/util.py": "def name():\n    return 'ls'\n",
        "app/main.py": "import os\nfrom app.util import name\ndef f():\n    os.system(name())\n",
    }
    report = _scan(tmp_path, files, config=IronLawsConfig(limits=Limits(max_cross_file_lookups=0)))
    point = next(p for p in report.coverage_ledger.points if p.path == "app/main.py")
    assert point.state == "budget_exceeded"
    assert any(d.kind == "analysis_limit" for d in report.diagnostics)


def test_policy_excluded_path_is_recorded_with_reason(tmp_path: Path):
    contract = Contract(exclude_paths=["legacy/*"], exclusion_reason="이관 예정 레거시, 보안팀 승인 SEC-12")
    report = _scan(tmp_path, {"legacy/old.py": "import os\ndef f():\n    os.system(make())\n"}, contract=contract)
    point = report.coverage_ledger.points[0]
    assert point.state == "policy_excluded" and "SEC-12" in point.reason
    assert report.coverage_ledger.status == "met"


def test_suppressed_finding_is_policy_excluded_not_clean(tmp_path: Path):
    code = FLASK + "def f():\n    os.system('ls ' + request.args['d'])  # iron-laws: ignore[IL-504] 내부 관리용 도구다\n"
    report = _scan(tmp_path, {"a.py": code})
    assert report.violations == []
    point = next(p for p in report.coverage_ledger.points if p.family == "command")
    assert point.state == "policy_excluded"


# ---------------------------------------------------------------------------
# 계약 파일과 차단 모드
# ---------------------------------------------------------------------------


def _write_contract(path: Path, **overrides) -> Path:
    data = {"version": 1, "mode": "report", "scope": "all", **overrides}
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    return path


def test_contract_file_loading_and_validation(tmp_path: Path):
    good = _write_contract(tmp_path / "c.yml", mode="block", families={"command": {"required": True}, "sql": {"required": False}})
    contract, digest = load_contract(good)
    assert contract.mode == "block" and len(digest) == 16
    for bad in (
        {"families": {"network": {}}},
        {"languages": ["java"]},
        {"exclude_paths": ["x/*"]},
        {"version": 9},
        {"mode": "enforce"},
        {"unknown_key": 1},
    ):
        with pytest.raises(Exception):  # noqa: B017 - ConfigError 또는 검증 오류
            load_contract(_write_contract(tmp_path / "bad.yml", **bad))


def test_report_mode_never_fails_but_block_mode_does(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    report_contract = _write_contract(tmp_path.parent / f"{tmp_path.name}_report.yml", mode="report")
    block_contract = _write_contract(tmp_path.parent / f"{tmp_path.name}_block.yml", mode="block")
    assert runner.invoke(app, ["check", str(tmp_path), "--contract", str(report_contract)]).exit_code == 0
    blocked = runner.invoke(app, ["check", str(tmp_path), "--contract", str(block_contract)])
    assert blocked.exit_code == 1
    assert "근거 계약" in blocked.output
    assert runner.invoke(app, ["check", str(tmp_path), "--contract-mode", "block"]).exit_code == 1
    assert runner.invoke(app, ["check", str(tmp_path), "--contract-mode", "enforce"]).exit_code == 2


def test_family_not_required_is_not_blocking(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    contract = Contract(mode="block", families={"command": FamilyRequirement(required=False), "path": FamilyRequirement(), "sql": FamilyRequirement()})
    report = AuditScanner(tmp_path, contract=contract).scan()
    assert report.coverage_ledger.status == "met"
    assert report.summary.is_passed


def test_block_on_can_be_narrowed_to_unsupported_only(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    contract = Contract(mode="block", families={"command": FamilyRequirement(block_on=[PointState.UNSUPPORTED]), "path": FamilyRequirement(), "sql": FamilyRequirement()})
    assert AuditScanner(tmp_path, contract=contract).scan().coverage_ledger.status == "met"


def test_candidate_cannot_weaken_the_contract_it_is_judged_by(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    (project / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    contract_file = _write_contract(project / ".iron-laws-contract.yml", mode="block")
    subprocess.run(["git", "add", "-A"], cwd=project, check=True)
    subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=n", "commit", "-qm", "base"], cwd=project, check=True)
    _write_contract(contract_file, mode="report")  # 후보 변경이 계약을 완화한다
    result = runner.invoke(
        app,
        ["audit", str(project), "--contract", str(contract_file), "--changed-since", "HEAD", "--format", "json"],
    )
    report = json.loads(result.output)
    assert report["coverage_ledger"]["status"] == "policy_change_review"
    assert report["summary"]["contract_status"] == "policy_change_review"


# ---------------------------------------------------------------------------
# 같은 판정이 모든 출력에서 보존된다
# ---------------------------------------------------------------------------


def test_every_output_preserves_verdict_scope_and_hashes(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    json_report = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--format", "json"]).output)
    ledger = json_report["coverage_ledger"]
    digest = ledger["digests"]["code"]
    markdown = runner.invoke(app, ["audit", str(tmp_path), "--format", "markdown"]).output
    assert ledger["status"] in markdown and digest in markdown and ledger["contract_digest"] in markdown
    sarif = json.loads(runner.invoke(app, ["audit", str(tmp_path), "--format", "sarif"]).output)
    run = sarif["runs"][0]
    assert run["properties"]["coverageLedger"]["status"] == ledger["status"]
    assert run["properties"]["coverageLedger"]["digests"]["code"] == digest
    gap_notifications = [n for n in run["invocations"][0]["toolExecutionNotifications"] if n["descriptor"]["id"].startswith("coverage/")]
    assert len(gap_notifications) == 1 and gap_notifications[0]["descriptor"]["id"] == "coverage/unresolved"
    prompt = runner.invoke(app, ["fix-prompt", str(tmp_path)]).output
    assert "[검사 공백]" in prompt and "os.system" in prompt
    console = runner.invoke(app, ["check", str(tmp_path)]).output
    assert "근거 계약" in console and "미충족" in console
    assert run["invocations"][0]["executionSuccessful"] is True


def test_same_code_config_tool_gives_same_digests_and_verdict(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    first = AuditScanner(tmp_path).scan().coverage_ledger
    second = AuditScanner(tmp_path).scan().coverage_ledger
    assert first.digests == second.digests
    assert [(p.id, p.state) for p in first.points] == [(p.id, p.state) for p in second.points]
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system('ls')\n")
    third = AuditScanner(tmp_path).scan().coverage_ledger
    assert third.digests["code"] != first.digests["code"]
    assert third.status == "met"


def test_prompt_with_clean_findings_but_gaps_does_not_claim_clean(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ndef f():\n    os.system(make())\n")
    out = runner.invoke(app, ["fix-prompt", str(tmp_path)]).output
    assert "지적은 없지만 검사 공백이 있습니다" in out
    assert "수정할 문제가 없습니다" not in out


def test_ledger_limitations_are_always_disclosed(tmp_path: Path):
    report = _scan(tmp_path, {"a.py": "x = 1\n"})
    text = " ".join(report.coverage_ledger.limitations)
    assert "호출 이름으로 찾는다" in text and "안전하다는 점수는 만들지 않는다" in text
