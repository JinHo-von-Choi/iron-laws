import json
from copy import deepcopy

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import ConfigError
from iron_laws.core.pilot import PilotStore
from iron_laws.core.scanner import AuditScanner
from iron_laws.evidence.verifier import verify_receipt, verify_report
from iron_laws.verify.receipt import CheckResult, Receipt, decide
from iron_laws.verify.regression import RESULT_PREFIX, run_harness
from iron_laws.verify.runner import DockerRunner, RunLimits, RunResult
from iron_laws.verify.snapshot import cleanup_workspace
from tests.runner_doubles import ScriptedRunner


@pytest.mark.parametrize("payload", [123, [], {}, {"outcome": 123}, {"outcome": "invented"},
    {"outcome": "passed", "reason": []}, {"outcome": "passed", "sink_calls": "bad"},
    {"outcome": "passed", "sink_calls": -1}, {"outcome": "passed", "sink_calls": True}])
def test_malformed_harness_output_is_error(tmp_path, payload):
    runner = ScriptedRunner([RunResult(status="passed", excerpt=RESULT_PREFIX + json.dumps(payload))])
    result = run_harness(runner, tmp_path, "attack", RunLimits())
    assert result.outcome == "error"


@pytest.mark.parametrize("outcome", ["passed", "defect_reproduced", "control_failed", "error"])
def test_valid_harness_output_retains_outcome(tmp_path, outcome):
    payload = {"outcome": outcome, "reason": "bounded observation", "sink_calls": 2}
    (tmp_path / "_iron_laws_harness" / "base").mkdir(parents=True)  # 설치된 harness의 기준 폴더(봉인값을 건네는 곳)
    runner = ScriptedRunner([RunResult(status="passed", excerpt=RESULT_PREFIX + json.dumps(payload))])
    result = run_harness(runner, tmp_path, "attack", RunLimits())
    assert (result.outcome, result.reason, result.sink_calls) == (outcome, "bounded observation", 2)


@pytest.fixture
def report(tmp_path):
    (tmp_path / "a.py").write_text("value = 1\n")
    return AuditScanner(tmp_path).scan().model_dump(mode="json")


@pytest.mark.parametrize("path,value", [
    (("summary",), 1), (("metadata",), [1]), (("violations",), [1]),
    (("coverage_ledger", "points"), [1]), (("coverage_ledger", "requirements"), {"path": 1}),
    (("coverage_ledger", "digests"), {"code": []}), (("diagnostics",), [1]),
    (("approval_checks",), [1]), (("metadata", "scope"), {"changed_paths": [[]]}),
    (("summary", "gates"), {"max_analysis_unknown_rate": []}),
    (("execution", "run_id"), []),
])
def test_malformed_report_is_undeterminable(report, path, value):
    bad = deepcopy(report)
    target = bad
    for field in path[:-1]:
        target = target.setdefault(field, {})
    target[path[-1]] = value
    result = verify_report(bad)
    assert result.undeterminable and not result.ok
    assert any(p.code.startswith("schema.") for p in result.problems)


def test_malformed_report_cli_returns_parseable_json(report, tmp_path):
    report["summary"] = 1
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(report))
    result = CliRunner().invoke(app, ["evidence", "verify", str(path), "--json"])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["undeterminable"]


@pytest.mark.parametrize("field,value", [("checks", [1]), ("verdict", 1), ("evidence", {"original": 1}), ("target", [])])
def test_malformed_receipt_is_undeterminable(field, value):
    checks = [CheckResult(id="test", title="test", result="pass")]
    receipt = Receipt(created="2026-10-11T00:00:00Z", verdict=decide(checks), checks=checks).seal()
    bad = receipt.model_dump(mode="json")
    bad[field] = value
    result = verify_receipt(bad)
    assert result.undeterminable and not result.ok


@pytest.mark.parametrize("row", [123, [], {}, {"kind": "invented"}, {"kind": "assign", "pr": "p"},
    {"kind": "review", "pr": "p", "team": "t", "arm": "bundle", "minutes": "bad"},
    {"kind": "review", "pr": "p", "team": "t", "arm": "bundle", "minutes": 10**400, "risk_accepted": False}])
def test_pilot_rejects_malformed_record_without_rewriting(tmp_path, row):
    path = tmp_path / "pilot.jsonl"
    original = json.dumps(row) + "\n"
    path.write_text(original)
    with pytest.raises(ConfigError, match="1"):
        PilotStore(path).records()
    assert path.read_text() == original


def test_pilot_cli_reports_bad_record(tmp_path):
    path = tmp_path / "pilot.jsonl"
    path.write_text("123\n")
    result = CliRunner().invoke(app, ["pilot", "assign", "p", "--team", "t", "--store", str(path)])
    assert result.exit_code == 2 and "1" in result.output


def test_docker_cleanup_reports_failures(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("daemon unavailable")
    monkeypatch.setattr("iron_laws.verify.runner.subprocess.run", unavailable)
    result = DockerRunner("unused").kill("unused")
    assert not result.complete and len(result.notes) == 2


def test_docker_cleanup_accepts_already_absent_container(monkeypatch):
    import subprocess
    monkeypatch.setattr("iron_laws.verify.runner.subprocess.run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, b"", b"Error: No such container: unused"))
    assert DockerRunner("unused").kill("unused").complete


def test_workspace_cleanup_reports_failure(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise PermissionError("cannot remove")
    monkeypatch.setattr("iron_laws.verify.snapshot.shutil.rmtree", deny)
    notes = cleanup_workspace(tmp_path)
    assert notes and "cannot remove" in notes[-1]


def test_workspace_cleanup_removes_readonly_tree(tmp_path):
    root = tmp_path / "work"
    root.mkdir()
    file = root / "data"
    file.write_text("temporary data")
    file.chmod(0o400)
    assert cleanup_workspace(root) == []
    assert not root.exists()


def test_receipt_records_cleanup_before_final_seal(tmp_path, monkeypatch):
    from iron_laws.verify import engine

    checks = [CheckResult(id="test", title="test", result="pass")]
    receipt = Receipt(created="2026-10-11T00:00:00Z", verdict=decide(checks), checks=checks).seal()
    patch = tmp_path / "candidate.patch"
    patch.write_text("")
    monkeypatch.setattr(engine, "_verify", lambda *args: receipt)
    monkeypatch.setattr(engine.tempfile, "mkdtemp", lambda **kwargs: str(tmp_path / "work"))
    monkeypatch.setattr(engine, "cleanup_workspace", lambda path: ["deletion denied"])
    result = engine.verify_patch(tmp_path, patch, engine.VerifyOptions())
    assert result.environment["workspace_cleanup"] == {"complete": False, "notes": ["deletion denied"]}
    assert result.verify_seal()
    assert result.verdict.overall == "verified"


def test_cleanup_warning_visible_in_cli(tmp_path, monkeypatch):
    from iron_laws.verify import engine
    checks = [CheckResult(id="test", title="test", result="pass")]
    receipt = Receipt(created="2026-10-11T00:00:00Z", verdict=decide(checks), checks=checks,
                      environment={"workspace_cleanup": {"complete": False, "notes": ["deletion denied"]}}).seal()
    monkeypatch.setattr(engine, 'verify_patch', lambda *args: receipt)
    result = CliRunner().invoke(app, ['verify-patch', str(tmp_path), '--patch', str(tmp_path / 'fix.diff')])
    assert result.exit_code == 0
    assert '정리 경고' in result.stderr and 'deletion denied' in result.stderr


def test_cleanup_preserves_original_exception_if_permissions_cannot_be_walked(tmp_path, monkeypatch):
    from iron_laws.verify import engine
    patch = tmp_path / 'fix.diff'
    patch.write_text('')
    def broken(*args):
        raise ConfigError('original failure')
    def deny(*args):
        raise PermissionError('cannot walk')
    monkeypatch.setattr(engine, '_verify', broken)
    monkeypatch.setattr('iron_laws.verify.snapshot.make_writable', deny)
    with pytest.warns(RuntimeWarning, match='cannot walk'), pytest.raises(ConfigError, match='original failure'):
        engine.verify_patch(tmp_path, patch, engine.VerifyOptions())
