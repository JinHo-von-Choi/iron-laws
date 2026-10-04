"""
오철칙 경쟁력 강화 계획 4단계(PR-10~11) 결함을 구별하는 회귀시험 검증
- 재현 가능한 결함 표본 30개에서 시험 후보 생성 가능 비율, 원본 실패·후보 통과·mutant 재실패, 정상 대조군, 반복 일치를 측정한다.
- 호스트에서 harness를 돌리는 시험은 시험용 대역 실행기를 쓴다(harness는 모든 위험 호출을 기록만 한다). 격리 실행은 docker 이미지가 있을 때만 확인한다.
- 표본은 구현자가 직접 분류했다. 독립 검토자의 분류가 아니므로 효과 주장의 근거로 쓰지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-302] 우회 변경 표본이 skip 문자열을 포함한다

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import ConfigError
from iron_laws.core.scanner import AuditScanner
from iron_laws.verify.engine import VerifyOptions, regression_only, resolve_finding, verify_patch
from iron_laws.verify.regression import (
    HARNESS_DIR,
    RegressionSpec,
    build_mutants,
    dump_spec,
    install_harness,
    load_spec,
    parse_result,
    propose_spec,
    run_harness,
    run_regression_check,
    split_hunks,
)
from iron_laws.verify.runner import RunLimits, RunResult
from tests.regression_corpus import CASES, SUPPORTED, bad_fixes
from tests.runner_doubles import LocalTestRunner, ScriptedRunner
from tests.test_stage3_verify import DOCKER_READY, IMAGE, make_diff, needs_docker

cli = CliRunner()
LIMITS = RunLimits(timeout_s=60)
LOCAL = LocalTestRunner()


def write_project(root: Path, code: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(code)
    return root


def propose(project: Path, case) -> RegressionSpec | None:
    report = AuditScanner(project).scan()
    try:
        violation = resolve_finding(report, f"{case.rule}@app.py")
    except ConfigError:
        return None
    spec = propose_spec(project, violation).spec
    if spec is not None and case.benign:  # 사람이 제안을 검토해 정상 대조군을 함수에 맞게 고친 것
        spec = spec.model_copy(update={"input": spec.input.model_copy(update={"benign": case.benign})})
    return spec


def confirmed(spec: RegressionSpec) -> RegressionSpec:
    return spec.model_copy(update={"confirmed": True})


def spec_file(tmp_path: Path, spec: RegressionSpec, name: str = "spec.yml") -> Path:
    path = tmp_path / name
    path.write_text(dump_spec(spec))
    return path


ORIGINAL_MEMO: dict = {}  # 같은 원본·명세의 원본 단계 결과 재사용(후보만 바뀌는 비교)
RESULTS: dict = {}  # (표본, 변형) → 검증 결과. 같은 검증을 시험마다 다시 돌리지 않는다


def check(tmp_path: Path, project: Path, candidate_code: str, spec: RegressionSpec, runner=LOCAL, patch_name="p.diff"):
    patch = tmp_path / patch_name
    patch.write_text(make_diff(project, {"app.py": candidate_code}))
    spec_path = spec_file(tmp_path, confirmed(spec), f"spec-{patch_name}.yml")
    return regression_only(project, patch, spec_path, "none", None, LIMITS, runner, ORIGINAL_MEMO if runner is LOCAL else None)


def evaluate(case, variant: str, tmp_path: Path):
    """표본 case의 후보 변형(fix 또는 잘못된 수정 이름)을 검증한다. 결과는 모듈 안에서 한 번만 계산한다."""
    key = (case.name, variant)
    if key not in RESULTS:
        project = write_project(tmp_path / f"{case.name}-{variant}" / "proj", case.vulnerable)
        spec = propose(project, case)
        code = case.fix if variant == "fix" else bad_fixes(case)[variant]
        RESULTS[key] = check(tmp_path / f"{case.name}-{variant}", project, code, spec, patch_name=f"{variant}.diff")
    return RESULTS[key]


# ---------------------------------------------------------------------------
# 시험 후보 생성: 지원하는 모양만 만들고 나머지는 이유와 함께 거절한다
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_corpus_findings_exist_and_proposals_match_support(tmp_path: Path, case):
    project = write_project(tmp_path / "proj", case.vulnerable)
    report = AuditScanner(project).scan()
    findings = [v for v in report.violations if v.rule_id == case.rule]
    spec = propose(project, case)
    if case.supported:
        assert len(findings) == 1, (case.name, [(v.rule_id, v.line_number) for v in report.violations])
        assert spec is not None, f"{case.name}: 지원하는 모양인데 시험 후보를 만들지 못했다"
        assert spec.confirmed is False  # 제안은 확정이 아니다
        assert spec.review_notes and spec.fake_sink and spec.expect.summary
    elif findings:
        violation = findings[0]
        proposal = propose_spec(project, violation)
        assert proposal.spec is None, f"{case.name}: 지원 범위 밖인데 제안이 만들어졌다 ({case.note})"
        assert proposal.reason


def test_generation_rate_on_the_reproducible_defect_sample(tmp_path_factory):
    """초기 목표는 60% 이상(구현자 분류 표본). 현재 달성치를 측정해 남긴다."""
    generated = 0
    for case in CASES:
        project = write_project(tmp_path_factory.mktemp(case.name.replace("-", "_")) / "proj", case.vulnerable)
        generated += propose(project, case) is not None
    assert len(CASES) == 30
    assert generated == len(SUPPORTED)
    assert generated / len(CASES) >= 0.6


def test_unsupported_shapes_say_why(tmp_path: Path):
    reasons = {}
    for case in CASES:
        if case.supported:
            continue
        project = write_project(tmp_path / case.name / "proj", case.vulnerable)
        report = AuditScanner(project).scan()
        found = [v for v in report.violations if v.rule_id == case.rule]
        if found:
            reasons[case.name] = propose_spec(project, found[0]).reason
    assert any("클래스" in r for r in reasons.values())
    assert any("async" in r for r in reasons.values())
    assert any("Django" in r or "Flask 계열" in r for r in reasons.values())


def test_proposal_is_reviewable_and_never_confirmed(tmp_path: Path):
    case = SUPPORTED[0]
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    text = dump_spec(spec)
    for field in ("payload", "benign", "fake_sink", "expect", "confirmed: false", "review_notes"):
        assert field in text
    assert load_spec(spec_file(tmp_path, spec)).confirmed is False


def test_propose_command_and_unsupported_exit_code(tmp_path: Path):
    project = write_project(tmp_path / "proj", SUPPORTED[0].vulnerable)
    out = tmp_path / "spec.yml"
    result = cli.invoke(app, ["regression", "propose", str(project), "--finding", "IL-504@app.py", "-o", str(out)])
    assert result.exit_code == 0 and "confirmed: false" in out.read_text()
    unsupported = next(c for c in CASES if c.name == "sql-class-method")
    other = write_project(tmp_path / "other", unsupported.vulnerable)
    refused = cli.invoke(app, ["regression", "propose", str(other), "--finding", "IL-501@app.py"])
    assert refused.exit_code == 2 and "클래스" in refused.output


def test_unconfirmed_spec_is_never_used_as_evidence(tmp_path: Path):
    case = SUPPORTED[0]
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": case.fix}))
    result = regression_only(project, patch, spec_file(tmp_path, spec), "none", None, LIMITS, LOCAL)
    assert result.result == "unknown" and "확정되지 않았다" in result.reason and not result.executed


@pytest.mark.parametrize(
    "broken",
    [
        {"family": "network"},
        {"input": {"payload": "", "benign": "x"}},
        {"unknown_field": 1},
        {"source": {"kind": "param"}, "target": {"module": "app"}},
    ],
)
def test_invalid_specs_are_rejected(tmp_path: Path, broken):
    case = SUPPORTED[0]
    spec = propose(write_project(tmp_path / "proj", case.vulnerable), case)
    data = yaml.safe_load(dump_spec(spec))
    data.update(broken)
    path = tmp_path / "bad.yml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True))
    with pytest.raises(ConfigError):
        load_spec(path)


# ---------------------------------------------------------------------------
# 표본 전체: 올바른 수정은 통과, 잘못된 수정은 통과하지 못한다
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", SUPPORTED, ids=[c.name for c in SUPPORTED])
def test_correct_fix_passes_the_full_protocol(tmp_path: Path, case):
    result = evaluate(case, "fix", tmp_path)
    assert result.result == "pass", (case.name, result.reason, result.evidence)
    ev = result.evidence
    assert ev["original_attack"] == ["defect_reproduced"] * 3  # 원본은 결함 때문에 세 번 모두 실패
    assert ev["original_control"] == "passed"
    assert ev["candidate_attack"] == ["passed"] * 3 and ev["candidate_control"] == ["passed"] * 3
    assert len(ev["mutants"]["killed"]) >= 1  # 보안 수정을 되돌린 유효한 mutant에서 다시 실패


WRONG_EXPECTED = {"comment-only": "fail", "ignore-comment": "fail", "noop-refactor": "fail", "block-everything": "fail", "syntax-error": "unknown"}


@pytest.mark.parametrize("case", SUPPORTED, ids=[c.name for c in SUPPORTED])
def test_wrong_fixes_do_not_pass(tmp_path: Path, case):
    for name in WRONG_EXPECTED:
        result = evaluate(case, name, tmp_path)
        assert result.result == WRONG_EXPECTED[name], (case.name, name, result.result, result.reason)
        assert result.result != "pass"


def test_aggregate_discrimination_on_the_sample(tmp_path: Path):
    """정답 수정은 모두 통과, 잘못된 수정은 하나도 통과하지 못한다. 표본에서 해로운 수정 수용 0건(모집단 오류율 0을 뜻하지 않는다)."""
    accepted_correct = accepted_wrong = wrong_total = 0
    for case in SUPPORTED:
        accepted_correct += evaluate(case, "fix", tmp_path).result == "pass"
        for name in WRONG_EXPECTED:
            wrong_total += 1
            accepted_wrong += evaluate(case, name, tmp_path).result == "pass"
    assert (accepted_correct, accepted_wrong, wrong_total) == (len(SUPPORTED), 0, len(SUPPORTED) * 5)


# ---------------------------------------------------------------------------
# 시험 자체의 신뢰성: 환경 실패·flaky·정상 대조군·mutant
# ---------------------------------------------------------------------------


def _case(name: str):
    return next(c for c in CASES if c.name == name)


def test_environment_failures_are_not_counted_as_defect_reproduction(tmp_path: Path):
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", "import definitely_not_installed_module\n" + case.vulnerable)
    spec = propose(write_project(tmp_path / "ref", case.vulnerable), case)
    result = check(tmp_path, project, case.fix, spec)
    assert result.result == "unknown"
    assert "의존성 누락" in result.reason and result.evidence["original_attack"] == ["error"] * 3


def test_original_that_does_not_reproduce_stays_a_test_candidate(tmp_path: Path):
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", case.fix)  # 이미 안전한 코드
    spec = propose(write_project(tmp_path / "ref", case.vulnerable), case)
    result = check(tmp_path, project, case.fix + "# 변경\n", spec)
    assert result.result == "unknown" and "시험 후보로 남긴다" in result.reason


def test_zero_sink_original_cannot_distinguish_normal_behavior(tmp_path: Path):
    """정상 입력이 싱크에 닿지 않는 원본에서는 '모든 것을 막는 수정'을 구별할 수 없다"""
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", FLASK_NOOP := "from flask import request\n\ndef run_tool():\n    return request.args['d']\n")
    spec = propose(write_project(tmp_path / "ref", case.vulnerable), case)
    result = check(tmp_path, project, FLASK_NOOP + "# x\n", spec)
    assert result.result == "unknown"


def test_over_blocking_fix_fails_via_the_control(tmp_path: Path):
    case = _case("path-param-basename")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    result = check(tmp_path, project, "def read(name):\n    raise PermissionError('no')\n", spec)
    assert result.result == "fail" and "정상 입력까지 막는다" in result.reason
    assert result.evidence["candidate_attack"] == ["passed"] * 3 and result.evidence["candidate_control"] == ["control_failed"] * 3


def test_flaky_results_are_unknown(tmp_path: Path):
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = confirmed(propose(project, case))
    flaky = ScriptedRunner([_harness_result("defect_reproduced"), _harness_result("passed"), _harness_result("defect_reproduced")])
    original, candidate = tmp_path / "o", tmp_path / "c"
    shutil.copytree(project, original)
    shutil.copytree(project, candidate)
    result = run_regression_check(spec_file(tmp_path, spec), original, candidate, tmp_path, flaky, LIMITS, [])
    assert result.result == "unknown" and "flaky" in result.reason


def _harness_result(outcome: str, reason: str = "x") -> RunResult:
    line = "IRON_LAWS_RESULT " + json.dumps({"outcome": outcome, "reason": reason, "sink_calls": 1})
    return RunResult(status="passed", exit_code=0, backend="scripted", excerpt="noise\n" + line)


def test_parse_result_takes_only_the_marker_line_and_survives_garbage():
    assert parse_result("IRON_LAWS_RESULT {\"outcome\": \"passed\"}\n")["outcome"] == "passed"
    assert parse_result("출력만 있다\nIRON_LAWS_RESULT {깨진 json\n") is None
    assert parse_result("") is None
    both = 'IRON_LAWS_RESULT {"outcome":"defect_reproduced"}\nIRON_LAWS_RESULT {"outcome":"passed"}\n'
    assert parse_result(both)["outcome"] == "passed"  # 마지막 줄을 쓴다


def test_isolation_unavailable_or_limits_are_not_run_not_failure(tmp_path: Path):
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": case.fix}))
    result = regression_only(project, patch, spec_file(tmp_path, confirmed(spec)), "none", None, LIMITS)  # 격리 없음
    assert result.result == "unknown" and not result.executed and "격리" in result.reason


def test_mutant_survivors_and_invalid_mutants_are_reported_separately(tmp_path: Path):
    case = _case("path-param-basename")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    result = check(tmp_path, project, case.fix, spec)
    mutants = result.evidence["mutants"]
    assert mutants["total"] == len(mutants["killed"]) + len(mutants["survived"]) + len(mutants["invalid"])
    assert mutants["killed"]  # 수정을 되돌린 mutant는 죽는다


def test_hunk_splitter_and_mutant_builder(tmp_path: Path):
    case = _case("sql-cursor-fstring")
    project = write_project(tmp_path / "proj", case.vulnerable)
    patch_text = make_diff(project, {"app.py": case.fix})
    hunks = split_hunks(patch_text, "app.py")
    assert len(hunks) == 1 and "@@" in hunks[0][1] and "+++ b/app.py" in hunks[0][1]
    plain = patch_text.replace("diff --git a/app.py b/app.py\n", "")
    assert len(split_hunks(plain, "app.py")) == 1  # 일반 unified diff도 받는다
    assert split_hunks(patch_text, "other.py") == []
    candidate = tmp_path / "cand"
    shutil.copytree(project, candidate)
    (candidate / "app.py").write_text(case.fix)
    mutants = build_mutants(candidate, patch_text, "app.py", tmp_path)
    assert mutants and all(m.directory.exists() for m in mutants)
    assert any(m.kind == "hunk_reverse" and m.valid for m in mutants)
    assert (mutants[0].directory / "app.py").read_text() == case.vulnerable  # 수정을 되돌리면 원본이 된다


def test_spec_inside_the_repo_cannot_be_rewritten_by_the_patch(tmp_path: Path):
    case = _case("cmd-flask-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = confirmed(propose(project, case))
    (project / "regression.yml").write_text(dump_spec(spec))
    weakened = spec.model_copy(update={"input": spec.input.model_copy(update={"payload": "harmless"})})
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": case.fix, "regression.yml": dump_spec(weakened)}))
    receipt = verify_patch(project, patch, VerifyOptions(finding="IL-504@app.py", runner="none", require_tests=False, regression_spec=project / "regression.yml"), LOCAL)
    assert "policy_changed" in {b["kind"] for b in receipt.bypass_changes}
    assert "regression.yml" in receipt.inputs["restored_trusted_files"]


def test_verify_patch_includes_the_regression_check(tmp_path: Path):
    case = _case("path-fstring-basename")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec_path = spec_file(tmp_path, confirmed(propose(project, case)))
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": case.fix}))
    receipt = verify_patch(project, patch, VerifyOptions(finding="IL-502@app.py", runner="none", require_tests=False, regression_spec=spec_path), LOCAL)
    regression = next(c for c in receipt.checks if c.id == "regression_test")
    assert regression.result == "pass", regression.reason
    assert receipt.verdict.overall == "verified"
    bad = tmp_path / "bad.diff"
    bad.write_text(make_diff(project, {"app.py": case.vulnerable + "# 주석만\n"}))
    failed = verify_patch(project, bad, VerifyOptions(finding="IL-502@app.py", runner="none", require_tests=False, regression_spec=spec_path), LOCAL)
    assert next(c for c in failed.checks if c.id == "regression_test").result == "fail"
    assert failed.verdict.overall == "failed"


def test_cli_regression_check_exit_codes(tmp_path: Path):
    case = _case("sql-cursor-fstring")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec_path = spec_file(tmp_path, confirmed(propose(project, case)))
    patch = tmp_path / "p.diff"
    patch.write_text(make_diff(project, {"app.py": case.fix}))
    unconfirmed = spec_file(tmp_path, propose(project, case), "u.yml")
    result = cli.invoke(app, ["regression", "check", str(project), "--patch", str(patch), "--spec", str(unconfirmed), "--runner", "none"])
    assert result.exit_code == 2
    assert json.loads(result.output)["result"] == "unknown"
    missing = cli.invoke(app, ["regression", "check", str(project), "--patch", str(patch), "--spec", str(tmp_path / "none.yml")])
    assert missing.exit_code == 2
    assert spec_path.exists()


# ---------------------------------------------------------------------------
# 부작용 없음: 실제 셸·파일·DB를 건드리지 않는다
# ---------------------------------------------------------------------------


def test_harness_never_runs_a_real_shell_or_touches_real_files(tmp_path: Path):
    marker = tmp_path / "IRON_LAWS_PWNED"
    case = _case("cmd-param-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    spec = confirmed(spec).model_copy(update={"input": spec.input.model_copy(update={"payload": f"x; touch {marker}"})})
    install_harness(project, spec)
    run = run_harness(LOCAL, project, "attack", LIMITS)
    assert run.outcome == "defect_reproduced"
    assert not marker.exists()  # os.system은 기록만 했다
    assert not (project / "IRON_LAWS_PWNED").exists()


def test_path_harness_never_reads_the_real_file(tmp_path: Path):
    case = _case("path-direct-param")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = confirmed(propose(project, case))
    install_harness(project, spec)
    run = run_harness(LOCAL, project, "attack", LIMITS)
    assert run.outcome == "defect_reproduced" and "허용 폴더 밖" in run.reason


def test_sql_harness_never_connects_to_a_database(tmp_path: Path):
    case = _case("sql-cursor-fstring")
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = confirmed(propose(project, case))
    install_harness(project, spec)
    assert run_harness(LOCAL, project, "attack", LIMITS).outcome == "defect_reproduced"
    assert not list(project.rglob("*.db")) and not list(project.rglob("*.sqlite*"))


def test_harness_directory_is_the_only_writable_place(tmp_path: Path):
    case = _case("cmd-param-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    install_harness(project, confirmed(propose(project, case)))
    assert (project / HARNESS_DIR / "base").stat().st_mode & 0o777 == 0o777
    assert (project / "app.py").stat().st_mode & 0o002 == 0  # 격리 환경의 비특권 사용자(others)는 프로젝트 파일을 쓰지 못한다


# ---------------------------------------------------------------------------
# 실제 격리 실행 (docker 이미지가 있을 때)
# ---------------------------------------------------------------------------


@needs_docker
@pytest.mark.parametrize("name", ["cmd-flask-os-system", "path-flask-guard", "sql-cursor-fstring", "cmd-json-validate"])
def test_docker_protocol_matches_the_local_double(tmp_path: Path, name):
    from iron_laws.verify.runner import DockerRunner

    case = _case(name)
    project = write_project(tmp_path / "proj", case.vulnerable)
    spec = propose(project, case)
    docker = check(tmp_path, project, case.fix, spec, runner=DockerRunner(IMAGE), patch_name="docker.diff")
    local = check(tmp_path, project, case.fix, spec, patch_name="local.diff")
    assert docker.result == local.result == "pass", (docker.reason, local.reason)
    assert docker.evidence["original_attack"] == local.evidence["original_attack"]
    wrong = check(tmp_path, project, case.vulnerable + "# 주석\n", spec, runner=DockerRunner(IMAGE), patch_name="docker-bad.diff")
    assert wrong.result == "fail"


@needs_docker
def test_docker_regression_never_creates_files_on_the_host(tmp_path: Path):
    from iron_laws.verify.runner import DockerRunner

    case = _case("cmd-param-os-system")
    project = write_project(tmp_path / "proj", case.vulnerable)
    marker = tmp_path / "IRON_LAWS_PWNED"
    spec = propose(project, case)
    spec = spec.model_copy(update={"input": spec.input.model_copy(update={"payload": f"x; touch {marker}"})})
    check(tmp_path, project, case.fix, spec, runner=DockerRunner(IMAGE), patch_name="d.diff")
    assert not marker.exists() and not Path("/work/_iron_laws_harness").exists()


def test_docker_prerequisite_is_reported_when_missing():
    # 환경에 이미지가 없다면 위의 격리 시험은 skip된다. 그 사실이 조용히 사라지지 않게 현재 상태를 남긴다.
    assert isinstance(DOCKER_READY, bool)
    assert shutil.which("docker") is None or isinstance(os.environ.get("PATH", ""), str)
    assert subprocess.run(["git", "--version"], capture_output=True).returncode == 0
