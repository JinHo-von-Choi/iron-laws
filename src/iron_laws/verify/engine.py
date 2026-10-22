"""
오철칙 패치 검증 엔진
지적 하나와 외부 AI가 만든 patch를 받아, 원본 스냅샷과 격리된 후보 스냅샷을 같은 정책으로 검사하고 Receipt로 남긴다.
- 정책(설정·계약·실행 정책)과 기존 시험은 원본에서 가져오며 후보 patch가 바꾸지 못한다. 바꾸려는 시도는 우회 변경으로 표시한다.
- 후보가 새로 단 억제 주석은 적용하지 않는다. 경고가 사라진 이유가 가려서인지 고쳐서인지 구분하기 위해서다.
- 격리 환경이 없으면 시험을 실행하지 않고 '판정 불가'로 남긴다. 호스트 실행으로 대체하지 않는다.
- 원본 수정·커밋·게시·병합은 하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import platform
import shutil
import sys
import tempfile
import time
import warnings
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.config import ConfigError, IronLawsConfig, load_config
from iron_laws.core.contract import Contract, contract_digest, default_contract, load_contract
from iron_laws.core.models import AuditReport
from iron_laws.core.scanner import AuditScanner, tool_version
from iron_laws.verify.bypass import POLICY_FILES, TEST_INFRA_NAMES, BypassChange, detect_bypasses
from iron_laws.verify.checks import FindingSelectionError as FindingSelectionError
from iron_laws.verify.checks import _check
from iron_laws.verify.checks import resolve_finding as resolve_finding
from iron_laws.verify.comparison import ComparisonContext, compare_reports
from iron_laws.verify.patchfile import apply_patch, inspect_patch
from iron_laws.verify.receipt import CheckResult, Receipt, decide
from iron_laws.verify.runner import (
    DEFAULT_ALLOWED_COMMANDS,
    RunLimits,
    Runner,
    RunResult,
    select_runner,
)
from iron_laws.verify.snapshot import Snapshot, cleanup_workspace, materialize, scan_tree

RUNNER_POLICY_FILE = ".iron-laws-runner.yml"
DEFAULT_IMAGE = "python:3.13-slim"


class RunnerPolicy(BaseModel):
    """시험 실행 정책. 원본 저장소의 신뢰된 파일에서 읽으며 후보 patch는 바꾸지 못한다."""

    model_config = ConfigDict(extra="forbid")

    image: str = DEFAULT_IMAGE
    allowed_commands: list[list[str]] = Field(default_factory=lambda: [list(c) for c in DEFAULT_ALLOWED_COMMANDS])
    limits: dict[str, float] = Field(default_factory=dict)


def load_runner_policy(root: Path) -> tuple[RunnerPolicy, str]:
    path = root / RUNNER_POLICY_FILE
    if not path.is_file():
        return RunnerPolicy(), "기본값"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return RunnerPolicy(**data), str(RUNNER_POLICY_FILE)
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as e:
        raise ConfigError(f"실행 정책 파일을 읽을 수 없습니다: {path} ({e})") from e


@dataclass
class VerifyOptions:
    finding: str | None = None
    config_path: Path | None = None
    contract_path: Path | None = None
    test_cmd: list[str] | None = None
    runner: str = "auto"
    image: str | None = None
    limits: RunLimits = field(default_factory=RunLimits)
    require_tests: bool = True
    max_files: int = 5
    allow_paths: tuple[str, ...] = ()
    regression_spec: Path | None = None  # 4단계: 결함을 구별하는 회귀시험 명세
    runner_policy: RunnerPolicy | None = None  # 지정하면 저장소의 실행 정책 파일 대신 쓴다(MCP 서버는 서버 설정의 정책만 신뢰한다)

    def to_record(self) -> dict[str, Any]:
        return {
            "finding": self.finding,
            "config_path": str(self.config_path) if self.config_path else None,
            "contract_path": str(self.contract_path) if self.contract_path else None,
            "test_cmd": self.test_cmd,
            "runner": self.runner,
            "image": self.image,
            "limits": self.limits.__dict__,
            "require_tests": self.require_tests,
            "max_files": self.max_files,
            "allow_paths": list(self.allow_paths),
            "regression_spec": str(self.regression_spec) if self.regression_spec else None,
        }








def _scan(root: Path, config: IronLawsConfig, contract: Contract, directive_filter=None) -> tuple[AuditReport, AuditScanner]:
    scanner = AuditScanner(root, config=config, contract=contract, directive_filter=directive_filter)
    return scanner.scan(), scanner




def _restore_trusted_files(original: Path, candidate: Path, touched: list[str], policy_names: set[str]) -> list[str]:
    """후보 작업영역의 정책·시험·시험 기반 파일을 원본 내용으로 되돌린다. 후보가 새로 만든 시험은 지운다."""
    restored: list[str] = []
    from iron_laws.core.paths import is_test_path

    for rel in sorted(set(touched)):
        name = Path(rel).name
        trusted = rel in policy_names or name in policy_names or name in TEST_INFRA_NAMES or name.endswith(".pth") or is_test_path(Path(rel))
        if not trusted:
            continue
        source, target = original / rel, candidate / rel
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            restored.append(rel)
        elif target.exists():
            target.unlink()
            restored.append(rel)
    return restored


def verify_patch(original: Path, patch_path: Path, options: VerifyOptions, runner: Runner | None = None) -> Receipt:
    original = original.resolve()
    if not original.is_dir():
        raise ConfigError(f"원본 경로가 폴더가 아닙니다: {original}")
    if not patch_path.is_file():
        raise ConfigError(f"patch 파일이 없습니다: {patch_path}")

    work = Path(tempfile.mkdtemp(prefix="iron-laws-verify-"))
    checks: list[CheckResult] = []
    receipt: Receipt | None = None
    try:
        receipt = _verify(original, patch_path, options, runner, work, checks)
        return receipt
    finally:
        notes = cleanup_workspace(work)
        if receipt is not None:
            receipt.environment["workspace_cleanup"] = {"complete": not notes, "notes": notes}
            receipt.seal()
        elif notes:
            warnings.warn("; ".join(notes), RuntimeWarning, stacklevel=2)


def _pin_inputs(original: Path, work: Path, checks: list[CheckResult]) -> tuple[Snapshot, Path, Path, Path]:
    """원본을 고정하고 읽기 전용·실행용·후보용 사본을 만든다."""
    original_snapshot: Snapshot = scan_tree(original)
    orig_ro = materialize(original_snapshot, work / "original-ro", read_only=True)
    orig_run = materialize(original_snapshot, work / "original-run")
    cand_run = materialize(original_snapshot, work / "candidate-run")
    pin_reason = "; ".join(original_snapshot.risks[:3])
    checks.append(
        _check(
            "input_pinning",
            "입력 고정(원본·후보 스냅샷과 해시)",
            "fail" if original_snapshot.risks else "pass",
            pin_reason,
            original_tree=original_snapshot.digest,
            files=len(original_snapshot.files),
            risks=original_snapshot.risks[:10],
        )
    )
    return original_snapshot, orig_ro, orig_run, cand_run


def _apply_patch_checked(patch_path: Path, cand_run: Path, checks: list[CheckResult]) -> tuple[object, bool, str]:
    """patch를 검사하고 적용한다. (patch 정보, 적용 여부, 실패 사유)"""
    info = inspect_patch(patch_path)
    if info.problems:
        checks.append(_check("patch_safety", "patch 안전성(경로·종류·적용 가능성)", "fail", "; ".join(info.problems[:3]), problems=info.problems, files=info.files))
        return info, False, "; ".join(info.problems[:3])
    applied_ok, apply_error = apply_patch(patch_path, cand_run)
    checks.append(
        _check(
            "patch_safety",
            "patch 안전성(경로·종류·적용 가능성)",
            "pass" if applied_ok else "fail",
            "" if applied_ok else f"patch를 적용하지 못했다: {apply_error}",
            files=info.files,
            patch_digest=info.digest,
        )
    )
    return info, applied_ok, apply_error


@dataclass
class _FrozenPolicies:
    """동결된 신뢰 정책과 우회 변경 목록."""

    config: IronLawsConfig
    config_source: str
    contract: Contract
    contract_file_digest: str
    runner_policy: RunnerPolicy
    spec_source: Path | None
    bypasses: list[BypassChange]
    restored: list[str]


def _freeze_policies(
    orig_ro: Path,
    cand_run: Path,
    original: Path,
    options: VerifyOptions,
    info_files: list[str],
    checks: list[CheckResult],
) -> _FrozenPolicies:
    """신뢰된 정책·시험 파일을 동결하고 후보가 바꾸려 한 것을 되돌린다."""
    config, config_source = load_config(orig_ro, options.config_path)
    if options.contract_path is not None:
        contract, contract_file_digest = load_contract(options.contract_path)
    else:
        contract, contract_file_digest = default_contract(), "기본값"
    runner_policy = options.runner_policy if options.runner_policy is not None else load_runner_policy(orig_ro)[0]
    policy_names = set(POLICY_FILES)
    spec_source: Path | None = options.regression_spec
    if spec_source is not None:
        try:
            spec_rel = spec_source.resolve().relative_to(original).as_posix()
        except ValueError:
            spec_rel = None  # 명세가 원본 저장소 밖에 있으면 원본 경로를 그대로 쓴다
        if spec_rel is not None:
            spec_source = orig_ro / spec_rel  # 명세가 원본 저장소 안에 있으면 후보가 바꾼 것이 아니라 원본 스냅샷의 것을 쓴다
            policy_names.add(spec_rel)
    deleted = [f for f in info_files if (orig_ro / f).is_file() and not (cand_run / f).exists()]
    bypasses: list[BypassChange] = detect_bypasses(orig_ro, cand_run, info_files, deleted, tuple(policy_names - set(POLICY_FILES)))
    restored = _restore_trusted_files(orig_ro, cand_run, info_files, policy_names)
    checks.append(
        _check(
            "policy_integrity",
            "정책·시험 동결(후보가 신뢰된 파일을 바꾸지 못함)",
            "fail" if any(b.kind in ("policy_changed", "baseline_changed", "config_weakened", "test_infra_changed") for b in bypasses) else "pass",
            "후보 patch가 정책·기준선·시험 기반 파일을 바꾸려 했다. 해당 변경은 적용하지 않고 원본으로 되돌렸다" if restored else "",
            restored=restored,
        )
    )
    checks.append(
        _check(
            "bypass_changes",
            "우회 변경(시험 삭제·skip·단언 약화·무시 주석·정책 약화)",
            "fail" if bypasses else "pass",
            f"{len(bypasses)}건의 우회 변경이 있다. 경고가 사라졌더라도 수정으로 인정하지 않는다" if bypasses else "",
            kinds=sorted({b.kind for b in bypasses}),
        )
    )
    return _FrozenPolicies(
        config=config,
        config_source=config_source,
        contract=contract,
        contract_file_digest=contract_file_digest,
        runner_policy=runner_policy,
        spec_source=spec_source,
        bypasses=bypasses,
        restored=restored,
    )


def _scan_same_condition(
    orig_run: Path, cand_run: Path, config: IronLawsConfig, contract: Contract, checks: list[CheckResult]
) -> tuple[AuditReport, AuditReport, bool]:
    """원본과 후보를 같은 조건으로 점검한다. 원본에 없던 억제 주석은 후보에서 인정하지 않는다."""
    t0 = time.monotonic()
    original_report, original_scanner = _scan(orig_run, config, contract)
    trusted_directives = original_scanner.directives_seen

    def directive_filter(path: str, directive) -> bool:  # 원본에 없던 억제 주석은 적용하지 않는다
        return (path, frozenset(directive.ids), directive.reason) in trusted_directives

    candidate_report, _candidate_scanner = _scan(cand_run, config, contract, directive_filter)
    scan_seconds = round(time.monotonic() - t0, 2)
    same_condition = original_report.metadata["ruleset"]["hash"] == candidate_report.metadata["ruleset"]["hash"] and original_report.metadata["config_hash"] == candidate_report.metadata["config_hash"]
    incomplete = [r for r in (original_report, candidate_report) if r.summary.scan_status != "complete"]
    if incomplete or not same_condition:
        checks.append(
            _check(
                "same_condition_scan",
                "동일 조건 정적 검사(같은 규칙·설정·상한)",
                "unknown",
                "원본 또는 후보 점검이 끝까지 이루어지지 않았거나 조건이 달라 비교할 수 없다",
                original_status=original_report.summary.scan_status,
                candidate_status=candidate_report.summary.scan_status,
            )
        )
    else:
        checks.append(
            _check(
                "same_condition_scan",
                "동일 조건 정적 검사(같은 규칙·설정·상한)",
                "pass",
                ruleset=original_report.metadata["ruleset"]["hash"],
                config=original_report.metadata["config_hash"],
                scan_seconds=scan_seconds,
            )
        )
    checks[-1].duration_s = scan_seconds
    return original_report, candidate_report, not incomplete and same_condition


def _run_existing_tests(
    runner_obj: Runner,
    orig_run: Path,
    cand_run: Path,
    options: VerifyOptions,
    runner_policy: RunnerPolicy,
    limits: RunLimits,
    checks: list[CheckResult],
) -> dict[str, RunResult]:
    """원본과 후보의 기존 시험을 격리 실행기로 돌린다."""
    for key, value in runner_policy.limits.items():
        if hasattr(limits, key) and limits.__dict__.get(key) == RunLimits().__dict__.get(key):
            setattr(limits, key, type(getattr(limits, key))(value))  # 신뢰된 정책의 상한을 기본값 위에 적용
    test_cmd = options.test_cmd
    runs: dict[str, RunResult] = {}
    tests_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "not_run", "시험 명령(--test-cmd)이 지정되지 않았다", required=options.require_tests, executed=False)
    if test_cmd:
        runs["original"] = runner_obj.run(orig_run, test_cmd, limits, runner_policy.allowed_commands)
        runs["candidate"] = runner_obj.run(cand_run, test_cmd, limits, runner_policy.allowed_commands)
        tests_check = _tests_check(runs, options.require_tests)
    checks.append(tests_check)
    return runs


def _verify(original: Path, patch_path: Path, options: VerifyOptions, runner: Runner | None, work: Path, checks: list[CheckResult]) -> Receipt:
    # ---- 1. 입력 고정 ----
    started = time.monotonic()
    original_snapshot, orig_ro, orig_run, cand_run = _pin_inputs(original, work, checks)

    # ---- 2. patch 검사와 적용 ----
    info, applied_ok, apply_error = _apply_patch_checked(patch_path, cand_run, checks)

    receipt_inputs: dict[str, Any] = {"original_tree": original_snapshot.digest, "patch": info.digest, "patch_files": info.files, "patch_bytes": info.size}
    if not applied_ok:
        return _finish(options, checks, receipt_inputs, {}, None, {}, {}, [], runner, started)

    # ---- 3. 정책 동결과 우회 변경 ----
    frozen = _freeze_policies(orig_ro, cand_run, original, options, info.files, checks)
    config, contract = frozen.config, frozen.contract
    runner_policy, spec_source, bypasses = frozen.runner_policy, frozen.spec_source, frozen.bypasses
    candidate_snapshot = scan_tree(cand_run)
    receipt_inputs["candidate_tree"] = candidate_snapshot.digest
    receipt_inputs["restored_trusted_files"] = frozen.restored

    # ---- 4. 같은 조건의 정적 검사 ----
    original_report, candidate_report, comparable = _scan_same_condition(orig_run, cand_run, config, contract, checks)

    comparison = compare_reports(ComparisonContext(original_report, candidate_report, config, contract, candidate_snapshot,
                                                   info.files, bypasses, options.finding, options.max_files,
                                                   options.allow_paths, comparable), checks)
    findings_summary, coverage_summary = comparison.findings, comparison.coverage
    target_info, debt_delta = comparison.target, comparison.debt_delta

    # ---- 8. 기존 시험(격리 실행) ----
    runner_obj = runner or select_runner(options.runner, options.image or runner_policy.image)
    limits = options.limits
    runs = _run_existing_tests(runner_obj, orig_run, cand_run, options, runner_policy, limits, checks)

    # ---- 9. 회귀시험(4단계) ----
    if spec_source is not None:
        from iron_laws.verify.regression import run_regression_check

        checks.append(
            run_regression_check(spec_source, orig_run, cand_run, work, runner_obj, limits, runner_policy.allowed_commands, patch_path=patch_path, bypass_count=len(bypasses))
        )

    digests = {
        "scanner": f"{tool_version()}+{original_report.metadata['ruleset']['hash']}",
        "config": original_report.metadata["config_hash"],
        "contract": contract_digest(contract),
        "contract_file": frozen.contract_file_digest,
        "runner_policy": _digest_policy(runner_policy),
    }
    environment = {
        "scanner_version": tool_version(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "config_source": frozen.config_source,
        "runner_backend": runner_obj.name,
        "runner_image": runs["original"].image if runs else (options.image or runner_policy.image),
        "runner_image_id": runs["original"].image_id if runs else "",
        "isolation": "container" if runner_obj.name in ("docker", "bwrap") and runs and runs["original"].status != "isolation_unavailable" else "none",
    }
    evidence = {
        side: {
            "run_id": report.coverage_ledger.run_id if report.coverage_ledger else "",
            "code_digest": report.execution.code_digest if report.execution else "",
            "finding_ids": [v.finding_id for v in report.violations],
            "fingerprints": [v.fingerprint for v in report.violations],
            "scan_status": report.summary.scan_status,
        }
        for side, report in (("original", original_report), ("candidate", candidate_report))
    }
    return _finish(options, checks, receipt_inputs, digests, target_info, findings_summary, coverage_summary, bypasses, runner_obj, started, environment, runs, evidence, debt_delta)


def _digest_policy(policy: RunnerPolicy) -> str:
    return hashlib.sha256(policy.model_dump_json().encode()).hexdigest()[:16]


def _tests_check(runs: dict[str, RunResult], required: bool) -> CheckResult:
    original, candidate = runs["original"], runs["candidate"]
    evidence = {
        side: {
            "status": r.status,
            "exit_code": r.exit_code,
            "duration_s": r.duration_s,
            "limit_reached": r.limit_reached,
            "attempts": r.attempts,
            "counts_untrusted": r.counts,
            "excerpt": r.excerpt,
            "notes": r.notes,
        }
        for side, r in runs.items()
    }
    duration = round(original.duration_s + candidate.duration_s, 2)
    if "isolation_unavailable" in (original.status, candidate.status):
        reason = "격리 환경을 얻지 못해 시험을 실행하지 않았다. 호스트에서 대신 실행하지 않았다: " + "; ".join(original.notes[:1])
        result = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", reason, required=required, executed=False, **evidence)
        return result
    if "not_allowed" in (original.status, candidate.status):
        return _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", "신뢰된 명령 목록에 없는 명령이라 실행하지 않았다: " + "; ".join(original.notes[:1]), required=required, executed=False, **evidence)
    limit_hit = original.limit_reached or candidate.limit_reached
    result_check: CheckResult
    if limit_hit:
        result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", "시간·출력 상한에 도달해 종료되었다. 충분한 검증으로 보지 않는다", required=required, **evidence)
        result_check.limit_reached = True
    elif "infrastructure_error" in (original.status, candidate.status):
        result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", "실행기 오류로 시험이 실행되지 않았다", required=required, **evidence)
    elif original.status == "failed":
        result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", "원본에서 이미 시험이 실패해 후보와 비교할 수 없다", required=required, **evidence)
    elif candidate.status == "failed":
        result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "fail", "원본에서 통과하던 시험이 후보에서 실패한다(정상 동작 훼손)", required=required, **evidence)
    else:
        # 종료코드는 통과지만 시험이 실행되지 않았거나(0건) skip이 늘었으면 통과로 보지 않는다. 건수는 시험 출력에서 읽은 비신뢰 값이다.
        oc, cc = original.counts, candidate.counts
        if cc.get("no_tests") or (cc.get("passed", 0) == 0 and cc.get("ran", 0) == 0):
            result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "unknown", "후보에서 실행된 시험이 0건으로 보인다. 통과로 인정하지 않는다", required=required, **evidence)
        elif cc.get("skipped", 0) > oc.get("skipped", 0) or cc.get("xfailed", 0) > oc.get("xfailed", 0):
            result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "fail", "후보에서 skip·xfail이 늘었다", required=required, **evidence)
        elif cc.get("passed", 0) < oc.get("passed", 0):
            result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "fail", "후보에서 통과한 시험 수가 줄었다", required=required, **evidence)
        else:
            result_check = _check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "pass", required=required, **evidence)
    result_check.duration_s = duration
    return result_check


def _finish(
    options: VerifyOptions,
    checks: list[CheckResult],
    inputs: dict[str, Any],
    digests: dict[str, str],
    target: dict[str, Any] | None,
    findings: dict[str, Any],
    coverage: dict[str, Any],
    bypasses: list[BypassChange],
    runner: Runner | None,
    started: float,
    environment: dict[str, Any] | None = None,
    runs: dict[str, RunResult] | None = None,
    evidence: dict[str, Any] | None = None,
    debt_delta: dict[str, Any] | None = None,
) -> Receipt:
    if not any(c.id == "existing_tests" for c in checks):
        checks.append(_check("existing_tests", "기존 시험(원본과 후보, 격리 실행)", "not_run", "patch 검사 단계에서 중단되어 실행하지 않았다", required=options.require_tests, executed=False))
    verdict = decide(checks)
    receipt = Receipt(
        created=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        options=options.to_record(),
        inputs=inputs,
        digests=digests,
        environment=environment or {"scanner_version": tool_version(), "runner_backend": runner.name if runner else "none", "isolation": "none"},
        target=target,
        checks=checks,
        findings=findings,
        evidence=evidence or {},
        debt_delta=debt_delta or {},
        coverage=coverage,
        bypass_changes=[b.__dict__ for b in bypasses],
        verdict=verdict,
    )
    receipt.environment["elapsed_s"] = round(time.monotonic() - started, 2)
    return receipt.seal()



def regression_only(
    original: Path,
    patch_path: Path,
    spec_path: Path,
    runner_pref: str,
    image: str | None,
    limits: RunLimits,
    runner: Runner | None = None,
    original_memo: dict | None = None,
) -> CheckResult:
    """정적 검사 없이 회귀시험 검증(원본 실패·후보 통과·mutant 재실패)만 실행한다."""
    from iron_laws.verify.regression import run_regression_check

    original = original.resolve()
    work = Path(tempfile.mkdtemp(prefix="iron-laws-regression-"))
    result: CheckResult | None = None
    try:
        snapshot = scan_tree(original)
        orig_run = materialize(snapshot, work / "original-run")
        cand_run = materialize(snapshot, work / "candidate-run")
        info = inspect_patch(patch_path)
        if info.problems:
            result = _check("regression_test", "회귀시험", "fail", "patch가 안전하지 않다: " + "; ".join(info.problems[:2]))
            return result
        ok, error = apply_patch(patch_path, cand_run)
        if not ok:
            result = _check("regression_test", "회귀시험", "fail", f"patch를 적용하지 못했다: {error}")
            return result
        policy, _ = load_runner_policy(orig_run)
        runner_obj = runner or select_runner(runner_pref, image or policy.image)
        _restore_trusted_files(original, cand_run, info.files, set(POLICY_FILES))
        result = run_regression_check(spec_path, orig_run, cand_run, work, runner_obj, limits, policy.allowed_commands, patch_path=patch_path, original_memo=original_memo)
        return result
    finally:
        notes = cleanup_workspace(work)
        if result is not None:
            result.evidence["workspace_cleanup"] = {"complete": not notes, "notes": notes}
        elif notes:
            warnings.warn("; ".join(notes), RuntimeWarning, stacklevel=2)
