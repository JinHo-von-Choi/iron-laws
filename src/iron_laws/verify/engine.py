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

import fnmatch
import hashlib
import platform
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.config import ConfigError, IronLawsConfig, load_config
from iron_laws.core.contract import Contract, contract_digest, default_contract, load_contract
from iron_laws.core.models import AuditReport, Violation
from iron_laws.core.scanner import SEVERITY_ORDER, AuditScanner, tool_version
from iron_laws.verify.bypass import POLICY_FILES, TEST_INFRA_NAMES, BypassChange, detect_bypasses
from iron_laws.verify.patchfile import apply_patch, inspect_patch
from iron_laws.verify.receipt import CheckResult, Receipt, decide
from iron_laws.verify.runner import (
    DEFAULT_ALLOWED_COMMANDS,
    RunLimits,
    Runner,
    RunResult,
    select_runner,
)
from iron_laws.verify.snapshot import Snapshot, make_writable, materialize, scan_tree

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


class FindingSelectionError(ConfigError):
    """지적을 하나로 정하지 못했을 때"""


def resolve_finding(report: AuditReport, spec: str) -> Violation:
    """지문 접두사, `RULE@경로:줄`, `RULE@경로`로 원본 지적 하나를 고른다."""
    candidates: list[Violation]
    if "@" in spec:
        rule, _, location = spec.partition("@")
        path, _, line = location.partition(":")
        candidates = [
            v for v in report.violations if v.rule_id.upper() == rule.upper() and v.file_path.as_posix() == path and (not line or str(v.line_number) == line)
        ]
    else:
        candidates = [v for v in report.violations if v.fingerprint.startswith(spec)]
    if not candidates:
        raise FindingSelectionError(f"지정한 지적을 원본에서 찾지 못했습니다: {spec}")
    if len(candidates) > 1:
        shown = ", ".join(f"{v.rule_id}@{v.file_path.as_posix()}:{v.line_number}" for v in candidates[:5])
        raise FindingSelectionError(f"지적이 여럿이라 하나로 정하지 못했습니다({len(candidates)}건): {shown}")
    return candidates[0]


def _check(id_: str, title: str, result: str, reason: str = "", required: bool = True, executed: bool = True, **evidence: Any) -> CheckResult:
    return CheckResult(id=id_, title=title, result=result, reason=reason, required=required, executed=executed, evidence=evidence)  # type: ignore[arg-type]


def _scan(root: Path, config: IronLawsConfig, contract: Contract, directive_filter=None) -> tuple[AuditReport, AuditScanner]:
    scanner = AuditScanner(root, config=config, contract=contract, directive_filter=directive_filter)
    return scanner.scan(), scanner


def _gaps_by_location(report: AuditReport) -> dict[tuple[str, str, str], int]:
    gaps: dict[tuple[str, str, str], int] = {}
    if report.coverage_ledger is None:
        return gaps
    for p in report.coverage_ledger.points:
        if p.in_scope and p.state in ("unsupported", "unresolved", "budget_exceeded"):
            key = (p.family, p.path, p.state)
            gaps[key] = gaps.get(key, 0) + 1
    return gaps


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
    try:
        return _verify(original, patch_path, options, runner, work, checks)
    finally:
        make_writable(work)
        shutil.rmtree(work, ignore_errors=True)


def _verify(original: Path, patch_path: Path, options: VerifyOptions, runner: Runner | None, work: Path, checks: list[CheckResult]) -> Receipt:
    # ---- 1. 입력 고정 ----
    started = time.monotonic()
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

    # ---- 2. patch 검사와 적용 ----
    info = inspect_patch(patch_path)
    applied_ok, apply_error = (False, "")
    if info.problems:
        checks.append(_check("patch_safety", "patch 안전성(경로·종류·적용 가능성)", "fail", "; ".join(info.problems[:3]), problems=info.problems, files=info.files))
    else:
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

    receipt_inputs: dict[str, Any] = {"original_tree": original_snapshot.digest, "patch": info.digest, "patch_files": info.files, "patch_bytes": info.size}
    if not applied_ok:
        return _finish(options, checks, receipt_inputs, {}, None, {}, {}, [], runner, started)

    # ---- 3. 정책 동결과 우회 변경 ----
    config, config_source = load_config(orig_ro, options.config_path)
    if options.contract_path is not None:
        contract, contract_file_digest = load_contract(options.contract_path)
    else:
        contract, contract_file_digest = default_contract(), "기본값"
    runner_policy, _runner_policy_source = load_runner_policy(orig_ro)
    policy_names = set(POLICY_FILES)
    spec_rel: str | None = None
    spec_source: Path | None = options.regression_spec
    if spec_source is not None:
        try:
            spec_rel = spec_source.resolve().relative_to(original).as_posix()
            spec_source = orig_ro / spec_rel  # 명세가 원본 저장소 안에 있으면 후보가 바꾼 것이 아니라 원본 스냅샷의 것을 쓴다
            policy_names.add(spec_rel)
        except ValueError:
            spec_rel = None
    deleted = [f for f in info.files if (orig_ro / f).is_file() and not (cand_run / f).exists()]
    bypasses: list[BypassChange] = detect_bypasses(orig_ro, cand_run, info.files, deleted, tuple(policy_names - set(POLICY_FILES)))
    restored = _restore_trusted_files(orig_ro, cand_run, info.files, policy_names)
    candidate_snapshot = scan_tree(cand_run)
    receipt_inputs["candidate_tree"] = candidate_snapshot.digest
    receipt_inputs["restored_trusted_files"] = restored
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

    # ---- 4. 같은 조건의 정적 검사 ----
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

    # ---- 5. 지적 변화 ----
    # 줄이 바뀐 지적을 같은 지적으로 맺으려고 (규칙, 파일, 함수) 단위의 개수로 비교한다. 고친 줄의 모양이 바뀌어도 새 지적으로 세지 않는다.
    def keyed(report: AuditReport) -> dict[tuple[str, str, str], list[Violation]]:
        grouped: dict[tuple[str, str, str], list[Violation]] = {}
        for v in report.violations:
            grouped.setdefault((v.rule_id, v.file_path.as_posix(), v.scope_name), []).append(v)
        return grouped

    before_groups, after_groups = keyed(original_report), keyed(candidate_report)
    new_findings: list[Violation] = []
    resolved_groups: list[tuple[str, str, str]] = []
    for key, items in after_groups.items():
        extra = len(items) - len(before_groups.get(key, []))
        if extra > 0:
            new_findings.extend(items[-extra:])
    for key, items in before_groups.items():
        if len(after_groups.get(key, [])) < len(items):
            resolved_groups.append(key)
    threshold = SEVERITY_ORDER[config.fail_on]
    blocking_new = [v for v in new_findings if SEVERITY_ORDER[v.severity] >= threshold]
    findings_summary = {
        "original_total": len(original_report.violations),
        "candidate_total": len(candidate_report.violations),
        "resolved": [{"rule": r, "path": pth, "scope": sc} for r, pth, sc in resolved_groups],
        "new": [{"rule": v.rule_id, "path": v.file_path.as_posix(), "line": v.line_number, "severity": v.severity.value} for v in new_findings],
        "untrusted_suppressions_ignored": sum(1 for d in candidate_report.diagnostics if "신뢰된 정책에 없던 억제" in d.message),
    }
    target_info: dict[str, Any] | None = None
    if options.finding:
        target = resolve_finding(original_report, options.finding)
        target_info = {"rule_id": target.rule_id, "path": target.file_path.as_posix(), "line": target.line_number, "fingerprint": target.fingerprint, "severity": target.severity.value}
        target_key = (target.rule_id, target.file_path.as_posix(), target.scope_name)
        resolved_entry = target_key if target_key in resolved_groups else None
        removed_file = target.file_path.as_posix() not in candidate_snapshot.files
        hiding = [b for b in bypasses if b.kind in ("ignore_added", "config_weakened", "policy_changed", "baseline_changed")]
        ignored_new = findings_summary["untrusted_suppressions_ignored"] > 0
        if removed_file:
            checks.append(_check("target_resolved", "대상 지적 해소", "fail", "파일을 지워서 지적이 사라졌다. 수정으로 인정하지 않는다", target=target_info))
        elif resolved_entry is None:
            checks.append(_check("target_resolved", "대상 지적 해소", "fail", "후보에서도 같은 지적이 남아 있다", target=target_info))
        elif hiding or ignored_new:
            checks.append(
                _check(
                    "target_resolved",
                    "대상 지적 해소",
                    "fail",
                    "지적이 사라졌지만 무시 주석·정책 변경이 함께 있어 수정으로 인정하지 않는다",
                    target=target_info,
                    hiding=[b.kind for b in hiding],
                )
            )
        else:
            checks.append(_check("target_resolved", "대상 지적 해소", "pass", target=target_info))
    else:
        checks.append(_check("target_resolved", "대상 지적 해소", "not_run", "대상 지적(--finding)을 지정하지 않았다", required=False, executed=False))
    checks.append(
        _check(
            "no_new_findings",
            "새 지적 없음(설정한 실패 기준 이상)",
            "fail" if blocking_new else "pass",
            f"새로 생긴 {config.fail_on.value} 이상 지적이 {len(blocking_new)}건 있다" if blocking_new else "",
            new=findings_summary["new"][:20],
        )
    )

    # ---- 6. 검사 공백 ----
    original_gaps, candidate_gaps = _gaps_by_location(original_report), _gaps_by_location(candidate_report)
    worse = {k: (original_gaps.get(k, 0), v) for k, v in candidate_gaps.items() if v > original_gaps.get(k, 0)}
    coverage_summary = {
        "original_status": original_report.coverage_ledger.status if original_report.coverage_ledger else None,
        "candidate_status": candidate_report.coverage_ledger.status if candidate_report.coverage_ledger else None,
        "original_gap_points": sum(original_gaps.values()),
        "candidate_gap_points": sum(candidate_gaps.values()),
        "new_gaps": [{"family": f, "path": p, "state": s, "before": b, "after": a} for (f, p, s), (b, a) in worse.items()],
        "contract_digest": contract_digest(contract),
    }
    checks.append(
        _check(
            "coverage_not_worse",
            "검사 공백이 늘지 않음",
            "fail" if worse else "pass",
            f"후보 변경으로 검사 공백이 {sum(a - b for b, a in worse.values())}곳 늘었다" if worse else "",
            new_gaps=coverage_summary["new_gaps"][:20],
        )
    )

    # ---- 7. 변경 범위 ----
    extras = [f for f in info.files if not options.finding or f != target_info["path"]] if target_info else list(info.files)
    outside = [f for f in info.files if options.allow_paths and not any(fnmatch.fnmatch(f, pat) for pat in options.allow_paths)]
    scope_problems = []
    if target_info and target_info["path"] not in info.files:
        scope_problems.append("patch가 대상 지적이 있는 파일을 바꾸지 않았다")
    if len(info.files) > options.max_files:
        scope_problems.append(f"변경 파일이 {len(info.files)}개로 상한 {options.max_files}개를 넘는다")
    if outside:
        scope_problems.append(f"허용 경로 밖 파일을 바꿨다: {', '.join(outside[:3])}")
    checks.append(
        _check(
            "change_scope",
            "변경 범위(대상 파일 포함·파일 수·허용 경로)",
            "fail" if scope_problems else "pass",
            "; ".join(scope_problems),
            files=info.files,
            extra_files=extras[:20],
        )
    )

    # ---- 8. 기존 시험(격리 실행) ----
    runner_obj = runner or select_runner(options.runner, options.image or runner_policy.image)
    limits = options.limits
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
        "contract_file": contract_file_digest,
        "runner_policy": _digest_policy(runner_policy),
    }
    environment = {
        "scanner_version": tool_version(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "config_source": config_source,
        "runner_backend": runner_obj.name,
        "runner_image": runs["original"].image if runs else (options.image or runner_policy.image),
        "runner_image_id": runs["original"].image_id if runs else "",
        "isolation": "container" if runner_obj.name in ("docker", "bwrap") and runs and runs["original"].status != "isolation_unavailable" else "none",
    }
    return _finish(options, checks, receipt_inputs, digests, target_info, findings_summary, coverage_summary, bypasses, runner_obj, started, environment, runs)


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
    try:
        snapshot = scan_tree(original)
        orig_run = materialize(snapshot, work / "original-run")
        cand_run = materialize(snapshot, work / "candidate-run")
        info = inspect_patch(patch_path)
        if info.problems:
            return _check("regression_test", "회귀시험", "fail", "patch가 안전하지 않다: " + "; ".join(info.problems[:2]))
        ok, error = apply_patch(patch_path, cand_run)
        if not ok:
            return _check("regression_test", "회귀시험", "fail", f"patch를 적용하지 못했다: {error}")
        policy, _ = load_runner_policy(orig_run)
        runner_obj = runner or select_runner(runner_pref, image or policy.image)
        _restore_trusted_files(original, cand_run, info.files, set(POLICY_FILES))
        return run_regression_check(spec_path, orig_run, cand_run, work, runner_obj, limits, policy.allowed_commands, patch_path=patch_path, original_memo=original_memo)
    finally:
        make_writable(work)
        shutil.rmtree(work, ignore_errors=True)
