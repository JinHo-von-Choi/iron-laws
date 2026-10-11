"""원본·후보의 지적·근거 공백·수정 범위 비교."""
import fnmatch
from dataclasses import dataclass
from typing import Any

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.contract import Contract, contract_digest
from iron_laws.core.models import AuditReport, Violation
from iron_laws.core.scanner import SEVERITY_ORDER
from iron_laws.verify.bypass import BypassChange
from iron_laws.verify.checks import _check, _gaps_by_location, resolve_finding
from iron_laws.verify.debt_delta import compare as compare_debt
from iron_laws.verify.receipt import CheckResult
from iron_laws.verify.snapshot import Snapshot


@dataclass
class ComparisonContext:
    original_report: AuditReport
    candidate_report: AuditReport
    config: IronLawsConfig
    contract: Contract
    candidate_snapshot: Snapshot
    patch_files: list[str]
    bypasses: list[BypassChange]
    finding: str | None
    max_files: int
    allow_paths: tuple[str, ...]
    comparable: bool


@dataclass
class ComparisonResult:
    findings: dict[str, Any]
    coverage: dict[str, Any]
    target: dict[str, Any] | None
    debt_delta: dict[str, Any]


def compare_reports(ctx: ComparisonContext, checks: list[CheckResult]) -> ComparisonResult:
    original_report, candidate_report = ctx.original_report, ctx.candidate_report
    config, candidate_snapshot, bypasses = ctx.config, ctx.candidate_snapshot, ctx.bypasses
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
    if not ctx.comparable:
        debt_delta: dict[str, Any] = {"status": "not_compared", "reason": "원본 또는 후보 점검이 끝까지 이루어지지 않았거나 조건이 달라 비교하지 않았다"}
    else:
        debt_delta = {"status": "compared", **compare_debt(original_report, candidate_report).to_dict()}
    threshold = SEVERITY_ORDER[config.fail_on]
    blocking_new = [v for v in new_findings if SEVERITY_ORDER[v.severity] >= threshold]
    findings_summary = {
        "original_total": len(original_report.violations),
        "candidate_total": len(candidate_report.violations),
        "resolved": [{"rule": r, "path": pth, "scope": sc} for r, pth, sc in resolved_groups],
        "new": [{"rule": v.rule_id, "path": v.file_path.as_posix(), "line": v.line_number, "severity": v.severity.value, "finding_id": v.finding_id} for v in new_findings],
        "untrusted_suppressions_ignored": sum(1 for d in candidate_report.diagnostics if "신뢰된 정책에 없던 억제" in d.message),
    }
    target_info: dict[str, Any] | None = None
    if ctx.finding:
        target = resolve_finding(original_report, ctx.finding)
        target_info = {
            "rule_id": target.rule_id,
            "path": target.file_path.as_posix(),
            "line": target.line_number,
            "fingerprint": target.fingerprint,
            "finding_id": target.finding_id,
            "severity": target.severity.value,
        }
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
        "contract_digest": contract_digest(ctx.contract),
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
    extras = [f for f in ctx.patch_files if not ctx.finding or f != target_info["path"]] if target_info else list(ctx.patch_files)
    outside = [f for f in ctx.patch_files if ctx.allow_paths and not any(fnmatch.fnmatch(f, pat) for pat in ctx.allow_paths)]
    scope_problems = []
    if target_info and target_info["path"] not in ctx.patch_files:
        scope_problems.append("patch가 대상 지적이 있는 파일을 바꾸지 않았다")
    if len(ctx.patch_files) > ctx.max_files:
        scope_problems.append(f"변경 파일이 {len(ctx.patch_files)}개로 상한 {ctx.max_files}개를 넘는다")
    if outside:
        scope_problems.append(f"허용 경로 밖 파일을 바꿨다: {', '.join(outside[:3])}")
    checks.append(
        _check(
            "change_scope",
            "변경 범위(대상 파일 포함·파일 수·허용 경로)",
            "fail" if scope_problems else "pass",
            "; ".join(scope_problems),
            files=ctx.patch_files,
            extra_files=extras[:20],
        )
    )

    return ComparisonResult(findings_summary, coverage_summary, target_info, debt_delta)
