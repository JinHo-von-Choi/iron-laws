"""
오철칙 독립 검증기: 점검 보고서와 검증 기록의 구조적 모순을 찾는다
- 이 모듈은 표준 라이브러리만 쓴다. 규칙·분석 엔진·장부 작성 코드를 호출하지 않으며, 생산자가 계산한 값을 복사해 기대값으로 삼지 않고
  보고서에 적힌 참조·범위·정책·실행 지문의 불변식을 직접 계산해 대조한다.
- 잡는 것: 존재하지 않는 지적을 가리키는 장부, 근거 없는 '충족', 다른 파일·다른 규칙의 지적 연결, 차단 사유와 상태의 불일치,
  통과 판정의 근거 부재, 만료·손상·다른 정책의 승인을 유효로 둔 경우, 다른 checkout의 코드와 맞지 않는 보고서.
- 잡지 못하는 것: 엔진이 일관되게 만든 의미 오류(예: 안전하지 않은 코드를 일관되게 안전으로 판정). 통과는 구조가 일관된다는 뜻이다.
작성자: 최진호
작성일: 2026-10-05
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any

SUPPORTED_REPORT_VERSIONS = ("1.3",)
SUPPORTED_RECEIPT_VERSIONS = ("1",)

# 검사 계열 → 그 계열의 지적을 내는 규칙. 보고서가 다른 계열의 지적을 연결하면 모순이다.
FAMILY_RULE = {"command": "IL-504", "path": "IL-502", "sql": "IL-501"}
POINT_STATES = ("evidence_met", "unsupported", "unresolved", "budget_exceeded", "policy_excluded")
EVIDENCE_KINDS = ("finding", "closed_value", "guard", "none")
APPROVAL_STATES = ("valid", "needs_review", "invalid", "revoked", "resolved", "unobserved")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
CHECK_RESULTS = ("pass", "fail", "not_run", "unknown")


@dataclass(frozen=True)
class Problem:
    code: str
    message: str
    where: str = ""

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}" + (f" ({self.where})" if self.where else "")


@dataclass
class Verification:
    """검증 결과. `undeterminable`이면 확인 자체를 하지 못한 것이며 통과가 아니다."""

    problems: list[Problem] = field(default_factory=list)
    checked: int = 0
    undeterminable: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems and not self.undeterminable


class _Collector:
    def __init__(self) -> None:
        self.result = Verification()

    def check(self, condition: bool, code: str, message: str, where: str = "") -> bool:
        self.result.checked += 1
        if not condition:
            self.result.problems.append(Problem(code, message, where))
        return condition


def _digest_of(parts: dict[str, str]) -> str:
    return hashlib.sha256("|".join(f"{k}={parts[k]}" for k in sorted(parts)).encode()).hexdigest()[:12]


def _normalized(path: str) -> bool:
    """저장소 상대 경로이고 정규형(절대 경로·`..`·역슬래시 없음)인지"""
    if not path or "\\" in path or path.startswith(("/", "~")) or (len(path) > 1 and path[1] == ":"):
        return False
    parts = PurePosixPath(path).parts
    return ".." not in parts and "." not in parts and path == "/".join(parts)


def _parse_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:  # iron-laws: ignore[IL-301] 날짜가 아니면 None으로 알리고, 호출부가 `approval.expiry_invalid` 문제로 기록한다
        return None


def finding_id_of(violation: dict[str, Any]) -> str:
    """보고서의 지적 필드에서 finding_id를 다시 계산한다(생산자의 계산 함수를 부르지 않는다)."""
    key = f"{violation.get('rule_id')}|{violation.get('file_path')}|{violation.get('line_number')}|{violation.get('column', 1)}|{violation.get('fingerprint')}"
    return "F-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def code_digest_of(files: list[tuple[str, str]]) -> str:
    """(경로, 본문)에서 코드 지문을 계산한다. 알고리즘은 보고서 형식 문서에 고정되어 있다."""
    h = hashlib.sha256()
    for path, text in sorted(files):
        h.update(path.encode())
        h.update(hashlib.sha256(text.encode()).digest())
    return h.hexdigest()[:16]


def verify_report(data: dict[str, Any], *, as_of: date | None = None, checkout: Path | None = None) -> Verification:
    """점검 보고서(JSON을 읽은 dict)의 불변식을 확인한다.
    as_of: 승인 만료 판단 기준일(기본 오늘). checkout: 다른 checkout 폴더. 주면 코드 지문을 다시 계산해 대조한다."""
    c = _Collector()
    as_of = as_of or date.today()
    version = data.get("schema_version")
    if version not in SUPPORTED_REPORT_VERSIONS:
        c.result.undeterminable = True
        c.result.problems.append(
            Problem("schema.unsupported", f"지원하지 않는 보고서 형식 버전입니다: {version!r} (지원: {', '.join(SUPPORTED_REPORT_VERSIONS)}). `evidence upgrade`로 옮기거나 다시 점검하십시오")
        )
        return c.result
    ledger = data.get("coverage_ledger")
    execution = data.get("execution")
    summary = data.get("summary") or {}
    if not isinstance(ledger, dict) or not isinstance(execution, dict):
        c.result.undeterminable = True
        c.result.problems.append(Problem("schema.missing", "coverage_ledger 또는 execution이 없어 근거를 확인할 수 없습니다(누락을 통과로 보지 않습니다)"))
        return c.result

    violations = data.get("violations") or []
    findings = _check_findings(c, violations)
    scope = (data.get("metadata") or {}).get("scope") or {}
    # 변경 파일만 표시하는 점검(changed-since)에서는 변경되지 않은 파일의 지적이 목록에 없다. 그 파일 경로를 알려 주는 경우에만 허용한다.
    hidden_paths = None if scope.get("mode") != "changed-since" else set(scope.get("changed_paths") or [])
    _check_execution(c, data, execution, ledger, summary)
    _check_ledger(c, ledger, findings, hidden_paths)
    _check_passed(c, data, summary, ledger, violations, execution)
    _check_approvals(c, data, ledger, execution, findings, violations, as_of)
    if checkout is not None:
        _check_checkout(c, ledger, execution, checkout)
    return c.result


def _check_findings(c: _Collector, violations: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    for index, v in enumerate(violations):
        where = f"violations[{index}]"
        fid = v.get("finding_id")
        c.check(bool(fid), "finding.id_missing", "지적에 finding_id가 없다", where)
        c.check(fid not in findings, "finding.id_duplicate", f"finding_id가 중복된다: {fid}", where)
        c.check(not fid or fid == finding_id_of(v), "finding.id_mismatch", "finding_id가 규칙·경로·위치·지문과 맞지 않는다(내용이 바뀌었거나 다른 실행의 지적)", where)
        c.check(_normalized(str(v.get("file_path", ""))), "finding.path_not_normalized", f"경로가 저장소 상대 정규형이 아니다: {v.get('file_path')!r}", where)
        c.check(isinstance(v.get("line_number"), int) and v["line_number"] >= 1, "finding.line_invalid", "줄 번호가 올바르지 않다", where)
        if fid:
            findings[fid] = v
    return findings


def _check_execution(c: _Collector, data: dict[str, Any], execution: dict[str, Any], ledger: dict[str, Any], summary: dict[str, Any]) -> None:
    metadata = data.get("metadata") or {}
    c.check(execution.get("run_id") == ledger.get("run_id"), "run.id_mismatch", "execution.run_id와 장부의 run_id가 다르다(다른 실행의 근거)")
    expected_run = "R-" + _digest_of(ledger.get("digests") or {})
    c.check(ledger.get("run_id") == expected_run, "run.id_not_derived", f"run_id가 지문 묶음에서 나온 값이 아니다(기대 {expected_run})")
    digests = ledger.get("digests") or {}
    c.check(execution.get("code_digest") == digests.get("code"), "run.code_digest_mismatch", "execution과 장부의 코드 지문이 다르다")
    c.check(execution.get("contract_digest") == ledger.get("contract_digest"), "run.contract_digest_mismatch", "execution과 장부의 계약 지문이 다르다")
    c.check(execution.get("config_hash") == (metadata.get("config_hash")), "run.config_mismatch", "execution과 metadata의 설정 지문이 다르다")
    c.check(execution.get("scan_status") == summary.get("scan_status"), "run.status_mismatch", "execution과 summary의 점검 상태가 다르다")
    c.check(summary.get("contract_status") == ledger.get("status"), "run.contract_status_mismatch", "summary.contract_status와 장부 상태가 다르다")
    errors = [d for d in data.get("diagnostics") or [] if d.get("severity") == "error"]
    c.check(execution.get("error_diagnostics") == len(errors), "run.error_count_mismatch", "execution의 오류 진단 수와 진단 목록이 다르다")
    scanned = execution.get("files_scanned", 0)
    c.check(summary.get("total_files_scanned") == scanned, "run.files_mismatch", "점검한 파일 수가 summary와 execution에서 다르다")
    status = summary.get("scan_status")
    if scanned == 0:
        c.check(status == "empty", "run.empty_not_marked", "점검한 파일이 없는데 점검 상태가 empty가 아니다")
    elif errors:
        c.check(status == "incomplete", "run.incomplete_not_marked", "오류 진단이 있는데 점검 상태가 incomplete가 아니다")
    else:
        c.check(status == "complete", "run.complete_expected", f"오류 없이 점검했는데 점검 상태가 {status!r}이다")


def _check_ledger(c: _Collector, ledger: dict[str, Any], findings: dict[str, dict[str, Any]], changed_paths: set[str] | None = None) -> None:
    points = ledger.get("points") or []
    files = {f.get("path"): f for f in ledger.get("files") or []}
    seen: set[str] = set()
    for index, p in enumerate(points):
        where = f"coverage_ledger.points[{index}]"
        pid = p.get("id")
        c.check(pid not in seen, "point.id_duplicate", f"관심 지점 id가 중복된다: {pid}", where)
        seen.add(pid)
        state, kind, ids = p.get("state"), p.get("evidence_kind"), p.get("finding_ids") or []
        c.check(state in POINT_STATES, "point.state_unknown", f"알 수 없는 상태: {state!r}", where)
        c.check(kind in EVIDENCE_KINDS, "point.kind_unknown", f"알 수 없는 근거 종류: {kind!r}", where)
        c.check(bool(p.get("finding")) == bool(ids), "point.finding_flag", "finding 표시와 finding_ids가 맞지 않는다(지적 없이 지적 표시, 또는 그 반대)", where)
        file_entry = files.get(p.get("path"))
        c.check(file_entry is not None and file_entry.get("classification") in ("analyzed", "policy_excluded"), "point.file_not_analyzed", f"분석 대상 파일 목록에 없는 파일의 지점이다: {p.get('path')}", where)
        rule = FAMILY_RULE.get(p.get("family", ""))
        c.check(rule is not None, "point.family_unknown", f"알 수 없는 검사 계열: {p.get('family')!r}", where)
        for fid in ids:
            target = findings.get(fid)
            if target is None and changed_paths is not None and p.get("path") not in changed_paths:
                continue  # 변경 범위 밖의 파일이라 표시 목록에서 빠진 지적
            if not c.check(target is not None, "point.finding_missing", f"존재하지 않는 지적을 가리킨다: {fid}", where):
                continue
            c.check(target.get("file_path") == p.get("path") and target.get("line_number") == p.get("line"), "point.finding_elsewhere", "다른 파일·다른 줄의 지적을 연결했다", where)
            c.check(target.get("rule_id") == rule, "point.finding_wrong_rule", f"{p.get('family')} 계열 지점에 다른 규칙({target.get('rule_id')})의 지적을 연결했다", where)
            c.check(target.get("confidence") in (None, "CONFIRMED"), "point.finding_not_confirmed", "확정되지 않은 지적을 근거로 삼았다", where)
        if state == "evidence_met":
            c.check(kind in ("finding", "closed_value", "guard"), "point.met_without_evidence", "근거 종류 없이 '근거 충족'이다", where)
            c.check((kind == "finding") == bool(ids), "point.kind_ids_mismatch", "근거 종류(finding)와 finding_ids가 맞지 않는다", where)
        else:
            c.check(kind == "none", "point.unmet_with_kind", f"{state} 상태인데 근거 종류가 {kind!r}이다", where)
            if state != "policy_excluded":
                c.check(not ids, "point.unmet_with_ids", f"{state} 상태인데 지적이 연결되어 있다", where)
        if state == "policy_excluded":
            suppressed = p.get("suppressed_rules") or []
            by_file_policy = file_entry is not None and file_entry.get("classification") == "policy_excluded"
            c.check(by_file_policy or bool(suppressed), "point.excluded_unexplained", "정책 제외인데 억제 규칙도, 제외된 파일도 아니다", where)
            if suppressed and rule is not None:
                c.check(set(suppressed) <= {rule}, "point.suppression_too_wide", f"{p.get('family')} 계열 지점에 다른 규칙({suppressed})의 억제가 적용되었다", where)

    requirements = ledger.get("requirements") or {}
    expected_blockers: list[str] = []
    for family, requirement in requirements.items():
        tally = next((t for t in ledger.get("families") or [] if t.get("family") == family), None)
        family_points = [p for p in points if p.get("family") == family]
        scoped = [p for p in family_points if p.get("in_scope", True)]
        if c.check(tally is not None, "tally.missing", f"{family} 계열의 집계가 없다"):
            c.check(tally.get("total") == len(family_points), "tally.total", f"{family} 계열 지점 수가 집계와 다르다")
            c.check(tally.get("in_scope") == len(scoped), "tally.in_scope", f"{family} 계열의 범위 안 지점 수가 집계와 다르다")
            by_state: dict[str, int] = {}
            for p in scoped:
                by_state[p.get("state")] = by_state.get(p.get("state"), 0) + 1
            c.check((tally.get("by_state") or {}) == by_state, "tally.by_state", f"{family} 계열의 상태별 집계가 지점 목록과 다르다")
        if requirement.get("required", True):
            blocking = set(requirement.get("block_on") or [])
            expected_blockers += [f"[{family}] {p['path']}:{p['line']} " for p in scoped if p.get("state") in blocking]
    blockers = ledger.get("blockers") or []
    point_blockers = [b for b in blockers if b.startswith("[") and not b.startswith(("[정책 변경]", "[분류 불가 변경 파일]"))]
    for prefix in expected_blockers:
        c.check(any(b.startswith(prefix) for b in point_blockers), "ledger.blocker_missing", f"필수 계열의 차단 상태 지점이 차단 사유에 없다: {prefix.strip()}")
    c.check(len(point_blockers) == len(expected_blockers), "ledger.blocker_extra", "차단 사유 수가 필수 계열의 차단 상태 지점 수와 다르다")
    unclassified_changed = sorted(f["path"] for f in files.values() if f.get("classification") == "unclassified" and f.get("changed"))
    c.check(sorted(ledger.get("unclassified_changed_files") or []) == unclassified_changed, "ledger.unclassified_mismatch", "분류하지 못한 변경 파일 목록이 파일 분류와 다르다")
    for path in unclassified_changed:
        c.check(any(b.startswith("[분류 불가 변경 파일]") and path in b for b in blockers), "ledger.unclassified_not_blocked", f"점검하지 못한 변경 파일이 차단 사유에 없다: {path}")
    analyzed = [f for f in files.values() if f.get("classification") in ("analyzed", "policy_excluded")]
    policy_change = any(b.startswith("[정책 변경]") for b in blockers)
    expected_status = "policy_change_review" if policy_change else "unmet" if blockers else "not_applicable" if not analyzed else "met"
    c.check(ledger.get("status") == expected_status, "ledger.status_mismatch", f"장부 상태 {ledger.get('status')!r}가 차단 사유·분석 파일에서 계산한 {expected_status!r}와 다르다(비적용·충족이 차단 사유를 가렸는지 확인)")


def _check_passed(c: _Collector, data: dict[str, Any], summary: dict[str, Any], ledger: dict[str, Any], violations: list[dict[str, Any]], execution: dict[str, Any]) -> None:
    metadata = data.get("metadata") or {}
    config = metadata.get("config") or {}
    threshold = SEVERITY_RANK.get(str(config.get("fail_on", "HIGH")).upper(), 3)
    has_baseline = "baseline" in metadata
    counted = [v for v in violations if (not has_baseline or v.get("baseline_status") in ("new", "review")) and v.get("approval_status") != "approved"]
    blocked_by_findings = any(SEVERITY_RANK.get(v.get("severity", ""), 0) >= threshold for v in counted)
    passed = bool(summary.get("is_passed"))
    status = summary.get("scan_status")
    if status != "complete":
        c.check(not passed, "pass.incomplete_passed", "점검이 끝까지 이루어지지 않았는데 통과로 표시되었다")
        return
    if summary.get("contract_mode") == "block" and ledger.get("status") in ("unmet", "policy_change_review"):
        c.check(not passed, "pass.contract_unmet_passed", "차단 모드의 근거 계약이 미충족인데 통과로 표시되었다")
        return
    c.check(passed == (not blocked_by_findings), "pass.unexplained", "통과 표시가 실패 기준 이상의 지적 유무와 맞지 않는다(설명할 수 없는 통과 또는 실패)")
    counts = {sev: sum(1 for v in violations if v.get("severity") == sev) for sev in SEVERITY_RANK}
    c.check(summary.get("total_violations") == len(violations), "summary.total_mismatch", "지적 총수가 목록과 다르다")
    for sev, key in (("CRITICAL", "critical_count"), ("HIGH", "high_count"), ("MEDIUM", "medium_count"), ("LOW", "low_count")):
        c.check(summary.get(key) == counts[sev], "summary.severity_mismatch", f"{sev} 지적 수가 목록과 다르다")


def _check_approvals(
    c: _Collector,
    data: dict[str, Any],
    ledger: dict[str, Any],
    execution: dict[str, Any],
    findings: dict[str, dict[str, Any]],
    violations: list[dict[str, Any]],
    as_of: date,
) -> None:
    checks = data.get("approval_checks") or []
    scope = (data.get("metadata") or {}).get("scope") or {}
    scoped = scope.get("mode") == "changed-since"
    changed_paths = set(scope.get("changed_paths") or [])
    analyzed_paths = {f.get("path") for f in ledger.get("files") or [] if f.get("classification") != "unclassified"}
    valid_by_finding: dict[str, str] = {}
    for index, a in enumerate(checks):
        where = f"approval_checks[{index}]"
        status = a.get("status")
        c.check(status in APPROVAL_STATES, "approval.state_unknown", f"알 수 없는 승인 상태: {status!r}", where)
        if status != "valid":
            continue
        fid = a.get("finding_id")
        target = findings.get(fid) if fid else None
        if scoped and a.get("path") not in changed_paths:
            continue  # 변경 범위 밖의 지적이라 보고서에 없다(경로가 변경 목록에 있으면 지적이 있어야 한다)
        if not c.check(target is not None, "approval.valid_without_finding", "유효 승인이 이번 실행의 지적을 가리키지 않는다(과거·다른 실행의 승인 재사용)", where):
            continue
        c.check(target.get("rule_id") == a.get("rule_id"), "approval.valid_other_rule", "유효 승인의 규칙이 현재 지적의 규칙과 다르다", where)
        if target.get("file_path") == a.get("path"):
            c.check(target.get("fingerprint") == a.get("approved_fingerprint"), "approval.valid_fingerprint_differs", "유효 승인의 지문이 현재 지적과 다르다(승인한 코드가 바뀌었다)", where)
        else:
            # 파일이 옮겨진 경우에만 경로가 달라도 승계된다. 승인한 경로가 지금도 점검 대상이면 복제본이 승인을 물려받은 것이다.
            c.check(a.get("path") not in analyzed_paths, "approval.valid_clone_inherited", "승인한 원본 파일이 그대로 있는데 다른 파일의 지적이 그 승인을 물려받았다(복제본의 승계)", where)
        c.check(target.get("approval_status") == "approved" and target.get("approval_id") == a.get("approval_id"), "approval.valid_not_applied", "유효 승인이 지적의 승인 표시와 맞지 않는다", where)
        expires = a.get("expires")
        if expires is not None:
            parsed = _parse_date(expires)
            c.check(parsed is not None, "approval.expiry_invalid", f"유효 승인의 유효기간이 날짜가 아니다: {expires!r}", where)
            if parsed is not None:
                c.check(parsed >= as_of, "approval.valid_expired", f"유효기간({expires})이 지난 승인이 유효로 표시되었다", where)
        policy = a.get("policy") or {}
        if policy.get("contract_digest"):
            c.check(policy["contract_digest"] == ledger.get("contract_digest"), "approval.valid_other_contract", "유효 승인의 계약 지문이 이번 실행의 계약과 다르다", where)
        if policy.get("config_hash"):
            c.check(policy["config_hash"] == execution.get("config_hash"), "approval.valid_other_config", "유효 승인의 설정 지문이 이번 실행의 설정과 다르다", where)
        c.check(fid not in valid_by_finding, "approval.valid_duplicate", "한 지적에 유효 승인이 둘 이상이다", where)
        valid_by_finding[fid] = a.get("approval_id", "")
    for v in violations:
        if v.get("approval_status") == "approved":
            c.check(v.get("finding_id") in valid_by_finding, "approval.approved_without_valid_row", "승인된 지적에 대응하는 유효 승인 판정이 없다", v.get("finding_id", ""))


def _check_checkout(c: _Collector, ledger: dict[str, Any], execution: dict[str, Any], checkout: Path) -> None:
    files = [f for f in ledger.get("files") or [] if f.get("classification") != "unclassified"]
    loaded: list[tuple[str, str]] = []
    missing: list[str] = []
    for f in files:
        path = checkout / f["path"]
        try:
            raw = path.read_bytes()
        except OSError:
            missing.append(f["path"])
            continue
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            c.result.notes.append(f"UTF-8이 아닌 파일이라 코드 지문을 다시 계산할 수 없다: {f['path']}")
            c.result.undeterminable = True
            return
        loaded.append((f["path"], text))
    if not c.check(not missing, "snapshot.files_missing", f"보고서가 점검했다고 한 파일이 이 checkout에 없다: {', '.join(missing[:3])}"):
        return
    c.check(code_digest_of(loaded) == execution.get("code_digest"), "snapshot.code_mismatch", "이 checkout의 코드가 보고서가 점검한 코드와 다르다(다른 코드의 근거)")


# ---------------------------------------------------------------------------
# 검증 기록(Receipt)
# ---------------------------------------------------------------------------


def verify_receipt(data: dict[str, Any], *, report: dict[str, Any] | None = None) -> Verification:
    """검증 기록의 봉인·판정 도출·항목 일관성을 확인한다. 점검 보고서를 함께 주면 같은 실행의 근거인지도 대조한다."""
    c = _Collector()
    version = data.get("schema_version")
    if version not in SUPPORTED_RECEIPT_VERSIONS:
        c.result.undeterminable = True
        c.result.problems.append(Problem("receipt.schema_unsupported", f"지원하지 않는 검증 기록 버전입니다: {version!r}"))
        return c.result
    body = {k: v for k, v in data.items() if k != "receipt_digest"}
    sealed = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
    c.check(sealed == data.get("receipt_digest"), "receipt.seal_mismatch", "기록의 내용 해시가 맞지 않는다(내용이 바뀌었다)")
    checks = data.get("checks") or []
    ids = [x.get("id") for x in checks]
    c.check(len(ids) == len(set(ids)), "receipt.check_duplicate", "검사 항목 id가 중복된다")
    for x in checks:
        where = str(x.get("id"))
        c.check(x.get("result") in CHECK_RESULTS, "receipt.result_unknown", f"알 수 없는 결과: {x.get('result')!r}", where)
        if x.get("result") == "pass":
            c.check(x.get("executed", True), "receipt.pass_not_executed", "실행하지 않은 항목이 통과로 표시되었다", where)
            c.check(not x.get("limit_reached", False), "receipt.pass_limit_reached", "상한에 도달한 항목이 통과로 표시되었다", where)
    required = [x for x in checks if x.get("required", True)]
    failed = [x for x in required if x.get("result") == "fail"]
    open_items = [x for x in required if x.get("result") in ("not_run", "unknown")]
    expected = "failed" if failed else "undeterminable" if open_items else "verified"
    verdict = data.get("verdict") or {}
    c.check(verdict.get("overall") == expected, "receipt.verdict_mismatch", f"종합 판정 {verdict.get('overall')!r}이 필수 항목 결과에서 계산한 {expected!r}와 다르다")
    target_check = next((x for x in checks if x.get("id") == "target_resolved"), None)
    target = data.get("target")
    if target_check is not None and target_check.get("executed", True):
        c.check(target is not None, "receipt.target_missing", "대상 지적 해소 항목을 실행했는데 대상 정보가 없다")
    evidence = data.get("evidence") or {}
    original = evidence.get("original") or {}
    candidate = evidence.get("candidate") or {}
    if target_check is not None and target_check.get("result") == "pass" and target:
        c.check(
            target.get("fingerprint") not in (candidate.get("fingerprints") or []),
            "receipt.target_still_present",
            "대상 지적 해소가 통과인데 후보에도 같은 지문의 지적이 있다",
        )
        c.check(target.get("finding_id") in (original.get("finding_ids") or []), "receipt.target_not_in_original", "대상 지적이 원본 점검의 지적 목록에 없다")
    if original and candidate:
        digests = data.get("digests") or {}
        c.check(bool(original.get("run_id")) and bool(candidate.get("run_id")), "receipt.run_missing", "원본·후보 점검의 실행 식별자가 없다")
        if original.get("code_digest") and original.get("code_digest") == candidate.get("code_digest"):
            c.check(bool(data.get("bypass_changes") or []) or not data.get("inputs", {}).get("patch_changes", True), "receipt.identical_code", "원본과 후보의 코드 지문이 같다(변경 없는 패치)")
        del digests
    if report is not None:
        execution = report.get("execution") or {}
        run_ids = {original.get("run_id"), candidate.get("run_id")}
        c.check(execution.get("run_id") in run_ids, "receipt.other_run", "함께 준 점검 보고서가 이 기록의 원본·후보 실행이 아니다")
    return c.result


# ---------------------------------------------------------------------------
# 이전 형식 기록 옮기기
# ---------------------------------------------------------------------------

UNRESTORABLE_LIMIT = 0.20


@dataclass
class Upgrade:
    ok: bool
    data: dict[str, Any] | None
    restored: int
    unrestorable: int
    reasons: list[str] = field(default_factory=list)


def upgrade_report(data: dict[str, Any], *, limit: float = UNRESTORABLE_LIMIT) -> Upgrade:
    """1.2 보고서를 1.3 형식으로 옮긴다. 근거를 복원할 수 없는 장부 지점이 limit(기본 20%) 이상이면 옮기지 않고 명시적 재검토(다시 점검)로 넘긴다(limit 1.0은 한도 없음).
    복원할 수 있는 것: 같은 줄·같은 규칙의 확정 지적이 보고서에 있는 지점(finding_ids), 지적이 없고 근거 충족이 아닌 지점.
    복원할 수 없는 것: 지적 없이 '근거 충족'이던 지점(닫힌 값인지 규칙이 인정한 안전 조건인지 이 형식에서는 구별할 수 없다)."""
    if data.get("schema_version") not in ("1.2", "1.1", "1.0"):
        return Upgrade(False, None, 0, 0, [f"옮길 수 없는 형식 버전입니다: {data.get('schema_version')!r}"])
    ledger = data.get("coverage_ledger")
    if not isinstance(ledger, dict):
        return Upgrade(False, None, 0, 0, ["장부가 없는 보고서는 근거를 복원할 수 없다. 다시 점검하십시오"])
    violations = data.get("violations") or []
    for v in violations:
        v["finding_id"] = finding_id_of(v)
    by_location: dict[tuple[str, str, int], list[str]] = {}
    for v in violations:
        if v.get("confidence") in (None, "CONFIRMED"):
            by_location.setdefault((v["rule_id"], v["file_path"], v["line_number"]), []).append(v["finding_id"])
    restored = unrestorable = 0
    reasons: list[str] = []
    for p in ledger.get("points") or []:
        ids = by_location.get((FAMILY_RULE.get(p.get("family", ""), ""), p.get("path"), p.get("line")), [])
        if p.get("state") == "evidence_met":
            if ids:
                p["finding_ids"], p["finding"], p["evidence_kind"] = ids, True, "finding"
                restored += 1
            else:
                p["finding_ids"], p["finding"], p["evidence_kind"] = [], False, "none"
                unrestorable += 1
                reasons.append(f"{p.get('path')}:{p.get('line')} — 지적 없이 '근거 충족'이던 지점의 근거 종류를 복원할 수 없다")
        else:
            p["finding_ids"], p["finding"], p["evidence_kind"] = [], False, "none"
            p.setdefault("suppressed_rules", [])
            restored += 1
    total = restored + unrestorable
    if total and limit < 1.0 and unrestorable / total >= limit:
        return Upgrade(False, None, restored, unrestorable, [f"근거를 복원할 수 없는 지점이 {unrestorable}/{total}({unrestorable / total:.0%})로 한도({limit:.0%}) 이상이다. 자동으로 옮기지 않고 다시 점검하십시오", *reasons[:5]])
    ledger.setdefault("requirements", {})
    ledger.setdefault("run_id", "")
    data["schema_version"] = "1.3"
    data.setdefault("approval_checks", [])
    data.setdefault("execution", None)
    return Upgrade(True, data, restored, unrestorable, reasons[:5])


def load_json(path: Path) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"JSON을 읽을 수 없습니다: {path} ({e})") from e
    if not isinstance(loaded, dict):
        raise ValueError(f"최상위 구조가 객체가 아닙니다: {path}")
    return loaded


__all__ = [
    "Problem",
    "Upgrade",
    "Verification",
    "finding_id_of",
    "code_digest_of",
    "load_json",
    "upgrade_report",
    "verify_receipt",
    "verify_report",
]

