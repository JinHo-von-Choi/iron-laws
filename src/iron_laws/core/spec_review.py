"""
사용자 명세가 이 저장소의 탐지를 줄이는지 비교한다.

명세는 프로젝트 고유의 소스·싱크·정제 함수를 더한다. 소스와 싱크를 더하면 지적은 늘어난다.
탐지를 줄일 수 있는 길은 정제 함수 선언뿐이다. 정제 함수 정규식이 넓으면 여러 흐름이 한꺼번에
안전하다고 판정되어 이미 보고되던 지적이 사라진다. 어디에 닿았는지와 무엇이 줄었는지를 밝히지
않으면 '탐지가 줄었다'는 사실이 조용히 사라진다.

비교는 같은 조건에서 두 번 돌린 결과의 차이다. 사람이 읽은 판정이나 언어 모델의 견해가 아니라
결정론적 스캔만으로 판단한다. 줄어든 지적은 '선언한 정제 함수 때문'과 '그 밖의 이유'로 갈라 밝힌다.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.config import IronLawsConfig, load_config
from iron_laws.core.contract import Contract, default_contract
from iron_laws.core.custom_spec import FAMILY_RULE, LoadedSpec, read_spec
from iron_laws.core.models import AuditReport, InterestPoint, Violation

RULE_FAMILY = {rule_id: family for family, rule_id in FAMILY_RULE.items()}
GAP_STATES = ("unsupported", "unresolved", "budget_exceeded")
REVIEW_STATES = ("unresolved", "policy_excluded")

VERDICT_OK = "ok"
VERDICT_REVIEW = "review"
VERDICT_BLOCKED = "blocked"


@dataclass
class SpecReview:
    """명세 한 개의 대조 결과."""

    root: str
    spec_path: str
    spec_digest: str
    verdict: str = VERDICT_OK
    blocking: list[str] = field(default_factory=list)
    review: list[str] = field(default_factory=list)
    lost_findings: list[dict] = field(default_factory=list)
    new_findings: list[dict] = field(default_factory=list)
    point_transitions: list[dict] = field(default_factory=list)
    gap_delta: dict[str, dict[str, int]] = field(default_factory=dict)
    new_points: dict[str, int] = field(default_factory=dict)
    reference_counts: dict[str, int] = field(default_factory=dict)
    candidate_counts: dict[str, int] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "spec_path": self.spec_path,
            "spec_digest": self.spec_digest,
            "verdict": self.verdict,
            "blocking": list(self.blocking),
            "review": list(self.review),
            "lost_findings": list(self.lost_findings),
            "new_findings": list(self.new_findings),
            "point_transitions": list(self.point_transitions),
            "gap_delta": {k: dict(v) for k, v in self.gap_delta.items()},
            "new_points": dict(self.new_points),
            "reference_counts": dict(self.reference_counts),
            "candidate_counts": dict(self.candidate_counts),
            "limitations": list(self.limitations),
        }


def _shape_of(violation: Violation) -> str:
    return violation.shape or re.sub(r"\s+", " ", violation.snippet).strip()


def _finding_key(violation: Violation) -> tuple[str, str, str, str]:
    """줄 번호와 출현 순번을 빼고 (규칙, 경로, 함수, 코드 모양)으로 묶는다. 줄이 밀려도 같은 지적으로 본다."""
    return (violation.rule_id, violation.file_path.as_posix(), violation.scope_name, _shape_of(violation))


def _confirmed(report: AuditReport) -> dict[tuple[str, str, str, str], Violation]:
    return {_finding_key(v): v for v in report.violations if v.confidence.value == "CONFIRMED"}


def _points(report: AuditReport) -> dict[str, InterestPoint]:
    ledger = report.coverage_ledger
    return {p.id: p for p in (ledger.points if ledger else [])}


def _gap_counts(report: AuditReport) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for point in _points(report).values():
        if point.state not in GAP_STATES:
            continue
        counts.setdefault(point.family, {})
        counts[point.family][point.state] = counts[point.family].get(point.state, 0) + 1
    return counts


def _counts(report: AuditReport) -> dict[str, int]:
    points = list(_points(report).values())
    return {
        "violations": len(report.violations),
        "confirmed": sum(1 for v in report.violations if v.confidence.value == "CONFIRMED"),
        "review": sum(1 for v in report.violations if v.confidence.value != "CONFIRMED"),
        "points": len(points),
        "gaps": sum(1 for p in points if p.state in GAP_STATES),
    }


def _scan(root: Path, config: IronLawsConfig, contract: Contract, contract_source: str) -> AuditReport:
    from iron_laws.core.scanner import AuditScanner

    # 명세 상태는 프로세스 전역이라 두 스캔을 겹쳐 돌릴 수 없다. 순차로 돌린다.
    return AuditScanner(root, config=config, contract=contract, contract_source=contract_source).scan()


def _sanitizer_ids(loaded: LoadedSpec, family: str | None) -> list[str]:
    if family is None:
        return []
    return [f"sanitizers.{e.id}" for e in loaded.spec.sanitizers if e.family == family]


def review_spec(
    root: Path,
    spec: Path,
    config_path: Path | None = None,
    search_parents: bool = False,
    contract: Contract | None = None,
    contract_source: str = "기본값",
) -> SpecReview:
    """명세를 적용하지 않은 점검과 적용한 점검을 같은 조건으로 두 번 돌려 비교한다."""
    root = Path(root)
    loaded = read_spec(Path(spec))
    base, _source = load_config(root, config_path, search_parents)
    used_contract = contract or default_contract()

    reference_config = base.model_copy(deep=True)
    reference_config.policies.custom_spec = None
    candidate_config = base.model_copy(deep=True)
    candidate_config.policies.custom_spec = str(Path(spec))

    reference = _scan(root, reference_config, used_contract, contract_source)
    candidate = _scan(root, candidate_config, used_contract, contract_source)

    result = SpecReview(root=str(root), spec_path=str(spec), spec_digest=loaded.digest[:16])
    result.reference_counts = _counts(reference)
    result.candidate_counts = _counts(candidate)

    _compare_findings(result, reference, candidate, loaded)
    _compare_points(result, reference, candidate)
    _compare_gaps(result, reference, candidate)
    _check_completeness(result, reference, candidate)
    _add_limitations(result, loaded, used_contract)

    if result.blocking:
        result.verdict = VERDICT_BLOCKED
    elif result.review:
        result.verdict = VERDICT_REVIEW
    else:
        result.verdict = VERDICT_OK
    return result


def _compare_findings(result: SpecReview, reference: AuditReport, candidate: AuditReport, spec: LoadedSpec) -> None:
    before = _confirmed(reference)
    after = _confirmed(candidate)
    for key, violation in before.items():
        if key in after:
            continue
        family = RULE_FAMILY.get(violation.rule_id)
        cause = _sanitizer_ids(spec, family)
        entry = {
            "rule_id": violation.rule_id,
            "path": violation.file_path.as_posix(),
            "line": violation.line_number,
            "scope": violation.scope_name,
            "family": family or "",
            "message": violation.message,
            "cause": cause,
        }
        result.lost_findings.append(entry)
        where = f"{violation.rule_id} {violation.file_path.as_posix()}:{violation.line_number}"
        if cause:
            result.review.append(
                f"{where} — 선언한 정제 함수({', '.join(cause)}) 때문에 사라진 지적입니다. "
                "그 정제 함수가 값을 실제로 안전하게 바꾸는지 확인하십시오."
            )
        else:
            result.blocking.append(f"{where} — 선언하지 않은 이유로 사라진 지적입니다. 명세를 적용하기 전에 확인하십시오.")
    for key, violation in after.items():
        if key in before:
            continue
        result.new_findings.append(
            {
                "rule_id": violation.rule_id,
                "path": violation.file_path.as_posix(),
                "line": violation.line_number,
                "scope": violation.scope_name,
                "message": violation.message,
            }
        )


def _compare_points(result: SpecReview, reference: AuditReport, candidate: AuditReport) -> None:
    before = _points(reference)
    after = _points(candidate)
    for point_id, point in before.items():
        if point.state != "evidence_met":
            continue
        counterpart = after.get(point_id)
        if counterpart is None:
            result.point_transitions.append(
                {
                    "point": point_id,
                    "family": point.family,
                    "path": point.path,
                    "line": point.line,
                    "callee": point.callee,
                    "before": point.state,
                    "after": "(지점이 사라짐)",
                    "severity": "blocking",
                }
            )
            result.blocking.append(
                f"[{point.family}] {point.path}:{point.line} {point.callee}() — 근거를 확보하던 지점이 사라졌습니다."
            )
            continue
        if counterpart.state == "evidence_met":
            if counterpart.evidence_kind != point.evidence_kind:
                result.point_transitions.append(
                    {
                        "point": point_id,
                        "family": point.family,
                        "path": point.path,
                        "line": point.line,
                        "callee": point.callee,
                        "before": point.evidence_kind,
                        "after": counterpart.evidence_kind,
                        "severity": "review",
                    }
                )
                if counterpart.evidence_kind == "declared_sanitizer":
                    result.review.append(
                        f"[{point.family}] {point.path}:{point.line} {point.callee}() — 근거가 지적({point.evidence_kind})에서 "
                        f"사용자 선언({counterpart.evidence_kind})으로 바뀌었습니다: {counterpart.reason}"
                    )
            continue
        severity = "review" if counterpart.state in REVIEW_STATES else "blocking"
        result.point_transitions.append(
            {
                "point": point_id,
                "family": point.family,
                "path": point.path,
                "line": point.line,
                "callee": point.callee,
                "before": point.state,
                "after": counterpart.state,
                "severity": severity,
            }
        )
        where = f"[{point.family}] {point.path}:{point.line} {point.callee}()"
        if severity == "review":
            result.review.append(f"{where} — 근거 상태가 {counterpart.state}(으)로 낮아졌습니다: {counterpart.reason}")
        else:
            result.blocking.append(f"{where} — 근거 상태가 {counterpart.state}(으)로 낮아졌습니다: {counterpart.reason}")
    for point_id, point in after.items():
        if point_id in before:
            continue
        result.new_points[point.state] = result.new_points.get(point.state, 0) + 1


def _compare_gaps(result: SpecReview, reference: AuditReport, candidate: AuditReport) -> None:
    before = _gap_counts(reference)
    after = _gap_counts(candidate)
    for family in sorted(set(before) | set(after)):
        result.gap_delta[family] = {
            "before": sum(before.get(family, {}).values()),
            "after": sum(after.get(family, {}).values()),
        }


def _check_completeness(result: SpecReview, reference: AuditReport, candidate: AuditReport) -> None:
    for label, report in (("기준", reference), ("후보", candidate)):
        if report.summary.scan_status == "complete":
            continue
        errors = [d.message for d in report.diagnostics if d.severity == "error"]
        detail = errors[0] if errors else f"scan_status={report.summary.scan_status}"
        result.blocking.append(f"{label} 점검이 끝까지 되지 않아 비교를 믿을 수 없습니다: {detail}")


def _add_limitations(result: SpecReview, spec: LoadedSpec, contract: Contract) -> None:
    result.limitations.append("이 비교는 지적과 검사 공백의 변화만 본다. 명세의 내용이 옳은지는 사람이 확인해야 합니다.")
    families = sorted(contract.families)
    result.limitations.append(f"검사 공백 대조 범위: 언어 {', '.join(contract.languages)} · 계열 {', '.join(families)}")
    ledger_families = {"command", "path", "sql"}
    entries = list(spec.spec.sources) + list(spec.spec.sinks) + list(spec.spec.sanitizers)
    outside = sorted({e.family for e in entries if e.family not in ledger_families})
    if outside:
        result.limitations.append(
            f"명세의 {', '.join(outside)} 계열 항목은 검사 공백 장부에 계열이 없어 대조하지 않았습니다."
        )
    contract_languages = set(contract.languages)
    other_languages = sorted({
        lang
        for e in entries
        for lang in e.languages
        if lang not in contract_languages
    })
    if other_languages:
        result.limitations.append(
            f"명세의 {', '.join(other_languages)} 언어 항목은 계약 언어가 {', '.join(sorted(contract_languages))}여서 검사 공백 대조에 들어가지 않았습니다."
        )


def render_markdown(result: SpecReview) -> str:
    label = {VERDICT_OK: "탐지 감소 없음", VERDICT_REVIEW: "확인 필요", VERDICT_BLOCKED: "채택 보류"}[result.verdict]
    lines = [
        "# 사용자 명세 대조 결과",
        "",
        f"- 명세: `{result.spec_path}` (지문 `{result.spec_digest}`)",
        f"- 대상: `{result.root}`",
        f"- 판정: **{label}**",
        "",
        "## 기준과 후보",
        "",
        "| 항목 | 기준 | 후보 |",
        "| --- | --- | --- |",
    ]
    for key in ("violations", "confirmed", "review", "points", "gaps"):
        lines.append(f"| {key} | {result.reference_counts.get(key, 0)} | {result.candidate_counts.get(key, 0)} |")
    if result.lost_findings:
        lines += ["", "## 사라진 지적", ""]
        for item in result.lost_findings:
            cause = f" — 원인 후보: {', '.join(item['cause'])}" if item["cause"] else ""
            lines.append(f"- `{item['rule_id']}` {item['path']}:{item['line']}{cause}")
    if result.new_findings:
        lines += ["", "## 새로 생긴 지적", ""]
        for item in result.new_findings:
            lines.append(f"- `{item['rule_id']}` {item['path']}:{item['line']}")
    if result.point_transitions:
        lines += ["", "## 근거 상태가 바뀐 지점", "", "| 계열 | 위치 | 호출 | 전 | 후 | 구분 |", "| --- | --- | --- | --- | --- | --- |"]
        for item in result.point_transitions:
            lines.append(
                f"| {item['family']} | {item['path']}:{item['line']} | `{item['callee']}()` | {item['before']} | {item['after']} | {item['severity']} |"
            )
    if result.gap_delta:
        lines += ["", "## 계열별 검사 공백", "", "| 계열 | 기준 | 후보 |", "| --- | --- | --- |"]
        for family, delta in result.gap_delta.items():
            lines.append(f"| {family} | {delta['before']} | {delta['after']} |")
    if result.blocking:
        lines += ["", "## 채택을 막는 사유", ""]
        lines += [f"- {item}" for item in result.blocking]
    if result.review:
        lines += ["", "## 확인할 사항", ""]
        lines += [f"- {item}" for item in result.review]
    if result.limitations:
        lines += ["", "## 한계", ""]
        lines += [f"- {item}" for item in result.limitations]
    return "\n".join(lines)
