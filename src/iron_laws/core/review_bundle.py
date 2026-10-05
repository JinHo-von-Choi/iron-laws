"""
오철칙 검토 묶음(Review Bundle): 변경이 어떤 승인 전제를 건드렸는지, 무엇을 다시 해야 하는지, 무엇이 아직 비어 있는지를
구조화된 근거에서 결정적으로 만든다. 자유로운 AI 요약은 판정 근거로 쓰지 않는다. 같은 입력이면 같은 묶음이 나온다.
- 승인은 유지 / 무효화(재검토) / 판정 불가로 나누고, 유지한 이유와 무효화한 이유를 모두 보여 준다.
- 호출 관계를 해석하지 못한 경계, 점검하지 못한 파일, 분석 한도는 '영향 없음'이 아니라 남은 공백과 넓힌 재검토 범위로 드러낸다.
- baseline의 지적은 사람의 승인으로 세지 않는다. 최소라는 말은 지원하는 의존 관계와 분석 한계 안에서 제안된 범위를 뜻한다.
작성자: 최진호
작성일: 2026-10-05
"""

from dataclasses import asdict, dataclass, field
from typing import Any

from iron_laws.core.approvals import ApprovalStatusRow
from iron_laws.core.models import AuditReport

DECISION_OF_STATUS = {
    "valid": "keep",
    "needs_review": "invalidate",
    "invalid": "invalidate",
    "unobserved": "undeterminable",
    "resolved": "resolved",
    "revoked": "revoked",
}
DECISION_LABEL = {
    "keep": "유지",
    "invalidate": "무효화(재검토)",
    "undeterminable": "판정 불가",
    "resolved": "해소됨",
    "revoked": "철회됨",
}
CAVEAT = "이 묶음의 '유지'는 기록된 전제가 지금도 같다는 뜻이며 코드가 안전하다는 뜻이 아닙니다. 범위는 지원하는 의존 관계와 분석 한계 안에서 제안된 것입니다."


@dataclass
class ApprovalDecision:
    approval_id: str
    rule_id: str
    location: str
    decision: str
    status: str
    why_changed: list[str] = field(default_factory=list)
    why_kept: list[str] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReviewBundle:
    run: dict[str, Any]
    changed_premises: list[dict[str, str]]
    approvals: list[ApprovalDecision]
    actions: list[dict[str, str]]
    gaps: list[dict[str, str]]
    reproduction: dict[str, Any]
    caveat: str = CAVEAT

    def counts(self) -> dict[str, int]:
        result = {"keep": 0, "invalidate": 0, "undeterminable": 0, "resolved": 0, "revoked": 0}
        for a in self.approvals:
            result[a.decision] += 1
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "iron-laws.review-bundle/1",
            "run": self.run,
            "counts": self.counts(),
            "changed_premises": self.changed_premises,
            "approvals": [asdict(a) for a in self.approvals],
            "actions": self.actions,
            "gaps": self.gaps,
            "reproduction": self.reproduction,
            "caveat": self.caveat,
        }


def _location(row: ApprovalStatusRow) -> str:
    finding = row.approval.record.finding
    if row.violation is not None:
        return f"{row.violation.file_path.as_posix()}:{row.violation.line_number}"
    return f"{finding.path}::{finding.scope_name}" if finding else ""


def build_bundle(
    report: AuditReport,
    rows: list[ApprovalStatusRow],
    *,
    changed_files: set[str] | None,
    command: str,
    approvals_path: str | None,
) -> ReviewBundle:
    execution = report.execution
    ledger = report.coverage_ledger
    run = {
        "run_id": execution.run_id if execution else "",
        "scan_status": report.summary.scan_status,
        "contract_status": report.summary.contract_status,
        "schema_version": report.schema_version,
        "tool_version": execution.tool_version if execution else "",
    }

    changed: list[dict[str, str]] = []
    for path in sorted(changed_files or []):
        changed.append({"kind": "file", "subject": path, "detail": "이번 변경에 포함된 파일"})
    current = {
        "contract_digest": execution.contract_digest if execution else "",
        "config_hash": execution.config_hash if execution else "",
        "ruleset_hash": execution.ruleset_hash if execution else "",
        "tool_version": execution.tool_version if execution else "",
    }
    policy_changes: dict[str, set[str]] = {}
    decisions: list[ApprovalDecision] = []
    for row in sorted(rows, key=lambda r: r.approval.id):
        record = row.approval.record
        finding = record.finding
        recorded = record.policy.model_dump() if record.policy else {}
        for key, label in (("contract_digest", "근거 계약"), ("config_hash", "점검 설정"), ("ruleset_hash", "규칙 집합"), ("tool_version", "도구 버전")):
            if recorded.get(key) and current[key] and recorded[key] != current[key]:
                policy_changes.setdefault(label, set()).add(row.approval.id)
        decision = DECISION_OF_STATUS.get(row.status, "undeterminable")
        boundaries = [p.detail for p in row.premises if p.key == "boundaries" and p.state == "unknown"]
        boundaries += [r for p in row.premises if p.key == "boundaries" and p.state == "changed" for r in p.reasons]
        decisions.append(
            ApprovalDecision(
                approval_id=row.approval.id,
                rule_id=finding.rule_id if finding else "",
                location=_location(row),
                decision=decision,
                status=row.status,
                why_changed=list(row.reasons) if decision != "keep" else [],
                why_kept=list(row.keep_reasons) if decision == "keep" else [],
                boundaries=boundaries,
                evidence={
                    "approval_id": row.approval.id,
                    "finding_id": row.violation.finding_id if row.violation is not None else None,
                    "approved_fingerprint": finding.fingerprint if finding else "",
                    "receipt_digest": record.receipt_digest,
                    "expires": record.expires,
                    "recorded_policy": recorded,
                    "current_policy": current,
                },
            )
        )
        for p in row.premises:
            if p.state == "changed":
                changed.append({"kind": "premise", "subject": f"{row.approval.id} · {p.label}", "detail": "; ".join(p.reasons)})
    for label, ids in sorted(policy_changes.items()):
        changed.append({"kind": "policy", "subject": label, "detail": f"승인 {len(ids)}건이 기록한 값과 현재 값이 다르다: {', '.join(sorted(ids)[:5])}"})

    actions: list[dict[str, str]] = []
    for d in decisions:
        if d.decision == "invalidate":
            actions.append({"kind": "re_review", "target": d.approval_id, "text": f"{d.rule_id} {d.location} 승인을 다시 검토한 뒤 새 근거로 승인하거나 수정하십시오 — {'; '.join(d.why_changed[:3])}"})
        elif d.decision == "undeterminable":
            actions.append({"kind": "confirm_target", "target": d.approval_id, "text": f"{d.location}: 승인 대상 파일이 없거나 점검하지 못했다. 대상을 확인하십시오(해소로 보지 않는다)"})
    if ledger is not None:
        for blocker in ledger.blockers:
            actions.append({"kind": "new_evidence", "target": ledger.contract_digest, "text": f"계약이 요구한 근거가 없다: {blocker}"})
    gaps: list[dict[str, str]] = []
    if ledger is not None:
        for blocker in ledger.blockers:
            gaps.append({"kind": "contract_gap", "text": blocker})
    for d in report.diagnostics:
        if d.severity in ("error", "warning") or d.kind == "analysis_limit":
            gaps.append({"kind": f"diagnostic:{d.kind}", "text": f"{d.file_path + ': ' if d.file_path else ''}{d.message}"})
    for d in decisions:
        for b in d.boundaries:
            gaps.append({"kind": "dynamic_boundary", "text": f"{d.approval_id}: {b}"})
    review_only = [v for v in report.violations if v.confidence.value == "REVIEW" and v.approval_status in (None, "none", "expired", "revoked", "invalid")]
    if review_only:
        gaps.append({"kind": "unreviewed_findings", "text": f"승인 없는 '확인 필요' 지적 {len(review_only)}건(`approvals queue`로 심각도 순 확인). 변경과 무관하게 남아 있는 판단 보류이며 필수 행동은 아니다"})
    gaps = [dict(t) for t in sorted({tuple(sorted(g.items())) for g in gaps})]

    reproduction = {
        "run_id": run["run_id"],
        "code_digest": execution.code_digest if execution else "",
        "tool": current["tool_version"],
        "ruleset_hash": current["ruleset_hash"],
        "config_hash": current["config_hash"],
        "contract_digest": current["contract_digest"],
        "approvals_file": approvals_path,
        "command": command,
        "verify": "iron-laws evidence verify <audit --format json 보고서>",
        "details": "승인별 근거 ID는 approvals[].evidence, 전제별 비교는 `approvals status --json`",
    }
    return ReviewBundle(run=run, changed_premises=changed, approvals=decisions, actions=actions, gaps=gaps, reproduction=reproduction)


def render_markdown(bundle: ReviewBundle) -> str:
    counts = bundle.counts()
    lines = ["# 검토 묶음", ""]
    lines.append(f"- 점검 상태: {bundle.run['scan_status']} · 계약: {bundle.run['contract_status']} · 실행: `{bundle.run['run_id']}`")
    lines.append(f"- 승인 {len(bundle.approvals)}건 중 유지 {counts['keep']} · 무효화 {counts['invalidate']} · 판정 불가 {counts['undeterminable']}"
                 + (f" · 해소 {counts['resolved']}" if counts["resolved"] else "")
                 + (f" · 철회 {counts['revoked']}" if counts["revoked"] else ""))
    lines += ["", "## 바뀐 전제", ""]
    if bundle.changed_premises:
        lines += [f"- [{c['kind']}] {c['subject']} — {c['detail']}" for c in bundle.changed_premises]
    else:
        lines.append("- 확인된 변경 없음")
    lines += ["", "## 기존 승인", ""]
    for decision in ("invalidate", "undeterminable", "keep", "resolved", "revoked"):
        items = [a for a in bundle.approvals if a.decision == decision]
        if not items:
            continue
        lines.append(f"### {DECISION_LABEL[decision]} ({len(items)})")
        lines.append("")
        for a in items:
            lines.append(f"- **{a.approval_id}** {a.rule_id} `{a.location}`")
            for reason in a.why_changed:
                lines.append(f"  - 이유: {reason}")
            for reason in a.why_kept:
                lines.append(f"  - 유지 근거: {reason}")
            for boundary in a.boundaries:
                lines.append(f"  - 경계: {boundary}")
            ev = a.evidence
            lines.append(f"  - 근거 ID: 승인 `{ev['approval_id']}` · 지적 `{ev['finding_id'] or '-'}` · 지문 `{ev['approved_fingerprint']}`" + (f" · 검증 기록 `{ev['receipt_digest']}`" if ev.get("receipt_digest") else ""))
        lines.append("")
    lines += ["## 필수 행동", ""]
    lines += [f"- [{a['kind']}] {a['text']}" for a in bundle.actions] or ["- 없음"]
    lines += ["", "## 남은 공백", ""]
    lines += [f"- [{g['kind']}] {g['text']}" for g in bundle.gaps] or ["- 없음"]
    lines += ["", "## 재현 정보", ""]
    r = bundle.reproduction
    lines += [
        f"- 실행 `{r['run_id']}` · 코드 `{r['code_digest']}` · 도구 `{r['tool']}`",
        f"- 규칙 집합 `{r['ruleset_hash']}` · 설정 `{r['config_hash']}` · 계약 `{r['contract_digest']}`",
        f"- 승인 기록: `{r['approvals_file'] or '-'}`",
        f"- 다시 만들기: `{r['command']}`",
        f"- 검증: {r['verify']}",
        f"- 상세: {r['details']}",
        "",
        f"> {bundle.caveat}",
    ]
    return "\n".join(lines) + "\n"
