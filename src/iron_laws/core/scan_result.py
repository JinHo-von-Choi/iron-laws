"""점검 결과의 기준선·승인·요약·불변식 조립."""
import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime

from iron_laws.core.baseline import apply_baseline
from iron_laws.core.models import (
    ApprovalCheck,
    AuditReport,
    AuditSummary,
    BaselineStatus,
    CoverageLedger,
    Diagnostic,
    ExecutionRecord,
    Severity,
    StandardRef,
    Violation,
)
from iron_laws.core.redaction import (
    MAX_MESSAGE_LENGTH,
    limit,
    redact_text,
)
from iron_laws.core.scan_constants import (
    INCOMPLETE_GRADE,
    NOT_SCANNED_GRADE,
    SEVERITY_ORDER,
    tool_version,
)
from iron_laws.engine.source import SourceFile
from iron_laws.standards.pack_registry import all_packs


@dataclass
class ScanResultInputs:
    sources: list[SourceFile]
    violations: list[Violation]
    suppressed: int
    ledger: CoverageLedger
    files_by_language: Counter


class ScanResultBuilder:
    def _assemble_report(self, inputs: ScanResultInputs) -> AuditReport:
        sources, violations = inputs.sources, inputs.violations
        suppressed, ledger = inputs.suppressed, inputs.ledger
        files_by_language = inputs.files_by_language
        # 기준선 대응은 전체 지적 집합에서 먼저 확정하고, 표시 범위(변경 파일)는 그 뒤에 줄인다
        outcome = None
        if self.baseline is not None:
            outcome = apply_baseline(
                violations,
                self.baseline,
                {r.rule_id: r.version for r in self.rules},
                {s.path.as_posix() for s in sources},
                set(self._all_paths),
            )
            self._diagnostics.extend(outcome.diagnostics)

        if self.approvals is not None:
            self._apply_approvals(violations, sources)

        scope_note: dict | None = None
        full_count = len(violations)
        if self.changed_files is not None:
            violations = [v for v in violations if v.file_path.as_posix() in self.changed_files]
            scope_note = {
                "mode": "changed-since",
                "ref": self.changed_since,
                "changed_files": len(self.changed_files),
                "changed_paths": sorted(self.changed_files),
                "renames": [{"from": old, "to": new} for old, new in self.renames],
                "full_findings": full_count,
                "note": "변경된 파일의 지적만 표시했습니다. 프로젝트 전체 규칙과 파일 간 영향은 전체 점검으로 정기적으로 대조하십시오.",
            }
        violations.sort(key=lambda v: (str(v.file_path), v.line_number, v.rule_id))
        files_scanned = len(sources)

        summary = AuditSummary(total_files_scanned=files_scanned, suppressed_count=suppressed)
        summary.total_violations = len(violations)
        summary.critical_count = sum(1 for v in violations if v.severity == Severity.CRITICAL)
        summary.high_count = sum(1 for v in violations if v.severity == Severity.HIGH)
        summary.medium_count = sum(1 for v in violations if v.severity == Severity.MEDIUM)
        summary.low_count = sum(1 for v in violations if v.severity == Severity.LOW)
        summary.grade = self._grade(summary.critical_count, summary.high_count, summary.medium_count, summary.low_count)
        if outcome is not None:
            summary.new_count = sum(1 for v in violations if v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW))
            summary.existing_count = sum(1 for v in violations if v.baseline_status is BaselineStatus.EXISTING)
            summary.resolved_count = len(outcome.resolved)
            summary.unobserved_count = len(outcome.unobserved)

        if self.approvals is not None:
            summary.approvals_valid = sum(1 for v in violations if v.approval_status == "approved")
            summary.approvals_review = sum(1 for r in self.approval_rows if r.status in ("needs_review", "invalid")) + sum(
                1 for v in violations if v.approval_status in ("expired", "revoked")
            )
            summary.approvals_unobserved = sum(1 for r in self.approval_rows if r.status == "unobserved")
            for row in self.approval_rows:
                if row.status in ("needs_review", "unobserved", "resolved", "invalid") and row.reasons:
                    where = row.approval.record.finding.path if row.approval.record.finding else ""
                    self._diagnostics.append(
                        Diagnostic(
                            kind="approval",
                            severity="warning" if row.status != "resolved" else "info",
                            file_path=where,
                            message=f"승인 {row.approval.id}: {row.status} — {'; '.join(row.reasons[:3])}",
                        )
                    )
        threshold = SEVERITY_ORDER[self.config.fail_on]
        counted = [
            v
            for v in violations
            if (self.baseline is None or v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW))
            and v.approval_status != "approved"  # 전제가 유지되는 유효한 승인은 받아들인 지적이다. 전제가 바뀐 승인은 다시 센다
        ]
        summary.is_passed = not any(SEVERITY_ORDER[v.severity] >= threshold for v in counted)

        summary.contract_mode = ledger.contract_mode
        summary.contract_status = ledger.status
        if self.contract.mode == "block" and ledger.status in ("unmet", "policy_change_review"):
            summary.is_passed = False  # 근거 계약을 충족하지 못했다. 경고 0건이 자동 승인으로 이어지지 않는다

        self._apply_gates(summary, violations, sources, ledger)

        if files_scanned == 0:
            summary.scan_status = "empty"
            summary.grade = NOT_SCANNED_GRADE  # 점검한 파일이 없으면 통과가 아니라 '점검 없음'이다
            summary.is_passed = False
        elif any(d.severity == "error" for d in self._diagnostics):
            summary.scan_status = "incomplete"
            summary.grade = INCOMPLETE_GRADE  # 일부를 점검하지 못했으면 등급과 통과를 확정하지 않는다
            summary.is_passed = False

        for d in self._diagnostics:
            d.message = limit(redact_text(d.message, self._secrets), MAX_MESSAGE_LENGTH)

        now_utc = datetime.now(UTC)
        doc_id = f"AUDIT-{now_utc.strftime('%Y%m%d-%H%M%S')}"
        metadata = {
            "config": self.config.model_dump(mode="json"),
            "config_source": self.config_source,
            "config_hash": hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()[:16],
            "fail_on_source": self.fail_on_source,
            "tool_version": tool_version(),
            "ruleset": self._ruleset_info(),
            "files_by_language": dict(sorted(files_by_language.items())),
            "skipped_files": self._skipped,
            "excluded_summary": {
                "files": dict(self._excluded_files.most_common()),
                "directories": dict(self._excluded_dirs.most_common()),
            },
            "unscanned_by_extension": dict(self._unscanned_ext.most_common(20)),
            "cross_file": self._cross_file,
            "repo_relative_prefix": self._repo_relative_prefix(),
            "standard_packs": [pack.describe() for pack in all_packs()],
            "routes": _route_summary(self._routes),
            "suppressions": sorted(self._suppression_rows, key=lambda r: (r["path"], r["line"], r["rule_id"]))[:MAX_ROUTE_ROWS],
        }
        if scope_note:
            metadata["scope"] = scope_note
        if self.baseline is not None:
            metadata["baseline"] = {"entries": len(self.baseline.entries), "tool_version": self.baseline.tool_version}
        if self.config.policies.custom_spec:
            metadata["custom_spec"] = {
                "path": self.config.policies.custom_spec,
                "digest": ledger.digests.get("spec", ""),
                "ledger_include_spec_points": self.config.policies.ledger_include_spec_points,
            }

        execution = ExecutionRecord(
            run_id=ledger.run_id,
            tool_version=tool_version(),
            ruleset_hash=metadata["ruleset"]["hash"],
            config_hash=metadata["config_hash"],
            contract_digest=ledger.contract_digest,
            code_digest=ledger.digests.get("code", ""),
            scan_status=summary.scan_status,
            files_scanned=files_scanned,
            files_skipped=len([x for x in self._skipped if not str(x.get("path", "")).startswith("(")]),
            error_diagnostics=sum(1 for d in self._diagnostics if d.severity == "error"),
            cross_file_limit_hits=self._cross_file["limit_hits"],
        )
        approval_checks = self._approval_checks(violations) if self.approvals is not None else []
        report = AuditReport(
            document_id=doc_id,
            audit_date=now_utc.strftime("%Y-%m-%d"),
            target_path=str(self.root_path),
            summary=summary,
            violations=violations,
            diagnostics=self._diagnostics,
            coverage_ledger=ledger,
            execution=execution,
            approval_checks=approval_checks,
            metadata=metadata,
        )
        self._consistency_gate(report)
        return report


    @staticmethod
    def _grade(crit: int, high: int, med: int, low: int) -> str:
        if crit > 0:
            return "F"
        if high > 0:
            return "D"
        if med > 0:
            return "B"
        if low > 0:
            return "A-"
        return "A+"


    @staticmethod
    def _support_manifest_digest() -> str:
        from importlib.resources import files

        raw = files("iron_laws.standards").joinpath("data", "support_fixtures.json").read_bytes()
        return hashlib.sha256(raw).hexdigest()[:16]


    def _ruleset_info(self) -> dict:
        entries = sorted(f"{r.rule_id}:{r.version}" for r in self.rules)
        support = self._support_manifest_digest()  # 규칙 검증 등급의 근거. 등급이 바뀌면 규칙 집합의 지문도 바뀐다
        return {
            "count": len(entries),
            "hash": hashlib.sha256("\n".join([*entries, f"support:{support}"]).encode()).hexdigest()[:16],
            "support_manifest": support,
            "rules": [{"id": r.rule_id, "version": r.version} for r in sorted(self.rules, key=lambda r: r.rule_id)],
        }


    def _trust_table(self) -> dict[tuple[str, str], bool]:
        """(규칙, 언어) → 양성·음성 시험이 모두 있는가. 적용되지 않는 조합은 표에 없다."""
        if self._trust_cells is None:
            from iron_laws.reporters.support import build_support_matrix

            self._trust_cells = {(row.rule_id, lang): cell.verified for row in build_support_matrix(self.rules) for lang, cell in row.cells.items() if cell.status != "미지원"}
        return self._trust_cells


    def _apply_trust(self, sources: list[SourceFile], violations: list[Violation]) -> tuple[int, int]:
        """지적마다 (규칙, 언어) 검증 등급을 붙이고, 이번 점검에서 실제로 적용된 조합 수와 그중 미검증 조합 수를 센다."""
        from iron_laws.reporters.support import FIXTURE_LANG_ALIASES

        table = self._trust_table()
        lang_of = {s.path.as_posix(): FIXTURE_LANG_ALIASES.get(s.lang.value, s.lang.value) for s in sources if s.lang is not None}
        from iron_laws.standards.pack_registry import refs_for

        for v in violations:
            v.standards = [StandardRef(**ref) for ref in refs_for(v.rule_id)]
            lang = lang_of.get(v.file_path.as_posix())
            if lang is not None and (v.rule_id, lang) in table:
                v.verification_grade = "verified" if table[(v.rule_id, lang)] else "unverified"
        scanned_langs = set(lang_of.values())
        evaluated = {pair for pair in table if pair[1] in scanned_langs}
        unverified = sum(1 for pair in evaluated if not table[pair])
        return len(evaluated), unverified


    def _consistency_gate(self, report: AuditReport) -> None:
        """보고서를 내보내기 전에 독립 검증기로 구조적 모순을 확인한다. 모순이 있으면 통과로 내보내지 않고 점검 불완전으로 표시한다."""
        from iron_laws.evidence.verifier import verify_report

        result = verify_report(report.model_dump(mode="json"))
        if result.ok:
            return
        for problem in result.problems[:5]:
            report.diagnostics.append(
                Diagnostic(kind="consistency", severity="error", message=limit(redact_text(f"점검 결과의 내부 모순: {problem}", self._secrets), MAX_MESSAGE_LENGTH))
            )
        report.summary.scan_status = "incomplete"
        report.summary.grade = INCOMPLETE_GRADE
        report.summary.is_passed = False
        if report.execution is not None:
            report.execution.scan_status = "incomplete"
            report.execution.error_diagnostics = sum(1 for d in report.diagnostics if d.severity == "error")


    def _apply_gates(self, summary: AuditSummary, violations: list[Violation], sources: list[SourceFile], ledger) -> None:
        """신뢰 지표(분석 unknown 비율, 미검증 규칙×언어 비율)를 보고서에 남기고, 상한 정책이 있으면 초과를 통과가 아니라 재검토로 돌린다."""
        evaluated, unverified = self._apply_trust(sources, violations)
        in_scope = [p for p in ledger.points if p.in_scope]
        gap_states = ("unsupported", "unresolved", "budget_exceeded")
        summary.analysis_unknown_rate = round(sum(1 for p in in_scope if p.state in gap_states) / len(in_scope), 4) if in_scope else None
        summary.evaluated_rule_language_pairs = evaluated
        summary.unverified_rule_language_pairs = unverified
        summary.unverified_rule_language_rate = round(unverified / evaluated, 4) if evaluated else None
        if not self.gates:
            return
        was_passed = summary.is_passed
        summary.gates = dict(sorted(self.gates.items()))
        rates = {"max_analysis_unknown_rate": summary.analysis_unknown_rate, "max_unverified_rule_language_rate": summary.unverified_rule_language_rate}
        names = {"max_analysis_unknown_rate": "analysis_unknown_rate", "max_unverified_rule_language_rate": "unverified_rule_language_rate"}
        for key, limit_value in summary.gates.items():
            rate = rates.get(key)
            if rate is not None and rate > limit_value:
                summary.gate_exceeded.append(f"{names[key]} {rate} > {limit_value}")
        if summary.gate_exceeded:
            summary.gate_only_failure = was_passed  # 지적이나 계약이 아니라 상한만으로 실패했는가(보고서 문구가 지적의 실패를 가리지 않게 한다)
            summary.is_passed = False  # 상한을 넘은 점검은 통과로 세지 않고 사람이 재검토한다


    def _approval_checks(self, violations: list[Violation]) -> list[ApprovalCheck]:
        by_fp = {v.fingerprint: v for v in violations}
        checks: list[ApprovalCheck] = []
        for row in self.approval_rows:
            record = row.approval.record
            finding = record.finding
            matched = by_fp.get(row.violation.fingerprint) if row.violation is not None else None
            policy = record.policy.model_dump() if record.policy is not None else {}
            checks.append(
                ApprovalCheck(
                    approval_id=row.approval.id,
                    status=row.status,
                    reasons=list(row.reasons),
                    rule_id=finding.rule_id if finding else "",
                    path=finding.path if finding else "",
                    approved_fingerprint=finding.fingerprint if finding else "",
                    finding_id=matched.finding_id if matched is not None else None,
                    expires=record.expires,
                    policy={k: str(v) for k, v in policy.items()},
                )
            )
        return checks


MAX_ROUTE_ROWS = 500


def _route_summary(rows: list[dict]) -> dict:
    """라우트 접근통제 행렬 요약. 중요 기능 라우트의 행을 함께 싣는다(인증 근거가 없거나 정할 수 없는 행이 먼저)."""
    sensitive = [r for r in rows if r.get("sensitive")]
    order = {"no": 0, "unknown": 1, "yes": 2}
    listed = sorted(sensitive, key=lambda r: (order.get(r["auth"], 3), r["file"], r["line"]))
    count = lambda key, value: sum(1 for r in sensitive if r[key] == value)  # noqa: E731
    return {
        "total": len(rows),
        "sensitive": len(sensitive),
        "auth": {v: count("auth", v) for v in ("yes", "no", "unknown")},
        "authz": {v: count("authz", v) for v in ("yes", "no", "unknown", "n/a")},
        "rows": listed[:MAX_ROUTE_ROWS],
        "truncated": len(listed) > MAX_ROUTE_ROWS,
    }
