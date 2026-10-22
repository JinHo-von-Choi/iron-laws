"""장부·승인 전제·지적 지문 생성."""
import hashlib
import re
from collections import Counter

from iron_laws.core.approvals import (
    ApprovalPolicy,
    evaluate_approvals,
)
from iron_laws.core.baseline import make_fingerprint
from iron_laws.core.contract import contract_digest
from iron_laws.core.dependencies import build_callers_index, dependency_snapshot
from iron_laws.core.ledger import FAMILY_RULES
from iron_laws.core.masking import mask_secrets
from iron_laws.core.models import (
    Diagnostic,
    Violation,
)
from iron_laws.core.redaction import redact_text
from iron_laws.core.scan_constants import tool_version
from iron_laws.engine.ast_tools import iter_functions
from iron_laws.engine.source import SourceFile


def self_shape(src: SourceFile | None, v: Violation, sensitive: set[str]) -> str:
    """지적 줄에서 주석을 빼고 공백을 정리한 코드 모양. 주석만 바뀐 변경은 같은 지적으로 보게 하고, 비밀 후보는 가린 뒤에 쓴다."""
    line = v.snippet
    if src is not None and 1 <= v.line_number <= len(src.code_lines):
        line = src.code_lines[v.line_number - 1]
        line = redact_text(line)
        if v.rule_id in sensitive:
            line = mask_secrets(line)
    return re.sub(r"\s+", " ", line).strip()


class ScanEvidenceBuilder:
    def _spec_digest(self) -> str:
        """이번 점검이 반영한 사용자 명세의 지문. 명세가 없으면 빈 문자열이다."""
        from iron_laws.engine.taint import sanitizers

        return sanitizers.CUSTOM_KIND

    def _build_ledger(self, sources: list[SourceFile], violations: list[Violation]):
        family_rules = {cls.rule_id for cls in FAMILY_RULES.values()}
        findings: dict[tuple[str, str, int, int], list[str]] = {}
        for v in violations:
            if v.rule_id in family_rules and v.confidence.value == "CONFIRMED":  # '확인 필요'는 근거가 확정된 지적이 아니다
                findings.setdefault((v.rule_id, v.file_path.as_posix(), v.line_number, v.column), []).append(v.finding_id)
        digests = {
            "code": self._code_digest(sources),
            "tool": f"{tool_version()}+{self._ruleset_info()['hash']}",
            "config": hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()[:16],
            "contract": contract_digest(self.contract),
            "spec": self._spec_digest(),
        }
        ledger = self._ledger_builder(
            sources,
            self._skipped,
            self.contract,
            self.contract_source,
            self.config,
            findings,
            set(self._suppressed_lines),
            self.changed_files,
            digests,
            policy_changed=self._contract_changed(),
            lookup_budget=self.config.limits.max_cross_file_lookups,
            rules=self.rules if self.config.policies.ledger_include_spec_points else None,
        )
        self._note_spec_scope(ledger)
        return ledger
    def _note_spec_scope(self, ledger) -> None:
        """명세의 계열 중 장부가 다루지 않는 계열이 있으면 감추지 않고 밝힌다."""
        if not self.config.policies.ledger_include_spec_points:
            return
        from iron_laws.core.custom_spec import current_spec

        loaded = current_spec()
        if loaded is None:
            return
        entries = list(loaded.spec.sources) + list(loaded.spec.sinks) + list(loaded.spec.sanitizers)
        outside = sorted({e.family for e in entries if e.family not in set(FAMILY_RULES)})
        if not outside:
            return
        message = f"명세의 {', '.join(outside)} 계열 항목은 검사 공백 장부에 계열이 없어 대조하지 않았습니다"
        ledger.limitations.append(message)
        self._diagnostics.append(Diagnostic(kind="spec_scope", severity="warning", message=message))


    def _attach_dependencies(self, sources: list[SourceFile], violations: list[Violation]) -> None:
        """지적마다 승인 전제(흐름의 함수·호출자·정제 함수·접근 범위)의 지문을 붙인다. 파일 간 색인이 켜진 상태에서 호출한다."""
        by_path = {s.path.as_posix(): s for s in sources}
        callers = build_callers_index(sources)
        for v in violations:
            v.dependencies = dependency_snapshot(by_path, v, callers)
        for src in sources:
            src.release()


    def _approval_policy(self) -> ApprovalPolicy:
        return ApprovalPolicy(
            contract_digest=contract_digest(self.contract),
            config_hash=hashlib.sha256(self.config.model_dump_json().encode()).hexdigest()[:16],
            ruleset_hash=self._ruleset_info()["hash"],
            tool_version=tool_version(),
        )


    def _apply_approvals(self, violations: list[Violation], sources: list[SourceFile]) -> None:
        assert self.approvals is not None
        self.approval_rows = evaluate_approvals(
            self.approvals,
            violations,
            self._approval_policy(),
            {r.rule_id: r.version for r in self.rules},
            {s.path.as_posix() for s in sources},
            set(self._all_paths),
            changed_files=self.changed_files,
        )
        by_fp = {v.fingerprint: v for v in violations}
        label = {"valid": "approved", "needs_review": "needs_review", "revoked": "revoked", "invalid": "invalid"}
        for row in self.approval_rows:
            if row.violation is None:
                continue
            target = by_fp.get(row.violation.fingerprint)
            if target is None:
                continue
            if row.status == "valid":
                target.approval_status = "approved"
            elif row.status == "invalid":
                target.approval_status = "invalid"
            else:
                target.approval_status = "expired" if any("유효기간" in r for r in row.reasons) else label.get(row.status, "needs_review")
            target.approval_id = row.approval.id
            target.approval_reasons = row.reasons
        for v in violations:
            if v.approval_status is None:
                v.approval_status = "none"


    def _fingerprint(self, violations: list[Violation], sources: list[SourceFile]) -> None:
        """위치(줄 번호)가 아니라 규칙·파일·함수·코드 모양으로 지적을 식별한다. 줄이 밀려도 같은 지적으로 인식된다."""
        by_path = {s.path.as_posix(): s for s in sources}
        sensitive = {rule.rule_id for rule in self.rules if rule.sensitive_snippet}
        occurrences: Counter[tuple[str, str, str, str]] = Counter()
        function_cache: dict[str, list] = {}
        for v in sorted(violations, key=lambda x: (x.file_path.as_posix(), x.line_number, x.rule_id)):
            path = v.file_path.as_posix()
            src = by_path.get(path)
            scope = ""
            if src is not None and src.lang is not None:
                if path not in function_cache:
                    function_cache[path] = [(f.start_line, f.end_line, f.name) for f in iter_functions(src)]
                spans = [(e - s, name) for s, e, name in function_cache[path] if s <= v.line_number <= e]
                scope = min(spans)[1] if spans else ""
            shape = self_shape(src, v, sensitive)
            key = (v.rule_id, path, scope, shape)
            occurrences[key] += 1
            v.scope_name = scope
            v.shape = shape
            v.fingerprint = make_fingerprint(v.rule_id, v.rule_version, path, scope, shape, occurrences[key])
            v.finding_id = "F-" + hashlib.sha256(f"{v.rule_id}|{path}|{v.line_number}|{v.column}|{v.fingerprint}".encode()).hexdigest()[:12]
        for src in sources:
            src.release()
