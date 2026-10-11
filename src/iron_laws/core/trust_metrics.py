"""보안 관심 지점의 분모와 미확정 원인을 함께 보관하는 집계."""

from collections import Counter
from typing import Any

GAPS = frozenset({'unsupported', 'unresolved', 'budget_exceeded'})


def gap_reason(state: str, reason: str) -> str:
    if state == 'unsupported':
        return 'api_not_modeled'
    if state == 'budget_exceeded':
        return 'analysis_budget'
    for needle, category in (('매개변수', 'caller_or_parameter'), ('반환값', 'unresolved_return'),
                             ('속성', 'object_state'), ('환경변수', 'untrusted_environment'),
                             ('명령행', 'cli_or_stdin'), ('외부 입력', 'unproven_guard')):
        if needle in reason:
            return category
    return 'other_unresolved'


def summarize_trust(report: dict[str, Any]) -> dict[str, Any]:
    """독립 검증을 통과한 보고서의 집계. 상태·범위·제외를 바꾸지 않는다."""
    ledger = report.get('coverage_ledger') or {}
    points = ledger.get('points') or []
    scoped = [p for p in points if p.get('in_scope')]
    gaps = [p for p in scoped if p['state'] in GAPS]
    groups = Counter((p['family'], p['callee'], p['state'], gap_reason(p['state'], p.get('reason', ''))) for p in gaps)
    summary = report.get('summary') or {}
    return {
        'schema_version': 1,
        'report_schema': report.get('schema_version'),
        'execution': report.get('execution'),
        'total_points': len(points),
        'in_scope_points': len(scoped),
        'out_of_scope_points': len(points) - len(scoped),
        'states': dict(sorted(Counter(p['state'] for p in scoped).items())),
        'gap_points': len(gaps),
        'analysis_unknown_rate': summary.get('analysis_unknown_rate'),
        'evaluated_rule_language_pairs': summary.get('evaluated_rule_language_pairs'),
        'unverified_rule_language_pairs': summary.get('unverified_rule_language_pairs'),
        'unverified_rule_language_rate': summary.get('unverified_rule_language_rate'),
        'contract_status': summary.get('contract_status'),
        'unclassified_changed_files': len(ledger.get('unclassified_changed_files') or []),
        'excluded_summary': (report.get('metadata') or {}).get('excluded_summary'),
        'gaps': [dict(family=f, callee=c, state=s, cause=cause, count=count)
                 for (f, c, s, cause), count in sorted(groups.items())],
    }
