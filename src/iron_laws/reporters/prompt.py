"""
오철칙 AI 수정 지시문 생성기: 코딩 AI에게 그대로 붙여넣을 수정 요청
작성자: 최진호
작성일: 2026-10-04
"""

from iron_laws.core.models import AuditReport, BaselineStatus, Confidence, Severity, Violation

SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

PREAMBLE = """아래는 보안·품질 점검 도구(오철칙)가 이 프로젝트에서 찾아낸 문제 목록입니다. 위에서부터 차례로 수정해 주세요.

수정 원칙:
- 기능의 동작은 바꾸지 말고, 아래 문제만 고칩니다. 관련 없는 코드는 건드리지 않습니다.
- 오류를 로그 없이 조용히 삼키지 않습니다. 처리할 수 없는 오류는 예외로 던지고, 처리하더라도 원인을 기록합니다.
- 비밀번호·API 키·토큰을 코드에 쓰지 않습니다. 환경변수로 읽고, 필요한 이름만 .env.example에 추가합니다 (실제 값은 넣지 않습니다).
- 타입 검사를 any, type: ignore, 강제 캐스팅으로 덮지 않습니다. 실제 타입을 정의합니다.
- 같은 일을 하는 함수가 이미 있으면 새로 만들지 말고 기존 것을 재사용하거나 한 곳으로 통합합니다.
- 설정값(주소, 포트, 경로)은 코드에 박지 않고 환경변수나 설정 파일로 분리합니다.
- '확인 필요'로 표시된 문제는 도구가 확정하지 못한 것입니다. 먼저 외부 입력이 실제로 그 코드에 닿는지 흐름을 확인하고, 위험이 사실일 때만 고칩니다. 아니라면 고치지 말고 근거를 한 줄 남깁니다.
- 수정 후 관련 테스트를 실행합니다. 테스트가 없으면 수정한 동작을 검증하는 테스트를 추가합니다.
"""


def _entry(index: int, v: Violation) -> str:
    label = "확인 필요" if v.confidence is Confidence.REVIEW else "확정"
    lines = [
        f"[문제 {index}] {v.severity.value} · {label} · {v.rule_id} {v.rule_name} · {v.file_path.as_posix()}:{v.line_number}",
        f"- 문제: {v.message}",
    ]
    if v.confidence is Confidence.REVIEW:
        lines.append("- 먼저 할 일: 이 지적이 실제로 위험한지 코드 흐름을 확인한 뒤 수정 여부를 정합니다.")
    if v.plain:
        lines.append(f"- 왜 위험한가: {v.plain}")
    if v.how_to_fix:
        lines.append(f"- 고치는 방법: {v.how_to_fix}")
    if v.snippet:
        lines.append(f"- 해당 코드: {v.snippet}")
    return "\n".join(lines)


def _status_notice(report: AuditReport) -> str:
    if report.summary.scan_status != "incomplete":
        return ""
    errors = [d for d in report.diagnostics if d.severity == "error"]
    return (
        f"※ 점검이 끝까지 이루어지지 않았습니다(오류 {len(errors)}건). 아래 목록이 전부가 아니며, 목록에 없다고 안전하다는 뜻이 아닙니다.\n"
        + "\n".join(f"  - {d.file_path + ': ' if d.file_path else ''}{d.message}" for d in errors[:5])
        + "\n"
    )


def _ledger_section(report: AuditReport, limit: int = 10) -> str:
    ledger = report.coverage_ledger
    if ledger is None or not ledger.blockers:
        return ""
    lines = [
        "[검사 공백] 도구가 아래 지점의 입력 출처를 확정하지 못했습니다. 위험하다는 뜻이 아니라 '확인하지 못했다'는 뜻입니다.",
        "고치는 방법: 값이 어디서 오는지 코드에서 분명히 드러나게(상수·검증 함수·호출자에서 닫힌 값으로) 정리하고, 정리한 뒤 다시 점검하세요.",
    ]
    lines.extend(f"- {b}" for b in ledger.blockers[:limit])
    if len(ledger.blockers) > limit:
        lines.append(f"- … 외 {len(ledger.blockers) - limit}건")
    return "\n".join(lines) + "\n"


def generate_fix_prompt(report: AuditReport, limit: int = 40) -> str:
    notice = _status_notice(report)
    candidates = report.violations
    if report.summary.new_count is not None:
        candidates = [v for v in candidates if v.baseline_status in (BaselineStatus.NEW, BaselineStatus.REVIEW)]
    ordered = sorted(
        candidates,
        key=lambda v: (SEVERITY_ORDER[v.severity], str(v.file_path), v.line_number),
    )
    if report.summary.scan_status == "empty":
        return "점검한 파일이 없어 수정할 문제를 판단할 수 없습니다. 경로와 제외 설정을 확인하세요."
    gap = _ledger_section(report)
    if not ordered and gap:
        return (notice + "\n" if notice else "") + "점검 결과 지적은 없지만 검사 공백이 있습니다.\n\n" + gap
    if not ordered:
        return (notice + "\n" if notice else "") + "점검 결과 수정할 문제가 없습니다." + (" (불완전한 점검이므로 문제가 없다는 뜻이 아닙니다)" if notice else "")
    selected = ordered[:limit]
    parts = [*([notice] if notice else []), PREAMBLE, f"총 {len(ordered)}건 중 우선순위가 높은 {len(selected)}건입니다.\n"]
    parts.extend(_entry(i, v) + "\n" for i, v in enumerate(selected, start=1))
    if len(ordered) > limit:
        parts.append(
            f"나머지 {len(ordered) - limit}건은 위 문제를 모두 고친 뒤 오철칙을 다시 실행해 확인합니다."
        )
    if gap:
        parts.append("\n" + gap)
    return "\n".join(parts)
