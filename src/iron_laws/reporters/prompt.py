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

금지(이렇게 하면 지적이 사라져도 수정으로 인정되지 않습니다):
- `iron-laws: ignore` 억제 주석, `# noqa`, `@SuppressWarnings`, `eslint-disable`로 지적을 가리기
- 실패하는 테스트를 지우거나 skip·xfail로 바꾸기, 검사 설정(.iron-laws.yml, 계약 파일)을 느슨하게 바꾸기
- 문제가 된 코드를 try/except로 감싸고 예외를 버리기
- 위험한 호출을 다른 이름의 도우미 함수로 옮기기만 하기(도구는 도우미 안까지 따라갑니다)
"""

# 규칙별 반례: 흔히 나오는 잘못된 수정과 올바른 수정
COUNTER_EXAMPLES = {
    "IL-501": ("문자열에서 따옴표를 지우거나 replace로 이스케이프하기", "파라미터 바인딩: cursor.execute('... WHERE id = %s', (value,)) / PreparedStatement.setString"),
    "IL-504": ("입력에서 ; & | 같은 글자만 지우기, shell=True를 유지한 채 shlex.quote를 일부에만 쓰기", "셸을 거치지 않는 인자 배열: subprocess.run(['cmd', value], check=True) / execFile('cmd', [value])"),
    "IL-502": ("'../' 문자열만 지우기", "기준 폴더와 합친 뒤 실제 경로로 정규화하고 기준 폴더 안인지 확인: realpath(join(BASE, v)).startswith(BASE + os.sep)"),
    "IL-503": ("eval 앞에 정규식 검사를 하나 덧붙이기", "eval·exec를 없애고 허용 목록의 함수 이름만 사전에서 고르기, 데이터는 json.loads·ast.literal_eval로 읽기"),
    "IL-505": ("innerHTML에 넣기 전 <script>만 지우기", "textContent나 템플릿의 자동 이스케이프 사용, HTML이 꼭 필요하면 검증된 sanitizer(DOMPurify 등)"),
    "IL-506": ("요청 주소에서 'localhost'만 막기", "허용 호스트 목록으로 확인하고, 이름 해석 뒤 사설·루프백 주소를 거부"),
    "AIA-103": ("LLM에 '위험한 명령은 출력하지 마'라고 지시하기", "LLM 응답은 허용 목록의 값만 고르게 하고, SQL은 바인딩, 실행은 격리 환경에서만"),
}



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
    counter = COUNTER_EXAMPLES.get(v.rule_id)
    if counter is not None:
        lines.append(f"- 이렇게 고치지 마세요: {counter[0]}")
        lines.append(f"- 이렇게 고치세요: {counter[1]}")
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
