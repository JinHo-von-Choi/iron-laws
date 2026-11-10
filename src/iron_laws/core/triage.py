"""
오철칙 선택형 검토 의견: '확인 필요' 지적을 사용자가 지정한 LLM 명령에 묶어 보내고, 의견을 지적의 review_opinion에만 담는다

- 판정·심각도·확정 여부·통과 여부는 바꾸지 않는다. 의견은 사람이 검토 순서를 정하는 참고다.
- 보내는 코드 조각은 비밀값을 가린 뒤 보낸다. 명령은 사용자가 고른 것이며(예: "claude -p"), 오철칙은 키나 주소를 정하지 않는다.
- 응답은 JSON 배열 [{"index", "verdict": likely_true|likely_false|unsure, "reason", "basis"}]만 받는다. 형식이 틀린 항목은 버린다.
- likely_false(오탐 같다)에는 근거(basis: constant·sanitized_by·unreachable·not_external, 줄, 이름)를 요구하고, 코드와 엔진의 근거 경로로
  기계적으로 대조해 check에 corroborated(근거 확인)·unsupported(확인 못 함)·contradicted(엔진 근거와 모순)를 남긴다.
  LLM의 말은 대조를 통과해도 판정을 바꾸지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
import shlex
import subprocess
from pathlib import Path

from iron_laws.core.masking import mask_secrets
from iron_laws.core.models import AuditReport, Confidence, Violation
from iron_laws.core.redaction import redact_text
from iron_laws.engine.taint.sanitizers import SANITIZER_FN_RE

VERDICTS = {"likely_true", "likely_false", "unsure"}
BASIS_KINDS = {"constant", "sanitized_by", "unreachable", "not_external"}
LITERAL_RHS = r"(?:\"[^\"]*\"|'[^']*'|-?\d+(?:\.\d+)?|true|false|True|False|None|null)"
DEAD_CONDITION = re.compile(r"\b(?:if|while)\s*\(?\s*(?:false|False|0|None|null)\s*\)?\s*[:{]?\s*$")


class TriageError(RuntimeError):
    """검토 의견 명령을 실행하지 못했다"""
MAX_FINDINGS = 30
WINDOW = 8


def _window(root: Path, rel: str, line: int, secrets: set[str]) -> str:
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:  # iron-laws: ignore[IL-301] 읽을 수 없는 파일은 코드 조각 없이 지적 문구만 보낸다
        return ""
    start, end = max(0, line - 1 - WINDOW), min(len(lines), line + WINDOW)
    body = "\n".join(f"{i + 1:5d}| {lines[i]}" for i in range(start, end))
    return mask_secrets(redact_text(body, secrets))


CRITERIA: dict[int, str] = {
    89: "SQL 삽입: 값이 SQL 문자열에 들어가면 위험이다. 파라미터 바인딩(`?`, `%s`, 이름 있는 바인딩)으로 넘기거나, 값이 상수·열거형·허용 목록 검사를 거친 값이면 오탐이다. 테이블·열 이름은 바인딩할 수 없으니 허용 목록 검사 여부를 본다.",
    78: "명령어 삽입: 셸이 해석하는 문자열(`shell=True`, `os.system`, `exec`)에 값이 들어가면 위험이다. 인자 배열로 넘기고 셸을 쓰지 않거나, 값이 상수·허용 목록 검사를 거친 값이면 오탐이다.",
    77: "명령어 삽입: 셸이 해석하는 문자열에 값이 들어가면 위험이다. 인자 배열로 넘기고 셸을 쓰지 않거나, 값이 상수·허용 목록 검사를 거친 값이면 오탐이다.",
    22: "경로 조작: 값이 파일 경로를 정하면 위험이다. 정규화(`realpath`·`resolve`) 뒤 허용 폴더 안인지 확인하거나, 값이 상수·허용 목록 검사를 거친 값이면 오탐이다.",
    79: "XSS: 값이 HTML 출력에 이스케이프 없이 들어가면 위험이다. 템플릿 자동 이스케이프, `html.escape`·`escape`, 텍스트 노드로만 넣는 DOM API(`textContent`)를 쓰면 오탐이다.",
    918: "SSRF: 값이 서버가 보내는 요청의 주소가 되면 위험이다. 허용 호스트 목록으로 검사하거나 이름 풀이 뒤 내부 주소를 막으면 오탐이다. 값이 URL의 경로·쿼리 일부이고 호스트가 고정이면 오탐이다.",
    94: "코드 삽입: 값이 `eval`·`exec`·동적 코드 평가에 들어가면 위험이다. 값이 상수이거나 `ast.literal_eval` 같은 안전한 해석기를 쓰면 오탐이다.",
    95: "코드 삽입: 값이 `eval`·`exec`·동적 코드 평가에 들어가면 위험이다. 값이 상수이거나 `ast.literal_eval` 같은 안전한 해석기를 쓰면 오탐이다.",
    90: "LDAP 삽입: 값이 LDAP 필터·DN 문자열에 들어가면 위험이다. LDAP 이스케이프 함수를 거치거나 값이 상수이면 오탐이다. 정규식 검색(`re.search`)처럼 LDAP과 무관한 호출이면 오탐이다.",
    502: "역직렬화: 신뢰할 수 없는 바이트를 `pickle`·`yaml.load`·`ObjectInputStream`으로 읽으면 위험이다. `yaml.safe_load`, 서명 검증된 데이터, 자기 프로세스가 만든 데이터이면 오탐이다.",
}


def _cwes(violation: Violation) -> list[int]:
    found: list[int] = []
    for step in violation.standards:
        found += [int(n) for n in re.findall(r"^CWE-(\d+)$", step.item_id)]
    gov = violation.gov_standard
    if gov is not None:
        found += [int(n) for n in re.findall(r"CWE-(\d+)", f"{gov.clause_id} {gov.description}")]
    return list(dict.fromkeys(found))


def criteria_for(violation: Violation) -> str:
    """지적의 CWE에 맞는 판정 기준. 기준이 없는 규칙은 빈 글이다."""
    for cwe in _cwes(violation):
        if cwe in CRITERIA:
            return f"CWE-{cwe} " + CRITERIA[cwe]
    return ""


def flow_lines(violation: Violation) -> str:
    """엔진이 확인한 입력 유입 → 전파 → 싱크 위치. 코드 원문은 담지 않는다."""
    if not violation.evidence:
        return ""
    labels = {"source": "입력", "propagation": "전파", "sink": "싱크"}
    steps = [f"{labels.get(s.role, s.role)} {s.file_path}:{s.line}" + (f"({s.note})" if s.note else "") for s in violation.evidence[:8]]
    return " → ".join(steps)


def precedent_notes(root: Path, rule_ids: set[str], lessons: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    """같은 규칙에 대해 사람이 남긴 판단: 승인 기록의 사유와 교훈 기록의 교훈. 읽지 못하면 빈 결과이며 검토는 계속한다."""
    notes: dict[str, list[str]] = {rule_id: list((lessons or {}).get(rule_id, []))[:3] for rule_id in rule_ids}
    try:
        from iron_laws.core.approvals import DEFAULT_APPROVALS_FILE, ApprovalStore

        base = root if root.is_dir() else root.parent
        path = base / DEFAULT_APPROVALS_FILE
        if path.is_file():
            store = ApprovalStore(path)
            revoked = {r.target for r in store.records if r.kind in ("revoke", "forget") and r.target}
            for record in store.records:
                if record.kind != "approve" or record.id in revoked or record.finding is None or not record.reason.strip():
                    continue
                bucket = notes.get(record.finding.rule_id)
                reason = f"승인 사유: {record.reason.strip()[:200]}"
                if bucket is not None and reason not in bucket and len(bucket) < 5:
                    bucket.append(reason)
    except Exception:  # noqa: BLE001  # iron-laws: ignore[IL-304] 판단 이력을 읽지 못해도 검토 의견은 이력 없이 만든다
        return {rule_id: list((lessons or {}).get(rule_id, []))[:3] for rule_id in rule_ids}
    return notes


def build_prompt(report: AuditReport, root: Path, secrets: set[str], lessons: dict[str, list[str]] | None = None) -> tuple[str, list]:
    picks = [v for v in report.violations if v.confidence is Confidence.REVIEW][:MAX_FINDINGS]
    parts = [
        "다음은 정적 분석 도구가 '확인 필요'로 남긴 지적이다. 각 지적이 실제 위험일 가능성을 코드만 보고 판단하라. "
        "JSON 배열만 출력하라: [{\"index\": 번호, \"verdict\": \"likely_true\"|\"likely_false\"|\"unsure\", \"reason\": \"한두 문장\", \"basis\": {...}}]. "
        "likely_false에는 basis를 반드시 넣어라: {\"kind\": \"constant\"(값이 상수다)|\"sanitized_by\"(정제 함수를 거친다)|\"unreachable\"(실행되지 않는 분기다)|\"not_external\"(외부 입력이 아니다), "
        "\"line\": 근거가 있는 줄 번호, \"name\": 변수 또는 정제 함수 이름}. 근거를 댈 수 없으면 unsure로 답하라. 확실하지 않으면 unsure로 답하라.\n"
        "각 지적에 '판정 기준'(그 결함 종류에서 위험인 경우와 오탐인 경우)과 '엔진이 확인한 흐름'(입력이 들어와 위험 호출에 닿기까지의 위치), "
        "사람이 같은 규칙에 남긴 판단이 있으면 함께 준다. 이 정보는 참고이며, 코드가 이와 다르면 코드를 따르라. 판단 이력에 있는 사례와 코드 모양이 다르면 그 이력은 쓰지 마라.\n"
    ]
    base = root if root.is_dir() else root.parent
    history = precedent_notes(root, {v.rule_id for v in picks}, lessons)
    for i, v in enumerate(picks):
        extra = []
        if criteria := criteria_for(v):
            extra.append(f"판정 기준: {criteria}")
        if flow := flow_lines(v):
            extra.append(f"엔진이 확인한 흐름: {flow}")
        for note in history.get(v.rule_id, []):
            extra.append(f"사람이 남긴 판단: {mask_secrets(redact_text(note, secrets))}")
        detail = "".join(f"{line}\n" for line in extra)
        parts.append(f"## {i}. {v.rule_id} {v.rule_name} — {v.file_path.as_posix()}:{v.line_number}\n지적: {v.message}\n{detail}```\n{_window(base, v.file_path.as_posix(), v.line_number, secrets)}\n```\n")
    return "\n".join(parts), picks


def parse_opinions(text: str, count: int) -> dict[int, dict]:
    body = re.sub(r"^```\w*\n|```\s*$", "", text.strip(), flags=re.MULTILINE)
    m = re.search(r"\[.*\]", body, re.DOTALL)
    try:
        data = json.loads(m.group(0) if m else body)
    except ValueError:  # iron-laws: ignore[IL-301] 형식이 틀린 응답은 의견 0건으로 보고한다(지적과 판정은 그대로다)
        return {}
    opinions = {}
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        index, verdict = item.get("index"), item.get("verdict")
        if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < count and isinstance(verdict, str) and verdict in VERDICTS:
            opinions[index] = {"verdict": verdict, "reason": str(item.get("reason", ""))[:400]}
            basis = item.get("basis")
            if isinstance(basis, dict) and basis.get("kind") in BASIS_KINDS:
                line = basis.get("line")
                opinions[index]["basis"] = {
                    "kind": basis["kind"],
                    "line": line if isinstance(line, int) and not isinstance(line, bool) else None,
                    "name": str(basis.get("name", ""))[:80],
                }
    return opinions


def check_basis(lines: list[str], violation: Violation, basis: dict | None) -> dict:
    """오탐이라는 의견의 근거를 코드와 엔진 근거 경로로 대조한다. 판정은 바꾸지 않는다."""
    if basis is None:
        return {"status": "unsupported", "why": "근거(basis)를 대지 않았다"}
    kind, line, name = basis["kind"], basis["line"], basis["name"]
    sources = [s for s in violation.evidence if s.role == "source"]
    if kind in ("constant", "not_external") and sources:
        where = ", ".join(f"{s.file_path}:{s.line}" for s in sources[:3])
        return {"status": "contradicted", "why": f"엔진은 외부 입력이 들어오는 곳을 확인했다({where})"}
    if line is None or not 1 <= line <= len(lines):
        return {"status": "unsupported", "why": "근거 줄이 파일 범위 밖이다"}
    text = lines[line - 1]
    if kind == "constant":
        if not name or line >= violation.line_number:
            return {"status": "unsupported", "why": "지적보다 앞선 줄의 변수 이름이 필요하다"}
        assigned = re.search(rf"\b{re.escape(name)}\s*=\s*{LITERAL_RHS}\s*;?\s*(?:(?://|#).*)?$", text)
        later = any(re.search(rf"\b{re.escape(name)}\s*(?:[-+*/%|&]?=)(?!=)", lines[i]) for i in range(line, violation.line_number - 1))
        used_at_sink = bool(re.search(rf"\b{re.escape(name)}\b", lines[violation.line_number - 1])) if violation.line_number <= len(lines) else False
        if assigned and not later and used_at_sink:
            return {"status": "corroborated", "why": f"{line}번 줄에서 {name}에 상수를 넣고 지적까지 다시 넣지 않으며, 지적한 줄이 {name}을 직접 쓴다"}
        return {"status": "unsupported", "why": f"{name}이 상수만 담은 채 지적한 줄에 직접 쓰이는지 확인하지 못했다(다른 호출·컬렉션을 거치면 사람이 확인)"}
    if kind == "sanitized_by":
        known = bool(name) and bool(SANITIZER_FN_RE.search(name))
        called = line <= violation.line_number and bool(name) and any(f"{name}(" in lines[i] for i in range(line - 1, violation.line_number))
        if known and called:
            return {"status": "corroborated", "why": f"{name}은(는) 오철칙이 아는 정제 함수이며 지적 앞에서 부른다(모든 경로에서 부르는지는 사람이 확인)"}
        return {"status": "unsupported", "why": f"{name or '이름 없음'}은(는) 오철칙이 아는 정제 함수가 아니거나 지적 앞에서 부르지 않는다"}
    if kind == "unreachable":
        if DEAD_CONDITION.search(text):
            return {"status": "corroborated", "why": f"{line}번 줄의 조건이 상수 거짓이다"}
        return {"status": "unsupported", "why": f"{line}번 줄의 조건이 상수 거짓인지 확인하지 못했다"}
    return {"status": "unsupported", "why": "엔진도 외부 입력 유입을 확인하지 못했다. 입력이 아닌지는 사람이 확인해야 한다"}


def apply_triage(report: AuditReport, root: Path, command: str, secrets: set[str] | None = None, timeout: int = 600, lessons: dict[str, list[str]] | None = None) -> int:
    """의견을 붙인 지적 수. 명령을 실행하지 못하면 TriageError(지적과 판정은 그대로다)."""
    prompt, picks = build_prompt(report, root, secrets or set(), lessons)
    if not picks:
        return 0
    try:
        done = subprocess.run(shlex.split(command), input=prompt, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        raise TriageError(f"검토 의견 명령을 실행하지 못했습니다: {e}") from e
    opinions = parse_opinions(done.stdout, len(picks))
    model = shlex.split(command)[0].rsplit("/", 1)[-1] if command.strip() else ""
    base = root if root.is_dir() else root.parent
    for index, opinion in opinions.items():
        violation = picks[index]
        if opinion["verdict"] == "likely_false":
            opinion["check"] = check_basis(_lines(base, violation.file_path.as_posix()), violation, opinion.get("basis"))
        violation.review_opinion = {"source": model, **opinion}
    return len(opinions)


def _lines(base: Path, rel: str) -> list[str]:
    try:
        return (base / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:  # iron-laws: ignore[IL-301] 읽을 수 없는 파일은 근거 대조를 하지 못한 것으로 남는다(빈 줄 목록 → unsupported)
        return []
