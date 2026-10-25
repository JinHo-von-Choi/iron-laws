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


def build_prompt(report: AuditReport, root: Path, secrets: set[str]) -> tuple[str, list]:
    picks = [v for v in report.violations if v.confidence is Confidence.REVIEW][:MAX_FINDINGS]
    parts = [
        "다음은 정적 분석 도구가 '확인 필요'로 남긴 지적이다. 각 지적이 실제 위험일 가능성을 코드만 보고 판단하라. "
        "JSON 배열만 출력하라: [{\"index\": 번호, \"verdict\": \"likely_true\"|\"likely_false\"|\"unsure\", \"reason\": \"한두 문장\", \"basis\": {...}}]. "
        "likely_false에는 basis를 반드시 넣어라: {\"kind\": \"constant\"(값이 상수다)|\"sanitized_by\"(정제 함수를 거친다)|\"unreachable\"(실행되지 않는 분기다)|\"not_external\"(외부 입력이 아니다), "
        "\"line\": 근거가 있는 줄 번호, \"name\": 변수 또는 정제 함수 이름}. 근거를 댈 수 없으면 unsure로 답하라. 확실하지 않으면 unsure로 답하라.\n"
    ]
    base = root if root.is_dir() else root.parent
    for i, v in enumerate(picks):
        parts.append(f"## {i}. {v.rule_id} {v.rule_name} — {v.file_path.as_posix()}:{v.line_number}\n지적: {v.message}\n```\n{_window(base, v.file_path.as_posix(), v.line_number, secrets)}\n```\n")
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


def apply_triage(report: AuditReport, root: Path, command: str, secrets: set[str] | None = None, timeout: int = 600) -> int:
    """의견을 붙인 지적 수. 명령을 실행하지 못하면 TriageError(지적과 판정은 그대로다)."""
    prompt, picks = build_prompt(report, root, secrets or set())
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
