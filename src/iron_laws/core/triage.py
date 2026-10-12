"""
오철칙 선택형 검토 의견: '확인 필요' 지적을 사용자가 지정한 LLM 명령에 묶어 보내고, 의견을 지적의 review_opinion에만 담는다

- 판정·심각도·확정 여부·통과 여부는 바꾸지 않는다. 의견은 사람이 검토 순서를 정하는 참고다.
- 보내는 코드 조각은 비밀값을 가린 뒤 보낸다. 명령은 사용자가 고른 것이며(예: "claude -p"), 오철칙은 키나 주소를 정하지 않는다.
- 응답은 JSON 배열 [{"index", "verdict": likely_true|likely_false|unsure, "reason"}]만 받는다. 형식이 틀린 항목은 버린다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
import shlex
import subprocess
from pathlib import Path

from iron_laws.core.masking import mask_secrets
from iron_laws.core.models import AuditReport, Confidence
from iron_laws.core.redaction import redact_text

VERDICTS = {"likely_true", "likely_false", "unsure"}


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
        "JSON 배열만 출력하라: [{\"index\": 번호, \"verdict\": \"likely_true\"|\"likely_false\"|\"unsure\", \"reason\": \"한두 문장\"}]. "
        "확실하지 않으면 unsure로 답하라.\n"
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
    return opinions


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
    for index, opinion in opinions.items():
        picks[index].review_opinion = {"source": model, **opinion}
    return len(opinions)
