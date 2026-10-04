"""
오철칙 지적 억제 주석 처리: 사유가 있는 억제만 인정한다
형식: `iron-laws: ignore[IL-101] 사유` 또는 `iron-laws: ignore-file[IL-101] 사유`
만료일을 두려면 사유 앞이나 뒤에 `until=2026-12-31`을 적는다. 만료된 억제는 적용되지 않고 보고서에 드러난다.
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass, field
from datetime import date

from iron_laws.core.models import Violation
from iron_laws.engine.source import SourceFile

SUPPRESS_RE = re.compile(
    r"iron-laws:\s*(?P<kind>ignore-file|ignore)\s*\[(?P<ids>[^\]]+)\]\s*(?P<reason>[^\n]*)"
)
UNTIL_RE = re.compile(r"\buntil=(?P<date>\S+)")
MIN_REASON_LENGTH = 3
FILE_DIRECTIVE_WINDOW = 30

HASH_KINDS = {"shell", "yaml", "env", "properties", "docker", "compose", "actions", "toml", "version"}
HASH_COMMENT_RE = re.compile(r"(?:^|\s)#(?P<text>.*)$")
SQL_COMMENT_RE = re.compile(r"--(?P<text>.*)$")
MARKUP_COMMENT_RE = re.compile(r"<!--(?P<text>.*?)(?:-->|$)|\{#(?P<t2>.*?)(?:#\}|$)|@\*(?P<t3>.*?)(?:\*@|$)")


@dataclass
class Directive:
    line: int
    kind: str
    ids: set[str]
    reason: str
    expires: date | None = None
    expired: bool = False
    used: set[str] = field(default_factory=set)


@dataclass
class FileSuppressions:
    directives: list[Directive] = field(default_factory=list)
    problems: list[tuple[int, str]] = field(default_factory=list)

    def covers(self, violation: Violation) -> bool:
        for d in self.directives:
            if violation.rule_id not in d.ids:
                continue
            if d.kind == "ignore":
                if d.line not in (violation.line_number, violation.line_number - 1):
                    continue
            if d.expired:
                continue
            d.used.add(violation.rule_id)
            return True
        return False


def _clean_reason(raw: str) -> str:
    return re.sub(r"(\*/|-->|\"\"\"|''')\s*$", "", raw).strip()


def _comment_texts(src: SourceFile) -> list[tuple[int, str]]:
    """실제 주석 안의 (줄 번호, 텍스트)만 돌려준다. 문자열 리터럴과 데이터 안의 문구는 억제 지시문이 아니다."""
    found: list[tuple[int, str]] = []
    if src.root is not None:
        for node in src.comment_nodes:
            first = node.start_point[0] + 1
            for offset, line in enumerate(src.text_of(node).splitlines() or [""]):
                found.append((first + offset, line))
        return found
    if src.kind in HASH_KINDS:
        pattern = HASH_COMMENT_RE
    elif src.kind == "sql":
        pattern = SQL_COMMENT_RE
    elif src.kind in {"xml", "doc", "text", "template"}:
        pattern = MARKUP_COMMENT_RE
    else:
        return found  # JSON 등 주석이 없는 형식은 억제를 지원하지 않는다
    for idx, line in enumerate(src.lines, start=1):
        for m in pattern.finditer(line):
            text = next((g for g in m.groups() if g is not None), "")
            found.append((idx, text))
    return found


def parse_suppressions(src: SourceFile, today: date | None = None) -> FileSuppressions:
    today = today or date.today()
    result = FileSuppressions()
    for idx, text in _comment_texts(src):
        m = SUPPRESS_RE.search(text)
        if not m:
            continue
        reason = _clean_reason(m.group("reason"))
        until: date | None = None
        until_match = UNTIL_RE.search(reason)
        if until_match:
            try:
                until = date.fromisoformat(until_match.group("date"))
            except ValueError:
                result.problems.append((idx, f"억제 만료일 형식이 올바르지 않습니다: {until_match.group('date')}"))
                continue
            reason = _clean_reason(UNTIL_RE.sub("", reason))
        if len(reason) < MIN_REASON_LENGTH:
            continue
        kind = m.group("kind")
        if kind == "ignore-file" and idx > FILE_DIRECTIVE_WINDOW:
            continue
        ids = {i.strip() for i in m.group("ids").split(",") if i.strip()}
        result.directives.append(
            Directive(idx, kind, ids, reason, until, expired=until is not None and until < today)
        )
    return result
