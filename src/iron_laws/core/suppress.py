"""
오철칙 지적 억제 주석 처리: 사유가 있는 억제만 인정한다
형식: `iron-laws: ignore[IL-101] 사유` 또는 `iron-laws: ignore-file[IL-101] 사유`
만료일을 두려면 사유 앞이나 뒤에 `until=2026-12-31`을 적는다. 만료된 억제는 적용되지 않고 보고서에 드러난다.
억제 지시문은 실제 주석 안에서만 인정한다. 문자열·여러 줄 문자열·here-document 안의 문구는 주석이 아니다.
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
MARKUP_COMMENT_RE = re.compile(r"<!--(?P<text>.*?)(?:-->|$)|\{#(?P<t2>.*?)(?:#\}|$)|@\*(?P<t3>.*?)(?:\*@|$)")
HEREDOC_RE = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)")
BLOCK_SCALAR_RE = re.compile(r"[|>][+\-0-9]*\s*$")
TOML_TRIPLES = ('"""', "'''")


@dataclass
class _QuoteState:
    """줄을 넘어 이어지는 따옴표 문자열의 상태. shell·YAML의 여러 줄 따옴표 문자열 안의 `#`은 주석이 아니다."""

    quote: str | None = None
    ansi: bool = False  # shell `$'...'`: 작은따옴표 안에서도 백슬래시가 다음 글자를 이스케이프한다


def _yaml_scalar_start(line: str, index: int) -> bool:
    """YAML에서 따옴표는 값(스칼라)의 첫 글자일 때만 문자열을 연다. `it's`처럼 값 중간의 작은따옴표는 문자열이 아니다."""
    before = line[:index].rstrip()
    return not before or before[-1] in ":-[{,?"


def _scan_hash_comment(line: str, kind: str, state: _QuoteState | None = None) -> int | None:
    """따옴표 밖에서 `#`가 시작하는 주석의 위치. 없으면 None. state를 넘기면 여러 줄 따옴표 문자열을 줄 사이에 이어서 따라간다."""
    state = state if state is not None else _QuoteState()
    quote = state.quote
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and (quote == '"' or (quote == "'" and state.ansi)):
                i += 2  # 큰따옴표(YAML 포함)와 shell `$'...'` 안의 백슬래시는 다음 글자를 이스케이프한다
                continue
            if ch == quote:
                quote = None
                state.ansi = False
        elif ch == "\\" and kind in ("shell", "env"):
            i += 2  # shell의 따옴표 밖 백슬래시는 다음 글자(따옴표 포함)를 이스케이프한다
            continue
        elif ch in ("'", '"'):
            if kind in ("yaml", "compose", "actions") and not _yaml_scalar_start(line, i):
                pass
            else:
                quote = ch
                state.ansi = kind == "shell" and ch == "'" and i > 0 and line[i - 1] == "$"
        elif ch == "#" and (kind == "toml" or i == 0 or line[i - 1].isspace()):
            state.quote = None
            return i
        i += 1
    state.quote = quote
    return None


def _toml_multiline_state(line: str, open_quote: str | None) -> tuple[str, str | None]:
    """TOML 삼중 따옴표 문자열을 따라가며 (주석 탐색에 쓸 줄, 줄 끝에서 열려 있는 삼중 따옴표)를 돌려준다.
    삼중 따옴표 문자열의 내용은 공백으로 지워 `#`가 주석으로 보이지 않게 한다."""
    out: list[str] = []
    i = 0
    quote = open_quote
    while i < len(line):
        if quote:
            end = line.find(quote, i)
            if end < 0:
                out.append(" " * (len(line) - i))
                return "".join(out), quote
            out.append(" " * (end + 3 - i))
            i = end + 3
            quote = None
            continue
        opened = next((t for t in TOML_TRIPLES if line.startswith(t, i)), None)
        if opened:
            quote = opened
            out.append("   ")
            i += 3
            continue
        out.append(line[i])
        i += 1
    return "".join(out), quote


def _hash_comments(lines: list[str], kind: str) -> list[tuple[int, str]]:
    """YAML·shell·TOML·.env 등에서 실제 주석만 뽑는다. 문자열, 여러 줄 문자열(YAML `|`·TOML 삼중 따옴표),
    here-document 안의 `#`은 주석이 아니다."""
    found: list[tuple[int, str]] = []
    heredoc_tag: str | None = None
    block_indent: int | None = None
    toml_quote: str | None = None
    state = _QuoteState()
    for idx, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if heredoc_tag is not None:
            if stripped == heredoc_tag:
                heredoc_tag = None
            continue
        if block_indent is not None:
            if not stripped or len(raw) - len(raw.lstrip()) > block_indent:
                continue
            block_indent = None
        if kind == "docker":
            if stripped.startswith("#"):
                found.append((idx, stripped[1:]))
            continue
        if kind == "properties":
            if stripped.startswith(("#", "!")):
                found.append((idx, stripped[1:]))
            continue
        line = raw
        if kind == "toml":
            line, toml_quote = _toml_multiline_state(raw, toml_quote)
        pos = _scan_hash_comment(line, kind, state if kind in ("shell", "yaml", "compose", "actions", "env") else None)
        code = line
        if pos is not None:
            found.append((idx, raw[pos + 1 :]))
            code = line[:pos]
        if kind == "shell":
            m = HEREDOC_RE.search(code)
            if m:
                heredoc_tag = m.group("tag")
        elif kind in ("yaml", "compose", "actions") and BLOCK_SCALAR_RE.search(code.rstrip()):
            block_indent = len(raw) - len(raw.lstrip())
    return found


def _sql_comments(lines: list[str]) -> list[tuple[int, str]]:
    """SQL의 `--`·`/* */` 주석만 뽑는다. 작은따옴표 문자열 안은 주석이 아니다."""
    found: list[tuple[int, str]] = []
    in_block = False
    in_string = False
    for idx, line in enumerate(lines, start=1):
        i = 0
        start = 0
        while i < len(line):
            two = line[i : i + 2]
            if in_block:
                if two == "*/":
                    found.append((idx, line[start:i]))
                    in_block = False
                    i += 2
                    continue
            elif in_string:
                if line[i] == "'":
                    if line[i + 1 : i + 2] == "'":
                        i += 2
                        continue
                    in_string = False
            elif line[i] == "'":
                in_string = True
            elif two == "--":
                found.append((idx, line[i + 2 :]))
                break
            elif two == "/*":
                in_block = True
                start = i + 2
                i += 2
                continue
            i += 1
        else:
            if in_block:
                found.append((idx, line[start:]))
    return found


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
        return _hash_comments(src.lines, src.kind)
    if src.kind == "sql":
        return _sql_comments(src.lines)
    if src.kind in {"xml", "doc", "text", "template"}:
        for idx, line in enumerate(src.lines, start=1):
            for m in MARKUP_COMMENT_RE.finditer(line):
                found.append((idx, next((g for g in m.groups() if g is not None), "")))
        return found
    return found  # JSON 등 주석이 없는 형식은 억제를 지원하지 않는다


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
