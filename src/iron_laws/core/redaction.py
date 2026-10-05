"""
오철칙 공통 비밀 가림(redaction): 어떤 보고서 형식에도 비밀 원문이 남지 않게 한다
- 비밀로 판정된 줄에서 값을 뽑아, 같은 줄의 다른 규칙 지적·message·evidence·진단에서도 지운다.
- 값이 알려진 토큰 형식(GitHub·OpenAI·AWS·Slack·JWT·개인키), URL 속 인증정보, Authorization 헤더, 명령행 비밀번호 옵션은
  어디에 나타나든 가린다.
- 원문을 먼저 가린 뒤 길이를 제한한다. (자른 뒤 가리면 잘린 조각이 남는다)
작성자: 최진호
작성일: 2026-10-04
"""

import re

from iron_laws.core.masking import ASSIGN_RE, MASK, QUOTED_RE

MIN_SECRET_LENGTH = 8
MAX_SNIPPET_LENGTH = 300
MAX_MESSAGE_LENGTH = 600

TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
]
URL_CREDENTIAL_RE = re.compile(r"(?<=://)([^/\s:@]+):([^/\s@]+)(?=@)")
AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+)[A-Za-z0-9._\-+/=]{8,}")
CLI_SECRET_RE = re.compile(r"(?i)(?<![\w-])(-p(?=\S{4,})|--(?:password|passwd|token|secret|api-key)[= ])(\S{4,})")


def _looks_secret(value: str) -> bool:
    """길이가 충분하고, 사람이 읽는 평범한 낱말이 아닌 값만 비밀 후보로 본다."""
    if len(value) < MIN_SECRET_LENGTH:
        return False
    return bool(re.search(r"[\d\W_]", value)) or not value.isalpha()


NAMED_SECRET_RE = re.compile(
    r"""(?ix)\b[\w.\-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?key)[\w.\-]*
    (?:\s*:\s*[^\n=]+?)?\s*(?::=|=|:)\s*(?P<q>["'`])(?P<value>[^"'`\n]{8,}?)(?P=q)"""
)
PARTIAL_MIN = 8
PARTIAL_SECRET_MIN = 12


def collect_named_secrets(line: str) -> set[str]:
    """비밀 이름(password·token·secret·api_key 등)에 대입된 따옴표 값. 비밀 규칙이 그 줄을 지적하지 않았어도 다른 규칙의 출력에 새면 안 된다."""
    # 비밀 이름에 대입된 값은 낱말처럼 보이는 글자뿐이어도 비밀이다(영문자만 있는 긴 토큰이 새지 않게 한다)
    return {m.group("value") for m in NAMED_SECRET_RE.finditer(line)}


def collect_secret_values(line: str) -> set[str]:
    """비밀로 판정된 한 줄에서 가릴 값 후보를 뽑는다."""
    values: set[str] = set()
    for m in QUOTED_RE.finditer(line):
        if _looks_secret(m.group("body")):
            values.add(m.group("body"))
    for m in ASSIGN_RE.finditer(line):
        value = m.group("value").strip().strip("\"'")
        if _looks_secret(value):
            values.add(value)
    for pattern in TOKEN_PATTERNS:
        values.update(m.group(0) for m in pattern.finditer(line))
    for m in CLI_SECRET_RE.finditer(line):
        values.add(m.group(2))
    values |= collect_named_secrets(line)
    return values


def redact_text(text: str, secrets: set[str] | frozenset[str] = frozenset()) -> str:
    """알려진 비밀 값과 토큰 형식을 가린다."""
    for secret in sorted(secrets, key=len, reverse=True):
        if secret and secret in text:
            text = text.replace(secret, MASK)
    for secret in secrets:
        text = _mask_fragments(text, secret)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(MASK, text)
    text = URL_CREDENTIAL_RE.sub(f"{MASK}:{MASK}", text)
    text = AUTH_HEADER_RE.sub(lambda m: m.group(1) + MASK, text)
    text = CLI_SECRET_RE.sub(lambda m: m.group(1) + MASK, text)
    return text


def _mask_fragments(text: str, secret: str) -> str:
    """길이를 제한하다 잘려 나간 긴 비밀의 앞·뒤 조각도 가린다. 긴 비밀(12자 이상)에서 8자 이상 이어지는 조각만 대상이다."""
    if len(secret) < PARTIAL_SECRET_MIN:
        return text
    spans: list[tuple[int, int]] = []
    head, tail = secret[:PARTIAL_MIN], secret[-PARTIAL_MIN:]
    start = text.find(head)
    while start >= 0:  # 앞 조각: 비밀과 이어서 일치하는 만큼
        end = start + PARTIAL_MIN
        while end - start < len(secret) and end < len(text) and text[end] == secret[end - start]:
            end += 1
        spans.append((start, end))
        start = text.find(head, end)
    start = text.find(tail)
    while start >= 0:  # 뒤 조각: 앞쪽으로 비밀과 이어서 일치하는 만큼
        first, k = start, len(secret) - PARTIAL_MIN
        while first > 0 and k > 0 and text[first - 1] == secret[k - 1]:
            first, k = first - 1, k - 1
        spans.append((first, start + PARTIAL_MIN))
        start = text.find(tail, start + PARTIAL_MIN)
    for first, last in sorted(_merge(spans), reverse=True):
        text = text[:first] + MASK + text[last:]
    return text


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for first, last in sorted(spans):
        if merged and first <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    return merged


def limit(text: str, size: int) -> str:
    return text if len(text) <= size else text[: size - 1] + "…"
