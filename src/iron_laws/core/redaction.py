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
    return values


def redact_text(text: str, secrets: set[str] | frozenset[str] = frozenset()) -> str:
    """알려진 비밀 값과 토큰 형식을 가린다."""
    for secret in sorted(secrets, key=len, reverse=True):
        if secret and secret in text:
            text = text.replace(secret, MASK)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(MASK, text)
    text = URL_CREDENTIAL_RE.sub(f"{MASK}:{MASK}", text)
    text = AUTH_HEADER_RE.sub(lambda m: m.group(1) + MASK, text)
    text = CLI_SECRET_RE.sub(lambda m: m.group(1) + MASK, text)
    return text


def limit(text: str, size: int) -> str:
    return text if len(text) <= size else text[: size - 1] + "…"
