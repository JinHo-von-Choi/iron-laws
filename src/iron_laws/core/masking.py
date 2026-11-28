"""
오철칙 비밀값 마스킹: 출력에 비밀 원문이 다시 나타나지 않게 한다
작성자: 최진호
작성일: 2026-10-04
"""

import re

MASK = "****"
QUOTED_RE = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).){3,}?)(?P=q)""")
ASSIGN_RE = re.compile(r"""(?P<head>^\s*[\w.\-\[\]"']+\s*[:=]\s*)(?P<value>[^\s#"'`][^\n#]*?)(?P<tail>\s*(?:#.*)?)$""")
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")


def mask_secrets(text: str, keep: frozenset[str] | set[str] = frozenset()) -> str:
    """따옴표 안의 값, `KEY=값` 형태의 값, 토큰처럼 긴 문자열을 가린다. 변수 이름과 구조는 남긴다.
    keep은 규칙이 비밀이 아니라고 판정해 보여 줄 따옴표 안 값이다."""
    masked = QUOTED_RE.sub(lambda m: m.group(0) if m.group("body") in keep else f"{m.group('q')}{MASK}{m.group('q')}", text)
    masked = ASSIGN_RE.sub(lambda m: f"{m.group('head')}{MASK}{m.group('tail')}", masked)
    return TOKEN_RE.sub(MASK, masked)


CODE_TOKEN_RE = re.compile(r"(?<![\w\-+/=])[A-Za-z0-9_\-+/=]{20,}(?![\w\-+/=])")
QUOTED_TOKEN_RE = re.compile(r"[^\s\"'`]{8,}")


def _token_like(value: str) -> bool:
    """숫자와 영문자가 섞인 값. 비밀 토큰·해시·키는 거의 언제나 숫자를 담고, 함수·형식 이름은 그렇지 않다"""
    return sum(c.isdigit() for c in value) >= 2 and sum(c.isalpha() for c in value) >= 2


def mask_code_secrets(text: str) -> str:
    """코드 조각을 밖으로 보낼 때 쓴다. mask_secrets와 달리 식별자와 평범한 문자열(SQL·경로·형식 문자열)은 남기고,
    공백 없이 숫자와 영문자가 섞인 따옴표 값과 20자 넘는 토큰 모양 값만 가린다.
    비밀로 판정된 값·비밀 이름에 대입된 값·알려진 토큰 형식은 redact_text가 먼저 가린다"""
    masked = QUOTED_RE.sub(
        lambda m: f"{m.group('q')}{MASK}{m.group('q')}" if QUOTED_TOKEN_RE.fullmatch(m.group("body")) and _token_like(m.group("body")) else m.group(0),
        text,
    )
    return CODE_TOKEN_RE.sub(lambda m: MASK if _token_like(m.group(0)) else m.group(0), masked)
