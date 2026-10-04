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


def mask_secrets(text: str) -> str:
    """따옴표 안의 값, `KEY=값` 형태의 값, 토큰처럼 긴 문자열을 가린다. 변수 이름과 구조는 남긴다."""
    masked = QUOTED_RE.sub(lambda m: f"{m.group('q')}{MASK}{m.group('q')}", text)
    masked = ASSIGN_RE.sub(lambda m: f"{m.group('head')}{MASK}{m.group('tail')}", masked)
    return TOKEN_RE.sub(MASK, masked)
