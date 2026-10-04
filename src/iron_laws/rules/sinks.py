"""
오철칙 싱크 기반 규칙 공통 도구
작성자: 최진호
작성일: 2026-10-04
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum

from tree_sitter import Node

from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_dynamic_composition,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import ALL_LANGS, C_FAMILY, JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import definitions, is_tainted

PY = frozenset({Lang.PYTHON})
JS = frozenset(JS_FAMILY)
JAVA = frozenset({Lang.JAVA})
CS = frozenset({Lang.CSHARP})
GO = frozenset({Lang.GO})
RUST = frozenset({Lang.RUST})
PHP = frozenset({Lang.PHP})
CFAM = frozenset(C_FAMILY)
ANY = ALL_LANGS


class Flow(Enum):
    TAINTED = "tainted"  # 외부 입력이 도달함이 코드에서 확인됨
    DYNAMIC = "dynamic"  # 변수 결합·보간으로 만든 식이나 외부 입력 도달은 미확인
    SAFE = "safe"  # 상수이거나 판단 근거 없음


@dataclass(frozen=True)
class Sink:
    langs: frozenset[Lang]
    callee: re.Pattern[str]
    arg: int | None = 0  # None이면 모든 인자를 검사

    @staticmethod
    def of(langs: frozenset[Lang], pattern: str, arg: int | None = 0) -> "Sink":
        return Sink(langs, re.compile(pattern), arg)


FUNCTION_LIKE = {"arrow_function", "function_expression", "function", "lambda", "lambda_expression", "closure_expression", "func_literal"}
BROWSER_HINT = re.compile(r"\b(document|window|localStorage|sessionStorage|navigator)\.")
SERVER_HINT = re.compile(r"process\.env|require\(\s*['\"](http|https|fs|express|child_process|net)|from\s+['\"](express|http|fs|next/server)|createServer")


def looks_like_browser_script(src: SourceFile) -> bool:
    text = src.text
    return bool(BROWSER_HINT.search(text)) and not SERVER_HINT.search(text)


def assess(src: SourceFile, arg: Node, cli: bool = False) -> Flow:
    if arg.type in FUNCTION_LIKE:
        return Flow.SAFE
    candidates = [arg]
    if arg.type in ("identifier", "variable_name"):
        scope = enclosing_function(arg, src.lang) or src.root
        if scope is not None:
            candidates.extend(definitions(src, scope, src.text_of(arg).lstrip("$")))
    for node in candidates:
        if not is_literal(node) and is_tainted(src, node, cli):
            return Flow.TAINTED
    for node in candidates:
        if is_dynamic_composition(src, node):
            return Flow.DYNAMIC
    return Flow.SAFE


def sink_hits(src: SourceFile, sinks: list[Sink], cli: bool = False) -> Iterator[tuple[Call, Node, Flow]]:
    applicable = [s for s in sinks if src.lang in s.langs]
    if not applicable:
        return
    for call in iter_calls(src):
        for sink in applicable:
            if not sink.callee.search(call.callee):
                continue
            indices = range(len(call.args)) if sink.arg is None else [sink.arg]
            for i in indices:
                if i < len(call.args):
                    flow = assess(src, call.args[i], cli)
                    if flow is not Flow.SAFE:
                        yield call, call.args[i], flow
                        break
            break
