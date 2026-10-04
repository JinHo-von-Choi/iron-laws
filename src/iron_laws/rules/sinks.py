"""
오철칙 싱크 기반 규칙 공통 도구
작성자: 최진호
작성일: 2026-10-04
"""

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from tree_sitter import Node

from iron_laws.engine.ast_tools import (
    Call,
    Func,
    enclosing_function,
    is_dynamic_composition,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import ALL_LANGS, C_FAMILY, JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import Ctx, is_tainted, param_name, reaching_definitions, resolve_any

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


def assess(
    src: SourceFile,
    arg: Node,
    cli: bool = False,
    seeds: frozenset[str] = frozenset(),
    ctx: Ctx = Ctx.ANY,
) -> Flow:
    if arg.type in FUNCTION_LIKE:
        return Flow.SAFE
    candidates = [arg]
    if arg.type in ("identifier", "variable_name"):
        scope = enclosing_function(arg, src.lang) or src.root
        if scope is not None:
            candidates.extend(reaching_definitions(src, scope, src.text_of(arg).lstrip("$"), arg.start_byte))
    for node in candidates:
        if not is_literal(node) and is_tainted(src, node, cli, seeds, ctx):
            return Flow.TAINTED
    for node in candidates:
        if is_dynamic_composition(src, node):
            return Flow.DYNAMIC
    return Flow.SAFE


ArgSelector = Callable[[SourceFile, Call, Sink], list[Node]]
SkipCheck = Callable[[SourceFile, Call, Node, Flow], bool]


class Hit(NamedTuple):
    call: Call
    arg: Node
    flow: Flow
    via: str | None = None  # 다른 함수·파일 안에서 싱크에 닿는 경우 그 위치


def _default_args(src: SourceFile, call: Call, sink: Sink) -> list[Node]:
    if sink.arg is None:
        return list(call.args)
    return [call.args[sink.arg]] if sink.arg < len(call.args) else []


def _hits_in(
    src: SourceFile,
    calls: Iterable[Call],
    applicable: list[Sink],
    cli: bool,
    select: ArgSelector,
    seeds: frozenset[str],
    ctx: Ctx,
) -> Iterator[tuple[Call, Node, Flow]]:
    for call in calls:
        for sink in applicable:
            if not sink.callee.search(call.callee):
                continue
            for arg in select(src, call, sink):
                flow = assess(src, arg, cli, seeds, ctx)
                if flow is not Flow.SAFE:
                    yield call, arg, flow
                    break
            break


def _calls_inside(calls: list[Call], fn: Func) -> list[Call]:
    return [c for c in calls if fn.node.start_byte <= c.node.start_byte and c.node.end_byte <= fn.node.end_byte]


def _tainted_helper_params(src: SourceFile, calls: list[Call], cli: bool, ctx: Ctx):
    """프로젝트의 도우미 함수 중 외부 입력이 인자로 넘어가는 (호출, 함수 파일, 함수, 매개변수) 조합"""
    found = []
    for call in calls:
        for hsrc, fn in resolve_any(src, call.callee, len(call.args)):
            params = [p for p in fn.params if hsrc.text_of(p) not in ("self", "cls")]
            for param, arg in zip(params, call.args, strict=False):
                name = param_name(hsrc, param)
                if name and not is_literal(arg) and is_tainted(src, arg, cli, ctx=ctx):
                    found.append((call, arg, hsrc, fn, name))
    return found


def sink_hits(
    src: SourceFile,
    sinks: list[Sink],
    cli: bool = False,
    select: ArgSelector | None = None,
    ctx: Ctx = Ctx.ANY,
    skip: SkipCheck | None = None,
) -> Iterator[Hit]:
    """싱크 호출과 그 인자의 흐름을 돌려준다. 프로젝트의 도우미 함수 안에 있는 싱크도
    호출부에서 외부 입력이 매개변수로 넘어가면 확정 지적으로 포함한다.
    같은 파일이면 싱크 위치에, 다른 파일이면 호출한 위치에 지적하고 via에 싱크 위치를 담는다."""
    applicable = [s for s in sinks if src.lang in s.langs]
    if not applicable:
        return
    pick = select or _default_args
    calls = list(iter_calls(src))
    merged: dict[int, Hit] = {}
    for call, arg, flow in _hits_in(src, calls, applicable, cli, pick, frozenset(), ctx):
        merged[call.node.id] = Hit(call, arg, flow)
    seen: set[tuple[int, str, int, str]] = set()
    for call_site, arg_at_site, hsrc, fn, name in _tainted_helper_params(src, calls, cli, ctx):
        key = (call_site.node.id, hsrc.path.as_posix(), fn.node.id, name)
        if key in seen:
            continue
        seen.add(key)
        inner_calls = list(iter_calls(hsrc)) if hsrc is not src else calls
        for inner, inner_arg, flow in _hits_in(
            hsrc, _calls_inside(inner_calls, fn), [s for s in sinks if hsrc.lang in s.langs], cli,
            select or _default_args, frozenset({name}), ctx,
        ):
            if flow is not Flow.TAINTED:
                continue
            if skip is not None and skip(hsrc, inner, inner_arg, flow):
                continue
            if hsrc is src:
                merged[inner.node.id] = Hit(inner, inner_arg, flow)
            else:
                where = f"{hsrc.path.as_posix()}:{inner.line}"
                proxy = Call(call_site.node, inner.callee, call_site.args)
                merged[call_site.node.id] = Hit(proxy, arg_at_site, flow, via=where)
    yield from merged.values()
