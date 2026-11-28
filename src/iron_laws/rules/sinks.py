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
from iron_laws.engine.taint.c_inputs import callee_names
from iron_laws.engine.taint.closed import is_closed_value
from iron_laws.engine.taint.constants import in_dead_branch
from iron_laws.engine.xfile import note_limit

PY = frozenset({Lang.PYTHON})
JS = frozenset(JS_FAMILY)
JAVA = frozenset({Lang.JAVA, Lang.KOTLIN})  # Kotlin은 JVM 표준 라이브러리 싱크를 그대로 쓴다
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
    prop: bool = False  # 참이면 호출이 아니라 속성 대입(`cmd.CommandText = 값`, `+=`)의 대상 이름과 맞춘다

    @staticmethod
    def of(langs: frozenset[Lang], pattern: str, arg: int | None = 0) -> "Sink":
        return Sink(langs, re.compile(pattern), arg)

    @staticmethod
    def assigned(langs: frozenset[Lang], pattern: str) -> "Sink":
        """속성 대입 싱크. 대입한 값(우변)을 인자 0으로 본다"""
        return Sink(langs, re.compile(pattern), 0, prop=True)


ASSIGNMENT_SINK_TYPES = frozenset({"assignment_expression"})


def _assignment_calls(src: SourceFile) -> list[Call]:
    """속성 대입문을 (대입문 노드, 대상 원문, [우변]) 호출 꼴로 바꾼다"""

    def build() -> list[Call]:
        found = []
        for node in src.nodes:
            if node.type not in ASSIGNMENT_SINK_TYPES:
                continue
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None and left.type in ("member_access_expression", "field_expression", "member_expression"):
                found.append(Call(node, src.text_of(left), [right]))
        return found

    return src.memo("assignment_calls", build)


CS_RESPONSE_TYPES = r"HttpResponse(?:Base)?"


def cs_response_receiver(src: SourceFile, call: Call) -> bool:
    """C# 호출의 수신자가 응답 객체인지: 형식이 HttpResponse인 매개변수·변수, `Response`, `HttpContext.Current.Response`"""
    receiver = call.callee.rsplit(".", 1)[0] if "." in call.callee else ""
    return receiver in ("Response", "HttpContext.Current.Response", "Context.Response") or receiver in typed_names(src, CS_RESPONSE_TYPES, call.node)


def typed_names(src: SourceFile, type_pattern: str, at: Node) -> set[str]:
    """at을 감싼 함수 안에서 선언한 형식이 type_pattern인 매개변수·지역 변수 이름(C#·Java).
    변수 이름이 아니라 형식으로 객체를 정할 때 쓴다"""
    scope = enclosing_function(at, src.lang)
    key = f"typed_names:{type_pattern}:{scope.id if scope is not None else -1}"
    text = src.code_of(scope) if scope is not None else ""
    return src.memo(key, lambda: set(re.findall(rf"\b(?:{type_pattern})\s+([A-Za-z_]\w*)\s*[,)=;]", text)))


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
            candidates.extend(d for d in reaching_definitions(src, scope, src.text_of(arg).lstrip("$"), arg.start_byte) if not in_dead_branch(src, d))
    for node in candidates:
        if not is_literal(node) and is_tainted(src, node, cli, seeds, ctx):
            return Flow.TAINTED
    for node in candidates:
        if is_dynamic_composition(src, node) and not is_closed_value(src, node):
            return Flow.DYNAMIC
    return Flow.SAFE


ArgSelector = Callable[[SourceFile, Call, Sink], list[Node]]
SkipCheck = Callable[[SourceFile, Call, Node, Flow], bool]
EntryGuard = Callable[[SourceFile, Call, Node], "str | None"]


class Hit(NamedTuple):
    call: Call
    arg: Node
    flow: Flow
    via: str | None = None  # 다른 함수·파일 안에서 싱크에 닿는 경우 그 위치
    entry_guard: str | None = None  # 도우미 함수로 닿을 때, 모든 호출하는 곳이 거친 검사를 이 규칙이 확인 필요로 낮추는 사유


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
        names = callee_names(src, call.callee) if src.lang in C_FAMILY else (call.callee,)
        for sink in applicable:  # iron-laws: ignore[PERF-102] applicable은 규칙에 고정된 싱크 표다
            if not any(sink.callee.search(name) for name in names):
                continue
            for arg in select(src, call, sink):
                flow = assess(src, arg, cli, seeds, ctx)
                if flow is not Flow.SAFE:
                    yield call, arg, flow
                    break
            break


def _calls_inside(calls: list[Call], fn: Func) -> list[Call]:
    return [c for c in calls if fn.node.start_byte <= c.node.start_byte and c.node.end_byte <= fn.node.end_byte]


MAX_CHAIN_DEPTH = 4


def _helper_entries(src: SourceFile, calls: list[Call], cli: bool, ctx: Ctx, seeds: frozenset[str] = frozenset(), confined: "SkipCheck | None" = None):
    """calls 중 인자가 오염된 채 프로젝트의 도우미 함수로 넘어가는 (호출, 인자, 함수 파일, 함수, 매개변수) 조합.
    confined가 참인 인자(호출하는 곳에서 이미 검사를 거친 값)는 따라가지 않는다"""
    found = []
    for call in calls:
        for hsrc, fn in resolve_any(src, call.callee, len(call.args), at=call.node):
            params = [p for p in fn.params if hsrc.text_of(p) not in ("self", "cls")]
            for param, arg in zip(params, call.args, strict=False):
                name = param_name(hsrc, param)
                if name and not is_literal(arg) and is_tainted(src, arg, cli, seeds, ctx) and not (confined is not None and confined(src, call, arg, Flow.TAINTED)):
                    found.append((call, arg, hsrc, fn, name))
    return found


def sink_hits(
    src: SourceFile,
    sinks: list[Sink],
    cli: bool = False,
    select: ArgSelector | None = None,
    ctx: Ctx = Ctx.ANY,
    skip: SkipCheck | None = None,
    confined: SkipCheck | None = None,
    entry_guard: EntryGuard | None = None,
) -> Iterator[Hit]:
    """싱크 호출과 그 인자의 흐름을 돌려준다. 프로젝트의 도우미 함수 안에 있는 싱크도
    호출부에서 외부 입력이 매개변수로 넘어가면 확정 지적으로 포함한다. 도우미가 다시 다른 도우미로 넘기는
    여러 단계도 따라간다(깊이 4). 같은 파일이면 싱크 위치에, 다른 파일이면 처음 호출한 위치에
    지적하고 via에 싱크 위치를 담는다. entry_guard가 처음 호출하는 곳의 인자에 사유를 내면, 그 싱크에 닿는
    모든 호출이 사유를 가질 때만 Hit.entry_guard에 담는다(검사 없이 닿는 호출이 하나라도 있으면 비운다)."""
    applicable = [s for s in sinks if src.lang in s.langs and not s.prop]
    assigned = [s for s in sinks if src.lang in s.langs and s.prop]
    if not applicable and not assigned:
        return
    pick = select or _default_args
    calls = list(iter_calls(src))
    merged: dict[int, Hit] = {}
    for call, arg, flow in _hits_in(src, calls, applicable, cli, pick, frozenset(), ctx):
        merged[call.node.id] = Hit(call, arg, flow)
    if assigned:
        for call, arg, flow in _hits_in(src, _assignment_calls(src), assigned, cli, pick, frozenset(), ctx):
            merged[call.node.id] = Hit(call, arg, flow)

    # (처음 호출, 처음 인자, 처음 호출하는 곳의 검사 사유, 함수 파일, 함수, 오염된 매개변수, 깊이)
    work = [
        (c, a, entry_guard(src, c, a) if entry_guard is not None else None, hs, fn, name, 1)
        for c, a, hs, fn, name in _helper_entries(src, calls, cli, ctx, confined=confined)
    ]
    guards: dict[int, str | None] = {}

    def guarded(key: int, reason: str | None) -> str | None:
        """도우미 경로로 닿은 싱크의 사유. 검사 없이 닿는 호출(직접 닿는 외부 입력 포함)이 하나라도 있으면 None"""
        if key in guards:
            guards[key] = guards[key] if reason is not None else None
        else:
            direct = merged.get(key)
            guards[key] = None if direct is not None and direct.flow is Flow.TAINTED else reason
        return guards[key]

    seen: set[tuple[int, str, int, str]] = set()
    while work:
        root_call, root_arg, reason, hsrc, fn, name, depth = work.pop()
        key = (root_call.node.id, hsrc.path.as_posix(), fn.node.id, name)
        if key in seen:
            continue
        seen.add(key)
        seeds = frozenset({name})
        inner_all = list(iter_calls(hsrc)) if hsrc is not src else calls
        inner_calls = _calls_inside(inner_all, fn)
        for inner, inner_arg, flow in _hits_in(
            hsrc, inner_calls, [s for s in sinks if hsrc.lang in s.langs], cli, select or _default_args, seeds, ctx
        ):
            if flow is not Flow.TAINTED:
                continue
            if skip is not None and skip(hsrc, inner, inner_arg, flow):
                continue
            if hsrc is src:
                merged[inner.node.id] = Hit(inner, inner_arg, flow, entry_guard=guarded(inner.node.id, reason))
            else:
                where = f"{hsrc.path.as_posix()}:{inner.line}"
                proxy = Call(root_call.node, inner.callee, root_call.args)
                merged[root_call.node.id] = Hit(proxy, root_arg, flow, via=where, entry_guard=guarded(root_call.node.id, reason))
        # 이 함수가 오염된 매개변수를 다시 다른 도우미 함수로 넘기면 한 단계 더 따라간다
        if depth >= MAX_CHAIN_DEPTH:
            note_limit(hsrc.path.as_posix(), fn.node.start_byte, "chain")
            continue
        for _call, _arg, hsrc2, fn2, name2 in _helper_entries(hsrc, inner_calls, cli, ctx, seeds, confined):
            work.append((root_call, root_arg, reason, hsrc2, fn2, name2, depth + 1))
    yield from merged.values()
