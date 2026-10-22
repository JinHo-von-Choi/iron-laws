"""
오철칙 흐름 해석기: 함수 안의 실행 순서를 따라가며 어느 변수가 오염되었는지 계산한다.
갈래(if·switch·try)는 따로 따라간 뒤 합치고, 반복문은 두 번 돌려 다음 회차로 넘어가는 값을 반영한다.
깊이·횟수 상한에 닿으면 '확인 못 함'으로 남긴다. 깨끗한 것으로 바꾸지 않는다.

흐름 해석기·분석 캐시·식의 오염 판정은 서로를 부르는 한 덩어리다. 나누면 모듈 순환이 생기므로 이 파일에 둔다.
작성자: 최진호
작성일: 2026-10-22
"""

import re
from dataclasses import dataclass

from tree_sitter import Node

import iron_laws.engine.taint.sanitizers as sanitizers
import iron_laws.engine.taint.sources as sources
import iron_laws.engine.taint.state as state
from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    FUNCTION_TYPES,
    enclosing_function,
    function_parts,
    identifiers_in,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint.nodes import (
    CASE_TYPES,
    CHAIN_TYPES,
    DEAD_END_TYPES,
    ELSE_TYPES,
    IF_TYPES,
    LOOP_TYPES,
    MARK_SUFFIXES,
    MAX_HELPER_DEPTH,
    MUTATING_METHODS,
    RETURN_TYPES,
    STATEMENT_PARENTS,
    SWITCH_TYPES,
    TRY_TYPES,
    Analysis,
    State,
    TaintResult,
)
from iron_laws.engine.taint.paths import (
    ASSIGN_TYPES,
    AUGMENTED_TYPES,
    COLLECTION_PUT,
    LOOP_ASSIGN_TYPES,
    _constant_key,
    _target_and_value,
    _target_paths,
    path_root,
    reads_tainted,
)
from iron_laws.engine.taint.resolve import _call_parts, _positional_params, param_name, resolve_any
from iron_laws.engine.taint.sanitizers import (
    _UNIVERSAL_RE,
    Ctx,
    sanitizer_name_matches,
)
from iron_laws.engine.taint.sources import (
    ANNOTATED_PARAM_RE,
    ARCHIVE_SOURCE_RE,
    _source_in,
    archive_file,
    expr_has_source,
)


def _analysis(src: SourceFile, scope: Node, cli: bool, seeds: frozenset[str], ctx: Ctx, own=None) -> Analysis:
    """흐름 해석 결과. 남은 깊이에 따라 결과가 달라지므로 깊이를 키에 넣는다.
    캐시에는 해석에 든 비용과 한도 도달 횟수를 함께 두고, 다시 쓸 때 같은 비용을 치른다. 그래서 같은 관심 지점은
    앞서 무엇을 분석했는지와 무관하게 같은 결과를 낸다. 예산이 바닥났거나 바깥 함수의 재귀를 끊은 결과는 캐시하지 않는다."""
    cache = src.__dict__.setdefault("_taint_cache", {})
    key = (scope.id, cli, seeds, ctx, state.DEPTH, sources._EXTRA_KIND, sanitizers.CUSTOM_KIND)
    index = xfile.get_index()
    if key in cache:
        analysis, cost, limits = cache[key]
        if index is not None:
            for limit in limits:
                index.note(limit)
            if index.metering and cost:
                index.spend(cost)
        return analysis
    mark = len(state.CUTS)
    charged = index.charged if index is not None else 0
    limits: set = set()
    if index is not None:
        index._collectors.append(limits)
    try:
        analysis = _Flow(src, scope, cli, seeds, ctx).run()
    finally:
        if index is not None:
            index._collectors.pop()
    if index is not None and index.exhausted:
        return analysis
    if set(state.CUTS[mark:]) - {own}:
        return analysis
    if index is None:
        cache[key] = (analysis, 0, frozenset())
    else:
        cache[key] = (analysis, index.charged - charged, frozenset(limits))
    return analysis


def taint_state(
    src: SourceFile,
    node: Node,
    cli: bool = False,
    seeds: frozenset[str] = frozenset(),
    ctx: Ctx = Ctx.ANY,
) -> frozenset[str]:
    """node가 실행되기 직전에 오염되어 있는 변수 이름의 집합"""
    scope = enclosing_function(node, src.lang) or src.root
    if scope is None:
        return frozenset()
    analysis = _analysis(src, scope, cli, seeds, ctx)
    current: Node | None = node
    while current is not None:
        found = analysis.before.get(current.id)
        if found is not None:
            return found
        current = current.parent
    return frozenset()


def _returns_tainted(src: SourceFile, fn_node: Node, seeds: frozenset[str], cli: bool, ctx: Ctx = Ctx.ANY) -> TaintResult:
    key = (src.path.as_posix(), fn_node.id, seeds, ctx)
    if key in state.IN_PROGRESS:
        # 오염된 인자가 재귀로 넘어가면 보수적으로 오염으로 본다. 오염된 인자 없이 도는 재귀(디렉터리 순회 등)는 '오염 없음'에서 시작해
        # 다른 반환 경로의 오염을 따른다(최소 고정점). 끊긴 결과는 호출 경로에 따라 달라 캐시하지 않는다
        state.CUTS.append(key)
        return TaintResult.TAINTED if seeds else TaintResult.CLEAN
    if state.DEPTH >= MAX_HELPER_DEPTH:
        xfile.note_limit(src.path.as_posix(), fn_node.start_byte, "depth")
        return TaintResult.UNKNOWN
    index = xfile.get_index()
    state.IN_PROGRESS.add(key)
    state.DEPTH += 1
    try:
        analysis = _analysis(src, fn_node, cli, seeds, ctx, own=key)
        tainted = any(expr_tainted(src, expr, set(state), cli, ctx) for expr, state in analysis.returns)
        if index is not None and index.exhausted:
            return TaintResult.UNKNOWN
        return TaintResult.TAINTED if tainted else TaintResult.CLEAN
    finally:
        state.DEPTH -= 1
        state.IN_PROGRESS.discard(key)



def _call_is_clean(src: SourceFile, parts, names: set[str], cli: bool, ctx: Ctx, by_name: bool = True) -> bool | None:
    """호출 결과가 외부 입력을 담지 않는지 판정한다. 프로젝트에 정의된 함수는 이름이 아니라 본문 동작을 따른다.
    True=깨끗함, False=오염된 값을 돌려줌, None=판단 근거 없음
    가장 바깥 호출 하나가 관심 지점이며, 그 안의 함수 간·파일 간 해석은 지점마다 같은 예산을 쓴다."""
    index = xfile.get_index()
    if state.POINT_ACTIVE:
        return _call_is_clean_in_point(src, parts, names, cli, ctx, by_name)
    state.POINT_ACTIVE = True
    start = index.limit_hits if index is not None else 0
    point = (src.path.as_posix(), parts[1][0].start_byte if parts[1] else 0, "budget:" + parts[0])
    if index is not None:
        index.begin_point()
    try:
        return _call_is_clean_in_point(src, parts, names, cli, ctx, by_name)
    finally:
        state.POINT_ACTIVE = False
        state.CUTS.clear()
        if index is not None:
            exhausted = index.exhausted
            index.end_point()
            if exhausted:
                index.limit_hits = start  # 예산 소진은 지점마다 한 번만 센다. 소진 전 기록은 분석 순서에 따라 달라진다
                index.note(point)


def _call_is_clean_in_point(src: SourceFile, parts, names: set[str], cli: bool, ctx: Ctx, by_name: bool) -> bool | None:
    callee, args = parts
    helpers = resolve_any(src, callee, len(args))
    index = xfile.get_index()
    if index is not None and index.exhausted:
        return None
    if helpers:
        result = _helper_returns_tainted(src, helpers, args, names, cli, ctx)
        if result is TaintResult.UNKNOWN:
            return None  # 끝까지 따라가지 못한 함수는 깨끗하다고 보지 않고, 인자의 오염이 결과로 전해진다고 본다
        return result is TaintResult.CLEAN
    if archive_file(src) and (
        ARCHIVE_SOURCE_RE.search(callee + "(")
        or (re.search(r"\.(getName|getFileName)$", callee) and callee.rsplit(".", 1)[0] in names)
    ):
        return False  # 압축 항목 이름(`entry.getName()`)은 이름이 정제 함수처럼 보여도 `../`가 든 외부 입력이다
    if by_name and sanitizer_name_matches(callee, ctx, src.lang):
        return True
    if not by_name and _UNIVERSAL_RE.search(callee):
        return True  # 중첩된 호출이라도 len()·int() 같은 값의 종류를 바꾸는 호출은 문자열 주입 경로가 아니다
    return None


def _helper_returns_tainted(src: SourceFile, helpers, args: list[Node], names: set[str], cli: bool, ctx: Ctx) -> TaintResult:
    outcome = TaintResult.CLEAN
    for hsrc, fn in helpers:
        params = _positional_params(hsrc, fn)
        # 인자 자리의 식도 같은 기준으로 판정한다: 인자가 오염된 값을 돌려주는 다른 함수 호출이어도 매개변수가 오염된다
        seeds = frozenset(param_name(hsrc, p) for p, a in zip(params, args, strict=False) if expr_tainted(src, a, names, cli, ctx))
        result = _returns_tainted(hsrc, fn.node, seeds, cli, ctx)
        if result is TaintResult.TAINTED:
            return result
        if result is TaintResult.UNKNOWN:
            outcome = result
    return outcome


def _clean_ranges(src: SourceFile, node: Node, names: set[str], cli: bool, ctx: Ctx) -> list[tuple[int, int]] | None:
    """식 안에 중첩된, 결과가 깨끗한 호출(프로젝트에 정의된 함수)의 바이트 범위.
    중첩된 프로젝트 함수 호출이 오염된 값을 돌려주면(함수 안에서 외부 입력을 읽는 경우 포함) None"""
    ranges: list[tuple[int, int]] = []
    stack = list(node.children)
    while stack:
        n = stack.pop()
        parts = _call_parts(src, n)
        # 도달하는 문맥이 정해져 있으면(셸·경로·SQL 등) 그 문맥에 유효한 정제 함수 호출은 중첩되어 있어도 그 호출 범위만 깨끗하다. 문맥을 모르면(ANY) 이름만으로 인정하지 않는다
        clean = _call_is_clean(src, parts, names, cli, ctx, by_name=ctx is not Ctx.ANY) if parts is not None else None
        if clean:
            ranges.append((n.start_byte, n.end_byte))
            continue
        if clean is False:
            return None
        stack.extend(n.children)
    return ranges


def expr_tainted(src: SourceFile, node: Node, names: set[str], cli: bool = False, ctx: Ctx = Ctx.ANY) -> bool:
    """이미 계산된 오염 변수 집합을 기준으로 식의 오염 여부를 판정한다."""
    parts = _call_parts(src, node)
    if parts is not None:
        clean = _call_is_clean(src, parts, names, cli, ctx)
        if clean is not None:
            return not clean
    ranges = _clean_ranges(src, node, names, cli, ctx)
    if ranges is None:
        return True
    if ranges:
        buf = bytearray(src.data[node.start_byte : node.end_byte])
        for a, b in ranges:
            for i in range(max(a, node.start_byte) - node.start_byte, min(b, node.end_byte) - node.start_byte):
                buf[i] = 32
        remaining = buf.decode("utf-8", errors="replace")
        if _source_in(remaining, cli, src.lang, archive_file(src)):
            return True
        return reads_tainted(src, node, names, skip=lambda n: any(a <= n.start_byte and n.end_byte <= b for a, b in ranges))
    if expr_has_source(src, node, cli):
        return True
    return reads_tainted(src, node, names)


def is_tainted(
    src: SourceFile,
    node: Node,
    cli: bool = False,
    seeds: frozenset[str] = frozenset(),
    ctx: Ctx = Ctx.ANY,
) -> bool:
    """식이 외부 입력에서 유래했는지(직접 사용 또는 함수 내 전파) 판정한다. cli=True면 명령행·표준입력도 포함한다.
    seeds는 오염된 것으로 가정할 변수 이름(함수 매개변수 효과 요약에 쓴다). ctx는 도달하는 곳의 종류."""
    if src.root is None:
        return expr_has_source(src, node, cli)
    state = taint_state(src, node, cli, seeds, ctx)
    return expr_tainted(src, node, set(state), cli, ctx)




def _join(*states: State) -> State:
    live = [s for s in states if s is not None]
    if not live:
        return None
    merged: set[str] = set()
    for s in live:
        merged |= s
    return frozenset(merged)


@dataclass


class _Flow:
    def __init__(self, src: SourceFile, scope: Node, cli: bool, seeds: frozenset[str], ctx: Ctx):
        self.src = src
        self.scope = scope
        self.cli = cli
        self.seeds = seeds
        self.ctx = ctx
        self.before: dict[int, frozenset[str]] = {}
        self.returns: list[tuple[Node, frozenset[str]]] = []
        self.fn_types = FUNCTION_TYPES.get(src.lang, set()) if src.lang else set()
        self.call_types = CALL_TYPES.get(src.lang, set()) if src.lang else set()

    # -- 진입점 --
    def run(self) -> Analysis:
        initial = frozenset(self.seeds) | self._annotated()
        self.before[self.scope.id] = initial
        is_function = self.scope.type in self.fn_types
        if is_function:
            body = function_parts(self.src, self.scope)[1]
            if body is None:
                return Analysis(self.before, self.returns)
            if body.type not in ("block", "statement_block", "compound_statement"):
                self.returns.append((body, initial))  # 식 본문 함수(화살표 함수 등)
                self.exec(body, initial)
            else:
                out = self._seq(body.named_children, initial)
                self._tail_expression(body, out)
        else:
            self._seq(self.scope.named_children, initial)
        return Analysis(self.before, self.returns)

    def _tail_expression(self, body: Node, out: State) -> None:
        """Rust처럼 마지막 식이 반환값인 언어"""
        if self.src.lang is None or self.src.lang.value != "rust" or not body.named_children:
            return
        last = body.named_children[-1]
        if last.type not in ("expression_statement", "let_declaration") and "comment" not in last.type:
            state = self.before.get(last.id)
            if state is not None:
                self.returns.append((last, state))

    def _annotated(self) -> frozenset[str]:
        if self.scope.type not in self.fn_types:
            return frozenset()
        params = function_parts(self.src, self.scope)[0]
        if params is None:
            declarator = self.scope.child_by_field_name("declarator")
            params = declarator.child_by_field_name("parameters") if declarator is not None else None
        if params is None:
            return frozenset()
        names: set[str] = set()
        children = params.named_children
        for i, n in enumerate(children):
            if not ANNOTATED_PARAM_RE.search(self.src.text_of(n)):
                continue
            if n.type == "parameter_modifiers" and i + 1 < len(children):  # Kotlin: 애너테이션이 매개변수 앞 형제 노드에 있다
                name = next((c for c in children[i + 1].named_children if c.type == "identifier"), None)
                if name is not None:
                    names.add(self.src.text_of(name))
            else:
                names |= identifiers_in(self.src, n)
        return frozenset(names)

    # -- 기록 --
    def _mark(self, node: Node, state: frozenset[str]) -> None:
        if node.id in self.before:
            self.before[node.id] = self.before[node.id] | state
        elif node.type.endswith(MARK_SUFFIXES) or (node.parent is not None and node.parent.type in STATEMENT_PARENTS):
            self.before[node.id] = state

    # -- 실행 --
    def _seq(self, nodes, state: State) -> State:
        for child in nodes:
            if state is None:
                return None
            if "comment" in child.type:
                continue
            state = self.exec(child, state)
        return state

    def exec(self, node: Node, state: State) -> State:
        if state is None:
            return None
        t = node.type
        if "comment" in t:
            return state
        if t in self.fn_types:
            return state  # 중첩 함수는 자기 범위에서 따로 분석한다
        self._mark(node, state)
        if t in RETURN_TYPES:
            return self._return(node, state)
        if t in DEAD_END_TYPES:
            return None
        if t in IF_TYPES:
            return self._if(node, state)
        if t in SWITCH_TYPES:
            return self._switch(node, state)
        if t in TRY_TYPES:
            return self._try(node, state)
        if t in LOOP_TYPES:
            return self._loop(node, state)
        return self._generic(node, state)

    def _generic(self, node: Node, state: State) -> State:
        for child in node.children:
            if state is None:
                return None
            if child.is_named:
                state = self.exec(child, state)
        return self._apply(node, state)

    def _return(self, node: Node, state: frozenset[str]) -> State:
        values = [c for c in node.named_children if "comment" not in c.type]
        for v in values:
            state = self.exec(v, state) or state
        if values:
            self.returns.append((values[0], state))
        return None

    def _if(self, node: Node, state: frozenset[str]) -> State:
        branch_fields = ("consequence", "alternative", "body")
        branches = [c for f in branch_fields for c in node.children_by_field_name(f)]
        branch_ids = {b.id for b in branches}
        header_state: State = state
        for child in node.named_children:
            if child.id in branch_ids or "comment" in child.type:
                continue
            header_state = self.exec(child, header_state) if header_state is not None else None
        if header_state is None:
            return None
        if not branches:
            return header_state
        outs = [self.exec(b, header_state) for b in branches]
        merged = _join(*outs)
        if node.type in CHAIN_TYPES:
            return merged
        if not self._has_final_else(node):
            merged = _join(merged, header_state)
        return merged

    def _has_final_else(self, node: Node) -> bool:
        alts = node.children_by_field_name("alternative")
        if not alts:
            return False
        last = alts[-1]
        if last.type in CHAIN_TYPES:
            return False
        if last.type in IF_TYPES:
            return self._has_final_else(last)
        if last.type in ELSE_TYPES:
            inner = [c for c in last.named_children if "comment" not in c.type]
            if len(inner) == 1 and inner[0].type in IF_TYPES:
                return self._has_final_else(inner[0])
            return True
        return True

    def _switch(self, node: Node, state: frozenset[str]) -> State:
        cases: list[Node] = []
        stack = list(reversed(node.children))
        while stack:
            n = stack.pop()
            if n.type in CASE_TYPES:
                cases.append(n)
                continue
            if n.type in SWITCH_TYPES or n.type in self.fn_types:
                continue
            stack.extend(reversed(n.children))
        case_ids = {c.id for c in cases}
        header: State = state
        for child in node.named_children:
            if child.type in ("switch_body", "switch_block", "match_block", "block", "body") or child.id in case_ids:
                continue
            header = self.exec(child, header) if header is not None else None
        if header is None:
            return None
        if not cases:
            return self._generic_children(node, header)
        outs = [self._seq(c.named_children, header) for c in cases]
        has_default = any("default" in c.type or self.src.text_of(c).lstrip().startswith("default") or self.src.text_of(c).lstrip().startswith("_ ") for c in cases)
        return _join(*outs) if has_default else _join(*outs, header)

    def _generic_children(self, node: Node, state: frozenset[str]) -> State:
        return self._seq(node.named_children, state)

    def _try(self, node: Node, state: frozenset[str]) -> State:
        body = node.child_by_field_name("body")
        handlers: list[Node] = []
        else_clause = None
        finally_clause = None
        header: State = state
        for child in node.named_children:
            if child.id == (body.id if body is not None else -1) or "comment" in child.type:
                continue
            if "catch" in child.type or "except" in child.type:
                handlers.append(child)
            elif "finally" in child.type:
                finally_clause = child
            elif child.type in ELSE_TYPES:
                else_clause = child
            else:
                header = self.exec(child, header) if header is not None else None
        if header is None:
            return None
        try_out = self.exec(body, header) if body is not None else header
        entry = _join(header, try_out) or header
        outs: list[State] = [self.exec(else_clause, try_out) if else_clause is not None and try_out is not None else try_out]
        outs.extend(self.exec(h, entry) for h in handlers)
        merged = _join(*outs)
        if finally_clause is not None:
            return self.exec(finally_clause, _join(merged, entry) or entry)
        return merged

    def _loop(self, node: Node, state: frozenset[str]) -> State:
        body = node.child_by_field_name("body")
        alternative = node.child_by_field_name("alternative")  # Python for-else
        header: State = state
        if node.type in LOOP_ASSIGN_TYPES:
            header = self._assign(node, header, kill=False)
        for child in node.named_children:
            if (body is not None and child.id == body.id) or (alternative is not None and child.id == alternative.id):
                continue
            if "comment" in child.type or header is None:
                continue
            header = self.exec(child, header)
        if header is None:
            return None
        if body is None:
            return header
        first = self.exec(body, header)
        second = self.exec(body, _join(header, first) or header)
        merged = _join(header, first, second) or header
        if alternative is not None:
            merged = _join(merged, self.exec(alternative, merged))
        return merged

    # -- 문장 효과 --
    def _apply(self, node: Node, state: State) -> State:
        if state is None:
            return None
        if node.type in ASSIGN_TYPES and node.type not in LOOP_ASSIGN_TYPES:
            return self._assign(node, state, kill=node.type not in AUGMENTED_TYPES)
        if node.type in self.call_types:
            parts = _call_parts(self.src, node)
            if parts and "." in parts[0] and parts[0].rsplit(".", 1)[-1] in MUTATING_METHODS:
                receiver = parts[0].rsplit(".", 1)[0]
                m = re.match(r"[A-Za-z_$][\w$]*", receiver)
                method = parts[0].rsplit(".", 1)[-1]
                key = _constant_key(self.src, parts[1][0]) if method in COLLECTION_PUT and len(parts[1]) >= 2 and re.fullmatch(r"[A-Za-z_$][\w$]*", receiver) else None
                if key is not None:
                    path = f"{receiver.lstrip('$')}[{key}]"
                    if any(expr_tainted(self.src, a, set(state), self.cli, self.ctx) for a in parts[1][1:]):
                        return state | {path}
                    return state - {path}  # 상수 키에 깨끗한 값을 넣으면 그 키는 깨끗하다
                if m and any(expr_tainted(self.src, a, set(state), self.cli, self.ctx) for a in parts[1]):
                    return state | {m.group(0).lstrip("$")}
        return state

    def _assign(self, node: Node, state: State, kill: bool) -> State:
        if state is None:
            return None
        left, right = _target_and_value(node)
        if left is None or right is None:
            return state
        names, strong = _target_paths(self.src, left)
        if not names:
            return state
        if node.type in LOOP_ASSIGN_TYPES and self.src.lang is Lang.PYTHON:
            callee = (_call_parts(self.src, right) or ("", []))[0]
            if callee == "range":
                return state  # range()가 만드는 반복 변수는 정수라 문자열 주입 경로가 아니다
            if callee == "enumerate":
                first = re.match(r"\s*\(?\s*([A-Za-z_]\w*)", self.src.text_of(left))
                if first:
                    names = names - {first.group(1)}  # enumerate의 첫 값(순번)은 정수다
        if expr_tainted(self.src, right, set(state), self.cli, self.ctx):
            return state | names
        if kill and strong:
            # 변수 전체를 새 값으로 바꾸면 그 변수의 필드 경로도 함께 지운다
            whole = {n for n in names if n == path_root(n)}
            return frozenset(n for n in state if n not in names and path_root(n) not in whole)
        return state


