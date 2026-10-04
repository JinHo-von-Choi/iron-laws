"""
오철칙 경량 오염(taint) 분석: 함수 내부의 외부 입력 전파 추적
작성자: 최진호
작성일: 2026-10-04
"""

import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    NESTING_TYPES,
    enclosing_function,
    identifiers_in,
    iter_calls,
    iter_functions,
    walk,
    walk_no_nested_functions,
)
from iron_laws.engine.source import SourceFile

WEB_SOURCE_RE = re.compile(
    r"""(?x)
    \brequest\.(args|form|values|json|data|files|cookies|headers|GET|POST|query_params|
                path_params|get_json|get_data|environ|META|FILES|body|query|params|url|path)\b
    | \brequest\.(getParameter\w*|getHeader\w*|getQueryString|getCookies|getInputStream|getReader|getPart\w*|getPathInfo|getPathTranslated|getRequestURI|getRequestURL|getContentType|getRemoteHost)\b
    | \breq\.(query|body|params|cookies|headers|url|originalUrl|path|files|file|hostname)\b
    | \bctx\.(query|request|params|req)\b
    | \bRequest\.(Query|Form|Headers|Cookies|Body|QueryString|Params|Path|Url|RawUrl|Files)\b
    | \bHttpContext\.Request\b
    | \$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b
    | \br\.(FormValue|PostFormValue|URL\.Query|URL\.Path|Header\.Get|Body|Form|PostForm|MultipartForm)\b
    | \bc\.(Query|Param|PostForm|GetHeader|BindJSON|ShouldBind\w*|DefaultQuery|FormValue|Params)\b
    | \.getOriginalFilename\s*\( | \.FileName\b | \bheader\.Filename\b | \bfile\.filename\b | \bfile\.name\b | \boriginalname\b
    | \bwindow\.location\b | \blocation\.(search|hash|href)\b | \bdocument\.(cookie|URL|referrer)\b
    | \.searchParams\b | \bURLSearchParams\b | \bFromQuery\b | \bFromBody\b | \bFromRoute\b | \bFromForm\b
    | \bweb::(Query|Path|Json|Form)\b | \bquery_params\b | \bpath_params\b
    """,
)
CLI_SOURCE_RE = re.compile(
    r"""(?x)
    \b(input|raw_input)\s*\( | \bsys\.argv\b | \bprocess\.argv\b | \bos\.Args\b | \bargv\[ | \bstd::env::args\b
    | \bscanf\s*\( | \bgets\s*\( | \bfgets\s*\( | \bgetline\s*\( | \bcin\s*>>
    """,
)
SOURCE_RE = WEB_SOURCE_RE
ANNOTATED_PARAM_RE = re.compile(
    r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|QueryParam|PathParam|FormParam)"
    r"|\[(FromQuery|FromBody|FromRoute|FromForm|FromHeader)\b"
)

ASSIGN_TYPES = {
    "assignment",
    "augmented_assignment",
    "variable_declarator",
    "assignment_expression",
    "short_var_declaration",
    "assignment_statement",
    "let_declaration",
    "init_declarator",
    "augmented_assignment_expression",
    "compound_assignment_expr",
    "enhanced_for_statement",
    "for_in_statement",
    "foreach_statement",
    "for_statement",
    "range_clause",
}


def _target_and_value(node: Node) -> tuple[Node | None, Node | None]:
    if node.type in ("enhanced_for_statement", "for_in_statement", "foreach_statement", "for_statement", "range_clause"):
        loop_var = node.child_by_field_name("name") or node.child_by_field_name("left")
        iterable = node.child_by_field_name("value") or node.child_by_field_name("right")
        return loop_var, iterable
    left = node.child_by_field_name("left") or node.child_by_field_name("name") or node.child_by_field_name("pattern")
    right = node.child_by_field_name("right") or node.child_by_field_name("value")
    if left is None and node.type == "init_declarator":
        left = node.child_by_field_name("declarator")
    if right is None and node.type == "variable_declarator":
        seen_equals = False
        for child in node.children:
            if child.type == "equals_value_clause" and child.named_children:
                right = child.named_children[-1]
            elif child.type == "=":
                seen_equals = True
            elif seen_equals and child.is_named:
                right = child
                break
    return left, right


def _target_names(src: SourceFile, target: Node) -> set[str]:
    return identifiers_in(src, target) if target.type != "member_expression" else set()


def expr_has_source(src: SourceFile, node: Node, cli: bool = False) -> bool:
    text = src.text_of(node)
    return bool(WEB_SOURCE_RE.search(text)) or (cli and bool(CLI_SOURCE_RE.search(text)))


SANITIZER_FN_RE = re.compile(
    r"(?i)(?:^|[._])(?:sanitiz\w*|escape\w*|encode\w*|quote\w*|clean\w*|validat\w*|whitelist\w*|allowlist\w*|secure_filename|normali[sz]e\w*|parseint|parsefloat|int|float|bool|number|len|length|abs|round|hashpw|hexdigest|digest|uuid\w*|isdigit|isnumeric)$"
)
MUTATING_METHODS = frozenset(
    {"add", "append", "put", "push", "extend", "insert", "offer", "addAll", "putAll", "setdefault", "update", "set", "write", "concat"}
)
CONDITIONAL_TYPES = NESTING_TYPES | {
    "conditional_expression",
    "ternary_expression",
    "catch_clause",
    "except_clause",
    "switch_case",
    "case_clause",
    "match_arm",
    "elif_clause",
    "else_clause",
    "finally_clause",
}
_IN_PROGRESS: set[tuple[int, frozenset[str]]] = set()


def _call_parts(src: SourceFile, node: Node):
    """호출 노드의 (피호출자 문자열, 인자 노드 목록)을 반환한다. 호출이 아니면 None."""
    if src.lang is None or node.type not in CALL_TYPES.get(src.lang, set()):
        return None
    index = src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(src)})
    call = index.get(node.id)
    return (call.callee, call.args) if call is not None else None


def _function_index(src: SourceFile) -> dict[str, list]:
    def build():
        index: dict[str, list] = {}
        for fn in iter_functions(src):
            index.setdefault(fn.name, []).append(fn)
        return index

    return src.memo("fn_index", build)


def _param_name(src: SourceFile, param: Node) -> str:
    name = param.child_by_field_name("name") or param.child_by_field_name("pattern")
    if name is not None:
        return src.text_of(name).lstrip("$")
    for n in walk(param):
        if n.type in ("identifier", "variable_name") and n.child_count in (0, 2):
            return src.text_of(n).lstrip("$")
    return ""


def _resolve_helper(src: SourceFile, callee: str, argc: int):
    last = callee.rsplit(".", 1)[-1]
    receiver = callee.rsplit(".", 1)[0] if "." in callee else ""
    if receiver and not (receiver in ("this", "self") or receiver.startswith("new") or receiver[:1].isupper()):
        return []
    matches = []
    for fn in _function_index(src).get(last, []):
        params = [p for p in fn.params if src.text_of(p) not in ("self", "cls")]
        if len(params) == argc:
            matches.append(fn)
    return matches


def _returns_tainted(src: SourceFile, fn, seeds: frozenset[str], cli: bool) -> bool:
    key = (fn.node.id, seeds)
    if key in _IN_PROGRESS:
        return True
    _IN_PROGRESS.add(key)
    try:
        names = tainted_names(src, fn.node, cli, seeds)
        returns = [n for n in walk_no_nested_functions(fn.node, src.lang) if n.type in ("return_statement", "return_expression")]
        expressions = [r.named_children[0] for r in returns if r.named_children]
        if not returns and fn.body is not None and fn.body.type not in ("block", "statement_block", "compound_statement"):
            expressions = [fn.body]
        return any(expr_tainted(src, e, names, cli) for e in expressions)
    finally:
        _IN_PROGRESS.discard(key)


def expr_tainted(src: SourceFile, node: Node, names: set[str], cli: bool = False) -> bool:
    """이미 계산된 오염 변수 집합을 기준으로 식의 오염 여부를 판정한다."""
    parts = _call_parts(src, node)
    if parts is not None:
        callee, args = parts
        if SANITIZER_FN_RE.search(callee):
            return False
        helpers = _resolve_helper(src, callee, len(args))
        if helpers:
            for fn in helpers:
                params = [p for p in fn.params if src.text_of(p) not in ("self", "cls")]
                seeds = frozenset(
                    _param_name(src, p)
                    for p, a in zip(params, args, strict=False)
                    if expr_has_source(src, a, cli) or (identifiers_in(src, a) & names)
                )
                if _returns_tainted(src, fn, seeds, cli):
                    return True
            return False
    if expr_has_source(src, node, cli):
        return True
    return bool(identifiers_in(src, node) & names)


def tainted_names(src: SourceFile, scope: Node, cli: bool = False, seeds: frozenset[str] = frozenset()) -> set[str]:
    cache_key = (scope.id, cli, seeds)
    cached = src.__dict__.setdefault("_taint_cache", {})
    if cache_key in cached:
        return cached[cache_key]

    tainted: set[str] = set(seeds)
    events: list[tuple[str, Node, set[str], Node | None, bool]] = []
    call_types = CALL_TYPES.get(src.lang, set()) if src.lang else set()
    for n in walk(scope):
        if n.type in ASSIGN_TYPES:
            left, right = _target_and_value(n)
            if left is not None and right is not None:
                names = _target_names(src, left)
                if names:
                    events.append(("assign", n, names, right, _unconditional(n, scope)))
        elif n.type in call_types:
            parts = _call_parts(src, n)
            if parts and "." in parts[0] and parts[0].rsplit(".", 1)[-1] in MUTATING_METHODS:
                receiver = parts[0].rsplit(".", 1)[0]
                m = re.match(r"[A-Za-z_$][\w$]*", receiver)
                if m:
                    events.append(("mutate", n, {m.group(0).lstrip("$")}, None, False))
        elif n.type in ("parameter", "formal_parameter", "typed_parameter", "required_parameter"):
            if ANNOTATED_PARAM_RE.search(src.text_of(n)):
                tainted |= identifiers_in(src, n)

    for _ in range(2):
        for kind, node, names, right, unconditional in events:
            if kind == "assign" and right is not None:
                if expr_tainted(src, right, tainted, cli):
                    tainted |= names
                elif unconditional and node.type not in ("augmented_assignment", "augmented_assignment_expression", "compound_assignment_expr"):
                    tainted -= names - set(seeds)
            else:
                parts = _call_parts(src, node)
                if parts and any(expr_tainted(src, a, tainted, cli) for a in parts[1]):
                    tainted |= names
    cached[cache_key] = tainted
    return tainted


def _unconditional(node: Node, scope: Node) -> bool:
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def is_tainted(src: SourceFile, node: Node, cli: bool = False) -> bool:
    """식이 외부 입력에서 유래했는지(직접 사용 또는 함수 내 전파) 판정한다. cli=True면 명령행·표준입력도 포함한다."""
    scope = enclosing_function(node, src.lang) or src.root
    if scope is None:
        return expr_has_source(src, node, cli)
    return expr_tainted(src, node, tainted_names(src, scope, cli), cli)


def definitions(src: SourceFile, scope: Node, name: str) -> list[Node]:
    """범위 안에서 name에 대입되는 우변 식들을 반환한다."""
    cache = src.__dict__.setdefault("_defs_cache", {})
    key = scope.id
    if key not in cache:
        table: dict[str, list[Node]] = {}
        for n in walk(scope):
            if n.type in ASSIGN_TYPES:
                left, right = _target_and_value(n)
                if left is None or right is None:
                    continue
                for ident in _target_names(src, left):
                    table.setdefault(ident, []).append(right)
        cache[key] = table
    return cache[key].get(name, [])
