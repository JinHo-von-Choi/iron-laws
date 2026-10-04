"""
오철칙 경량 오염(taint) 분석: 함수 내부의 외부 입력 전파 추적

실행 순서를 따라가는 흐름 분석이다. 문장마다 그 문장이 실행되기 직전의 오염 변수 집합을 계산하고,
분기(if·switch·try)에서는 갈래별로 따로 실행한 뒤 합치며, 반복문은 두 번 돌려 반복 간 전달을 반영한다.
싱크는 자기 위치의 상태로 판정하므로 뒤따르는 재대입이 앞선 위험한 사용을 가리지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from tree_sitter import Node

from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    FUNCTION_TYPES,
    NESTING_TYPES,
    STRING_TYPES,
    enclosing_function,
    identifiers_in,
    iter_calls,
    iter_functions,
    walk,
)
from iron_laws.engine.languages import Lang
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
AUGMENTED_TYPES = ("augmented_assignment", "augmented_assignment_expression", "compound_assignment_expr")
LOOP_ASSIGN_TYPES = {"enhanced_for_statement", "for_in_statement", "foreach_statement", "for_statement", "range_clause"}


def _target_and_value(node: Node) -> tuple[Node | None, Node | None]:
    if node.type in LOOP_ASSIGN_TYPES:
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


def _text_without_plain_strings(src: SourceFile, node: Node) -> str:
    """보간이 없는 문자열 리터럴의 내용을 지운 식의 원문. 문자열 안에 적힌 `request.args` 같은 글자는 코드가 아니다."""
    buf = bytearray(src.data[node.start_byte : node.end_byte])
    for n in walk(node):
        if n.type in STRING_TYPES and "interpol" not in n.type and not any("interpol" in c.type for c in n.children):
            for i in range(n.start_byte - node.start_byte, n.end_byte - node.start_byte):
                buf[i] = 32
    return buf.decode("utf-8", errors="replace")


def expr_has_source(src: SourceFile, node: Node, cli: bool = False) -> bool:
    text = src.text_of(node)
    if not (WEB_SOURCE_RE.search(text) or (cli and CLI_SOURCE_RE.search(text))):
        return False
    if src.root is None:
        return True
    # 원문에서 입력 원천처럼 보이는 글자가 보이면, 그것이 문자열 리터럴 안의 글자인지 코드인지 가려서 다시 본다
    code = _text_without_plain_strings(src, node)
    return bool(WEB_SOURCE_RE.search(code)) or (cli and bool(CLI_SOURCE_RE.search(code)))


# ---------------------------------------------------------------------------
# 정제 함수: 취약점 문맥별로 유효한 정제만 인정한다
# ---------------------------------------------------------------------------


class Ctx(StrEnum):
    """오염된 값이 도달하는 곳의 종류. 정제는 자기가 막는 문맥에서만 인정된다."""

    ANY = "any"
    HTML = "html"
    SQL = "sql"
    SHELL = "shell"
    PATH = "path"
    URL = "url"
    LDAP = "ldap"
    XPATH = "xpath"
    CODE = "code"
    HEADER = "header"


def _fn_re(names: str) -> re.Pattern[str]:
    return re.compile(rf"(?i)(?:^|[._])(?:{names})$")


# 값의 종류를 바꾸거나 값에서 파생된 수치여서 어느 문맥에서든 문자열 주입을 막는 함수
_UNIVERSAL = "parseint|parsefloat|int|float|bool|number|len|length|abs|round|hashpw|hexdigest|digest|uuid\\w*|isdigit|isnumeric"
# 이름이 검증·허용 목록임을 말하는 함수. 무엇을 막는지는 알 수 없으므로 모든 문맥에서 인정한다.
_GENERIC = "sanitiz\\w*|validat\\w*|whitelist\\w*|allowlist\\w*|is_?safe\\w*"
_BY_CONTEXT: dict[Ctx, str] = {
    Ctx.HTML: "escape\\w*|encode_?for_?html\\w*|encode_?html\\w*|for_?html\\w*|htmlspecialchars|htmlentities|esc_html\\w*|dompurify|bleach|clean",
    Ctx.SQL: "escape\\w*|quote\\w*|encode_?for_?sql\\w*|addslashes|real_escape\\w*|format_?sql",
    Ctx.SHELL: "quote\\w*|escapeshell\\w*|shellescape|shellwords|escape\\w*",
    Ctx.PATH: "secure_filename|basename|getname|filepath\\.base|getfilename|sanitize_?filename|safe_?join|safe_?path|clean",
    Ctx.URL: "",
    Ctx.LDAP: "escape\\w*|encode_?for_?ldap\\w*|escape_filter_chars",
    Ctx.XPATH: "escape\\w*|encode_?for_?xpath\\w*|quote\\w*",
    Ctx.CODE: "",
    Ctx.HEADER: "escape\\w*|encode\\w*|quote\\w*|clean",
}
# 문맥을 모르는 호출(기본값)은 위 이름을 모두 인정한다.
_ALL_NAMES = "|".join(
    dict.fromkeys(n for names in [_UNIVERSAL, _GENERIC, "encode\\w*", *_BY_CONTEXT.values()] for n in names.split("|") if n)
)
SANITIZER_FN_RE = _fn_re(_ALL_NAMES)
_CONTEXT_SANITIZERS: dict[Ctx, re.Pattern[str]] = {
    ctx: _fn_re("|".join(n for n in (_UNIVERSAL + "|" + _GENERIC + "|" + names).split("|") if n))
    for ctx, names in _BY_CONTEXT.items()
}


_UNIVERSAL_RE = _fn_re(_UNIVERSAL)
_BASE_SANITIZERS = _fn_re(f"{_UNIVERSAL}|{_GENERIC}")
# HTML 출력용 이스케이프는 이름이 escape라도 SQL·셸·경로에는 아무 보호도 하지 못한다
_HTML_ONLY_RE = re.compile(
    r"(?i)(?:^|\.)(?:html|cgi|markupsafe|saxutils|bleach|dompurify|xml)\.|escape_?html|htmlspecialchars|htmlentities|encode_?for_?html|esc_html|for_?html"
)


def sanitizer_name_matches(callee: str, ctx: Ctx) -> bool:
    if ctx is Ctx.ANY:
        return bool(SANITIZER_FN_RE.search(callee))
    if ctx is not Ctx.HTML and _HTML_ONLY_RE.search(callee):
        return bool(_BASE_SANITIZERS.search(callee))
    return bool(_CONTEXT_SANITIZERS[ctx].search(callee))


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
_IN_PROGRESS: set[tuple[str, int, frozenset[str], Ctx]] = set()
_DEPTH = 0
MAX_HELPER_DEPTH = 4


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


def param_name(src: SourceFile, param: Node) -> str:
    name = param.child_by_field_name("name") or param.child_by_field_name("pattern")
    if name is not None:
        return src.text_of(name).lstrip("$")
    for n in walk(param):
        if n.type in ("identifier", "variable_name") and n.child_count in (0, 2):
            return src.text_of(n).lstrip("$")
    return ""


def _positional_params(src: SourceFile, fn) -> list[Node]:
    return [p for p in fn.params if src.text_of(p) not in ("self", "cls")]


def resolve_helper(src: SourceFile, callee: str, argc: int):
    """같은 파일에 정의된 함수 중 호출과 이름·인자 수가 맞는 것"""
    last = callee.rsplit(".", 1)[-1]
    receiver = callee.rsplit(".", 1)[0] if "." in callee else ""
    if receiver and not (receiver in ("this", "self") or receiver.startswith("new") or receiver[:1].isupper()):
        return []
    return [fn for fn in _function_index(src).get(last, []) if len(_positional_params(src, fn)) == argc]


def resolve_any(src: SourceFile, callee: str, argc: int) -> list[tuple[SourceFile, object]]:
    """같은 파일 함수를 먼저, 없으면 프로젝트의 다른 파일(Python 시범 지원)에서 호출 대상을 찾는다."""
    local = [(src, fn) for fn in resolve_helper(src, callee, argc)]
    if local:
        return local
    return xfile.resolve_external(src, callee, argc)


# ---------------------------------------------------------------------------
# 실행 순서를 따르는 흐름 해석기
# ---------------------------------------------------------------------------

RETURN_TYPES = {"return_statement", "return_expression"}
DEAD_END_TYPES = {"raise_statement", "throw_statement", "throw_expression"}
IF_TYPES = {"if_statement", "if_expression", "elif_clause", "else_if_clause"}
CHAIN_TYPES = {"elif_clause", "else_if_clause"}
ELSE_TYPES = {"else_clause", "else"}
SWITCH_TYPES = {
    "switch_statement",
    "switch_expression",
    "expression_switch_statement",
    "type_switch_statement",
    "match_expression",
    "match_statement",
    "select_statement",
}
CASE_TYPES = {
    "switch_case",
    "switch_default",
    "switch_block_statement_group",
    "switch_section",
    "case_clause",
    "expression_case",
    "default_case",
    "type_case",
    "communication_case",
    "match_arm",
    "switch_rule",
}
LOOP_TYPES = {
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "loop_expression",
    "for_expression",
    "while_expression",
}
TRY_TYPES = {"try_statement", "try_expression"}
MARK_SUFFIXES = ("statement", "declaration", "_clause", "_arm", "_case", "_rule", "_section", "block")
SCOPE_ROOT_TYPES = {"module", "program", "source_file", "translation_unit", "compilation_unit"}

State = frozenset[str] | None  # None은 이 경로가 끝났음(return·throw)을 뜻한다


def _join(*states: State) -> State:
    live = [s for s in states if s is not None]
    if not live:
        return None
    merged: set[str] = set()
    for s in live:
        merged |= s
    return frozenset(merged)


@dataclass
class Analysis:
    before: dict[int, frozenset[str]]
    returns: list[tuple[Node, frozenset[str]]]


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
            body = self.scope.child_by_field_name("body")
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
        params = self.scope.child_by_field_name("parameters")
        if params is None:
            declarator = self.scope.child_by_field_name("declarator")
            params = declarator.child_by_field_name("parameters") if declarator is not None else None
        if params is None:
            return frozenset()
        names: set[str] = set()
        for n in params.named_children:
            if ANNOTATED_PARAM_RE.search(self.src.text_of(n)):
                names |= identifiers_in(self.src, n)
        return frozenset(names)

    # -- 기록 --
    def _mark(self, node: Node, state: frozenset[str]) -> None:
        if node.id in self.before:
            self.before[node.id] = self.before[node.id] | state
        elif node.type.endswith(MARK_SUFFIXES) or (node.parent is not None and node.parent.type in SCOPE_ROOT_TYPES):
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
                if m and any(expr_tainted(self.src, a, set(state), self.cli, self.ctx) for a in parts[1]):
                    return state | {m.group(0).lstrip("$")}
        return state

    def _assign(self, node: Node, state: State, kill: bool) -> State:
        if state is None:
            return None
        left, right = _target_and_value(node)
        if left is None or right is None:
            return state
        names = _target_names(self.src, left)
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
        if kill:
            return state - names
        return state


def _analysis(src: SourceFile, scope: Node, cli: bool, seeds: frozenset[str], ctx: Ctx) -> Analysis:
    cache = src.__dict__.setdefault("_taint_cache", {})
    key = (scope.id, cli, seeds, ctx)
    if key not in cache:
        cache[key] = _Flow(src, scope, cli, seeds, ctx).run()
    return cache[key]


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


def _returns_tainted(src: SourceFile, fn_node: Node, seeds: frozenset[str], cli: bool, ctx: Ctx = Ctx.ANY) -> bool:
    global _DEPTH
    key = (src.path.as_posix(), fn_node.id, seeds, ctx)
    if key in _IN_PROGRESS:
        return True  # 재귀는 보수적으로 오염으로 본다
    if _DEPTH >= MAX_HELPER_DEPTH:
        xfile.note_limit()
        return False
    _IN_PROGRESS.add(key)
    _DEPTH += 1
    try:
        analysis = _analysis(src, fn_node, cli, seeds, ctx)
        return any(expr_tainted(src, expr, set(state), cli, ctx) for expr, state in analysis.returns)
    finally:
        _DEPTH -= 1
        _IN_PROGRESS.discard(key)


# ---------------------------------------------------------------------------
# 식의 오염 판정
# ---------------------------------------------------------------------------


def _call_is_clean(src: SourceFile, parts, names: set[str], cli: bool, ctx: Ctx, by_name: bool = True) -> bool | None:
    """호출 결과가 외부 입력을 담지 않는지 판정한다. 프로젝트에 정의된 함수는 이름이 아니라 본문 동작을 따른다.
    True=깨끗함, False=오염된 값을 돌려줌, None=판단 근거 없음"""
    callee, args = parts
    helpers = resolve_any(src, callee, len(args))
    if helpers:
        return not _helper_returns_tainted(src, helpers, args, names, cli, ctx)
    if by_name and sanitizer_name_matches(callee, ctx):
        return True
    if not by_name and _UNIVERSAL_RE.search(callee):
        return True  # 중첩된 호출이라도 len()·int() 같은 값의 종류를 바꾸는 호출은 문자열 주입 경로가 아니다
    return None


def _helper_returns_tainted(src: SourceFile, helpers, args: list[Node], names: set[str], cli: bool, ctx: Ctx) -> bool:
    for hsrc, fn in helpers:
        params = _positional_params(hsrc, fn)
        seeds = frozenset(
            param_name(hsrc, p)
            for p, a in zip(params, args, strict=False)
            if expr_has_source(src, a, cli) or (identifiers_in(src, a) & names)
        )
        if _returns_tainted(hsrc, fn.node, seeds, cli, ctx):
            return True
    return False


def _clean_ranges(src: SourceFile, node: Node, names: set[str], cli: bool, ctx: Ctx) -> list[tuple[int, int]]:
    """식 안에 중첩된, 결과가 깨끗한 호출(프로젝트에 정의된 함수)의 바이트 범위"""
    ranges: list[tuple[int, int]] = []
    stack = list(node.children)
    while stack:
        n = stack.pop()
        parts = _call_parts(src, n)
        if parts is not None and _call_is_clean(src, parts, names, cli, ctx, by_name=False):
            ranges.append((n.start_byte, n.end_byte))
            continue
        stack.extend(n.children)
    return ranges


def _identifiers_outside(src: SourceFile, node: Node, ranges: list[tuple[int, int]]) -> set[str]:
    def inside(n: Node) -> bool:
        return any(a <= n.start_byte and n.end_byte <= b for a, b in ranges)

    names: set[str] = set()
    for n in walk(node):
        if inside(n):
            continue
        if n.type in ("identifier", "variable_name", "property_identifier", "field_identifier"):
            if n.child_count == 0 or n.type == "variable_name":
                names |= identifiers_in(src, n)
    return names


def expr_tainted(src: SourceFile, node: Node, names: set[str], cli: bool = False, ctx: Ctx = Ctx.ANY) -> bool:
    """이미 계산된 오염 변수 집합을 기준으로 식의 오염 여부를 판정한다."""
    parts = _call_parts(src, node)
    if parts is not None:
        clean = _call_is_clean(src, parts, names, cli, ctx)
        if clean is not None:
            return not clean
    ranges = _clean_ranges(src, node, names, cli, ctx)
    if ranges:
        buf = bytearray(src.data[node.start_byte : node.end_byte])
        for a, b in ranges:
            for i in range(max(a, node.start_byte) - node.start_byte, min(b, node.end_byte) - node.start_byte):
                buf[i] = 32
        remaining = buf.decode("utf-8", errors="replace")
        if WEB_SOURCE_RE.search(remaining) or (cli and CLI_SOURCE_RE.search(remaining)):
            return True
        return bool(_identifiers_outside(src, node, ranges) & names)
    if expr_has_source(src, node, cli):
        return True
    return bool(identifiers_in(src, node) & names)


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


# ---------------------------------------------------------------------------
# 정의 추적 (문자열 조합 여부 판정용)
# ---------------------------------------------------------------------------


def _unconditional(node: Node, scope: Node) -> bool:
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def reaching_definitions(src: SourceFile, scope: Node, name: str, before: int) -> list[Node]:
    """before 위치의 name에 도달하는 대입 우변들. 무조건 실행되는 마지막 대입 뒤에는 그 이전 대입이 도달하지 못한다."""
    defs = definitions(src, scope, name)
    prior = sorted((d for d in defs if d.end_byte <= before), key=lambda d: d.start_byte)
    if not prior:
        return defs
    last_sure = -1
    for i, d in enumerate(prior):
        holder = d.parent
        if _unconditional(d, scope) and not (holder is not None and holder.type in AUGMENTED_TYPES):
            last_sure = i
    return prior[last_sure:] if last_sure >= 0 else prior


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
