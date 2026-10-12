"""장부의 닫힌 값·전파·호출자 근거 평가."""


import re
from dataclasses import dataclass, field

from tree_sitter import Node

from iron_laws.core.contract import Contract
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    WEB_SOURCE_RE,
    Ctx,
    definitions,
    param_name,
    reaching_definitions,
    resolve_any,
    sanitizer_name_matches,
)
from iron_laws.rules.injection import (
    SinkRule,
)

PURE_CALLS = frozenset(
    {
        "str", "int", "float", "bool", "repr", "len", "abs", "round", "min", "max", "sum", "sorted", "list", "tuple",
        "dict", "set", "frozenset", "range", "enumerate", "zip", "reversed", "bytes", "bytearray", "chr", "ord", "hex",
        "format", "ascii", "any", "all", "map", "filter", "isinstance", "type",
        "os.path.join", "os.path.basename", "os.path.dirname", "os.path.abspath", "os.path.normpath", "os.path.realpath",
        "os.path.splitext", "os.path.split", "os.path.expanduser", "os.path.exists", "os.path.isfile", "os.path.isdir",
        "os.getcwd", "pathlib.Path", "Path", "shlex.quote", "shlex.split", "json.dumps", "uuid.uuid4", "time.time",
        "datetime.now", "datetime.datetime.now", "text", "sa.text", "sqlalchemy.text",
    }
)
STR_METHODS = frozenset(
    {
        "format", "join", "strip", "lstrip", "rstrip", "lower", "upper", "title", "replace", "split", "rsplit", "splitlines",
        "encode", "decode", "startswith", "endswith", "zfill", "ljust", "rjust", "center", "casefold", "capitalize",
        "joinpath", "with_suffix", "with_name", "resolve", "absolute", "parent", "name", "stem", "suffix", "as_posix",
        "get", "items", "keys", "values", "append", "extend", "copy",
    }
)
ENV_ACCESS_RE = re.compile(r"^os\.(?:environ|getenv)|^environ")
CLI_INPUT_RE = re.compile(r"\bsys\.argv\b|\binput\s*\(|\bargparse\b|\bsys\.stdin\b")
MAX_CLOSED_DEPTH = 8
@dataclass
class _Context:
    contract: Contract
    callers: dict[tuple[str, int], list[tuple[SourceFile, Call]]] = field(default_factory=dict)
    modeled: dict[str, list] = field(default_factory=dict)
    rules: dict[str, SinkRule] = field(default_factory=dict)


class _Closed:
    """식의 모든 입력이 상수이거나 확인된 닫힌 값인지 판정한다. 확정하지 못하면 (False, 이유)를 돌려준다."""

    def __init__(self, src: SourceFile, ctx: _Context, taint_ctx: Ctx = Ctx.ANY):
        self.src = src
        self.ctx = ctx
        self.taint_ctx = taint_ctx  # 이 지점이 속한 계열(명령·경로·SQL)에서 유효한 정제만 인정한다

    def check(self, node: Node, depth: int = 0, seen: frozenset[int] = frozenset()) -> tuple[bool, str]:
        if depth > MAX_CLOSED_DEPTH:
            return False, "해석 깊이 한도에 도달했다"
        if node.id in seen:
            return True, ""
        seen = seen | {node.id}
        src = self.src
        t = node.type
        text = src.text_of(node)
        if is_literal(node) or t in ("integer", "float", "true", "false", "none", "ellipsis"):
            return True, ""
        if t in CALL_TYPES.get(Lang.PYTHON, set()) and self._sanitized_call(node):
            return True, ""
        if WEB_SOURCE_RE.search(text):
            return False, "외부 입력이 섞여 있다"
        if t == "identifier":
            return self._identifier(node, depth, seen)
        if t in ("attribute", "subscript"):
            return self._attribute_or_subscript(node, text, depth, seen)
        if t in CALL_TYPES.get(Lang.PYTHON, set()):
            return self._call(node, depth, seen)
        if t == "conditional_expression" and len(node.named_children) >= 3:
            branches = [node.named_children[0], node.named_children[-1]]  # 값이 되는 두 갈래. 어느 쪽을 고르는 조건은 값의 닫힘과 무관하다
            for branch in branches:
                ok, reason = self.check(branch, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        if t in ("lambda", "generator_expression", "yield", "await"):
            return False, f"{t} 식의 값을 추적하지 않는다"
        # 문자열 보간·이항 연산·조건식·컨테이너 등은 하위 식이 모두 닫혀 있으면 닫혀 있다
        for child in node.named_children:
            if "comment" in child.type:
                continue
            ok, reason = self.check(child, depth + 1, seen)
            if not ok:
                return False, reason
        return True, ""

    def _sanitized_call(self, node: Node) -> bool:
        """int()·정제 함수처럼 이 계열에서 값을 무해하게 만드는 호출(프로젝트에 정의된 함수는 제외 — 본문을 따른다)"""
        index = self.src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(self.src)})
        call = index.get(node.id)
        if call is None or resolve_any(self.src, call.callee, len(call.args)):
            return False
        return sanitizer_name_matches(call.callee, self.taint_ctx, self.src.lang)

    def _identifier(self, node: Node, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        name = self.src.text_of(node)
        if name in ("True", "False", "None", "__file__", "__name__"):
            return True, ""
        scope = enclosing_function(node, Lang.PYTHON) or self.src.root
        if scope is None:
            return False, f"변수 {name}의 범위를 알 수 없다"
        defs = reaching_definitions(self.src, scope, name, node.start_byte)
        if defs:
            for d in defs:
                ok, reason = self.check(d, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        # 함수 매개변수
        fn = enclosing_function(node, Lang.PYTHON)
        if fn is not None:
            params = fn.child_by_field_name("parameters")
            names = [param_name(self.src, p) for p in (params.named_children if params else [])]
            if name in names:
                return self._parameter(fn, name, depth, seen)
        # 모듈 수준 상수
        module_defs = [d for d in definitions(self.src, self.src.root, name) if enclosing_function(d, Lang.PYTHON) is None] if self.src.root else []
        if module_defs:
            for d in module_defs:
                ok, reason = self.check(d, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        return False, f"변수 {name}의 값이 어디서 오는지 확정하지 못했다(가져온 이름·전역·내포식 변수 등)"

    def _parameter(self, fn: Node, name: str, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        func = next((f for f in iter_functions(self.src) if f.node.id == fn.id), None)
        if func is None:
            return False, f"매개변수 {name}의 호출자를 찾지 못했다"
        sites = self.ctx.callers.get((self.src.path.as_posix(), fn.id), [])
        if not sites:
            return False, f"매개변수 {name}를 넘기는 호출자를 프로젝트에서 찾지 못했다(외부에서 호출되는 함수일 수 있다)"
        params = [p for p in func.params if self.src.text_of(p) not in ("self", "cls")]
        index = next((i for i, p in enumerate(params) if param_name(self.src, p) == name), None)
        if index is None:
            return False, f"매개변수 {name}의 위치를 알 수 없다"
        for caller_src, call in sites:
            if index >= len(call.args):
                return False, f"호출자가 매개변수 {name}를 넘기지 않아 기본값에 의존한다"
            ok, reason = _Closed(caller_src, self.ctx, self.taint_ctx).check(call.args[index], depth + 1, seen)
            if not ok and WEB_SOURCE_RE.search(caller_src.text_of(call.args[index])):
                continue  # 호출자에서 외부 입력이 닿는 흐름은 지적으로 따로 나타난다
            if not ok:
                return False, f"호출자 {caller_src.path.as_posix()}:{call.line}의 인자가 닫혀 있지 않다: {reason}"
        return True, ""

    def _attribute_or_subscript(self, node: Node, text: str, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        compact = re.sub(r"\s+", "", text)
        if ENV_ACCESS_RE.match(compact):
            if "env" in self.ctx.contract.trusted_sources:
                return True, ""
            return False, "환경변수 값은 신뢰된 출처로 선언되지 않았다"
        if CLI_INPUT_RE.search(text):
            return False, "명령행·표준입력 값이다"
        if node.type == "subscript":
            base = node.child_by_field_name("value")
            index = node.child_by_field_name("subscript")
            parts = [p for p in (base, index) if p is not None]
            for part in parts:
                ok, reason = self.check(part, depth + 1, seen)
                if not ok:
                    return False, reason
            return True, ""
        obj = node.child_by_field_name("object")
        if obj is not None and obj.type == "identifier" and self.src.text_of(obj) in ("self", "cls"):
            return False, f"객체 속성 {compact}의 값을 추적하지 않는다"
        if obj is not None:
            ok, reason = self.check(obj, depth + 1, seen)
            if ok:
                return True, ""  # 닫힌 객체의 속성(예: 문자열·경로의 속성)
        return False, f"{compact}의 값을 추적하지 않는다(모듈·객체 속성)"

    def _call(self, node: Node, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        index = self.src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(self.src)})
        call = index.get(node.id)
        if call is None:
            return False, "호출을 해석하지 못했다"
        callee = call.callee
        text = self.src.text_of(node)
        if ENV_ACCESS_RE.match(re.sub(r"\s+", "", callee)):
            if "env" in self.ctx.contract.trusted_sources:
                return True, ""
            return False, "환경변수 값은 신뢰된 출처로 선언되지 않았다"
        if CLI_INPUT_RE.search(text):
            return False, "명령행·표준입력 값이다"
        helpers = resolve_any(self.src, callee, len(call.args))
        args_ok = self._args_closed(call, depth, seen)
        if helpers:
            for hsrc, fn in helpers:
                ok, reason = self._helper_returns_closed(hsrc, fn, depth, seen)
                if not ok:
                    return False, reason
            return (True, "") if args_ok[0] else args_ok
        if sanitizer_name_matches(callee, self.taint_ctx, self.src.lang):
            return True, ""
        last = callee.rsplit(".", 1)[-1]
        if callee in PURE_CALLS or (("." in callee) and last in STR_METHODS):
            if "." in callee and callee not in PURE_CALLS:
                func = node.child_by_field_name("function")
                receiver = func.child_by_field_name("object") if func is not None else None
                if receiver is not None:
                    ok, reason = self.check(receiver, depth + 1, seen)
                    if not ok:
                        return False, reason
            return args_ok
        return False, f"미해석 호출 {callee}()의 반환값을 확인하지 못했다"

    def _args_closed(self, call: Call, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        for arg in call.args:
            ok, reason = self.check(arg, depth + 1, seen)
            if not ok:
                return False, reason
        return True, ""

    def _helper_returns_closed(self, hsrc: SourceFile, fn, depth: int, seen: frozenset[int]) -> tuple[bool, str]:
        if hsrc.root is None:
            return False, "다른 파일 함수를 읽지 못했다"
        returns = [n for n in _walk(fn.node) if n.type == "return_statement" and n.named_children]
        if not returns:
            return True, ""
        checker = _Closed(hsrc, self.ctx, self.taint_ctx)
        for r in returns:
            ok, reason = checker.check(r.named_children[0], depth + 1, seen)
            if not ok:
                return False, f"{fn.name}()의 반환값: {reason}"
        return True, ""


def _walk(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))
