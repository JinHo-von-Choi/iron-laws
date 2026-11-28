"""
오철칙 안전 면제 판정 도구: 검증 분기가 실제로 실행 흐름을 끊는지, 검증한 값이 싱크까지 같은 값인지 확인한다
문자열 속 `return`이나 조건부로만 실행되는 검사, 검사 뒤 재대입을 안전 근거로 인정하지 않기 위한 것이다.
작성자: 최진호
작성일: 2026-10-05
"""

import re
from dataclasses import dataclass, field

from tree_sitter import Node

from iron_laws.engine.ast_tools import CALL_TYPES, iter_calls, walk
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import CONDITIONAL_TYPES, definitions

TERMINATOR_TYPES = frozenset(
    {"return_statement", "raise_statement", "throw_statement", "continue_statement", "break_statement", "return_expression"}
)
EXIT_CALL_RE = re.compile(r"^(sys\.exit|exit|quit|abort|os\._exit|die|panic|process\.exit|os\.Exit|log\.Fatal\w*|Environment\.Exit)$")
BLOCK_TYPES = frozenset({"block", "statement_block", "compound_statement", "declaration_list"})


def _statements(consequence: Node) -> list[Node]:
    """분기 본문의 문장들. 중괄호 없는 한 문장 본문은 그 문장 자체"""
    if consequence.type in BLOCK_TYPES:
        return [c for c in consequence.named_children if "comment" not in c.type]
    return [consequence]


def terminates(src: SourceFile, consequence: Node | None) -> bool:
    """분기 본문이 최상위 문장으로 실행을 끊는다(return·raise·throw·continue·break 또는 종료 호출).
    문자열이나 주석 속의 단어, 중첩된 조건 안의 return은 인정하지 않는다."""
    if consequence is None:
        return False
    for statement in _statements(consequence):
        if statement.type in TERMINATOR_TYPES:
            return True
        if statement.type == "expression_statement":
            for child in statement.named_children:
                call = _call_of(src, child)
                if call is not None and EXIT_CALL_RE.search(call):
                    return True
    return False


def _call_of(src: SourceFile, node: Node) -> str | None:
    inner = node.named_children[0] if node.type == "await_expression" and node.named_children else node
    if src.lang is None or inner.type not in CALL_TYPES.get(src.lang, set()):
        return None
    index = src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(src)})
    call = index.get(inner.id)
    return call.callee if call is not None else None


def executes_unconditionally(node: Node, scope: Node) -> bool:
    """node가 scope 안에서 어떤 분기·반복·예외 처리의 조건도 거치지 않고 실행된다"""
    current = node.parent
    while current is not None and current.id != scope.id:
        if current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


HANDLER_TYPES = frozenset({"except_clause", "catch_clause"})


def _handlers_terminate(src: SourceFile, try_node: Node) -> bool:
    handlers = [c for c in try_node.named_children if c.type in HANDLER_TYPES]
    for handler in handlers:
        body = handler.child_by_field_name("body") or next((c for c in handler.named_children if c.type in BLOCK_TYPES), None)
        if body is None:
            return False
        if not terminates(src, body):
            return False
    return bool(handlers)


def runs_before(src: SourceFile, node: Node, at: Node, scope: Node) -> bool:
    """at까지 가는 모든 경로에서 node가 먼저 실행된다. executes_unconditionally와 같되,
    try 본문 안의 node는 예외 처리 분기가 모두 실행을 끊으면 무조건 실행으로 본다(예외가 나면 at에 닿지 않는다)"""
    if node.end_byte > at.start_byte:
        return False
    stop = shared_scope(node, at, scope)
    current = node.parent
    while current is not None and current.id != stop.id:
        if current.type == "try_statement":
            body = current.child_by_field_name("body") or next((c for c in current.named_children if c.type in BLOCK_TYPES), None)
            if body is None or not (body.start_byte <= node.start_byte and node.end_byte <= body.end_byte) or not _handlers_terminate(src, current):
                return False
            if any(c.type in ("finally_clause",) and c.start_byte <= at.start_byte < c.end_byte for c in current.named_children):
                return False  # finally는 예외 처리 분기가 끝낸 뒤에도 실행된다
        elif current.type in CONDITIONAL_TYPES:
            return False
        current = current.parent
    return True


def shared_scope(a: Node, b: Node, scope: Node) -> Node:
    """a와 b를 함께 감싸는 가장 가까운 노드(없으면 scope). 반복문 안에서 항목마다 하는 검사는 그 반복 본문을 기준으로
    무조건 실행되는지 본다. 검사가 싱크와 다른 분기 안에 있으면 이 노드까지 올라가는 길에 조건이 끼어 인정되지 않는다."""
    ancestors = set()
    current = b
    while current is not None and current.id != scope.id:
        ancestors.add(current.id)
        current = current.parent
    current = a.parent
    while current is not None and current.id != scope.id:
        if current.id in ancestors:
            # 두 노드가 같은 조건문의 서로 다른 분기에 있으면 그 조건문 바깥을 기준으로 삼아, 분기 안의 노드가 조건부임을 드러낸다
            return current.parent if current.type in CONDITIONAL_TYPES and current.parent is not None else current
        current = current.parent
    return scope


def redefined_between(src: SourceFile, scope: Node, name: str, start: int, end: int) -> bool:
    """[start, end) 사이에서 name에 새 값이 대입되는지(증분 대입 포함). 검증한 값이 싱크까지 같은 값인지 본다."""
    for value in definitions(src, scope, name):
        holder = value.parent
        position = holder.start_byte if holder is not None else value.start_byte
        if start <= position < end:
            return True
    return False


def mutated_between(src: SourceFile, scope: Node, name: str, start: int, end: int) -> bool:
    """대입뿐 아니라 `name.update(...)`·`name[...] = ...`처럼 값을 바꾸는 호출·인덱스 대입도 본다."""
    if redefined_between(src, scope, name, start, end):
        return True
    pattern = re.compile(rf"\b{re.escape(name)}\s*(\.(append|extend|insert|update|pop|remove|clear|add|discard|setdefault|replace)\(|\[[^\]]*\]\s*=)")
    for node in walk(scope):
        if node.type in ("expression_statement", "assignment") and start <= node.start_byte < end and pattern.search(src.text_of(node)):
            return True
    return False


@dataclass
class PassFacts:
    """거부 분기를 통과한 경로에서 변수 하나에 대해 성립하는 사실"""

    blocked: set[str] = field(default_factory=set)  # 값에 들어 있지 않은 리터럴(차단 목록 검사)
    validated: set[str] = field(default_factory=set)  # 사용자 명세의 검사 함수를 통과한 문맥(Ctx 값)
    digits: bool = False  # 값이 숫자로만 이루어진다
    quoted: set[str] = field(default_factory=set)  # 값이 이 따옴표로 감싼 문자열 리터럴 하나다(안쪽에 같은 따옴표 없음)
    lines: list[int] = field(default_factory=list)  # 근거가 된 검사 줄

    def describe(self) -> str:
        parts = []
        if self.blocked:
            parts.append(", ".join(repr(b) for b in sorted(self.blocked)) + " 포함")
        if self.quoted:
            parts.append("문자열 리터럴이 아닌 값")
        if self.digits:
            parts.append("숫자가 아닌 값")
        if self.validated:
            parts.append("선언한 검사 함수를 통과하지 못한 값")
        return "·".join(parts)


DIGIT_PATTERN_RE = re.compile(r"^\^?(?:\\d|\[0-9\])[+*](?:\$|\\Z)?$")
_START_END = {"startswith": "starts", "endswith": "ends", "startsWith": "starts", "endsWith": "ends"}


def _unwrap(node: Node) -> Node:
    while node.type in ("parenthesized_expression",) and node.named_children:
        node = node.named_children[0]
    return node


def _or_terms(src: SourceFile, cond: Node) -> list[Node]:
    """거부 조건을 or(||)로 나눈 항. 통과한 경로에서는 모든 항이 거짓이다"""
    cond = _unwrap(cond)
    if cond.type in ("boolean_operator", "binary_expression"):
        operator = cond.child_by_field_name("operator")
        if operator is not None and src.text_of(operator) in ("or", "||"):
            left, right = cond.child_by_field_name("left"), cond.child_by_field_name("right")
            return [*(_or_terms(src, left) if left is not None else []), *(_or_terms(src, right) if right is not None else [])]
    return [cond]


def _negated(node: Node) -> Node | None:
    node = _unwrap(node)
    if node.type == "not_operator":
        inner = node.child_by_field_name("argument") or (node.named_children[0] if node.named_children else None)
        return _unwrap(inner) if inner is not None else None
    if node.type in ("unary_expression", "prefix_unary_expression") and node.child_by_field_name("operator") is not None and node.child_by_field_name("operator").type == "!":
        inner = node.child_by_field_name("operand") or node.child_by_field_name("argument")  # Java·C#은 operand, JS·TS는 argument
        return _unwrap(inner) if inner is not None else None
    return None


def _subject(src: SourceFile, node: Node | None) -> tuple[str, bool] | None:
    """검사 대상 변수 이름과, 앞뒤 한 글자를 뺀 안쪽(`v[1:-1]`)인지"""
    if node is None:
        return None
    node = _unwrap(node)
    if node.type == "identifier":
        return src.text_of(node), False
    if node.type == "subscript" and src.text_of(node.child_by_field_name("subscript") or node).replace(" ", "") == "1:-1":
        value = node.child_by_field_name("value")
        if value is not None and value.type == "identifier":
            return src.text_of(value), True
    return None


def _method_call(src: SourceFile, node: Node) -> tuple[str, str, list[Node]] | None:
    """(수신자 원문, 메서드 이름, 인자들). Python call·Java method_invocation"""
    if node.type == "call":
        function, arguments = node.child_by_field_name("function"), node.child_by_field_name("arguments")
        if function is None or function.type != "attribute" or arguments is None:
            return None
        target, attribute = function.child_by_field_name("object"), function.child_by_field_name("attribute")
        if target is None or attribute is None:
            return None
        return src.text_of(target), src.text_of(attribute), [a for a in arguments.named_children if "comment" not in a.type]
    if node.type == "method_invocation":
        target, name, arguments = node.child_by_field_name("object"), node.child_by_field_name("name"), node.child_by_field_name("arguments")
        if target is None or name is None or arguments is None:
            return None
        return src.text_of(target), src.text_of(name), [a for a in arguments.named_children if "comment" not in a.type]
    if node.type in ("call_expression", "invocation_expression"):
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or function.type not in ("member_expression", "member_access_expression"):
            return None
        target = function.child_by_field_name("object") or function.child_by_field_name("expression")
        name = function.child_by_field_name("property") or function.child_by_field_name("name")
        if target is None or name is None:
            return None
        args = [a.named_children[0] if a.type == "argument" and a.named_children else a for a in arguments.named_children if "comment" not in a.type]
        return src.text_of(target), src.text_of(name), args
    return None


def _literal(src: SourceFile, node: Node) -> str | None:
    if node.type in ("string", "string_literal") and not any(c.type == "interpolation" for c in node.children):
        from iron_laws.engine.ast_tools import string_value

        # 따옴표·역슬래시 이스케이프만 푼다: '\'' → '
        return re.sub(r"\\(['\"\\])", r"\1", string_value(src, node))
    return None


def _validator_fact(src: SourceFile, term: Node, negated: bool) -> tuple[str, str, str] | None:
    """사용자 명세의 검사 함수 호출이면 (검사한 변수, validated, 막는 문맥). 거부 조건이므로 참이면 안전한 함수는 부정형으로 쓰여야 한다"""
    callee = _call_of(src, term)
    if callee is None:
        return None
    from iron_laws.engine.taint.sanitizers import custom_validator

    found = custom_validator(callee, src.lang)
    if found is None:
        return None
    arg_at, success, ctx = found
    index = src.memo("call_by_id", lambda: {c.node.id: c for c in iter_calls(src)})
    call = index.get(_unwrap(term).id)
    args = call.args if call is not None else []
    if arg_at >= len(args) or args[arg_at].type not in ("identifier", "variable_name") or negated != success:
        return None
    return src.text_of(args[arg_at]).lstrip("$"), "validated", ctx.value


def _term_fact(src: SourceFile, term: Node) -> tuple[str, str, str] | None:
    """거부 조건의 항 하나를 (변수, 종류, 리터럴)로 읽는다. 종류: contains, contains_inner, not_digits, not_starts, not_ends,
    validated(사용자 명세의 검사 함수, 리터럴 자리에 막는 문맥)"""
    term = _unwrap(term)
    inner = _negated(term)
    validated = _validator_fact(src, inner if inner is not None else term, inner is not None)
    if validated is not None:
        return validated
    if inner is not None:
        call = _method_call(src, inner)
        if call is not None:
            receiver, method, args = call
            if method in ("isdigit", "isnumeric", "isdecimal") and not args and re.fullmatch(r"\w+", receiver):
                return receiver, "not_digits", ""
            if method == "matches" and len(args) == 1 and (lit := _literal(src, args[0])) is not None and DIGIT_PATTERN_RE.match(lit) and re.fullmatch(r"\w+", receiver):
                return receiver, "not_digits", ""
            if method in _START_END and len(args) == 1 and (lit := _literal(src, args[0])) is not None and re.fullmatch(r"\w+", receiver):
                return receiver, "not_" + _START_END[method], lit
            if receiver == "re" and method in ("fullmatch", "match") and len(args) >= 2 and (lit := _literal(src, args[0])) is not None:
                subject = _subject(src, args[1])
                anchored = method == "fullmatch" or lit.endswith(("$", "\\Z"))
                if subject is not None and not subject[1] and anchored and DIGIT_PATTERN_RE.match(lit):
                    return subject[0], "not_digits", ""
        return None
    if term.type == "comparison_operator" and len(term.named_children) == 2:
        left, right = term.named_children
        between = src.data[left.end_byte : right.start_byte].decode("utf-8", errors="replace").strip()
        lit = _literal(src, left)
        subject = _subject(src, right)
        if between == "in" and lit is not None and subject is not None:
            return subject[0], "contains_inner" if subject[1] else "contains", lit
        return None
    call = _method_call(src, term)
    if call is not None:
        receiver, method, args = call
        if method == "contains" and len(args) == 1 and (lit := _literal(src, args[0])) is not None and re.fullmatch(r"\w+", receiver):
            return receiver, "contains", lit
    if term.type == "binary_expression":
        left, right = term.child_by_field_name("left"), term.child_by_field_name("right")
        operator = term.child_by_field_name("operator")
        if left is not None and right is not None and operator is not None:
            op, bound = src.text_of(operator), src.text_of(right).replace(" ", "")
            if (op, bound) in (("!=", "-1"), (">=", "0"), (">", "-1")):
                call = _method_call(src, _unwrap(left))
                if call is not None and call[1] == "indexOf" and len(call[2]) == 1 and (lit := _literal(src, call[2][0])) is not None and re.fullmatch(r"\w+", call[0]):
                    return call[0], "contains", lit
    return None


def passing_facts(src: SourceFile, scope: Node, at: Node) -> dict[str, PassFacts]:
    """at(싱크 호출)보다 앞서 무조건 실행되고, 조건이 참이면 실행을 끊는 if 문들에서 통과한 경로의 사실을 모은다.
    검사한 변수가 검사와 at 사이에 다시 대입되면 그 사실은 버린다"""
    facts: dict[str, PassFacts] = {}
    for node in walk(scope):
        if node.type != "if_statement" or node.end_byte > at.start_byte:
            continue
        cond = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if cond is None or not terminates(src, consequence):
            continue
        if not runs_before(src, node, at, scope):
            continue
        per_var: dict[str, list[tuple[str, str]]] = {}
        for term in _or_terms(src, cond):
            fact = _term_fact(src, term)
            if fact is not None:
                per_var.setdefault(fact[0], []).append((fact[1], fact[2]))
        for variable, items in per_var.items():
            if redefined_between(src, scope, variable, node.end_byte, at.start_byte):
                continue
            entry = facts.setdefault(variable, PassFacts())
            entry.lines.append(src.line_of(node))
            kinds = {(k, lit) for k, lit in items}
            for kind, lit in kinds:
                if kind == "contains":
                    entry.blocked.add(lit)
                elif kind == "not_digits":
                    entry.digits = True
                elif kind == "validated":
                    entry.validated.add(lit)
            for q in ("'", '"'):
                if {("not_starts", q), ("not_ends", q), ("contains_inner", q)} <= kinds:
                    entry.quoted.add(q)
    return facts
