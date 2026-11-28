"""
닫힌 값 판정: 식의 값이 코드만으로 정해지는 상수 문자열·숫자인지 본다. 상수 계산(constants.py)과 도달 정의(definitions.py)를 함께 쓴다.
작성자: 최진호
작성일: 2026-11-12
"""

import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import enclosing_function
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint.constants import (
    _PAREN,
    LANGS,
    MAX_DEPTH,
    UNKNOWN,
    _literal,
    _operator,
    condition_value,
    const_value,
    in_dead_branch,
    list_get_is_literal,
    python_container_get_is_literal,
    route_segment_is_literal,
)
from iron_laws.engine.taint.definitions import reaching_definitions
from iron_laws.engine.taint.nodes import ternary_parts


def is_closed_value(src: SourceFile, node: Node | None, depth: int = 0) -> bool:
    """값이 코드만으로 정해지는 상수 문자열·숫자인지. 실행되지 않는 갈래의 정의는 보지 않는다. 모르면 False"""
    if node is None or src.lang not in LANGS or depth > MAX_DEPTH:
        return False
    if _literal(src, node) is not UNKNOWN or const_value(src, node) is not UNKNOWN:
        return True
    if node.type in _PAREN:
        inner = [c for c in node.named_children if "comment" not in c.type]
        return len(inner) == 1 and is_closed_value(src, inner[0], depth + 1)
    if node.type in ("binary_expression", "binary_operator") and _operator(src, node) == "+":
        operands = [c for c in node.named_children if "comment" not in c.type]
        return len(operands) == 2 and all(is_closed_value(src, c, depth + 1) for c in operands)
    if node.type in ("ternary_expression", "conditional_expression"):
        parts = ternary_parts(node)
        known = condition_value(src, parts[0]) if parts is not None else None
        return known is not None and is_closed_value(src, parts[1] if known else parts[2], depth + 1)
    if node.type == "method_invocation":
        return list_get_is_literal(src, node) or _helper_returns_closed(src, node, depth) or _resolved_returns_closed(src, node, depth)
    if node.type == "string" and src.lang is Lang.PYTHON:
        # f-문자열: 보간한 식이 모두 닫힌 값이면 닫혀 있다
        parts = [c for c in node.named_children if c.type == "interpolation"]
        return bool(parts) and all(
            any(is_closed_value(src, e, depth + 1) for e in p.named_children if e.type not in ("format_specifier", "type_conversion"))
            for p in parts
        )
    if node.type == "subscript" and src.lang is Lang.PYTHON:
        return python_container_get_is_literal(src, node) or route_segment_is_literal(src, node)
    if node.type == "call" and src.lang is Lang.PYTHON:
        return python_container_get_is_literal(src, node) or _pure_python_call_closed(src, node, depth) or _resolved_returns_closed(src, node, depth)
    if node.type == "cast_expression":
        return is_closed_value(src, node.child_by_field_name("value"), depth + 1)
    if node.type == "identifier":
        scope = enclosing_function(node, src.lang)
        if scope is None:
            return False
        name = src.text_of(node)
        params = scope.child_by_field_name("parameters")
        if params is not None and re.search(rf"\b{re.escape(name)}\b", src.text_of(params)):
            return False
        defs = [d for d in reaching_definitions(src, scope, name, node.start_byte) if d.end_byte <= node.start_byte and not in_dead_branch(src, d)]
        return bool(defs) and all(is_closed_value(src, d, depth + 1) for d in defs)
    return False


# 값만 바꾸고 바깥 상태를 읽지 않는 Python 함수·메서드. 인자(메서드는 수신자까지)가 모두 닫힌 값이면 결과도 닫힌 값이다
PURE_PY_FUNCTIONS = re.compile(r"^(?:base64\.\w+|binascii\.(?:hexlify|unhexlify|a2b_\w+|b2a_\w+)|codecs\.(?:encode|decode)|bytes|str|bytes\.fromhex|urllib\.parse\.(?:quote|unquote)\w*)$")
PURE_PY_METHODS = frozenset({"encode", "decode", "strip", "lstrip", "rstrip", "lower", "upper", "replace"})


def _pure_python_call_closed(src: SourceFile, call: Node, depth: int) -> bool:
    function, arguments = call.child_by_field_name("function"), call.child_by_field_name("arguments")
    if function is None or arguments is None or arguments.type != "argument_list":
        return False
    args = [a for a in arguments.named_children if "comment" not in a.type]
    if any(a.type in ("keyword_argument", "list_splat", "dictionary_splat") for a in args):
        return False
    if PURE_PY_FUNCTIONS.match(src.text_of(function)):
        return bool(args) and all(is_closed_value(src, a, depth + 1) for a in args)
    if function.type == "attribute":
        method, receiver = function.child_by_field_name("attribute"), function.child_by_field_name("object")
        if method is not None and receiver is not None and src.text_of(method) in PURE_PY_METHODS:
            return is_closed_value(src, receiver, depth + 1) and all(is_closed_value(src, a, depth + 1) for a in args)
    return False


def _resolved_returns_closed(src: SourceFile, call: Node, depth: int) -> bool:
    """호출 대상이 프로젝트 함수 하나로 정해지고(지역 객체의 메서드 포함) 그 함수의 모든 반환값이 상수이면 True"""
    # 호출 해석 모듈이 도달 정의를 거쳐 이 모듈을 쓰므로 함수 안에서 가져온다
    from iron_laws.engine.taint.resolve import _call_parts, resolve_any

    parts = _call_parts(src, call)
    if parts is None:
        return False
    receiver = parts[0].rsplit(".", 1)[0] if "." in parts[0] else ""
    scope = enclosing_function(call, src.lang)
    if receiver and re.fullmatch(r"[A-Za-z_$][\w$]*", receiver) and scope is not None and reaching_definitions(src, scope, receiver, call.start_byte):
        # 지역 변수에서 부른 메서드는 그 변수에 담긴 객체의 클래스로만 정한다(같은 이름의 클래스 static 메서드가 아니다)
        from iron_laws.engine.taint.resolve import _local_object_methods

        targets = _local_object_methods(src, parts[0], len(parts[1]), call)
    else:
        targets = resolve_any(src, parts[0], len(parts[1]), at=call)
    if len(targets) != 1:
        return False
    target, fn = targets[0]
    returns = []
    stack = [fn.node.child_by_field_name("body")]
    while stack:
        n = stack.pop()
        if n is None or n.type in ("lambda", "lambda_expression", "class_body", "class_definition", "function_definition", "method_declaration"):
            continue  # 안쪽 함수·클래스의 return은 이 함수의 반환이 아니다
        if n.type == "return_statement":
            returns.append(n)
            continue
        stack.extend(n.children)
    values = [r.named_children[0] for r in returns if r.named_children]
    return bool(values) and len(values) == len(returns) and all(is_closed_value(target, v, depth + 1) for v in values)


def _helper_returns_closed(src: SourceFile, call: Node, depth: int) -> bool:
    """같은 파일에 이름·인자 수가 같은 메서드가 하나뿐이고 그 메서드의 모든 반환값이 상수이면 True"""
    name = call.child_by_field_name("name")
    args = call.child_by_field_name("arguments")
    if src.lang is not Lang.JAVA or name is None or args is None:
        return False
    method, count = src.text_of(name), len([a for a in args.named_children if "comment" not in a.type])
    candidates = []
    for n in src.nodes:
        if n.type == "method_declaration" and src.text_of(n.child_by_field_name("name") or n) == method:
            params = n.child_by_field_name("parameters")
            if params is not None and len([p for p in params.named_children if p.type in ("formal_parameter", "spread_parameter")]) == count:
                candidates.append(n)
    if len(candidates) != 1 or candidates[0].child_by_field_name("body") is None:
        return False
    returns = []
    stack = [candidates[0].child_by_field_name("body")]
    while stack:
        n = stack.pop()
        if n.type in ("lambda_expression", "class_body", "method_declaration"):
            continue
        if n.type == "return_statement":
            returns.append(n)
            continue
        stack.extend(n.children)
    values = [r.named_children[0] for r in returns if r.named_children]
    return bool(values) and len(values) == len(returns) and all(is_closed_value(src, v, depth + 1) for v in values)
