"""Java SQL 문자열의 닫힌 값 근거. 해석되지 않은 객체·호출은 정상으로 바꾸지 않는다."""

import re

from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import (
    call_index,
    enclosing_function,
    is_literal,
    walk_no_nested_functions,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.taint import definitions, param_name, reaching_definitions


def is_closed_java(src, node, depth=0, seen=frozenset()):
    if src.lang is not Lang.JAVA or depth > 8 or node.id in seen:
        return False
    seen = seen | {node.id}
    if is_literal(node):
        return True
    if node.type in ('binary_expression', 'parenthesized_expression', 'cast_expression'):
        children = [n for n in node.named_children if n.type not in ('type_identifier', 'integral_type')]
        return bool(children) and all(is_closed_java(src, n, depth + 1, seen) for n in children)
    if node.type == 'ternary_expression':
        choices = [node.child_by_field_name(k) for k in ('consequence', 'alternative')]
        return all(n is not None and is_closed_java(src, n, depth + 1, seen) for n in choices)
    scope = enclosing_function(node, src.lang)
    if scope is None:
        return False
    if node.type == 'identifier':
        name = src.text_of(node)
        params = scope.child_by_field_name('parameters')
        if params and any(param_name(src, p) == name for p in params.named_children):
            return False
        defs = [d for d in reaching_definitions(src, scope, name, node.start_byte) if d.end_byte <= node.start_byte]
        # 수신자를 조작하거나 외부 호출에 전달한 컬렉션의 상태는 보류한다.
        for call in call_index(src).all:
            if call.node.start_byte >= node.start_byte or enclosing_function(call.node, src.lang) != scope:
                continue
            if call.callee.startswith(name + '.') and call.callee != name + '.get':
                return False
            if any(src.text_of(arg) == name for arg in call.args):
                return False
        return bool(defs) and all(is_closed_java(src, d, depth + 1, seen) for d in defs)
    if node.type != 'method_invocation':
        return False
    call = next((c for c in call_index(src).all if c.node.id == node.id), None)
    if call is None:
        return False
    if call.callee in ('java.util.List.of', 'List.of'):
        qualified = src.text_of(node).startswith('java.util.List.of(')
        if call.callee == 'List.of' and not qualified and not re.search(r'import\s+java\.util\.List\s*;', src.code_text):
            return False
        if re.search(r'class\s+List\b', src.code_text) or definitions(src, scope, 'List') or any(param_name(src, p) == 'List' for p in (scope.child_by_field_name('parameters').named_children if scope.child_by_field_name('parameters') else [])):
            return False
        return all(is_closed_java(src, arg, depth + 1, seen) for arg in call.args)
    if call.callee.endswith('.get'):
        receiver = node.child_by_field_name('object')
        return receiver is not None and is_closed_java(src, receiver, depth + 1, seen) and all(is_literal(a) for a in call.args)
    index = xfile.get_index()
    if index is None:
        return False
    owner = call.callee.split('.')[0]
    params = scope.child_by_field_name('parameters')
    if definitions(src, scope, owner) or params and any(param_name(src, p) == owner for p in params.named_children):
        return False
    helpers = index.resolve_java_static(src, call.callee, len(call.args))
    if not helpers:
        return False
    for hsrc, fn in helpers:
        returns = [n for n in walk_no_nested_functions(fn.body, hsrc.lang) if n.type == 'return_statement'] if fn.body else []
        if not returns or not all(n.named_children and is_closed_java(hsrc, n.named_children[0], depth + 1, seen) for n in returns):
            return False
    return True
