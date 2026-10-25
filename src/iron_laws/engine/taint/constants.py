"""
상수 계산: 조건·switch 선택값·리스트 원소가 코드만으로 정해지는 경우를 계산해, 실행되지 않는 갈래를 흐름 해석에서 뺀다.

- 계산할 수 있는 것: 숫자·문자·문자열·참거짓 리터럴, 괄호, 사칙·나머지·비교·논리 연산, 상수 문자열의 charAt(상수),
  함수 안에서 리터럴(또는 계산되는 식)로 한 번만 정의되고 다시 대입되지 않는 지역 변수.
- 하나라도 확실하지 않으면 UNKNOWN을 돌려준다. 호출자는 UNKNOWN이면 지금처럼 모든 갈래를 따라간다(지적을 숨기지 않는 쪽).
- 리스트·Map: 같은 블록에서 new ArrayList·HashMap으로 만들고 add·put(상수 키)·remove(상수)·clear만 한 지역 컬렉션에서
  상수 위치·키로 꺼낸 원소가 리터럴이면 깨끗한 값으로 본다. 다른 메서드를 부르거나 다른 함수에 넘기거나 갈래·반복 안에서 바꾸면 계산하지 않는다.
작성자: 최진호
작성일: 2026-10-26
"""

import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import enclosing_function
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile

UNKNOWN = object()
LANGS = frozenset({Lang.JAVA, Lang.JAVASCRIPT, Lang.TYPESCRIPT, Lang.PYTHON})
MAX_DEPTH = 12
_INT_TYPES = {"decimal_integer_literal", "integer", "number", "integer_literal", "int_literal"}
_STRING_TYPES = {"string_literal", "string"}
_TRUE = {"true", "True"}
_FALSE = {"false", "False"}
_BINARY = {"binary_expression", "binary_operator", "comparison_operator", "boolean_operator"}
_UNARY = {"unary_expression", "not_operator", "unary_operator"}
_PAREN = {"parenthesized_expression"}
_LIST_CTOR = re.compile(r"^new\s+(?:java\.util\.)?(?:ArrayList|LinkedList)\s*<[^>]*>\s*\(\s*\)$")
_MAP_CTOR = re.compile(r"^new\s+(?:java\.util\.)?(?:HashMap|LinkedHashMap|TreeMap)\s*<[^>]*>\s*\(\s*\)$")
_BLOCK_TYPES = {"block", "statement_block", "program", "module"}
_BRANCHING = {"if_statement", "for_statement", "enhanced_for_statement", "while_statement", "do_statement", "try_statement",
              "switch_expression", "switch_statement", "lambda_expression", "catch_clause"}


def _literal(src: SourceFile, node: Node):
    text = src.text_of(node)
    if node.type in _INT_TYPES:
        try:
            return int(text.rstrip("lL").replace("_", ""), 0)
        except ValueError:
            return UNKNOWN
    if node.type == "character_literal" and len(text) == 3:
        return text[1]
    if node.type in _STRING_TYPES:
        body = text
        if src.lang is Lang.PYTHON:
            body = re.sub(r"^[rRbBuU]*", "", body)
            if body[:3] in ('"""', "'''") or "{" in body and text[:1] in "fF":
                return UNKNOWN
        if len(body) >= 2 and body[0] == body[-1] and body[0] in "\"'" and "\\" not in body:
            return body[1:-1]
        return UNKNOWN
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return UNKNOWN


def _operator(src: SourceFile, node: Node) -> str:
    op = node.child_by_field_name("operator")
    if op is not None:
        return src.text_of(op)
    named = {c.id for c in node.named_children}
    return " ".join(src.text_of(c) for c in node.children if c.id not in named).strip()


def _apply(op: str, left, right):
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    try:
        if op in ("+", "-", "*", "%", "/", "//") and all(isinstance(v, int) and not isinstance(v, bool) for v in (left, right)):
            if op in ("/", "//", "%") and right == 0:
                return UNKNOWN
            return {"+": left + right, "-": left - right, "*": left * right, "%": left % right if left >= 0 and right > 0 else UNKNOWN,
                    "/": left // right if left * right >= 0 else UNKNOWN, "//": left // right}[op]
        if op == "+" and isinstance(left, str) and isinstance(right, str):
            return left + right
        if op in ("<", ">", "<=", ">=") and type(left) is type(right) and not isinstance(left, bool):
            return {"<": left < right, ">": left > right, "<=": left <= right, ">=": left >= right}[op]
        if op in ("==", "!=", "===", "!==") and type(left) is type(right):
            return (left == right) == (op in ("==", "==="))
        if op in ("&&", "and") and isinstance(left, bool) and isinstance(right, bool):
            return left and right
        if op in ("||", "or") and isinstance(left, bool) and isinstance(right, bool):
            return left or right
    except TypeError:  # iron-laws: ignore[IL-301] 계산할 수 없는 조합은 모르는 값으로 남기고 호출자가 모든 갈래를 따라간다
        return UNKNOWN
    return UNKNOWN


_WRITE_TYPES = {"variable_declarator", "assignment", "assignment_expression", "augmented_assignment", "augmented_assignment_expression",
                "update_expression", "for_in_statement", "enhanced_for_statement", "for_statement"}


def _assignment_count(src: SourceFile, scope: Node, name: str) -> int:
    """scope 안에서 이름에 값을 쓰는 곳의 수(선언·대입·복합 대입·증감·반복 변수). 문자열 안의 글자는 세지 않는다."""
    count = 0
    stack = [scope]
    while stack:
        n = stack.pop()
        if n.type in _WRITE_TYPES:
            if n.type == "update_expression":
                target = next((c for c in n.named_children if c.type == "identifier"), None)
            elif n.type in ("for_in_statement", "enhanced_for_statement", "for_statement"):
                target = n.child_by_field_name("left") or n.child_by_field_name("name")
            else:
                target = n.child_by_field_name("name") or n.child_by_field_name("left")
            if target is not None and target.type == "identifier" and src.text_of(target) == name:
                count += 1
        stack.extend(n.children)
    return count


def _local_definition(src: SourceFile, node: Node, scope: Node) -> Node | None:
    """scope 안에서 이름이 단 한 번, 값과 함께 정의되고 다시 바뀌지 않으면 그 값 노드. 매개변수·필드는 None"""
    name = src.text_of(node)
    params = scope.child_by_field_name("parameters")
    if params is not None and re.search(rf"\b{re.escape(name)}\b", src.text_of(params)):
        return None
    if _assignment_count(src, scope, name) != 1:
        return None
    stack = [scope]
    while stack:
        n = stack.pop()
        if n.type in ("variable_declarator", "assignment", "assignment_expression"):
            target = n.child_by_field_name("name") or n.child_by_field_name("left")
            value = n.child_by_field_name("value") or n.child_by_field_name("right")
            if target is not None and value is not None and src.text_of(target) == name:
                return value if n.end_byte <= node.start_byte else None
        stack.extend(n.children)
    return None


def const_value(src: SourceFile, node: Node | None, depth: int = 0):
    """식의 값. 코드만으로 정해지지 않으면 UNKNOWN"""
    if node is None or src.lang not in LANGS or depth > MAX_DEPTH:
        return UNKNOWN
    value = _literal(src, node)
    if value is not UNKNOWN:
        return value
    if node.type in _PAREN or node.type == "condition_clause":
        inner = [c for c in node.named_children if "comment" not in c.type]
        return const_value(src, inner[0], depth + 1) if len(inner) == 1 else UNKNOWN
    if node.type in _BINARY:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            named = node.named_children
            if len(named) != 2:
                return UNKNOWN
            left, right = named
        return _apply(_operator(src, node), const_value(src, left, depth + 1), const_value(src, right, depth + 1))
    if node.type in _UNARY:
        named = node.named_children
        if len(named) != 1:
            return UNKNOWN
        operand = const_value(src, named[0], depth + 1)
        op = _operator(src, node)
        if op in ("!", "not") and isinstance(operand, bool):
            return not operand
        if op == "-" and isinstance(operand, int) and not isinstance(operand, bool):
            return -operand
        return UNKNOWN
    if node.type == "identifier":
        scope = enclosing_function(node, src.lang)
        definition = _local_definition(src, node, scope) if scope is not None else None
        return const_value(src, definition, depth + 1) if definition is not None else UNKNOWN
    if node.type == "subscript" and src.lang is Lang.PYTHON:
        text, index = const_value(src, node.child_by_field_name("value"), depth + 1), const_value(src, node.child_by_field_name("subscript"), depth + 1)
        if isinstance(text, str) and isinstance(index, int) and not isinstance(index, bool) and -len(text) <= index < len(text):
            return text[index]
        return UNKNOWN
    if node.type == "method_invocation" and src.lang is Lang.JAVA:
        name = node.child_by_field_name("name")
        target = node.child_by_field_name("object")
        args = node.child_by_field_name("arguments")
        if name is not None and src.text_of(name) == "charAt" and target is not None and args is not None and len(args.named_children) == 1:
            text, index = const_value(src, target, depth + 1), const_value(src, args.named_children[0], depth + 1)
            if isinstance(text, str) and isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(text):
                return text[index]
    return UNKNOWN


def condition_value(src: SourceFile, condition: Node | None) -> bool | None:
    """조건식이 항상 참이면 True, 항상 거짓이면 False, 모르면 None"""
    value = const_value(src, condition)
    return value if isinstance(value, bool) else None


def _statement_of(node: Node) -> Node:
    while node.parent is not None and node.parent.type not in _BLOCK_TYPES:
        node = node.parent
    return node


def _map_get_is_literal(src: SourceFile, call: Node, declaration: Node, operations: list[Node], block: Node, key) -> bool:
    """지역 Map에 상수 키로 put·remove·clear만 했을 때 get(상수 키)의 값이 리터럴이면 True"""
    if key is UNKNOWN:
        return False
    entries: dict = {}
    for op in sorted(operations, key=lambda o: o.start_byte):
        if op.start_byte > call.start_byte:
            continue
        statement = _statement_of(op)
        if statement.parent is None or statement.parent.id != block.id or statement.start_byte <= declaration.start_byte:
            return False
        method = src.text_of(op.child_by_field_name("name"))
        op_args = [a for a in (op.child_by_field_name("arguments").named_children if op.child_by_field_name("arguments") else []) if "comment" not in a.type]
        op_key = const_value(src, op_args[0]) if op_args else UNKNOWN
        if method == "put" and len(op_args) == 2 and op_key is not UNKNOWN:
            entries[op_key] = op_args[1]
        elif method == "remove" and len(op_args) == 1 and op_key is not UNKNOWN:
            entries.pop(op_key, None)
        elif method == "clear" and not op_args:
            entries = {}
        else:
            return False
    return key in entries and _literal(src, entries[key]) is not UNKNOWN


def list_get_is_literal(src: SourceFile, call: Node) -> bool:
    """Java 지역 리스트·Map에서 상수 위치·키로 꺼낸 원소가 리터럴임이 확실하면 True(깨끗한 값). 모르면 False"""
    if src.lang is not Lang.JAVA or call.type != "method_invocation":
        return False
    name, receiver, args = call.child_by_field_name("name"), call.child_by_field_name("object"), call.child_by_field_name("arguments")
    if name is None or src.text_of(name) != "get" or receiver is None or receiver.type != "identifier" or args is None or len(args.named_children) != 1:
        return False
    index = const_value(src, args.named_children[0])
    scope = enclosing_function(call, src.lang)
    if index is UNKNOWN or isinstance(index, bool) or scope is None:
        return False
    list_name = src.text_of(receiver)
    get_statement = _statement_of(call)
    block = get_statement.parent
    declaration = None
    operations: list[Node] = []
    stack = [scope]
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator" and src.text_of(n.child_by_field_name("name") or n) == list_name:
            declaration = n
        elif n.type == "identifier" and src.text_of(n) == list_name and n.parent is not None:
            parent = n.parent
            if parent.type == "method_invocation" and (obj := parent.child_by_field_name("object")) is not None and obj.id == n.id:
                if parent.id != call.id:
                    operations.append(parent)
            elif not (parent.type == "variable_declarator" and (decl := parent.child_by_field_name("name")) is not None and decl.id == n.id):
                if n.start_byte < call.start_byte:
                    return False  # 다른 곳에 넘기거나 다시 대입한 리스트는 계산하지 않는다
        stack.extend(n.children)
    if declaration is None or block is None or _statement_of(declaration).parent is None or _statement_of(declaration).parent.id != block.id:
        return False
    value = declaration.child_by_field_name("value")
    constructor = re.sub(r"\s+", " ", src.text_of(value)).strip() if value is not None else ""
    if _MAP_CTOR.match(constructor):
        return _map_get_is_literal(src, call, declaration, operations, block, const_value(src, args.named_children[0]))
    if not _LIST_CTOR.match(constructor):
        return False
    elements: list[Node] = []
    for op in sorted(operations, key=lambda o: o.start_byte):
        if op.start_byte > call.start_byte:
            continue
        statement = _statement_of(op)
        if statement.parent is None or statement.parent.id != block.id or statement.start_byte <= declaration.start_byte:
            return False
        method = src.text_of(op.child_by_field_name("name"))
        op_args = [a for a in (op.child_by_field_name("arguments").named_children if op.child_by_field_name("arguments") else []) if "comment" not in a.type]
        if method == "add" and len(op_args) == 1:
            elements.append(op_args[0])
        elif method == "add" and len(op_args) == 2 and isinstance(position := const_value(src, op_args[0]), int) and 0 <= position <= len(elements):
            elements.insert(position, op_args[1])
        elif method == "remove" and len(op_args) == 1 and op_args[0].type in _INT_TYPES:
            position = const_value(src, op_args[0])
            if not isinstance(position, int) or not 0 <= position < len(elements):
                return False
            elements.pop(position)
        elif method == "clear" and not op_args:
            elements = []
        else:
            return False
    return isinstance(index, int) and 0 <= index < len(elements) and _literal(src, elements[index]) is not UNKNOWN


def switch_selector(node: Node) -> Node | None:
    """switch·match의 선택값 식"""
    return node.child_by_field_name("condition") or node.child_by_field_name("value") or node.child_by_field_name("subject")


def switch_case_index(src: SourceFile, selector: Node | None, cases: list[Node]) -> int | None:
    """switch 선택값이 상수이면 실행이 시작되는 case의 위치(맞는 case가 없으면 default, 둘 다 없으면 -1). 모르면 None"""
    value = const_value(src, selector)
    if value is UNKNOWN:
        return None
    default = -1
    for position, case in enumerate(cases):
        if case.type == "case_clause":  # Python match: 상수 패턴과 | 묶음, _ 기본값만 계산한다
            pattern = next((c for c in case.named_children if c.type == "case_pattern"), None)
            if pattern is None or case.child_by_field_name("guard") is not None:
                return None
            if src.text_of(pattern).strip() == "_":
                default = position
                continue
            inner = pattern.named_children[0] if pattern.named_children else None
            options = [c for c in inner.named_children] if inner is not None and inner.type == "union_pattern" else [inner]
            known = [_literal(src, o) if o is not None else UNKNOWN for o in options]
            if any(k is UNKNOWN for k in known):
                return None
            if any(k == value and type(k) is type(value) for k in known):
                return position
            continue
        labels = [c for c in case.named_children if c.type == "switch_label"] or [case]
        for label in labels:
            label_values = [c for c in label.named_children if "comment" not in c.type and c.type not in ("statement", "expression_statement")]
            text = src.text_of(label).lstrip()
            if text.startswith("default"):
                default = position
                continue
            if case.type == "switch_case":
                label_values = [case.child_by_field_name("value")] if case.child_by_field_name("value") is not None else []
            known = [const_value(src, v) for v in label_values[:1]]
            if not known or known[0] is UNKNOWN:
                return None
            if known[0] == value and type(known[0]) is type(value):
                return position
        if case.type == "switch_default":
            default = position
    return default


def _cases_of(switch: Node) -> list[Node]:
    from iron_laws.engine.taint.nodes import CASE_TYPES, SWITCH_TYPES

    cases: list[Node] = []
    stack = list(reversed(switch.children))
    while stack:
        n = stack.pop()
        if n.type in CASE_TYPES:
            cases.append(n)
            continue
        if n.type in SWITCH_TYPES:
            continue
        stack.extend(reversed(n.children))
    return cases


def in_dead_branch(src: SourceFile, node: Node) -> bool:
    """node가 조건이 상수인 if·조건식·switch의 실행되지 않는 갈래 안에 있으면 True"""
    if src.lang not in LANGS:
        return False
    child, parent = node, node.parent
    while parent is not None:
        if parent.type == "if_statement":
            known = condition_value(src, parent.child_by_field_name("condition"))
            if known is not None:
                live = parent.children_by_field_name("consequence" if known else "alternative")
                dead = parent.children_by_field_name("alternative" if known else "consequence")
                if any(d.id == child.id for d in dead) and not any(lv.id == child.id for lv in live):
                    return True
        elif parent.type in ("ternary_expression", "conditional_expression"):
            from iron_laws.engine.taint.paths import _ternary_parts

            parts = _ternary_parts(parent)
            known = condition_value(src, parts[0]) if parts is not None else None
            if known is not None and (parts[2] if known else parts[1]).id == child.id:
                return True
        elif parent.type in ("switch_expression", "switch_statement", "match_statement"):
            cases = _cases_of(parent)
            start = switch_case_index(src, switch_selector(parent), cases)
            holder = next((i for i, c in enumerate(cases) if c.start_byte <= node.start_byte and node.end_byte <= c.end_byte), None)
            if start is not None and holder is not None:
                reachable: set[int] = set()
                for i in range(start, len(cases)) if start >= 0 else ():
                    reachable.add(i)
                    if cases[i].type == "case_clause" or any(c.type in ("break_statement", "return_statement", "throw_statement") for c in cases[i].named_children):
                        break
                if holder not in reachable:
                    return True
        child, parent = parent, parent.parent
    return False


def is_closed_value(src: SourceFile, node: Node | None, depth: int = 0) -> bool:
    """값이 코드만으로 정해지는 상수 문자열·숫자인지. 실행되지 않는 갈래의 정의는 보지 않는다. 모르면 False"""
    from iron_laws.engine.taint.definitions import reaching_definitions

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
        from iron_laws.engine.taint.paths import _ternary_parts

        parts = _ternary_parts(node)
        known = condition_value(src, parts[0]) if parts is not None else None
        return known is not None and is_closed_value(src, parts[1] if known else parts[2], depth + 1)
    if node.type == "method_invocation":
        return list_get_is_literal(src, node) or _helper_returns_closed(src, node, depth)
    if node.type == "string" and src.lang is Lang.PYTHON:
        # f-문자열: 보간한 식이 모두 닫힌 값이면 닫혀 있다
        parts = [c for c in node.named_children if c.type == "interpolation"]
        return bool(parts) and all(
            any(is_closed_value(src, e, depth + 1) for e in p.named_children if e.type not in ("format_specifier", "type_conversion"))
            for p in parts
        )
    if node.type == "subscript" and src.lang is Lang.PYTHON:
        return python_container_get_is_literal(src, node)
    if node.type == "call" and src.lang is Lang.PYTHON:
        return python_container_get_is_literal(src, node)
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


def python_container_get_is_literal(src: SourceFile, read: Node) -> bool:
    """Python 지역 컨테이너에서 상수 위치·키로 꺼낸 값이 리터럴이면 True.
    dict(`{}` + 상수 키 첨자 대입), list(`[]` + append·insert·pop·clear), configparser(`ConfigParser()` + add_section·set)를
    같은 블록 안에서만 계산한다. 다른 메서드·다른 함수에 넘기기·갈래·반복 안의 변경이 있으면 계산하지 않는다."""
    scope = enclosing_function(read, src.lang)
    if scope is None:
        return False
    if read.type == "subscript":
        target, key_nodes = read.child_by_field_name("value"), [read.child_by_field_name("subscript")]
    else:
        function = read.child_by_field_name("function")
        args = read.child_by_field_name("arguments")
        if function is None or function.type != "attribute" or src.text_of(function.child_by_field_name("attribute")) != "get" or args is None:
            return False
        target, key_nodes = function.child_by_field_name("object"), [a for a in args.named_children if "comment" not in a.type]
    if target is None or target.type != "identifier" or not key_nodes or any(k is None for k in key_nodes):
        return False
    key = tuple(const_value(src, k) for k in key_nodes)
    if any(k is UNKNOWN for k in key):
        return False
    name = src.text_of(target)
    block = _statement_of(read).parent
    uses = []
    stack = [scope]
    while stack:
        n = stack.pop()
        if n.type == "identifier" and src.text_of(n) == name and n.start_byte < read.start_byte:
            uses.append(n)
        stack.extend(n.children)
    kind, entries, items = None, {}, []
    for use in sorted(uses, key=lambda u: u.start_byte):
        parent, statement = use.parent, _statement_of(use)
        if block is None or statement.parent is None or statement.parent.id != block.id:
            return False
        if parent.type == "assignment" and parent.child_by_field_name("left") is not None and parent.child_by_field_name("left").id == use.id:
            right = parent.child_by_field_name("right")
            text = re.sub(r"\s+", "", src.text_of(right)) if right is not None else ""
            kind = "dict" if text == "{}" else "list" if text == "[]" else "config" if re.fullmatch(r"(?:configparser\.)?(?:Raw|Safe)?ConfigParser\(\)", text) else None
            if kind is None:
                return False
            entries, items = {}, []
            continue
        if kind is None:
            return False
        if parent.type == "subscript" and parent.child_by_field_name("value").id == use.id:
            holder = parent.parent
            if holder is not None and holder.type == "assignment" and holder.child_by_field_name("left").id == parent.id:
                k = const_value(src, parent.child_by_field_name("subscript"))
                if kind != "dict" or k is UNKNOWN:
                    return False
                entries[(k,)] = holder.child_by_field_name("right")
            continue  # 읽기는 상태를 바꾸지 않는다
        if parent.type == "attribute" and parent.child_by_field_name("object").id == use.id and parent.parent is not None and parent.parent.type == "call":
            method = src.text_of(parent.child_by_field_name("attribute"))
            call_args = [a for a in parent.parent.child_by_field_name("arguments").named_children if "comment" not in a.type]
            values = [const_value(src, a) for a in call_args]
            if kind == "list" and method == "append" and len(call_args) == 1:
                items.append(call_args[0])
            elif kind == "list" and method == "insert" and len(call_args) == 2 and isinstance(values[0], int) and 0 <= values[0] <= len(items):
                items.insert(values[0], call_args[1])
            elif kind == "list" and method == "pop" and len(call_args) <= 1 and items:
                position = values[0] if call_args else -1
                if not isinstance(position, int) or not -len(items) <= position < len(items):
                    return False
                items.pop(position)
            elif kind == "list" and method == "clear" and not call_args:
                items = []
            elif kind == "config" and method == "add_section" and len(call_args) == 1:
                pass
            elif kind == "config" and method == "set" and len(call_args) == 3 and UNKNOWN not in values[:2]:
                entries[tuple(values[:2])] = call_args[2]
            elif method == "get" and parent.parent.id == read.id:
                continue
            else:
                return False
            continue
        return False
    if kind == "list":
        index = key[0] if len(key) == 1 else UNKNOWN
        return isinstance(index, int) and not isinstance(index, bool) and -len(items) <= index < len(items) and _literal(src, items[index]) is not UNKNOWN
    return kind in ("dict", "config") and key in entries and _literal(src, entries[key]) is not UNKNOWN
