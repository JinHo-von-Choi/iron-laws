import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import (
    STRING_TYPES,
    _is_property_position,
    has_interpolation,
    identifiers_in,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint.constants import (
    condition_value,
    list_get_is_literal,
    python_container_get_is_literal,
)
from iron_laws.engine.taint.resolve import _call_parts

ASSIGN_TYPES = {
    "assignment",
    "augmented_assignment",
    "variable_declarator",
    "assignment_expression",
    "named_expression",
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
    "property_declaration",
}


AUGMENTED_TYPES = ("augmented_assignment", "augmented_assignment_expression", "compound_assignment_expr")


LOOP_ASSIGN_TYPES = {"enhanced_for_statement", "for_in_statement", "foreach_statement", "for_statement", "range_clause"}


def _target_and_value(node: Node) -> tuple[Node | None, Node | None]:
    if node.type == "property_declaration":  # Kotlin val x = 식 (필드 이름이 없다)
        target = next((c for c in node.named_children if c.type == "variable_declaration"), None)
        value = node.named_children[-1] if node.named_children and node.named_children[-1].type not in ("variable_declaration", "user_type", "modifiers") else None
        return target, value
    if node.type == "assignment" and node.child_by_field_name("left") is None and len(node.named_children) == 2:
        return node.named_children[0], node.named_children[1]  # Kotlin 대입
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


_FIELD_ACCESS = {
    "attribute": ("object", "attribute"),
    "member_expression": ("object", "property"),
    "field_access": ("object", "field"),
    "member_access_expression": ("expression", "name"),
    "selector_expression": ("operand", "field"),
    "field_expression": ("argument", "field"),
}


_INDEX_ACCESS = {
    "subscript": ("value", "subscript"),
    "subscript_expression": ("object", "index"),
    "array_access": ("array", "index"),
    "element_access_expression": ("expression", "subscript"),
    "index_expression": ("operand", "index"),
}


_ROOT_TYPES = {"identifier", "variable_name", "this", "self", "this_expression"}


COLLECTION_GET = frozenset({"get", "getOrDefault", "getProperty"})


COLLECTION_PUT = frozenset({"put", "set", "setdefault", "setProperty", "putIfAbsent"})


def _constant_key(src: SourceFile, node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type in ("argument_list", "bracketed_argument_list") and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type in ("integer", "number", "decimal_integer_literal", "integer_literal", "int_literal"):
        # Python에서는 d[1]과 d["1"]이 다른 칸이다. JavaScript 등은 숫자 키가 문자열 키와 같은 칸이라 그대로 둔다
        if src.lang is Lang.PYTHON:
            try:
                return "\x00int:" + str(int(src.text_of(node), 0))  # 0x1·1_0 같은 표기를 값으로 맞추고, 문자열 키와 겹치지 않게 한다
            except ValueError:  # iron-laws: ignore[IL-301] 값으로 바꿀 수 없는 표기(예: 0으로 시작하는 정수)는 원문 표기를 키로 쓴다
                return "\x00int:" + src.text_of(node)
        return src.text_of(node)
    if node.type in STRING_TYPES and not has_interpolation(node):
        text = src.text_of(node)
        return text[1:-1] if len(text) >= 2 and text[0] in "'\"`" else None
    return None


def _root_name(src: SourceFile, node: Node) -> str | None:
    if node.type in _ROOT_TYPES or (node.type == "identifier" and node.child_count == 0):
        return src.text_of(node).lstrip("$")
    return None


def access_path(src: SourceFile, node: Node) -> tuple[str, bool] | None:
    """(경로, 정확한지). `obj.f`·`d['k']` → ('obj.f', True)·('d[k]', True). 더 깊거나 키가 상수가 아니면 (객체 루트, False)"""
    root = _root_name(src, node)
    if root is not None:
        return root, True
    spec = _FIELD_ACCESS.get(node.type)
    kind = "."
    if spec is None:
        spec = _INDEX_ACCESS.get(node.type)
        kind = "["
    if spec is None:
        return None
    obj = node.child_by_field_name(spec[0])
    if obj is None:
        return None
    inner = access_path(src, obj)
    if inner is None:
        return None
    base, exact = inner
    if not exact or "." in base or "[" in base:
        return base.split(".", 1)[0].split("[", 1)[0], False
    if kind == ".":
        prop = node.child_by_field_name(spec[1])
        return (f"{base}.{src.text_of(prop)}", True) if prop is not None else (base, False)
    key = _constant_key(src, node.child_by_field_name(spec[1]) or (node.named_children[1] if len(node.named_children) > 1 else None))
    if key is None:
        return base, False
    return (f"{base}.{key}" if src.lang in JS_FAMILY else f"{base}[{key}]"), True


def path_root(name: str) -> str:
    return name.split(".", 1)[0].split("[", 1)[0]


def tainted_roots(names) -> set[str]:
    """오염 상태의 경로들을 변수 이름으로(증거 표시용)"""
    return {path_root(n) for n in names}


def _path_hit(path: str, whole_use: bool, names: set[str]) -> bool:
    if path in names:
        return True
    root = path_root(path)
    if root != path and root in names:
        return True
    if whole_use:
        return any(n.startswith(path + ".") or n.startswith(path + "[") for n in names)
    return False


def _ternary_parts(node: Node) -> tuple[Node, Node, Node] | None:
    """(조건, 참일 때 값, 거짓일 때 값). Python 조건식(a if 조건 else b)은 필드 이름이 없어 자식 순서로 찾는다."""
    if node.type == "conditional_expression":
        named = [c for c in node.named_children if "comment" not in c.type]
        return (named[1], named[0], named[2]) if len(named) == 3 else None
    parts = tuple(node.child_by_field_name(k) for k in ("condition", "consequence", "alternative"))
    return parts if all(p is not None for p in parts) else None


def dead_ternary_ranges(src: SourceFile, node: Node) -> list[tuple[int, int]]:
    """node 안에서 조건이 상수인 조건식의 실행되지 않는 갈래(바이트 범위)"""
    found: list[tuple[int, int]] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("ternary_expression", "conditional_expression"):
            parts3 = _ternary_parts(n)
            known = condition_value(src, parts3[0]) if parts3 is not None else None
            if known is not None:
                dead = parts3[2] if known else parts3[1]
                found.append((dead.start_byte, dead.end_byte))
                stack.append(parts3[1] if known else parts3[2])
                continue
        stack.extend(n.children)
    return found


def _reads(src: SourceFile, node: Node, skip=None) -> list[tuple[str, bool]]:
    """식이 읽는 (경로, 객체 통째로 쓰는지). 메서드 호출의 수신 객체는 통째로 쓰는 것으로 본다(게터가 필드를 돌려줄 수 있다).
    상수 키 조회(`d.get('k')`)는 그 경로만 읽는다."""
    found: list[tuple[str, bool]] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if skip is not None and skip(n):
            continue
        if n.type in ("ternary_expression", "conditional_expression"):
            parts3 = _ternary_parts(n)
            known = condition_value(src, parts3[0]) if parts3 is not None else None
            if known is not None:
                stack.append(parts3[1] if known else parts3[2])
                continue
        if n.type == "method_invocation" and list_get_is_literal(src, n):
            continue  # 지역 리스트에서 꺼낸 원소가 상수 리터럴이다
        if src.lang is Lang.PYTHON and n.type in ("subscript", "call") and python_container_get_is_literal(src, n):
            continue  # 지역 dict·list·configparser에서 상수 키·위치로 꺼낸 값이 리터럴이다
        parts = _call_parts(src, n) if src.lang is not None else None
        if parts is not None and "." in parts[0]:
            method = parts[0].rsplit(".", 1)[-1]
            if n.type in ("method_invocation", "member_call_expression"):
                receiver = n.child_by_field_name("object")  # Java·PHP: 수신 객체가 호출 노드의 object 필드에 있다
            else:
                fn = n.child_by_field_name("function")
                receiver = fn.child_by_field_name(_FIELD_ACCESS[fn.type][0]) if fn is not None and fn.type in _FIELD_ACCESS else None
            receiver_path = access_path(src, receiver) if receiver is not None else None
            if receiver_path is not None and receiver_path[1] and method in COLLECTION_GET and parts[1]:
                key = _constant_key(src, parts[1][0])
                if key is not None and "." not in receiver_path[0] and "[" not in receiver_path[0]:
                    found.append((f"{receiver_path[0]}[{key}]", False))
                    stack.extend(parts[1][1:])
                    continue
            if receiver_path is not None:
                found.append((receiver_path[0], True))
                stack.extend(parts[1])
                continue
        path = access_path(src, n) if n.type in _FIELD_ACCESS or n.type in _INDEX_ACCESS else None
        if path is not None:
            found.append((path[0], not path[1] or path[0] == path_root(path[0])))
            spec = _INDEX_ACCESS.get(n.type)
            if spec is not None:  # 상수가 아닌 첨자 식 안의 변수도 읽는다
                index = n.child_by_field_name(spec[1])
                if index is not None:
                    stack.append(index)
            continue
        if n.type in ("identifier", "variable_name", "property_identifier", "field_identifier"):
            if (n.child_count == 0 or n.type == "variable_name") and not _is_property_position(n):
                found.append((src.text_of(n).lstrip("$"), True))
            continue
        if n.type == "string_literal" and src.lang is Lang.KOTLIN:  # "$name" 단순 템플릿
            found += [(m, True) for m in re.findall(r"(?<!\\)\$([A-Za-z_]\w*)", src.text_of(n))]
        stack.extend(n.children)
    return found


def reads_tainted(src: SourceFile, node: Node, names: set[str], skip=None) -> bool:
    if not names:
        return False
    return any(_path_hit(path, whole, names) for path, whole in _reads(src, node, skip))


def _target_names(src: SourceFile, target: Node) -> set[str]:
    """정의 추적용: 변수 전체에 값을 넣는 대입의 변수 이름(필드·첨자 대입은 변수 정의가 아니다)"""
    return identifiers_in(src, target) if target.type not in _FIELD_ACCESS and target.type not in _INDEX_ACCESS else set()


def _target_paths(src: SourceFile, target: Node) -> tuple[set[str], bool]:
    """대입 대상의 경로와, 이 대입이 대상의 이전 값을 덮어쓰는지(강한 갱신). 필드·상수 키는 그 경로만, 그 밖의 첨자는 객체 전체에 약하게 더한다."""
    if target.type in _FIELD_ACCESS or target.type in _INDEX_ACCESS:
        path = access_path(src, target)
        if path is None:
            return set(), False
        return {path[0]}, path[1]
    return identifiers_in(src, target), True
