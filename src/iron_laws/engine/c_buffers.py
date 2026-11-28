"""
C 버퍼 크기·문자열 길이의 상수 계산: 복사 함수(strcpy·strcat)가 목적지를 넘는지, 서식 인자가 리터럴만 담은 버퍼인지 판정하는 근거
- 목적지 크기: 배열 선언 `T b[N]`, `alloca·malloc(N * sizeof(T))`, 그 배열·할당을 가리키는 포인터(`data = buf`, `data = buf - 8`)를 따라간다.
  크기는 원소 개수로 센다. 포인터 오프셋은 남은 크기에서 뺀다(음수면 버퍼 앞을 쓴다).
- 원본 길이: 문자열 리터럴, `memset(v, c, N); v[K] = '\\0'`로 채운 배열, 리터럴로 초기화한 배열.
- 계산할 수 없으면 None을 돌려준다. 호출자는 None이면 확인 필요로 낸다.
작성자: 최진호
작성일: 2026-11-24
"""

import ast
import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import enclosing_function, iter_calls, walk
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint.c_inputs import callee_names, expand_name

ARRAY_DECL_TYPES = ("declaration",)
_ALLOC_RE = re.compile(r"^\(?\s*(?:\(\s*[\w\s\*]+\)\s*)?(?:ALLOCA|alloca|_alloca|malloc|MALLOC|calloc)\s*\((.*)\)\s*\)?$", re.S)


def c_int(src: SourceFile, text: str) -> int | None:
    """정수 상수 식(`100`, `100-1`, `50*sizeof(char)`)의 값. sizeof는 원소 하나로 센다. 매크로는 펼친다"""
    text = re.sub(r"sizeof\s*\(\s*[\w\s\*]+\)", "1", text)
    for name in set(re.findall(r"\b[A-Za-z_]\w*\b", text)):
        expanded = _macro_int(src, name)
        if expanded is None:
            return None
        text = re.sub(rf"\b{re.escape(name)}\b", str(expanded), text)
    if not re.fullmatch(r"[\d\s+\-*/()]+", text):
        return None
    try:
        tree = ast.parse(text.strip(), mode="eval")
    except SyntaxError:  # iron-laws: ignore[IL-301] 계산하지 못한 식은 크기를 모르는 것으로 둔다
        return None
    return _arith(tree.body)


def _arith(node: ast.AST) -> int | None:
    """정수 사칙연산 식의 값. 다른 식이 섞이면 None"""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        inner = _arith(node.operand)
        return -inner if inner is not None else None
    if isinstance(node, ast.BinOp):
        left, right = _arith(node.left), _arith(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div | ast.FloorDiv) and right != 0:
            return left // right
    return None


def _macro_int(src: SourceFile, name: str) -> int | None:
    from iron_laws.engine.taint.c_inputs import macro_table

    values = macro_table(src).get(name, set())
    if len(values) != 1:
        return None
    value = next(iter(values))
    return int(value) if re.fullmatch(r"\d+", value) else None


def _decl_of(src: SourceFile, scope: Node, name: str) -> Node | None:
    """scope 안에서 name을 선언한 declarator(init_declarator 또는 array_declarator)"""
    for n in walk(scope):
        if n.type not in ("init_declarator", "array_declarator", "pointer_declarator"):
            continue
        target = n.child_by_field_name("declarator")
        while target is not None and target.type in ("array_declarator", "pointer_declarator", "parenthesized_declarator"):
            if target.type == "array_declarator" and n.type == "init_declarator":
                break
            target = target.child_by_field_name("declarator")
        if target is not None and target.type == "identifier" and src.text_of(target) == name and (n.parent is None or n.parent.type != "init_declarator"):
            return n
        if target is not None and target.type == "array_declarator":
            inner = target.child_by_field_name("declarator")
            if inner is not None and src.text_of(inner) == name:
                return n
    return None


def _array_size(src: SourceFile, decl: Node) -> int | None:
    array = decl if decl.type == "array_declarator" else decl.child_by_field_name("declarator")
    if array is None or array.type != "array_declarator":
        return None
    size = array.child_by_field_name("size")
    if size is None:
        value = decl.child_by_field_name("value") if decl.type == "init_declarator" else None
        literal = _literal_length(src, value) if value is not None else None
        return literal + 1 if literal is not None else None
    return c_int(src, src.text_of(size))


def _pointer_parts(src: SourceFile, node: Node) -> tuple[str, int] | None:
    """`buf`, `buf + 2`, `buf - 8`, `(char *)buf` → (바탕 이름, 오프셋)"""
    offset = 0
    while node is not None:
        if node.type == "identifier":
            names = expand_name(src, src.text_of(node))
            return (next(iter(names)) if len(names) == 1 else src.text_of(node)), offset
        if node.type in ("parenthesized_expression",):
            node = node.named_children[0] if node.named_children else None
        elif node.type == "cast_expression":
            node = node.child_by_field_name("value")
        elif node.type == "binary_expression":
            op = src.text_of(node.child_by_field_name("operator") or node)
            right = node.child_by_field_name("right")
            k = c_int(src, src.text_of(right)) if right is not None else None
            if op not in ("+", "-") or k is None:
                return None
            offset += k if op == "+" else -k
            node = node.child_by_field_name("left")
        else:
            return None
    return None


def _base_name(src: SourceFile, node: Node | None) -> str | None:
    """`buf`, `buf + n`, `(char *)(buf + len)` → 바탕 이름. 오프셋이 상수가 아니어도 이름은 찾는다"""
    while node is not None:
        if node.type == "identifier":
            names = expand_name(src, src.text_of(node))
            return next(iter(names)) if len(names) == 1 else src.text_of(node)
        if node.type == "parenthesized_expression":
            node = node.named_children[0] if node.named_children else None
        elif node.type == "cast_expression":
            node = node.child_by_field_name("value")
        elif node.type == "binary_expression" and src.text_of(node.child_by_field_name("operator") or node) in ("+", "-"):
            node = node.child_by_field_name("left")
        else:
            return None
    return None


def _written_args(callee: set[str], args: list[Node]) -> list[Node]:
    """쓰기 함수가 채우는 인자: 대부분 첫 인자, recv·recvfrom·read는 둘째, scanf는 서식 뒤, fscanf·sscanf는 둘째 뒤"""
    if callee & {"recv", "recvfrom", "read"}:
        return args[1:2]
    if "scanf" in callee:
        return args[1:]
    if callee & {"fscanf", "sscanf"}:
        return args[2:]
    return args[:1]


def _single_assignment(src: SourceFile, scope: Node, name: str, before: int) -> Node | None:
    """before 앞에서 name에 값을 넣는 곳이 하나뿐이면 그 값(선언 초기값 포함)"""
    values = []
    for n in walk(scope):
        if n.start_byte >= before:
            continue
        if n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            if left is not None and left.type == "identifier" and src.text_of(left) == name:
                values.append(n.child_by_field_name("right"))
        elif n.type == "init_declarator":
            target = n.child_by_field_name("declarator")
            while target is not None and target.type == "pointer_declarator":
                target = target.child_by_field_name("declarator")
            if target is not None and target.type == "identifier" and src.text_of(target) == name:
                values.append(n.child_by_field_name("value"))
    return values[0] if len(values) == 1 and values[0] is not None else None


def capacity(src: SourceFile, node: Node, at: Node, depth: int = 0) -> tuple[int, int] | None:
    """식이 가리키는 버퍼의 (원소 개수, 시작 위치에서의 오프셋)"""
    scope = enclosing_function(at, src.lang)
    parts = _pointer_parts(src, node)
    if scope is None or parts is None or depth > 4:
        return None
    name, offset = parts
    decl = _decl_of(src, scope, name)
    if decl is not None:
        size = _array_size(src, decl)
        if size is not None:
            return size, offset
    value = _single_assignment(src, scope, name, at.start_byte)
    if value is None:
        return None
    alloc = _ALLOC_RE.match(src.text_of(value).strip())
    if alloc:
        size = c_int(src, alloc.group(1))
        return (size, offset) if size is not None else None
    inner = capacity(src, value, at, depth + 1)
    return (inner[0], inner[1] + offset) if inner is not None else None


def _literal_length(src: SourceFile, node: Node | None) -> int | None:
    if node is None:
        return None
    if node.type == "concatenated_string":
        parts = [_literal_length(src, c) for c in node.named_children]
        return sum(parts) if parts and all(p is not None for p in parts) else None
    if node.type != "string_literal":
        if node.type == "identifier":
            for value in macro_values(src, src.text_of(node)):
                if re.fullmatch(r'L?"(?:[^"\\]|\\.)*"', value):
                    return _text_length(value)
        return None
    return _text_length(src.text_of(node))


def macro_values(src: SourceFile, name: str) -> set[str]:
    from iron_laws.engine.taint.c_inputs import macro_table

    return macro_table(src).get(name, set())


def _text_length(text: str) -> int | None:
    m = re.fullmatch(r'L?"((?:[^"\\]|\\.)*)"', text.strip())
    if m is None:
        return None
    try:
        return len(m.group(1).encode("utf-8").decode("unicode_escape"))
    except UnicodeDecodeError:  # iron-laws: ignore[IL-301] 이스케이프를 풀지 못한 리터럴은 길이를 모르는 것으로 둔다
        return None


def string_length(src: SourceFile, node: Node, at: Node, depth: int = 0) -> int | None:
    """원본 문자열의 길이(종료 문자 제외). 리터럴, memset으로 채우고 끝을 0으로 막은 배열, 리터럴로 초기화한 배열"""
    literal = _literal_length(src, node)
    if literal is not None or depth > 3:
        return literal
    scope = enclosing_function(at, src.lang)
    parts = _pointer_parts(src, node)
    if scope is None or parts is None or parts[1] != 0:
        return None
    name = parts[0]
    fill = None
    end = None
    for call in iter_calls(src):
        if not (scope.start_byte <= call.node.start_byte < at.start_byte) or not call.args:
            continue
        target = _pointer_parts(src, call.args[0])
        if target is None or target[0] != name:
            continue
        names = callee_names(src, call.callee)
        if names & {"memset", "wmemset"} and len(call.args) == 3 and target[1] == 0:
            fill = c_int(src, src.text_of(call.args[2]))
        else:
            return None  # 다른 함수가 이 배열에 쓴다
    for n in walk(scope):
        if n.type == "assignment_expression" and n.start_byte < at.start_byte:
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and left.type == "subscript_expression" and src.text_of(left.child_by_field_name("argument") or left) == name:
                index = left.child_by_field_name("index")
                k = c_int(src, src.text_of(index)) if index is not None else None
                if k is not None and right is not None and src.text_of(right).strip() in ("'\\0'", "L'\\0'", "0"):
                    end = k if end is None else min(end, k)
    if fill is not None and end is not None and end <= fill:
        return end
    decl = _decl_of(src, scope, name)
    if decl is not None and decl.type == "init_declarator" and fill is None and end is None:
        return _literal_length(src, decl.child_by_field_name("value"))
    value = _single_assignment(src, scope, name, at.start_byte)
    return string_length(src, value, at, depth + 1) if value is not None and value.type != "string_literal" and depth < 3 else None


WRITERS = frozenset({"strcpy", "strncpy", "strcat", "strncat", "wcscpy", "wcsncpy", "wcscat", "wcsncat", "memcpy", "memmove", "memset", "wmemset",
                     "sprintf", "snprintf", "swprintf", "vsprintf", "vsnprintf", "fgets", "fgetws", "gets", "fread", "recv", "recvfrom", "read",
                     "scanf", "fscanf", "sscanf", "strlcpy", "strlcat"})


def current_length(src: SourceFile, node: Node, at: Node) -> int | None:
    """strcat 목적지에 이미 든 문자열 길이: `b[0] = '\\0'`이나 리터럴 초기값만 있으면 그 길이"""
    scope = enclosing_function(at, src.lang)
    parts = _pointer_parts(src, node)
    if scope is None or parts is None or parts[1] != 0:
        return None
    names = {parts[0]}
    value = _single_assignment(src, scope, parts[0], at.start_byte)
    alias = _pointer_parts(src, value) if value is not None else None
    if alias is not None and alias[1] == 0:
        names.add(alias[0])
    for call in iter_calls(src):
        if scope.start_byte <= call.node.start_byte < at.start_byte and call.args and callee_names(src, call.callee) & WRITERS:
            target = _pointer_parts(src, call.args[0])
            if target is not None and target[0] in names:
                return None
    for n in walk(scope):
        if n.type == "assignment_expression" and n.start_byte < at.start_byte:
            left = n.child_by_field_name("left")
            if left is not None and left.type == "subscript_expression" and src.text_of(left.child_by_field_name("argument") or left) in names:
                index = left.child_by_field_name("index")
                right = n.child_by_field_name("right")
                if index is not None and src.text_of(index).strip() == "0" and right is not None and src.text_of(right).strip() in ("'\\0'", "L'\\0'", "0"):
                    return 0
    for name in names:
        decl = _decl_of(src, scope, name)
        if decl is not None and decl.type == "init_declarator":
            length = _literal_length(src, decl.child_by_field_name("value"))
            if length is not None:
                return length
    return None


def literal_only_buffer(src: SourceFile, node: Node, at: Node) -> bool:
    """서식 인자로 쓰는 버퍼에 리터럴만 들어 있다: 리터럴 초기값이나 `strcpy(버퍼, "리터럴")`로 버퍼 전체를 덮은 것 말고는 쓰지 않는다"""
    scope = enclosing_function(at, src.lang)
    parts = _pointer_parts(src, node)
    if scope is None or parts is None or parts[1] != 0:
        return False
    names = {parts[0]}
    value = _single_assignment(src, scope, parts[0], at.start_byte)
    alias = _pointer_parts(src, value) if value is not None else None
    if alias is not None and alias[1] == 0:
        names.add(alias[0])
    elif value is not None and value.type != "string_literal":
        return False
    written = False
    for call in iter_calls(src):
        if not (scope.start_byte <= call.node.start_byte < at.start_byte) or not call.args:
            continue
        callee = callee_names(src, call.callee)
        # 버퍼의 어느 위치든(`data + len`처럼 오프셋을 계산할 수 없어도) 채우는 호출이 있으면 리터럴만 든 버퍼가 아니다
        if callee & WRITERS and not (callee & {"strcpy", "wcscpy"}) and any(_base_name(src, a) in names for a in _written_args(callee, call.args)):
            return False
        target = _pointer_parts(src, call.args[0])
        if target is None or target[0] not in names:
            continue
        if callee & {"strcpy", "wcscpy"} and target[1] == 0 and len(call.args) == 2 and _literal_length(src, call.args[1]) is not None:
            written = True
            continue
        if callee & WRITERS:
            return False
    if written:
        return True
    return value is not None and value.type == "string_literal"
