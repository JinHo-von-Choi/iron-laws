"""
오철칙 AST 탐색 도구: 호출, 함수, 예외 처리기, 문자열 조합 식별
작성자: 최진호
작성일: 2026-10-04
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass

from tree_sitter import Node

from iron_laws.engine.languages import C_FAMILY, JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

FUNCTION_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: {"function_definition"},
    Lang.JAVA: {"method_declaration", "constructor_declaration"},
    Lang.CSHARP: {"method_declaration", "local_function_statement", "constructor_declaration"},
    Lang.GO: {"function_declaration", "method_declaration"},
    Lang.RUST: {"function_item"},
    Lang.PHP: {"function_definition", "method_declaration"},
    Lang.C: {"function_definition"},
    Lang.CPP: {"function_definition"},
}
for _lang in JS_FAMILY:
    FUNCTION_TYPES[_lang] = {
        "function_declaration",
        "method_definition",
        "arrow_function",
        "function_expression",
        "function",
        "generator_function_declaration",
    }

CALL_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: {"call"},
    Lang.JAVA: {"method_invocation", "object_creation_expression"},
    Lang.CSHARP: {"invocation_expression", "object_creation_expression"},
    Lang.GO: {"call_expression"},
    Lang.RUST: {"call_expression", "macro_invocation"},
    Lang.PHP: {
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
        "object_creation_expression",
    },
    Lang.C: {"call_expression"},
    Lang.CPP: {"call_expression"},
}
for _lang in JS_FAMILY:
    CALL_TYPES[_lang] = {"call_expression", "new_expression"}

HANDLER_TYPES = {"except_clause", "catch_clause"}
THROW_TYPES = {"raise_statement", "throw_statement", "throw_expression"}
STRING_TYPES = {
    "string",
    "string_literal",
    "interpreted_string_literal",
    "raw_string_literal",
    "verbatim_string_literal",
    "template_string",
    "encapsed_string",
    "interpolated_string_expression",
    "raw_string_literal_content",
}
LOOP_TYPES = {
    "while_statement",
    "for_statement",
    "do_statement",
    "loop_expression",
    "while_expression",
}
BLOCK_TYPES = {
    "block",
    "statement_block",
    "compound_statement",
    "statement_list",
    "declaration_list",
    "switch_block",
}
NESTING_TYPES = {
    "if_statement",
    "for_statement",
    "for_in_statement",
    "for_of_statement",
    "foreach_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "switch_expression",
    "try_statement",
    "match_expression",
    "loop_expression",
    "for_expression",
    "while_expression",
    "if_expression",
}

LOG_CALL_RE = re.compile(
    r"""(?ix)
    (\blog(ger|ging)?\b | \b_?logger\b | \bconsole\.(error|warn|log|info|debug|trace)
    | \bslog\b | \btracing\b | \bSystem\.err | \bConsole\.(Error\.)?Write | \berror_log\b
    | \bprint(ln|f)?\b | \beprint | \bprintStackTrace\b | \bfmt\.(F)?Print | \bpanic\b
    | \bsyslog\b | \bDebug\.Log | \bTrace\.Write | \bILogger\b | \.Log[A-Z]\w* | \bsentry
    | \bcapture(Exception|Message)\b | \bwarnings\.warn | \btraceback\. | \bsys\.stderr
    | \bsend_?error | \breport(Error|Exception)\b | \bnotify\w* | \bLog\.(d|e|i|w|v)\b)""",
)
PACKAGE_PREFIX_RE = re.compile(r"(?:\b[a-z_][a-z0-9_]*\s*\.\s*)+(?=[A-Z])")
LOG_MACRO_RE = re.compile(r"""\b(e?println|error|warn|info|debug|trace|panic|log|dbg|eprint)!""")


@dataclass
class Call:
    node: Node
    callee: str
    args: list[Node]

    @property
    def line(self) -> int:
        return self.node.start_point[0] + 1


@dataclass
class Func:
    node: Node
    name: str
    params: list[Node]
    body: Node | None
    lang: Lang

    @property
    def start_line(self) -> int:
        return self.node.start_point[0] + 1

    @property
    def end_line(self) -> int:
        return self.node.end_point[0] + 1

    @property
    def length(self) -> int:
        return self.end_line - self.start_line + 1


def walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def walk_no_nested_functions(node: Node, lang: Lang) -> Iterator[Node]:
    """중첩 함수 본문을 제외하고 순회한다."""
    fn_types = FUNCTION_TYPES.get(lang, set())
    stack = list(reversed(node.children))
    while stack:
        current = stack.pop()
        yield current
        if current.type in fn_types:
            continue
        stack.extend(reversed(current.children))


def _unwrap_arg(node: Node) -> Node:
    if node.type in ("argument", "value_argument") and node.named_children:
        return node.named_children[-1]
    return node


def _args_of(node: Node) -> list[Node]:
    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        for child in node.children:
            if child.type in ("arguments", "argument_list", "token_tree"):
                args_node = child
                break
    if args_node is None:
        return []
    return [
        _unwrap_arg(c)
        for c in args_node.named_children
        if "comment" not in c.type
    ]


def _callee_text(src: SourceFile, node: Node) -> str:
    t = node.type
    if t == "method_invocation":
        obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name")
        object_text = PACKAGE_PREFIX_RE.sub("", src.text_of(obj)) if obj is not None else ""
        prefix = f"{object_text}." if obj is not None else ""
        return prefix + (src.text_of(name) if name is not None else "")
    if t in ("member_call_expression", "scoped_call_expression"):
        obj = node.child_by_field_name("object") or node.child_by_field_name("scope")
        name = node.child_by_field_name("name")
        sep = "::" if t == "scoped_call_expression" else "->"
        return f"{src.text_of(obj)}{sep}{src.text_of(name)}" if obj is not None and name else ""
    if t in ("object_creation_expression", "new_expression"):
        type_node = node.child_by_field_name("type") or node.child_by_field_name("constructor")
        if type_node is None:
            for child in node.children:
                if child.is_named and child.type not in ("arguments", "argument_list"):
                    type_node = child
                    break
        if type_node is None:
            return "new"
        type_text = src.text_of(type_node)
        if src.lang in (Lang.JAVA, Lang.CSHARP):
            type_text = PACKAGE_PREFIX_RE.sub("", type_text)
        return f"new {type_text}"
    if t == "macro_invocation":
        macro = node.child_by_field_name("macro")
        return f"{src.text_of(macro)}!" if macro is not None else ""
    fn = node.child_by_field_name("function")
    return src.text_of(fn) if fn is not None else ""


def iter_calls(src: SourceFile) -> Iterator[Call]:
    if src.root is None or src.lang is None:
        return iter(())
    return iter(src.memo("calls", lambda: _collect_calls(src)))


def _collect_calls(src: SourceFile) -> list[Call]:
    types = CALL_TYPES.get(src.lang, set()) if src.lang else set()
    calls = []
    for node in src.nodes:
        if node.type in types:
            callee = re.sub(r"\s+", "", _callee_text(src, node))
            calls.append(Call(node, callee, _args_of(node)))
    return calls


def _function_name(src: SourceFile, node: Node) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return src.text_of(name)
    if src.lang in C_FAMILY:
        declarator = node.child_by_field_name("declarator")
        while declarator is not None:
            inner = declarator.child_by_field_name("declarator")
            if inner is None:
                break
            declarator = inner
        return src.text_of(declarator) if declarator is not None else "<anonymous>"
    parent = node.parent
    if parent is not None:
        if parent.type == "variable_declarator":
            name = parent.child_by_field_name("name")
            if name is not None:
                return src.text_of(name)
        if parent.type in ("pair", "assignment_expression", "public_field_definition"):
            key = parent.child_by_field_name("key") or parent.child_by_field_name("left")
            if key is not None:
                return src.text_of(key)
    return "<anonymous>"


def iter_functions(src: SourceFile) -> Iterator[Func]:
    if src.root is None or src.lang is None:
        return iter(())
    return iter(src.memo("functions", lambda: _collect_functions(src)))


def _collect_functions(src: SourceFile) -> list[Func]:
    types = FUNCTION_TYPES.get(src.lang, set()) if src.lang else set()
    functions = []
    for node in src.nodes:
        if node.type not in types:
            continue
        params_node = node.child_by_field_name("parameters")
        if params_node is None and src.lang in C_FAMILY:
            declarator = node.child_by_field_name("declarator")
            if declarator is not None:
                params_node = declarator.child_by_field_name("parameters")
        params = [p for p in (params_node.named_children if params_node else []) if "comment" not in p.type]
        functions.append(Func(node, _function_name(src, node), params, node.child_by_field_name("body"), src.lang))
    return functions


def enclosing_function(node: Node, lang: Lang | None) -> Node | None:
    if lang is None:
        return None
    types = FUNCTION_TYPES.get(lang, set())
    current = node.parent
    while current is not None:
        if current.type in types:
            return current
        current = current.parent
    return None


def iter_handlers(src: SourceFile) -> Iterator[Node]:
    return iter(src.memo("handlers", lambda: [n for n in src.nodes if n.type in HANDLER_TYPES]))


def handler_body(node: Node) -> Node | None:
    body = node.child_by_field_name("body")
    if body is not None:
        return body
    for child in reversed(node.named_children):
        if child.type in BLOCK_TYPES:
            return child
    return None


def handler_header(src: SourceFile, node: Node) -> str:
    body = handler_body(node)
    end = body.start_byte if body is not None else node.end_byte
    return src.data[node.start_byte : end].decode("utf-8", errors="replace")


def body_statements(body: Node | None) -> list[Node]:
    if body is None:
        return []
    items: list[Node] = []
    for child in body.named_children:
        if "comment" in child.type:
            continue
        if child.type in ("statement_list",):
            items.extend(body_statements(child))
        else:
            items.append(child)
    return items


def contains_type(node: Node, types: set[str]) -> bool:
    return any(n.type in types for n in walk(node))


def has_throw(src: SourceFile, node: Node) -> bool:
    for n in walk(node):
        if n.type in THROW_TYPES or n.type == "try_expression":
            return True
        if n.type == "return_expression" and "Err" in src.text_of(n):
            return True
        if n.type == "return_statement" and re.search(r"\berr\w*\b", src.text_of(n)) and src.lang is Lang.GO:
            return True
        if n.type == "macro_invocation" and re.match(r"(panic|unreachable|todo|unimplemented)!", src.text_of(n)):
            return True
    return False


def has_logging(src: SourceFile, node: Node) -> bool:
    for n in walk(node):
        if src.lang is not None and n.type in CALL_TYPES.get(src.lang, set()):
            callee = re.sub(r"\s+", "", _callee_text(src, n))
            if LOG_CALL_RE.search(callee):
                return True
            if n.type == "macro_invocation" and LOG_MACRO_RE.search(src.text_of(n)):
                return True
    return False


def is_string_node(node: Node) -> bool:
    return node.type in STRING_TYPES


def string_value(src: SourceFile, node: Node) -> str:
    """따옴표와 접두사를 제거한 문자열 리터럴 본문 (보간식은 그대로 둔다)."""
    raw = src.text_of(node)
    raw = re.sub(r'^[rbfuRBFU$@]{0,3}("""|\'\'\'|"|\'|`)', "", raw)
    raw = re.sub(r'("""|\'\'\'|"|\'|`)$', "", raw)
    return raw


INTERPOLATION_TYPES = {"interpolation", "template_substitution", "interpolation_expression"}


def has_interpolation(node: Node) -> bool:
    for n in walk(node):
        if n is node:
            continue
        if n.type in INTERPOLATION_TYPES:
            return True
        if n.type == "variable_name" and node.type == "encapsed_string":
            return True
    return False


_LITERAL_TYPES = {
    "string",
    "string_literal",
    "interpreted_string_literal",
    "raw_string_literal",
    "verbatim_string_literal",
    "number",
    "integer",
    "float",
    "integer_literal",
    "decimal_integer_literal",
    "number_literal",
    "true",
    "false",
    "null",
    "none",
    "nil",
    "boolean",
    "string_fragment",
    "string_content",
    "escape_sequence",
}


def is_literal(node: Node) -> bool:
    if node.type in ("string", "template_string", "encapsed_string", "interpolated_string_expression"):
        return not has_interpolation(node)
    if node.type == "parenthesized_expression" and node.named_children:
        return is_literal(node.named_children[0])
    if node.type == "binary_expression" or node.type == "binary_operator":
        return all(is_literal(c) for c in node.named_children if "comment" not in c.type)
    return node.type in _LITERAL_TYPES


def is_dynamic_composition(src: SourceFile, node: Node) -> bool:
    """문자열을 변수와 결합·보간·포맷하여 만든 식인지 판정한다."""
    t = node.type
    if t in ("string", "template_string", "encapsed_string", "interpolated_string_expression"):
        return has_interpolation(node)
    if t in ("binary_expression", "binary_operator"):
        operator = node.child_by_field_name("operator")
        op = src.text_of(operator) if operator is not None else ""
        if op in ("+", ".", "%"):
            operands = [c for c in node.named_children if "comment" not in c.type]
            has_string = any(
                is_string_node(c) or (c.type in ("binary_expression", "binary_operator") and is_dynamic_composition(src, c))
                for c in operands
            )
            has_dynamic = any(not is_literal(c) for c in operands)
            return has_string and has_dynamic or op == "%" and has_dynamic
    if t in ("call", "call_expression", "method_invocation", "invocation_expression", "macro_invocation"):
        text = src.text_of(node)
        if re.search(r"\.format\(|String\.format\(|string\.Format\(|fmt\.Sprintf|format!\(|sprintf\(|\.concat\(|String\.Join\(|\.join\(", text):
            return not all(is_literal(a) for a in _args_of(node))
    if t in ("parenthesized_expression", "await_expression", "reference_expression", "unary_expression") and node.named_children:
        return is_dynamic_composition(src, node.named_children[-1])
    return False


PROPERTY_FIELDS = {
    "member_expression": "property",
    "attribute": "attribute",
    "field_expression": "field",
    "selector_expression": "field",
    "member_access_expression": "name",
    "method_invocation": "name",
    "scoped_identifier": "name",
}


def _is_property_position(node: Node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    field = PROPERTY_FIELDS.get(parent.type)
    if field is None:
        return False
    target = parent.child_by_field_name(field)
    return target is not None and target.id == node.id


def identifiers_in(src: SourceFile, node: Node) -> set[str]:
    """식에 쓰인 변수 이름들. 점 뒤의 속성·메서드 이름은 변수가 아니므로 제외한다."""
    names: set[str] = set()
    for n in walk(node):
        if n.type in ("identifier", "variable_name", "property_identifier", "field_identifier"):
            if (n.child_count == 0 or n.type == "variable_name") and not _is_property_position(n):
                names.add(src.text_of(n).lstrip("$"))
    return names
