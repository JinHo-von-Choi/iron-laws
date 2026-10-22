from tree_sitter import Node

from iron_laws.engine import xfile, xfile_js
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    FUNCTION_TYPES,
    enclosing_function,
    identifiers_in,
    iter_calls,
    iter_functions,
    walk,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile


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


def _in_class(fn) -> bool:
    parent = fn.node.parent
    while parent is not None:
        if parent.type == "class_definition":
            return True
        parent = parent.parent
    return False


def _java_local_classes(src: SourceFile) -> set[str]:
    def find() -> set[str]:
        names = set()
        for node in src.nodes:
            if node.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
                ident = node.child_by_field_name("name")
                if ident is not None:
                    names.add(src.text_of(ident))
        return names

    return src.memo("java_local_classes", find)


_PARAM_TYPES = {"parameters", "formal_parameters", "lambda_parameters"}


_LOCAL_BIND_TYPES = {"assignment", "variable_declarator", "for_statement", "for_in_statement"}


def _scoped_names(src: SourceFile) -> set[str]:
    """함수 안에서 묶이는 이름(매개변수, 지역 대입·선언). 이 이름이 import 이름과 같으면 가림이 생길 수 있다."""

    def find() -> set[str]:
        names: set[str] = set()
        functions = FUNCTION_TYPES.get(src.lang, set()) if src.lang else set()
        for node in src.nodes:
            if node.type in _PARAM_TYPES and node.parent is not None and node.parent.type in functions | {"lambda"}:
                for child in node.named_children:
                    name = param_name(src, child) if child.type not in ("identifier",) else src.text_of(child)
                    if name:
                        names.add(name)
            elif node.type in _LOCAL_BIND_TYPES and enclosing_function(node, src.lang) is not None:
                target = node.child_by_field_name("left") or node.child_by_field_name("name")
                if target is not None:
                    names |= identifiers_in(src, target)
        return names

    return src.memo("scoped_names", find)


def _module_rebinds(src: SourceFile, name: str) -> bool:
    """모듈 최상위에서 name에 값을 대입하면 그 이름이 가리키는 함수를 정할 수 없다."""
    if src.root is None:
        return False
    return name in _module_rebound_names(src)


def _module_rebound_names(src: SourceFile) -> set[str]:
    """모듈 최상위에서 값을 다시 대입한 이름들. 호출마다 훑지 않도록 파일마다 한 번만 구한다."""
    def find() -> set[str]:
        names: set[str] = set()
        root = src.root
        if root is None:
            return names
        for stmt in root.named_children:
            node = stmt.named_children[0] if stmt.type == "expression_statement" and stmt.named_children else stmt
            if node.type in ("assignment", "augmented_assignment"):
                left = node.child_by_field_name("left")
                targets = [left] if left is not None and left.type == "identifier" else (left.named_children if left is not None and left.type in ("pattern_list", "tuple_pattern", "list_pattern") else [])
                for t in targets:
                    if t.type == "identifier":
                        names.add(src.text_of(t))
        return names

    return src.memo("module_rebound_names", find)


def resolve_any(src: SourceFile, callee: str, argc: int) -> list[tuple[SourceFile, object]]:
    """호출 대상 함수 후보. Python은 이름의 바인딩을 먼저 본다: import로 묶인 이름이면 import 대상,
    같은 파일 정의면 그 함수, 둘 다 있으면 양쪽을 모두 후보로 둔다(어느 쪽이든 오염을 돌려주면 오염).
    모듈 최상위에서 이름을 다시 대입하면 대상을 정할 수 없어 후보를 내지 않는다. 다른 언어는 같은 파일 함수가 우선이다."""
    local = [(src, fn) for fn in resolve_helper(src, callee, argc)]
    if src.lang is Lang.JAVA and "." in callee:
        receiver = callee.rsplit(".", 1)[0]
        if receiver[:1].isupper() and receiver not in _java_local_classes(src):
            return xfile.resolve_external(src, callee, argc)  # 다른 클래스의 static 호출은 같은 이름의 이 파일 메서드가 아니다
    head = callee.split(".", 1)[0]
    if src.lang in JS_FAMILY:
        if head in _scoped_names(src) and head in xfile_js.imports(src):
            return []  # 매개변수·지역 변수가 import 이름을 가리면 어느 쪽이 호출되는지 정할 수 없다
        return local or xfile.resolve_external(src, callee, argc)
    if src.lang is not Lang.PYTHON:
        return local or xfile.resolve_external(src, callee, argc)
    if head in _scoped_names(src) and head in xfile.imported_names(src):
        return []
    if "." not in callee:
        if _module_rebinds(src, callee):
            return []
        local = [(s, fn) for s, fn in local if not _in_class(fn)]  # 메서드는 맨 이름 호출로 불리지 않는다
    if local and head not in xfile.imported_names(src):
        return local
    external = xfile.resolve_external(src, callee, argc)
    return local + [t for t in external if t not in local]
