"""
오철칙 파일 간 호출 해석: Python
import 문을 따라 다른 파일의 최상위 함수를 찾는다. 모듈 이름이 둘 이상의 파일에 맞고 가까운 쪽을 정할 수 없으면 해석 공백으로 남긴다.
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import PurePosixPath

from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile


def build(index, sources: list[SourceFile]) -> None:
    for s in sources:
        if s.lang is Lang.PYTHON:
            rel = s.path.as_posix()
            for name in _module_names(rel):
                index.modules.setdefault(name, []).append(rel)


def lookup_module(index, name: str, from_path: str) -> str | None:
    return _lookup(index, name, from_path)[0]


def _lookup(index, name: str, from_path: str) -> tuple[str | None, bool]:
    """(파일, 모호했는지)"""
    candidates = index.modules.get(name, [])
    if len(candidates) == 1:
        return candidates[0], False
    if not candidates:
        return None, False
    origin = PurePosixPath(from_path).parts
    scored = sorted(((_common_prefix(origin, PurePosixPath(c).parts), c) for c in candidates), reverse=True)
    if scored[0][0] == scored[1][0]:
        return None, True  # 어느 파일인지 정할 수 없으면 연결하지 않는다
    return scored[0][1], False


def resolve(index, src: SourceFile, callee: str, argc: int):
    from iron_laws.engine.xfile import ResolveResult

    table = imports(src)
    parts = callee.split(".")
    module_name: str | None = None
    function: str
    if len(parts) == 1:
        entry = table.get(parts[0])
        if entry is None or entry[1] is None:
            return ResolveResult([])
        module_name, function = entry[0], entry[1]
    else:
        function = parts[-1]
        prefix = ".".join(parts[:-1])
        entry = table.get(prefix)
        if entry is not None and entry[1] is None:
            module_name = entry[0]
        else:
            head = table.get(parts[0])
            if head is not None and head[1] is not None:
                module_name = ".".join([head[0], head[1], *parts[1:-1]])
            elif head is not None:
                module_name = ".".join([head[0], *parts[1:-1]])
    if not module_name:
        return ResolveResult([])
    rel, ambiguous = _lookup(index, module_name, src.path.as_posix())
    if rel is None:
        return ResolveResult([], "ambiguous_module" if ambiguous else None)
    target = index.files[rel]
    return ResolveResult([(target, fn) for fn in _top_level_functions(target, function, argc)])


def _module_names(rel: str) -> list[str]:
    parts = list(PurePosixPath(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return [".".join(parts[i:]) for i in range(len(parts))]


def _common_prefix(a: tuple[str, ...], b: tuple[str, ...]) -> int:
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n


def _top_level_functions(src: SourceFile, name: str, argc: int):
    from iron_laws.engine.ast_tools import iter_functions

    found = []
    for fn in iter_functions(src):
        if fn.name != name:
            continue
        parent = fn.node.parent
        in_class = False
        while parent is not None:
            if parent.type == "class_definition":
                in_class = True
                break
            parent = parent.parent
        params = [p for p in fn.params if src.text_of(p) not in ("self", "cls")]
        if not in_class and len(params) == argc:
            found.append(fn)
    return found


def _relative_module(src: SourceFile, text: str) -> str:
    dots = len(text) - len(text.lstrip("."))
    rest = text.lstrip(".")
    base = list(src.path.parent.parts)
    if dots > 1:
        base = base[: max(0, len(base) - (dots - 1))]
    return ".".join([*base, *([rest] if rest else [])])


def imported_names(src: SourceFile) -> set[str]:
    """import로 이 파일에 묶인 지역 이름"""
    return set(imports(src))


def imports(src: SourceFile) -> dict[str, tuple[str, str | None]]:
    """지역 이름 → (모듈, 가져온 이름). import a.b as m 이면 m → (a.b, None)"""

    def build_table() -> dict[str, tuple[str, str | None]]:
        table: dict[str, tuple[str, str | None]] = {}
        for node in src.nodes:
            if node.type == "import_statement":
                for child in node.named_children:
                    if child.type == "aliased_import":
                        name, alias = child.child_by_field_name("name"), child.child_by_field_name("alias")
                        if name is not None and alias is not None:
                            table[src.text_of(alias)] = (src.text_of(name), None)
                    elif child.type == "dotted_name":
                        text = src.text_of(child)
                        table[text] = (text, None)
            elif node.type == "import_from_statement":
                module = node.child_by_field_name("module_name")
                if module is None:
                    continue
                module_text = src.text_of(module)
                if module_text.startswith("."):
                    module_text = _relative_module(src, module_text)
                for child in node.children_by_field_name("name"):
                    if child.type == "aliased_import":
                        name, alias = child.child_by_field_name("name"), child.child_by_field_name("alias")
                        if name is not None and alias is not None:
                            table[src.text_of(alias)] = (module_text, src.text_of(name))
                    else:
                        text = src.text_of(child)
                        table[text] = (module_text, text)
        return table

    return src.memo("py_imports", build_table)
