"""
오철칙 파일 간 호출 해석: PHP
- 함수 호출 `run($x)`: 이 파일이 require·include한 파일의 함수, 없으면 프로젝트에서 그 이름의 전역 함수가 하나뿐일 때 그 함수
- static 호출 `Text::clean($x)`: `use`로 가져온 이름 또는 같은 이름의 클래스가 프로젝트에 하나뿐일 때 그 클래스의 static 메서드
같은 이름의 함수·클래스가 여럿이면 해석 공백이다. 객체 메서드 호출(`$o->m()`)은 형식을 모르므로 해석하지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import re
from pathlib import PurePosixPath
from posixpath import normpath

from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile

INCLUDE_TYPES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}


def build(index, sources: list[SourceFile]) -> None:
    from iron_laws.engine.ast_tools import iter_functions

    for s in sources:
        if s.lang is not Lang.PHP or s.is_test:
            continue
        rel = s.path.as_posix()
        for fn in iter_functions(s):
            if fn.node.type == "function_definition":
                index.php_functions.setdefault(fn.name.lower(), []).append(rel)
        for node in s.nodes:
            if node.type == "class_declaration":
                name = node.child_by_field_name("name")
                if name is not None:
                    index.php_classes.setdefault(s.text_of(name).lower(), []).append(rel)


def includes(src: SourceFile) -> list[str]:
    """require·include한 파일의 프로젝트 상대 경로(문자열 상수와 __DIR__ 조합만)"""

    def find() -> list[str]:
        here = PurePosixPath(src.path.as_posix()).parent
        found = []
        for node in src.nodes:
            if node.type not in INCLUDE_TYPES:
                continue
            text = src.text_of(node)
            m = re.search(r"['\"]([^'\"]+\.php)['\"]", text)
            if m:
                found.append(normpath(str(here / m.group(1).lstrip("/"))) if "__DIR__" in text or not m.group(1).startswith("/") else m.group(1).lstrip("/"))
        return found

    return src.memo("php_includes", find)


def uses(src: SourceFile) -> dict[str, str]:
    """use로 가져온 지역 이름(소문자) → 클래스 단순 이름(소문자)"""

    def find() -> dict[str, str]:
        table = {}
        for m in re.finditer(r"(?im)^\s*use\s+([\w\\]+)(?:\s+as\s+(\w+))?\s*;", src.code_text):
            simple = m.group(1).rsplit("\\", 1)[-1].lower()
            table[(m.group(2) or simple).lower()] = simple
        return table

    return src.memo("php_uses", find)


def _in_file(index, rel: str, name: str, static_class: str | None = None):
    from iron_laws.engine.ast_tools import iter_functions

    target = index.files.get(rel)
    if target is None:
        return []
    found = []
    for fn in iter_functions(target):
        if fn.name.lower() != name.lower():
            continue
        if static_class is None and fn.node.type == "function_definition":
            found.append((target, fn))
        elif static_class is not None and fn.node.type == "method_declaration" and re.search(r"\bstatic\b", target.text_of(fn.node).split("(", 1)[0]):
            cls = fn.node.parent
            while cls is not None and cls.type != "class_declaration":
                cls = cls.parent
            if cls is not None and target.text_of(cls.child_by_field_name("name")).lower() == static_class:
                found.append((target, fn))
    return found


def resolve(index, src: SourceFile, callee: str, argc: int):
    from iron_laws.engine.xfile import ResolveResult

    if "->" in callee or callee.startswith("$"):
        return ResolveResult([])
    if "::" in callee:
        owner, method = callee.rsplit("::", 1)
        if owner.lower() in ("self", "static", "parent"):
            return ResolveResult([])
        simple = uses(src).get(owner.lower(), owner.rsplit("\\", 1)[-1].lower())
        paths = index.php_classes.get(simple, [])
        if not paths:
            return ResolveResult([])
        if len(paths) > 1:
            return ResolveResult([], "ambiguous_class")
        return ResolveResult(_in_file(index, paths[0], method, static_class=simple))
    name = callee.rsplit("\\", 1)[-1]
    for rel in includes(src):
        found = _in_file(index, rel, name)
        if found:
            return ResolveResult(found)
    paths = [p for p in index.php_functions.get(name.lower(), []) if p != src.path.as_posix()]
    if not paths:
        return ResolveResult([])
    if len(paths) > 1:
        return ResolveResult([], "ambiguous_function")
    return ResolveResult(_in_file(index, paths[0], name))
