"""
공개 API 진입점: 라이브러리처럼 쓰이는 코드에서 공개 함수의 매개변수를 외부 입력으로 볼 때 쓴다(설정 policies.entry_points: public_api).
- 공개 기준: Python은 이름이 `_`로 시작하지 않는 모듈 수준 함수와 (공개 클래스의) 메서드, JS·TS는 export한 함수,
  Go는 대문자로 시작하는 함수, Java·C#은 public 클래스의 public 메서드
- 매개변수 형식: 문자열·바이트·스트림·경로·URL. 형식을 적지 않는 언어(Python 주석 없음, JS)는 형식을 따지지 않는다
작성자: 최진호
작성일: 2026-11-24
"""

import re

from tree_sitter import Node

from iron_laws.engine.ast_tools import Func, iter_functions
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile

PARAM_TYPES: dict[Lang, re.Pattern[str]] = {
    Lang.PYTHON: re.compile(r"\b(str|bytes|bytearray|Path|PurePath|PathLike|IO|TextIO|BinaryIO|AnyStr|URL)\b"),
    Lang.TYPESCRIPT: re.compile(r"\b(string|Buffer|URL|Readable)\b"),
    Lang.TSX: re.compile(r"\b(string|Buffer|URL|Readable)\b"),
    Lang.GO: re.compile(r"(^|\s)(string|\[\]byte|io\.Reader|\*url\.URL|\*os\.File)\s*$"),
    Lang.JAVA: re.compile(r"\b(String|CharSequence|byte\s*\[\]|char\s*\[\]|InputStream|Reader|Path|File|URL|URI)\b"),
    Lang.KOTLIN: re.compile(r"\b(String|CharSequence|ByteArray|InputStream|Reader|Path|File|URL|URI)\b"),
    Lang.CSHARP: re.compile(r"\b(string|String|byte\s*\[\]|Stream|TextReader|Uri)\b"),
}
UNTYPED = frozenset({Lang.PYTHON, Lang.JAVASCRIPT})


def _modifiers(src: SourceFile, node: Node) -> str:
    mods = next((c for c in node.named_children if c.type == "modifiers"), None)
    return src.text_of(mods) if mods is not None else ""


def _enclosing_class(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in ("class_declaration", "class_definition", "interface_declaration", "record_declaration", "struct_declaration"):
            return current
        current = current.parent
    return None


def _js_exported(src: SourceFile, fn: Func) -> bool:
    current = fn.node.parent
    while current is not None and current.type not in ("program",):
        if current.type in ("export_statement",):
            return True
        current = current.parent
    name = re.escape(fn.name)
    return re.search(rf"\bmodule\.exports\s*=\s*\{{[^}}]*\b{name}\b|\b(?:module\.)?exports\.{name}\s*=|\bmodule\.exports\s*=\s*{name}\b", src.code_text) is not None


def is_public(src: SourceFile, fn: Func) -> bool:
    name = fn.name.rsplit(".", 1)[-1]
    if not name or name.startswith("<"):
        return False
    if src.lang is Lang.PYTHON:
        cls = _enclosing_class(fn.node)
        owner = src.text_of(cls.child_by_field_name("name")) if cls is not None and cls.child_by_field_name("name") is not None else ""
        return not name.startswith("_") and not owner.startswith("_")
    if src.lang in JS_FAMILY:
        return _js_exported(src, fn)
    if src.lang is Lang.GO:
        return name[:1].isupper()
    if src.lang in (Lang.JAVA, Lang.CSHARP, Lang.KOTLIN):
        cls = _enclosing_class(fn.node)
        if src.lang is Lang.KOTLIN:
            return "private" not in _modifiers(src, fn.node) and "internal" not in _modifiers(src, fn.node)
        return "public" in _modifiers(src, fn.node).split() and cls is not None and "public" in _modifiers(src, cls).split()
    return False


def entry_params(src: SourceFile, fn: Func) -> frozenset[str]:
    """공개 함수에서 외부 입력으로 볼 매개변수 이름(문자열·바이트·스트림·경로·URL 형식)"""
    from iron_laws.engine.taint import param_name

    names = set()
    pattern = PARAM_TYPES.get(src.lang) if src.lang is not None else None
    for param in fn.params:
        name = param_name(src, param)
        text = src.text_of(param)
        if not name or name in ("self", "cls", "this"):
            continue
        typed = ":" in text if src.lang is Lang.PYTHON else src.lang not in UNTYPED
        if typed and (pattern is None or not pattern.search(text.replace(name, " ", 1) if src.lang is not Lang.GO else text.split(None, 1)[-1])):
            continue
        names.add(name)
    return frozenset(names)


def public_entries(src: SourceFile) -> list[tuple[Func, frozenset[str]]]:
    """시험이 아닌 파일의 공개 함수와 그 입력 매개변수"""
    if src.is_test or src.root is None:
        return []

    def build() -> list[tuple[Func, frozenset[str]]]:
        found = []
        for fn in iter_functions(src):
            if is_public(src, fn):
                params = entry_params(src, fn)
                if params:
                    found.append((fn, params))
        return found

    return src.memo("public_entries", build)
