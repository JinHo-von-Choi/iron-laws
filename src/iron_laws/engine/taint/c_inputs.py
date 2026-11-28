"""
C·C++ 입력 함수와 객체형 매크로: 결과를 반환하지 않고 인자 버퍼에 쓰는 입력 함수(fgets·recv·scanf 등)와
문자열을 다른 버퍼로 옮기는 함수(strcpy·strncat 등)의 오염 전파, 같은 파일과 프로젝트 헤더의 `#define 이름 값` 펼치기
- 입력이 쓰이는 인자 위치: fgets·gets·fgetws·fread 0, recv·recvfrom·read 1, scanf 서식 뒤, fscanf 서식(1) 뒤.
  버퍼 인자에 오프셋·형변환(`data + dataLen`, `(char *)(data + n)`)이 있어도 바탕 변수를 오염시킨다.
- 대입을 억제하는 서식(`%*s`)의 자리, 프로젝트 안의 고정 파일 이름으로 연 스트림에서 읽는 fgets·fread는 입력으로 보지 않는다.
- getenv 반환값은 외부 입력이다.
- 함수형 매크로는 펼치지 않는다.
작성자: 최진호
작성일: 2026-11-24
"""

import re
from pathlib import Path

from tree_sitter import Node

from iron_laws.engine.languages import C_FAMILY
from iron_laws.engine.source import SourceFile

INPUT_BUFFERS: dict[str, int] = {"fgets": 0, "gets": 0, "fgetws": 0, "fread": 0, "recv": 1, "recvfrom": 1, "read": 1, "_read": 1}
INPUT_STREAM_ARG: dict[str, int] = {"fgets": 2, "fgetws": 2, "fread": 3}
SCANF_FORMAT: dict[str, int] = {"scanf": 0, "wscanf": 0, "fscanf": 1, "fwscanf": 1}
# (목적지 인자 위치, 원본 인자 위치들). 원본이 오염되면 목적지 버퍼가 오염된다
COPY_FUNCTIONS: dict[str, tuple[int, tuple[int, ...]]] = {
    "strcpy": (0, (1,)), "strncpy": (0, (1,)), "strcat": (0, (1,)), "strncat": (0, (1,)), "wcscpy": (0, (1,)), "wcsncpy": (0, (1,)),
    "wcscat": (0, (1,)), "wcsncat": (0, (1,)), "memcpy": (0, (1,)), "memmove": (0, (1,)), "strlcpy": (0, (1,)), "strlcat": (0, (1,)),
    "sprintf": (0, (2, 3, 4, 5, 6)), "snprintf": (0, (3, 4, 5, 6, 7)), "swprintf": (0, (3, 4, 5, 6, 7)),
}
RETURNS_INPUT = frozenset({"getenv", "secure_getenv", "_wgetenv", "_wgetenv_s"})
_INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)
_DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)[ \t]+([^\n]*?)\s*$", re.MULTILINE)


def _header_macros(path: Path, seen: set[Path]) -> dict[str, set[str]]:
    if path in seen or not path.is_file() or len(seen) > 20:
        return {}
    seen.add(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:  # iron-laws: ignore[IL-301] 읽지 못한 헤더의 매크로는 펼치지 않는다(펼치지 않으면 지금처럼 판정한다)
        return {}
    table = _defines(text)
    for name in _INCLUDE_RE.findall(text):
        for key, values in _header_macros(path.parent / name, seen).items():
            table.setdefault(key, set()).update(values)
    return table


def _defines(text: str) -> dict[str, set[str]]:
    table: dict[str, set[str]] = {}
    for name, value in _DEFINE_RE.findall(text):
        value = re.sub(r"/\*.*?\*/|//.*$", "", value).strip()
        if value and "(" not in name:
            table.setdefault(name, set()).add(value)
    return table


def macro_table(src: SourceFile) -> dict[str, set[str]]:
    """이 파일과 이 파일이 따옴표로 포함한 프로젝트 헤더의 객체형 매크로: 이름 → 값들(#ifdef 갈래마다 하나)"""

    def build() -> dict[str, set[str]]:
        from iron_laws.engine import xfile

        table = _defines(src.text)
        index = xfile.get_index()
        root = index.root if index is not None else None
        if root is not None:
            seen: set[Path] = set()
            for name in _INCLUDE_RE.findall(src.text):
                for key, values in _header_macros((root / src.path).parent / name, seen).items():
                    table.setdefault(key, set()).update(values)
        return table

    return src.memo("c_macro_table", build)


def expand_name(src: SourceFile, name: str, depth: int = 0) -> set[str]:
    """이름이 객체형 매크로로 가리키는 식별자들(여러 단계를 따라간다). 매크로가 아니면 빈 집합"""
    if src.lang not in C_FAMILY or depth > 4:
        return set()
    found: set[str] = set()
    for value in macro_table(src).get(name, set()):
        if re.fullmatch(r"[A-Za-z_]\w*", value):
            found.add(value)
            found |= expand_name(src, value, depth + 1)
    return found


def callee_names(src: SourceFile, callee: str) -> set[str]:
    """호출 이름과 매크로를 펼친 이름들"""
    return {callee, *expand_name(src, callee)}


def base_variable(src: SourceFile, node: Node | None) -> str | None:
    """버퍼 인자의 바탕 변수: `data + dataLen`, `(char *)(data + n)`, `&buf[i]`, `buf`"""
    while node is not None:
        if node.type == "identifier":
            names = expand_name(src, src.text_of(node))
            return next(iter(sorted(names))) if len(names) == 1 else src.text_of(node)
        if node.type == "parenthesized_expression":
            node = node.named_children[0] if node.named_children else None
        elif node.type == "cast_expression":
            node = node.child_by_field_name("value")
        elif node.type == "pointer_expression":
            node = node.child_by_field_name("argument")
        elif node.type == "subscript_expression":
            node = node.child_by_field_name("argument")
        elif node.type == "binary_expression" and src.text_of(node.child_by_field_name("operator") or node) in ("+", "-"):
            node = node.child_by_field_name("left")
        else:
            return None
    return None


def _fixed_file_stream(src: SourceFile, stream: Node, scope: Node | None) -> bool:
    """fopen("고정 이름", ...)으로 연 스트림이다(프로젝트 안의 파일이라 외부 입력으로 보지 않는다)"""
    if stream.type != "identifier" or scope is None:
        return False
    from iron_laws.engine.taint.definitions import definitions

    defs = definitions(src, scope, src.text_of(stream))
    return bool(defs) and all(re.match(r"\s*(?:FOPEN|fopen|_wfopen)\s*\(\s*(?:L)?\"", src.text_of(d)) for d in defs)


def _scanf_outputs(src: SourceFile, fmt: Node, args: list[Node]) -> list[Node]:
    text = src.text_of(fmt)
    conversions = re.findall(r"%(\*?)\d*(?:hh|h|ll|l|L|z|j|t)?([diouxXeEfgGaAcspn\[])", text.replace("%%", ""))
    outputs = []
    for (suppressed, kind), arg in zip(conversions, args, strict=False):
        if not suppressed and kind != "n":
            outputs.append(arg)
    return outputs


def input_targets(src: SourceFile, callee: str, args: list[Node], scope: Node | None) -> list[str]:
    """입력 함수가 외부 입력을 써 넣는 버퍼의 바탕 변수들"""
    names = callee_names(src, callee)
    targets: list[Node] = []
    for name in names:
        if name in INPUT_BUFFERS and len(args) > INPUT_BUFFERS[name]:
            stream_at = INPUT_STREAM_ARG.get(name)
            if stream_at is not None and len(args) > stream_at and _fixed_file_stream(src, args[stream_at], scope):
                continue
            targets.append(args[INPUT_BUFFERS[name]])
        elif name in SCANF_FORMAT and len(args) > SCANF_FORMAT[name]:
            at = SCANF_FORMAT[name]
            targets.extend(_scanf_outputs(src, args[at], args[at + 1 :]))
    return [v for v in (base_variable(src, t) for t in targets) if v]


def copy_flow(src: SourceFile, callee: str) -> tuple[int, tuple[int, ...]] | None:
    for name in callee_names(src, callee):
        if name in COPY_FUNCTIONS:
            return COPY_FUNCTIONS[name]
    return None


def returns_input(src: SourceFile, callee: str) -> bool:
    return bool(callee_names(src, callee) & RETURNS_INPUT)
