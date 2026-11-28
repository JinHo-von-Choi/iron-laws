"""
Java 설정 값 해석: `Properties.getProperty(키, 기본값)`과 Spring `@Value("${키:기본값}")`이 실제로 돌려줄 값을
프로젝트 리소스 파일(.properties)에서 찾는다. 값마다 그 값을 쓴다는 근거의 강도(확정·확인 필요)를 함께 돌려준다.
작성자: 최진호
작성일: 2026-11-24
"""

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from tree_sitter import Node

from iron_laws.engine.ast_tools import enclosing_function, iter_calls, string_value, walk
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import reaching_definitions

RESOURCE_DIRS = ("src/main/resources/", "src/test/resources/", "resources/")
LOAD_RESOURCE_RE = re.compile(r"getResourceAsStream\s*\(\s*\"/?([^\"]+)\"\s*\)")
SPRING_VALUE_RE = re.compile(r"@(?:[\w.]+\.)?Value\s*\(\s*\"\$\{([^:}]+)(?::([^}]*))?\}\"\s*\)")


@dataclass(frozen=True)
class ConfigValue:
    value: str
    confirmed: bool  # 이 값을 쓴다는 근거가 코드와 저장소 파일에 있다(외부 설정이 덮어쓸 수 없다)
    origin: str  # 사람이 읽을 출처 설명


def parse_properties(text: str) -> dict[str, str]:
    """Java .properties의 `키=값`·`키: 값` 줄. 주석(#, !)과 줄 이어쓰기(\\)를 처리한다"""
    values: dict[str, str] = {}
    pending = ""
    for raw in text.splitlines():
        line = pending + raw.strip()
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending = line[:-1]
            continue
        pending = ""
        if not line or line[0] in "#!":
            continue
        m = re.match(r"((?:\\.|[^=:\s])+)\s*[=:\s]\s*(.*)$", line)
        if m:
            values[m.group(1).replace("\\", "")] = m.group(2)
    return values


def properties_index(files: list[SourceFile]) -> dict[str, dict[str, str]]:
    """리소스 폴더의 .properties 파일: 파일 이름 → (키 → 값). 같은 이름이 여러 곳에 있으면 그 이름은 쓰지 않는다"""
    index: dict[str, dict[str, str]] = {}
    clashes: set[str] = set()
    for f in files:
        rel = f.path.as_posix()
        if f.kind != "properties" or f.is_test or not any(d in f"/{rel}" or rel.startswith(d) for d in RESOURCE_DIRS):
            continue
        name = PurePosixPath(rel).name
        if name in index:
            clashes.add(name)
        index[name] = parse_properties(f.text)
    return {name: table for name, table in index.items() if name not in clashes}


def _loaded_resource(src: SourceFile, scope: Node, receiver: str, before: int) -> tuple[str, Node] | None:
    """receiver.load(...getResourceAsStream("이름")) 호출이 before 앞에 하나만 있으면 (리소스 이름, load 호출)"""
    loads = [
        c for c in iter_calls(src)
        if c.callee == f"{receiver}.load" and scope.start_byte <= c.node.start_byte and c.node.end_byte <= before
    ]
    if len(loads) != 1:
        return None
    m = LOAD_RESOURCE_RE.search(src.text_of(loads[0].node))
    return (PurePosixPath(m.group(1)).name, loads[0].node) if m else None


def _try_body_of(node: Node) -> Node | None:
    parent = node.parent
    while parent is not None and parent.type not in ("method_declaration", "constructor_declaration", "lambda_expression"):
        if parent.type in ("try_statement", "try_with_resources_statement"):
            return parent.child_by_field_name("body")
        parent = parent.parent
    return None


def _property_values(src: SourceFile, call: Node, props: dict[str, dict[str, str]]) -> list[ConfigValue] | None:
    function = call.child_by_field_name("name")
    receiver = call.child_by_field_name("object")
    arguments = call.child_by_field_name("arguments")
    args = [a for a in arguments.named_children if "comment" not in a.type] if arguments is not None else []
    if function is None or src.text_of(function) != "getProperty" or not args or args[0].type != "string_literal":
        return None
    key = string_value(src, args[0])
    default = string_value(src, args[1]) if len(args) > 1 and args[1].type == "string_literal" else None
    receiver_text = src.text_of(receiver) if receiver is not None else ""
    scope = enclosing_function(call, src.lang)
    loaded = _loaded_resource(src, scope, receiver_text, call.start_byte) if scope is not None and re.fullmatch(r"\w+", receiver_text) else None
    if loaded is not None:
        name, load = loaded
        table = props.get(name)
        # 읽기 실패를 잡아 삼키고 계속하면 기본값을 쓸 수도 있다. load와 getProperty가 같은 try 본문에 있어야 실패 시 getProperty가 실행되지 않는다
        same_try = _try_body_of(load) is not None and _try_body_of(load) == _try_body_of(call)
        if table is not None and key in table:
            return [ConfigValue(table[key], same_try or _try_body_of(load) is None, f"{name}의 {key}")]
        if table is not None and default is not None:
            return [ConfigValue(default, same_try or _try_body_of(load) is None, f"{name}에 {key} 키가 없어 쓰는 기본값")]
    if default is not None:
        return [ConfigValue(default, False, f"{key}의 기본값(설정 파일에서 값을 확인하지 못함)")]
    return []


def _spring_values(src: SourceFile, field: Node, props: dict[str, dict[str, str]]) -> list[ConfigValue]:
    """@Value("${키:기본값}") 필드. 외부 설정이 저장소 파일을 덮어쓸 수 있으므로 값은 모두 확인 필요 근거다"""
    m = SPRING_VALUE_RE.search(src.text_of(field))
    if m is None:
        return []
    key, default = m.group(1).strip(), m.group(2)
    found = [ConfigValue(t[key], False, f"{name}의 {key}") for name, t in props.items() if name.startswith("application") and key in t]
    if default is not None:
        found.append(ConfigValue(default, False, f"{key}의 기본값"))
    return found


def _field_declaration(src: SourceFile, node: Node, name: str) -> Node | None:
    cls = node.parent
    while cls is not None and cls.type != "class_body":
        cls = cls.parent
    if cls is None:
        return None
    for child in cls.named_children:
        if child.type != "field_declaration":
            continue
        for d in child.named_children:
            if d.type == "variable_declarator" and src.text_of(d.child_by_field_name("name") or d) == name:
                return child
    return None


def config_values(src: SourceFile, node: Node, props: dict[str, dict[str, str]], depth: int = 0) -> list[ConfigValue] | None:
    """식이 설정 파일에서 읽은 값이면 그 후보 값들. 설정 값과 관계없는 식이면 None.
    값이 둘 이상으로 갈리거나 다시 대입되면 모든 후보를 확인 필요 근거로 낮춘다"""
    if depth > 2:
        return None
    if node.type == "method_invocation":
        return _property_values(src, node, props)
    if node.type != "identifier":
        return None
    scope = enclosing_function(node, src.lang)
    name = src.text_of(node)
    defs = reaching_definitions(src, scope, name, node.start_byte) if scope is not None else []
    if not defs:
        field = _field_declaration(src, node, name)
        return (_spring_values(src, field, props) or None) if field is not None else None
    found: list[ConfigValue] = []
    literals: list[ConfigValue] = []
    for d in defs:
        values = config_values(src, d, props, depth + 1)
        if values is not None:
            found.extend(values)
        elif d.type == "string_literal":
            literals.append(ConfigValue(string_value(src, d), False, f"{name}에 대입한 값"))
        else:
            return None
    if not found:
        return None  # 설정 파일과 관계없는 값이다. 리터럴은 줄 단위 검사가 판정한다
    found.extend(literals)
    if len(defs) > 1:
        found = [ConfigValue(v.value, False, v.origin + ", 값이 둘 이상으로 갈림") for v in found]
    return found


def property_defaults(src: SourceFile) -> list[Node]:
    """getProperty(키, 기본값)의 기본값 문자열. 기본값은 알고리즘을 쓰는 곳이 아니라 후보 값이다"""
    found = []
    for n in walk(src.root) if src.root is not None else []:
        if n.type != "method_invocation":
            continue
        name = n.child_by_field_name("name")
        arguments = n.child_by_field_name("arguments")
        if name is None or arguments is None or src.text_of(name) != "getProperty":
            continue
        args = [a for a in arguments.named_children if "comment" not in a.type]
        if len(args) == 2 and args[1].type == "string_literal" and args[1].start_point[0] == args[1].end_point[0]:
            found.append(args[1])
    return found
