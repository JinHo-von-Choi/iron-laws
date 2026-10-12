"""
오철칙 파일 간 호출 해석: Java
- `Owner.method(...)` static 메서드 호출: Owner는 명시 import, 같은 패키지, 와일드카드 import 순으로 찾는다.
- `field.method(...)`·`this.field.method(...)` 주입 필드 호출: 필드의 선언 형식이 클래스면 그 클래스, 인터페이스면 구현 클래스가
  하나일 때 그 클래스(여럿이면 @Primary가 하나일 때만)의 인스턴스 메서드를 따른다. @Profile이 붙은 구현이 섞이면 실행 설정에 따라
  달라지므로 해석 공백이다. 메서드 안의 지역 변수·매개변수가 필드 이름을 가리면 해석하지 않는다.
- 후보 클래스가 둘 이상이거나 같은 인자 수의 메서드가 둘 이상(형식으로 갈리는 중복 정의)이면 해석 공백으로 남긴다. 시험 소스의 클래스는 후보에서 뺀다.
작성자: 최진호
작성일: 2026-10-12
"""

import re

from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile

CLASS_TYPES = ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration")


def _annotations(src: SourceFile, node) -> set[str]:
    mods = next((c for c in node.named_children if c.type == "modifiers"), None)
    names = set()
    for a in mods.named_children if mods is not None else []:
        name = a.child_by_field_name("name")
        if name is not None:
            names.add(src.text_of(name).rsplit(".", 1)[-1])
    return names


def build(index, sources: list[SourceFile]) -> None:
    for s in sources:
        if s.lang is not Lang.JAVA or s.is_test:
            continue
        package = package_of(s)
        for node in s.root.named_children if s.root is not None else []:
            if node.type in CLASS_TYPES:
                name = node.child_by_field_name("name")
                if name is None:
                    continue
                fqcn = f"{package}.{s.text_of(name)}" if package else s.text_of(name)
                index.java_classes.setdefault(fqcn, []).append(s.path.as_posix())
                if node.type != "class_declaration":
                    continue
                supers = []
                interfaces = node.child_by_field_name("interfaces")
                superclass = node.child_by_field_name("superclass")
                for holder in (interfaces, superclass):
                    for t in (n for n in _walk_types(holder)):
                        supers.append(s.text_of(t))
                for super_name in supers:
                    index.java_impls.setdefault(super_name, []).append((fqcn, frozenset(_annotations(s, node))))


def _walk_types(node):
    if node is None:
        return
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "type_identifier" and (n.parent is None or n.parent.type != "type_arguments"):
            yield n
            continue
        if n.type == "type_arguments":
            continue
        stack.extend(n.named_children)


def package_of(src: SourceFile) -> str:
    def find() -> str:
        for node in src.root.named_children if src.root is not None else []:
            if node.type == "package_declaration":
                for child in node.named_children:
                    if child.type in ("scoped_identifier", "identifier"):
                        return src.text_of(child)
        return ""

    return src.memo("java_package", find)


def imports(src: SourceFile) -> tuple[dict[str, str], list[str]]:
    """(단순 이름 → 정규 이름, 와일드카드로 가져온 패키지 목록). static import는 다루지 않는다."""

    def find() -> tuple[dict[str, str], list[str]]:
        named: dict[str, str] = {}
        wildcard: list[str] = []
        for node in src.root.named_children if src.root is not None else []:
            if node.type != "import_declaration":
                continue
            text = src.text_of(node)
            if " static " in f" {text} ":
                continue
            body = text.removeprefix("import").strip().rstrip(";").strip()
            if body.endswith(".*"):
                wildcard.append(body[:-2])
            elif body:
                named[body.rsplit(".", 1)[-1]] = body
        return named, wildcard

    return src.memo("java_imports", find)


def _owner_candidates(index, src: SourceFile, owner: str) -> list[str]:
    if "." in owner:
        return [owner] if owner in index.java_classes else []
    named, wildcard = imports(src)
    if owner in named:
        return [named[owner]] if named[owner] in index.java_classes else []
    package = package_of(src)
    same = f"{package}.{owner}" if package else owner
    if same in index.java_classes:
        return [same]
    return [f"{p}.{owner}" for p in wildcard if f"{p}.{owner}" in index.java_classes]


def _field_types(src: SourceFile) -> dict[str, set[str]]:
    """파일의 클래스 필드 이름 → 선언 형식(단순 이름)"""

    def find() -> dict[str, set[str]]:
        fields: dict[str, set[str]] = {}
        for node in src.nodes:
            if node.type != "field_declaration":
                continue
            type_node = node.child_by_field_name("type")
            if type_node is None:
                continue
            type_name = src.text_of(type_node).split("<", 1)[0].rsplit(".", 1)[-1]
            for decl in node.children_by_field_name("declarator"):
                name = decl.child_by_field_name("name")
                if name is not None:
                    fields.setdefault(src.text_of(name), set()).add(type_name)
        return fields

    return src.memo("java_field_types", find)


def _shadowing_names(src: SourceFile) -> set[str]:
    """메서드 안의 지역 변수와 (생성자가 아닌) 메서드의 매개변수 이름. 필드 이름을 가리면 그 호출은 필드가 아니다."""

    def find() -> set[str]:
        names: set[str] = set()
        for node in src.nodes:
            if node.type == "local_variable_declaration":
                for decl in node.children_by_field_name("declarator"):
                    name = decl.child_by_field_name("name")
                    if name is not None:
                        names.add(src.text_of(name))
            elif node.type == "formal_parameter" and node.parent is not None and node.parent.parent is not None and node.parent.parent.type == "method_declaration":
                name = node.child_by_field_name("name")
                if name is not None:
                    names.add(src.text_of(name))
        return names

    return src.memo("java_shadowing", find)


def _instance_methods(index, fqcn: str, method: str, argc: int):
    from iron_laws.engine.ast_tools import iter_functions

    paths = index.java_classes.get(fqcn, [])
    if len(paths) != 1:
        return None
    target = index.files[paths[0]]
    simple = fqcn.rsplit(".", 1)[-1]
    bodies = [n.child_by_field_name("body") for n in target.root.named_children if n.type in CLASS_TYPES and target.text_of(n.child_by_field_name("name")) == simple]
    found = []
    for fn in iter_functions(target):
        if fn.name != method or len(fn.params) != argc or fn.node.parent not in bodies:
            continue
        modifiers = next((n for n in fn.node.named_children if n.type == "modifiers"), None)
        if modifiers is None or "static" not in target.text_of(modifiers).split():
            found.append((target, fn))
    return found


def _resolve_field(index, src: SourceFile, field: str, method: str, argc: int):
    from iron_laws.engine.xfile import ResolveResult

    types = _field_types(src).get(field)
    if not types:
        return ResolveResult([])
    if field in _shadowing_names(src):
        return ResolveResult([], "shadowed_field")
    if len(types) > 1:
        return ResolveResult([], "ambiguous_field")
    type_name = next(iter(types))
    declared = _owner_candidates(index, src, type_name)
    if len(declared) > 1:
        return ResolveResult([], "ambiguous_class")
    if not declared:
        return ResolveResult([])  # 라이브러리 형식(JdbcTemplate 등)은 프로젝트 함수가 아니다
    paths = index.java_classes[declared[0]]
    is_interface = len(paths) == 1 and any(
        n.type == "interface_declaration" and index.files[paths[0]].text_of(n.child_by_field_name("name")) == type_name
        for n in index.files[paths[0]].root.named_children
    )
    target_class = declared[0]
    if is_interface:
        impls = index.java_impls.get(type_name, [])
        if not impls:
            return ResolveResult([], "no_implementation")
        if any("Profile" in ann for _, ann in impls) and len(impls) > 1:
            return ResolveResult([], "profile_dependent")
        if len(impls) > 1:
            primary = [fq for fq, ann in impls if "Primary" in ann]
            if len(primary) != 1:
                return ResolveResult([], "ambiguous_implementation")
            target_class = primary[0]
        else:
            target_class = impls[0][0]
    found = _instance_methods(index, target_class, method, argc)
    if found is None:
        return ResolveResult([], "ambiguous_class")
    if len(found) > 1:
        return ResolveResult([], "overloaded")
    return ResolveResult(found)


def resolve(index, src: SourceFile, callee: str, argc: int):
    from iron_laws.engine.ast_tools import iter_functions
    from iron_laws.engine.xfile import ResolveResult

    if "." not in callee:
        return ResolveResult([])
    owner, method = callee.rsplit(".", 1)
    field = owner.removeprefix("this.")
    if re.fullmatch(r"[a-z_$][\w$]*", field):
        return _resolve_field(index, src, field, method, argc)
    if not owner.rsplit(".", 1)[-1][:1].isupper():
        return ResolveResult([])  # 그 밖의 소문자 수신자는 정할 수 없는 객체다
    classes = _owner_candidates(index, src, owner)
    if not classes:
        return ResolveResult([])
    paths = {p for c in classes for p in index.java_classes[c]}
    if len(classes) > 1 or len(paths) > 1:
        return ResolveResult([], "ambiguous_class")
    target = index.files[paths.pop()]
    simple = classes[0].rsplit(".", 1)[-1]
    bodies = [
        n.child_by_field_name("body")
        for n in target.root.named_children
        if n.type in ("class_declaration", "interface_declaration", "enum_declaration") and target.text_of(n.child_by_field_name("name")) == simple
    ]
    found = []
    for fn in iter_functions(target):
        if fn.name != method or len(fn.params) != argc or fn.node.parent not in bodies:
            continue
        modifiers = next((n for n in fn.node.named_children if n.type == "modifiers"), None)
        if modifiers is not None and "static" in target.text_of(modifiers).split():
            found.append((target, fn))
    if len(found) > 1:
        return ResolveResult([], "overloaded")
    return ResolveResult(found)
