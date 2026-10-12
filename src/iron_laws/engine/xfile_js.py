"""
오철칙 파일 간 호출 해석: JavaScript·TypeScript
파일마다 import 표(지역 이름 → (모듈 지정자, 가져온 이름))와 export 표(내보낸 이름 → 정의)를 심볼 단위로 만들고 호출을 따라간다.

해석 범위: ESM(named, default, namespace, 재내보내기 1단계), CommonJS(`module.exports = {..}`, `module.exports = f`, `exports.a =`,
`const {a} = require(..)`, `require(..).a`), 상대 경로, 확장자 후보와 `/index.*`, tsconfig `paths`의 단일 와일드카드 별칭.
후보 파일이 둘 이상이면 첫 파일을 고르지 않고 해석 공백으로 남긴다. 동적 `import()`, 계산된 `require`, 찾을 수 없는 상대 경로도 공백이다.
패키지 import는 프로젝트 함수가 아니므로 공백으로 세지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import re
from pathlib import PurePosixPath
from posixpath import normpath

from iron_laws.engine.languages import JS_FAMILY
from iron_laws.engine.source import SourceFile

CODE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
ASSET_RE = re.compile(r"\.(css|scss|sass|less|json|svg|png|jpe?g|gif|webp|ico|html|md|txt|wasm|graphql|gql)$", re.IGNORECASE)
FUNCTION_VALUES = {"arrow_function", "function_expression", "function", "generator_function"}
MAX_REEXPORT_DEPTH = 1

# import 표의 값: (모듈 지정자, 가져온 이름). 가져온 이름 "*"는 모듈 객체(namespace·require 결과)다.
# 지정자가 None이면 해석할 수 없는 바인딩이고 가져온 이름 자리에 사유가 들어 있다.
Binding = tuple[str | None, str]


def build(index, sources: list[SourceFile]) -> None:
    for s in sources:
        if not re.match(r"tsconfig(\..+)?\.json$", s.path.name):
            continue
        try:
            data = _loose_json(s.text)
        except ValueError:
            index.config_errors.append(s.path.as_posix())  # 별칭 없이 해석하고 진단으로 알린다
            continue
        options = data.get("compilerOptions", {}) if isinstance(data, dict) else {}
        paths = options.get("paths") if isinstance(options, dict) else None
        if not isinstance(paths, dict):
            continue
        base = normpath(str(PurePosixPath(s.path.parent.as_posix()) / str(options.get("baseUrl", "."))))
        for pattern, targets in paths.items():
            if isinstance(pattern, str) and pattern.count("*") <= 1 and isinstance(targets, list):
                index.js_aliases.append((base, pattern, [t for t in targets if isinstance(t, str) and t.count("*") <= 1]))


def _loose_json(text: str):
    text = re.sub(r"(?m)^\s*//[^\n]*|/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def _string(src: SourceFile, node) -> str | None:
    if node is None or node.type != "string":
        return None
    return src.text_of(node)[1:-1]


def _require_spec(src: SourceFile, node) -> tuple[bool, str | None]:
    """(require 호출인지, 문자열 지정자). 계산된 require는 (True, None)"""
    if node is None or node.type != "call_expression":
        return False, None
    fn = node.child_by_field_name("function")
    if fn is None or src.text_of(fn) != "require":
        return False, None
    args = node.child_by_field_name("arguments")
    first = args.named_children[0] if args is not None and args.named_children else None
    return True, _string(src, first)


def _is_dynamic_import(src: SourceFile, node) -> bool:
    while node is not None and node.type in ("await_expression", "parenthesized_expression"):
        node = node.named_children[0] if node.named_children else None
    if node is None or node.type != "call_expression":
        return False
    fn = node.child_by_field_name("function")
    return fn is not None and fn.type == "import"


def imports(src: SourceFile) -> dict[str, Binding]:
    def build_table() -> dict[str, Binding]:
        table: dict[str, Binding] = {}
        for node in src.root.named_children if src.root is not None else []:
            if node.type == "import_statement":
                _import_statement(src, node, table)
            elif node.type in ("lexical_declaration", "variable_declaration"):
                for decl in node.named_children:
                    if decl.type == "variable_declarator":
                        _declarator(src, decl, table)
        return table

    return src.memo("js_imports", build_table)


def _import_statement(src: SourceFile, node, table: dict[str, Binding]) -> None:
    spec = _string(src, node.child_by_field_name("source"))
    clauses = [c for c in node.named_children if c.type == "import_clause"] if spec is not None else []
    for part in (p for clause in clauses for p in clause.named_children):
        if part.type == "identifier":
            table[src.text_of(part)] = (spec, "default")
        elif part.type == "namespace_import":
            ident = next((c for c in part.named_children if c.type == "identifier"), None)
            if ident is not None:
                table[src.text_of(ident)] = (spec, "*")
        elif part.type == "named_imports":
            for item in part.named_children:
                name = item.child_by_field_name("name") if item.type == "import_specifier" else None
                if name is not None:
                    alias = item.child_by_field_name("alias") or name
                    table[src.text_of(alias)] = (spec, src.text_of(name))


def _declarator(src: SourceFile, decl, table: dict[str, Binding]) -> None:
    target, value = decl.child_by_field_name("name"), decl.child_by_field_name("value")
    if target is None or value is None:
        return
    names: list[tuple[str, str]] = []  # (지역 이름, 가져온 이름)
    if target.type == "identifier":
        names.append((src.text_of(target), "*"))
    elif target.type == "object_pattern":
        for part in target.named_children:
            if part.type == "shorthand_property_identifier_pattern":
                names.append((src.text_of(part), src.text_of(part)))
            elif part.type == "pair_pattern":
                key, val = part.child_by_field_name("key"), part.child_by_field_name("value")
                if key is not None and val is not None and val.type == "identifier":
                    names.append((src.text_of(val), src.text_of(key)))
    if not names:
        return
    if _is_dynamic_import(src, value):
        for local, _ in names:
            table[local] = (None, "dynamic_import")
        return
    member = None
    if value.type == "member_expression":
        member = value.child_by_field_name("property")
        value = value.child_by_field_name("object")
    is_require, spec = _require_spec(src, value)
    if not is_require:
        return
    for local, imported in names:
        if spec is None:
            table[local] = (None, "computed_require")
        elif member is not None:
            if imported == "*":
                table[local] = (spec, src.text_of(member))  # const s = require('./v').t
        else:
            table[local] = (spec, imported)


# export 표의 값: ("def", 함수 노드 시작 위치) | ("local", 지역 이름) | ("re", 지정자, 이름)
Export = tuple


def exports(src: SourceFile) -> tuple[dict[str, Export], list[str]]:
    """(내보낸 이름 → 정의, `export * from` 지정자 목록). 객체로 내보낸 멤버는 `default.이름`으로도 둔다."""

    def build_table() -> tuple[dict[str, Export], list[str]]:
        table: dict[str, Export] = {}
        stars: list[str] = []
        for node in src.root.named_children if src.root is not None else []:
            if node.type == "export_statement":
                _export_statement(src, node, table, stars)
            elif node.type == "expression_statement" and node.named_children:
                expr = node.named_children[0]
                if expr.type == "assignment_expression":
                    _cjs_assignment(src, expr, table)
        return table, stars

    return src.memo("js_exports", build_table)


def _value_export(src: SourceFile, value) -> Export | None:
    if value is None:
        return None
    if value.type in FUNCTION_VALUES:
        return ("def", value.start_byte)
    if value.type == "identifier":
        return ("local", src.text_of(value))
    return None


def _object_members(src: SourceFile, obj, prefix: str, table: dict[str, Export]) -> None:
    for part in obj.named_children:
        if part.type == "shorthand_property_identifier":
            name = src.text_of(part)
            table[f"{prefix}{name}"] = ("local", name)
        elif part.type == "pair":
            key = part.child_by_field_name("key")
            found = _value_export(src, part.child_by_field_name("value"))
            if key is not None and found is not None:
                table[f"{prefix}{src.text_of(key).strip(chr(39) + chr(34))}"] = found
        elif part.type == "method_definition":
            name = part.child_by_field_name("name")
            if name is not None:
                table[f"{prefix}{src.text_of(name)}"] = ("def", part.start_byte)


def _export_statement(src: SourceFile, node, table: dict[str, Export], stars: list[str]) -> None:
    spec = _string(src, node.child_by_field_name("source"))
    declaration = node.child_by_field_name("declaration")
    value = node.child_by_field_name("value")
    is_default = any(c.type == "default" for c in node.children)
    if declaration is not None:
        if declaration.type in ("function_declaration", "generator_function_declaration"):
            name = declaration.child_by_field_name("name")
            table["default" if is_default or name is None else src.text_of(name)] = ("def", declaration.start_byte)
        elif declaration.type in ("lexical_declaration", "variable_declaration"):
            for decl in declaration.named_children:
                name = decl.child_by_field_name("name") if decl.type == "variable_declarator" else None
                found = _value_export(src, decl.child_by_field_name("value")) if name is not None else None
                if name is not None and found is not None and found[0] == "def":
                    table[src.text_of(name)] = found
        return
    if is_default:
        target = value or next((c for c in node.named_children if c.type not in ("comment",)), None)
        if target is not None and target.type == "object":
            _object_members(src, target, "default.", table)
        found = _value_export(src, target)
        if found is not None:
            table["default"] = found
        return
    clause = next((c for c in node.named_children if c.type == "export_clause"), None)
    if clause is None:
        if spec is not None and any(c.type == "*" for c in node.children):
            namespace = next((c for c in node.named_children if c.type == "namespace_export"), None)
            if namespace is None:
                stars.append(spec)
        return
    for item in clause.named_children:
        if item.type != "export_specifier":
            continue
        name = item.child_by_field_name("name")
        alias = item.child_by_field_name("alias") or name
        if name is None:
            continue
        exported = src.text_of(alias)
        table[exported] = ("re", spec, src.text_of(name)) if spec is not None else ("local", src.text_of(name))


def _cjs_assignment(src: SourceFile, expr, table: dict[str, Export]) -> None:
    left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
    if left is None or right is None:
        return
    target = src.text_of(left).replace(" ", "")
    if target == "module.exports":
        if right.type == "object":
            _object_members(src, right, "", table)
            _object_members(src, right, "default.", table)
        found = _value_export(src, right)
        if found is not None:
            table["default"] = found
        return
    m = re.fullmatch(r"(?:module\.)?exports\.([A-Za-z_$][\w$]*)", target)
    if m:
        found = _value_export(src, right)
        if found is not None:
            table[m.group(1)] = found
            table[f"default.{m.group(1)}"] = found


def _local_function(src: SourceFile, name: str):
    """파일 최상위의 함수 정의(function 선언, 함수를 대입한 const·let·var)"""
    from iron_laws.engine.ast_tools import iter_functions

    starts: set[int] = set()
    for node in src.root.named_children if src.root is not None else []:
        decl = node.child_by_field_name("declaration") if node.type == "export_statement" else node
        if decl is None:
            continue
        if decl.type in ("function_declaration", "generator_function_declaration"):
            ident = decl.child_by_field_name("name")
            if ident is not None and src.text_of(ident) == name:
                starts.add(decl.start_byte)
        elif decl.type in ("lexical_declaration", "variable_declaration"):
            for d in decl.named_children:
                ident = d.child_by_field_name("name") if d.type == "variable_declarator" else None
                value = d.child_by_field_name("value") if ident is not None else None
                if ident is not None and src.text_of(ident) == name and value is not None and value.type in FUNCTION_VALUES:
                    starts.add(value.start_byte)
    return [fn for fn in iter_functions(src) if fn.node.start_byte in starts]


def _functions_at(src: SourceFile, start: int):
    from iron_laws.engine.ast_tools import iter_functions

    return [fn for fn in iter_functions(src) if fn.node.start_byte == start]


def _candidates(index, base: str) -> list[str]:
    found: list[str] = []
    if base in index.files and index.files[base].lang in JS_FAMILY:
        found.append(base)
    stem = base
    if base.endswith((".js", ".jsx", ".mjs", ".cjs")):
        stem = base.rsplit(".", 1)[0]  # TS의 ESM 관례: './a.js'가 a.ts를 가리킨다
        found += [stem + ext for ext in (".ts", ".tsx", ".mts", ".cts") if stem + ext in index.files]
    else:
        found += [base + ext for ext in CODE_EXTS if base + ext in index.files]
        found += [f"{base}/index{ext}" for ext in CODE_EXTS if f"{base}/index{ext}" in index.files]
    return sorted(set(found))


def resolve_module(index, from_path: str, spec: str) -> tuple[str | None, str | None]:
    """(파일, 공백 사유). 패키지 지정자는 (None, None)"""
    bases: list[str] = []
    if spec.startswith("."):
        bases.append(normpath(str(PurePosixPath(from_path).parent / spec)))
    else:
        for base_dir, pattern, targets in index.js_aliases:
            if "*" in pattern:
                head, tail = pattern.split("*")
                if not (spec.startswith(head) and spec.endswith(tail) and len(spec) >= len(head) + len(tail)):
                    continue
                middle = spec[len(head) : len(spec) - len(tail)]
                bases += [normpath(str(PurePosixPath(base_dir) / t.replace("*", middle))) for t in targets]
            elif spec == pattern:
                bases += [normpath(str(PurePosixPath(base_dir) / t)) for t in targets]
        if not bases:
            return None, None
    if ASSET_RE.search(spec):
        return None, None
    found = sorted({c for b in bases for c in _candidates(index, b)})
    if len(found) == 1:
        return found[0], None
    return None, ("ambiguous_module" if found else "module_not_found")


def _export_targets(index, rel: str, name: str, depth: int, seen: set[tuple[str, str]]):
    """(함수 목록, 공백 사유)"""
    if (rel, name) in seen:
        return [], None
    seen.add((rel, name))
    src = index.files[rel]
    table, stars = exports(src)
    entry = table.get(name)
    if entry is not None:
        kind = entry[0]
        if kind == "def":
            return [(src, fn) for fn in _functions_at(src, entry[1])], None
        if kind == "local":
            return [(src, fn) for fn in _local_function(src, entry[1])], None
        if depth >= MAX_REEXPORT_DEPTH:
            return [], "reexport_depth"
        target, gap = resolve_module(index, rel, entry[1])
        if target is None:
            return [], gap
        return _export_targets(index, target, entry[2], depth + 1, seen)
    if not stars or "." in name:
        return [], None
    if depth >= MAX_REEXPORT_DEPTH:
        return [], "reexport_depth"
    hits = []
    for spec in stars:
        target, gap = resolve_module(index, rel, spec)
        if target is None:
            if gap:
                return [], gap
            continue
        found, gap = _export_targets(index, target, name, depth + 1, seen)
        if gap:
            return [], gap
        if found:
            hits.append(found)
    if len(hits) > 1:
        return [], "ambiguous_export"
    return (hits[0] if hits else []), None


def resolve(index, src: SourceFile, callee: str, argc: int):
    from iron_laws.engine.xfile import ResolveResult

    parts = callee.split(".")
    binding = imports(src).get(parts[0])
    if binding is None or len(parts) > 2:
        return ResolveResult([])
    spec, imported = binding
    if spec is None:
        return ResolveResult([], imported)
    rel, gap = resolve_module(index, src.path.as_posix(), spec)
    if rel is None:
        return ResolveResult([], gap)
    if len(parts) == 1:
        name = "default" if imported == "*" else imported
    elif imported == "*":
        name = parts[1]
    else:
        name = f"{imported}.{parts[1]}" if imported == "default" else ""
        if not name:
            return ResolveResult([])
    found, gap = _export_targets(index, rel, name, 0, set())
    return ResolveResult(found, None if found else gap)
