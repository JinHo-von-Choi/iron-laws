"""
오철칙 파일 간 호출 해석: Go
- 맨 이름 호출 `run(x)`: 같은 폴더·같은 패키지의 다른 파일에 정의된 함수(메서드 제외)
- 패키지 호출 `util.Run(x)`: go.mod의 모듈 경로와 폴더 위치로 만든 import 경로가 같은 프로젝트 폴더의 내보낸 함수
  go.mod가 없는 폴더는 import 경로의 끝부분과 폴더 경로를 맞춘다. 맞는 폴더가 둘 이상이면 해석 공백
표준 라이브러리 패키지(`strings`, `net/http` 등)와 다른 모듈의 import는 같은 이름의 프로젝트 폴더가 있어도 프로젝트 함수로 보지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import re
from pathlib import PurePosixPath

from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile

# 표준 라이브러리의 최상위 패키지. 첫 경로 요소가 이 이름이면 프로젝트 폴더로 연결하지 않는다
STDLIB_ROOTS = frozenset(
    "archive bufio builtin bytes cmp compress container context crypto database debug embed encoding errors expvar flag fmt go hash html "
    "image index io iter log maps math mime net os path plugin reflect regexp runtime slices sort strconv strings sync syscall testing "
    "text time unicode unique unsafe weak".split()
)
MODULE_RE = re.compile(r"(?m)^\s*module\s+\"?([^\s\"]+)\"?")


def build(index, sources: list[SourceFile]) -> None:
    for s in sources:
        if s.lang is Lang.GO and not s.path.name.endswith("_test.go"):
            index.go_dirs.setdefault(PurePosixPath(s.path.as_posix()).parent.as_posix(), []).append(s.path.as_posix())
    if index.root is None:
        return
    modules: dict[str, str | None] = {}  # 폴더 → 그 폴더에 있는 go.mod의 모듈 경로(없으면 None)

    def module_at(folder: str) -> str | None:
        if folder not in modules:
            mod = index.root / folder / "go.mod"
            try:
                m = MODULE_RE.search(mod.read_text(encoding="utf-8", errors="replace")) if mod.is_file() else None
            except OSError:  # iron-laws: ignore[IL-301] 읽지 못한 go.mod는 없는 것으로 보고 폴더 끝부분 맞추기로 해석한다
                m = None
            modules[folder] = m.group(1) if m else None
        return modules[folder]

    for folder in index.go_dirs:
        parts = [] if folder == "." else folder.split("/")
        for depth in range(len(parts), -1, -1):
            base = "/".join(parts[:depth]) or "."
            module = module_at(base)
            if module is not None:
                index.go_import_paths[folder] = "/".join([module, *parts[depth:]])
                break


def package_of(src: SourceFile) -> str:
    def find() -> str:
        for node in src.root.named_children if src.root is not None else []:
            if node.type == "package_clause":
                ident = next((c for c in node.named_children if c.type == "package_identifier"), None)
                return src.text_of(ident) if ident is not None else ""
        return ""

    return src.memo("go_package", find)


def imports(src: SourceFile) -> dict[str, str]:
    """지역 이름 → import 경로"""

    def find() -> dict[str, str]:
        table: dict[str, str] = {}
        for node in src.nodes:
            if node.type != "import_spec":
                continue
            path_node = node.child_by_field_name("path")
            if path_node is None:
                continue
            path = src.text_of(path_node).strip('"`')
            alias = node.child_by_field_name("name")
            name = src.text_of(alias) if alias is not None else path.rsplit("/", 1)[-1]
            if name not in ("_", "."):
                table[name] = path
        return table

    return src.memo("go_imports", find)


def _functions(index, files: list[str], name: str, exported_only: bool):
    from iron_laws.engine.ast_tools import iter_functions

    found = []
    for rel in files:
        target = index.files[rel]
        for fn in iter_functions(target):
            if fn.name == name and fn.node.type == "function_declaration" and (not exported_only or name[:1].isupper()):
                found.append((target, fn))
    return found


def resolve(index, src: SourceFile, callee: str, argc: int):
    from iron_laws.engine.xfile import ResolveResult

    here = PurePosixPath(src.path.as_posix()).parent.as_posix()
    if "." not in callee:
        same = [p for p in index.go_dirs.get(here, []) if p != src.path.as_posix() and package_of(index.files[p]) == package_of(src)]
        return ResolveResult(_functions(index, same, callee, exported_only=False))
    alias, name = callee.split(".", 1)
    if "." in name:
        return ResolveResult([])
    path = imports(src).get(alias)
    if path is None:
        return ResolveResult([])  # 수신 변수의 메서드 호출은 형식을 모르므로 해석하지 않는다
    exact = [folder for folder, import_path in index.go_import_paths.items() if import_path == path]
    if exact:
        return ResolveResult(_functions(index, index.go_dirs[exact[0]], name, exported_only=True)) if len(exact) == 1 else ResolveResult([], "ambiguous_package")
    if path.split("/", 1)[0] in STDLIB_ROOTS:
        return ResolveResult([])  # 표준 라이브러리
    parts = path.split("/")
    best_len, best = 0, []
    for folder in index.go_dirs:
        if folder in index.go_import_paths:
            continue  # go.mod로 import 경로가 정해진 폴더는 그 경로로만 맞춘다(다른 모듈의 같은 이름 폴더와 섞지 않는다)
        segments = [] if folder == "." else folder.split("/")
        if not segments or len(segments) > len(parts) or parts[-len(segments):] != segments:
            continue
        if len(segments) > best_len:
            best_len, best = len(segments), [folder]
        elif len(segments) == best_len:
            best.append(folder)
    if not best:
        return ResolveResult([])
    if len(best) > 1:
        return ResolveResult([], "ambiguous_package")
    return ResolveResult(_functions(index, index.go_dirs[best[0]], name, exported_only=True))
