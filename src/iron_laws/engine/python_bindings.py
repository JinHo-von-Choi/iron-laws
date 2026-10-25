"""Python 호출 수신자의 import·대입 근거. 해석하지 못한 바인딩은 면제하지 않는다."""

import ast
import re
from dataclasses import dataclass, field

from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import Call
from iron_laws.engine.languages import Lang
from iron_laws.engine.python_ast import parse_python
from iron_laws.engine.source import SourceFile

# 위험 호출 정의가 모듈 경로로 찾는 표준 라이브러리 모듈. 이 모듈의 별칭(import os as o)과 이름 가져오기(from os import system)는
# 호출 이름을 모듈 경로(os.system)로 바꿔 같은 정의로 찾는다. 다른 모듈은 규칙이 짧은 이름으로 찾으므로 바꾸지 않는다.
SINK_MODULES = frozenset({"os", "os.path", "subprocess", "commands", "pty", "shutil", "pickle", "marshal", "shelve", "yaml", "sqlite3"})
_MODULE_NAMES = r"(?:os|os\.path|subprocess|commands|pty|shutil|pickle|marshal|shelve|yaml|sqlite3)"
SINK_IMPORT_RE = re.compile(rf"^[ \t]*(?:from[ \t]+{_MODULE_NAMES}[ \t]+import|import[ \t][^\n]*\b{_MODULE_NAMES}\b)|__import__|import_module", re.M)
GETATTR_CALLEE = re.compile(r"^getattr\(([A-Za-z_][\w.]*),[\"']([A-Za-z_]\w*)[\"']\)(.*)$")
DYNAMIC_IMPORT_CALLEE = re.compile(r"^(?:__import__|importlib\.import_module)\([\"']([\w.]+)[\"']\)\.(.+)$")


@dataclass
class Scope:
    start: int
    end: int
    parent: 'Scope | None' = None
    events: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)
    is_class: bool = False
    origins: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)

    def bind(self, name: str, line: int, kind: str | None, origin: str | None = None) -> None:
        self.events.setdefault(name, []).append((line, kind))
        self.origins.setdefault(name, []).append((line, origin))

    def resolve_origin(self, name: str, line: int) -> str | None:
        """이 이름이 가리키는 위험 모듈 경로. 마지막 바인딩이 그 모듈의 import가 아니면(다시 대입·매개변수) None"""
        if name in self.origins:
            before = [origin for at, origin in self.origins[name] if at <= line]
            return before[-1] if before else None
        return self.parent.resolve_origin(name, line) if self.parent else None

    def resolve(self, name: str, line: int) -> str | None:
        if name in self.events:
            before = [kind for at, kind in self.events[name] if at <= line]
            return before[-1] if before else None
        return self.parent.resolve(name, line) if self.parent else None


class BindingIndex(ast.NodeVisitor):
    def __init__(self, tree: ast.Module):
        self.scope = Scope(1, 10**9)
        self.scopes = [self.scope]
        self.functions = {}
        self.conditional = 0
        self.visit(tree)

    def visit_FunctionDef(self, node):
        self.scope.bind(node.name, node.lineno, None)
        self.functions[node.lineno] = node
        outer = self.scope
        parent = outer.parent if outer.is_class else outer
        self.scope = Scope(node.lineno, node.end_lineno, parent)
        self.scopes.append(self.scope)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.scope.bind(arg.arg, node.lineno, None)
        for arg in (node.args.vararg, node.args.kwarg):
            if arg:
                self.scope.bind(arg.arg, node.lineno, None)
        saved = self.conditional
        self.conditional = 0
        for statement in node.body:
            self.visit(statement)
        self.conditional = saved
        self.scope = outer

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.scope.bind(node.name, node.lineno, None)
        parent = self.scope
        self.scope = Scope(node.lineno, node.end_lineno, parent, is_class=True)
        self.scopes.append(self.scope)
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    def visit_Lambda(self, node):
        parent = self.scope
        self.scope = Scope(node.lineno, node.end_lineno, parent)
        self.scopes.append(self.scope)
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.scope.bind(arg.arg, node.lineno, None)
        self.visit(node.body)
        self.scope = parent

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scope.bind(node.id, node.lineno, None)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.scope.bind(node.name, node.lineno, None)
        self.generic_visit(node)

    def visit_Global(self, node):
        for name in node.names:
            self.scopes[0].bind(name, node.lineno, None)
            self.scope.bind(name, node.lineno, None)

    visit_Nonlocal = visit_Global

    def visit_Import(self, node):
        for alias in node.names:
            kind = alias.name if alias.name in ('re', 'typer', 'subprocess') and not self.conditional else None
            name = alias.asname or alias.name.split('.')[0]
            origin = (alias.name if alias.asname else name) if alias.name in SINK_MODULES or name in SINK_MODULES else None
            self.scope.bind(name, node.lineno, kind, origin)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            kind = None
            if not self.conditional and not node.level:
                kind = f'{node.module}.{alias.name}' if node.module in ('re', 'typer', 'subprocess') else f'imported:{node.module}:{alias.name}'
            origin = f'{node.module}.{alias.name}' if not node.level and node.module in SINK_MODULES else None
            self.scope.bind(alias.asname or alias.name, node.lineno, kind, origin)

    def kind(self, node, line):
        if isinstance(node, ast.Name):
            return self.scope.resolve(node.id, line)
        if isinstance(node, ast.Attribute):
            receiver = self.kind(node.value, line)
            return f'{receiver}.{node.attr}' if receiver else None
        if isinstance(node, ast.Call):
            callee = self.kind(node.func, line)
            return {'re.compile': 'regex', 'typer.Typer': 'typer_app'}.get(callee)
        return None

    def origin(self, node, line):
        """식이 가리키는 위험 모듈 경로(os.system 등). 모르면 None"""
        if isinstance(node, ast.Name):
            return self.scope.resolve_origin(node.id, line)
        if isinstance(node, ast.Attribute):
            base = self.origin(node.value, line)
            return f'{base}.{node.attr}' if base else None
        return None

    def visit_Assign(self, node):
        kind = self.kind(node.value, node.lineno) if not self.conditional else None
        origin = self.origin(node.value, node.lineno)
        for target in node.targets:
            self._target(target, node.lineno, kind, origin)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        kind = self.kind(node.value, node.lineno) if not self.conditional else None
        self._target(node.target, node.lineno, kind)

    def visit_AugAssign(self, node):
        self._target(node.target, node.lineno, None)

    def _target(self, node, line, kind, origin=None):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                self.scope.bind(child.id, line, kind if child is node else None, origin if child is node else None)

    def visit_If(self, node):
        self.conditional += 1
        self.generic_visit(node)
        self.conditional -= 1

    visit_For = visit_If
    visit_AsyncFor = visit_If
    visit_While = visit_If
    visit_Try = visit_If
    visit_With = visit_If

    def at(self, line: int) -> Scope:
        return min((s for s in self.scopes if s.start <= line <= s.end), key=lambda s: s.end - s.start)


def binding_index(src: SourceFile) -> BindingIndex | None:
    def build():
        if src.lang is not Lang.PYTHON:
            return None
        result = parse_python(src)
        return BindingIndex(result.tree) if result.tree is not None else None
    return src.memo('python_bindings', build)


def canonical_callee(src: SourceFile, callee: str, line: int) -> str:
    """위험 모듈의 별칭·가져온 이름·변수에 담은 함수·getattr·__import__로 부른 호출을 모듈 경로로 바꾼다
    (o.system, system, run = os.system 뒤의 run, getattr(os, "system"), __import__("os").system → os.system).
    그 줄에서 이름이 다른 값으로 다시 묶였으면 바꾸지 않는다. getattr의 속성 이름이 상수가 아니면 바꾸지 않는다."""
    if not SINK_IMPORT_RE.search(src.text):
        return callee
    dynamic = DYNAMIC_IMPORT_CALLEE.match(callee)
    if dynamic and dynamic.group(1) in SINK_MODULES:
        return f'{dynamic.group(1)}.{dynamic.group(2)}'
    named = GETATTR_CALLEE.match(callee)
    if named:
        callee = f'{named.group(1)}.{named.group(2)}{named.group(3)}'
    index = binding_index(src)
    if index is None:
        return callee
    head, dot, rest = callee.partition('.')
    origin = index.at(line).resolve_origin(head, line)
    return f'{origin}{dot}{rest}' if origin else callee


def is_regex_call(src: SourceFile, call: Call) -> bool:
    index = binding_index(src)
    if index is None or '.' not in call.callee:
        return False
    receiver, method = call.callee.rsplit('.', 1)
    if '.' in receiver:
        return False
    scope = index.at(call.line)
    kind = scope.resolve(receiver, call.line)
    # 전역 재대입이 있으면 함수가 실행되는 시점을 알 수 없으므로 면제하지 않는다.
    owner = scope
    while receiver not in owner.events and owner.parent:
        owner = owner.parent
    # 열 위치가 없는 이 인덱스로는 같은 줄의 대입과 호출 순서를 증명할 수 없다.
    if any(at == call.line for at, _ in owner.events.get(receiver, [])):
        return False
    if owner.parent is None and scope is not owner and len(owner.events.get(receiver, [])) != 1:
        return False
    return kind == 're' and method in ('search', 'match', 'fullmatch', 'finditer', 'findall') or kind == 'regex'


def _imported_kind(src: SourceFile, kind: str | None, depth: int = 0) -> str | None:
    if kind is None or not kind.startswith('imported:'):
        return kind
    if depth >= 3:
        return None
    index = xfile.get_index()
    if index is None:
        return None

    def resolve():
        _, module, name = kind.split(':', 2)
        path = index.lookup_module(module, src.path.as_posix())
        if path is None:
            return None
        target = index.files[path]
        bindings = binding_index(target)
        if bindings is None or len(bindings.scopes[0].events.get(name, [])) != 1:
            return None
        value = bindings.scopes[0].resolve(name, 10**9)
        return _imported_kind(target, value, depth + 1)

    return src.memo('imported_binding:' + kind, resolve)


def is_typer_command(src: SourceFile, function_line: int) -> bool:
    index = binding_index(src)
    if index is None:
        return False
    function = index.functions.get(function_line)
    for fn in [function] if function is not None else []:
        parent = index.at(fn.lineno).parent
        if parent is None:
            continue
        for decorator in fn.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == 'command':
                receiver = decorator.func.value
                if isinstance(receiver, ast.Name) and _imported_kind(src, parent.resolve(receiver.id, fn.lineno)) == 'typer_app':
                    return True
    return False
