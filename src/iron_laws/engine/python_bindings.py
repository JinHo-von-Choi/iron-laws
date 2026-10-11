"""Python 호출 수신자의 import·대입 근거. 해석하지 못한 바인딩은 면제하지 않는다."""

import ast
from dataclasses import dataclass, field

from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import Call
from iron_laws.engine.languages import Lang
from iron_laws.engine.python_ast import parse_python
from iron_laws.engine.source import SourceFile


@dataclass
class Scope:
    start: int
    end: int
    parent: 'Scope | None' = None
    events: dict[str, list[tuple[int, str | None]]] = field(default_factory=dict)
    is_class: bool = False

    def bind(self, name: str, line: int, kind: str | None) -> None:
        self.events.setdefault(name, []).append((line, kind))

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
            self.scope.bind(alias.asname or alias.name.split('.')[0], node.lineno, kind)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            kind = None
            if not self.conditional and not node.level:
                kind = f'{node.module}.{alias.name}' if node.module in ('re', 'typer', 'subprocess') else f'imported:{node.module}:{alias.name}'
            self.scope.bind(alias.asname or alias.name, node.lineno, kind)

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

    def visit_Assign(self, node):
        kind = self.kind(node.value, node.lineno) if not self.conditional else None
        for target in node.targets:
            self._target(target, node.lineno, kind)
        self.visit(node.value)

    def visit_AnnAssign(self, node):
        kind = self.kind(node.value, node.lineno) if not self.conditional else None
        self._target(node.target, node.lineno, kind)

    def visit_AugAssign(self, node):
        self._target(node.target, node.lineno, None)

    def _target(self, node, line, kind):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                self.scope.bind(child.id, line, kind if child is node else None)

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
        if index.budget <= 0:
            index.limit_hits += 1
            return None
        index.budget -= 1
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
