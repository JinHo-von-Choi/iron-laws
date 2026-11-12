"""Python 호출의 종류 판정: 정규식 객체의 메서드 호출, typer 명령 함수. import로 가져온 이름은 프로젝트 색인으로 따라간다."""

import ast

from iron_laws.engine import xfile
from iron_laws.engine.ast_tools import Call
from iron_laws.engine.python_bindings import binding_index
from iron_laws.engine.source import SourceFile


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
