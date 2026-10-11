"""공유 Python AST와 명시적인 구문 실패 결과. 미해석 입력을 성공으로 바꾸지 않는다."""

import ast
from dataclasses import dataclass

from iron_laws.engine.source import SourceFile


@dataclass(frozen=True)
class PythonSyntaxIssue:
    line: int | None
    offset: int | None


@dataclass(frozen=True)
class PythonParseResult:
    tree: ast.Module | None
    issue: PythonSyntaxIssue | None = None


def parse_python(src: SourceFile) -> PythonParseResult:
    def build() -> PythonParseResult:
        try:
            return PythonParseResult(ast.parse(src.text))
        except SyntaxError as error:
            return PythonParseResult(None, PythonSyntaxIssue(error.lineno, error.offset))
    return src.memo('python_ast', build)
