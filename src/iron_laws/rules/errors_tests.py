"""
오철칙 시험 코드 규칙: 꺼 둔 시험(IL-302)과 검증 문이 없는 시험(IL-306)
작성자: 최진호
작성일: 2026-11-12
"""

import ast
import re

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    iter_calls,
    iter_functions,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.python_ast import parse_python
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule


class DisabledTestRule(BaseRule):
    rule_id = "IL-302"
    name = "단위/통합 테스트 회피 및 통과 위장 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.HIGH
    gov_standard = None
    include_tests = True
    plain = "실패하는 테스트를 지우거나 건너뛰게 만들면 '통과'로 보이지만 결함은 그대로 배포됩니다."
    how_to_fix = "건너뛰기 표시를 지우고 실패 원인을 고치세요. 외부 환경 의존이면 조건부 건너뛰기(skipif)와 사유를 명시하세요."
    unconditional: list[tuple[re.Pattern[str], str, frozenset[Lang]]] = [
        (re.compile(r"@Disabled\b|@Ignore\b"), "JUnit @Disabled/@Ignore로 테스트를 꺼 둡니다.", frozenset({Lang.JAVA})),
        (re.compile(r"@pytest\.mark\.skip\b(?!if)|@unittest\.skip\("), "pytest/unittest의 무조건 skip으로 테스트를 회피합니다.", frozenset({Lang.PYTHON})),
        (
            re.compile(r"\b(it|test|describe)\.(skip|todo|fixme)\b|\b(xit|xdescribe|xtest)\("),
            "Jest/Mocha/Playwright의 skip/todo로 테스트를 회피합니다.",
            frozenset(JS_FAMILY),
        ),
        (re.compile(r"\[(Ignore|Skip)(\(|\])|\[(Fact|Theory)\([^)]*Skip\s*="), "C# 테스트에 Ignore/Skip이 지정되어 있습니다.", frozenset({Lang.CSHARP})),
        (re.compile(r"#\[ignore\b"), "Rust 테스트에 #[ignore]가 지정되어 있습니다.", frozenset({Lang.RUST})),
    ]
    reason_re = re.compile(r"Skip\s*=\s*[\"'][^\"']{3,}[\"']|@Disabled\(\s*[\"'][^\"']{3,}|\[Ignore\(\s*[\"'][^\"']{3,}|reason\s*=\s*[\"'][^\"']{3,}")
    conditional = re.compile(r"\bt\.Skip(f|Now)?\(|\bself\.skipTest\(|\bpytest\.skip\(|\bmarkTest(Skipped|Incomplete)\(")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        lines = src.code_lines
        for idx, line in enumerate(lines, start=1):
            matched = False
            for pattern, message, langs in self.unconditional:
                if src.lang in langs and pattern.search(line):
                    if self.reason_re.search(line):
                        found.append(
                            self.at_line(
                                src,
                                idx,
                                message + " (사유는 적혀 있으나 테스트는 실행되지 않습니다)",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.REVIEW,
                            )
                        )
                    else:
                        found.append(self.at_line(src, idx, message))
                    matched = True
                    break
            if matched:
                continue
            if self.conditional.search(line):
                previous = " ".join(lines[max(0, idx - 3) : idx - 1])
                if re.search(r"\b(if|else|elif|unless|when)\b|\?\s*$", previous) or re.search(r"\bif\b", line):
                    continue
                found.append(self.at_line(src, idx, "조건 없이 테스트를 건너뜁니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found


ASSERT_RE = re.compile(
    r"\bcy\.(get|contains|findBy\w+)\(|\b(getBy|findBy|queryBy|getAllBy|findAllBy)\w+\(|toBeVisible|toHaveText|toHaveURL|toPass\b|\bassert|\bexpect\(|\bshould\b|\.should\.|\bverify\(|\bfail\(|\bAssert\.|\bt\.(Error|Errorf|Fatal|Fatalf|Fail|FailNow|Run)\b|"
    r"\bpytest\.(raises|fail|warns)|\bassertThat|\bandExpect|\bpanic!|\.unwrap\(\)|\.expect\(|\bAssert_|\bt\.(is|equal|ok|deepEqual|throws|pass|same|notOk|true|false)\b|"
    r"toHaveBeenCalled|\.toBe|\.toEqual|\bmock\.\w*assert|\bassert_\w+|\bself\.assert|\bwith\s+pytest|\bshould_panic|\.Should\b|\bStatusCode\b"
)


class TestWithoutAssertionRule(BaseRule):
    version = 2
    rule_id = "IL-306"
    name = "검증문(assert) 없는 테스트 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    gov_standard = None
    include_tests = True
    plain = "assert(검증)가 없는 테스트는 코드를 실행만 해 보고 항상 통과합니다. AI가 테스트 개수만 채울 때 자주 생깁니다."
    how_to_fix = "테스트마다 기대 결과를 assert/expect로 검증하세요. 예외가 나야 하는 경우도 pytest.raises/assertThrows로 확인하세요."

    def check(self, src: SourceFile) -> list[Violation]:
        if not src.is_test or src.root is None:
            return []
        found = []
        if src.lang is Lang.PYTHON:
            for fn in iter_functions(src):
                if fn.name.startswith("test") and fn.body is not None and not self._python_asserts(src, fn.start_line):
                    found.append(self.at_node(src, fn.node, f"테스트 {fn.name}에 검증문이 없습니다.", confidence=Confidence.REVIEW))
        elif src.lang in JS_FAMILY:
            for call in iter_calls(src):
                if call.callee in ("it", "test") and len(call.args) >= 2:
                    cb = call.args[-1]
                    if cb.type in ("arrow_function", "function_expression", "function") and not ASSERT_RE.search(src.text_of(cb)):
                        found.append(self.at_node(src, call.node, "테스트 콜백에 expect/assert가 없습니다.", confidence=Confidence.REVIEW))
        elif src.lang in (Lang.JAVA, Lang.CSHARP):
            for fn in iter_functions(src):
                head = src.data[fn.node.start_byte : (fn.body.start_byte if fn.body is not None else fn.node.end_byte)].decode("utf-8", "replace")
                if re.search(r"@Test\b|\[(Fact|Test|TestMethod|Theory)\b", head) and fn.body is not None:
                    if not ASSERT_RE.search(src.text_of(fn.body)) and not re.search(r"expected\s*=|Throws", head):
                        found.append(self.at_node(src, fn.node, f"테스트 {fn.name}에 검증문이 없습니다.", confidence=Confidence.REVIEW))
        elif src.lang is Lang.GO:
            for fn in iter_functions(src):
                if re.match(r"Test[A-Z_0-9]", fn.name) and fn.body is not None and not ASSERT_RE.search(src.text_of(fn.body)) and "assert." not in src.text_of(fn.body) and "require." not in src.text_of(fn.body):
                    found.append(self.at_node(src, fn.node, f"테스트 {fn.name}에 검증이 없습니다.", confidence=Confidence.REVIEW))
        return found
    @staticmethod
    def _python_asserts(src: SourceFile, line: int) -> bool:
        def compute():
            tree = parse_python(src).tree
            if tree is None:
                return {}
            functions = {}
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.setdefault(node.name, []).append(node)
            def asserts(fn, seen, depth):
                if fn.name in seen or depth > 4:
                    return False
                rebound = {arg.arg for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)}
                statements = list(_python_function_statements(fn))
                rebound.update(n.id for n in statements if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)))
                for node in statements:
                    if isinstance(node, ast.Assert):
                        return True
                    if not isinstance(node, ast.Call):
                        continue
                    if isinstance(node.func, ast.Name) and node.func.id in functions:
                        helpers = functions[node.func.id]
                        if node.func.id not in rebound and len(helpers) == 1 and asserts(helpers[0], seen | {fn.name}, depth + 1):
                            return True
                        continue
                    if ASSERT_RE.search(ast.unparse(node.func) + '('):
                        return True
                return False
            return {fn.lineno: asserts(fn, set(), 0) for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
        return src.memo('python_test_assertions', compute).get(line, False)


def _python_function_statements(node):
    """로컬 함수 선언은 실행된 검증으로 세지 않는다."""
    stack = list(node.body)
    while stack:
        item = stack.pop()
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield item
        stack.extend(ast.iter_child_nodes(item))
