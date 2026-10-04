"""
제3철칙: 병신같이 덮지 않는다 - 오류 처리와 검증 회피 계열 (행안부 2021 구현단계 4장)
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-302] 테스트 회피 구문을 탐지하는 패턴 정의

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    body_statements,
    handler_body,
    handler_header,
    has_logging,
    has_throw,
    is_literal,
    iter_calls,
    iter_functions,
    iter_handlers,
    walk_no_nested_functions,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.rules.base import BaseRule
from iron_laws.standards import mois_ref

CLEANUP_CALL_RE = re.compile(r"\.(terminate|cancel|close|destroy|abort|disconnect|end|unref|kill|release|stop|dispose)\(.*\)$")
BENIGN_PY_EXCEPTIONS = re.compile(
    r"\b(ImportError|ModuleNotFoundError|StopIteration|StopAsyncIteration|KeyboardInterrupt|CancelledError|queue\.Empty|Empty|BrokenPipeError|GeneratorExit)\b"
)
DEFAULT_VALUE_RE = re.compile(
    r"^\s*(return|yield)?\s*(None|null|nil|false|False|true|True|0|-1|\"\"|''|\[\]|\{\}|undefined|\(\)|string\.Empty|default|new\s+\w+(<[^>]*>)?\(\s*\)|Array\.Empty<[^>]*>\(\)|Optional\.empty\(\)|Collections\.empty\w+\(\))\s*;?\s*$"
)
CAUGHT_VAR_RE = {
    "python": re.compile(r"\bas\s+(\w+)"),
    "java": re.compile(r"\)\s*$|\(\s*(?:final\s+)?[\w.|<>\s]+?\s+(\w+)\s*\)"),
}


def caught_variable(src: SourceFile, handler: Node) -> str | None:
    header = handler_header(src, handler)
    if src.lang is Lang.PYTHON:
        m = re.search(r"\bas\s+(\w+)", header)
        return m.group(1) if m else None
    if src.lang in JS_FAMILY:
        m = re.search(r"catch\s*\(\s*(\w+)", header)
        return m.group(1) if m else None
    if src.lang in (Lang.JAVA, Lang.CSHARP, Lang.PHP):
        m = re.search(r"\(\s*(?:final\s+)?[\w.|\\<>\s]+?\s+\$?(\w+)\s*\)\s*$", header.strip())
        if m:
            return m.group(1)
        m = re.search(r"\$(\w+)\s*\)\s*$", header.strip())
        return m.group(1) if m else None
    return None


def uses_name(src: SourceFile, node: Node | None, name: str | None) -> bool:
    if node is None or not name:
        return False
    return re.search(rf"(?<![\w$]){re.escape(name)}(?!\w)", src.text_of(node)) is not None


class SwallowedExceptionRule(BaseRule):
    rule_id = "IL-301"
    name = "예외 은폐 (로그도 전파도 없는 오류 처리) 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.HIGH
    gov_standard = mois_ref("4-2")
    plain = "오류가 났는데 기록도 하지 않고 조용히 넘어가면, 서비스가 잘못된 결과를 내도 아무도 모르고 원인도 찾을 수 없습니다. AI가 코드를 '일단 돌아가게' 만들 때 자주 이렇게 덮어 둡니다."
    how_to_fix = (
        "예상하지 못한 오류는 다시 던지거나(raise/throw) 최소한 로그로 남기세요. "
        "복구할 수 있는 경우에만 처리하고, 그 이유를 주석과 로그에 남기세요. 예: logger.exception('결제 처리 실패'); raise"
    )
    languages = None

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None:
            return found
        for handler in iter_handlers(src):
            v = self._check_handler(src, handler)
            if v is not None:
                found.append(v)
        if src.lang in JS_FAMILY:
            found.extend(self._promise_catch(src))
        if src.lang is Lang.GO:
            found.extend(self._go(src))
        if src.lang is Lang.RUST:
            found.extend(self._rust(src))
        if src.lang is Lang.PYTHON:
            found.extend(self._py_suppress(src))
        if src.lang is Lang.PHP:
            found.extend(self._php_suppress(src))
        return found

    def _check_handler(self, src: SourceFile, handler: Node) -> Violation | None:
        body = handler_body(handler)
        if body is None:
            return None
        header = handler_header(src, handler)
        if src.lang is Lang.PYTHON and BENIGN_PY_EXCEPTIONS.search(header):
            return None
        if has_throw(src, body) or has_logging(src, body):
            return None
        if re.search(r"\.interrupt\(\)|Thread\.currentThread", src.text_of(body)):
            return None
        stmts = body_statements(body)
        var = caught_variable(src, handler)
        if uses_name(src, body, var):
            return None
        if var and re.fullmatch(r"(?i)_+|ignored?|unused|expected|nothing|swallowed", var):
            return self.at_node(
                src,
                handler,
                f"예외 변수를 {var}로 이름 붙여 의도적으로 무시합니다. 무시해도 되는 이유를 주석이나 억제 주석으로 남기십시오.",
                severity=Severity.LOW,
                confidence=Confidence.REVIEW,
            )
        try_body = handler.parent.child_by_field_name("body") if handler.parent is not None else None
        if try_body is not None and re.search(r"(localStorage|sessionStorage|document\.cookie)\s*[.\[]", src.text_of(try_body)):
            return self.at_node(
                src,
                handler,
                "브라우저 저장소 접근 실패를 조용히 넘깁니다 (저장소가 막힌 환경 대비). 사용자에게 알릴 필요가 없는지 확인하십시오.",
                severity=Severity.LOW,
                confidence=Confidence.REVIEW,
            )
        documented = any(
            "comment" in c.type
            and handler.start_byte <= c.start_byte < handler.end_byte
            and len(src.text_of(c).strip("/#* \t\n")) >= 3
            for c in src.comment_nodes
        )
        if documented:
            return self.at_node(
                src,
                handler,
                "예외를 무시하는 이유를 주석으로 남겼지만 로그나 전파는 없습니다. 의도한 생략이면 오철칙 억제 주석으로 사유를 명시하십시오.",
                severity=Severity.LOW,
                confidence=Confidence.REVIEW,
            )
        if not stmts or all(s.type in ("pass_statement", "ellipsis", "continue_statement", "break_statement", "empty_statement") for s in stmts):
            if self._narrow_control_flow(src, handler, header):
                return self.at_node(
                    src,
                    handler,
                    "구체적인 예외를 잡고 아무 처리 없이 넘어갑니다. 의도한 흐름 제어라면 사유를 주석이나 억제 주석으로 남기십시오.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.REVIEW,
                )
            return self.at_node(src, handler, "예외를 잡고 아무 처리도 하지 않습니다 (빈 처리). 오류를 기록하거나 다시 던지십시오.")
        if len(stmts) == 1 and stmts[0].type in ("return_statement", "expression_statement"):
            text = src.text_of(stmts[0])
            if stmts[0].type == "return_statement":
                if DEFAULT_VALUE_RE.match(text) or text.strip() in ("return", "return;"):
                    return self.at_node(src, handler, "예외를 잡고 기본값을 반환해 오류를 숨깁니다. 기록하거나 다시 던지십시오.")
            elif DEFAULT_VALUE_RE.match(text):
                return self.at_node(src, handler, "예외를 잡고 아무 의미 없는 식만 실행합니다. 기록하거나 다시 던지십시오.")
        return self.at_node(
            src,
            handler,
            "예외를 로그나 전파 없이 처리합니다. 대체 동작이 의도된 것인지 확인하고 최소한 로그를 남기십시오.",
            severity=Severity.MEDIUM,
            confidence=Confidence.REVIEW,
        )

    @staticmethod
    def _narrow_control_flow(src: SourceFile, handler: Node, header: str) -> bool:
        """구체적인 예외 타입을 잡고 try 본문이 짧거나 반복문 흐름 제어(continue·break)인 경우"""
        if re.search(r"\b(Exception|BaseException|Throwable)\b|except\s*:|catch\s*\(\s*\w+\s*\)", header) or "catch" in header and not re.search(r"\(\s*[\w.|]+\s+\w+\s*\)", header):
            return False
        parent = handler.parent
        if parent is None:
            return False
        try_body = parent.child_by_field_name("body")
        return try_body is not None and len(body_statements(try_body)) <= 2

    def _promise_catch(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not call.callee.endswith(".catch") or not call.args:
                continue
            fn = call.args[0]
            if fn.type not in ("arrow_function", "function_expression", "function"):
                continue
            body = fn.child_by_field_name("body")
            if body is None:
                continue
            params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
            var = None
            if params is not None:
                m = re.search(r"\w+", src.text_of(params))
                var = m.group(0) if m else None
            if has_logging(src, fn) or has_throw(src, fn) or uses_name(src, body, var):
                continue
            if CLEANUP_CALL_RE.search(call.callee.rsplit(".catch", 1)[0]):
                found.append(self.at_node(src, call.node, "정리(close/cancel 등) 호출의 실패를 조용히 넘깁니다. 최선 노력 정리라면 사유를 남기십시오.", severity=Severity.LOW, confidence=Confidence.REVIEW))
                continue
            if body.type == "statement_block":
                if body_statements(body) and not all(s.type in ("return_statement", "empty_statement") for s in body_statements(body)):
                    continue
                found.append(self.at_node(src, call.node, "Promise의 .catch가 오류를 기록하거나 다시 던지지 않고 삼킵니다."))
            elif is_literal(body) or body.type in ("identifier", "undefined", "null", "array", "object"):
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        "Promise의 .catch가 기본값만 반환해 오류를 숨깁니다.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.REVIEW,
                    )
                )
        return found

    def _go(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for node in src.nodes:
            if node.type == "if_statement":
                cond = node.child_by_field_name("condition")
                block = node.child_by_field_name("consequence")
                if cond is None or block is None:
                    continue
                if not re.search(r"\berr\w*\s*!=\s*nil", src.text_of(cond)):
                    continue
                if has_throw(src, block) or has_logging(src, block):
                    continue
                stmts = body_statements(block)
                if not stmts:
                    found.append(self.at_node(src, node, "err != nil 분기가 비어 있어 에러를 무시합니다."))
                elif all(s.type in ("return_statement", "continue_statement", "break_statement") for s in stmts):
                    bare = all(
                        not s.named_children or s.type in ("continue_statement", "break_statement") for s in stmts
                    )
                    found.append(
                        self.at_node(
                            src,
                            node,
                            "err != nil일 때 에러를 반환·기록하지 않고 빠져나갑니다.",
                            severity=Severity.MEDIUM if bare else Severity.HIGH,
                            confidence=Confidence.REVIEW if bare else Confidence.CONFIRMED,
                        )
                    )
            elif node.type in ("assignment_statement", "short_var_declaration"):
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is None or right is None:
                    continue
                left_text = src.text_of(left)
                call_text = src.text_of(right)
                if re.fullmatch(r"_\s*", left_text) and "(" in call_text:
                    if re.search(r"(Close|Write|Flush|Remove|Commit|Rollback|Exec|Scan|Decode|Encode|Unmarshal|Marshal|Send|Copy|Read|Seek|Sync|Chmod|Rename)\w*\(", call_text):
                        found.append(self.at_node(src, node, "반환된 에러를 _ 로 버립니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                elif re.search(r",\s*_\s*$", left_text) and re.search(r"\b(Open|ReadFile|ReadAll|Atoi|Parse\w*|Unmarshal|Marshal|Decode|Query\w*|Exec\w*|Create|Stat|Dial\w*|WriteFile|ReadDir|Scan)\w*\(", call_text):
                    found.append(self.at_node(src, node, "에러 반환값을 _ 로 버립니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _rust(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for node in src.nodes:
            if node.type == "let_declaration":
                pattern = node.child_by_field_name("pattern")
                value = node.child_by_field_name("value")
                if pattern is not None and value is not None and src.text_of(pattern) == "_" and value.type in ("call_expression", "await_expression", "try_expression"):
                    if not re.match(r"\s*(drop|std::mem::drop)\(", src.text_of(value)):
                        found.append(self.at_node(src, node, "let _ = 로 Result를 버립니다. 오류를 처리하거나 기록하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
            elif node.type == "expression_statement" and node.named_children:
                expr = node.named_children[0]
                if expr.type == "call_expression" and re.search(r"\.ok\(\)$", src.text_of(expr)):
                    found.append(self.at_node(src, node, ".ok()로 Result를 Option으로 바꿔 오류를 버립니다."))
            elif node.type == "match_arm":
                pattern = node.child_by_field_name("pattern")
                value = node.child_by_field_name("value")
                if pattern is None or value is None or not src.text_of(pattern).startswith("Err("):
                    continue
                vtext = src.text_of(value).strip()
                if vtext in ("{}", "()", "{ }") or re.fullmatch(r"\{\s*\}", vtext):
                    found.append(self.at_node(src, node, "Err 분기를 비워 오류를 삼킵니다."))
        for m in re.finditer(r"\.(parse|read_to_string|open|send|write_all|flush|try_into|from_str)\b[^;\n]*\.unwrap_or(_default|_else)?\(", src.code_text):
            line = src.code_text.count("\n", 0, m.start()) + 1
            found.append(self.at_line(src, line, "실패할 수 있는 연산의 오류를 기본값으로 대체합니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _py_suppress(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if call.callee in ("suppress", "contextlib.suppress"):
                args = " ".join(src.text_of(a) for a in call.args)
                broad = bool(re.search(r"\b(Exception|BaseException)\b", args))
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        "contextlib.suppress로 예외를 조용히 무시합니다.",
                        severity=Severity.HIGH if broad else Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED if broad else Confidence.REVIEW,
                    )
                )
        return found

    def _php_suppress(self, src: SourceFile) -> list[Violation]:
        found = []
        assert src.root is not None
        for node in src.nodes:
            if node.type == "error_suppression_expression":
                found.append(self.at_node(src, node, "@ 연산자로 오류 출력을 억제합니다. 오류를 처리하거나 예외로 던지십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found


class BroadExceptionRule(BaseRule):
    rule_id = "IL-304"
    name = "부적절한 예외 처리 (포괄적 예외 처리) 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    gov_standard = mois_ref("4-3")
    plain = "'모든 오류'를 한꺼번에 잡으면 예상치 못한 진짜 버그까지 같은 방식으로 덮여서 문제를 찾기 어려워집니다."
    how_to_fix = "처리할 수 있는 구체적인 예외 타입만 잡으세요 (예: ValueError, IOException). 최상위 경계(요청 처리기 등)에서만 포괄 처리하고 그때도 로그를 남기고 다시 던지세요."
    broad_header = re.compile(
        r"(?:except\s*:|except\s+(?:BaseException|Exception)\b|catch\s*\(\s*(?:final\s+)?(?:System\.)?(?:Exception|Throwable|Error|RuntimeException)\b|catch\s*\(\s*\\?(?:Exception|Throwable)\b|catch\s*:?\s*\{|catch\s*$)"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang in JS_FAMILY or src.lang is None:
            return found
        for handler in iter_handlers(src):
            body = handler_body(handler)
            header = handler_header(src, handler).strip()
            if not self.broad_header.search(header + " "):
                continue
            if body is not None and has_throw(src, body):
                continue
            found.append(self.at_node(src, handler, "포괄적 예외(Exception/Throwable/bare except)를 잡고 있습니다. 구체적인 예외 타입을 지정하십시오.", confidence=Confidence.REVIEW))
        if src.lang is Lang.JAVA and src.root is not None:
            for node in src.nodes:
                if node.type == "throws":
                    if re.search(r"\b(Exception|Throwable)\b", src.text_of(node)) and not re.search(r"\w+Exception", src.text_of(node).replace("Exception", "", 1)):
                        found.append(self.at_node(src, node, "메서드가 throws Exception/Throwable로 모든 예외를 위임합니다. 구체적인 예외를 선언하십시오.", confidence=Confidence.REVIEW))
        return found


class ErrorExposureRule(BaseRule):
    rule_id = "IL-305"
    name = "오류 메시지를 통한 정보 노출 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    gov_standard = mois_ref("4-1")
    plain = "오류 내용(스택, 쿼리, 경로)을 사용자 화면에 그대로 보내면 공격자가 서버 내부 구조를 알아내는 단서로 씁니다."
    how_to_fix = "사용자에게는 '요청을 처리할 수 없습니다' 같은 일반 문구와 오류 추적 ID만 보여 주고, 상세 내용은 서버 로그에만 남기세요."
    handler_patterns = {
        Lang.PYTHON: re.compile(r"(str|repr)\(\s*\w+\s*\)|traceback\.format_exc|\.args\b|exc_info"),
        Lang.JAVA: re.compile(r"(getWriter|sendError|\.body\(|\.entity\(|ResponseEntity)[^\n;]*\b\w+\.(getMessage|toString|getStackTrace|printStackTrace)\b|printStackTrace\(\s*\w*\.?getWriter"),
        Lang.CSHARP: re.compile(r"(Response\.Write|StatusCode|BadRequest|Content|Problem|Json|Ok)\([^;\n]*\b\w+\.(Message|ToString\(\)|StackTrace)"),
        Lang.PHP: re.compile(r"(echo|print|die|exit)\b[^;\n]*\$\w+->(getMessage|getTraceAsString)\(|print_r\(\s*\$e"),
    }
    py_response = re.compile(r"\b(jsonify|Response|HttpResponse|JsonResponse|JSONResponse|make_response|abort|HTTPException|render_template|return)\b")
    js_response = re.compile(r"^(res|response|reply)\..*(send|json|end|write|render)$")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None:
            return found
        if src.lang in self.handler_patterns:
            pattern = self.handler_patterns[src.lang]
            for handler in iter_handlers(src):
                body = handler_body(handler)
                if body is None:
                    continue
                for idx in range(body.start_point[0], body.end_point[0] + 1):
                    line = src.lines[idx] if idx < len(src.lines) else ""
                    if not pattern.search(line):
                        continue
                    if src.lang is Lang.PYTHON and not self.py_response.search(line):
                        continue
                    if src.lang is Lang.PYTHON and has_logging_line(line):
                        continue
                    found.append(self.at_line(src, idx + 1, "오류 내용(메시지/스택)을 응답으로 사용자에게 내보냅니다."))
                    break
        if src.lang in JS_FAMILY:
            for handler in iter_handlers(src):
                body = handler_body(handler)
                var = caught_variable(src, handler)
                if body is None or not var:
                    continue
                for call in iter_calls(src):
                    if not (body.start_byte <= call.node.start_byte < body.end_byte):
                        continue
                    if self.js_response.search(call.callee) and any(re.search(rf"\b{re.escape(var)}\.(stack|message)|\b{re.escape(var)}\b\s*$", src.text_of(a)) for a in call.args):
                        found.append(self.at_node(src, call.node, "오류 객체(메시지/스택)를 응답으로 내보냅니다."))
        if src.lang is Lang.GO:
            for call in iter_calls(src):
                if call.callee == "http.Error" and len(call.args) >= 2 and re.search(r"\berr\w*\.Error\(\)|\berr\w*$", src.text_of(call.args[1])):
                    found.append(self.at_node(src, call.node, "err.Error()를 HTTP 응답으로 그대로 내보냅니다.", confidence=Confidence.REVIEW))
        if src.lang is Lang.PHP:
            for idx, line in enumerate(src.code_lines, start=1):
                if re.search(r"ini_set\(\s*['\"]display_errors['\"]\s*,\s*(['\"]?(1|On|true)['\"]?|true)", line, re.IGNORECASE):
                    found.append(self.at_line(src, idx, "display_errors를 켜서 오류를 화면에 출력합니다."))
        return found


def has_logging_line(line: str) -> bool:
    return bool(re.search(r"\b(log|logger|logging)\.", line))


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
                if fn.name.startswith("test") and fn.body is not None and not ASSERT_RE.search(src.text_of(fn.body)):
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


class AuthBypassRule(BaseRule):
    rule_id = "IL-303"
    name = "인증/인가 무력화 및 가짜 통과 코드 탐지"
    iron_law = IronLaw.LAW_3
    severity = Severity.CRITICAL
    gov_standard = mois_ref("2-1", "2-2")
    plain = "로그인·권한 확인 함수가 항상 '통과'를 돌려주면 보호하는 척만 하고 누구나 관리자 기능을 쓸 수 있습니다."
    how_to_fix = "실제 세션/토큰에서 사용자와 권한을 확인해 결과를 계산하세요. 개발 중 임시로 막아 둔 인증은 배포 전에 반드시 복구하세요."
    auth_fn = re.compile(
        r"(?i)^(is_?admin|is_?authenticated|is_?authorized|authenticate\w*|authorize\w*|verify_?token|check_?auth\w*|check_?permission\w*|has_?permission|has_?role|require_?auth\w*|requires?_?login|login_?required|ensure_?auth\w*|protect|is_?logged_?in|validate_?token|verify_?user|isAdmin)$"
    )
    trivial_body = re.compile(r"^\s*\{?\s*(return\s+(True|true|1)\s*;?|next\(\)\s*;?|return\s+next\(\)\s*;?|pass|return\s*;?|\.\.\.)\s*\}?\s*$")
    permit_all = re.compile(r"anyRequest\(\)\s*\.permitAll\(\)|requestMatchers\(\s*\"/\*\*\"\s*\)\s*\.permitAll\(\)|antMatchers\(\s*\"/\*\*\"\s*\)\s*\.permitAll\(\)|AllowAnonymous\]\s*\n?\s*\[?ApiController")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None:
            return found
        for fn in iter_functions(src):
            if not self.auth_fn.match(fn.name):
                continue
            body = fn.body
            if body is None:
                text = src.text_of(fn.node)
                arrow = text.split("=>", 1)[-1].strip() if "=>" in text else ""
                if arrow in ("true", "next()", "null"):
                    found.append(self.at_node(src, fn.node, f"{fn.name}이(가) 항상 통과합니다."))
                continue
            stmts = body_statements(body)
            if body.type not in ("block", "statement_block", "compound_statement", "declaration_list") and re.match(r"\s*(true|True)\s*$", src.text_of(body)):
                found.append(self.at_node(src, fn.node, f"{fn.name}이(가) 항상 통과합니다."))
            elif 0 < len(stmts) <= 1 and self.trivial_body.match(src.text_of(stmts[0])):
                found.append(self.at_node(src, fn.node, f"{fn.name}이(가) 검사 없이 항상 통과시킵니다."))
            elif not stmts and src.lang is not Lang.PYTHON:
                found.append(self.at_node(src, fn.node, f"{fn.name}의 본문이 비어 있어 인증이 수행되지 않습니다."))
        for idx, line in enumerate(src.code_lines, start=1):
            if self.permit_all.search(line):
                found.append(self.at_line(src, idx, "모든 요청에 인증 없이 접근을 허용(permitAll)합니다."))
        return found


IF_TYPES = {"if_statement", "if_expression"}
NULL_GUARD_RE = re.compile(
    r"^\(?\s*(?:!\s*|not\s+)?\w+(?:\.\w+|\[[^\]]*\])*\s*(?:(?:==|!=|is|is\s+not)\s*(?:null|None|nil|undefined)\b)?\s*\)?$"
)


class FailureAsDefaultRule(BaseRule):
    rule_id = "IL-307"
    name = "검증·처리 실패를 null·기본값으로 대체하고 기록하지 않음"
    iron_law = IronLaw.LAW_3
    severity = Severity.MEDIUM
    gov_standard = mois_ref("4-2")
    plain = "검증이나 복호화가 실패했는데 예외 없이 null·false를 돌려주면, 호출한 쪽은 실패를 모른 채 정상처럼 처리를 이어 갑니다. 결제·인증처럼 정확성이 중요한 곳에서는 잘못된 결과가 조용히 쌓이고 원인도 남지 않습니다."
    how_to_fix = "정상 흐름을 벗어나면 예외를 던지세요(복구할 수 있는 경우에만 처리). 던지지 않고 값을 돌려줘야 한다면 실패 사유를 로그로 남기고, 호출한 쪽이 실패를 구분할 수 있게 결과 타입(성공·실패)을 명시하세요."
    sensitive_fn = re.compile(
        r"(?i)(verif|validat|decrypt|decod|encrypt|authenticat|authoriz|check|parse|token|sign|checksum|permission|credential|pay|charge|refund|settle|transfer|withdraw|deposit|order|amount|balance|login|otp)"
    )
    or_null = re.compile(r"(?i)(OrNull|_or_none|OrDefault|_or_default|OrEmpty)$")
    return_types = {"return_statement"}

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None or src.lang in (Lang.RUST, Lang.C, Lang.CPP):
            return found
        for fn in iter_functions(src):
            if fn.body is None:
                continue
            if self.or_null.search(fn.name):
                found.append(
                    self.at_node(
                        src,
                        fn.node,
                        f"{fn.name}은(는) 실패를 null·기본값으로 돌려주는 API입니다. 호출부가 실패를 구분하지 못합니다.",
                        severity=Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
            if not self.sensitive_fn.search(fn.name):
                continue
            for node in walk_no_nested_functions(fn.body, src.lang):
                if node.type in IF_TYPES:
                    violation = self._check_branch(src, fn.name, node)
                    if violation is not None:
                        found.append(violation)
        return found

    def _check_branch(self, src: SourceFile, fn_name: str, node: Node) -> Violation | None:
        cond = node.child_by_field_name("condition")
        block = node.child_by_field_name("consequence")
        if cond is None or block is None:
            return None
        cond_text = src.text_of(cond).strip().strip("()").strip()
        if NULL_GUARD_RE.match(cond_text):
            return None  # 단순 null 전파 가드는 실패 대체로 보지 않는다
        stmts = body_statements(block) if block.type in ("block", "statement_block", "compound_statement") else [block]
        if len(stmts) != 1 or stmts[0].type not in self.return_types:
            return None
        if not DEFAULT_VALUE_RE.match(src.text_of(stmts[0])) and src.text_of(stmts[0]).strip() not in ("return", "return;"):
            return None
        if has_throw(src, block) or has_logging(src, block):
            return None
        return self.at_node(
            src,
            node,
            f"{fn_name}에서 조건 실패 시 예외나 로그 없이 기본값을 반환합니다. 실패가 정상 결과처럼 전달됩니다.",
            confidence=Confidence.REVIEW,
        )


class ValidationMessageMismatchRule(BaseRule):
    rule_id = "IL-531"
    name = "입력 검증 조건과 오류 메시지의 불일치 의심"
    iron_law = IronLaw.LAW_3
    severity = Severity.LOW
    gov_standard = None
    plain = "허용 범위가 위아래 두 쪽인데 오류 메시지는 한쪽만 알려 주면, 사용자는 왜 거절됐는지 알 수 없고 검증 규칙이 바뀔 때 메시지가 어긋납니다."
    how_to_fix = "검증 조건의 상·하한을 상수로 두고 오류 메시지에도 같은 상수를 써서 조건과 메시지가 함께 바뀌게 하세요. 예: \"최대 횟수는 {MIN} 이상 {MAX} 이하여야 합니다\""
    number_re = re.compile(r"(?<![\w.])(\d[\d_,]*)(?![\w.])")
    one_sided = re.compile(r"이상|이하|초과|미만|at least|at most|minimum|maximum|greater|less")
    two_sided = re.compile(r"사이|범위|between|range|~|이상[^\n]*이하|이하[^\n]*이상|초과[^\n]*미만|미만[^\n]*초과|min[^\n]*max")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None or src.is_test:
            return found
        for node in src.nodes:
            if node.type not in IF_TYPES:
                continue
            cond = node.child_by_field_name("condition")
            block = node.child_by_field_name("consequence")
            if cond is None or block is None:
                continue
            cond_text = src.text_of(cond)
            numbers = {n.replace("_", "").replace(",", "") for n in self.number_re.findall(cond_text)}
            numbers.discard("0")
            if len(numbers) < 2 or not re.search(r"\|\||&&|\bor\b|\band\b", cond_text):
                continue
            if len(re.findall(r"<=|>=|<|>", cond_text)) < 2:
                continue
            message = re.search(r"[\"'`]([^\"'`\n]{4,})[\"'`]", src.text_of(block))
            if message is None:
                continue
            text = message.group(1)
            message_numbers = {n.replace("_", "").replace(",", "") for n in self.number_re.findall(text)}
            if numbers <= message_numbers or self.two_sided.search(text) or not self.one_sided.search(text):
                continue
            found.append(
                self.at_node(
                    src,
                    node,
                    f"검증 조건은 두 경계({', '.join(sorted(numbers))})를 두는데 오류 메시지는 한쪽만 안내합니다: {text[:40]}",
                    confidence=Confidence.REVIEW,
                )
            )
        return found


ERROR_RULES: list[type[BaseRule]] = [
    SwallowedExceptionRule,
    DisabledTestRule,
    AuthBypassRule,
    BroadExceptionRule,
    ErrorExposureRule,
    TestWithoutAssertionRule,
    FailureAsDefaultRule,
    ValidationMessageMismatchRule,
]
