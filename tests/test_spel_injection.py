"""
오철칙 표현식 삽입(SpEL·OGNL·MVEL) 시험: 웹 입력이 식에 닿으면 확정, 상수가 아닌 식을 StandardEvaluationContext로 평가하면 확인 필요
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from tests.helpers import scan_files

HEAD = (
    "import org.springframework.expression.*;\nimport org.springframework.expression.spel.standard.*;\n"
    "import org.springframework.expression.spel.support.*;\nimport javax.servlet.http.*;\n\nclass X {\n"
)

# (사례 이름, 코드, 기대: None=지적 없음, "CONFIRMED", "REVIEW")
CASES = [
    ("web-input-to-parse", HEAD + "  Object m(HttpServletRequest req) {\n    return new SpelExpressionParser().parseExpression(req.getParameter(\"e\")).getValue();\n  }\n}\n", "CONFIRMED"),
    ("dynamic-expression-standard-context", HEAD + "  static Object v(SpelExpressionParser parser, String entryValue) {\n    StandardEvaluationContext context = new StandardEvaluationContext();\n    Expression expression = parser.parseExpression(entryValue, new TemplateParserContext());\n    return expression.getValue(context);\n  }\n}\n", "REVIEW"),
    ("field-expression-standard-context", HEAD + "  private Expression message;\n  Object text(Object root) {\n    StandardEvaluationContext context = new StandardEvaluationContext(root);\n    return message.getValue(context, String.class);\n  }\n}\n", "REVIEW"),
    ("dynamic-expression-simple-context", HEAD + "  static Object v(SpelExpressionParser parser, String entryValue) {\n    EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n    return parser.parseExpression(entryValue).getValue(context);\n  }\n}\n", None),
    ("constant-expression-standard-context", HEAD + "  Object v(Object root) {\n    StandardEvaluationContext context = new StandardEvaluationContext(root);\n    Expression e = new SpelExpressionParser().parseExpression(\"name\");\n    return e.getValue(context);\n  }\n}\n", None),
    ("constant-variable-expression-standard-context", HEAD + "  Object v() {\n    String source = \"1 + 1\";\n    Expression e = new SpelExpressionParser().parseExpression(source);\n    StandardEvaluationContext ctx = new StandardEvaluationContext();\n    return e.getValue(ctx);\n  }\n}\n", None),
    ("parameter-context-and-expression", HEAD + "  Object evaluate(Expression expression, StandardEvaluationContext ctx) {\n    return expression.getValue(ctx);\n  }\n}\n", "REVIEW"),
    ("ognl-dynamic-expression", "import ognl.Ognl;\n\nclass O {\n  Object evaluate(String input, Object root) throws Exception {\n    Object expression = Ognl.parseExpression(input + \"\");\n    return Ognl.getValue(expression, root);\n  }\n}\n", "REVIEW"),
    ("dynamic-expression-default-context", HEAD + "  Object v(SpelExpressionParser parser, String input) {\n    Expression exp = parser.parseExpression(input);\n    return exp.getValue();\n  }\n}\n", "REVIEW"),
    ("prefixed-dynamic-expression-standard-context", HEAD + "  Object v(SpelExpressionParser parser, String input) {\n    StandardEvaluationContext ctx = new StandardEvaluationContext();\n    Expression expr = parser.parseExpression(\"prefix.\" + input);\n    return expr.getValue(ctx);\n  }\n}\n", "REVIEW"),
    ("ognl-web-input", "import ognl.Ognl;\nimport javax.servlet.http.*;\n\nclass O {\n  Object m(HttpServletRequest request, Object root) throws Exception {\n    return Ognl.getValue(request.getParameter(\"e\"), root);\n  }\n}\n", "CONFIRMED"),
]


@pytest.mark.parametrize(("name", "code", "expected"), CASES, ids=[c[0] for c in CASES])
def test_expression_injection(tmp_path: Path, name: str, code: str, expected: str | None):
    found = {v.confidence.value for v in scan_files(tmp_path, {"X.java": code}) if v.rule_id == "IL-503"}
    assert found == ({expected} if expected else set()), name
