"""Java 별도 평가 사례: 개발 사례의 이름·호출 경로와 입력 전파를 달리한다."""

import pytest

from tests.helpers import scan_files


@pytest.mark.parametrize('setup, helper, expected', [
    ('String value=Names.label();', 'class Names { public static String label() { return "sample"; } }', False),
    ('String value="a"; if(request.getParameter("choose") != null) { value="b"; }', '', False),
    ('java.util.List<String> values=java.util.List.of("a", "b"); String value=values.get(1);', '', False),
    ('String value=Names.label();', 'class Names { public String label() { return "sample"; } }', True),
    ('String value=unknown.label();', '', True),
    ('java.util.List<String> values=java.util.List.of(request.getParameter("name")); String value=values.get(0);', '', True),
    ('String value="a"; if(request.getParameter("choose") != null) { value=request.getParameter("name"); }', '', True),
    ('java.util.List<String> values=java.util.List.of("a"); mutate(values); String value=values.get(0);', '', True),
    ('java.util.List<String> values=java.util.List.of("a"); values.set(0, unknown()); String value=values.get(0);', '', True),
    ('Names Names=unknown(); String value=Names.label();', 'class Names { public static String label() { return "sample"; } }', True),
    ('String value=Names.label();', 'class Names { public static String label() { return unknown(); } }', True),
])
def test_heldout_java_sql_and_path(tmp_path, setup, helper, expected):
    source = 'class Handler { void handle(HttpServletRequest request) { ' + setup + ' stmt.executeQuery("SELECT name FROM entries WHERE id="+value); new java.io.File("/srv/" + value); } }'
    files = {'Handler.java': source}
    if helper:
        files['Names.java'] = helper
    findings = scan_files(tmp_path, files)
    assert bool([v for v in findings if v.rule_id == 'IL-501']) is expected
    # 미해석 경로는 기존처럼 보류하며 SQL 정상 근거를 경로 규칙의 허용으로 넓히지 않는다.
    if 'request.getParameter("name")' in source:
        assert [v for v in findings if v.rule_id == 'IL-502']
