"""개발용 Java 닫힌 값 사례. heldout 파일과 분리하며 벤치마크 점수로 사용하지 않는다."""

import pytest

from tests.helpers import scan_files


@pytest.mark.parametrize('setup', [
    'String value="initial"; if(flag) { value="fixed"; } else { value="other"; }',
    'String value=Labels.name();',
    'java.util.List<String> names=java.util.List.of("fixed"); String value=names.get(0);',
])
@pytest.mark.parametrize('risky', [False, True])
def test_java_closed_value_and_external_input(tmp_path, setup, risky):
    value = 'request.getParameter("id")' if risky else 'value'
    code = 'class App { void run(HttpServletRequest request, boolean flag) { ' + setup + ' statement.executeQuery("SELECT * FROM t WHERE id=" + ' + value + '); } }'
    findings = scan_files(tmp_path, {'App.java': code, 'Labels.java': 'class Labels { static String name() { return "fixed"; } }'})
    assert bool([v for v in findings if v.rule_id == 'IL-501']) is risky
