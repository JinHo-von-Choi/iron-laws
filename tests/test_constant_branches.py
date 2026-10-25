"""
상수 계산으로 갈래 줄이기: 실행되지 않는 갈래의 외부 입력은 확정 지적을 만들지 않고, 조금이라도 불확실하면 지금처럼 모든 갈래를 따라간다
OWASP Benchmark의 모양과 다른 이름·상수·구조로 쓴 반례다(벤치마크 점수만 올리는 맞춤을 막는다).
작성자: 최진호
작성일: 2026-10-26
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner

JAVA_HEAD = "import java.sql.*;\nimport javax.servlet.http.*;\npublic class Svc {\n  public void handle(HttpServletRequest request, Connection conn) throws Exception {\n    String input = request.getParameter(\"q\");\n    String value;\n"
JAVA_TAIL = "    conn.createStatement().execute(\"SELECT * FROM t WHERE c = '\" + value + \"'\");\n  }\n}\n"


def confirmed(tmp_path: Path, name: str, code: str, rule: str) -> bool:
    (tmp_path / name).write_text(code, encoding="utf-8")
    return any(v.rule_id == rule and v.confidence.value == "CONFIRMED" for v in AuditScanner(tmp_path).scan().violations)


@pytest.mark.parametrize("body, flagged", [
    ("    int limit = 9;\n    if (limit * 3 < 10) value = input; else value = \"fixed\";\n", False),
    ("    int limit = 9;\n    if (limit * 3 > 10) value = input; else value = \"fixed\";\n", True),
    ("    int limit = 9;\n    limit = limit + Integer.parseInt(input);\n    if (limit * 3 < 10) value = input; else value = \"fixed\";\n", True),
    ("    if (input.length() > 99) value = input; else value = \"fixed\";\n", True),
    ("    value = (2 + 2 == 5) ? input : \"fixed\";\n", False),
    ("    value = (2 + 2 == 4) ? input : \"fixed\";\n", True),
    ("    String key = \"XYZ\";\n    switch (key.charAt(2)) {\n      case 'X': value = input; break;\n      case 'Z': value = \"fixed\"; break;\n      default: value = input; break;\n    }\n", False),
    ("    String key = \"XYZ\";\n    switch (key.charAt(0)) {\n      case 'X': value = input; break;\n      case 'Z': value = \"fixed\"; break;\n      default: value = input; break;\n    }\n", True),
    ("    String key = \"XYZ\";\n    switch (key.charAt(2)) {\n      case 'Z': value = \"fixed\";\n      case 'Q': value = input; break;\n      default: value = \"other\"; break;\n    }\n", True),
    ("    java.util.List<String> items = new java.util.ArrayList<String>();\n    items.add(input);\n    items.add(\"fixed\");\n    value = items.get(1);\n", False),
    ("    java.util.List<String> items = new java.util.ArrayList<String>();\n    items.add(\"fixed\");\n    items.add(input);\n    items.remove(0);\n    value = items.get(0);\n", True),
    ("    java.util.List<String> items = new java.util.ArrayList<String>();\n    items.add(input);\n    items.add(\"fixed\");\n    java.util.Collections.reverse(items);\n    value = items.get(1);\n", True),
    ("    java.util.List<String> items = new java.util.ArrayList<String>();\n    items.add(input);\n    items.add(\"fixed\");\n    if (input.isEmpty()) items.remove(1);\n    value = items.get(1);\n", True),
])
def test_java_constant_branches(tmp_path, body, flagged):
    assert confirmed(tmp_path, "Svc.java", JAVA_HEAD + body + JAVA_TAIL, "IL-501") is flagged


@pytest.mark.parametrize("body, flagged", [
    ("    if 3 > 4:\n        value = request.args['q']\n    else:\n        value = 'fixed'\n", False),
    ("    if 3 < 4:\n        value = request.args['q']\n    else:\n        value = 'fixed'\n", True),
    ("    value = request.args['q'] if 1 == 2 else 'fixed'\n", False),
    ("    limit = 5\n    if limit > 3:\n        value = 'fixed'\n    else:\n        value = request.args['q']\n", False),
    ("    limit = 5\n    limit += len(request.args)\n    if limit > 3:\n        value = 'fixed'\n    else:\n        value = request.args['q']\n", True),
])
def test_python_constant_branches(tmp_path, body, flagged):
    code = "import os\nfrom flask import request\n\ndef handler():\n" + body + "    os.system('ls ' + value)\n"
    assert confirmed(tmp_path, "app.py", code, "IL-504") is flagged


@pytest.mark.parametrize("selected, review", [(2, False), (0, True)])
def test_switch_dead_cases_do_not_leave_review_findings(tmp_path, selected, review):
    body = (f"    String key = \"XYZ\";\n    switch (key.charAt({selected})) {{\n      case 'X': value = input; break;\n"
            "      case 'Z': value = \"fixed\"; break;\n      default: value = \"other\"; break;\n    }\n")
    (tmp_path / "Svc.java").write_text(JAVA_HEAD + body + JAVA_TAIL, encoding="utf-8")
    found = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id == "IL-501"]
    assert bool(found) is review


@pytest.mark.parametrize("body, review", [
    ("    java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();\n    m.put(\"a\", \"fixed\");\n    m.put(\"b\", input);\n    value = (String) m.get(\"a\");\n", False),
    ("    java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();\n    m.put(\"a\", \"fixed\");\n    m.put(\"b\", input);\n    value = (String) m.get(\"b\");\n", True),
    ("    java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();\n    m.put(\"a\", \"fixed\");\n    m.put(\"a\", input);\n    value = (String) m.get(\"a\");\n", True),
    ("    java.util.Map<String, Object> m = new java.util.HashMap<String, Object>();\n    m.put(\"a\", \"fixed\");\n    m.putAll(java.util.Map.of(\"a\", input));\n    value = (String) m.get(\"a\");\n", True),
])
def test_map_constant_keys(tmp_path, body, review):
    (tmp_path / "Svc.java").write_text(JAVA_HEAD + body + JAVA_TAIL, encoding="utf-8")
    found = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id == "IL-501"]
    assert bool(found) is review


@pytest.mark.parametrize("helper, review", [
    ("    int n = 1;\n    String bar = (n > 5) ? p : \"fixed\";\n    return bar;\n", False),
    ("    int n = 9;\n    String bar = (n > 5) ? p : \"fixed\";\n    return bar;\n", True),
    ("    if (p.isEmpty()) return \"fixed\";\n    return p;\n", True),
])
def test_same_file_helper_returning_constant(tmp_path, helper, review):
    code = ("import java.sql.*;\nimport javax.servlet.http.*;\npublic class Svc {\n  public void handle(HttpServletRequest request, Connection conn) throws Exception {\n"
            "    String input = request.getParameter(\"q\");\n    String value = new Helper().pick(input);\n" + JAVA_TAIL.replace("  }\n}\n", "  }\n")
            + "  private class Helper {\n    public String pick(String p) {\n" + helper + "    }\n  }\n}\n")
    (tmp_path / "Svc.java").write_text(code, encoding="utf-8")
    found = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id == "IL-501"]
    assert bool(found) is review


@pytest.mark.parametrize("guard, flagged", [
    ("    if not value.isalnum():\n        raise ValueError('bad')\n", False),
    ("    if not re.fullmatch(r'[A-Za-z0-9_-]+', value):\n        raise ValueError('bad')\n", False),
    ("    if not re.fullmatch(r'[A-Za-z0-9 ;]+', value):\n        raise ValueError('bad')\n", True),
    ("    if not value.isalnum():\n        print('bad')\n", True),
    ("    if value.isalnum():\n        value = value + ';'\n", True),
])
def test_character_class_guards(tmp_path, guard, flagged):
    code = "import os\nimport re\nfrom flask import request\n\ndef handler():\n    value = request.args['q']\n" + guard + "    os.system('echo ' + value)\n"
    assert confirmed(tmp_path, "app.py", code, "IL-504") is flagged


def test_dead_branch_definition_does_not_reach_the_sink(tmp_path):
    code = "import subprocess\nfrom flask import request\n\ndef handler():\n    cmd = 'ls'\n    if 3 > 4:\n        cmd = 'ls ' + request.args['p']\n    subprocess.call(cmd, shell=True)\n"
    assert confirmed(tmp_path, "app.py", code, "IL-504") is False


@pytest.mark.parametrize("body, review", [
    ("    m = {}\n    m['a'] = 'fixed'\n    m['b'] = request.args['q']\n    value = m['a']\n    cmd = 'sh -c '\n    cmd += f'echo {value}'\n", False),
    ("    m = {}\n    m['a'] = 'fixed'\n    m['b'] = request.args['q']\n    value = m['b']\n    cmd = 'sh -c '\n    cmd += f'echo {value}'\n", True),
    ("    m = {}\n    m['a'] = 'fixed'\n    m.update({'a': request.args['q']})\n    value = m['a']\n    cmd = 'sh -c '\n    cmd += f'echo {value}'\n", True),
])
def test_python_dict_constant_keys(tmp_path, body, review):
    code = "import subprocess\nfrom flask import request\n\ndef handler():\n" + body + "    subprocess.run(cmd, shell=True)\n"
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    found = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id == "IL-504"]
    assert bool(found) is review


@pytest.mark.parametrize("body, review", [
    ("    possible = 'ABC'\n    guess = possible[1]\n    match guess:\n        case 'A':\n            value = request.args['q']\n        case 'B':\n            value = 'fixed'\n        case 'C' | 'D':\n            value = request.args['q']\n        case _:\n            value = 'other'\n", False),
    ("    possible = 'ABC'\n    guess = possible[2]\n    match guess:\n        case 'A':\n            value = request.args['q']\n        case 'B':\n            value = 'fixed'\n        case 'C' | 'D':\n            value = request.args['q']\n        case _:\n            value = 'other'\n", True),
    ("    items = []\n    items.append('safe')\n    items.append(request.args['q'])\n    items.append('moresafe')\n    items.pop(0)\n    value = items[1]\n", False),
    ("    items = []\n    items.append('safe')\n    items.append(request.args['q'])\n    items.pop(0)\n    value = items[0]\n", True),
    ("    import configparser\n    conf = configparser.ConfigParser()\n    conf.add_section('s')\n    conf.set('s', 'a', 'fixed')\n    conf.set('s', 'b', request.args['q'])\n    value = conf.get('s', 'a')\n", False),
    ("    import configparser\n    conf = configparser.ConfigParser()\n    conf.add_section('s')\n    conf.set('s', 'a', 'fixed')\n    conf.set('s', 'b', request.args['q'])\n    value = conf.get('s', 'b')\n", True),
])
def test_python_match_list_and_configparser(tmp_path, body, review):
    code = "import subprocess\nfrom flask import request\n\ndef handler():\n" + body + "    subprocess.run('sh -c ' + f'echo {value}', shell=True)\n"
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    found = [v for v in AuditScanner(tmp_path).scan().violations if v.rule_id == "IL-504"]
    assert bool(found) is review
