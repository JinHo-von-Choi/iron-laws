from pathlib import Path

import pytest

from iron_laws.engine.source import SourceFile
from iron_laws.rules.ai_code import HardcodedConfigRule
from iron_laws.rules.architecture import DbInLoopRule, SizeAndComplexityRule
from iron_laws.rules.errors import TestWithoutAssertionRule, ValidationMessageMismatchRule
from iron_laws.rules.injection import LdapInjectionRule


@pytest.mark.parametrize('receiver', ['import re\nre.search', 'import re as rx\nrx.search', 'from re import compile as compile_rx\ndb = compile_rx("(uid=")\ndb.search'])
def test_regex_is_not_ldap(receiver):
    setup, call = receiver.rsplit('\n', 1)
    src = SourceFile(Path('app.py'), setup + '\nfrom flask import request\n' + call + '("(uid=" + request.args["q"])\n')
    assert not LdapInjectionRule().check(src)


def test_ldap_receiver_shadowing_is_still_detected():
    src = SourceFile(Path('app.py'), 'import re\nfrom flask import request\ndef handle(re):\n    re.search("(uid=" + request.args["q"])\n')
    assert LdapInjectionRule().check(src)


def test_later_same_line_regex_assignment_does_not_exempt_ldap():
    src = SourceFile(Path('app.py'), 'import re\nfrom flask import request\ndb = connection\ndb.search("(uid=" + request.args["q"]); db = re.compile("x")\n')
    assert LdapInjectionRule().check(src)


def test_python_parse_failure_records_issue_and_cannot_exempt_receiver():
    from iron_laws.engine.python_ast import parse_python
    from iron_laws.engine.python_bindings import binding_index
    src = SourceFile(Path('app.py'), 'import re\nre.search(\n')
    result = parse_python(src)
    assert result.tree is None and result.issue is not None
    assert result.issue.line == 2
    assert binding_index(src) is None


@pytest.mark.parametrize('condition, annotation, denial, expected', [
    ('role in allowed_roles', 'None', 'raise PermissionError("denied")', False),
    ('role not in allowed_roles', 'None', 'raise PermissionError("denied")', True),
    ('not valid_password', 'None', 'raise PermissionError("denied")', True),
    ('role in allowed_roles', 'bool', 'raise PermissionError("denied")', True),
    ('role in allowed_roles', 'None', 'return None', True),
])
def test_allowlist_success_requires_void_contract_and_denial(condition, annotation, denial, expected):
    from iron_laws.rules.errors import FailureAsDefaultRule
    src = SourceFile(Path('app.py'), f'def check_permission(role) -> {annotation}:\n    if {condition}:\n        return None\n    {denial}\n')
    assert bool(FailureAsDefaultRule().check(src)) is expected


@pytest.mark.parametrize('compile_expr', ['re.compile("x")', 'rx.compile("x")'])
def test_regex_finditer_is_not_db(compile_expr):
    src = SourceFile(Path('app.py'), f'import re\nimport re as rx\ndb = {compile_expr}\nfor row in rows:\n    db.finditer(row)\n')
    assert not DbInLoopRule().check(src)


def test_unknown_db_receiver_remains_review():
    src = SourceFile(Path('app.py'), 'def load(db, rows):\n    for row in rows:\n        db.finditer(row)\n')
    assert DbInLoopRule().check(src)


@pytest.mark.parametrize('text, expected', [('import subprocess\nsubprocess.run(["cmd"], timeout=1800)\n', False), ('app.run(port=1800)\n', True), ('worker.run(retries=1800)\n', False)])
def test_port_uses_port_argument(text, expected):
    assert bool(HardcodedConfigRule().check(SourceFile(Path('app.py'), text))) is expected


@pytest.mark.parametrize('helper, expected', [('assert value == 1', False), ('pass', True), ('_assert_value(value)', True)])
def test_assert_helper_requires_real_assertion(helper, expected):
    src = SourceFile(Path('test_app.py'), f'def _assert_value(value):\n    {helper}\ndef test_value():\n    _assert_value(1)\n', is_test=True)
    assert bool(TestWithoutAssertionRule().check(src)) is expected


def test_uncalled_assert_helper_does_not_count():
    src = SourceFile(Path('test_app.py'), 'def helper():\n    assert True\ndef test_value():\n    value = 1\n', is_test=True)
    assert TestWithoutAssertionRule().check(src)


@pytest.mark.parametrize('body, expected', [('findings.append(report("at least 2048 bits"))', False), ('raise ValueError("at least 2048 bits")', True)])
def test_detection_condition_is_not_input_validation(body, expected):
    src = SourceFile(Path('app.py'), f'def check_key(bits):\n    if bits < 256 or bits > 2048:\n        {body}\n')
    assert bool(ValidationMessageMismatchRule().check(src)) is expected


@pytest.mark.parametrize('setup, expected', [('import typer\napp = typer.Typer()', False), ('app = Unknown()', True)])
def test_typer_options_are_not_business_parameters(setup, expected):
    src = SourceFile(Path('app.py'), setup + '\n@app.command()\ndef command(a,b,c,d,e,f,g,h,i,j):\n    return a\n')
    assert bool(SizeAndComplexityRule().check(src)) is expected


@pytest.mark.parametrize('doc, selected, expected', [
    ('Python 3.12+', '3.13', False),
    ('Python 3.12 이상', '3.13', False),
    ('Python 3.12 이상', '3.11', True),
    ('Python 3.12', '3.13', True),
    ('Supported Python 3.12/3.13', '3.13', False),
    ('Supported Python 3.12/3.13', '3.14', True),
])
def test_python_version_constraints(tmp_path, doc, selected, expected):
    from tests.helpers import scan_files
    findings = scan_files(tmp_path, {'README.md': doc, '.python-version': selected})
    assert bool([v for v in findings if v.rule_id == 'AI-121']) is expected


def test_python_ci_matrix_is_support_not_fixed_deployment(tmp_path):
    from tests.helpers import scan_files
    findings = scan_files(tmp_path, {'.github/workflows/ci.yml': 'strategy:\n  matrix:\n    python-version: ["3.12", "3.13"]\n', '.python-version': '3.13'})
    assert not [v for v in findings if v.rule_id == 'AI-121']


@pytest.mark.parametrize('record, expected', [
    ('diagnostics.append(Diagnostic(severity="error", message="check failed"))', True),
    ('diagnostics.append("ignored")', True),
    ('pass', True),
])
def test_broad_exception_requires_failure_diagnostic(record, expected):
    from iron_laws.rules.errors import BroadExceptionRule
    src = SourceFile(Path('app.py'), 'try:\n    check()\nexcept Exception:\n    ' + record + '\n')
    assert bool(BroadExceptionRule().check(src)) is expected


@pytest.mark.parametrize('annotation, name, expected', [('list[Violation]', 'check', False), ('bool', 'authenticate', True), ('list[Violation]', 'authenticate', True)])
def test_analysis_empty_result_is_not_authentication_fallback(annotation, name, expected):
    from iron_laws.rules.errors import FailureAsDefaultRule
    src = SourceFile(Path('app.py'), f'def {name}(value) -> {annotation}:\n    if len(value) < 3:\n        return []\n')
    assert bool(FailureAsDefaultRule().check(src)) is expected


def test_call_index_scans_once_and_excludes_nested_functions(monkeypatch):
    from iron_laws.engine import ast_tools
    src = SourceFile(Path('app.py'), 'def before_request():\n    db.findAll()\n    def local():\n        db.findAll()\n')
    original = ast_tools.iter_calls
    visited = []
    def counted(source):
        visited.append(source)
        return original(source)
    monkeypatch.setattr(ast_tools, 'iter_calls', counted)
    findings = DbInLoopRule().check(src)
    assert [v.line_number for v in findings] == [2]
    assert len(visited) == 1


def test_handler_index_excludes_nested_callbacks():
    from iron_laws.rules.errors import ErrorExposureRule
    src = SourceFile(Path('app.js'), 'try { work(); } catch (err) { function later(err) { res.send(err.message); } res.send(err.message); }')
    assert len(ErrorExposureRule().check(src)) == 1


@pytest.mark.parametrize('code', [
    'import re\nfrom flask import request\nfor re in connections:\n    re.search("(uid=" + request.args["q"])',
    'import re\nfrom flask import request\nhandle = lambda re: re.search("(uid=" + request.args["q"])',
    'import re\nfrom flask import request\ndef handle():\n    global re\n    re = connection\n    re.search("(uid=" + request.args["q"])',
    'from flask import request\nclass Service:\n    import re\n    def handle(self, re):\n        re.search("(uid=" + request.args["q"])',
])
def test_regex_rebinding_never_hides_ldap(code):
    assert LdapInjectionRule().check(SourceFile(Path('app.py'), code))


def test_returned_failure_diagnostic_is_a_boundary():
    from iron_laws.rules.errors import BroadExceptionRule
    code = 'def boundary():\n    diagnostics = []\n    try:\n        check()\n    except Exception:\n        diagnostics.append(Diagnostic(severity="error", message="failure"))\n    return diagnostics\n'
    assert not BroadExceptionRule().check(SourceFile(Path('app.py'), code))


def test_imported_typer_app_is_resolved_without_path_exemption(tmp_path):
    from tests.helpers import scan_files
    files = {'common.py': 'import typer\napp=typer.Typer()\n', 'commands.py': 'from common import app\n@app.command()\ndef entry(a,b,c,d,e,f,g,h,i,j):\n    return a\n'}
    assert not [v for v in scan_files(tmp_path, files) if v.rule_id == 'ARC-201']


@pytest.mark.parametrize('receiver, expected', [
    ('report', False),
    ('reporters', False),
    ('repo', True),
    ('repos', True),
    ('repo_client', True),
    ('repoClient', True),
    ('repositories', True),
    ('userRepository', True),
])
def test_db_receiver_name_boundary(receiver, expected):
    src = SourceFile(Path('app.py'), f'def load({receiver}, rows):\n    for row in rows:\n        {receiver}.find(row)\n')
    assert bool(DbInLoopRule().check(src)) is expected


def test_report_lookups_are_not_db_queries():
    from iron_laws.rules.performance import ManyQueriesRule
    body = ''.join(f'    report.get("k{i}")\n' for i in range(6))
    assert not ManyQueriesRule().check(SourceFile(Path('app.py'), 'def summarize(report):\n' + body))
    assert ManyQueriesRule().check(SourceFile(Path('app.py'), 'def summarize(repo):\n' + body.replace('report', 'repo')))


@pytest.mark.parametrize('name, expected', [
    ('_assignment_hit', False),
    ('_sequential_by_design', False),
    ('_signature_hit', False),
    ('checkout', False),
    ('read_payload', False),
    ('verify_sign', True),
    ('checkPermission', True),
    ('check_order', True),
    ('revalidate', True),
    ('is_token_expired', True),
    ('process_payment', True),
    ('tryparse', True),
    ('safedecode', True),
    ('verify_hmac_signature', True),
    ('webhookSignature', True),
    ('build_signature', False),
])
def test_failure_default_sensitive_name_tokens(name, expected):
    from iron_laws.rules.errors import FailureAsDefaultRule
    src = SourceFile(Path('app.py'), f'def {name}(data):\n    if data.size > 10:\n        return None\n    return data\n')
    assert bool(FailureAsDefaultRule().check(src)) is expected


@pytest.mark.parametrize('annotation, expected', [
    ('Violation | None', False),
    ('Optional[Violation]', False),
    ('dict | None', True),
])
def test_failure_default_optional_finding_result(annotation, expected):
    from iron_laws.rules.errors import FailureAsDefaultRule
    src = SourceFile(Path('app.py'), f'def check_handler(node) -> {annotation}:\n    if node.kind != "call":\n        return None\n    return make(node)\n')
    assert bool(FailureAsDefaultRule().check(src)) is expected


@pytest.mark.parametrize('handler, expected', [
    ('        result.problems.append((1, "bad date"))\n        continue\n', False),
    ('        index.config_errors.append(path)\n        continue\n', False),
    ('        self.result.notes.append(f"cannot read {path}")\n        continue\n', False),
    ('        missing.append(path)\n        continue\n', False),
    ('        return [self.at_line(src, 1, "cannot parse")]\n', False),
    ('        found.append(self.at_line(src, 1, "cannot parse"))\n        continue\n', False),
    ('        cache.append(path)\n        continue\n', True),
    ('        return ["fallback value"]\n', True),
    ('        unused_errors.append(path)\n        continue\n', True),
])
def test_swallowed_exception_accepts_reported_failure(handler, expected):
    from iron_laws.rules.errors import SwallowedExceptionRule
    code = (
        'def collect(self, src, paths, result, index):\n'
        '    missing = []\n'
        '    found = []\n'
        '    for path in paths:\n'
        '        try:\n'
        '            load(path)\n'
        '        except ValueError:\n'
        + handler.replace('        ', '            ', 1).replace('\n        ', '\n            ')
        + '    return missing, found\n'
    )
    assert bool(SwallowedExceptionRule().check(SourceFile(Path('app.py'), code))) is expected


@pytest.mark.parametrize('path, line, expected', [
    ('data.json', '  "src/main/java/org/app/challenge7/MD5.java",', False),
    ('data.json', '  "lib/SHA1.py",', False),
    ('app.py', 'import hashlib\nh = hashlib.md5(data)', True),
    ('App.cs', 'var h = MD5.Create();', True),
    ('app.py', 'import hashlib\nload("lib/MD5.java"); h = hashlib.md5(data)', True),
])
def test_weak_hash_ignores_file_path_strings(path, line, expected):
    from iron_laws.rules.secrets_crypto import InsecureCryptoRule
    assert bool(InsecureCryptoRule().check(SourceFile(Path(path), line + '\n'))) is expected


def test_upload_rule_ignores_marker_strings(tmp_path):
    from tests.helpers import lines_of, scan_files
    files = {'rules.py': 'UPLOAD_MARKERS = ["MultipartFile", "UploadFile"]\nSAVE_MARKERS = [".save(", "transferTo("]\n'}
    assert not lines_of(scan_files(tmp_path, files), 'IL-530')
    assert lines_of(scan_files(tmp_path / 'real', {'a.py': 'def up():\n    f = request.files["f"]\n    f.save("x")\n'}), 'IL-530') == [2]


UPLOAD_CLIENT_TYPE = 'def up():\n    f = request.files["f"]\n    if f.content_type == "image/png" and f.filename.endswith(".png"):\n        f.save("x")\n'


@pytest.mark.parametrize('other, flagged', [
    ({}, True),
    ({'notes.py': '# TODO: Tika로 바꾸기\nDOC = "python-magic, file-type, sniff"\n'}, True),
    ({'tests/test_up.py': 'import magic\n'}, True),
    ({'detect.py': 'import magic\n'}, False),
    ({'detect.js': "const { fileTypeFromBuffer } = require('file-type')\n"}, False),
])
def test_upload_content_check_needs_real_library_use(tmp_path, other, flagged):
    from tests.helpers import lines_of, scan_files
    assert (3 in lines_of(scan_files(tmp_path, {'app.py': UPLOAD_CLIENT_TYPE, **other}), 'IL-530')) is flagged


@pytest.mark.parametrize('url, shown', [
    ('https://openvex.dev/ns/v0.2.0', None),
    ('https://api.internal.example.io/v1', 'https://api.internal.example.io/v1'),
    ('postgres://admin:s3cretpass@db.internal.io/app', ''),  # 같은 줄의 비밀 규칙이 주소 전체를 가린다
    ('redis://cache.internal.io:6379?password=s3cretpass', ''),  # 비밀 질의 값이 있는 주소는 통째로 가린다
])
def test_hardcoded_url_finding_shows_host_without_credentials(tmp_path, url, shown):
    from tests.helpers import scan_files
    found = [v for v in scan_files(tmp_path, {'app.py': f'CONFIG = {{"@context": "{url}"}}\n'}) if v.rule_id == 'AI-101']
    if shown is None:
        assert not found
        return
    assert len(found) == 1
    assert shown in found[0].message
    assert 's3cretpass' not in found[0].message + found[0].snippet + (found[0].snippet_full or '')


def test_public_url_stays_visible_while_other_values_on_the_line_are_masked(tmp_path):
    from tests.helpers import scan_files
    code = 'import requests\nrequests.get("https://api.internal.example.io/v1", headers={"X-Api": "q8Zr2Lm9Xc4Vb7Nt1Kp6"})\n'
    found = [v for v in scan_files(tmp_path, {'app.py': code}) if v.rule_id == 'AI-101']
    assert found and 'https://api.internal.example.io/v1' in found[0].message
    assert 'https://api.internal.example.io/v1' in found[0].snippet
    assert all('q8Zr2Lm9Xc4Vb7Nt1Kp6' not in v.snippet + (v.snippet_full or '') + v.message for v in found)
