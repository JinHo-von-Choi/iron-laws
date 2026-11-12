"""
오철칙 회귀시험 SSRF·XSS 계열 시험: 취약한 원본은 결함이 재현되고, 올바른 수정은 통과하며, 일부 입력만 막는 수정은 통과하지 못한다.
harness는 호스트의 시험용 대역 실행기로 돌린다(요청·응답을 기록만 한다). 표본은 구현자가 직접 만들고 분류했다.
작성자: 최진호
작성일: 2026-11-10
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from iron_laws.verify.engine import resolve_finding
from iron_laws.verify.regression_spec import RegressionSpec, propose_spec
from tests.test_stage4_regression import ORIGINAL_MEMO, check, write_project  # noqa: F401

SSRF_VULNERABLE = "import requests\nfrom flask import request\n\n\ndef fetch():\n    url = request.args['url']\n    return requests.get(url).text\n"
SSRF_FIX = (
    "import ipaddress\nimport socket\nfrom urllib.parse import urlsplit\n\nimport requests\nfrom flask import request\n\n\n"
    "def fetch():\n    url = request.args['url']\n    host = urlsplit(url).hostname or ''\n"
    "    address = ipaddress.ip_address(socket.getaddrinfo(host, None)[0][4][0])\n"
    "    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified:\n"
    "        raise ValueError('blocked')\n    return requests.get(url).text\n"
)
SSRF_ALLOWLIST_FIX = (
    "from urllib.parse import urlsplit\n\nimport requests\nfrom flask import request\n\n\n"
    "def fetch():\n    url = request.args['url']\n    if urlsplit(url).hostname not in ('example.com',):\n        raise ValueError('blocked')\n    return requests.get(url).text\n"
)
SSRF_PARTIAL_FIX = (  # 메타데이터 주소 문자열만 막는다. 다른 내부 주소 표기는 그대로 통과한다
    "import requests\nfrom flask import request\n\n\n"
    "def fetch():\n    url = request.args['url']\n    if '169.254' in url:\n        raise ValueError('blocked')\n    return requests.get(url).text\n"
)
XSS_VULNERABLE = "from flask import request\n\n\ndef hello():\n    name = request.args['name']\n    return '<h1>Hello ' + name + '</h1>'\n"
XSS_FIX = "import html\nfrom flask import request\n\n\ndef hello():\n    name = request.args['name']\n    return '<h1>Hello ' + html.escape(name) + '</h1>'\n"
XSS_PARTIAL_FIX = (  # `<script>`만 지운다. 대소문자·중첩·이벤트 속성은 그대로 통과한다
    "from flask import request\n\n\ndef hello():\n    name = request.args['name']\n    return '<h1>Hello ' + name.replace('<script>', '') + '</h1>'\n"
)
XSS_TEMPLATE_VULNERABLE = "from flask import render_template_string, request\n\n\ndef hello():\n    name = request.args['name']\n    return render_template_string('<h1>Hello ' + name + '</h1>')\n"
XSS_TEMPLATE_FIX = "from flask import render_template_string, request\n\n\ndef hello():\n    name = request.args['name']\n    return render_template_string('<h1>Hello {{ name }}</h1>', name=name)\n"


def proposal(tmp_path: Path, code: str, rule: str, benign: str = "") -> tuple[Path, RegressionSpec]:
    project = write_project(tmp_path / "proj", code)
    report = AuditScanner(project).scan()
    violation = resolve_finding(report, f"{rule}@app.py")
    spec = propose_spec(project, violation).spec
    assert spec is not None and spec.confirmed is False and spec.fake_sink and spec.expect.summary
    if benign:
        spec = spec.model_copy(update={"input": spec.input.model_copy(update={"benign": benign})})
    return project, spec


def test_ssrf_fix_blocking_internal_addresses_passes(tmp_path: Path):
    project, spec = proposal(tmp_path, SSRF_VULNERABLE, "IL-506")
    assert spec.family == "ssrf" and len(spec.input.variants) >= 8
    result = check(tmp_path, project, SSRF_FIX, spec, patch_name="fix.diff")
    assert result.result == "pass", result.reason


def test_ssrf_allowlist_fix_passes_with_an_allowed_benign_url(tmp_path: Path):
    project, spec = proposal(tmp_path, SSRF_VULNERABLE, "IL-506")
    spec = spec.model_copy(update={"expect": spec.expect.model_copy(update={"allowed_hosts": ["example.com"]})})
    result = check(tmp_path, project, SSRF_ALLOWLIST_FIX, spec, patch_name="allow.diff")
    assert result.result == "pass", result.reason


def test_ssrf_fix_that_only_blocks_the_metadata_address_fails(tmp_path: Path):
    project, spec = proposal(tmp_path, SSRF_VULNERABLE, "IL-506")
    result = check(tmp_path, project, SSRF_PARTIAL_FIX, spec, patch_name="partial.diff")
    assert result.result == "fail", result.reason


def test_xss_escaping_fix_passes(tmp_path: Path):
    project, spec = proposal(tmp_path, XSS_VULNERABLE, "IL-505")
    assert spec.family == "xss"
    result = check(tmp_path, project, XSS_FIX, spec, patch_name="fix.diff")
    assert result.result == "pass", result.reason


def test_xss_fix_that_only_removes_script_tags_fails(tmp_path: Path):
    project, spec = proposal(tmp_path, XSS_VULNERABLE, "IL-505")
    result = check(tmp_path, project, XSS_PARTIAL_FIX, spec, patch_name="partial.diff")
    assert result.result == "fail", result.reason


def test_xss_template_source_built_from_input_is_a_defect_and_context_variable_is_the_fix(tmp_path: Path):
    project, spec = proposal(tmp_path, XSS_TEMPLATE_VULNERABLE, "IL-505")
    result = check(tmp_path, project, XSS_TEMPLATE_FIX, spec, patch_name="template.diff")
    assert result.result == "pass", result.reason


@pytest.mark.parametrize("code,rule", [(SSRF_VULNERABLE, "IL-506"), (XSS_VULNERABLE, "IL-505")])
def test_a_fix_that_breaks_the_benign_input_is_not_evidence(tmp_path: Path, code: str, rule: str):
    project, spec = proposal(tmp_path, code, rule)
    broken = "def " + ("fetch" if rule == "IL-506" else "hello") + "():\n    raise ValueError('always blocked')\n"
    result = check(tmp_path, project, broken, spec, patch_name="broken.diff")
    assert result.result != "pass"
