"""
오철칙 객체 필드·컬렉션 흐름 시험: 필드와 상수 키 한 단계까지 구분하고, 그 밖은 객체 전체로 본다
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from iron_laws.core.models import Confidence
from tests.helpers import scan_files

PY = "import os\nfrom flask import request\n\n"
JS = "const { exec } = require('child_process');\napp.get('/a', (req, res) => {\n"
JAVA = (
    "import java.util.*;\nimport javax.servlet.http.*;\n\npublic class Run {{\n"
    "    public void handle(HttpServletRequest request) throws Exception {{\n"
    "        Map<String, String> map = new HashMap<>();\n{body}    }}\n}}\n"
)

CASES = [
    ("py-field-tainted", "app.py", PY + "def run(cfg):\n    cfg.name = request.args['n']\n    os.system(cfg.name)\n", "IL-504", True),
    ("py-other-field-clean", "app.py", PY + "def run(cfg):\n    cfg.name = request.args['n']\n    os.system(cfg.mode)\n", "IL-504", False),
    ("py-field-overwritten", "app.py", PY + "def run(cfg):\n    cfg.name = request.args['n']\n    cfg.name = 'ls'\n    os.system(cfg.name)\n", "IL-504", False),
    ("py-whole-object-carries-field", "app.py", PY + "def go(c):\n    os.system(c.name)\n\ndef run(cfg):\n    cfg.name = request.args['n']\n    go(cfg)\n", "IL-504", True),
    ("py-dict-constant-key", "app.py", PY + "def run():\n    d = {}\n    d['cmd'] = request.args['c']\n    os.system(d['cmd'])\n", "IL-504", True),
    ("py-dict-other-key-clean", "app.py", PY + "def run():\n    d = {}\n    d['cmd'] = request.args['c']\n    os.system(d['mode'])\n", "IL-504", False),
    ("py-dict-get-constant-key", "app.py", PY + "def run():\n    d = {}\n    d['cmd'] = request.args['c']\n    os.system(d.get('cmd'))\n", "IL-504", True),
    ("py-dict-variable-key-is-whole", "app.py", PY + "def run(k):\n    d = {}\n    d[k] = request.args['c']\n    os.system(d['mode'])\n", "IL-504", True),
    ("py-reassigned-object-drops-fields", "app.py", PY + "def run(cfg, make):\n    cfg.name = request.args['n']\n    cfg = make()\n    os.system(cfg.name)\n", "IL-504", False),
    ("js-member-assignment-tainted", "app.js", JS + "  const o = {};\n  o.cmd = req.query.c;\n  exec(o.cmd);\n});\n", "IL-504", True),
    ("js-other-member-clean", "app.js", JS + "  const o = {};\n  o.cmd = req.query.c;\n  exec(o.mode);\n});\n", "IL-504", False),
    ("js-bracket-same-as-dot", "app.js", JS + "  const o = {};\n  o['cmd'] = req.query.c;\n  exec(o.cmd);\n});\n", "IL-504", True),
    ("py-int-and-str-keys-distinct", "app.py", PY + "def run():\n    d = {}\n    d[1] = request.args['c']\n    d['1'] = 'ls'\n    os.system(d[1])\n", "IL-504", True),
    ("py-hash-string-key-not-int", "app.py", PY + "def run():\n    d = {}\n    d['#1'] = request.args['c']\n    d[1] = 'ls'\n    os.system(d['#1'])\n", "IL-504", True),
    ("py-int-literal-forms-same-key", "app.py", PY + "def run():\n    d = {}\n    d[0x1] = request.args['c']\n    os.system(d[1])\n", "IL-504", True),
    ("js-numeric-key-same-as-string", "app.js", JS + "  const o = {};\n  o[1] = req.query.c;\n  o['1'] = 'ls';\n  exec(o[1]);\n});\n", "IL-504", False),
    ("java-map-constant-key", "Run.java", JAVA.format(body='        map.put("cmd", request.getParameter("c"));\n        Runtime.getRuntime().exec(map.get("cmd"));\n'), "IL-504", True),
    ("java-map-other-key-clean", "Run.java", JAVA.format(body='        map.put("cmd", request.getParameter("c"));\n        Runtime.getRuntime().exec(map.get("mode"));\n'), "IL-504", False),
]


@pytest.mark.parametrize("name,path,code,rule,expected", CASES, ids=[c[0] for c in CASES])
def test_field_and_key_flow(tmp_path: Path, name, path, code, rule, expected):
    confirmed = [v for v in scan_files(tmp_path, {path: code}) if v.rule_id == rule and v.confidence is Confidence.CONFIRMED]
    assert bool(confirmed) is expected, name
