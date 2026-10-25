"""자체 감사에서 쓰는 Python 규칙의 양성·음성 짝. 지원 목록 생성에도 사용한다."""

import pytest

from tests.helpers import lines_of, scan_files

CASES = [
    ('cors-specific-python', 'AI-105', {'a.py': 'app.add_middleware(CORSMiddleware, allow_origins=["https://example.com"])\n'}, {}),
    ('settings-specific-python', 'AI-106', {'a.py': 'ALLOWED_HOSTS = ["app.example.com"]\n'}, {}),
    ('null-match-checked', 'IL-519', {'a.py': 'import re\ndef parse(text):\n    match = re.match("[0-9]+", text)\n    if match is None:\n        raise ValueError("not numeric")\n    return match.group(0)\n'}, {}),
    ('validation-message-both-boundaries', 'IL-531', {'a.py': 'def validate(value):\n    if value < 3 or value > 9:\n        raise ValueError("must be between 3 and 9")\n'}, {}),
    ('validation-message-one-boundary', 'IL-531', {'a.py': 'def validate(value):\n    if value < 3 or value > 9:\n        raise ValueError("must be at least 3")\n'}, {'a.py': [2]}),
    ('typer-option-signature', 'ARC-201', {'a.py': 'import typer\napp=typer.Typer()\n@app.command()\ndef entry(a,b,c,d,e,f,g,h,i,j):\n    return a\n'}, {}),
    ('db-loop', 'ARC-212', {'a.py': 'def load(db, rows):\n    for row in rows:\n        db.find(row)\n'}, {'a.py': [3]}),
    ('regex-loop', 'ARC-212', {'a.py': 'import re\ndb=re.compile("x")\nfor row in rows:\n    db.finditer(row)\n'}, {}),
    ('minimum-version-python', 'AI-121', {'README.md': 'Python 3.12+\n', '.python-version': '3.13\n'}, {}),
    ('fixed-version-python', 'AI-121', {'README.md': 'Python 3.12\n', '.python-version': '3.13\n'}, {'.python-version': [1]}),
    ('mkdir-external', 'IL-502', {'a.py': 'from pathlib import Path\nfrom flask import request\ndef create():\n    target=Path("/srv") / request.args["p"]\n    target.mkdir()\n'}, {'a.py': [5]}),
    ('mkdir-closed', 'IL-502', {'a.py': 'from pathlib import Path\ndef create():\n    Path("/srv/fixed").mkdir()\n'}, {}),
    ('ldap-external', 'IL-508', {'a.py': 'from flask import request\ndef search(conn):\n    conn.search("(uid=" + request.args["q"])\n'}, {'a.py': [3]}),
    ('report-lookup-loop', 'ARC-212', {'a.py': 'def load(report, rows):\n    for row in rows:\n        report.get(row)\n'}, {}),
    ('weak-hash-path-string', 'IL-102', {'a.py': 'FILES = ["lessons/challenge7/MD5.java"]\n'}, {}),
    ('weak-hash-call', 'IL-102', {'a.py': 'import hashlib\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n'}, {'a.py': [3]}),
    ('regex-ldap-shaped', 'IL-508', {'a.py': 'import re as rx\nfrom flask import request\ndef search():\n    rx.search("(uid=" + request.args["q"])\n'}, {}),
]


@pytest.mark.parametrize('name,rule,files,expected', CASES, ids=[c[0] for c in CASES])
def test_support_cases(tmp_path, name, rule, files, expected):
    found = scan_files(tmp_path, files)
    actual = {path: lines_of(found, rule, path) for path in files if lines_of(found, rule, path)}
    assert actual == expected
