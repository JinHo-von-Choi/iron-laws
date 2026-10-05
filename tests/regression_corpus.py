"""
오철칙 회귀시험 표본: 재현 가능한 결함 30개(명령 실행·경로 접근·SQL 조립 각 10개)와 올바른 수정, 잘못된 수정
- supported=False는 첫 지원 범위 밖의 모양(클래스 메서드, async, Django·FastAPI, 전역 연결 등)이다. 시험 후보를 만들지 못하는 것이 정답이다.
- 이 표본은 구현자가 직접 만들고 분류한 것이다. 독립 검토자의 분류가 아니므로 효과 주장의 근거가 아니라 회귀 방지에 쓴다.
작성자: 최진호
작성일: 2026-10-04
"""

from dataclasses import dataclass, field


@dataclass
class Case:
    name: str
    family: str
    rule: str
    finding_line: int
    vulnerable: str
    fix: str = ""
    supported: bool = True
    note: str = ""
    benign: str = ""  # 사람이 제안된 정상 대조군을 이 함수에 맞게 고친 값(비우면 제안 그대로)
    extra: dict[str, str] = field(default_factory=dict)


FLASK = "import os\nimport subprocess\nfrom flask import request\n\n"

COMMAND = [
    Case("cmd-flask-os-system", "command", "IL-504", 7,
         FLASK + "def run_tool():\n    d = request.args['d']\n    os.system('ls ' + d)\n",
         FLASK + "def run_tool():\n    d = request.args['d']\n    subprocess.run(['ls', d], check=True)\n"),
    Case("cmd-param-os-system", "command", "IL-504", 4,
         "import os\nimport subprocess\n\ndef run(cmd):\n    os.system(cmd)\n",
         "import os\nimport subprocess\n\ndef run(cmd):\n    subprocess.run(['echo', cmd], check=False)\n"),
    Case("cmd-param-shell-true", "command", "IL-504", 4,
         "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
         "import subprocess\n\ndef run(cmd):\n    subprocess.run(['echo', cmd])\n"),
    Case("cmd-popen-form", "command", "IL-504", 7,
         FLASK + "def run_tool():\n    name = request.form['name']\n    os.popen('echo ' + name)\n",
         FLASK + "def run_tool():\n    name = request.form['name']\n    subprocess.run(['echo', name], capture_output=True)\n"),
    Case("cmd-check-output-host", "command", "IL-504", 4,
         "import subprocess\n\ndef ping(host):\n    return subprocess.check_output(f'ping -c 1 {host}', shell=True)\n",
         "import subprocess\n\ndef ping(host):\n    return subprocess.check_output(['ping', '-c', '1', host])\n"),
    Case("cmd-json-validate", "command", "IL-504", 8,
         FLASK + "def run_tool():\n    target = request.json['target']\n    os.system('nslookup ' + target)\n",
         FLASK + "import re\n\ndef run_tool():\n    target = request.json['target']\n    if not re.fullmatch(r'[A-Za-z0-9.-]+', target):\n        raise ValueError('bad target')\n    subprocess.run(['nslookup', target])\n"),
    Case("cmd-popen-shell", "command", "IL-504", 4,
         "import subprocess\n\ndef start(cmd):\n    subprocess.Popen(cmd, shell=True)\n",
         "import subprocess\n\ndef start(cmd):\n    subprocess.Popen(['echo', cmd])\n"),
    Case("cmd-class-method", "command", "IL-504", 5,
         "import os\n\nclass Tool:\n    def run(self, cmd):\n        os.system(cmd)\n", "", False, "클래스 메서드"),
    Case("cmd-async", "command", "IL-504", 6,
         "import os\nfrom flask import request\n\nasync def run():\n    cmd = request.args['c']\n    os.system(cmd)\n", "", False, "async 함수"),
    Case("cmd-django", "command", "IL-504", 5,
         "import os\nfrom django.http import HttpResponse\n\ndef view(request):\n    os.system(request.GET['c'])\n    return HttpResponse('ok')\n", "", False, "Django 요청 객체"),
]

PATH = [
    Case("path-param-basename", "path", "IL-502", 4,
         "def read(name):\n    return open('/srv/uploads/' + name).read()\n",
         "import os\n\ndef read(name):\n    return open('/srv/uploads/' + os.path.basename(name)).read()\n"),
    Case("path-flask-guard", "path", "IL-502", 8,
         "import os\nfrom flask import request\nBASE = '/srv/files'\n\ndef get():\n    f = request.args['f']\n    return open(os.path.join(BASE, f)).read()\n",
         "import os\nfrom flask import request\nBASE = '/srv/files'\n\ndef get():\n    f = request.args['f']\n    p = os.path.abspath(os.path.join(BASE, f))\n    if not p.startswith(BASE + '/'):\n        raise PermissionError('outside')\n    return open(p).read()\n"),
    Case("path-pathlib-read-text", "path", "IL-502", 6,
         "from pathlib import Path\n\ndef read(name):\n    return (Path('/srv/data') / name).read_text()\n",
         "from pathlib import Path\n\ndef read(name):\n    target = (Path('/srv/data') / name).resolve()\n    if not target.is_relative_to(Path('/srv/data')):\n        raise PermissionError('outside')\n    return target.read_text()\n"),
    Case("path-fstring-basename", "path", "IL-502", 4,
         "def load(name):\n    return open(f'/data/{name}').read()\n",
         "import os\n\ndef load(name):\n    return open(f'/data/{os.path.basename(name)}').read()\n"),
    Case("path-remove", "path", "IL-502", 6,
         "import os\n\ndef delete(name):\n    os.remove(os.path.join('/srv/tmp', name))\n",
         "import os\n\ndef delete(name):\n    os.remove(os.path.join('/srv/tmp', os.path.basename(name)))\n"),
    Case("path-direct-param", "path", "IL-502", 4,
         "def show(path):\n    return open(path).read()\n",
         "import os\n\ndef show(path):\n    full = os.path.abspath(os.path.join('/srv/pub', path))\n    if not full.startswith('/srv/pub/'):\n        raise PermissionError('outside')\n    return open(full).read()\n"),
    Case("path-form-name", "path", "IL-502", 6,
         "from flask import request\n\ndef save():\n    return open('/srv/up/' + request.form['n'], 'w')\n",
         "import os\nfrom flask import request\n\ndef save():\n    return open('/srv/up/' + os.path.basename(request.form['n']), 'w')\n"),
    Case("path-class-method", "path", "IL-502", 4,
         "class Store:\n    def read(self, name):\n        return open('/srv/' + name).read()\n", "", False, "클래스 메서드"),
    Case("path-module-level", "path", "IL-502", 3,
         "import sys\n\ndata = open('/srv/' + sys.argv[1]).read()\n", "", False, "모듈 수준 코드"),
    Case("path-fastapi", "path", "IL-502", 6,
         "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/f')\ndef f(name: str):\n    return open('/srv/' + name).read()\n", "", False, "FastAPI 핸들러"),
]

SQL = [
    Case("sql-cursor-fstring", "sql", "IL-501", 4,
         "def find(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
         "def find(cur, name):\n    cur.execute('SELECT * FROM users WHERE name = ?', (name,))\n"),
    Case("sql-conn-concat", "sql", "IL-501", 4,
         "def find(conn, uid):\n    conn.execute('SELECT * FROM t WHERE id = ' + uid)\n",
         "def find(conn, uid):\n    conn.execute('SELECT * FROM t WHERE id = ?', (uid,))\n"),
    Case("sql-flask-cursor", "sql", "IL-501", 6,
         "from flask import request\n\ndef search(cur):\n    q = request.args['q']\n    cur.execute(\"SELECT * FROM t WHERE title = '\" + q + \"'\")\n",
         "from flask import request\n\ndef search(cur):\n    q = request.args['q']\n    cur.execute('SELECT * FROM t WHERE title = ?', (q,))\n"),
    Case("sql-percent-format", "sql", "IL-501", 4,
         "def find(cursor, name):\n    cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)\n",
         "def find(cursor, name):\n    cursor.execute('SELECT * FROM users WHERE name = %s', (name,))\n"),
    Case("sql-like", "sql", "IL-501", 4,
         "def search(cur, term):\n    cur.execute(\"SELECT * FROM t WHERE title LIKE '%\" + term + \"%'\")\n",
         "def search(cur, term):\n    cur.execute('SELECT * FROM t WHERE title LIKE ?', ('%' + term + '%',))\n"),
    Case("sql-login-form", "sql", "IL-501", 6,
         "from flask import request\n\ndef login(conn):\n    u = request.form['u']\n    conn.execute(f\"SELECT * FROM users WHERE u = '{u}'\")\n",
         "from flask import request\n\ndef login(conn):\n    u = request.form['u']\n    conn.execute('SELECT * FROM users WHERE u = ?', (u,))\n"),
    Case("sql-order-by-allowlist", "sql", "IL-501", 4,
         "def listing(cur, col):\n    cur.execute('SELECT * FROM t ORDER BY ' + col)\n",
         "def listing(cur, col):\n    if col not in ('id', 'name'):\n        raise ValueError('bad column')\n    cur.execute('SELECT * FROM t ORDER BY ' + col)\n", benign="name"),
    Case("sql-global-connection", "sql", "IL-501", 5,
         "import sqlite3\ndb = sqlite3.connect(':memory:')\n\ndef find(name):\n    db.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n", "", False, "전역 연결 객체"),
    Case("sql-sqlalchemy-session", "sql", "IL-501", 5,
         "from sqlalchemy import text\n\ndef find(session, name):\n    session.execute(text(f\"SELECT * FROM t WHERE n = '{name}'\"))\n", "", False, "ORM 세션"),
    Case("sql-class-method", "sql", "IL-501", 4,
         "class Repo:\n    def find(self, cur, name):\n        cur.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n", "", False, "클래스 메서드"),
]

# 호출자 없이 매개변수만 있는 함수는 정적 분석이 외부 입력 도달을 확정하지 못한다(검사 공백). 지적이 나오는 결함 표본이 되도록
# 요청 값을 넘기는 호출자를 함께 둔다. 시험 대상은 여전히 취약한 함수 자체다.
CALLERS = {
    "cmd-param-os-system": "run",
    "cmd-param-shell-true": "run",
    "cmd-popen-shell": "start",
    "path-param-basename": "read",
    "path-pathlib-read-text": "read",
    "path-fstring-basename": "load",
    "path-remove": "delete",
    "path-direct-param": "show",
}


def _with_caller(case: Case) -> Case:
    function = CALLERS.get(case.name)
    if function is None:
        return case
    caller = f"\n\nfrom flask import request\n\ndef view():\n    return {function}(request.args['v'])\n"
    case.vulnerable += caller
    case.fix += caller
    return case


CASES = [_with_caller(c) for c in [*COMMAND, *PATH, *SQL]]
SUPPORTED = [c for c in CASES if c.supported]


def bad_fixes(case: Case) -> dict[str, str]:
    """올바르지 않은 수정 변형: 시험이 구별해야 하는 대상"""
    vulnerable = case.vulnerable
    return {
        "comment-only": vulnerable + "# 보안 검토 완료\n",
        "ignore-comment": "# iron-laws: ignore-file[" + case.rule + "] 내부용이라 괜찮다\n" + vulnerable,
        "noop-refactor": vulnerable + "\n\ndef _unused_helper():\n    return None\n",
        "block-everything": _block_everything(vulnerable),
        "syntax-error": vulnerable + "def broken(:\n",
    }


def _block_everything(code: str) -> str:
    """위험한 호출을 하는 함수 본문을 통째로 막는다. 정상 입력까지 막으므로 정답이 아니다."""
    lines = code.splitlines()
    out: list[str] = []
    for index, line in enumerate(lines):
        out.append(line)
        if line.startswith("def "):
            out.append("    raise PermissionError('blocked')")
            out.extend(f"    # {rest}" for rest in lines[index + 1 :] if rest.strip())
            break
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# 평가용 잘못된 수정(시험 작성에 쓰지 않은 독립 변이): 시험 입력 하나만 막는 수정
# ---------------------------------------------------------------------------

FILTERS = {
    "command": "v.replace(';', '')",  # 세미콜론만 지우는 필터: && · | · $() 로는 뚫린다
    "path": "v.replace('../', '')",  # 상대 경로만 지우는 필터: 절대 경로로는 뚫린다
    "sql": "v.replace(\"'\", \"''\")",  # 따옴표만 겹치는 필터: 따옴표 없는 입력으로는 뚫린다
}


def held_out_fixes(case: Case, function: str, payload: str, source_kind: str) -> dict[str, str]:
    """시험이 쓰는 입력 하나만 막고 같은 결함을 건드리는 다른 입력은 통과시키는 수정. 이 변형은 시험 명세에 적히지 않은 독립 반례로만 가려낼 수 있다."""
    import re

    renamed = re.sub(rf"\bdef {function}\(", f"def _orig_{function}(", case.vulnerable, count=1)
    header = "\n\nimport functools\n"
    fixes: dict[str, str] = {}
    if source_kind == "request":
        guard = (
            f"{header}\n@functools.wraps(_orig_{function})\ndef {function}(*a, **k):\n"
            "    from flask import request as _r\n"
            "    for _part in ('args', 'form', 'values', 'json', 'cookies', 'headers'):\n"
            "        try:\n            _v = str(getattr(_r, _part)['v'])\n        except Exception:\n            continue\n"
            f"        if _v == {payload!r}:\n            raise ValueError('blocked')\n"
            f"    return _orig_{function}(*a, **k)\n"
        )
        fixes["exact-payload-block"] = renamed + guard
        return fixes
    fixes["exact-payload-block"] = renamed + (
        f"{header}\n@functools.wraps(_orig_{function})\ndef {function}(*a, **k):\n"
        f"    if any(str(x) == {payload!r} for x in (*a, *k.values())):\n        raise ValueError('blocked')\n"
        f"    return _orig_{function}(*a, **k)\n"
    )
    fixes["character-filter"] = renamed + (
        f"{header}\n@functools.wraps(_orig_{function})\ndef {function}(*a, **k):\n"
        f"    a = tuple({FILTERS[case.family].replace('v.', 'x.')} if isinstance(x, str) else x for x in a)\n"
        f"    k = {{n: ({FILTERS[case.family]} if isinstance(v, str) else v) for n, v in k.items()}}\n"
        f"    return _orig_{function}(*a, **k)\n"
    )
    return fixes
