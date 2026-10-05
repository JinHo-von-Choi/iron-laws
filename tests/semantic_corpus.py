"""
오철칙 v1.3 의미 변형 사례집(개발용): 정상 코드와 위험이 늘어난 코드를 짝으로 두고, 의미를 보존하는 변형 연산을 적용해
판정이 뒤집히지 않는지 본다. 이 파일의 사례는 개발에 쓴다. 최종 평가용은 `semantic_holdout.py`에 따로 둔다(유형·스타일 단위 분리).

- 기본 사례 한 쌍(benign, risky)마다 변형 연산 6종을 양쪽에 적용한다. 변형은 의미를 보존하므로 기대 판정은 원본과 같다.
- 변형 수백 건을 독립 결함 수백 개로 세지 않는다. 보고는 항상 원본 수와 변형 수를 나눠 쓴다.
- 표본의 정답은 구현자가 직접 정했다. 독립 검토자의 분류도, LLM 자기평가도 아니다.
작성자: 최진호
작성일: 2026-10-05
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

# 변형 연산이 바꾸는 이름 자리표시자: 변수 @V@, 함수 @FN@, 상수 @C@
RENAMES = {"@V@": "value_in", "@FN@": "handler_two", "@C@": "ALLOWED_SET"}
DEFAULT_NAMES = {"@V@": "cmd", "@FN@": "handler", "@C@": "ALLOWED"}


@dataclass(frozen=True)
class ScanCase:
    id: str
    group: str  # 판정 대상(허용 목록·경로 범위·보간·객체 상태 등)
    style: str  # 사례를 쓴 프로젝트 스타일(flask·express·plain-java…). 평가용 분리의 단위
    ext: str
    rule: str
    benign: str
    risky: str
    files: dict[str, str] = field(default_factory=dict)  # 같은 사례의 추가 파일(도우미 모듈 등). 양쪽에 공통


@dataclass(frozen=True)
class ApprovalCase:
    id: str
    group: str
    style: str
    benign_change: dict  # 승인을 유지해야 하는 변경(test_stage5의 apply_variant 형식)
    risky_change: dict  # 승인을 유지하면 안 되는 변경
    base: dict | None = None  # None이면 BASE
    finding: str | None = None
    benign_expires: int | None = None  # 승인 유효기간(오늘부터 며칠 뒤). None이면 기한 없음
    risky_expires: int | None = None
    risky_expect: str = "not_valid"  # not_valid: 승인이 유효로 남으면 안 된다 / clone_not_approved: 원본 승인이 새 지적(복제본)에 번지면 안 된다


@dataclass(frozen=True)
class OutputCase:
    id: str
    group: str
    style: str
    kind: str  # suppression / secret
    benign: dict  # 기대: 억제가 인정되거나 비밀이 가려진다(정상 동작)
    risky: dict  # 기대: 억제가 인정되지 않거나 모든 출력에서 비밀 조각이 없다


# ---------------------------------------------------------------------------
# 의미 보존 변형 연산 6종
# ---------------------------------------------------------------------------


def _fill(code: str, names: dict[str, str]) -> str:
    for token, name in names.items():
        code = code.replace(token, name)
    return code


def op_identity(code: str, ext: str) -> str:
    return code


def op_rename(code: str, ext: str) -> str:
    return code  # 이름 바꾸기는 render에서 names를 바꿔 적용한다


def _comment(ext: str, text: str) -> str:
    return f"# {text}" if ext == ".py" else f"// {text}"


def op_comments(code: str, ext: str) -> str:
    """최상위 함수·클래스 줄 앞과 파일 맨 앞에 주석을 넣는다. PHP 파일은 `<?php` 다음 줄부터 넣는다."""
    lines = code.split("\n")
    out: list[str] = []
    top_level = re.compile(r"^(def |async def |class |function |public |static |void |const \w+ = \(|exports\.)")
    header_done = False
    for line in lines:
        if not header_done:
            out.append(line)
            if ext != ".php" or line.startswith("<?php"):
                out.append(_comment(ext, "검토용 설명 주석"))
                header_done = True
            continue
        if top_level.match(line):
            out.append(_comment(ext, "함수 설명"))
        out.append(line)
    return "\n".join(out)


def op_blank_lines(code: str, ext: str) -> str:
    """최상위 줄 사이에 빈 줄을 늘린다(들여쓴 줄 사이는 건드리지 않는다)."""
    out: list[str] = []
    for line in code.split("\n"):
        out.append(line)
        if line and not line[0].isspace() and not line.endswith(("{", ":", "(", "[", ",")):
            out.append("")
    return "\n".join(out)


UNRELATED = {
    ".py": "def unrelated_helper(a, b):\n    total = a + b\n    return total * 2\n",
    ".js": "function unrelatedHelper(a, b) {\n  const total = a + b;\n  return total * 2;\n}\n",
    ".ts": "function unrelatedHelper(a: number, b: number): number {\n  const total = a + b;\n  return total * 2;\n}\n",
    ".php": "function unrelated_helper($a, $b) {\n  $total = $a + $b;\n  return $total * 2;\n}\n",
    ".java": "",
}


def op_unrelated_after(code: str, ext: str) -> str:
    extra = UNRELATED.get(ext, "")
    if ext == ".java" or not extra:
        return code.rstrip("\n") + "\n// 관련 없는 줄\n" if ext == ".java" else code
    return code.rstrip("\n") + "\n\n" + extra


def op_unrelated_first(code: str, ext: str) -> str:
    extra = UNRELATED.get(ext, "")
    if not extra:
        return code
    lines = code.split("\n")
    # import·require·use·<?php 묶음 뒤에 넣는다
    index = 0
    for i, line in enumerate(lines):
        if re.match(r"^(import |from |const .* = require|use |<\?php|package )", line):
            index = i + 1
    return "\n".join([*lines[:index], "", *extra.split("\n"), *lines[index:]])


_SIMPLE_DQ = re.compile(r'"([^"\\\n{}$%`]*)"')


def op_quote_style(code: str, ext: str) -> str:
    """따옴표만 없는 단순한 큰따옴표 문자열을 작은따옴표로 바꾼다(f-string·템플릿·보간 문자열은 건드리지 않는다)."""
    if ext == ".java":
        return code
    out: list[str] = []
    for line in code.split("\n"):
        if re.search(r"\bf\"|\bf'|`|<<<|\$\w", line) and ext in (".php", ".py"):
            out.append(line)
            continue
        out.append(_SIMPLE_DQ.sub(lambda m: "'" + m.group(1) + "'", line) if "'" not in line else line)
    return "\n".join(out)


OPERATORS: dict[str, Callable[[str, str], str]] = {
    "rename": op_rename,
    "comments": op_comments,
    "blank_lines": op_blank_lines,
    "unrelated_after": op_unrelated_after,
    "unrelated_first": op_unrelated_first,
    "quote_style": op_quote_style,
}


def render(code: str, ext: str, operator: str | None = None) -> str:
    names = RENAMES if operator == "rename" else DEFAULT_NAMES
    text = _fill(code, names)
    if operator and operator != "rename":
        text = OPERATORS[operator](text, ext)
    return text


# ---------------------------------------------------------------------------
# 개발용 기본 사례
# ---------------------------------------------------------------------------

PY_HEAD = "import os\nfrom flask import request\n@C@ = ('a', 'b')\n\n"
PY_PATH_HEAD = "import os\nfrom flask import request\n\n"
SQL_HEAD = "from flask import request\n\n"


def _py(body: str, head: str = PY_HEAD) -> str:
    return head + body


DEV_SCAN: list[ScanCase] = [
    # ---- 허용 목록 검사 (flask) ----
    ScanCase(
        "py-cmd-allow-reassign", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    os.system('run ' + @V@)\n"),
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    @V@ = request.args['d']\n    os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-conditional", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@(flag):\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    os.system('run ' + @V@)\n"),
        _py("def @FN@(flag):\n    @V@ = request.args['c']\n    if flag:\n        if @V@ not in @C@:\n            return\n    os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-string-return", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        raise ValueError('bad')\n    os.system('run ' + @V@)\n"),
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        print('return')\n    os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-nested-return", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@(flag):\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    os.system('run ' + @V@)\n"),
        _py("def @FN@(flag):\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        if flag:\n            return\n    os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-passbranch", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ in @C@:\n        os.system('run ' + @V@)\n"),
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ in @C@:\n        @V@ = request.args['d']\n        os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-augmented", "allowlist", "flask", ".py", "IL-504",
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    os.system('run ' + @V@)\n"),
        _py("def @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        return\n    @V@ += request.args['d']\n    os.system('run ' + @V@)\n"),
    ),
    ScanCase(
        "py-cmd-allow-abort", "allowlist", "flask", ".py", "IL-504",
        "import os\nfrom flask import request, abort\n@C@ = ('a', 'b')\n\ndef @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        abort(400)\n    os.system('run ' + @V@)\n",
        "import os\nfrom flask import request, abort\n@C@ = ('a', 'b')\n\ndef @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        print('unexpected value')\n    os.system('run ' + @V@)\n",
    ),
    ScanCase(
        "py-cmd-allow-exit", "allowlist", "flask", ".py", "IL-504",
        "import os, sys\nfrom flask import request\n@C@ = ('a', 'b')\n\ndef @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        sys.exit(1)\n    os.system('run ' + @V@)\n",
        "import os, sys\nfrom flask import request\n@C@ = ('a', 'b')\n\ndef @FN@():\n    @V@ = request.args['c']\n    if @V@ not in @C@:\n        pass\n    os.system('run ' + @V@)\n",
    ),
    # ---- 경로 범위 검사 (flask) ----
    ScanCase(
        "py-path-confined-reassign", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@():\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if not full.startswith(base):\n        return\n    return open(full).read()\n", PY_PATH_HEAD),
        _py("def @FN@():\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if not full.startswith(base):\n        return\n    full = os.path.join(base, request.args['q'])\n    return open(full).read()\n", PY_PATH_HEAD),
    ),
    ScanCase(
        "py-path-confined-conditional", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@(flag):\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if not full.startswith(base):\n        return\n    return open(full).read()\n", PY_PATH_HEAD),
        _py("def @FN@(flag):\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if flag:\n        if not full.startswith(base):\n            return\n    return open(full).read()\n", PY_PATH_HEAD),
    ),
    ScanCase(
        "py-path-confined-string-return", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@():\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if not full.startswith(base):\n        raise PermissionError('no')\n    return open(full).read()\n", PY_PATH_HEAD),
        _py("def @FN@():\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, request.args['p']))\n    if not full.startswith(base):\n        print('return')\n    return open(full).read()\n", PY_PATH_HEAD),
    ),
    ScanCase(
        "py-path-checked-other-value", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@():\n    p = request.args['p']\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, p))\n    if not full.startswith(base):\n        return\n    return open(full).read()\n", PY_PATH_HEAD),
        _py("def @FN@():\n    p = request.args['p']\n    base = '/srv'\n    full = os.path.realpath(os.path.join(base, p))\n    if not full.startswith(base):\n        return\n    p = request.args['q']\n    return open(os.path.join(base, p)).read()\n", PY_PATH_HEAD),
    ),
    ScanCase(
        "py-path-basename", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@():\n    return open('/srv/' + os.path.basename(request.args['p'])).read()\n", PY_PATH_HEAD),
        _py("def @FN@():\n    return open('/srv/' + request.args['p']).read()\n", PY_PATH_HEAD),
    ),
    ScanCase(
        "py-path-constant", "path-guard", "flask", ".py", "IL-502",
        _py("def @FN@():\n    return open('/srv/fixed.txt').read()\n", PY_PATH_HEAD),
        _py("def @FN@():\n    return open('/srv/' + request.args['p']).read()\n", PY_PATH_HEAD),
    ),
    # ---- SQL·명령 (flask) ----
    ScanCase(
        "py-sql-bound", "sql", "flask", ".py", "IL-501",
        _py("def @FN@(cur):\n    cur.execute('SELECT * FROM t WHERE id = %s', (request.args['i'],))\n", SQL_HEAD),
        _py("def @FN@(cur):\n    cur.execute('SELECT * FROM t WHERE id = ' + request.args['i'])\n", SQL_HEAD),
    ),
    ScanCase(
        "py-sql-int-cast", "sql", "flask", ".py", "IL-501",
        _py("def @FN@(cur):\n    n = int(request.args['i'])\n    cur.execute('SELECT * FROM t WHERE id = ' + str(n))\n", SQL_HEAD),
        _py("def @FN@(cur):\n    n = request.args['i']\n    cur.execute('SELECT * FROM t WHERE id = ' + n)\n", SQL_HEAD),
    ),
    ScanCase(
        "py-cmd-list-noshell", "command", "flask", ".py", "IL-504",
        "import subprocess\nfrom flask import request\n\ndef @FN@():\n    subprocess.run(['ls', request.args['d']])\n",
        "import subprocess\nfrom flask import request\n\ndef @FN@():\n    subprocess.run('ls ' + request.args['d'], shell=True)\n",
    ),
    ScanCase(
        "py-cmd-shlex", "command", "flask", ".py", "IL-504",
        "import os, shlex\nfrom flask import request\n\ndef @FN@():\n    os.system('ls ' + shlex.quote(request.args['d']))\n",
        "import os\nfrom flask import request\n\ndef @FN@():\n    os.system('ls ' + request.args['d'])\n",
    ),
    ScanCase(
        "py-cmd-constant", "command", "flask", ".py", "IL-504",
        "import os\nfrom flask import request\n\ndef @FN@():\n    os.system('uptime')\n",
        "import os\nfrom flask import request\n\ndef @FN@():\n    os.system('uptime ' + request.args['d'])\n",
    ),
    # ---- 도우미 함수 (plain) ----
    ScanCase(
        "py-helper-validates", "helper", "plain", ".py", "IL-504",
        "import os\nfrom flask import request\n\ndef clean(x):\n    return str(int(x))\n\ndef @FN@():\n    os.system('ls ' + clean(request.args['d']))\n",
        "import os\nfrom flask import request\n\ndef clean(x):\n    return x\n\ndef @FN@():\n    os.system('ls ' + clean(request.args['d']))\n",
    ),
    ScanCase(
        "py-helper-two-hops", "helper", "plain", ".py", "IL-504",
        "import os\nfrom flask import request\n\ndef run(c):\n    os.system('ls ' + c)\n\ndef @FN@():\n    run('fixed')\n",
        "import os\nfrom flask import request\n\ndef run(c):\n    os.system('ls ' + c)\n\ndef @FN@():\n    run(request.args['d'])\n",
    ),
    # ---- 보간 (express) ----
    ScanCase(
        "js-template-command", "interpolation", "express", ".js", "IL-504",
        "const { exec } = require('child_process');\nfunction @FN@(req, res) {\n  exec(`ls ${'-l'}`);\n}\n",
        "const { exec } = require('child_process');\nfunction @FN@(req, res) {\n  exec(`ls ${req.query.d}`);\n}\n",
    ),
    ScanCase(
        "js-template-path", "interpolation", "express", ".js", "IL-502",
        "const fs = require('fs');\nfunction @FN@(req) {\n  return fs.readFileSync(`/srv/fixed.txt`);\n}\n",
        "const fs = require('fs');\nfunction @FN@(req) {\n  return fs.readFileSync(`/srv/${req.query.f}`);\n}\n",
    ),
    ScanCase(
        "js-template-sql", "interpolation", "express", ".js", "IL-501",
        "function @FN@(req, db) {\n  db.query('SELECT * FROM t WHERE id = ?', [req.params.id]);\n}\n",
        "function @FN@(req, db) {\n  db.query(`SELECT * FROM t WHERE id = ${req.params.id}`);\n}\n",
    ),
    ScanCase(
        "js-concat-command", "interpolation", "express", ".js", "IL-504",
        "const { execFile } = require('child_process');\nfunction @FN@(req, res) {\n  execFile('ls', [req.query.d]);\n}\n",
        "const { exec } = require('child_process');\nfunction @FN@(req, res) {\n  exec('ls ' + req.query.d);\n}\n",
    ),
    ScanCase(
        "js-path-basename", "path-guard", "express", ".js", "IL-502",
        "const fs = require('fs');\nconst path = require('path');\nfunction @FN@(req) {\n  return fs.readFileSync('/srv/' + path.basename(req.query.f));\n}\n",
        "const fs = require('fs');\nfunction @FN@(req) {\n  return fs.readFileSync('/srv/' + req.query.f);\n}\n",
    ),
    ScanCase(
        "ts-template-command", "interpolation", "express", ".ts", "IL-504",
        "import { exec } from 'child_process';\nexport function @FN@(req: any) {\n  exec(`uptime ${'-p'}`);\n}\n",
        "import { exec } from 'child_process';\nexport function @FN@(req: any) {\n  exec(`uptime ${req.body.name}`);\n}\n",
    ),
    # ---- XXE (plain-java) ----
    ScanCase(
        "java-xxe-safe-vs-reset", "xml-state", "plain-java", ".java", "IL-509",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a, java.io.InputStream b) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(a);\n    f.newDocumentBuilder().parse(b);\n  }\n}\n",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a, java.io.InputStream b) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(a);\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", false);\n    f.newDocumentBuilder().parse(b);\n  }\n}\n",
    ),
    ScanCase(
        "java-xxe-second-factory", "xml-state", "plain-java", ".java", "IL-509",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a, java.io.InputStream b) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(a);\n    f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(b);\n  }\n}\n",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a, java.io.InputStream b) throws Exception {\n    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newDocumentBuilder().parse(a);\n    f = DocumentBuilderFactory.newInstance();\n    f.newDocumentBuilder().parse(b);\n  }\n}\n",
    ),
    ScanCase(
        "java-xxe-sax", "xml-state", "plain-java", ".java", "IL-509",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a) throws Exception {\n    SAXParserFactory f = SAXParserFactory.newInstance();\n    f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n    f.newSAXParser().parse(a, new org.xml.sax.helpers.DefaultHandler());\n  }\n}\n",
        "import javax.xml.parsers.*;\npublic class A {\n  void @FN@(java.io.InputStream a) throws Exception {\n    SAXParserFactory f = SAXParserFactory.newInstance();\n    f.newSAXParser().parse(a, new org.xml.sax.helpers.DefaultHandler());\n  }\n}\n",
    ),
]


# 승인: 같은 변경이라도 승인한 전제를 건드리지 않으면 유지, 건드리면 재검토
DEV_APPROVAL: list[ApprovalCase] = [
    ApprovalCase(
        "approval-caller-same-name",
        "callers",
        "flask",
        benign_change={"extra.py": "def unrelated():\n    return 1\n"},
        risky_change={"routes_b.py": "from app import run_tool\n\ndef handle():\n    return run_tool()\n"},
        base={
            "app.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n',
            "routes_a.py": "from app import run_tool\n\ndef handle():\n    return run_tool()\n",
        },
    ),
    ApprovalCase(
        "approval-callee-same-name",
        "callees",
        "flask",
        benign_change={"helpers_c.py": "def clean(x):\n    return x\n"},
        risky_change={"app.py": 'import os\nfrom flask import request\nfrom helpers_b import clean\n\ndef run_tool():\n    d = clean(request.args["d"])\n    os.system("ls " + d)\n'},
        base={
            "app.py": 'import os\nfrom flask import request\nfrom helpers_a import clean\n\ndef run_tool():\n    d = clean(request.args["d"])\n    os.system("ls " + d)\n',
            "helpers_a.py": "def clean(x):\n    if not x.isalnum():\n        raise ValueError('bad')\n    return x\n",
            "helpers_b.py": "def clean(x):\n    return x\n",
        },
    ),
    ApprovalCase(
        "approval-file-move-vs-clone",
        "identity",
        "flask",
        benign_change={"__rename__": ("app.py", "pkg/app.py")},
        risky_change={"clone.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'},
        risky_expect="clone_not_approved",
    ),
    ApprovalCase(
        "approval-sanitizer-removed",
        "sanitizer",
        "flask",
        benign_change={"app.py": "# 주석\nimport os\nfrom flask import request\nfrom helpers import clean\n\ndef run_tool():\n    d = clean(request.args['d'])\n    os.system('ls ' + d)\n"},
        risky_change={"app.py": "import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    os.system('ls ' + d)\n"},
        base={
            "app.py": "import os\nfrom flask import request\nfrom helpers import clean\n\ndef run_tool():\n    d = clean(request.args['d'])\n    os.system('ls ' + d)\n",
            "helpers.py": "def clean(x):\n    if not x.isalnum():\n        raise ValueError('bad')\n    return x\n",
        },
        finding="IL-504@app.py",
    ),
    ApprovalCase(
        "approval-literal-scope",
        "literals",
        "flask",
        benign_change={"app.py": "# 설명 주석\nimport os\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    os.system('ls ' + d)\n"},
        risky_change={"app.py": "import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    os.system('ls -R / ' + d)\n"},
        base={"app.py": "import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args['d']\n    os.system('ls ' + d)\n"},
    ),
    # 평가용 실패에서 옮겨 온 사례: 독스트링만 바뀐 변경은 승인을 유지하고, 라우트 노출은 재검토한다(첫 평가용 실행에서 독스트링 변경이 재검토로 잡혀 엔진을 고침)
    ApprovalCase(
        "approval-route-exposed-docstring",
        "exposure",
        "flask",
        benign_change={"app.py": 'import os\nfrom flask import request\n\ndef run_tool():\n    """도구를 실행한다."""\n    d = request.args["d"]\n    os.system("ls " + d)\n'},
        risky_change={"app.py": 'import os\nfrom flask import request\nfrom web import route\n\n@route("/public")\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'},
    ),
]

SECRET_TOKEN = "Zq" + "m7Kp2Xw9Rt4Vb6Nc8Hd3Jf5Lg1Sa0Eu" + "ABCDEFGH"

DEV_OUTPUT: list[OutputCase] = [
    OutputCase(
        "suppression-python-string",
        "suppression",
        "flask",
        "suppression",
        benign={"file": "a.py", "text": "import os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])  # iron-laws: ignore[IL-504] 내부 관리 도구라서 허용한다\n", "rule": "IL-504", "suppressed": True},
        risky={"file": "a.py", "text": "import os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])\n    note = 'iron-laws: ignore[IL-504] 문자열 속의 문구는 억제가 아니다'\n    return note\n", "rule": "IL-504", "suppressed": False},
    ),
    OutputCase(
        "suppression-yaml-quoted",
        "suppression",
        "yaml",
        "suppression",
        benign={"file": "a.yml", "text": "# iron-laws: ignore-file[IL-101] 시험용 무효 값이다\nnote: ok\npassword: \"supersecretvalue123\"\n", "rule": "IL-101", "suppressed": True},
        risky={"file": "a.yml", "text": "note: \"first\n# iron-laws: ignore-file[IL-101] 문자열 안의 문구는 억제가 아니다\n end\"\npassword: \"supersecretvalue123\"\n", "rule": "IL-101", "suppressed": False},
    ),
    OutputCase(
        "suppression-shell-quoted",
        "suppression",
        "shell",
        "suppression",
        benign={"file": "a.sh", "text": "# iron-laws: ignore-file[IL-101] 시험용 무효 값이다\nPASSWORD='supersecretvalue123'\n", "rule": "IL-101", "suppressed": True},
        risky={"file": "a.sh", "text": "NOTE=$'first\n# iron-laws: ignore-file[IL-101] 문자열 안의 문구는 억제가 아니다 \\' end'\nPASSWORD='supersecretvalue123'\n", "rule": "IL-101", "suppressed": False},
    ),
    OutputCase(
        "secret-long-line-with-other-rule",
        "masking",
        "flask",
        "secret",
        benign={"file": "a.py", "text": f"import os\nfrom flask import request\n\ndef f():\n    token = '{SECRET_TOKEN}'\n    return token\n", "secrets": [SECRET_TOKEN]},
        risky={"file": "a.py", "text": "import os\nfrom flask import request\n\ndef f():\n    PAD = '" + "x" * 280 + f"'; token = '{SECRET_TOKEN}'; os.system('ls ' + request.args['d'])\n", "secrets": [SECRET_TOKEN]},
    ),
]


def all_dev() -> tuple[list[ScanCase], list[ApprovalCase], list[OutputCase]]:
    return DEV_SCAN, DEV_APPROVAL, DEV_OUTPUT
