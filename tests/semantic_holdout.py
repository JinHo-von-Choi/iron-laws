"""
오철칙 v1.3 의미 변형 사례집(평가용 holdout): 개발용(`semantic_corpus.py`)과 스타일·유형이 다른 사례다.
- 개발용 사례를 보며 고친 코드가 이 사례에서도 통하는지 본다. 이 사례를 보고 엔진을 조정하지 않는다.
- 평가용 사례가 실패해 엔진을 고치면, 그 사례는 개발용으로 옮기고 같은 유형의 새 평가용 사례로 바꾼다(`docs/ACCURACY.md`의 이력 참고).
- 표본의 정답은 구현자가 직접 정했다. 독립 검토자의 분류가 아니다.
작성자: 최진호
작성일: 2026-10-05
"""

from tests.semantic_corpus import ApprovalCase, OutputCase, ScanCase

DJ_HEAD = "import os\nfrom pathlib import Path\n\n"
SECRET_JS = "Kd" + "p4Qw8Zx2Vn6Mb0Lc3Hj7Gf1Sa9Ur5Te" + "WXYZ1234"

HOLDOUT_SCAN: list[ScanCase] = [
    # ---- Django 스타일 ----
    ScanCase(
        "dj-cmd-allow-reassign",
        "allowlist",
        "django",
        ".py",
        "IL-504",
        "import os\n@C@ = ('a', 'b')\n\ndef @FN@(request):\n    @V@ = request.GET['c']\n    if @V@ not in @C@:\n        raise ValueError('no')\n    os.system('run ' + @V@)\n",
        "import os\n@C@ = ('a', 'b')\n\ndef @FN@(request):\n    @V@ = request.GET['c']\n    if @V@ not in @C@:\n        raise ValueError('no')\n    @V@ = request.GET['d']\n    os.system('run ' + @V@)\n",
    ),
    ScanCase(
        "dj-path-resolve-confined",
        "path-guard",
        "django",
        ".py",
        "IL-502",
        DJ_HEAD
        + "BASE = Path('/srv')\n\ndef @FN@(request):\n    target = (BASE / request.GET['p']).resolve()\n    if not target.is_relative_to(BASE):\n        raise PermissionError('no')\n    return target.read_text()\n",
        DJ_HEAD
        + "BASE = Path('/srv')\n\ndef @FN@(request):\n    target = (BASE / request.GET['p']).resolve()\n    return target.read_text()\n",
    ),
    ScanCase(
        "dj-sql-raw",
        "sql",
        "django",
        ".py",
        "IL-501",
        "def @FN@(request, User):\n    return User.objects.raw('SELECT * FROM t WHERE id = %s', [request.GET['i']])\n",
        "def @FN@(request, User):\n    return User.objects.raw('SELECT * FROM t WHERE id = ' + request.GET['i'])\n",
    ),
    ScanCase(
        "dj-cmd-popen",
        "command",
        "django",
        ".py",
        "IL-504",
        "import subprocess\n\ndef @FN@(request):\n    return subprocess.Popen(['ls', request.GET['d']])\n",
        "import subprocess\n\ndef @FN@(request):\n    return subprocess.Popen('ls ' + request.GET['d'], shell=True)\n",
    ),
    ScanCase(
        "dj-path-basename",
        "path-guard",
        "django",
        ".py",
        "IL-502",
        "import os\n\ndef @FN@(request):\n    return open('/srv/' + os.path.basename(request.POST['f'])).read()\n",
        "def @FN@(request):\n    return open('/srv/' + request.POST['f']).read()\n",
    ),
    # ---- 순수 PHP ----
    ScanCase(
        "php-system-escaped",
        "interpolation",
        "php-raw",
        ".php",
        "IL-504",
        '<?php\nfunction @FN@() {\n  system("ls " . escapeshellarg($_GET["d"]));\n}\n',
        '<?php\nfunction @FN@() {\n  system("ls " . $_GET["d"]);\n}\n',
    ),
    ScanCase(
        "php-readfile-basename",
        "path-guard",
        "php-raw",
        ".php",
        "IL-502",
        '<?php\nfunction @FN@() {\n  readfile("/srv/" . basename($_GET["f"]));\n}\n',
        '<?php\nfunction @FN@() {\n  readfile("/srv/" . $_GET["f"]);\n}\n',
    ),
    ScanCase(
        "php-sql-prepared",
        "sql",
        "php-raw",
        ".php",
        "IL-501",
        '<?php\nfunction @FN@($db) {\n  $stmt = $db->prepare("SELECT * FROM t WHERE id = ?");\n  $stmt->execute([$_GET["id"]]);\n}\n',
        '<?php\nfunction @FN@($db) {\n  $db->query("SELECT * FROM t WHERE id = " . $_GET["id"]);\n}\n',
    ),
    ScanCase(
        "php-heredoc",
        "interpolation",
        "php-raw",
        ".php",
        "IL-504",
        "<?php\nfunction @FN@() {\n  $c = <<<EOT\nls -l\nEOT;\n  system($c);\n}\n",
        '<?php\nfunction @FN@() {\n  $c = <<<EOT\nls {$_GET["d"]}\nEOT;\n  system($c);\n}\n',
    ),
    # ---- Spring(Java) ----
    ScanCase(
        "java-spring-exec",
        "command",
        "spring",
        ".java",
        "IL-504",
        'import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n  @GetMapping("/x")\n  public String @FN@(@RequestParam String d) throws Exception {\n    Runtime.getRuntime().exec(new String[]{"ls", d});\n    return "ok";\n  }\n}\n',
        'import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n  @GetMapping("/x")\n  public String @FN@(@RequestParam String d) throws Exception {\n    Runtime.getRuntime().exec("ls " + d);\n    return "ok";\n  }\n}\n',
    ),
    ScanCase(
        "java-spring-file",
        "path-guard",
        "spring",
        ".java",
        "IL-502",
        'import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n  @GetMapping("/x")\n  public String @FN@(@RequestParam String name) throws Exception {\n    java.io.File f = new java.io.File("/srv", "fixed.txt");\n    return f.getName();\n  }\n}\n',
        'import org.springframework.web.bind.annotation.*;\n@RestController\npublic class A {\n  @GetMapping("/x")\n  public String @FN@(@RequestParam String name) throws Exception {\n    java.io.File f = new java.io.File("/srv/" + name);\n    return f.getName();\n  }\n}\n',
    ),
    ScanCase(
        "java-xxe-stax-reset",
        "xml-state",
        "spring",
        ".java",
        "IL-509",
        "import javax.xml.stream.*;\npublic class A {\n  void @FN@(java.io.InputStream a) throws Exception {\n    XMLInputFactory f = XMLInputFactory.newInstance();\n    f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);\n    f.createXMLStreamReader(a);\n  }\n}\n",
        "import javax.xml.stream.*;\npublic class A {\n  void @FN@(java.io.InputStream a) throws Exception {\n    XMLInputFactory f = XMLInputFactory.newInstance();\n    f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);\n    f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);\n    f.createXMLStreamReader(a);\n  }\n}\n",
    ),
    ScanCase(
        "java-xxe-transformer",
        "xml-state",
        "spring",
        ".java",
        "IL-509",
        'import javax.xml.transform.*;\npublic class A {\n  void @FN@() throws Exception {\n    TransformerFactory f = TransformerFactory.newInstance();\n    f.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");\n    f.newTransformer();\n  }\n}\n',
        "import javax.xml.transform.*;\npublic class A {\n  void @FN@() throws Exception {\n    TransformerFactory f = TransformerFactory.newInstance();\n    f.newTransformer();\n  }\n}\n",
    ),
    # ---- FastAPI·asyncpg ----
    ScanCase(
        "fastapi-sql-fetch",
        "sql",
        "fastapi",
        ".py",
        "IL-501",
        "async def @FN@(request, conn):\n    return await conn.fetch('SELECT * FROM t WHERE id = $1', request.query_params['i'])\n",
        "async def @FN@(request, conn):\n    return await conn.fetch(f\"SELECT * FROM t WHERE id = {request.query_params['i']}\")\n",
    ),
    ScanCase(
        "fastapi-path-basename",
        "path-guard",
        "fastapi",
        ".py",
        "IL-502",
        "import os\n\nasync def @FN@(request):\n    return open('/srv/' + os.path.basename(request.path_params['name'])).read()\n",
        "async def @FN@(request):\n    return open('/srv/' + request.path_params['name']).read()\n",
    ),
]

HOLDOUT_APPROVAL: list[ApprovalCase] = [
    ApprovalCase(
        "approval-config-weakened",
        "policy",
        "flask",
        benign_change={".iron-laws.yml": "fail_on: HIGH\n"},
        risky_change={".iron-laws.yml": "fail_on: CRITICAL\n"},
    ),
    ApprovalCase(
        "approval-route-exposed-v2",
        "exposure",
        "flask",
        benign_change={"app.py": 'import os\nfrom flask import request\n\n\ndef run_tool():\n    d = request.args["d"]  # 입력\n\n    os.system("ls " + d)  # 실행\n'},
        risky_change={"app.py": 'import os\nfrom flask import request\nfrom web import route\n\n@route("/public")\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'},
    ),
    ApprovalCase(
        "approval-expiry",
        "expiry",
        "flask",
        benign_change={"extra.py": "def extra():\n    return 1\n"},
        risky_change={"extra.py": "def extra():\n    return 1\n"},
        benign_expires=30,
        risky_expires=-1,
    ),
]

HOLDOUT_OUTPUT: list[OutputCase] = [
    OutputCase(
        "suppression-python-triple-quoted",
        "suppression",
        "python-multiline",
        "suppression",
        benign={
            "file": "a.py",
            "text": "# iron-laws: ignore-file[IL-504] 내부 관리 도구라서 허용한다\nimport os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])\n",
            "rule": "IL-504",
            "suppressed": True,
        },
        risky={
            "file": "a.py",
            "text": "import os\nfrom flask import request\n\nDOC = '''\n# iron-laws: ignore-file[IL-504] 여러 줄 문자열 안의 문구\n'''\n\ndef f():\n    os.system('ls ' + request.args['d'])\n",
            "rule": "IL-504",
            "suppressed": False,
        },
    ),
    OutputCase(
        "suppression-toml-string",
        "suppression",
        "toml",
        "suppression",
        benign={
            "file": "a.toml",
            "text": '# iron-laws: ignore-file[IL-101] 시험용 무효 값이다\npassword = "supersecretvalue123"\n',
            "rule": "IL-101",
            "suppressed": True,
        },
        risky={
            "file": "a.toml",
            "text": 'note = """\n# iron-laws: ignore-file[IL-101] 여러 줄 문자열 안의 문구\n"""\npassword = "supersecretvalue123"\n',
            "rule": "IL-101",
            "suppressed": False,
        },
    ),
    OutputCase(
        "secret-long-line-js",
        "masking",
        "express",
        "secret",
        benign={
            "file": "a.js",
            "text": f"const apiKey = '{SECRET_JS}';\nmodule.exports = apiKey;\n",
            "secrets": [SECRET_JS],
        },
        risky={
            "file": "a.js",
            "text": "const {exec} = require('child_process');\nfunction f(req) {\n  const pad = '"
            + "y" * 300
            + f"'; const apiKey = '{SECRET_JS}'; exec('ls ' + req.query.d);\n}}\n",
            "secrets": [SECRET_JS],
        },
    ),
]
