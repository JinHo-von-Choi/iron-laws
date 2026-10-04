"""
오철칙 규칙별 양성·음성 사례 시험 (언어별)
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-302] 탐지 대상 샘플 문자열

import base64
import json
from pathlib import Path

import pytest

from tests.helpers import lines_of


def _jwt(payload: dict) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.{'s' * 43}"


SERVICE_ROLE_JWT = _jwt({"role": "service_role", "iss": "supabase"})
ANON_JWT = _jwt({"role": "anon", "iss": "supabase"})

# (사례 이름, 규칙 ID, {파일: 내용}, 기대 위치 {파일: [줄 번호]}) - 빈 dict는 지적 없음을 뜻한다
CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # ---- IL-501 SQL 삽입
    ("sqli-py-concat", "IL-501", {"a.py": 'def h():\n    uid = request.args.get("id")\n    cur.execute("SELECT * FROM t WHERE id = " + uid)\n'}, {"a.py": [3]}),
    ("sqli-py-fstring-var", "IL-501", {"a.py": 'def h():\n    name = request.form["n"]\n    q = f"SELECT * FROM t WHERE n = \'{name}\'"\n    cur.execute(q)\n'}, {"a.py": [4]}),
    ("sqli-py-asyncpg-fstring", "IL-501", {"a.py": 'async def h(conn, request):\n    uid = request.args.get("id")\n    return await conn.fetch(f"SELECT * FROM t WHERE id = {uid}")\n'}, {"a.py": [3]}),
    ("sqli-py-asyncpg-bound", "IL-501", {"a.py": 'async def h(conn, request):\n    uid = request.args.get("id")\n    return await conn.fetch("SELECT * FROM t WHERE id = $1", uid)\n'}, {}),
    ("path-py-pathlib-receiver", "IL-502", {"a.py": 'from pathlib import Path\nfrom flask import request\ndef h():\n    return (Path("/srv/data") / request.args["n"]).read_text()\n'}, {"a.py": [4]}),
    ("path-py-pathlib-receiver-constant", "IL-502", {"a.py": 'from pathlib import Path\ndef h():\n    return (Path("/srv/data") / "x.txt").read_text()\n'}, {}),
    ("allowlist-sql-reject-guard", "IL-501", {"a.py": 'from flask import request\ndef f(cur):\n    col = request.args["c"]\n    if col not in ("id", "name"):\n        raise ValueError("bad")\n    cur.execute("SELECT * FROM t ORDER BY " + col)\n'}, {}),
    ("allowlist-sql-pass-branch", "IL-501", {"a.py": 'from flask import request\ndef f(cur):\n    col = request.args["c"]\n    if col in ("id", "name"):\n        cur.execute("SELECT * FROM t ORDER BY " + col)\n'}, {}),
    ("allowlist-sql-module-constant", "IL-501", {"a.py": 'from flask import request\nALLOWED = ("id", "name")\ndef f(cur):\n    col = request.args["c"]\n    if col not in ALLOWED:\n        raise ValueError("bad")\n    cur.execute("SELECT * FROM t ORDER BY " + col)\n'}, {}),
    ("allowlist-sql-check-after-use", "IL-501", {"a.py": 'from flask import request\ndef f(cur):\n    col = request.args["c"]\n    cur.execute("SELECT * FROM t ORDER BY " + col)\n    if col not in ("id", "name"):\n        raise ValueError("bad")\n'}, {"a.py": [4]}),
    ("allowlist-sql-guard-on-other-variable", "IL-501", {"a.py": 'from flask import request\ndef f(cur):\n    col = request.args["c"]\n    other = request.args["o"]\n    if other not in ("id", "name"):\n        raise ValueError("bad")\n    cur.execute("SELECT * FROM t ORDER BY " + col)\n'}, {"a.py": [7]}),
    ("allowlist-sql-two-variables-one-guard", "IL-501", {"a.py": 'from flask import request\ndef f(cur):\n    col = request.args["c"]\n    d = request.args["d"]\n    if col not in ("id", "name"):\n        raise ValueError("bad")\n    cur.execute("SELECT * FROM t ORDER BY " + col + " " + d)\n'}, {"a.py": [7]}),
    ("allowlist-sql-non-literal-list", "IL-501", {"a.py": 'from flask import request\ndef f(cur, allowed):\n    col = request.args["c"]\n    if col not in allowed:\n        raise ValueError("bad")\n    cur.execute("SELECT * FROM t ORDER BY " + col)\n'}, {"a.py": [6]}),
    ("allowlist-cmd-reject-guard", "IL-504", {"a.py": 'import os\nfrom flask import request\ndef f():\n    c = request.args["c"]\n    if c not in ("ls", "pwd"):\n        raise ValueError("bad")\n    os.system(c)\n'}, {}),
    ("sqli-py-param", "IL-501", {"a.py": 'def h():\n    uid = request.args.get("id")\n    cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n'}, {}),
    ("sqli-js-concat", "IL-501", {"a.js": 'app.get("/u", (req, res) => {\n  db.query("SELECT * FROM users WHERE id = " + req.params.id);\n});\n'}, {"a.js": [2]}),
    ("sqli-js-template", "IL-501", {"a.js": 'function f(req) {\n  db.query(`SELECT * FROM users WHERE name = \'${req.body.name}\'`);\n}\n'}, {"a.js": [2]}),
    ("sqli-js-param", "IL-501", {"a.js": 'function f(req) {\n  db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);\n}\n'}, {}),
    ("sqli-js-map-get-not-sql", "IL-501", {"a.js": 'function f(id) {\n  return cache.get("user:" + id);\n}\n'}, {}),
    ("sqli-java-concat", "IL-501", {"A.java": 'class A {\n  void m(HttpServletRequest request) throws Exception {\n    stmt.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id"));\n  }\n}\n'}, {"A.java": [3]}),
    ("sqli-java-prepared", "IL-501", {"A.java": 'class A {\n  void m() throws Exception {\n    var ps = conn.prepareStatement("SELECT * FROM t WHERE id=?");\n  }\n}\n'}, {}),
    ("sqli-cs-concat", "IL-501", {"A.cs": 'class A {\n  void M() {\n    var c = new SqlCommand("SELECT * FROM T WHERE Id=" + Request.Query["id"], conn);\n  }\n}\n'}, {"A.cs": [3]}),
    ("sqli-cs-param", "IL-501", {"A.cs": 'class A {\n  void M() {\n    var c = new SqlCommand("SELECT * FROM T WHERE Id=@id", conn);\n  }\n}\n'}, {}),
    ("sqli-go-concat", "IL-501", {"a.go": 'package a\nfunc f(r *http.Request) {\n\tdb.Query("SELECT * FROM t WHERE id=" + r.URL.Query().Get("id"))\n}\n'}, {"a.go": [3]}),
    ("sqli-go-param", "IL-501", {"a.go": 'package a\nfunc f(id int) {\n\tdb.Query("SELECT * FROM t WHERE id=$1", id)\n}\n'}, {}),
    ("sqli-php-concat", "IL-501", {"a.php": '<?php\nmysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]);\n'}, {"a.php": [2]}),
    ("sqli-php-prepare", "IL-501", {"a.php": '<?php\n$stmt = $pdo->prepare("SELECT * FROM t WHERE id = ?");\n'}, {}),
    ("sqli-rust-format", "IL-501", {"a.rs": 'fn f(id: &str) {\n    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id));\n}\n'}, {"a.rs": [2]}),
    ("sqli-rust-bind", "IL-501", {"a.rs": 'fn f(id: &str) {\n    sqlx::query("SELECT * FROM t WHERE id = $1").bind(id);\n}\n'}, {}),
    ("sqli-mybatis", "IL-501", {"m.xml": "<mapper namespace='u'>\n<select id='g'>\n SELECT * FROM t WHERE id = ${id}\n</select></mapper>\n"}, {"m.xml": [3]}),
    ("sqli-pom-not-mybatis", "IL-501", {"pom.xml": "<project><version>${project.version}</version></project>\n"}, {}),
    # ---- IL-502 경로 조작
    ("path-py-direct", "IL-502", {"a.py": 'def h():\n    return open(request.args["f"]).read()\n'}, {"a.py": [2]}),
    ("path-py-joined-var", "IL-502", {"a.py": 'def h():\n    n = request.args.get("n")\n    return open(os.path.join(BASE, n)).read()\n'}, {"a.py": [3]}),
    ("path-py-const", "IL-502", {"a.py": 'def h():\n    return open("config.json").read()\n'}, {}),
    ("path-py-secure", "IL-502", {"a.py": 'def h():\n    n = request.args.get("n")\n    return open(os.path.join(BASE, secure_filename(n))).read()\n'}, {}),
    ("path-js-readfile", "IL-502", {"a.js": 'function f(req) {\n  fs.readFile(req.query.file, cb);\n}\n'}, {"a.js": [2]}),
    ("path-js-const", "IL-502", {"a.js": 'function f(res) {\n  res.sendFile(path.join(__dirname, "index.html"));\n}\n'}, {}),
    ("path-java-file", "IL-502", {"A.java": 'class A {\n  void m(HttpServletRequest request) {\n    new File(request.getParameter("f"));\n  }\n}\n'}, {"A.java": [3]}),
    ("path-java-const", "IL-502", {"A.java": 'class A {\n  void m() {\n    new File("a.txt");\n  }\n}\n'}, {}),
    ("path-go-open", "IL-502", {"a.go": 'package a\nfunc f(r *http.Request) {\n\tos.Open(r.URL.Query().Get("f"))\n}\n'}, {"a.go": [3]}),
    ("path-php-include", "IL-502", {"a.php": '<?php\ninclude $_GET["p"];\n'}, {"a.php": [2]}),
    # ---- IL-503 코드 삽입
    ("code-py-eval-tainted", "IL-503", {"a.py": 'def h():\n    eval(request.args["x"])\n'}, {"a.py": [2]}),
    ("code-py-eval-input", "IL-503", {"a.py": 'def h():\n    code = input()\n    eval(code)\n'}, {"a.py": [3]}),
    ("code-py-eval-literal", "IL-503", {"a.py": 'def h():\n    eval("1+1")\n'}, {}),
    ("code-py-literal-eval", "IL-503", {"a.py": 'import ast\ndef h(x):\n    ast.literal_eval(x)\n'}, {}),
    ("code-js-eval", "IL-503", {"a.js": 'function f(req) {\n  eval(req.body.code);\n}\n'}, {"a.js": [2]}),
    ("code-js-timeout-fn", "IL-503", {"a.js": "setTimeout(() => {}, 100);\n"}, {}),
    ("code-php-eval", "IL-503", {"a.php": '<?php\neval($_POST["c"]);\n'}, {"a.php": [2]}),
    # ---- IL-504 명령어 삽입
    ("cmd-py-system", "IL-504", {"a.py": 'def h():\n    os.system("ls " + request.args["d"])\n'}, {"a.py": [2]}),
    ("cmd-py-list", "IL-504", {"a.py": 'def h(d):\n    subprocess.run(["ls", d])\n'}, {}),
    ("cmd-py-shell-true", "IL-504", {"a.py": 'def h():\n    cmd = "ls " + request.args["d"]\n    subprocess.run(cmd, shell=True)\n'}, {"a.py": [3]}),
    ("cmd-js-exec", "IL-504", {"a.js": 'function f(req) {\n  exec("ls " + req.query.d);\n}\n'}, {"a.js": [2]}),
    ("cmd-js-execfile", "IL-504", {"a.js": 'function f(d) {\n  execFile("ls", [d]);\n}\n'}, {}),
    ("cmd-java-exec", "IL-504", {"A.java": 'class A {\n  void m(HttpServletRequest request) throws Exception {\n    Runtime.getRuntime().exec("ls " + request.getParameter("d"));\n  }\n}\n'}, {"A.java": [3]}),
    ("cmd-java-array", "IL-504", {"A.java": 'class A {\n  void m(String d) throws Exception {\n    Runtime.getRuntime().exec(new String[]{"ls", d});\n  }\n}\n'}, {}),
    ("cmd-go-shell", "IL-504", {"a.go": 'package a\nfunc f(r *http.Request) {\n\texec.Command("sh", "-c", r.URL.Query().Get("c"))\n}\n'}, {"a.go": [3]}),
    ("cmd-go-args", "IL-504", {"a.go": 'package a\nfunc f(d string) {\n\texec.Command("ls", d)\n}\n'}, {}),
    ("cmd-php-system", "IL-504", {"a.php": '<?php\nsystem("ls " . $_GET["d"]);\n'}, {"a.php": [2]}),
    # ---- IL-505 XSS
    ("xss-js-innerhtml-tainted", "IL-505", {"a.js": "el.innerHTML = location.search;\n"}, {"a.js": [1]}),
    ("xss-js-textcontent", "IL-505", {"a.js": "el.textContent = location.search;\n"}, {}),
    ("xss-js-innerhtml-literal", "IL-505", {"a.js": 'el.innerHTML = "<b>hi</b>";\n'}, {}),
    ("xss-js-innerhtml-var-review", "IL-505", {"a.js": "function f(userInput) {\n  div.innerHTML = userInput;\n}\n"}, {"a.js": [2]}),
    ("xss-js-purify", "IL-505", {"a.js": "function f(x) {\n  div.innerHTML = DOMPurify.sanitize(x);\n}\n"}, {}),
    ("xss-py-return-html", "IL-505", {"a.py": 'def h():\n    return f"<h1>Hello {request.args[\'n\']}</h1>"\n'}, {"a.py": [2]}),
    ("xss-py-template", "IL-505", {"a.py": 'def h():\n    return render_template("a.html", n=request.args["n"])\n'}, {}),
    ("xss-php-echo", "IL-505", {"a.php": '<?php\necho $_GET["q"];\n'}, {"a.php": [2]}),
    ("xss-php-escaped", "IL-505", {"a.php": '<?php\necho htmlspecialchars($_GET["q"]);\n'}, {}),
    ("xss-java-writer", "IL-505", {"A.java": 'class A {\n  void m(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    response.getWriter().println("<p>" + request.getParameter("q") + "</p>");\n  }\n}\n'}, {"A.java": [3]}),
    ("xss-jsx-dangerous", "IL-505", {"a.jsx": "export const C = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;\n"}, {"a.jsx": [1]}),
    # ---- IL-506 SSRF / IL-507 리다이렉트
    ("ssrf-py", "IL-506", {"a.py": 'def h():\n    requests.get(request.args["url"])\n'}, {"a.py": [2]}),
    ("ssrf-py-const", "IL-506", {"a.py": 'def h():\n    requests.get("https://api.service.io/x")\n'}, {}),
    ("ssrf-js", "IL-506", {"a.js": "function f(req) {\n  fetch(req.query.url);\n}\n"}, {"a.js": [2]}),
    ("ssrf-js-const", "IL-506", {"a.js": 'function f() {\n  fetch("/api/x");\n}\n'}, {}),
    ("ssrf-go", "IL-506", {"a.go": 'package a\nfunc f(r *http.Request) {\n\thttp.Get(r.URL.Query().Get("u"))\n}\n'}, {"a.go": [3]}),
    ("redirect-py", "IL-507", {"a.py": 'def h():\n    return redirect(request.args["next"])\n'}, {"a.py": [2]}),
    ("redirect-py-const", "IL-507", {"a.py": 'def h():\n    return redirect("/home")\n'}, {}),
    ("redirect-js", "IL-507", {"a.js": "function f(req, res) {\n  res.redirect(req.query.url);\n}\n"}, {"a.js": [2]}),
    ("redirect-java", "IL-507", {"A.java": 'class A {\n  void m(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    response.sendRedirect(request.getParameter("u"));\n  }\n}\n'}, {"A.java": [3]}),
    # ---- IL-508 LDAP / IL-509 XXE / IL-510 CSRF / IL-511 / IL-512 / IL-513
    ("ldap-py", "IL-508", {"a.py": 'def h():\n    conn.search_s(base, SCOPE, "(uid=" + request.form["u"] + ")")\n'}, {"a.py": [2]}),
    ("ldap-py-const", "IL-508", {"a.py": 'def h():\n    conn.search_s(base, SCOPE, "(uid=admin)")\n'}, {}),
    ("xxe-java", "IL-509", {"A.java": "class A {\n  void m() throws Exception {\n    var f = DocumentBuilderFactory.newInstance();\n  }\n}\n"}, {"A.java": [3]}),
    ("xxe-java-hardened", "IL-509", {"A.java": 'class A {\n  void m() throws Exception {\n    var f = DocumentBuilderFactory.newInstance();\n    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n  }\n}\n'}, {}),
    ("xxe-py", "IL-509", {"a.py": "p = etree.XMLParser(resolve_entities=True)\n"}, {"a.py": [1]}),
    ("csrf-py", "IL-510", {"a.py": "@csrf_exempt\ndef v(r):\n    pass\n"}, {"a.py": [1]}),
    ("csrf-java", "IL-510", {"A.java": "class A {\n  void c(HttpSecurity http) throws Exception {\n    http.csrf().disable();\n  }\n}\n"}, {"A.java": [3]}),
    ("csrf-clean", "IL-510", {"a.py": "app.run()\n"}, {}),
    ("header-java", "IL-511", {"A.java": 'class A {\n  void m(HttpServletRequest request, HttpServletResponse response) {\n    response.setHeader("X", request.getParameter("v"));\n  }\n}\n'}, {"A.java": [3]}),
    ("decision-py-cookie", "IL-512", {"a.py": 'def h():\n    if request.cookies.get("role") == "admin":\n        return 1\n'}, {"a.py": [2]}),
    ("decision-py-user", "IL-512", {"a.py": 'def h(user):\n    if user.role == "admin":\n        return 1\n'}, {}),
    ("upload-py-filename", "IL-513", {"a.py": 'def h():\n    file = request.files["f"]\n    file.save(os.path.join("up", file.filename))\n'}, {"a.py": [3]}),
    ("upload-py-secure", "IL-513", {"a.py": 'def h():\n    file = request.files["f"]\n    file.save(os.path.join("up", secure_filename(file.filename)))\n'}, {}),
    # ---- IL-514 C/C++ 메모리
    ("mem-c-strcpy", "IL-514", {"a.c": "void f(int argc, char **argv) {\n  char buf[8];\n  strcpy(buf, argv[1]);\n}\n"}, {"a.c": [3]}),
    ("mem-c-printf-var", "IL-514", {"a.c": "void f(int argc, char **argv) {\n  printf(argv[1]);\n}\n"}, {"a.c": [2]}),
    ("mem-c-printf-ok", "IL-514", {"a.c": 'void f(char *s) {\n  printf("%s", s);\n}\n'}, {}),
    ("mem-c-scanf-unbounded", "IL-514", {"a.c": 'void f() {\n  char b[64];\n  scanf("%s", b);\n}\n'}, {"a.c": [3]}),
    ("mem-c-scanf-bounded", "IL-514", {"a.c": 'void f() {\n  char b[64];\n  scanf("%63s", b);\n}\n'}, {}),
    ("mem-c-snprintf", "IL-514", {"a.c": 'void f(char *s) {\n  char b[8];\n  snprintf(b, 8, "%s", s);\n}\n'}, {}),
    ("api-c-gets", "IL-524", {"a.c": "void f() {\n  char b[8];\n  gets(b);\n}\n"}, {"a.c": [3]}),
    # ---- IL-515 역직렬화
    ("deser-py-pickle", "IL-515", {"a.py": "def h(d):\n    return pickle.loads(d)\n"}, {"a.py": [2]}),
    ("deser-py-yaml", "IL-515", {"a.py": "def h(f):\n    return yaml.load(f)\n"}, {"a.py": [2]}),
    ("deser-py-safe-load", "IL-515", {"a.py": "def h(f):\n    return yaml.safe_load(f)\n"}, {}),
    ("deser-py-safe-loader", "IL-515", {"a.py": "def h(f):\n    return yaml.load(f, Loader=yaml.SafeLoader)\n"}, {}),
    ("deser-java", "IL-515", {"A.java": "class A {\n  void m(InputStream in) throws Exception {\n    new ObjectInputStream(in).readObject();\n  }\n}\n"}, {"A.java": [3]}),
    ("deser-cs", "IL-515", {"A.cs": "class A {\n  void M(Stream s) {\n    new BinaryFormatter().Deserialize(s);\n  }\n}\n"}, {"A.cs": [3]}),
    ("deser-php", "IL-515", {"a.php": '<?php\n$o = unserialize($_GET["d"]);\n'}, {"a.php": [2]}),
    # ---- IL-516~IL-523 코드오류 계열
    ("toctou-py", "IL-516", {"a.py": "def h(p):\n    if os.path.exists(p):\n        return open(p).read()\n"}, {"a.py": [2]}),
    ("toctou-none", "IL-516", {"a.py": "def h(p):\n    return open(p).read()\n"}, {}),
    ("loop-py-infinite", "IL-517", {"a.py": "def h():\n    while True:\n        work()\n"}, {"a.py": [2]}),
    ("loop-py-break", "IL-517", {"a.py": "def h():\n    while True:\n        if done():\n            break\n"}, {}),
    ("leak-py-open", "IL-518", {"a.py": 'def h():\n    f = open("a")\n    return f.read()\n'}, {"a.py": [2]}),
    ("leak-py-with", "IL-518", {"a.py": 'def h():\n    with open("a") as f:\n        return f.read()\n'}, {}),
    ("leak-py-closed", "IL-518", {"a.py": 'def h():\n    f = open("a")\n    d = f.read()\n    f.close()\n    return d\n'}, {}),
    ("leak-java", "IL-518", {"A.java": 'class A {\n  void m() throws Exception {\n    FileInputStream in = new FileInputStream("a");\n    in.read();\n  }\n}\n'}, {"A.java": [3]}),
    ("leak-java-twr", "IL-518", {"A.java": 'class A {\n  void m() throws Exception {\n    try (FileInputStream in = new FileInputStream("a")) {\n      in.read();\n    }\n  }\n}\n'}, {}),
    ("leak-go", "IL-518", {"a.go": 'package a\nfunc f() {\n\tf, _ := os.Open("a")\n\t_ = f\n}\n'}, {"a.go": [3]}),
    ("leak-go-defer", "IL-518", {"a.go": 'package a\nfunc f() {\n\tf, _ := os.Open("a")\n\tdefer f.Close()\n}\n'}, {}),
    ("leak-cs-using", "IL-518", {"A.cs": 'class A {\n  void M() {\n    using var r = new StreamReader("a");\n  }\n}\n'}, {}),
    ("leak-cs", "IL-518", {"A.cs": 'class A {\n  void M() {\n    var r = new StreamReader("a");\n    r.ReadToEnd();\n  }\n}\n'}, {"A.cs": [3]}),
    ("null-c-malloc", "IL-519", {"a.c": "void f() {\n  char *p = malloc(10);\n  p[0] = 'a';\n}\n"}, {"a.c": [2]}),
    ("null-c-checked", "IL-519", {"a.c": "void f() {\n  char *p = malloc(10);\n  if (p == NULL) return;\n  p[0] = 'a';\n}\n"}, {}),
    ("null-py-match", "IL-519", {"a.py": 'def h(s):\n    return re.match("a", s).group(0)\n'}, {"a.py": [2]}),
    ("debug-py-run", "IL-520", {"a.py": "app.run(debug=True)\n"}, {"a.py": [1]}),
    ("debug-py-breakpoint", "IL-520", {"a.py": "def h():\n    breakpoint()\n"}, {"a.py": [2]}),
    ("debug-js-debugger", "IL-520", {"a.js": "function f() {\n  debugger;\n}\n"}, {"a.js": [2]}),
    ("debug-php-vardump", "IL-520", {"a.php": "<?php\nvar_dump($x);\n"}, {"a.php": [2]}),
    ("debug-clean", "IL-520", {"a.py": "app.run(debug=False)\n"}, {}),
    ("servlet-field", "IL-521", {"A.java": "public class A extends HttpServlet {\n  private String user;\n}\n"}, {"A.java": [2]}),
    ("servlet-final-field", "IL-521", {"A.java": "public class A extends HttpServlet {\n  private static final String X = \"a\";\n}\n"}, {}),
    ("array-java-expose", "IL-522", {"A.java": "public class A {\n  private int[] a;\n  public int[] get() {\n    return a;\n  }\n}\n"}, {"A.java": [4]}),
    ("array-java-clone", "IL-522", {"A.java": "public class A {\n  private int[] a;\n  public int[] get() {\n    return a.clone();\n  }\n}\n"}, {}),
    ("dns-py", "IL-523", {"a.py": 'def h(ip):\n    if socket.gethostbyaddr(ip)[0] == "trusted.com":\n        return 1\n'}, {"a.py": [2]}),
    # ---- IL-101~IL-114 보안기능
    ("secret-py-password", "IL-101", {"a.py": 'password = "hunter22hunter"\n'}, {"a.py": [1]}),
    ("secret-py-env", "IL-101", {"a.py": 'password = os.environ["P"]\n'}, {}),
    ("secret-py-placeholder", "IL-101", {"a.py": 'password = "changeme"\n'}, {}),
    ("secret-aws-key", "IL-101", {"a.py": 'k = "AKIAIOSFODNN7ABCDEFG"\n'}, {"a.py": [1]}),
    ("secret-env-file", "IL-101", {".env": "DB_PASSWORD=supersecret123\n"}, {".env": [1]}),
    ("secret-env-example", "IL-101", {".env.example": "DB_PASSWORD=supersecret123\n"}, {}),
    ("secret-yaml", "IL-101", {"c.yml": 'password: "abc12345"\n'}, {"c.yml": [1]}),
    ("secret-yaml-placeholder", "IL-101", {"c.yml": "password: ${DB_PASSWORD}\n"}, {}),
    ("secret-jwt-literal-key", "IL-101", {"a.js": 'const t = jwt.sign(payload, "secret");\n'}, {"a.js": [1]}),
    ("secret-conn-string", "IL-101", {"a.py": 'URL = "postgres://app:pw12345@db.internal/app"\n'}, {"a.py": [1]}),
    ("secret-supabase-service-role", "IL-101", {"a.js": f'const k = "{SERVICE_ROLE_JWT}";\n'}, {"a.js": [1]}),
    ("secret-supabase-anon", "IL-101", {"a.js": f'const k = "{ANON_JWT}";\n'}, {}),
    ("secret-private-key", "IL-101", {"k.sh": "-----BEGIN RSA PRIVATE KEY-----\n"}, {"k.sh": [1]}),
    ("crypto-py-md5-password", "IL-102", {"a.py": "def hash_password(p):\n    return hashlib.md5(p.encode())\n"}, {"a.py": [2]}),
    ("crypto-py-des", "IL-102", {"a.py": "c = DES.new(key)\n"}, {"a.py": [1]}),
    ("crypto-java-des", "IL-102", {"A.java": 'class A {\n  void m() throws Exception {\n    Cipher.getInstance("DES/ECB/PKCS5Padding");\n  }\n}\n'}, {"A.java": [3]}),
    ("crypto-py-sha256", "IL-102", {"a.py": "def h(d):\n    return hashlib.sha256(d)\n"}, {}),
    ("crypto-py-md5-nonsecurity", "IL-102", {"a.py": "x = hashlib.md5(d, usedforsecurity=False)\n"}, {}),
    ("crypto-go-3des-allowed", "IL-102", {"a.java": 'class A {\n  void m() throws Exception {\n    Cipher.getInstance("DESede/CBC/PKCS5Padding");\n  }\n}\n'}, {}),
    ("keylen-py-1024", "IL-103", {"a.py": "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"}, {"a.py": [1]}),
    ("keylen-py-2048", "IL-103", {"a.py": "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"}, {}),
    ("random-py-token", "IL-104", {"a.py": "token = random.randint(0, 999999)\n"}, {"a.py": [1]}),
    ("random-py-dice", "IL-104", {"a.py": "roll = random.randint(1, 6)\n"}, {}),
    ("random-js-token", "IL-104", {"a.js": "const token = Math.random().toString(36);\n"}, {"a.js": [1]}),
    ("random-js-plain", "IL-104", {"a.js": "const x = Math.random();\n"}, {}),
    ("jwt-py-noverify", "IL-105", {"a.py": 'p = jwt.decode(t, options={"verify_signature": False})\n'}, {"a.py": [1]}),
    ("tls-py-verify-false", "IL-106", {"a.py": "requests.get(u, verify=False)\n"}, {"a.py": [1]}),
    ("tls-js", "IL-106", {"a.js": "const o = { rejectUnauthorized: false };\n"}, {"a.js": [1]}),
    ("tls-go", "IL-106", {"a.go": "package a\nvar c = &tls.Config{InsecureSkipVerify: true}\n"}, {"a.go": [2]}),
    ("tls-clean", "IL-106", {"a.py": "requests.get(u, verify=True)\n"}, {}),
    ("unsalted-py", "IL-107", {"a.py": "def h(password):\n    return hashlib.sha256(password.encode()).hexdigest()\n"}, {"a.py": [2]}),
    ("unsalted-bcrypt", "IL-107", {"a.py": "def h(password):\n    return bcrypt.hashpw(password, bcrypt.gensalt())\n"}, {}),
    ("credcmp-py", "IL-108", {"a.py": 'def login(password):\n    if password == "admin123":\n        return True\n'}, {"a.py": [2]}),
    ("credcmp-py-user-pass", "IL-108", {"a.py": 'def login(u, password):\n    if u == "admin" and password == "1234":\n        return True\n'}, {"a.py": [2]}),
    ("credcmp-hash", "IL-108", {"a.py": "def login(password, hashed):\n    if password == hashed:\n        return True\n"}, {}),
    ("plain-http", "IL-109", {"a.py": 'u = "http://api.service.io/x"\n'}, {"a.py": [1]}),
    ("plain-localhost", "IL-109", {"a.py": 'u = "http://localhost:3000/x"\n'}, {}),
    ("pwpolicy-short", "IL-110", {"a.py": "password = StringField(validators=[Length(min_length=4)])\n"}, {"a.py": [1]}),
    ("comment-secret", "IL-111", {"a.py": "# password = hunter22hunter\nx = 1\n"}, {"a.py": [1]}),
    ("cookie-password", "IL-112", {"a.py": 'def h(resp, pw):\n    resp.set_cookie("password", pw)\n'}, {"a.py": [2]}),
    ("curl-pipe-sh", "IL-113", {"Dockerfile": "FROM python:3.12\nRUN curl -sSL https://x.io/i.sh | sh\nUSER app\n"}, {"Dockerfile": [2]}),
    ("chmod-777", "IL-114", {"s.sh": "chmod 777 /app\n"}, {"s.sh": [1]}),
    ("chmod-750", "IL-114", {"s.sh": "chmod 750 /app\n"}, {}),
    # ---- IL-301 예외 은폐
    ("swallow-py-pass", "IL-301", {"a.py": "def h():\n    try:\n        x()\n    except ValueError:\n        pass\n"}, {"a.py": [4]}),
    ("swallow-py-return-none", "IL-301", {"a.py": "def h():\n    try:\n        x()\n    except ValueError:\n        return None\n"}, {"a.py": [4]}),
    ("swallow-py-logged", "IL-301", {"a.py": 'def h():\n    try:\n        x()\n    except ValueError:\n        logger.error("fail")\n'}, {}),
    ("swallow-py-raise", "IL-301", {"a.py": "def h():\n    try:\n        x()\n    except ValueError as e:\n        raise RuntimeError('x') from e\n"}, {}),
    ("swallow-py-uses-exc", "IL-301", {"a.py": "def h():\n    try:\n        x()\n    except ValueError as e:\n        return {'error': str(e)}\n"}, {}),
    ("swallow-py-optional-import", "IL-301", {"a.py": "try:\n    import ujson\nexcept ImportError:\n    ujson = None\n"}, {}),
    ("swallow-py-suppress", "IL-301", {"a.py": "def h():\n    with contextlib.suppress(Exception):\n        x()\n"}, {"a.py": [2]}),
    ("swallow-js-empty", "IL-301", {"a.js": "function f() {\n  try { x(); } catch (e) {}\n}\n"}, {"a.js": [2]}),
    ("swallow-js-logged", "IL-301", {"a.js": "function f() {\n  try { x(); } catch (e) { console.error(e); }\n}\n"}, {}),
    ("swallow-js-promise", "IL-301", {"a.js": "function f() {\n  fetch(u).catch(() => {});\n}\n"}, {"a.js": [2]}),
    ("swallow-js-promise-null", "IL-301", {"a.js": "function f() {\n  return fetch(u).catch(() => null);\n}\n"}, {"a.js": [2]}),
    ("swallow-js-promise-logged", "IL-301", {"a.js": "function f() {\n  fetch(u).catch((e) => console.error(e));\n}\n"}, {}),
    ("swallow-java-empty", "IL-301", {"A.java": "class A {\n  void m() {\n    try { x(); } catch (IOException e) { }\n  }\n}\n"}, {"A.java": [3]}),
    ("swallow-java-default", "IL-301", {"A.java": "class A {\n  int m() {\n    try { return x(); } catch (NumberFormatException e) { return 0; }\n  }\n}\n"}, {"A.java": [3]}),
    ("swallow-java-log", "IL-301", {"A.java": 'class A {\n  void m() {\n    try { x(); } catch (IOException e) { log.error("x", e); }\n  }\n}\n'}, {}),
    ("swallow-cs-empty", "IL-301", {"A.cs": "class A {\n  void M() {\n    try { X(); } catch (Exception) { }\n  }\n}\n"}, {"A.cs": [3]}),
    ("swallow-cs-throw", "IL-301", {"A.cs": "class A {\n  void M() {\n    try { X(); } catch (Exception) { throw; }\n  }\n}\n"}, {}),
    ("swallow-go-empty", "IL-301", {"a.go": "package a\nfunc f() {\n\t_, err := g()\n\tif err != nil {\n\t}\n}\n"}, {"a.go": [4]}),
    ("swallow-go-return-nil", "IL-301", {"a.go": "package a\nfunc f() error {\n\t_, err := g()\n\tif err != nil {\n\t\treturn nil\n\t}\n\treturn nil\n}\n"}, {"a.go": [4]}),
    ("swallow-go-return-err", "IL-301", {"a.go": "package a\nfunc f() error {\n\t_, err := g()\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn nil\n}\n"}, {}),
    ("swallow-go-logged", "IL-301", {"a.go": "package a\nfunc f() {\n\t_, err := g()\n\tif err != nil {\n\t\tlog.Println(err)\n\t}\n}\n"}, {}),
    ("swallow-rust-let-underscore", "IL-301", {"a.rs": "fn f() {\n    let _ = std::fs::remove_file(\"a\");\n}\n"}, {"a.rs": [2]}),
    ("swallow-rust-ok", "IL-301", {"a.rs": "fn f() {\n    g().ok();\n}\n"}, {"a.rs": [2]}),
    ("swallow-rust-err-arm", "IL-301", {"a.rs": "fn f(r: Result<i32, E>) {\n    match r {\n        Ok(v) => use_it(v),\n        Err(_) => {}\n    }\n}\n"}, {"a.rs": [4]}),
    ("swallow-rust-question", "IL-301", {"a.rs": "fn f() -> Result<(), E> {\n    g()?;\n    Ok(())\n}\n"}, {}),
    ("swallow-php-empty", "IL-301", {"a.php": "<?php\ntry { x(); } catch (Exception $e) { }\n"}, {"a.php": [2]}),
    ("swallow-php-suppress", "IL-301", {"a.php": '<?php\n$d = @file_get_contents("a");\n'}, {"a.php": [2]}),
    # ---- IL-302 / IL-303 / IL-304 / IL-305 / IL-306
    ("disabled-py-skip", "IL-302", {"test_a.py": "@pytest.mark.skip\ndef test_x():\n    assert 1\n"}, {"test_a.py": [1]}),
    ("disabled-py-skipif", "IL-302", {"test_a.py": '@pytest.mark.skipif(sys.platform == "win32", reason="x")\ndef test_x():\n    assert 1\n'}, {}),
    ("disabled-js-skip", "IL-302", {"a.test.js": 'it.skip("x", () => { expect(1).toBe(1); });\n'}, {"a.test.js": [1]}),
    ("disabled-java", "IL-302", {"ATest.java": "class ATest {\n  @Disabled\n  @Test void t() { assertTrue(true); }\n}\n"}, {"ATest.java": [2]}),
    ("authbypass-py", "IL-303", {"a.py": "def is_admin(user):\n    return True\n"}, {"a.py": [1]}),
    ("authbypass-js-arrow", "IL-303", {"a.js": "const isAuthenticated = () => true;\n"}, {"a.js": [1]}),
    ("authbypass-js-next", "IL-303", {"a.js": "function authenticate(req, res, next) {\n  next();\n}\n"}, {"a.js": [1]}),
    ("authbypass-java-permitall", "IL-303", {"A.java": "class A {\n  void c(HttpSecurity h) throws Exception {\n    h.authorizeRequests().anyRequest().permitAll();\n  }\n}\n"}, {"A.java": [3]}),
    ("authbypass-real", "IL-303", {"a.py": "def is_admin(user):\n    return user.role == 'admin'\n"}, {}),
    ("broad-py", "IL-304", {"a.py": "def h():\n    try:\n        x()\n    except Exception as e:\n        logger.error(e)\n"}, {"a.py": [4]}),
    ("broad-py-specific", "IL-304", {"a.py": "def h():\n    try:\n        x()\n    except ValueError as e:\n        logger.error(e)\n"}, {}),
    ("broad-java", "IL-304", {"A.java": "class A {\n  void m() {\n    try { x(); } catch (Exception e) { log.error(e); }\n  }\n}\n"}, {"A.java": [3]}),
    ("exposure-py", "IL-305", {"a.py": "def h():\n    try:\n        x()\n    except ValueError as e:\n        return jsonify(error=str(e))\n"}, {"a.py": [5]}),
    ("exposure-js", "IL-305", {"a.js": "function f(req, res) {\n  try { x(); } catch (err) {\n    res.status(500).send(err.stack);\n  }\n}\n"}, {"a.js": [3]}),
    ("exposure-go", "IL-305", {"a.go": "package a\nfunc f(w http.ResponseWriter) {\n\thttp.Error(w, err.Error(), 500)\n}\n"}, {"a.go": [3]}),
    ("noassert-py", "IL-306", {"test_a.py": "def test_x():\n    run()\n"}, {"test_a.py": [1]}),
    ("noassert-py-ok", "IL-306", {"test_a.py": "def test_x():\n    assert run() == 1\n"}, {}),
    ("noassert-js", "IL-306", {"a.test.js": 'it("x", () => {\n  run();\n});\n'}, {"a.test.js": [1]}),
    ("noassert-java", "IL-306", {"ATest.java": "class ATest {\n  @Test void t() { run(); }\n}\n"}, {"ATest.java": [2]}),
    ("noassert-go", "IL-306", {"a_test.go": "package a\nfunc TestX(t *testing.T) {\n\trun()\n}\n"}, {"a_test.go": [2]}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_rule_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    from iron_laws.core.scanner import AuditScanner

    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
