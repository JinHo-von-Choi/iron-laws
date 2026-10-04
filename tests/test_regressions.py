"""
오철칙 실제 프로젝트 점검에서 확인된 오탐·미탐 회귀 시험
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of

CASES = [
    ("env-name-constant", "IL-101", {"c.py": 'ENV_KEY = "SOME_SERVICE_API_KEY"\n'}, {}),
    ("php-cast-hashed", "IL-101", {"a.php": "<?php\nreturn ['password' => 'hashed'];\n"}, {}),
    ("shell-var-ref", "IL-101", {"s.sh": 'export PGPASSWORD="$DB_PASSWORD"\n'}, {}),
    ("secret-name-ref", "IL-101", {"b.yml": 'secrets: "github-pat-bot-repo"\n'}, {}),
    ("default-password-word", "IL-101", {"c.py": 'DEFAULT_PASSWORD = "hindsight"\n'}, {"c.py": [1]}),
    ("des-in-prose", "IL-102", {"d.c": 'const char *s = "HALLS DES DAMNES";\n'}, {}),
    ("ecb-struct-field", "IL-102", {"d.c": "void f() {\n  packets[0].ecb.fAddress = 1;\n}\n"}, {}),
    ("des-quoted-spec", "IL-102", {"A.java": 'class A {\n  void m() throws Exception {\n    Cipher.getInstance("DES");\n  }\n}\n'}, {"A.java": [3]}),
    ("sql-ddl-fstring", "IL-501", {"m.py": 'def up(op, schema):\n    op.execute(f"DROP TABLE IF EXISTS {schema}t CASCADE")\n'}, {}),
    ("sql-dml-fstring", "IL-501", {"m.py": 'def q(conn, uid):\n    conn.execute(f"SELECT * FROM t WHERE id = {uid}")\n'}, {"m.py": [2]}),
    ("sql-disabled-param", "IL-302", {"p.sql": "CREATE PROCEDURE P\n  @Disabled bit,\n  @X int\nAS SELECT 1\n"}, {}),
    ("cs-skip-with-reason", "IL-302", {"ATests.cs": 'class ATests {\n  [Fact(Skip = "needs more work")]\n  public void T() { Assert.True(true); }\n}\n'}, {"ATests.cs": [2]}),
    ("cs-request-body-reader", "IL-502", {"A.cs": "class A {\n  void M() {\n    using var r = new StreamReader(HttpContext.Request.Body);\n  }\n}\n"}, {}),
    ("cs-header-exists", "IL-512", {"A.cs": 'class A {\n  void M() {\n    if (!Request.Headers.ContainsKey("Auth-Email")) { }\n  }\n}\n'}, {}),
    ("documented-empty-catch", "IL-301", {"a.js": "function f() {\n  try { x(); } catch (e) { /* 이미 닫힌 소켓은 무시한다 */ }\n}\n"}, {"a.js": [2]}),
    ("compose-placeholder-default", "AI-102", {"docker-compose.yml": "services:\n  a:\n    environment:\n      K: ${OPENAI_API_KEY:-your-api-key}\n"}, {}),
    ("env-override-url", "AI-101", {"a.js": 'const BASE = process.env.API_BASE || "https://api.service.io/v1";\n'}, {}),
    ("property-name-not-variable", "IL-502", {"a.mjs": 'import { join } from "node:path";\nimport fs from "node:fs";\nconst root = new URL("../", import.meta.url).pathname;\nfunction h(req) {\n  const url = req.url;\n  return url;\n}\nfs.readFileSync(path.join(root, "a.txt"));\n'}, {}),
    ("go-conditional-loop", "IL-517", {"a.go": "package a\nfunc f(n int) {\n\tfor n > 0 {\n\t\tn--\n\t}\n}\n"}, {}),
    ("js-array-join-not-path", "IL-502", {"a.js": 'function f(req) {\n  return [req.query.a, "b"].join(",");\n}\n'}, {}),
    ("browser-fetch-not-ssrf", "IL-506", {"a.js": "function f() {\n  const u = location.search;\n  document.title = 'x';\n  fetch(u);\n}\n"}, {}),
    ("cli-argv-not-web-path", "IL-502", {"a.js": "const fs = require('fs');\nconst d = fs.readFileSync(process.argv[2]);\n"}, {}),
    ("function-callback-not-code", "IL-503", {"a.js": "setInterval(function () { go(window.location.href); }, 1000);\n"}, {}),
    ("xpath-java", "IL-527", {"A.java": 'class A {\n  void m(HttpServletRequest request, XPath xp) throws Exception {\n    xp.evaluate("/Emp/E[@id=\'" + request.getParameter("i") + "\']", doc);\n  }\n}\n'}, {"A.java": [3]}),
    ("xpath-py", "IL-527", {"a.py": 'def h(tree):\n    return tree.xpath("//user[@name=\'" + request.args["n"] + "\']")\n'}, {"a.py": [2]}),
    ("xpath-const", "IL-527", {"a.py": 'def h(tree):\n    return tree.xpath("//user[@name=\'a\']")\n'}, {}),
    ("trust-java", "IL-526", {"A.java": 'class A {\n  void m(HttpServletRequest request, HttpSession session) {\n    session.setAttribute("u", request.getParameter("u"));\n  }\n}\n'}, {"A.java": [3]}),
    ("trust-py", "IL-526", {"a.py": 'def h():\n    session["user"] = request.args["u"]\n'}, {"a.py": [2]}),
    ("trust-py-const", "IL-526", {"a.py": 'def h():\n    session["user"] = "x"\n'}, {}),
    ("cookie-py-missing", "AI-115", {"a.py": 'def h(resp):\n    resp.set_cookie("session", "v")\n'}, {"a.py": [2]}),
    ("cookie-py-ok", "AI-115", {"a.py": 'def h(resp):\n    resp.set_cookie("session", "v", secure=True, httponly=True)\n'}, {}),
    ("cookie-js-missing", "AI-115", {"a.js": 'function f(res) {\n  res.cookie("token", "v");\n}\n'}, {"a.js": [2]}),
    ("cookie-js-ok", "AI-115", {"a.js": 'function f(res) {\n  res.cookie("token", "v", { httpOnly: true, secure: true });\n}\n'}, {}),
    ("cookie-java-missing", "AI-115", {"A.java": 'class A {\n  void m(HttpServletResponse r) {\n    Cookie c = new Cookie("s", "v");\n    r.addCookie(c);\n  }\n}\n'}, {"A.java": [3]}),
    ("cookie-java-ok", "AI-115", {"A.java": 'class A {\n  void m(HttpServletResponse r) {\n    Cookie c = new Cookie("s", "v");\n    c.setSecure(true);\n    c.setHttpOnly(true);\n    r.addCookie(c);\n  }\n}\n'}, {}),
    ("uaf-c", "IL-528", {"a.c": "void f() {\n  char *p = malloc(4);\n  free(p);\n  p[0] = 1;\n}\n"}, {"a.c": [4]}),
    ("uaf-c-reassigned", "IL-528", {"a.c": "void f() {\n  char *p = malloc(4);\n  free(p);\n  p = malloc(8);\n  p[0] = 1;\n}\n"}, {}),
    ("uninit-c", "IL-529", {"a.c": "int f() {\n  int x;\n  return x + 1;\n}\n"}, {"a.c": [2]}),
    ("uninit-c-assigned", "IL-529", {"a.c": "int f() {\n  int x;\n  x = 3;\n  return x + 1;\n}\n"}, {}),
    ("uninit-c-scanf", "IL-529", {"a.c": 'int f() {\n  int x;\n  scanf("%d", &x);\n  return x;\n}\n'}, {}),
    ("failure-default-java", "IL-307", {"A.java": 'class A {\n  String decryptText(byte[] d) {\n    if (d.length < 16) {\n      return null;\n    }\n    return "x";\n  }\n}\n'}, {"A.java": [3]}),
    ("failure-default-py", "IL-307", {"a.py": "def verify_token(t):\n    if len(t) != 32:\n        return None\n    return t\n"}, {"a.py": [2]}),
    ("failure-default-logged", "IL-307", {"a.py": 'def verify_token(t):\n    if len(t) != 32:\n        logger.warning("bad token")\n        return None\n    return t\n'}, {}),
    ("failure-default-raise", "IL-307", {"a.py": "def verify_token(t):\n    if len(t) != 32:\n        raise ValueError('bad')\n    return t\n"}, {}),
    ("failure-null-guard-ok", "IL-307", {"A.java": "class A {\n  String decryptText(String d) {\n    if (d == null) {\n      return null;\n    }\n    return d;\n  }\n}\n"}, {}),
    ("failure-ornull-api", "IL-307", {"A.java": "class A {\n  String decryptTextOrNull(byte[] d) {\n    return null;\n  }\n}\n"}, {"A.java": [2]}),
    ("failure-unrelated-fn", "IL-307", {"a.py": "def get_color(x):\n    if x == 3:\n        return None\n    return 1\n"}, {}),
    ("msg-mismatch-java", "IL-531", {"A.java": 'class A {\n  void m(int maxCount) {\n    if (maxCount < 1 || maxCount > 100000) {\n      throw ApiException.badRequest("최대 횟수는 1 이상이어야 합니다.");\n    }\n  }\n}\n'}, {"A.java": [3]}),
    ("msg-match-java", "IL-531", {"A.java": 'class A {\n  void m(int maxCount) {\n    if (maxCount < 1 || maxCount > 100000) {\n      throw ApiException.badRequest("최대 횟수는 1 이상 100000 이하여야 합니다.");\n    }\n  }\n}\n'}, {}),
    ("msg-mismatch-py", "IL-531", {"a.py": 'def f(n):\n    if n < 1 or n > 100:\n        raise ValueError("n은 1 이상이어야 합니다")\n'}, {"a.py": [2]}),
    ("docstring-example-not-code", "IL-520", {"a.py": 'def f():\n    """예시:\n\n        DEBUG = True\n    """\n    return 1\n'}, {}),
    ("docstring-secret-example", "IL-101", {"a.py": 'def f():\n    """\n    SECRET_KEY = \'development key\'\n    """\n    return 1\n'}, {}),
    ("env-in-test-fixture-ok", "AI-104", {"tests/apps/.env": "API_KEY=abcdef123456\n"}, {}),
    ("specific-except-continue", "IL-301", {"a.py": "def f(xs):\n    for x in xs:\n        try:\n            return g(x)\n        except KeyError:\n            continue\n"}, {"a.py": [5]}),
    ("pagination-import-not-db", "ARC-207", {"src/com/x/controller/C.java": "package com.x.controller;\nimport org.springframework.data.domain.Page;\nclass C {}\n", "src/com/x/service/S.java": "package com.x.service;\nclass S {}\n"}, {}),
    ("annotation-beats-directory", "ARC-207", {"src/com/x/service/HintService.java": "package com.x.service;\nimport org.springframework.web.bind.annotation.GetMapping;\n@RestController\nclass HintService {}\n", "src/com/x/repository/R.java": "package com.x.repository;\nclass R {}\n"}, {}),
    ("standard-header-keys-ok", "ARC-210", {f"{n}.java": f'class {n} {{\n  String m(HttpServletRequest r) {{\n    return r.getHeader("Content-Type");\n  }}\n}}\n' for n in "ABC"}, {}),
    ("route-handler-not-global-filter", "ARC-212", {"a.js": "const express = require('express');\nconst app = express();\napp.get('/x', (req, res, next) => {\n  usersDao.find(1);\n});\n"}, {}),
    ("global-middleware-db", "ARC-212", {"a.js": "const express = require('express');\nconst app = express();\napp.use((req, res, next) => {\n  adminDao.findAll();\n  next();\n});\n"}, {"a.js": [4]}),
    ("changelog-version-ignored", "AI-121", {"pom.xml": "<project>\n<java.version>17</java.version>\n</project>\n", "RELEASE_NOTES.md": "Java 8 was supported before.\n"}, {}),
    ("docker-arg-version-ignored", "AI-121", {"pom.xml": "<project>\n<java.version>17</java.version>\n</project>\n", "Dockerfile": "FROM mcr.microsoft.com/java:0-${VARIANT}\nUSER app\n"}, {}),
    ("nosql-where-dynamic", "IL-533", {"a.js": "function f(t) {\n  return col.find({ $where: `this.stocks > ${t}` });\n}\n"}, {"a.js": [2]}),
    ("nosql-where-literal", "IL-533", {"a.js": 'function f() {\n  return col.find({ $where: "this.stocks > 1" });\n}\n'}, {}),
    ("nosql-operator-injection", "IL-533", {"a.js": "function f(req) {\n  return users.findOne({ username: req.body.username, password: req.body.password });\n}\n"}, {"a.js": [2]}),
    ("nosql-coerced", "IL-533", {"a.js": "function f(req) {\n  return users.findOne({ username: String(req.body.username) });\n}\n"}, {}),
    ("nosql-whole-body", "IL-533", {"a.js": "function f(req) {\n  return users.find(req.body);\n}\n"}, {"a.js": [2]}),
    ("session-cookie-options", "AI-115", {"a.js": "const session = require('express-session');\napp.use(session({ secret: 'x', resave: false }));\n"}, {"a.js": [2]}),
    ("session-cookie-secure", "AI-115", {"a.js": "const session = require('express-session');\napp.use(session({ secret: 'x', cookie: { secure: true, httpOnly: true } }));\n"}, {}),
    ("csrf-missing-express", "IL-510", {"a.js": "const session = require('express-session');\napp.post('/a', h);\napp.post('/b', h);\napp.put('/c', h);\n"}, {"a.js": [1]}),
    ("csrf-present-express", "IL-510", {"a.js": "const session = require('express-session');\nconst csrf = require('csurf');\napp.post('/a', h);\napp.post('/b', h);\napp.put('/c', h);\n"}, {}),
    ("eol-node", "AI-121", {"Dockerfile": "FROM node:18-alpine\nUSER app\n"}, {"Dockerfile": [1]}),
    ("supported-node", "AI-121", {"Dockerfile": "FROM node:22-alpine\nUSER app\n"}, {}),
    ("eol-python", "AI-121", {".python-version": "3.8\n"}, {".python-version": [1]}),
    ("php-form-login-no-limit", "IL-532", {"login.php": '<?php\n$p = $_POST["password"];\n'}, {"login.php": [2]}),
    ("cypress-get-assertion", "IL-306", {"a.cy.js": 'it("has input", () => {\n  cy.get("input");\n});\n'}, {}),
    ("ignored-var-low", "IL-301", {"A.java": "class A {\n  void m() {\n    try { x(); } catch (IllegalStateException ignored) { }\n  }\n}\n"}, {"A.java": [3]}),
    ("storage-guard-low", "IL-301", {"a.js": "function f(v) {\n  try { localStorage.setItem('k', v); } catch (e) { }\n}\n"}, {"a.js": [2]}),
    ("cleanup-catch-low", "IL-301", {"a.js": "function f(w) {\n  w.terminate().catch(() => {});\n}\n"}, {"a.js": [2]}),
    ("form-body-not-password", "IL-101", {"a.html": "<script>\nvar b = 'password=' + encodeURIComponent(p.value) + '&x=1';\n</script>\n"}, {}),
    ("korean-label-not-secret", "IL-101", {"a.py": 'LABELS = {"SECRET": "숨은 벽"}\n'}, {}),
    ("sql-placeholder-identifier", "IL-501", {"a.py": 'async def f(conn, bank):\n    await conn.execute(f"DELETE FROM {table()} WHERE bank_id = $1", bank)\n'}, {}),
    ("sql-migration-dynamic", "IL-501", {"migrations/001.py": 'def up(op, s):\n    op.execute(f"INSERT INTO {s}.t SELECT 1")\n'}, {}),
    ("build-output-skipped", "IL-101", {".next-e2e/m.json": '{"encryptionKey": "0rssPPrb6CV9pOZaeqx6dB0FQO9LTR+jFIjdKR1ij+4="}\n'}, {}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_regression(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"


def test_suppression_requires_reason(tmp_path: Path):
    with_reason = "def f():\n    try:\n        x()\n    except ValueError:  # iron-laws: ignore[IL-301] 선택적 기능이라 생략해도 무방하다\n        pass\n"
    without_reason = "def f():\n    try:\n        x()\n    except ValueError:  # iron-laws: ignore[IL-301]\n        pass\n"
    (tmp_path / "ok.py").write_text(with_reason, encoding="utf-8")
    (tmp_path / "bad.py").write_text(without_reason, encoding="utf-8")
    report = AuditScanner(tmp_path).scan()
    assert lines_of(report.violations, "IL-301", "ok.py") == []
    assert lines_of(report.violations, "IL-301", "bad.py") == [4]
    assert report.summary.suppressed_count == 1


def test_minified_and_generated_files_are_skipped(tmp_path: Path):
    (tmp_path / "bundle.js").write_text("var a=1;" * 5000 + 'password="hunter22hunter";', encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    report = AuditScanner(tmp_path).scan()
    assert report.summary.total_files_scanned == 1
    assert any(s["path"] == "bundle.js" for s in report.metadata["skipped_files"])


def test_vendored_javascript_library_is_skipped(tmp_path: Path):
    banner = "/*! jQuery v3.6.0 | (c) OpenJS Foundation | MIT License */\n"
    (tmp_path / "jquery.js").write_text(banner + "var a = 1;\n" * 3000, encoding="utf-8")
    (tmp_path / "app.js").write_text("var x = 1;\n", encoding="utf-8")
    report = AuditScanner(tmp_path).scan()
    assert report.summary.total_files_scanned == 1
    assert any("제3자" in s["reason"] for s in report.metadata["skipped_files"])
