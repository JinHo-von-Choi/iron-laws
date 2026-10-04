"""
오철칙 AI 보정·구조·타입 안전성 규칙 사례 시험
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of

LONG_FUNCTION = 'def big(x):\n    x = x + 0\n    x = x + 1\n    x = x + 2\n    x = x + 3\n    x = x + 4\n    x = x + 5\n    x = x + 6\n    x = x + 7\n    x = x + 8\n    x = x + 9\n    x = x + 10\n    x = x + 11\n    x = x + 12\n    x = x + 13\n    x = x + 14\n    x = x + 15\n    x = x + 16\n    x = x + 17\n    x = x + 18\n    x = x + 19\n    x = x + 20\n    x = x + 21\n    x = x + 22\n    x = x + 23\n    x = x + 24\n    x = x + 25\n    x = x + 26\n    x = x + 27\n    x = x + 28\n    x = x + 29\n    x = x + 30\n    x = x + 31\n    x = x + 32\n    x = x + 33\n    x = x + 34\n    x = x + 35\n    x = x + 36\n    x = x + 37\n    x = x + 38\n    x = x + 39\n    x = x + 40\n    x = x + 41\n    x = x + 42\n    x = x + 43\n    x = x + 44\n    x = x + 45\n    x = x + 46\n    x = x + 47\n    x = x + 48\n    x = x + 49\n    x = x + 50\n    x = x + 51\n    x = x + 52\n    x = x + 53\n    x = x + 54\n    x = x + 55\n    x = x + 56\n    x = x + 57\n    x = x + 58\n    x = x + 59\n    x = x + 60\n    x = x + 61\n    x = x + 62\n    x = x + 63\n    x = x + 64\n    x = x + 65\n    x = x + 66\n    x = x + 67\n    x = x + 68\n    x = x + 69\n    x = x + 70\n    x = x + 71\n    x = x + 72\n    x = x + 73\n    x = x + 74\n    x = x + 75\n    x = x + 76\n    x = x + 77\n    x = x + 78\n    x = x + 79\n    x = x + 80\n    x = x + 81\n    x = x + 82\n    x = x + 83\n    x = x + 84\n    return x\n'
DEEP_NESTING = 'def deep(a):\n    if a:\n        for i in a:\n            while i:\n                if i > 1:\n                    for j in i:\n                        if j:\n                            return j\n'
MANY_PARAMS = 'def many(a, b, c, d, e, f, g, h):\n    return a\n'


def dup_body(name: str, var: str) -> str:
    return (
        f"def {name}({var}):\n"
        f"    result = []\n"
        f"    for item in {var}:\n"
        f"        if item is not None and item.strip():\n"
        f"            cleaned = item.strip().lower().replace('-', '_')\n"
        f"            result.append(cleaned)\n"
        f"    return sorted(set(result))\n"
    )


CASES = [
    ('hard-url-localhost', 'AI-101', {'a.py': 'API = "http://localhost:3000/api"\n'}, {'a.py': [1]}),
    ('hard-url-external', 'AI-101', {'a.py': 'BASE = "https://api.service.io/v1"\n'}, {'a.py': [1]}),
    ('hard-path-home', 'AI-101', {'a.py': 'DATA = "/home/jinho/data/in.csv"\n'}, {'a.py': [1]}),
    ('hard-ip-private', 'AI-101', {'a.py': 'HOST = "192.168.0.25"\n'}, {'a.py': [1]}),
    ('hard-doc-url-in-print', 'AI-101', {'a.py': 'print("see https://docs.service.io/guide")\n'}, {}),
    ('hard-w3', 'AI-101', {'a.py': 'NS = "https://www.w3.org/2000/svg"\n'}, {}),
    ('hard-port', 'AI-101', {'a.py': 'app.run(port=5000)\n'}, {'a.py': [1]}),
    ('hard-port-env', 'AI-101', {'a.py': 'app.run(port=int(os.environ["PORT"]))\n'}, {}),
    ('fallback-py-secret', 'AI-102', {'a.py': 'SECRET = os.environ.get("SECRET_KEY", "dev-secret")\n'}, {'a.py': [1]}),
    ('fallback-py-port-ok', 'AI-102', {'a.py': 'PORT = os.environ.get("PORT", "3000")\n'}, {}),
    ('fallback-js-jwt', 'AI-102', {'a.js': 'const s = process.env.JWT_SECRET || "secret";\n'}, {'a.js': [1]}),
    ('fallback-compose', 'AI-102', {'docker-compose.yml': 'services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}\n'}, {'docker-compose.yml': [4]}),
    ('frontend-secret-openai', 'AI-103', {'.env.local': 'NEXT_PUBLIC_OPENAI_API_KEY=abc\n'}, {'.env.local': [1]}),
    ('frontend-anon-ok', 'AI-103', {'.env.local': 'NEXT_PUBLIC_SUPABASE_ANON_KEY=abc\n'}, {}),
    ('frontend-service-role', 'AI-103', {'src/app/page.tsx': '"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n'}, {'src/app/page.tsx': [2]}),
    ('envfile-committed', 'AI-104', {'.env': 'API_KEY=abcdef123456\n'}, {'.env': [1]}),
    ('envfile-ignored', 'AI-104', {'.env': 'API_KEY=abcdef123456\n', '.gitignore': '.env\n'}, {}),
    ('envfile-example', 'AI-104', {'.env.example': 'API_KEY=\n'}, {}),
    ('keyfile-committed', 'AI-104', {'id_rsa': 'x\n'}, {'id_rsa': [1]}),
    ('cors-js-default', 'AI-105', {'a.js': 'app.use(cors());\n'}, {'a.js': [1]}),
    ('cors-js-specific', 'AI-105', {'a.js': 'app.use(cors({ origin: "https://app.service.io" }));\n'}, {}),
    ('cors-py-star', 'AI-105', {'a.py': 'app.add_middleware(CORSMiddleware, allow_origins=["*"])\n'}, {'a.py': [1]}),
    ('cors-java', 'AI-105', {'A.java': '@CrossOrigin("*")\nclass A {}\n'}, {'A.java': [1]}),
    ('settings-allowed-hosts', 'AI-106', {'s.py': 'ALLOWED_HOSTS = ["*"]\n'}, {'s.py': [1]}),
    ('settings-actuator', 'AI-106', {'application.properties': 'management.endpoints.web.exposure.include=*\n'}, {'application.properties': [1]}),
    ('rls-missing', 'AI-108', {'m.sql': 'create table public.notes (id int);\n', 'c.js': "import { createClient } from '@supabase/supabase-js';\n"}, {'m.sql': [1]}),
    ('rls-enabled', 'AI-108', {'m.sql': 'create table public.notes (id int);\nalter table public.notes enable row level security;\n', 'c.js': "import { createClient } from '@supabase/supabase-js';\n"}, {}),
    ('firestore-open', 'AI-108', {'firestore.rules': 'match /a/{d} {\n  allow read, write: if true;\n}\n'}, {'firestore.rules': [2]}),
    ('clientauth', 'AI-109', {'a.js': 'if (localStorage.getItem("isAdmin") === "true") { show(); }\n'}, {'a.js': [1]}),
    ('docker-root', 'AI-110', {'Dockerfile': 'FROM python:3.12\nRUN pip install x\n'}, {'Dockerfile': [1]}),
    ('docker-user', 'AI-110', {'Dockerfile': 'FROM python:3.12\nUSER app\n'}, {}),
    ('compose-db-port', 'AI-110', {'docker-compose.yml': 'services:\n  db:\n    ports:\n      - "5432:5432"\n'}, {'docker-compose.yml': [4]}),
    ('compose-db-local', 'AI-110', {'docker-compose.yml': 'services:\n  db:\n    ports:\n      - "127.0.0.1:5432:5432"\n'}, {}),
    ('actions-injection', 'AI-110', {'.github/workflows/ci.yml': 'name: ci\njobs:\n  a:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n'}, {'.github/workflows/ci.yml': [5]}),
    ('pkg-typosquat', 'AI-111', {'package.json': '{"dependencies":{"expres":"^4.0.0"}}\n', 'package-lock.json': '{}\n'}, {'package.json': [1]}),
    ('pkg-loose', 'AI-111', {'package.json': '{"dependencies":{"express":"*"}}\n', 'package-lock.json': '{}\n'}, {'package.json': [1]}),
    ('pkg-nolock', 'AI-111', {'package.json': '{"dependencies":{"express":"^4.18.0"}}\n'}, {'package.json': [1]}),
    ('pkg-ok', 'AI-111', {'package.json': '{"dependencies":{"express":"^4.18.0"}}\n', 'package-lock.json': '{}\n'}, {}),
    ('req-typosquat', 'AI-111', {'requirements.txt': 'reqeusts==2.0.0\n'}, {'requirements.txt': [1]}),
    ('log-password', 'AI-112', {'a.py': 'def h(password):\n    logger.info(f"login {password}")\n'}, {'a.py': [2]}),
    ('log-plain', 'AI-112', {'a.py': 'def h():\n    logger.info("login ok")\n'}, {}),
    ('log-injection', 'AI-112', {'a.py': 'def h():\n    logger.info("user %s", request.args["u"])\n'}, {'a.py': [2]}),
    ('idor-django', 'AI-113', {'a.py': 'def h(request):\n    return Order.objects.get(id=request.GET["id"])\n'}, {'a.py': [2]}),
    ('idor-owner', 'AI-113', {'a.py': 'def h(request):\n    return Order.objects.get(id=request.GET["id"], user=request.user)\n'}, {}),
    ('idor-js', 'AI-113', {'a.js': 'async function f(req, res) {\n  const o = await Order.findById(req.params.id);\n  res.json(o);\n}\n'}, {'a.js': [2]}),
    ('hardening-express', 'AI-114', {'package.json': '{"dependencies":{"express":"^4.18.0"}}\n', 'package-lock.json': '{}\n'}, {'package.json': [1]}),
    ('noauth-flask', 'IL-525', {'a.py': '@app.route("/admin/delete", methods=["POST"])\ndef d():\n    return "x"\n'}, {'a.py': [2]}),
    ('noauth-flask-login', 'IL-525', {'a.py': '@app.route("/admin/delete", methods=["POST"])\n@login_required\ndef d():\n    return "x"\n'}, {}),
    ('noauth-flask-public', 'IL-525', {'a.py': '@app.route("/login", methods=["POST"])\ndef d():\n    return "x"\n'}, {}),
    ('noauth-express', 'IL-525', {'a.js': 'app.post("/users/delete", (req, res) => {\n  res.send("x");\n});\n'}, {'a.js': [1]}),
    ('noauth-express-mw', 'IL-525', {'a.js': 'app.post("/users/delete", authenticate, (req, res) => {\n  res.send("x");\n});\n'}, {}),
    ('noauth-spring', 'IL-525', {'A.java': '@RestController\nclass A {\n  @DeleteMapping("/users/{id}")\n  void d() {}\n}\n'}, {'A.java': [3]}),
    ('noauth-spring-secured', 'IL-525', {'A.java': '@RestController\nclass A {\n  @PreAuthorize("hasRole(\'ADMIN\')")\n  @DeleteMapping("/users/{id}")\n  void d() {}\n}\n'}, {}),
    ('noauth-aspnet', 'IL-525', {'A.cs': 'class A : ControllerBase {\n  [HttpDelete("users")]\n  public void D() {}\n}\n'}, {'A.cs': [2]}),
    ('size-function', 'ARC-201', {'a.py': LONG_FUNCTION}, {'a.py': [1]}),
    ('size-nesting', 'ARC-201', {'a.py': DEEP_NESTING}, {'a.py': [1]}),
    ('size-params', 'ARC-201', {'a.py': MANY_PARAMS}, {'a.py': [1]}),
    ('layer-flask-db', 'ARC-202', {'a.py': '@app.route("/x")\ndef x():\n    cursor.execute("select 1")\n'}, {'a.py': [3]}),
    ('layer-separate', 'ARC-202', {'a.py': '@app.route("/x")\ndef x():\n    return svc.get()\n', 'svc.py': 'def get():\n    cursor.execute("select 1")\n'}, {}),
    ('cycle-py', 'ARC-203', {'pkg/__init__.py': '', 'pkg/a.py': 'from pkg import b\n', 'pkg/b.py': 'from pkg import a\n'}, {'pkg/a.py': [1]}),
    ('cycle-js', 'ARC-203', {'a.js': 'import { b } from "./b";\n', 'b.js': 'import { a } from "./a";\n'}, {'a.js': [1]}),
    ('cycle-none', 'ARC-203', {'a.js': 'import { b } from "./b";\n', 'b.js': 'export const b = 1;\n'}, {}),
    ('dup-exact', 'ARC-204', {'a.py': dup_body("clean_names", "names"), 'b.py': dup_body("normalize_labels", "labels")}, {'a.py': [1]}),
    ('dup-different', 'ARC-204', {'a.py': dup_body("clean_names", "names"), 'b.py': 'def other(x):\n    total = 0\n    for i in range(x):\n        total += i * 2\n        if total > 100:\n            break\n    print(total)\n    return total\n'}, {}),
    ('repeat-literal', 'ARC-205', {'a.py': 'A = "payment_status_failed"\nB = "payment_status_failed"\n', 'b.py': 'C = "payment_status_failed"\nD = "payment_status_failed"\n'}, {'a.py': [1]}),
    ('no-tests', 'ARC-206', {'m0.py': 'def f0():\n    return 0\n', 'm1.py': 'def f1():\n    return 1\n', 'm2.py': 'def f2():\n    return 2\n', 'm3.py': 'def f3():\n    return 3\n', 'm4.py': 'def f4():\n    return 4\n'}, {'m0.py': [1]}),
    ('has-tests', 'ARC-206', {'m0.py': 'def f0():\n    return 0\n', 'm1.py': 'def f1():\n    return 1\n', 'm2.py': 'def f2():\n    return 2\n', 'm3.py': 'def f3():\n    return 3\n', 'm4.py': 'def f4():\n    return 4\n', 'test_m0.py': 'def test_a():\n    assert 1\n'}, {}),
    ('ts-any', 'TYP-301', {'a.ts': 'const x: any = 1;\n'}, {'a.ts': [1]}),
    ('ts-as-any', 'TYP-301', {'a.ts': 'const x = y as any;\n'}, {'a.ts': [1]}),
    ('ts-ignore', 'TYP-301', {'a.ts': "// @ts-ignore\nconst x: number = 'a';\n"}, {'a.ts': [1]}),
    ('ts-unknown', 'TYP-301', {'a.ts': 'const x: unknown = 1;\n'}, {}),
    ('tsconfig-nostrict', 'TYP-301', {'tsconfig.json': '{"compilerOptions": {"strict": false}}\n'}, {'tsconfig.json': [1]}),
    ('py-type-ignore', 'TYP-302', {'a.py': "x: int = 'a'  # type: ignore\n"}, {'a.py': [1]}),
    ('py-cast', 'TYP-302', {'a.py': 'y = cast(int, v)\n'}, {'a.py': [1]}),
    ('py-clean', 'TYP-302', {'a.py': 'x: int = 1\n'}, {}),
    ('java-raw', 'TYP-303', {'A.java': 'class A {\n  void m() {\n    List list = new ArrayList();\n  }\n}\n'}, {'A.java': [3]}),
    ('java-generic', 'TYP-303', {'A.java': 'class A {\n  void m() {\n    List<String> list = new ArrayList<>();\n  }\n}\n'}, {}),
    ('java-suppress', 'TYP-303', {'A.java': 'class A {\n  @SuppressWarnings("unchecked")\n  void m() {}\n}\n'}, {'A.java': [2]}),
    ('cs-dynamic', 'TYP-304', {'A.cs': 'class A {\n  void M() {\n    dynamic x = 1;\n  }\n}\n'}, {'A.cs': [3]}),
    ('cs-nullable-disable', 'TYP-304', {'A.cs': '#nullable disable\nclass A {}\n'}, {'A.cs': [1]}),
    ('go-assert', 'TYP-305', {'a.go': 'package a\nfunc f(v interface{}) {\n\tx := v.(string)\n\t_ = x\n}\n'}, {'a.go': [2, 3]}),
    ('go-assert-ok', 'TYP-305', {'a.go': 'package a\nfunc f(v interface{}) {\n\tx, ok := v.(string)\n\t_, _ = x, ok\n}\n'}, {'a.go': [2]}),
    ('rust-unsafe', 'TYP-305', {'a.rs': 'fn f() {\n    unsafe { g(); }\n}\n'}, {'a.rs': [2]}),
    ('rust-unsafe-safety', 'TYP-305', {'a.rs': 'fn f() {\n    // SAFETY: g is sound here\n    unsafe { g(); }\n}\n'}, {}),
    ('rust-unwrap', 'TYP-305', {'a.rs': 'fn f() {\n    let x = g().unwrap();\n}\n'}, {'a.rs': [2]}),
    ('php-strict', 'TYP-305', {'a.php': '<?php\nfunction f($a) { return $a; }\n'}, {'a.php': [1]}),
    ('php-loose-pw', 'TYP-305', {'a.php': '<?php\nif ($password == $input) { ok(); }\n'}, {'a.php': [2]}),
    ('js-loose', 'TYP-305', {'a.js': 'if (a == b) { go(); }\n'}, {'a.js': [1]}),
    ('layer-up-py', 'ARC-207', {'app/controllers/user.py': 'def get():\n    return 1\n', 'app/repositories/user.py': 'from app.controllers import user\n', 'app/services/user.py': 'def run():\n    return 1\n'}, {'app/repositories/user.py': [1]}),
    ('layer-clean-py', 'ARC-207', {'app/controllers/user.py': 'from app.services import user\n', 'app/services/user.py': 'from app.repositories import user\n', 'app/repositories/user.py': 'def q():\n    return 1\n'}, {}),
    ('layer-skip-py', 'ARC-207', {'app/controllers/user.py': 'from app.repositories import user\n', 'app/services/user.py': 'def run():\n    return 1\n', 'app/repositories/user.py': 'def q():\n    return 1\n'}, {'app/controllers/user.py': [1]}),
    ('layer-controller-db-js', 'ARC-207', {'src/controllers/a.ts': "import { Pool } from 'pg';\n", 'src/services/b.ts': 'export const b = 1;\n'}, {'src/controllers/a.ts': [1]}),
    ('layer-service-web-js', 'ARC-207', {'src/services/b.ts': "import express from 'express';\n", 'src/controllers/a.ts': 'export const a = 1;\n'}, {'src/services/b.ts': [1]}),
    ('layer-java-up', 'ARC-207', {'src/com/x/repository/UserRepository.java': 'package com.x.repository;\nimport com.x.controller.UserController;\nclass UserRepository {}\n', 'src/com/x/controller/UserController.java': 'package com.x.controller;\nclass UserController {}\n'}, {'src/com/x/repository/UserRepository.java': [2]}),
    ('layer-flat-project', 'ARC-207', {'a.py': 'import b\n', 'b.py': 'import sqlite3\n'}, {}),
    ('layer-entity-annotation-ok', 'ARC-207', {'src/com/x/domain/Account.java': 'package com.x.domain;\nimport org.springframework.data.annotation.Id;\nimport jakarta.persistence.Entity;\nclass Account {}\n', 'src/com/x/controller/C.java': 'package com.x.controller;\nclass C {}\n'}, {}),
    ('layer-cs-identity-ok', 'ARC-207', {'A/Services/UserService.cs': 'using Microsoft.AspNetCore.Identity;\nclass UserService {}\n', 'A/Controllers/UserController.cs': 'class UserController {}\n'}, {}),
    ('layer-cs-http-in-service', 'ARC-207', {'A/Services/UserService.cs': 'using Microsoft.AspNetCore.Http;\nclass UserService {}\n', 'A/Controllers/UserController.cs': 'class UserController {}\n'}, {'A/Services/UserService.cs': [1]}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
