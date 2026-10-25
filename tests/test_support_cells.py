"""
오철칙 지원 범위 행렬의 빈 칸(한쪽 사례만 있거나 TypeScript 사례가 없는 규칙×언어) 양성·음성 사례 시험
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from tests.helpers import lines_of, scan_files


def J(body: str) -> str:
    return (
        "class A {\n  void m(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        + body
        + "  }\n}\n"
    )


# (사례 이름, 규칙 ID, {파일: 내용}, 기대 위치 {파일: [줄 번호]})
CASES: list[tuple[str, str, dict[str, str], dict[str, list[int]]]] = [
    # 한쪽만 있던 칸
    (
        "ai101-js-pos",
        "AI-101",
        {"a.js": 'const BASE = "https://api.service.io/v1";\n'},
        {"a.js": [1]},
    ),
    (
        "ai102-js-neg",
        "AI-102",
        {
            "a.js": 'const s = process.env.JWT_SECRET;\nif (!s) throw new Error("JWT_SECRET missing");\n'
        },
        {},
    ),
    (
        "ai103-ts-neg",
        "AI-103",
        {
            "src/app/page.tsx": '"use client";\nconst k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\n'
        },
        {},
    ),
    (
        "ai105-java-neg",
        "AI-105",
        {"A.java": '@CrossOrigin("https://app.example.com")\nclass A {}\n'},
        {},
    ),
    (
        "ai109-js-neg",
        "AI-109",
        {
            "a.js": 'const r = await fetch("/api/me");\nconst me = await r.json();\nif (me.role === "admin") { show(); }\n'
        },
        {},
    ),
    (
        "ai113-js-neg",
        "AI-113",
        {
            "a.js": "async function f(req, res) {\n  const o = await Order.findOne({ _id: req.params.id, owner: req.user.id });\n  res.json(o);\n}\n"
        },
        {},
    ),
    (
        "ai120-js-neg",
        "AI-120",
        {
            "a.js": "const express = require('express');\nconst app = express();\napp.get('/r0', (req, res) => res.send(0));\napp.get('/r1', (req, res) => res.send(1));\napp.get('/r2', (req, res) => res.send(2));\napp.get('/r3', (req, res) => res.send(3));\napp.get('/r4', (req, res) => res.send(4));\napp.use((err, req, res, next) => { res.status(500).send('error'); });\n"
        },
        {},
    ),
    (
        "il101-ts-neg",
        "IL-101",
        {"a.ts": 'const password: string = process.env.DB_PASSWORD ?? "";\n'},
        {},
    ),
    (
        "il101-php-pos",
        "IL-101",
        {"a.php": '<?php\n$password = "Sup3rS3cretPassw0rd!";\n'},
        {"a.php": [2]},
    ),
    ("il105-py-neg", "IL-105", {"a.py": 'p = jwt.decode(t, key, algorithms=["HS256"])\n'}, {}),
    ("il106-js-neg", "IL-106", {"a.js": "const o = { rejectUnauthorized: true };\n"}, {}),
    (
        "il106-go-neg",
        "IL-106",
        {"a.go": "package a\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}\n"},
        {},
    ),
    (
        "il110-py-neg",
        "IL-110",
        {"a.py": "password = StringField(validators=[Length(min=12)])\n"},
        {},
    ),
    (
        "il111-py-neg",
        "IL-111",
        {"a.py": "# password is read from the PASSWORD environment variable\nx = 1\n"},
        {},
    ),
    (
        "il112-py-neg",
        "IL-112",
        {
            "a.py": 'def h(resp, sid):\n    resp.set_cookie("session", sid, httponly=True, secure=True)\n'
        },
        {},
    ),
    (
        "il301-php-neg",
        "IL-301",
        {
            "a.php": "<?php\ntry { x(); } catch (Exception $e) { error_log($e->getMessage()); throw $e; }\n"
        },
        {},
    ),
    ("il302-js-neg", "IL-302", {"a.test.js": 'it("x", () => { expect(1).toBe(1); });\n'}, {}),
    (
        "il302-java-neg",
        "IL-302",
        {"ATest.java": "class ATest {\n  @Test void t() { assertTrue(true); }\n}\n"},
        {},
    ),
    (
        "il302-cs-neg",
        "IL-302",
        {"ATests.cs": "class ATests {\n  [Fact]\n  public void T() { Assert.True(true); }\n}\n"},
        {},
    ),
    (
        "il303-js-neg",
        "IL-303",
        {
            "a.js": "function authenticate(req, res, next) {\n  if (!req.session.user) return res.status(401).end();\n  next();\n}\n"
        },
        {},
    ),
    (
        "il303-java-neg",
        "IL-303",
        {
            "A.java": "class A {\n  void c(HttpSecurity h) throws Exception {\n    h.authorizeRequests().anyRequest().authenticated();\n  }\n}\n"
        },
        {},
    ),
    (
        "il304-java-neg",
        "IL-304",
        {
            "A.java": "class A {\n  void m() {\n    try { x(); } catch (IOException e) { log.error(e); }\n  }\n}\n"
        },
        {},
    ),
    (
        "il305-py-neg",
        "IL-305",
        {
            "a.py": 'def h():\n    try:\n        x()\n    except ValueError:\n        return jsonify(error="invalid input")\n'
        },
        {},
    ),
    (
        "il305-js-neg",
        "IL-305",
        {
            "a.js": 'function f(req, res) {\n  try { x(); } catch (err) {\n    res.status(500).send("internal error");\n  }\n}\n'
        },
        {},
    ),
    (
        "il305-go-neg",
        "IL-305",
        {
            "a.go": 'package a\nfunc f(w http.ResponseWriter) {\n\thttp.Error(w, "internal error", 500)\n}\n'
        },
        {},
    ),
    (
        "il306-java-neg",
        "IL-306",
        {"ATest.java": "class ATest {\n  @Test void t() { assertEquals(1, run()); }\n}\n"},
        {},
    ),
    (
        "il306-go-neg",
        "IL-306",
        {
            "a_test.go": 'package a\nfunc TestX(t *testing.T) {\n\tif run() != 1 {\n\t\tt.Fatal("bad")\n\t}\n}\n'
        },
        {},
    ),
    (
        "il502-cs-pos",
        "IL-502",
        {
            "A.cs": 'class A : Controller {\n  public IActionResult M(string name) {\n    return Content(System.IO.File.ReadAllText("/srv/" + Request.Query["f"]));\n  }\n}\n'
        },
        {"A.cs": [3]},
    ),
    (
        "il505-java-neg",
        "IL-505",
        {
            "A.java": J(
                '    response.getWriter().println("<p>" + Encode.forHtml(request.getParameter("q")) + "</p>");\n'
            )
        },
        {},
    ),
    (
        "il507-js-neg",
        "IL-507",
        {"a.js": 'function f(req, res) {\n  res.redirect("/home");\n}\n'},
        {},
    ),
    ("il507-java-neg", "IL-507", {"A.java": J('    response.sendRedirect("/home");\n')}, {}),
    ("il509-py-neg", "IL-509", {"a.py": "p = etree.XMLParser(resolve_entities=False)\n"}, {}),
    (
        "il510-java-neg",
        "IL-510",
        {
            "A.java": "class A {\n  void c(HttpSecurity http) throws Exception {\n    http.csrf(Customizer.withDefaults());\n  }\n}\n"
        },
        {},
    ),
    (
        "il511-java-neg",
        "IL-511",
        {"A.java": J('    response.setHeader("X-Frame-Options", "DENY");\n')},
        {},
    ),
    (
        "il512-cs-pos",
        "IL-512",
        {
            "A.cs": 'class A : Controller {\n  public IActionResult M() {\n    if (Request.Cookies["role"] == "admin") { return Ok(); }\n    return Forbid();\n  }\n}\n'
        },
        {"A.cs": [3]},
    ),
    (
        "il515-java-neg",
        "IL-515",
        {
            "A.java": "class A {\n  void m(String s) throws Exception {\n    new ObjectMapper().readValue(s, Item.class);\n  }\n}\n"
        },
        {},
    ),
    (
        "il515-cs-neg",
        "IL-515",
        {
            "A.cs": "class A {\n  void M(string s) {\n    JsonSerializer.Deserialize<Item>(s);\n  }\n}\n"
        },
        {},
    ),
    (
        "il517-go-pos",
        "IL-517",
        {"a.go": "package a\nfunc f() {\n\tfor {\n\t\twork()\n\t}\n}\n"},
        {"a.go": [3]},
    ),
    ("il520-js-neg", "IL-520", {"a.js": "function f() {\n  return 1;\n}\n"}, {}),
    ("il520-php-neg", "IL-520", {"a.php": "<?php\nerror_log($x);\n"}, {}),
    (
        "il523-py-neg",
        "IL-523",
        {"a.py": "def h(ip):\n    if ip in ALLOWED_IPS:\n        return 1\n"},
        {},
    ),
    (
        "il525-cs-neg",
        "IL-525",
        {
            "A.cs": 'class A : ControllerBase {\n  [Authorize(Roles = "Admin")]\n  [HttpDelete("users")]\n  public void D() {}\n}\n'
        },
        {},
    ),
    (
        "il526-java-neg",
        "IL-526",
        {
            "A.java": 'class A {\n  void m(HttpServletRequest request, HttpSession session) {\n    session.setAttribute("u", "guest");\n  }\n}\n'
        },
        {},
    ),
    (
        "il527-java-neg",
        "IL-527",
        {
            "A.java": "class A {\n  void m(HttpServletRequest request, XPath xp) throws Exception {\n    xp.evaluate(\"/Emp/E[@id='1']\", doc);\n  }\n}\n"
        },
        {},
    ),
    (
        "il530-py-neg",
        "IL-530",
        {
            "a.py": 'ALLOWED = {".png", ".jpg"}\ndef up():\n    f = request.files["f"]\n    if os.path.splitext(f.filename)[1].lower() not in ALLOWED:\n        abort(400)\n    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))\n'
        },
        {},
    ),
    (
        "il532-js-neg",
        "IL-532",
        {
            "a.js": 'const rateLimit = require("express-rate-limit");\napp.post("/login", rateLimit({ windowMs: 60000, max: 5 }), (req, res) => { res.send(1); });\n'
        },
        {},
    ),
    ("il532-php-neg", "IL-532", {"a.php": '<?php\n$q = $_POST["query"];\n'}, {}),
    # TS 칸 (JS에서 동작하는 규칙)
    (
        "il302-ts-pos",
        "IL-302",
        {"a.test.ts": 'it.skip("x", () => { expect(1).toBe(1); });\n'},
        {"a.test.ts": [1]},
    ),
    ("il302-ts-neg", "IL-302", {"a.test.ts": 'it("x", () => { expect(1).toBe(1); });\n'}, {}),
    (
        "il303-ts-pos",
        "IL-303",
        {"a.ts": "export const isAuthenticated = (): boolean => true;\n"},
        {"a.ts": [1]},
    ),
    (
        "il303-ts-neg",
        "IL-303",
        {"a.ts": "export const isAuthenticated = (u?: User): boolean => !!u && u.active;\n"},
        {},
    ),
    (
        "il305-ts-pos",
        "IL-305",
        {
            "a.ts": "export function f(req: Request, res: Response) {\n  try { x(); } catch (err: any) {\n    res.status(500).send(err.stack);\n  }\n}\n"
        },
        {"a.ts": [3]},
    ),
    (
        "il305-ts-neg",
        "IL-305",
        {
            "a.ts": 'export function f(req: Request, res: Response) {\n  try { x(); } catch (err) {\n    res.status(500).send("internal error");\n  }\n}\n'
        },
        {},
    ),
    (
        "il507-ts-pos",
        "IL-507",
        {
            "a.ts": "export function f(req: Request, res: Response) {\n  res.redirect(req.query.url as string);\n}\n"
        },
        {"a.ts": [2]},
    ),
    (
        "il507-ts-neg",
        "IL-507",
        {"a.ts": 'export function f(req: Request, res: Response) {\n  res.redirect("/home");\n}\n'},
        {},
    ),
    (
        "il520-ts-pos",
        "IL-520",
        {"a.ts": "export function f(): number {\n  debugger;\n  return 1;\n}\n"},
        {"a.ts": [2]},
    ),
    ("il520-ts-neg", "IL-520", {"a.ts": "export function f(): number {\n  return 1;\n}\n"}, {}),
    (
        "il106-ts-pos",
        "IL-106",
        {"a.ts": "const o: https.AgentOptions = { rejectUnauthorized: false };\n"},
        {"a.ts": [1]},
    ),
    (
        "il106-ts-neg",
        "IL-106",
        {"a.ts": "const o: https.AgentOptions = { rejectUnauthorized: true };\n"},
        {},
    ),
    (
        "il501-ts-pos",
        "IL-501",
        {
            "a.ts": 'export async function f(req: Request, res: Response) {\n  await db.query("SELECT * FROM t WHERE id = " + req.query.id);\n}\n'
        },
        {"a.ts": [2]},
    ),
    (
        "il501-ts-neg",
        "IL-501",
        {
            "a.ts": 'export async function f(req: Request, res: Response) {\n  await db.query("SELECT * FROM t WHERE id = $1", [req.query.id]);\n}\n'
        },
        {},
    ),
    (
        "il504-ts-pos",
        "IL-504",
        {
            "a.ts": 'import { exec } from "child_process";\nexport function f(req: Request) {\n  exec("ls " + req.query.d);\n}\n'
        },
        {"a.ts": [3]},
    ),
    (
        "il504-ts-neg",
        "IL-504",
        {
            "a.ts": 'import { execFile } from "child_process";\nexport function f(req: Request) {\n  execFile("ls", ["--", "/srv/static"]);\n}\n'
        },
        {},
    ),
    (
        "il502-ts-pos",
        "IL-502",
        {
            "a.ts": 'import fs from "fs";\nexport function f(req: Request) {\n  return fs.readFileSync("/srv/" + req.query.f);\n}\n'
        },
        {"a.ts": [3]},
    ),
    (
        "il502-ts-neg",
        "IL-502",
        {
            "a.ts": 'import fs from "fs";\nexport function f(req: Request) {\n  return fs.readFileSync("/srv/static/index.html");\n}\n'
        },
        {},
    ),
    (
        "il506-ts-pos",
        "IL-506",
        {
            "a.ts": "export async function f(req: Request) {\n  return fetch(req.query.url as string);\n}\n"
        },
        {"a.ts": [2]},
    ),
    (
        "il506-ts-neg",
        "IL-506",
        {
            "a.ts": 'export async function f(req: Request) {\n  return fetch("https://api.example.com/v1/items");\n}\n'
        },
        {},
    ),
    (
        "il503-ts-pos",
        "IL-503",
        {
            "a.ts": "export function f(req: Request) {\n  return eval(req.query.code as string);\n}\n"
        },
        {"a.ts": [2]},
    ),
    (
        "il503-ts-neg",
        "IL-503",
        {
            "a.ts": "export function f(req: Request) {\n  return JSON.parse(req.query.code as string);\n}\n"
        },
        {},
    ),
    (
        "il505-ts-pos",
        "IL-505",
        {
            "a.ts": 'export function f(req: Request, res: Response) {\n  res.send("<p>" + req.query.q + "</p>");\n}\n'
        },
        {"a.ts": [2]},
    ),
    (
        "il505-ts-neg",
        "IL-505",
        {
            "a.ts": 'export function f(req: Request, res: Response) {\n  res.send("<p>" + escapeHtml(String(req.query.q)) + "</p>");\n}\n'
        },
        {},
    ),
    (
        "ai102-ts-pos",
        "AI-102",
        {"a.ts": 'const s: string = process.env.JWT_SECRET || "secret";\n'},
        {"a.ts": [1]},
    ),
    (
        "ai102-ts-neg",
        "AI-102",
        {
            "a.ts": 'const s = process.env.JWT_SECRET;\nif (!s) throw new Error("JWT_SECRET missing");\n'
        },
        {},
    ),
    (
        "ai109-ts-pos",
        "AI-109",
        {"a.ts": 'if (localStorage.getItem("isAdmin") === "true") { show(); }\n'},
        {"a.ts": [1]},
    ),
    (
        "ai109-ts-neg",
        "AI-109",
        {
            "a.ts": 'const me = await (await fetch("/api/me")).json();\nif (me.role === "admin") { show(); }\n'
        },
        {},
    ),
    (
        "ai113-ts-pos",
        "AI-113",
        {
            "a.ts": "export async function f(req: Request, res: Response) {\n  const o = await Order.findById(req.params.id);\n  res.json(o);\n}\n"
        },
        {"a.ts": [2]},
    ),
    (
        "ai113-ts-neg",
        "AI-113",
        {
            "a.ts": "export async function f(req: Request, res: Response) {\n  const o = await Order.findOne({ _id: req.params.id, owner: req.user.id });\n  res.json(o);\n}\n"
        },
        {},
    ),
    (
        "il532-ts-pos",
        "IL-532",
        {"a.ts": 'app.post("/login", (req: Request, res: Response) => { res.send(1); });\n'},
        {"a.ts": [1]},
    ),
    (
        "il532-ts-neg",
        "IL-532",
        {"a.ts": 'app.post("/items", (req: Request, res: Response) => { res.send(1); });\n'},
        {},
    ),
    (
        "il101-ts-pos",
        "IL-101",
        {"a.ts": 'const password: string = "ActualHardcodedPassword123!";\n'},
        {"a.ts": [1]},
    ),
    (
        "il301-ts-pos",
        "IL-301",
        {"a.ts": "export function f(): void {\n  try { x(); } catch (e) { }\n}\n"},
        {"a.ts": [2]},
    ),
    (
        "il301-ts-neg",
        "IL-301",
        {
            "a.ts": "export function f(): void {\n  try { x(); } catch (e) { logger.error(e); throw e; }\n}\n"
        },
        {},
    ),
    ("il306-ts-pos", "IL-306", {"a.test.ts": 'it("x", () => { run(); });\n'}, {"a.test.ts": [1]}),
    ("il306-ts-neg", "IL-306", {"a.test.ts": 'it("x", () => { expect(run()).toBe(1); });\n'}, {}),
    (
        "il511-ts-pos",
        "IL-511",
        {
            "a.ts": 'export function f(req: Request, res: Response) {\n  res.setHeader("X", req.query.v as string);\n}\n'
        },
        {"a.ts": [2]},
    ),
    (
        "il511-ts-neg",
        "IL-511",
        {
            "a.ts": 'export function f(req: Request, res: Response) {\n  res.setHeader("X-Frame-Options", "DENY");\n}\n'
        },
        {},
    ),
    (
        "il511-js-pos",
        "IL-511",
        {"a.js": 'function f(req, res) {\n  res.setHeader("X", req.query.v);\n}\n'},
        {"a.js": [2]},
    ),
    (
        "il511-js-neg",
        "IL-511",
        {"a.js": 'function f(req, res) {\n  res.setHeader("X-Frame-Options", "DENY");\n}\n'},
        {},
    ),
    (
        "ai101-ts-pos",
        "AI-101",
        {"a.ts": 'export const BASE: string = "https://api.service.io/v1";\n'},
        {"a.ts": [1]},
    ),
    (
        "ai101-ts-neg",
        "AI-101",
        {"a.ts": 'export const BASE: string = process.env.API_BASE ?? "";\n'},
        {},
    ),
    (
        "il512-js-pos",
        "IL-512",
        {
            "a.js": 'function f(req, res) {\n  if (req.cookies.role === "admin") { res.send(1); }\n}\n'
        },
        {"a.js": [2]},
    ),
    (
        "il512-js-neg",
        "IL-512",
        {
            "a.js": 'function f(req, res) {\n  if (req.session.user.role === "admin") { res.send(1); }\n}\n'
        },
        {},
    ),
    (
        "il517-js-pos",
        "IL-517",
        {"a.js": "function f() {\n  while (true) {\n    work();\n  }\n}\n"},
        {"a.js": [2]},
    ),
    (
        "il517-js-neg",
        "IL-517",
        {"a.js": "function f(n) {\n  while (n > 0) {\n    n--;\n  }\n}\n"},
        {},
    ),
    ("il101-py-bypass-ratio", "IL-101", {"a.py": 'row = {"bypass_rejected": "34/34", "passed_count": "12/12"}\n'}, {}),
    ("il101-py-fstring-placeholders", "IL-101", {"a.py": 'row = {"bypass_rejected": f"{bypass_hit}/{bypass_n}"}\n'}, {}),
    ("il101-py-password-still-found", "IL-101", {"a.py": 'cfg = {"bypass_password": "Zq9xKm2LpQw8RtYu"}\n'}, {"a.py": [1]}),
]


@pytest.mark.parametrize(
    ("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES]
)
def test_support_cell_case(
    tmp_path: Path,
    case_id: str,
    rule_id: str,
    files: dict[str, str],
    expected: dict[str, list[int]],
):
    violations = scan_files(tmp_path, files)
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
