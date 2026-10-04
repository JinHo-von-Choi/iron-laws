"""
오철칙 검토자 지적 항목 규칙 사례 시험 (업로드, 로그인 제한, 자체 토큰, 예외 처리기, 버전, 권한, 구조)
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner
from tests.helpers import lines_of

UPLOAD_JAVA = (
    "class U {\n"
    "  void up(MultipartFile file) throws Exception {\n"
    '    if (file.getContentType().equals("image/png")) {\n'
    '      file.transferTo(new File("a"));\n'
    "    }\n"
    "  }\n"
    "}\n"
)
UPLOAD_JAVA_OK = (
    "class U {\n"
    "  void up(MultipartFile file) throws Exception {\n"
    "    Tika tika = new Tika();\n"
    '    if (allowedExtensions.contains(ext) && tika.detect(file.getInputStream()).equals("image/png")) {\n'
    '      file.transferTo(new File("a"));\n'
    "    }\n"
    "  }\n"
    "}\n"
)
TOKEN_JAVA = (
    "class TokenService {\n"
    "  String sign(String d) throws Exception {\n"
    '    Mac mac = Mac.getInstance("HmacSHA256");\n'
    "    return d;\n"
    "  }\n"
    "  String[] parse(String t) {\n"
    '    return t.split("\\\\|");\n'
    "  }\n"
    "}\n"
)


def _error_files(count_files: int, per_file: int) -> dict[str, str]:
    files = {}
    n = 0
    for i in range(count_files):
        body = ""
        for _ in range(per_file):
            body += f'    throw new IllegalStateException("처리할 수 없는 상태 번호 {n}");\n'
            n += 1
        files[f"E{i}.java"] = f"class E{i} {{\n  void m() {{\n{body}  }}\n}}\n"
    return files


def _attr_files() -> dict[str, str]:
    return {f"{n}.java": f'class {n} {{\n  void m(HttpServletRequest request, Object a) {{\n    request.setAttribute("adminUser", a);\n  }}\n}}\n' for n in "ABC"}


CASES = [
    ("upload-client-type", "IL-530", {"U.java": UPLOAD_JAVA}, {"U.java": [2, 3]}),
    ("upload-verified", "IL-530", {"U.java": UPLOAD_JAVA_OK}, {}),
    ("upload-py-no-allowlist", "IL-530", {"a.py": 'def up():\n    f = request.files["f"]\n    f.save("x")\n'}, {"a.py": [2]}),
    ("login-no-limit-py", "IL-532", {"a.py": '@app.post("/login")\ndef login(u, p):\n    return 1\n'}, {"a.py": [2]}),
    ("login-limited-py", "IL-532", {"a.py": '@app.post("/login")\ndef login(u, p):\n    return 1\n', "b.py": "from slowapi import Limiter\n"}, {}),
    ("login-no-limit-js", "IL-532", {"a.js": 'app.post("/login", (req, res) => { res.send(1); });\n'}, {"a.js": [1]}),
    ("custom-token", "AI-118", {"TokenService.java": TOKEN_JAVA}, {"TokenService.java": [3]}),
    ("custom-token-jwt-lib", "AI-118", {"TokenService.java": "import io.jsonwebtoken.Jwts;\n" + TOKEN_JAVA}, {}),
    ("no-spring-security", "AI-119", {"pom.xml": "<project>\n<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n</project>\n", "F.java": "class F extends OncePerRequestFilter {}\n"}, {"pom.xml": [2]}),
    ("with-spring-security", "AI-119", {"pom.xml": "<project>\n<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n<dependency><artifactId>spring-boot-starter-security</artifactId></dependency>\n</project>\n", "F.java": "class F extends OncePerRequestFilter {}\n"}, {}),
    ("no-global-handler", "AI-120", {f"{n}.java": f"@RestController\nclass {n} {{}}\n" for n in "ABC"}, {"A.java": [1]}),
    ("global-handler", "AI-120", {**{f"{n}.java": f"@RestController\nclass {n} {{}}\n" for n in "ABC"}, "H.java": "@RestControllerAdvice\nclass H {}\n"}, {}),
    ("express-no-error-mw", "AI-120", {"a.js": "const express = require('express');\nconst app = express();\n" + "".join(f"app.get('/r{i}', (req, res) => res.send({i}));\n" for i in range(5))}, {"a.js": [1]}),
    ("single-admin-role", "AI-122", {f"{n}.java": f'class {n} {{\n  @PreAuthorize("hasRole(\'ADMIN\')")\n  void m() {{}}\n}}\n' for n in "ABC"}, {"A.java": [2]}),
    ("multiple-roles", "AI-122", {**{f"{n}.java": f'class {n} {{\n  @PreAuthorize("hasRole(\'ADMIN\')")\n  void m() {{}}\n}}\n' for n in "AB"}, "C.java": 'class C {\n  @PreAuthorize("hasRole(\'FINANCE\')")\n  void m() {}\n}\n'}, {}),
    ("version-mismatch-java", "AI-121", {"pom.xml": "<project>\n<java.version>17</java.version>\n</project>\n", "Dockerfile": "FROM eclipse-temurin:21-jre\nUSER app\n"}, {"Dockerfile": [1]}),
    ("version-doc-mismatch", "AI-121", {"pom.xml": "<project>\n<java.version>17</java.version>\n</project>\n", "README.md": "이 서비스는 Java 21에서 동작한다.\n"}, {"pom.xml": [2]}),
    ("version-consistent", "AI-121", {"pom.xml": "<project>\n<java.version>17</java.version>\n</project>\n", "Dockerfile": "FROM eclipse-temurin:17-jre\nUSER app\n"}, {}),
    ("version-python-mismatch", "AI-121", {".python-version": "3.12\n", "Dockerfile": "FROM python:3.11-slim\nUSER app\n"}, {".python-version": [1]}),
    ("version-policy", "AI-121", {".iron-laws.yml": 'policies:\n  min_versions:\n    spring-boot: "4.0.8"\n', "pom.xml": "<project>\n<parent>\n<artifactId>spring-boot-starter-parent</artifactId>\n<version>3.2.0</version>\n</parent>\n</project>\n"}, {"pom.xml": [4]}),
    ("version-old-spring", "AI-121", {"pom.xml": "<project>\n<parent>\n<artifactId>spring-boot-starter-parent</artifactId>\n<version>2.7.0</version>\n</parent>\n</project>\n"}, {"pom.xml": [4]}),
    ("dto-map-mix", "ARC-208", {"A.java": "class A {\n  Map<String, Object> a(Map<String, Object> x) { return x; }\n  Map<String, Object> b() { return null; }\n  void c(HashMap<String, Object> y) {}\n}\n"}, {"A.java": [2]}),
    ("dto-clean", "ARC-208", {"A.java": "class A {\n  Dto a(Dto x) { return x; }\n}\n"}, {}),
    ("error-scatter", "ARC-209", _error_files(3, 4), {"E0.java": [3]}),
    ("error-central", "ARC-209", {**_error_files(3, 4), "ErrorCode.java": "enum ErrorCode { A }\n"}, {}),
    ("attribute-keys", "ARC-210", _attr_files(), {"A.java": [3]}),
    ("reusable-java", "ARC-211", {"A.java": 'class A {\n  boolean m(String s) {\n    return Pattern.compile("a+b").matcher(s).matches();\n  }\n}\n'}, {"A.java": [3]}),
    ("reusable-static-field", "ARC-211", {"A.java": 'class A {\n  static final Pattern P = Pattern.compile("a+b");\n}\n'}, {}),
    ("reusable-py", "ARC-211", {"a.py": 'import re\ndef f(x):\n    return re.compile("a+").match(x)\n'}, {"a.py": [3]}),
    ("reusable-py-module", "ARC-211", {"a.py": 'import re\nPATTERN = re.compile("a+")\n'}, {}),
    ("db-in-loop", "ARC-212", {"A.java": "class A {\n  void m(List<Long> ids) {\n    for (Long id : ids) {\n      repo.findById(id);\n    }\n  }\n}\n"}, {"A.java": [4]}),
    ("db-outside-loop", "ARC-212", {"A.java": "class A {\n  void m(List<Long> ids) {\n    repo.findAllById(ids);\n  }\n}\n"}, {}),
    ("db-in-filter", "ARC-212", {"F.java": "class F extends OncePerRequestFilter {\n  void doFilterInternal(HttpServletRequest r) {\n    adminIpRepository.findAll();\n  }\n}\n"}, {"F.java": [3]}),
]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_review_case(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[int]]):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    violations = AuditScanner(tmp_path).scan().violations
    actual = {path: lines_of(violations, rule_id, path) for path in files}
    actual = {p: ls for p, ls in actual.items() if ls}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
