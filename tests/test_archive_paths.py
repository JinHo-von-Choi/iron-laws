"""
오철칙 압축 해제 경로 조작(Zip Slip)과 프레임워크 요청 경로 시험: 압축 항목 이름을 외부 입력으로 보고, 올바른 기준 폴더 검사는 인정한다
작성자: 최진호
작성일: 2026-10-12
"""

from pathlib import Path

import pytest

from iron_laws.core.models import Confidence
from tests.helpers import scan_files

ZIP = "import java.io.*;\nimport java.nio.file.*;\nimport java.util.zip.*;\n\nclass Z {\n  void unzip(InputStream in, File dir) throws IOException {\n    ZipInputStream zip = new ZipInputStream(in);\n    ZipEntry entry;\n    while ((entry = zip.getNextEntry()) != null) {\n"
END = "    }\n  }\n}\n"

# (사례 이름, {파일: 내용}, 지적이 있어야 하는가)
CASES = [
    # 압축 항목 이름이 그대로 경로가 된다
    ("java-zip-slip", {"Z.java": ZIP + "      File f = new File(dir, entry.getName());\n      new FileOutputStream(f).close();\n" + END}, True),
    ("java-zip-slip-files-copy", {"Z.java": ZIP + "      Files.copy(zip, dir.toPath().resolve(entry.getName()));\n" + END}, True),
    ("java-jar-enumeration", {"J.java": "import java.io.*;\nimport java.util.*;\nimport java.util.jar.*;\n\nclass J {\n  void list(JarFile jar, File dir) throws IOException {\n    Enumeration<JarEntry> entries = jar.entries();\n    while (entries.hasMoreElements()) {\n      JarEntry e = entries.nextElement();\n      new FileOutputStream(new File(dir, e.getName())).close();\n    }\n  }\n}\n"}, True),
    # 정규화한 경로가 기준 폴더 안인지 반복마다 검사하고 벗어나면 거부한다
    ("java-zip-guard-in-loop", {"Z.java": ZIP + "      File f = new File(dir, entry.getName());\n      if (!f.toPath().normalize().startsWith(dir.toPath().normalize())) {\n        throw new IOException(\"bad entry\");\n      }\n      new FileOutputStream(f).close();\n" + END}, False),
    ("java-zip-guard-canonical-alias", {"Z.java": ZIP + "      File f = new File(dir, entry.getName());\n      String canonical = f.getCanonicalPath();\n      if (!canonical.startsWith(dir.getCanonicalPath() + File.separator)) {\n        throw new IOException(\"bad entry\");\n      }\n      new FileOutputStream(f).close();\n" + END}, False),
    ("java-zip-guard-inline-check", {"Z.java": ZIP + "      String target = dir.getPath() + File.separator + entry.getName();\n      if (!new File(target).getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)) {\n        throw new IOException(\"bad entry\");\n      }\n      new FileOutputStream(target).close();\n" + END}, False),
    # 검사가 다른 분기 안에만 있으면 인정하지 않는다
    ("java-zip-guard-in-other-branch", {"Z.java": ZIP + "      File f = new File(dir, entry.getName());\n      if (entry.isDirectory()) {\n        if (!f.toPath().normalize().startsWith(dir.toPath())) {\n          throw new IOException(\"bad entry\");\n        }\n      }\n      new FileOutputStream(f).close();\n" + END}, True),
    # 파일 이름만 남기면 경로 정보가 없다
    ("java-new-file-getname", {"F.java": "import java.io.*;\nimport javax.servlet.http.*;\n\nclass F {\n  File get(HttpServletRequest request, File logDir) {\n    String name = new File(request.getParameter(\"f\")).getName();\n    return new File(logDir, name);\n  }\n}\n"}, False),
    # File.getName()은 압축 API가 없는 파일에서 여전히 정제다
    ("java-file-getname-outside-archive", {"G.java": "import java.io.*;\n\nclass G {\n  void copy(File src, File dir) throws IOException {\n    new FileOutputStream(new File(dir, src.getName())).close();\n  }\n}\n"}, False),
    # Files.copy의 스트림 인자는 경로가 아니다
    ("java-files-copy-stream-arg", {"C.java": ZIP + "      Path target = dir.toPath().resolve(\"fixed.txt\");\n      Files.copy(zip, target);\n" + END}, False),
    # 내용 인자를 빼는 것은 Files.copy·Files.write의 자리로만 정한다. 이름이 data인 경로 변수는 경로다
    ("java-files-read-path-named-data", {"R.java": "import java.nio.file.*;\nimport javax.servlet.http.*;\n\nclass R {\n  byte[] read(HttpServletRequest request, Path base) throws Exception {\n    Path data = base.resolve(request.getParameter(\"p\"));\n    return Files.readAllBytes(data);\n  }\n}\n"}, True),
    # 정규화 별칭에 다른 값을 다시 넣고 검사하면 원래 경로의 검사가 아니다
    ("java-canonical-alias-reassigned", {"A.java": "import java.io.*;\nimport javax.servlet.http.*;\n\nclass A {\n  void m(HttpServletRequest request) throws Exception {\n    File f = new File(\"/srv/safe\", request.getParameter(\"p\"));\n    String c = f.getCanonicalPath();\n    c = \"/srv/safe/x\";\n    if (!c.startsWith(\"/srv/safe/\")) {\n      throw new SecurityException();\n    }\n    new FileInputStream(f).close();\n  }\n}\n"}, True),
    # 열거 변수 이름이 entries가 아니어도 압축 항목이다
    ("java-zip-enumeration-any-name", {"E.java": "import java.io.*;\nimport java.util.*;\nimport java.util.zip.*;\n\nclass E {\n  void x(ZipFile zip, File base) throws IOException {\n    Enumeration<? extends ZipEntry> items = zip.entries();\n    while (items.hasMoreElements()) {\n      ZipEntry e = items.nextElement();\n      new FileOutputStream(new File(base, e.getName())).close();\n    }\n  }\n}\n"}, True),
    # Python zipfile·tarfile
    ("py-zipfile-namelist", {"a.py": "import os\nimport zipfile\n\ndef unpack(path, dest):\n    with zipfile.ZipFile(path) as z:\n        for name in z.namelist():\n            with open(os.path.join(dest, name), 'wb') as out:\n                out.write(z.read(name))\n"}, True),
    ("py-zipfile-namelist-confined", {"a.py": "import os\nimport zipfile\n\ndef unpack(path, dest):\n    base = os.path.realpath(dest)\n    with zipfile.ZipFile(path) as z:\n        for name in z.namelist():\n            target = os.path.realpath(os.path.join(base, name))\n            if not target.startswith(base + os.sep):\n                raise ValueError(name)\n            with open(target, 'wb') as out:\n                out.write(z.read(name))\n"}, False),
    # JavaScript adm-zip
    ("js-adm-zip-entry-name", {"a.js": "const AdmZip = require('adm-zip');\nconst fs = require('fs');\nconst path = require('path');\nfunction unpack(file, dest) {\n  for (const entry of new AdmZip(file).getEntries()) {\n    fs.writeFileSync(path.join(dest, entry.entryName), entry.getData());\n  }\n}\n"}, True),
    # 웹 프레임워크의 요청 경로
    ("java-flink-path-parameter", {"H.java": "import java.io.*;\n\nclass H {\n  File getFile(HandlerRequest handlerRequest, File logDir) {\n    String filename = handlerRequest.getPathParameter(LogFileNamePathParameter.class);\n    return new File(logDir, filename);\n  }\n}\n"}, True),
    ("java-vertx-normalised-path", {"V.java": "import java.io.*;\n\nclass V {\n  void handle(RoutingContext context, File root) throws IOException {\n    String path = context.normalisedPath();\n    new FileInputStream(new File(root, path)).close();\n  }\n}\n"}, True),
    ("java-undertow-relative-path", {"U.java": "import java.io.*;\n\nclass U {\n  void handleRequest(HttpServerExchange exchange, File root) throws IOException {\n    new FileInputStream(new File(root, exchange.getRelativePath())).close();\n  }\n}\n"}, True),
]


@pytest.mark.parametrize(("name", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_archive_and_framework_paths(tmp_path: Path, name: str, files: dict[str, str], expected: bool):
    found = [v for v in scan_files(tmp_path, files) if v.rule_id == "IL-502" and v.confidence is Confidence.CONFIRMED]
    assert bool(found) is expected, f"{name}: {[(v.file_path.as_posix(), v.line_number) for v in found]}"


def test_archive_names_are_not_sources_without_archive_imports(tmp_path: Path):
    """getName()은 흔한 이름이라 압축·메일 API를 가져온 파일에서만 외부 입력으로 본다"""
    code = "import java.io.*;\n\nclass P {\n  void save(Plugin entry, File dir) throws IOException {\n    new FileOutputStream(new File(dir, entry.getName())).close();\n  }\n}\n"
    assert not [v for v in scan_files(tmp_path, {"P.java": code}) if v.rule_id == "IL-502" and v.confidence is Confidence.CONFIRMED]


SERVLET = "import java.io.*;\nimport javax.servlet.http.*;\n\nclass S {\n  void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {\n"
XSS_CASES = [
    ("java-jsonp-callback-output-stream", SERVLET + "    String callback = req.getParameter(\"callback\");\n    resp.setContentType(\"text/javascript\");\n    OutputStream out = resp.getOutputStream();\n    out.write((callback + \"({});\").getBytes(\"UTF-8\"));\n  }\n}\n", True),
    ("java-writer-variable-html", SERVLET + "    PrintWriter w = resp.getWriter();\n    w.println(\"<p>\" + req.getParameter(\"q\") + \"</p>\");\n  }\n}\n", True),
    ("java-writer-variable-escaped", SERVLET + "    PrintWriter w = resp.getWriter();\n    w.println(\"<p>\" + Encode.forHtml(req.getParameter(\"q\")) + \"</p>\");\n  }\n}\n", False),
    ("java-writer-variable-json", SERVLET + "    resp.setContentType(\"application/json\");\n    PrintWriter w = resp.getWriter();\n    w.print(\"{\\\"q\\\": \\\"\" + req.getParameter(\"q\") + \"\\\"}\");\n  }\n}\n", False),
    ("java-printf-format-argument", SERVLET + "    resp.setContentType(\"text/html\");\n    PrintWriter out = resp.getWriter();\n    out.printf(\"<p>%s</p>\", req.getParameter(\"q\"));\n  }\n}\n", True),
    ("java-json-word-in-comment-only", SERVLET + "    // 클라이언트는 application/json도 지원한다\n    PrintWriter out = resp.getWriter();\n    out.print(\"<p>\" + req.getParameter(\"q\") + \"</p>\");\n  }\n}\n", True),
    ("java-json-chained-writer", SERVLET + "    resp.setContentType(\"application/json\");\n    resp.getWriter().print(\"{\\\"q\\\":\\\"\" + req.getParameter(\"q\") + \"\\\"}\");\n  }\n}\n", False),
    ("java-json-only-in-other-branch", SERVLET + "    if (\"json\".equals(req.getParameter(\"format\"))) {\n      resp.setContentType(\"application/json\");\n      resp.getWriter().write(\"{}\");\n    } else {\n      PrintWriter out = resp.getWriter();\n      out.write(\"<p>\" + req.getParameter(\"name\") + \"</p>\");\n    }\n  }\n}\n", True),
    ("java-writer-variable-constant", SERVLET + "    PrintWriter w = resp.getWriter();\n    w.println(\"<p>ok</p>\");\n  }\n}\n", False),
]


@pytest.mark.parametrize(("name", "code", "expected"), XSS_CASES, ids=[c[0] for c in XSS_CASES])
def test_java_response_stream_variables_are_xss_sinks(tmp_path: Path, name: str, code: str, expected: bool):
    found = [v for v in scan_files(tmp_path, {"S.java": code}) if v.rule_id == "IL-505" and v.confidence is Confidence.CONFIRMED]
    assert bool(found) is expected, f"{name}: {[v.line_number for v in found]}"


def test_writer_variables_are_scoped_to_their_function(tmp_path: Path):
    code = (
        "import java.io.*;\nimport javax.servlet.http.*;\n\nclass L {\n"
        "  void respond(HttpServletResponse resp) throws Exception {\n    PrintWriter out = resp.getWriter();\n    out.print(\"ok\");\n  }\n"
        "  void log(HttpServletRequest req) throws Exception {\n    PrintWriter out = new PrintWriter(\"audit.log\");\n    out.print(req.getParameter(\"q\"));\n  }\n}\n"
    )
    assert not [v for v in scan_files(tmp_path, {"L.java": code}) if v.rule_id == "IL-505" and v.confidence is Confidence.CONFIRMED]
