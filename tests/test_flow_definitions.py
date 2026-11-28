"""
오철칙 입력 원천·싱크·정제 정의 시험: 바뀐 정의마다 지적해야 할 코드와 지적하지 말아야 할 코드를 함께 둔다
작성자: 최진호
작성일: 2026-11-24
"""

from pathlib import Path

import pytest

from iron_laws.core.scanner import AuditScanner

FLASK = "from flask import Flask, request\n\napp = Flask(__name__)\n\n\n"

# (사례 ID, 규칙, 파일, 기대: 파일 → [(줄, 확정 여부)])
CASES = [
    (
        # 호출하는 곳에서 구분자 없는 접두사 비교만 거친 경로는 도우미 함수 안의 싱크도 확인 필요다. 검사 없이 넘기는 호출이 하나라도 있으면 확정이다
        "py-helper-after-prefix-compare",
        "IL-502",
        {
            "files.py": "def read(path):\n    with open(path) as f:\n        return f.read()\n",
            "a.py": FLASK + 'import os\nfrom files import read\n\nBASE = "/data/app"\n\n\ndef local_read(path):\n    with open(path) as f:\n        return f.read()\n\n\n'
            '@app.route("/a")\ndef a():\n    p = os.path.realpath(os.path.join(BASE, request.args["name"]))\n    if not p.startswith(BASE):\n        return ""\n    return read(p) + local_read(p)\n',
            "b.py": FLASK + 'from files import read\n\n\ndef local_read(path):\n    with open(path) as f:\n        return f.read()\n\n\n'
            '@app.route("/b")\ndef b():\n    return read(request.args["n"]) + local_read(request.args["n"])\n',
        },
        {"a.py": [(13, "REVIEW"), (19, "REVIEW"), (22, "REVIEW")], "b.py": [(10, "CONFIRMED"), (16, "CONFIRMED")]},
    ),
    (
        "py-codecs-open-path",
        "IL-502",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    import codecs\n    name = request.args.get("n")\n    return codecs.open(f"/srv/{name}", "r", "utf-8").read()\n'},
        {"a.py": [(10, "CONFIRMED")]},
    ),
    (
        "py-codecs-open-encoding-only",
        "IL-502",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    import codecs\n    return codecs.open("/srv/static.txt", "r", request.args.get("enc")).read()\n'},
        {},
    ),
    (
        "py-path-exists",
        "IL-502",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    import os\n    import pathlib\n    doc = request.query_string.decode()\n    if os.path.exists("/srv/" + doc):\n        return "1"\n    target = pathlib.Path("/srv") / doc\n    return "2" if target.exists() else "3"\n'},
        {"a.py": [(11, "CONFIRMED"), (14, "CONFIRMED")]},
    ),
    (
        "py-queryset-exists",
        "IL-502",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    rows = Member.objects.filter(nick=request.args.get("n"))\n    return "taken" if rows.exists() else "free"\n'},
        {},
    ),
    (
        "py-redirect-module-alias",
        "IL-507",
        {"a.py": 'import flask as fl\nfrom django import shortcuts\nfrom flask import request\n\n\ndef a():\n    return fl.redirect(request.args.get("next"))\n\n\ndef b():\n    return shortcuts.redirect(request.args.get("next"))\n'},
        {"a.py": [(7, "CONFIRMED"), (11, "CONFIRMED")]},
    ),
    (
        "py-redirect-other-module",
        "IL-507",
        {"a.py": 'import routing\nfrom flask import request\n\n\ndef a():\n    return routing.redirect(request.args.get("next"))\n'},
        {},
    ),
    (
        "py-session-key-value-update",
        "IL-526",
        {"a.py": 'import flask\nfrom flask import request\n\n\ndef a():\n    slot = request.args.get("k")\n    flask.session[slot] = "1"\n    flask.session["who"] = request.form["u"]\n    flask.session.update({"n": request.args.get("n")})\n'},
        {"a.py": [(7, "CONFIRMED"), (8, "CONFIRMED"), (9, "CONFIRMED")]},
    ),
    (
        "py-session-html-escape-is-not-validation",
        "IL-526",
        {"a.py": 'import html\nfrom flask import request, session\nfrom markupsafe import escape\n\n\ndef a():\n    nick = escape(request.form["nick"])\n    session["nick"] = nick\n    session["title"] = html.escape(request.args.get("t"))\n    session["age"] = int(request.args.get("age"))\n'},
        {"a.py": [(8, "CONFIRMED"), (9, "CONFIRMED")]},
    ),
    (
        "py-session-from-other-module",
        "IL-526",
        {"a.py": 'from flask import request\nfrom store import session\n\n\ndef a():\n    session["who"] = request.form["u"]\n'},
        {},
    ),
    (
        "py-xpath-selector-and-object",
        "IL-527",
        {"a.py": 'import elementpath\nfrom flask import request\nfrom lxml import etree\n\n\ndef a(root):\n    who = request.args.get("id")\n    return elementpath.select(root, f"/staff/member[@no=\'{who}\']")\n\n\ndef b(root):\n    who = request.args.get("id")\n    run = etree.XPath(f"/staff/member[@no=\'{who}\']")\n    return run(root)\n'},
        {"a.py": [(8, "CONFIRMED"), (14, "CONFIRMED")]},
    ),
    (
        "py-xpath-stringio-query",
        "IL-527",
        {"a.py": 'import io\nfrom flask import request\n\n\ndef a(root):\n    who = request.args.get("id")\n    buf = io.StringIO()\n    buf.write("/staff/member[@no=\'")\n    buf.write(who)\n    buf.write("\']")\n    expr = buf.getvalue()\n    return root.xpath(expr)\n'},
        {"a.py": [(12, "CONFIRMED")]},
    ),
    (
        "py-xpath-fixed-query-dynamic-document",
        "IL-527",
        {"a.py": 'from flask import request\nfrom lxml import etree\n\n\ndef a():\n    doc = etree.fromstring(request.data)\n    run = etree.XPath("/staff/member[@no=$no]")\n    return run(doc, no=request.args.get("id"))\n'},
        {},
    ),
    (
        "py-flask-route-returns-text",
        "IL-505",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    page = ""\n    page += f"Hello {request.args.get(\'n\')}"\n    return page\n\n\n@app.route("/b")\ndef b():\n    return b_inner()\n\n\ndef b_inner():\n    return "Hi %s" % request.form["n"]\n'},
        {"a.py": [(10, "CONFIRMED"), (19, "CONFIRMED")]},
    ),
    (
        "py-flask-partial-escape",
        "IL-505",
        {"a.py": FLASK + 'from html import escape\n\n\n@app.route("/a")\ndef a():\n    return f"{escape(request.args.get(\'x\'))} {request.args.get(\'y\')}"\n'},
        {"a.py": [(11, "CONFIRMED")]},
    ),
    (
        "py-flask-plain-text-and-helper",
        "IL-505",
        {"a.py": FLASK + '@app.route("/a")\ndef a():\n    return f"Hello {request.args.get(\'n\')}", 200, {"Content-Type": "text/plain"}\n\n\ndef label(v):\n    return "value: " + v\n\n\n@app.route("/c")\ndef c():\n    from html import escape\n    return f"Hello {escape(request.args.get(\'n\'))}"\n'},
        {},
    ),
    (
        "py-deserialize-by-data-reach",
        "IL-515",
        {"a.py": 'import pickle\n\nfrom flask import request\n\n\ndef a():\n    return pickle.loads(request.data)\n\n\ndef b():\n    token = "fixed"\n    return pickle.loads(token.encode())\n\n\ndef c(path):\n    with open(path, "rb") as fh:\n        return pickle.load(fh)\n\n\ndef d():\n    import html\n    return pickle.loads(html.escape(request.args.get("p")).encode())\n'},
        {"a.py": [(7, "CONFIRMED"), (17, "REVIEW"), (22, "CONFIRMED")]},
    ),
    (
        "py-xxe-parser-input",
        "IL-509",
        {"a.py": 'import xml.dom.minidom\nimport xml.sax\nimport xml.sax.handler\n\nfrom flask import request\nfrom lxml import etree\n\n\ndef a():\n    rdr = xml.sax.make_parser()\n    rdr.setFeature(xml.sax.handler.feature_external_ges, True)\n    return xml.dom.minidom.parseString(request.data, rdr)\n\n\ndef b():\n    rdr = xml.sax.make_parser()\n    rdr.setFeature(xml.sax.handler.feature_external_ges, True)\n    return xml.dom.minidom.parseString("<a/>", rdr)\n\n\ndef c(text):\n    return etree.fromstring(text, etree.XMLParser(resolve_entities=True))\n'},
        {"a.py": [(12, "CONFIRMED"), (22, "REVIEW")]},
    ),
    (
        "java-jdbc-call-batch-rowset",
        "IL-501",
        {"A.java": 'import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\nclass A {\n    void a(HttpServletRequest request, java.sql.Connection connection) throws Exception {\n        String proc = "{call " + request.getParameter("p") + "}";\n        java.sql.CallableStatement cs = connection.prepareCall(proc);\n        cs.executeQuery();\n    }\n\n    void b(HttpServletRequest request, java.sql.Statement statement) throws Exception {\n        String q = "UPDATE item SET qty = 1 WHERE name = \'" + request.getParameter("n") + "\'";\n        statement.addBatch(q);\n        statement.executeBatch();\n    }\n\n    void c(HttpServletRequest request, org.springframework.jdbc.core.JdbcTemplate template) {\n        template.queryForRowSet("SELECT * FROM item WHERE name = \'" + request.getParameter("n") + "\'");\n    }\n}\n'},
        {"A.java": [(7, "CONFIRMED"), (13, "CONFIRMED"), (18, "CONFIRMED")]},
    ),
    (
        "java-html-escape-contexts",
        "IL-505",
        {"A.java": 'import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\nclass A {\n    void a(HttpServletRequest request, HttpServletResponse response) throws Exception {\n        String v = org.springframework.web.util.HtmlUtils.htmlEscape(request.getParameter("v"));\n        response.getWriter().println(v);\n    }\n}\n'},
        {},
    ),
    (
        "java-html-escape-not-sql",
        "IL-501",
        {"A.java": 'import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\nclass A {\n    void a(HttpServletRequest request, java.sql.Statement statement) throws Exception {\n        String v = org.springframework.web.util.HtmlUtils.htmlEscape(request.getParameter("v"));\n        statement.executeQuery("SELECT * FROM item WHERE name = \'" + v + "\'");\n    }\n}\n'},
        {"A.java": [(7, "CONFIRMED")]},
    ),
    (
        "java-exec-environment-keys",
        "IL-504",
        {"A.java": 'import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\nclass A {\n    void a(HttpServletRequest request) throws Exception {\n        String v = request.getParameter("v");\n        String[] whole = {v};\n        Runtime.getRuntime().exec(new String[] {"ls"}, whole);\n        String[] fixedKey = {"LANG=C", "GREETING=" + v};\n        Runtime.getRuntime().exec(new String[] {"ls"}, fixedKey);\n        Runtime.getRuntime().exec(new String[] {"ls"}, new String[] {"LD_PRELOAD=" + v});\n        Runtime.getRuntime().exec(new String[] {"ls"}, new String[] {"LANG=C"});\n    }\n}\n'},
        {"A.java": [(8, "CONFIRMED"), (10, "REVIEW"), (11, "CONFIRMED")]},
    ),
    (
        "java-process-builder-start",
        "IL-504",
        {"A.java": 'import javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\nclass A {\n    void a(HttpServletRequest request) throws Exception {\n        String v = request.getParameter("v");\n        java.util.List<String> argv = new java.util.ArrayList<String>();\n        argv.add("sh");\n        argv.add("-c");\n        argv.add("echo " + v);\n        ProcessBuilder pb = new ProcessBuilder();\n        pb.command(argv);\n        pb.environment().put("PATH", v);\n        pb.start();\n    }\n\n    void b(HttpServletRequest request) throws Exception {\n        ProcessBuilder pb = new ProcessBuilder();\n        pb.command("echo", request.getParameter("v"));\n        pb.command("ls");\n        pb.environment().put("GREETING", request.getParameter("g"));\n        pb.start();\n    }\n}\n'},
        {"A.java": [(12, "CONFIRMED"), (13, "CONFIRMED"), (21, "REVIEW")]},
    ),
    (
        "kotlin-process-builder-start",
        "IL-504",
        {"K.kt": 'import javax.servlet.http.HttpServletRequest\n\nfun run(request: HttpServletRequest) {\n    val pb = ProcessBuilder()\n    pb.command("sh", "-c", "echo " + request.getParameter("v"))\n    pb.start()\n}\n\nfun fixed() {\n    val pb = ProcessBuilder()\n    pb.command("ls", "-l")\n    pb.start()\n}\n'},
        {"K.kt": [(5, "CONFIRMED")]},
    ),
    (
        "java-properties-algorithm-values",
        "IL-102",
        {
            "src/main/resources/algs.properties": "cipherA=AES/CCM/NoPadding\nhashA=MD5\n",
            "src/main/java/a/A.java": 'package a;\n\nclass A {\n    String read(String key, String fallback) throws Exception {\n        java.util.Properties props = new java.util.Properties();\n        try {\n            props.load(getClass().getClassLoader().getResourceAsStream("algs.properties"));\n            String alg = props.getProperty(key, fallback);\n            return alg;\n        } catch (Exception e) {\n            throw e;\n        }\n    }\n\n    void file() throws Exception {\n        java.util.Properties props = new java.util.Properties();\n        props.load(getClass().getClassLoader().getResourceAsStream("algs.properties"));\n        String c = props.getProperty("cipherA", "AES/ECB/PKCS5Padding");\n        javax.crypto.Cipher.getInstance(c);\n        String h = props.getProperty("hashA", "SHA-512");\n        java.security.MessageDigest.getInstance(h);\n        String d = props.getProperty("absent", "DES");\n        javax.crypto.Cipher.getInstance(d);\n    }\n\n    void unknownFile() throws Exception {\n        java.util.Properties props = new java.util.Properties();\n        String h = props.getProperty("x", "MD5");\n        java.security.MessageDigest.getInstance(h);\n    }\n\n    void sameLine() throws Exception {\n        String a = System.getProperty("k", "AES/GCM/NoPadding"); javax.crypto.Cipher.getInstance("DES");\n    }\n}\n',
        },
        {"src/main/java/a/A.java": [(21, "CONFIRMED"), (23, "CONFIRMED"), (29, "REVIEW"), (33, "CONFIRMED")], "src/main/resources/algs.properties": [(2, "REVIEW")]},
    ),
    (
        "py-local-object-methods",
        "IL-504",
        {
            "wrappers/__init__.py": "",
            "wrappers/req.py": 'class Incoming:\n    def __init__(self, request):\n        self.request = request\n\n    def value(self, name):\n        return self.request.args.get(name)\n\n    def fixed(self, name):\n        return "ls"\n\n\nclass Quiet:\n    def __init__(self, request):\n        self.request = request\n\n    def value(self, name):\n        return "ls"\n',
            "app.py": 'import os\n\nimport wrappers.req\nfrom flask import request\n\n\ndef a():\n    w = wrappers.req.Incoming(request)\n    os.system(w.value("c"))\n    os.system(w.fixed("c"))\n\n\ndef b():\n    w = wrappers.req.Quiet(request)\n    os.system(w.value("c"))\n\n\ndef c(flag):\n    if flag:\n        w = wrappers.req.Incoming(request)\n    else:\n        w = wrappers.req.Quiet(request)\n    os.system(w.value("c"))\n',
        },
        {"app.py": [(9, "CONFIRMED")]},
    ),
    (
        "java-local-object-methods",
        "IL-501",
        {
            "src/main/java/h/Incoming.java": 'package h;\n\nimport javax.servlet.http.HttpServletRequest;\n\npublic class Incoming {\n    private HttpServletRequest request;\n\n    public Incoming(HttpServletRequest request) {\n        this.request = request;\n    }\n\n    public String value(String p) {\n        return request.getParameter(p);\n    }\n\n    public String fixed(String p) {\n        return "bar";\n    }\n}\n',
            "src/main/java/h/A.java": 'package h;\n\nimport javax.servlet.http.HttpServletRequest;\n\nclass A {\n    void a(HttpServletRequest request, java.sql.Statement st) throws Exception {\n        Incoming in = new Incoming(request);\n        st.executeQuery("SELECT * FROM t WHERE n = \'" + in.value("n") + "\'");\n        st.executeQuery("SELECT * FROM t WHERE n = \'" + in.fixed("n") + "\'");\n    }\n}\n',
        },
        {"src/main/java/h/A.java": [(8, "CONFIRMED")]},
    ),
    (
        "py-path-blocklist-guard",
        "IL-502",
        {"a.py": 'from flask import Flask, request\n\napp = Flask(__name__)\nBASE = "/srv/files"\n\n\ndef ok():\n    doc = request.args.get("d")\n    if "../" in doc:\n        return "no"\n    target = f"{BASE}/{doc}"\n    return open(target).read()\n\n\ndef after():\n    doc = request.args.get("d")\n    data = open(f"{BASE}/{doc}").read()\n    if "../" in doc:\n        return "no"\n    return data\n\n\ndef other_var():\n    doc = request.args.get("d")\n    other = request.args.get("o")\n    if "../" in other:\n        return "no"\n    return open(f"{BASE}/{doc}").read()\n\n\ndef second_input():\n    doc = request.args.get("d")\n    if "../" in doc:\n        return "no"\n    return open(f"{BASE}/{doc}/{request.args.get(\'x\')}").read()\n\n\ndef reassigned():\n    doc = request.args.get("d")\n    if "../" in doc:\n        return "no"\n    doc = request.args.get("e")\n    return open(f"{BASE}/{doc}").read()\n\n\ndef swallowed():\n    doc = request.args.get("d")\n    try:\n        if "../" in doc:\n            raise ValueError(doc)\n    except ValueError:\n        pass\n    return open(f"{BASE}/{doc}").read()\n\n\ndef in_finally():\n    doc = request.args.get("d")\n    try:\n        if "../" in doc:\n            return "no"\n    finally:\n        open(f"{BASE}/{doc}").read()\n\n\ndef digits():\n    doc = request.args.get("d")\n    if not doc.isdigit():\n        return "no"\n    return open(f"{BASE}/{doc}.txt").read()\n'},
        {"a.py": [(12, "REVIEW"), (17, "CONFIRMED"), (28, "CONFIRMED"), (35, "CONFIRMED"), (43, "CONFIRMED"), (53, "CONFIRMED"), (62, "CONFIRMED")]},
    ),
    (
        "py-xpath-quote-guard-and-code-literal",
        "IL-527",
        {"a.py": 'from flask import request\n\n\ndef a(root):\n    who = request.args.get("id")\n    if "\'" in who:\n        return "no"\n    return root.xpath(f"/staff/member[@no=\'{who}\']")\n\n\ndef b(root):\n    who = request.args.get("id")\n    if \'"\' in who:\n        return "no"\n    return root.xpath(f"/staff/member[@no=\'{who}\']")\n\n\ndef c(root):\n    who = request.args.get("id")\n    return root.xpath(f"/staff/member[@no=\'{who.replace(\'\\\'\', \'&apos;\')}\']")\n'},
        {"a.py": [(8, "REVIEW"), (15, "CONFIRMED"), (20, "REVIEW")]},
    ),
    (
        "py-code-literal-check",
        "IL-503",
        {"a.py": 'from flask import request\n\n\ndef a():\n    expr = request.args.get("e")\n    if not expr.startswith("\'") or not expr.endswith("\'") or "\'" in expr[1:-1]:\n        return "no"\n    return eval(expr)\n\n\ndef b():\n    expr = request.args.get("e")\n    if not expr.startswith("\'"):\n        return "no"\n    return eval(expr)\n'},
        {"a.py": [(8, "REVIEW"), (15, "CONFIRMED")]},
    ),
    (
        "py-redirect-host-allowlist",
        "IL-507",
        {"a.py": 'import urllib.parse\n\nimport flask\nfrom flask import request\n\n\ndef a():\n    nxt = request.args.get("n")\n    url = urllib.parse.urlparse(nxt)\n    if url.netloc not in ["example.com"] or url.scheme != "https":\n        return "no"\n    return flask.redirect(nxt)\n\n\ndef b():\n    nxt = request.args.get("n")\n    url = urllib.parse.urlparse(nxt)\n    if url.scheme != "https":\n        return "no"\n    return flask.redirect(nxt)\n'},
        {"a.py": [(20, "CONFIRMED")]},
    ),
    (
        "java-archive-path-checks",
        "IL-502",
        {"Z.java": 'import java.io.File;\nimport java.util.zip.ZipEntry;\nimport org.apache.commons.io.FilenameUtils;\n\nclass Z {\n    void dotdotAndPrefix(ZipEntry entry, File outputDir) throws Exception {\n        String name = entry.getName();\n        File file = new File(outputDir, name);\n        if (name.indexOf("..") != -1 && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {\n            throw new Exception("bad");\n        }\n        org.apache.commons.io.FileUtils.forceMkdir(file);\n    }\n\n    void otherCondition(ZipEntry entry, File outputDir) throws Exception {\n        String name = entry.getName();\n        File file = new File(outputDir, name);\n        if (name.isEmpty() && !file.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {\n            throw new Exception("bad");\n        }\n        org.apache.commons.io.FileUtils.forceMkdir(file);\n    }\n\n    void pathCompare(ZipEntry entry, File outputDir) throws Exception {\n        File file = new File(outputDir, entry.getName());\n        if (!file.toPath().normalize().startsWith(outputDir.toPath())) {\n            throw new Exception("bad");\n        }\n        org.apache.commons.io.FileUtils.forceMkdir(file);\n    }\n\n    void separatorPrefix(ZipEntry entry, File outputDir) throws Exception {\n        File file = new File(outputDir, entry.getName());\n        if (!file.getCanonicalPath().startsWith(outputDir.getCanonicalPath() + File.separator)) {\n            throw new Exception("bad");\n        }\n        org.apache.commons.io.FileUtils.forceMkdir(file);\n    }\n\n    void normalizeChild(ZipEntry entry, File destination) throws Exception {\n        String normal = FilenameUtils.normalize(entry.getName());\n        if (normal == null) {\n            throw new Exception("bad");\n        }\n        new File(destination, normal).mkdirs();\n    }\n\n    void normalizeResolve(ZipEntry entry, java.nio.file.Path destination) throws Exception {\n        String normal = FilenameUtils.normalize(entry.getName());\n        if (normal == null) {\n            throw new Exception("bad");\n        }\n        java.nio.file.Files.createDirectories(destination.resolve(normal));\n    }\n\n    java.util.List<File> listed(ZipEntry entry, File rootDir) {\n        java.util.List<File> list = new java.util.ArrayList<File>();\n        list.add(new File(rootDir, entry.getName()));\n        File held = new File(rootDir, entry.getName());\n        if (!list.contains(held.getParentFile())) {\n            list.add(held);\n        }\n        return list;\n    }\n}\n'},
        {"Z.java": [(8, "REVIEW"), (17, "CONFIRMED"), (53, "REVIEW"), (58, "REVIEW"), (59, "REVIEW")]},
    ),
    (
        "java-value-only-file-object",
        "IL-502",
        {"V.java": 'import java.io.File;\nimport javax.servlet.http.HttpServletRequest;\n\nclass V {\n    boolean check(HttpServletRequest request) throws Exception {\n        File file = new File(request.getParameter("f"));\n        return !file.getCanonicalFile().equals(file.getAbsoluteFile());\n    }\n\n    byte[] read(HttpServletRequest request) throws Exception {\n        File file = new File(request.getParameter("f"));\n        String c = file.getCanonicalPath();\n        return java.nio.file.Files.readAllBytes(file.toPath());\n    }\n\n    boolean absolute(HttpServletRequest request) {\n        return java.nio.file.Path.of(request.getParameter("f")).isAbsolute();\n    }\n}\n'},
        {"V.java": [(11, "CONFIRMED"), (13, "CONFIRMED")]},
    ),
    (
        "py-constant-compare-and-route-segment",
        "IL-504",
        {"a.py": 'import os\n\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n\n@app.route("/tools/run")\ndef a():\n    probe = "This should never happen"\n    if "should" not in probe:\n        cmd = request.args.get("c")\n    else:\n        cmd = "ls"\n    return os.popen(cmd).read()\n\n\n@app.route("/tools/run2")\ndef b():\n    probe = "This should never happen"\n    probe = request.args.get("p")\n    if "should" not in probe:\n        cmd = request.args.get("c")\n    else:\n        cmd = "ls"\n    return os.popen(cmd).read()\n\n\n@app.route("/tools/run3")\ndef c():\n    parts = request.path.split("/")\n    return os.popen(parts[1]).read()\n\n\n@app.route("/tools/run4")\n@app.route("/<name>/run4")\ndef d():\n    parts = request.path.split("/")\n    return os.popen(parts[1]).read()\n'},
        {"a.py": [(26, "CONFIRMED"), (39, "CONFIRMED")]},
    ),
    (
        "py-prefix-compare-separator",
        "IL-502",
        {"a.py": 'import os\n\nfrom flask import request\n\n\ndef a():\n    p = os.path.realpath(os.path.join("/srv", request.args["p"]))\n    if not p.startswith("/srv"):\n        return "no"\n    return open(p).read()\n\n\ndef b():\n    p = os.path.realpath(os.path.join("/srv", request.args["p"]))\n    if not p.startswith("/srv/"):\n        return "no"\n    return open(p).read()\n'},
        {"a.py": [(7, "REVIEW"), (10, "REVIEW")]},
    ),
    (
        "c-output-buffer-input-and-macros",
        "IL-504",
        {"a.c": '#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n#define RUN execl\n#define ARG3 cmd\n\nvoid a(void) {\n    char buf[100] = "ls ";\n    char *cmd = buf;\n    size_t n = strlen(cmd);\n    if (fgets(cmd + n, (int)(100 - n), stdin) != NULL) {\n        RUN("/bin/sh", "sh", "-c", ARG3, NULL);\n    }\n}\n\nvoid b(void) {\n    char buf[100] = "ls ";\n    FILE *fp = fopen("/etc/app/settings.txt", "r");\n    if (fgets(buf, 100, fp) != NULL) {\n        system(buf);\n    }\n}\n\nvoid c(void) {\n    char buf[100] = "ls ";\n    char *env = getenv("EXTRA");\n    if (env != NULL) {\n        strncat(buf, env, 50);\n    }\n    system(buf);\n}\n'},
        {"a.c": [(12, "CONFIRMED"), (30, "CONFIRMED")]},
    ),
    (
        "c-copy-sizes-and-format",
        "IL-514",
        {"m.c": '#include <stdio.h>\n#include <string.h>\n\nvoid fits(void) {\n    char dest[100];\n    char src[100];\n    memset(src, \'C\', 99);\n    src[99] = \'\\0\';\n    strcpy(dest, src);\n}\n\nvoid overflows(void) {\n    char small[50];\n    char *dest = small;\n    char src[100];\n    memset(src, \'C\', 99);\n    src[99] = \'\\0\';\n    strcpy(dest, src);\n}\n\nvoid underwrite(void) {\n    char buf[100];\n    char *dest = buf - 8;\n    strcpy(dest, "abc");\n}\n\nvoid unknown(char *dest, const char *src) {\n    strcpy(dest, src);\n}\n\nvoid literal_format(void) {\n    char buf[100] = "";\n    char *fmt = buf;\n    strcpy(fmt, "fixed text");\n    printf(fmt);\n}\n\nvoid input_format(void) {\n    char buf[100] = "";\n    if (fgets(buf, 100, stdin) != NULL) {\n        printf(buf);\n    }\n}\n'},
        {"m.c": [(18, "CONFIRMED"), (24, "CONFIRMED"), (28, "REVIEW"), (41, "CONFIRMED")]},
    ),
    (
        "c-format-buffer-filled-at-offset",
        "IL-514",
        {"n.c": '#include <stdio.h>\n#include <string.h>\n\nint choose(void);\n\nvoid mixed(const char *extra) {\n    char line[64] = "";\n    char *msg = line;\n    size_t used = strlen(msg);\n    if (choose()) {\n        strcat(msg + used, extra);\n    } else {\n        strcpy(msg, "status ok");\n    }\n    printf(msg);\n}\n'},
        {"n.c": [(11, "REVIEW"), (15, "CONFIRMED")]},
    ),
    (
        "cs-request-and-property-sinks",
        "IL-501",
        {"A.cs": 'using System.Data.SqlClient;\nusing System.Web;\n\nclass A {\n    void Bad(HttpRequest req, SqlConnection conn) {\n        string name = req.Params.Get("name");\n        SqlCommand cmd = new SqlCommand(null, conn);\n        cmd.CommandText = "select * from users where name=\'" + name + "\'";\n        cmd.ExecuteNonQuery();\n    }\n\n    void Bound(HttpRequest req, SqlConnection conn) {\n        SqlCommand cmd = new SqlCommand(null, conn);\n        cmd.CommandText = "select * from users where name=@name";\n        cmd.Parameters.AddWithValue("@name", req.Params.Get("name"));\n        cmd.ExecuteNonQuery();\n    }\n\n    void NotRequest(Settings req, SqlConnection conn) {\n        SqlCommand cmd = new SqlCommand(null, conn);\n        cmd.CommandText = "select * from users where name=\'" + req.Params.Get("name") + "\'";\n        cmd.ExecuteNonQuery();\n    }\n}\n'},
        {"A.cs": [(8, "CONFIRMED"), (21, "REVIEW")]},
    ),
    (
        "cs-response-write-and-redirect",
        "IL-507",
        {"A.cs": 'using System.Web;\n\nclass A {\n    void Bad(HttpRequest req, HttpResponse resp) {\n        resp.Redirect(req.QueryString["next"]);\n    }\n\n    void Other(HttpRequest req, Router resp) {\n        resp.Redirect(req.QueryString["next"]);\n    }\n}\n'},
        {"A.cs": [(5, "CONFIRMED")]},
    ),
    (
        "js-negated-prefix-check",
        "IL-502",
        {"a.js": "const fs = require('fs');\nconst path = require('path');\n\nfunction a(req, res) {\n  const filePath = path.resolve('files', path.normalize(req.path));\n  if (!filePath.startsWith(path.resolve('files')) || filePath.endsWith('.md')) {\n    return res.status(403).end();\n  }\n  fs.readFile(filePath, 'utf8', () => {});\n}\n\nfunction b(req, res) {\n  const filePath = path.resolve('files', path.normalize(req.path));\n  if (!filePath.startsWith(path.resolve('files') + path.sep)) {\n    return res.status(403).end();\n  }\n  fs.readFile(filePath, 'utf8', () => {});\n}\n"},
        {"a.js": [(5, "REVIEW"), (9, "REVIEW")]},
    ),
    (
        "java-deserialize-try-resource",
        "IL-515",
        {"A.java": 'import java.io.*;\nimport org.springframework.web.bind.annotation.*;\n\nclass A {\n    @PostMapping("/t")\n    Object a(@RequestParam String token) throws Exception {\n        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(token)))) {\n            return ois.readObject();\n        }\n    }\n}\n'},
        {"A.java": [(8, "CONFIRMED")]},
    ),
    (
        "java-path-checks-derived-forms",
        "IL-502",
        {"D.java": 'import java.io.*;\nimport java.util.zip.*;\nimport org.apache.commons.io.FilenameUtils;\n\nclass D {\n    void normalizedFile(ZipEntry entry, File destination) throws Exception {\n        String normal = FilenameUtils.normalize(entry.getName());\n        if (normal == null) {\n            throw new IOException("bad");\n        }\n        File f = new File(destination, normal);\n        new FileOutputStream(f).close();\n    }\n\n    void splitName(ZipEntry entry, File outputDir) throws Exception {\n        String name = entry.getName();\n        String[] dirs = name.split("/");\n        File dest = new File(outputDir, dirs[dirs.length - 1]);\n        if (name.indexOf("..") != -1 && !dest.getCanonicalPath().startsWith(outputDir.getCanonicalPath())) {\n            throw new IOException("bad");\n        }\n        new FileOutputStream(dest).close();\n    }\n\n    void parentOfChecked(ZipFile zf, String zipDir) throws Exception {\n        java.util.Enumeration<? extends ZipEntry> entries = zf.entries();\n        while (entries.hasMoreElements()) {\n            ZipEntry entry = entries.nextElement();\n            File checked = new File(zipDir + entry.getName());\n            String canonical = checked.getCanonicalPath();\n            if (!canonical.startsWith(zipDir + File.separator)) {\n                throw new IOException("bad");\n            }\n            int index = entry.getName().lastIndexOf(\'/\');\n            new File(zipDir + entry.getName().substring(0, index)).mkdirs();\n        }\n    }\n}\n'},
        {"D.java": [(18, "REVIEW"), (22, "REVIEW")]},
    ),
    (
        # 검사한 Path를 문자열로 바꿔 넘기면 검사를 인정하고, Path.of(...)를 문자열로 바꾼 값의 접두사 비교는 문자열 비교로 본다
        "java-path-object-checks",
        "IL-502",
        {"P.java": 'import java.io.*;\nimport java.nio.file.*;\nimport java.util.zip.*;\n\nclass P {\n    void checkedThenString(ZipEntry ze, String dest) throws Exception {\n        Path path = Paths.get(dest, ze.getName()).normalize();\n        String pathString = path.toFile().getAbsolutePath();\n        if (!path.startsWith(Paths.get(dest).normalize())) {\n            throw new IOException("bad");\n        }\n        new FileOutputStream(pathString).close();\n    }\n\n    void stringPrefix(ZipEntry ze, String dest) throws Exception {\n        String path = Paths.get(dest, ze.getName()).normalize().toFile().getAbsolutePath();\n        if (!path.startsWith(dest)) {\n            throw new IOException("bad");\n        }\n        new FileOutputStream(path).close();\n    }\n\n    void checkedOther(ZipEntry ze, String dest) throws Exception {\n        Path path = Paths.get(dest, ze.getName()).normalize();\n        String pathString = path.toString();\n        path = Paths.get(dest).normalize();\n        if (!path.startsWith(Paths.get(dest).normalize())) {\n            throw new IOException("bad");\n        }\n        new FileOutputStream(pathString).close();\n    }\n}\n'},
        {"P.java": [(20, "REVIEW"), (30, "CONFIRMED")]},
    ),
]


PUBLIC_API_FILES = {
    "lib/tools.py": 'import os\nimport subprocess\n\n\ndef run_report(name: str):\n    os.system("report " + name)\n\n\ndef _private(name):\n    os.system("report " + name)\n\n\ndef fixed():\n    os.system("report daily")\n\n\ndef count(n: int):\n    os.system("report " + str(n))\n',
    "lib/web.py": 'import os\nfrom flask import request\n\n\ndef handle(name: str):\n    os.system("report " + name + request.args.get("x"))\n',
    "tests/test_tools.py": 'import os\n\n\ndef test_run(name):\n    os.system("report " + name)\n',
}


@pytest.mark.parametrize("mode", ["web", "public_api"])
def test_public_api_entry_points_are_review_only(tmp_path: Path, mode: str):
    from iron_laws.core.config import IronLawsConfig, Policies

    for rel, content in PUBLIC_API_FILES.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    config = IronLawsConfig(policies=Policies(entry_points=mode))
    violations = [v for v in AuditScanner(tmp_path, config).scan().violations if v.rule_id == "IL-504"]
    confirmed = {(v.file_path.as_posix(), v.line_number) for v in violations if v.confidence.value == "CONFIRMED"}
    public = {(v.file_path.as_posix(), v.line_number, v.confidence.value) for v in violations if "공개 API 매개변수" in v.message}
    assert confirmed == {("lib/web.py", 6)}  # 웹 입력이 닿는 지적은 모드와 관계없이 확정이다
    assert public == ({("lib/tools.py", 6, "REVIEW")} if mode == "public_api" else set())  # 비공개 함수·정수 매개변수·시험 파일은 보지 않는다


def test_public_api_finding_keeps_weak_prefix_reason(tmp_path: Path):
    """공개 API 매개변수 흐름도 싱크 앞의 구분자 없는 접두사 비교를 사유로 싣는다. 검사가 없는 메서드에는 싣지 않는다"""
    from iron_laws.core.config import IronLawsConfig, Policies

    (tmp_path / "Vault.java").write_text(
        "import java.io.IOException;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n\npublic class Vault {\n    private final Path home;\n\n"
        "    public Vault(Path home) {\n        this.home = home;\n    }\n\n"
        "    public void put(String key, byte[] body) throws IOException {\n        Path file = home.resolve(key);\n"
        "        if (!file.toFile().getCanonicalPath().startsWith(home.toFile().getCanonicalPath())) {\n            throw new IOException(\"bad key\");\n        }\n"
        "        Files.write(file, body);\n    }\n\n"
        "    public byte[] get(String key) throws IOException {\n        return Files.readAllBytes(home.resolve(key));\n    }\n}\n",
        encoding="utf-8",
    )
    found = {v.line_number: v.message for v in AuditScanner(tmp_path, IronLawsConfig(policies=Policies(entry_points="public_api"))).scan().violations if v.rule_id == "IL-502"}
    assert sorted(found) == [17, 21]
    assert "구분자 없이 문자열 접두사로 비교" in found[17] and "공개 API 매개변수" in found[17]
    assert "구분자 없이" not in found[21]


@pytest.mark.parametrize(("case_id", "rule_id", "files", "expected"), CASES, ids=[c[0] for c in CASES])
def test_flow_definition(tmp_path: Path, case_id: str, rule_id: str, files: dict[str, str], expected: dict[str, list[tuple[int, str]]]):
    for rel, content in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    actual: dict[str, list[tuple[int, str]]] = {}
    for v in AuditScanner(tmp_path).scan().violations:
        if v.rule_id == rule_id:
            actual.setdefault(v.file_path.as_posix(), []).append((v.line_number, v.confidence.value))
    actual = {path: sorted(set(found)) for path, found in actual.items()}
    assert actual == expected, f"{case_id}: 기대 {expected}, 실제 {actual}"
