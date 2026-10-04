"""
제5철칙: 전수 검증의 원칙 - 입력값 검증 및 표현 계열 (행안부 2021 구현단계 1장)
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import definitions, expr_has_source, is_tainted
from iron_laws.rules.base import BaseRule
from iron_laws.rules.sinks import (
    CFAM,
    CS,
    GO,
    JAVA,
    JS,
    PHP,
    PY,
    RUST,
    Flow,
    Sink,
    assess,
    looks_like_browser_script,
    sink_hits,
)
from iron_laws.standards import mois_ref

SQL_TEXT_RE = re.compile(
    r"(?is)\b(select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|create\s+table|alter\s+table|where\b|union\s+select|exec(ute)?\s)"
)
DDL_TEXT_RE = re.compile(r"(?is)\s*(drop|alter|create|truncate|comment\s+on|grant|revoke|set\s+search_path|vacuum|analyze|reindex)\b")
LDAP_TEXT_RE = re.compile(r"\([&|!]?\w+\s*[=~<>]")
SANITIZER_RE = re.compile(
    r"(?i)secure_filename|basename|GetFileName|filepath\.Base|\.getName\(\)|normalize|getCanonical|"
    r"realpath|is_relative_to|startswith|startsWith|sanitize|uuid|Path\.GetRandomFileName|allowlist|whitelist|"
    r"abspath|resolve\("
)
FILENAME_RE = re.compile(
    r"\.filename\b|getOriginalFilename|originalname|\.FileName\b|\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]|header\.Filename|\bfile\.name\b"
)
ESCAPER_RE = re.compile(
    r"(?i)\bescape\b|html\.escape|markupsafe|htmlspecialchars|htmlentities|encodeURI|he\.encode|sanitize|DOMPurify|bleach|"
    r"cgi\.escape|HtmlEncode|Encoder\.|escapeHtml|StringEscapeUtils|textContent|html/template|escapeXml|\be\(|"
    r"(?-i:\b(?:[a-z]{1,4}Esc|esc|Esc|escape|[A-Za-z]+Escape)\w*\()"
)


def _context_text(src: SourceFile, arg: Node) -> str:
    """인자 식과, 식별자일 경우 그 정의식들의 원문을 합쳐 반환한다."""
    parts = [src.text_of(arg)]
    if arg.type in ("identifier", "variable_name"):
        scope = enclosing_function(arg, src.lang) or src.root
        if scope is not None:
            for d in definitions(src, scope, src.text_of(arg).lstrip("$")):
                parts.append(src.text_of(d))
    return "\n".join(parts)


class SinkRule(BaseRule):
    """싱크 호출의 인자가 외부 입력이거나 동적으로 조합된 경우를 지적한다."""

    sinks: list[Sink] = []
    iron_law = IronLaw.LAW_5
    dynamic_is_finding: bool = True
    include_cli_sources: bool = False
    tainted_message: str = ""
    dynamic_message: str = ""

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        return False

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        for call, arg, flow in sink_hits(src, self.sinks, self.include_cli_sources):
            if self.skip_hit(src, call, arg, flow):
                continue
            if flow is Flow.TAINTED:
                found.append(
                    self.at_node(src, call.node, self.tainted_message.format(callee=call.callee))
                )
            elif self.dynamic_is_finding:
                found.append(
                    self.at_node(
                        src,
                        call.node,
                        self.dynamic_message.format(callee=call.callee),
                        severity=self.downgrade(self.severity),
                        confidence=Confidence.REVIEW,
                    )
                )
        return found


DB_RECEIVER_RE = re.compile(
    r"(?i)(stmt|statement|ps\b|prepared|conn|connection|cursor|\bcur\b|\bdb\b|jdbc|template|session|entitymanager|\bem\b|repo|dao|query|sql|pool|client|knex|prisma|sequelize|mongo|collection|database|\bcmd\b|command|\bdbo\b)"
)
STRONG_SQL_CALLEES = re.compile(
    r"(^|\.)(execute|executemany|executescript|executeQuery|executeUpdate|prepareStatement|createNativeQuery|"
    r"ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|"
    r"queryRawUnsafe|executeRawUnsafe|\$queryRawUnsafe|\$executeRawUnsafe|mysqli_query|mysql_query|pg_query|sqlite3_exec|PQexec)$|^new\w*Command$"
)


class SqlInjectionRule(SinkRule):
    rule_id = "IL-501"
    name = "SQL Injection 취약점 탐지"
    severity = Severity.CRITICAL
    gov_standard = mois_ref("1-1")
    plain = "화면에서 받은 값이 그대로 데이터베이스 명령문에 섞이면 공격자가 데이터를 빼내거나 지울 수 있습니다."
    how_to_fix = (
        "SQL 문자열에 값을 직접 붙이지 말고 파라미터 바인딩을 쓰세요. "
        "예: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) / "
        "db.query('SELECT * FROM users WHERE id = $1', [id]) / PreparedStatement의 ? 자리표시자"
    )
    tainted_message = "외부 입력이 SQL 문자열에 결합되어 {callee}로 실행됩니다. 파라미터 바인딩으로 바꾸십시오."
    dynamic_message = "SQL 문을 변수와 결합해 {callee}로 실행합니다. 외부 입력이 닿는지 확인하고 파라미터 바인딩을 쓰십시오."
    sinks = [
        Sink.of(PY, r"(^|\.)(execute|executemany|executescript|raw|read_sql|read_sql_query|text|mogrify|extra)$"),
        Sink.of(JS, r"(^|\.)(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe|unsafe|all|get|run|exec)$"),
        Sink.of(JAVA, r"(^|\.)(executeQuery|executeUpdate|execute|executeLargeUpdate|createQuery|createNativeQuery|prepareStatement|prepareCall|queryForObject|queryForList|queryForMap|update|batchUpdate|query)$"),
        Sink.of(CS, r"(^|\.)(ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQuery|QueryAsync|ExecuteAsync|QueryFirst|QuerySingle)$"),
        Sink.of(CS, r"^new(SqlCommand|MySqlCommand|NpgsqlCommand|OleDbCommand|OdbcCommand|SqliteCommand|OracleCommand|SqlDataAdapter)$"),
        Sink.of(GO, r"(^|\.)(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Prepare|PrepareContext|Raw|Select|Get)$"),
        Sink.of(PHP, r"^(mysqli_query|mysql_query|pg_query|sqlite_query|odbc_exec)$", 1),
        Sink.of(PHP, r"(->|::)(query|exec|prepare|real_query|multi_query)$"),
        Sink.of(CFAM, r"^(mysql_query|mysql_real_query|sqlite3_exec|PQexec|SQLExecDirect)$", 1),
        Sink.of(RUST, r"(^|::|\.)(query|execute|query_as|query_scalar|raw_sql)$"),
    ]

    placeholder_re = re.compile(r"\$\d+|%s|%\(\w+\)s|\?|:\w+|@\w+")
    migration_path_re = re.compile(r"(?i)(migration|alembic|versions|flyway|liquibase|schema|seed)")

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        context = _context_text(src, arg)
        if flow is not Flow.TAINTED:
            if self.migration_path_re.search(src.path.as_posix()):
                return True  # 마이그레이션은 스키마·테이블 이름을 동적으로 만든다
            if len(call.args) >= 2 and self.placeholder_re.search(context):
                return True  # 값은 바인딩하고 식별자만 보간하는 형태
        if flow is not Flow.TAINTED and DDL_TEXT_RE.match(self._sql_literal_start(context)):
            return True  # 식별자(스키마·테이블 이름)는 파라미터로 바인딩할 수 없는 DDL이다
        if src.lang is Lang.CSHARP and re.search(r"FromSql$|FromSqlInterpolated|ExecuteSql$|ExecuteSqlInterpolated", call.callee):
            return True  # 보간 문자열이 자동으로 파라미터화되는 EF Core API
        if SQL_TEXT_RE.search(context):
            return False
        # SQL 문이라는 단서가 없으면 DB 객체에서 호출한 확실한 SQL 실행 함수의 외부 입력 도달만 지적한다.
        receiver = call.callee.rsplit(".", 1)[0] if "." in call.callee else call.callee
        return not (
            flow is Flow.TAINTED
            and STRONG_SQL_CALLEES.search(call.callee)
            and DB_RECEIVER_RE.search(receiver)
        )

    @staticmethod
    def _sql_literal_start(context: str) -> str:
        quote_positions = [i for i in (context.find('"'), context.find("'")) if i >= 0]
        if not quote_positions:
            return context
        return context[min(quote_positions) + 1 :].lstrip("\"' ")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind == "xml":
            return self._check_mybatis(src)
        if src.kind == "sql":
            return []
        return super().check(src)

    def _check_mybatis(self, src: SourceFile) -> list[Violation]:
        if "<mapper" not in src.text:
            return []
        found = []
        for idx, line in enumerate(src.lines, start=1):
            if "${" in line and "<!--" not in line:
                found.append(
                    self.at_line(
                        src,
                        idx,
                        "MyBatis 매퍼 쿼리 내 문자열 치환(${...})이 탐지되었습니다. 바인딩(#{...})으로 변경하십시오.",
                        how_to_fix="${...}를 #{...}로 바꾸세요. 테이블·컬럼명처럼 바인딩이 불가능한 값은 허용 목록으로 검증하세요.",
                    )
                )
        return found


class CodeInjectionRule(SinkRule):
    rule_id = "IL-503"
    name = "코드 삽입 (동적 코드 실행) 탐지"
    severity = Severity.CRITICAL
    gov_standard = mois_ref("1-2")
    plain = "받은 문자열을 코드로 실행하면 공격자가 서버에서 원하는 프로그램을 돌릴 수 있습니다."
    how_to_fix = "eval/exec 대신 JSON 파싱, 딕셔너리 매핑, 명시적 분기 등 코드를 실행하지 않는 방법을 쓰세요."
    include_cli_sources = True
    tainted_message = "외부 입력이 {callee}로 코드처럼 실행됩니다. 동적 코드 실행을 제거하십시오."
    dynamic_message = "동적으로 만든 문자열을 {callee}로 실행합니다. 코드 실행 대신 안전한 방법을 쓰십시오."
    sinks = [
        Sink.of(PY, r"^(eval|exec|compile)$"),
        Sink.of(JS, r"^(eval|Function|newFunction|vm\.runInNewContext|vm\.runInThisContext|newvm\.Script)$", None),
        Sink.of(JS, r"^(setTimeout|setInterval)$"),
        Sink.of(JAVA, r"(^|\.)eval$"),
        Sink.of(CS, r"CSharpScript\.(EvaluateAsync|RunAsync)$"),
        Sink.of(PHP, r"^(eval|assert|create_function)$"),
    ]


class CommandInjectionRule(SinkRule):
    rule_id = "IL-504"
    name = "운영체제 명령어 삽입 탐지"
    severity = Severity.CRITICAL
    gov_standard = mois_ref("1-5")
    plain = "받은 값이 명령어에 섞이면 공격자가 서버에서 임의의 명령을 실행할 수 있습니다."
    how_to_fix = (
        "셸을 거치지 말고 인자 배열로 호출하세요. 예: subprocess.run(['ls', path], check=True) / "
        "execFile('ls', [path]) / ProcessBuilder('ls', path). 값은 허용 목록으로 검증하세요."
    )
    tainted_message = "외부 입력이 {callee}를 통해 운영체제 명령으로 실행됩니다. 인자 배열 방식으로 바꾸십시오."
    dynamic_message = "명령 문자열을 변수와 결합해 {callee}로 실행합니다. 셸을 거치지 않는 호출로 바꾸십시오."
    shell_word_re = re.compile(r"""["'](sh|bash|zsh|cmd(\.exe)?|powershell(\.exe)?|/bin/(ba)?sh|-c|/c)["']""")
    sinks = [
        Sink.of(PY, r"^(os\.system|os\.popen|commands\.getoutput|pty\.spawn)$"),
        Sink.of(PY, r"^subprocess\.(call|run|Popen|check_output|check_call|getoutput)$"),
        Sink.of(JS, r"(^|\.)(exec|execSync)$"),
        Sink.of(JS, r"(^|\.)(spawn|spawnSync)$"),
        Sink.of(JAVA, r"(^|\.)exec$"),
        Sink.of(JAVA, r"^newProcessBuilder$", None),
        Sink.of(CS, r"^Process\.Start$", None),
        Sink.of(GO, r"^exec\.Command(Context)?$", None),
        Sink.of(PHP, r"^(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)$"),
        Sink.of(CFAM, r"^(system|popen|_wsystem)$"),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        call_text = src.text_of(call.node)
        callee = call.callee
        if callee.startswith("subprocess.") and callee != "subprocess.getoutput":
            return arg.type in ("list", "tuple") and not re.search(r"shell\s*=\s*True", call_text)
        if re.search(r"(^|\.)(spawn|spawnSync)$", callee):
            return not re.search(r"shell\s*:\s*true", call_text)
        if callee.endswith("exec") and src.lang is Lang.JAVA:
            return arg.type == "array_creation_expression" and not self.shell_word_re.search(call_text)
        if callee in ("newProcessBuilder", "Process.Start") or callee.startswith("exec.Command"):
            if bool(self.shell_word_re.search(call_text)):
                return False
            return flow is not Flow.TAINTED or callee.startswith("exec.Command")
        return False


class PathTraversalRule(SinkRule):
    rule_id = "IL-502"
    name = "경로 조작 및 자원 삽입 (Path Traversal) 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-3")
    plain = "받은 파일 이름이나 경로를 그대로 쓰면 공격자가 서버의 다른 폴더 파일(비밀번호 파일 등)을 읽거나 덮어쓸 수 있습니다."
    how_to_fix = (
        "허용된 기준 폴더 밖으로 나가지 못하게 하세요. 파일명은 basename으로 줄이고, "
        "경로를 정규화한 뒤 기준 폴더로 시작하는지 확인하세요. 예: Path(base).joinpath(name).resolve().is_relative_to(base)"
    )
    dynamic_is_finding = False
    tainted_message = "외부 입력이 파일 경로로 {callee}에 전달됩니다. 경로 정규화와 기준 폴더 이탈 검증을 적용하십시오."
    sinks = [
        Sink.of(PY, r"^(open|os\.path\.join|os\.remove|os\.unlink|os\.rmdir|os\.listdir|os\.makedirs|os\.rename|send_file|send_from_directory|FileResponse|Path|pathlib\.Path|shutil\.\w+)$", None),
        Sink.of(PY, r"\.(read_text|write_text|read_bytes|write_bytes)$", None),
        Sink.of(JS, r"(^|\.)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync|sendFile|download|rm|rmSync|appendFile|appendFileSync)$|^path\.(join|resolve)$", None),
        Sink.of(JAVA, r"^new(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)$", None),
        Sink.of(JAVA, r"(^|\.)(Paths\.get|Path\.of|getResourceAsStream|Files\.\w+)$", None),
        Sink.of(CS, r"^File\.(ReadAll\w+|WriteAll\w+|Open\w*|Delete|Copy|Move|Create\w*|AppendAll\w+)$", None),
        Sink.of(CS, r"^new(FileStream|StreamReader|StreamWriter)$|^Path\.Combine$|^Directory\.\w+$", None),
        Sink.of(GO, r"^(os\.(Open|OpenFile|ReadFile|WriteFile|Remove|RemoveAll|Create|Mkdir\w*)|ioutil\.\w+|filepath\.Join|http\.ServeFile)$", None),
        Sink.of(PHP, r"^(file_get_contents|file_put_contents|fopen|readfile|unlink|file|copy|rename|mkdir|rmdir|opendir|scandir|move_uploaded_file)$", None),
        Sink.of(CFAM, r"^(fopen|open|freopen|remove|unlink|rename|opendir)$", None),
        Sink.of(RUST, r"(^|::)(File::open|File::create|read_to_string|fs::read|fs::write|remove_file|Path::new|PathBuf::from)$", None),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        text = _context_text(src, arg)
        if SANITIZER_RE.search(text) or re.search(r"\.(Body|InputStream|OutputStream|BaseStream)\b", text):
            return True
        # 파일명 입력은 업로드 규칙(IL-513)이 담당한다.
        return bool(FILENAME_RE.search(src.text_of(call.node)))

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PHP and src.root is not None:
            for node in src.nodes:
                if node.type in ("include_expression", "require_expression", "include_once_expression", "require_once_expression"):
                    child = node.named_children[0] if node.named_children else None
                    if child is not None and not is_literal(child) and is_tainted(src, child):
                        found.append(self.at_node(src, node, "외부 입력으로 파일을 include/require 합니다 (원격·로컬 파일 포함 위험).", severity=Severity.CRITICAL))
        return found


class UploadFilenameRule(SinkRule):
    rule_id = "IL-513"
    name = "위험한 형식 파일 업로드 (클라이언트 파일명 사용)"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-6")
    plain = "업로드한 사람이 정한 파일 이름·확장자를 그대로 저장하면 악성 스크립트가 올라가거나 다른 파일이 덮어써집니다."
    how_to_fix = (
        "저장 파일명은 서버가 만든 무작위 이름(uuid)을 쓰고, 허용 확장자·크기·MIME 타입을 검사하세요. "
        "업로드 폴더는 웹에서 직접 실행되지 않는 위치에 두세요."
    )
    dynamic_is_finding = False
    tainted_message = "클라이언트가 보낸 파일명이 {callee}로 저장 경로에 쓰입니다. 서버가 생성한 이름과 확장자 검증을 적용하십시오."
    sinks = [
        Sink.of(PY, r"\.save$", None),
        Sink.of(JS, r"(^|\.)(mv|writeFile|writeFileSync|rename|createWriteStream|renameSync|copyFile)$", None),
        Sink.of(JAVA, r"(^|\.)transferTo$|^new(File|FileOutputStream)$|(^|\.)(Paths\.get|Path\.of)$", None),
        Sink.of(CS, r"(^|\.)(SaveAs|CopyTo|Combine)$|^new(FileStream)$", None),
        Sink.of(GO, r"^os\.(Create|OpenFile)$|^filepath\.Join$", None),
        Sink.of(PHP, r"^move_uploaded_file$", None),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        text = src.text_of(call.node)
        if not FILENAME_RE.search(text):
            return True
        return bool(re.search(r"(?i)secure_filename|uuid|GetRandomFileName|basename|GetFileName|filepath\.Base", text))

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(s.callee.search(call.callee) and src.lang in s.langs for s in self.sinks):
                continue
            if self.skip_hit(src, call, call.node, Flow.TAINTED):
                continue
            found.append(self.at_node(src, call.node, self.tainted_message.format(callee=call.callee)))
        return found


class XssRule(BaseRule):
    rule_id = "IL-505"
    name = "크로스사이트 스크립트(XSS) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-4")
    plain = "사용자가 입력한 글이 화면에 그대로 출력되면 공격자가 다른 사용자의 브라우저에서 스크립트를 실행시켜 계정을 탈취할 수 있습니다."
    how_to_fix = (
        "출력할 때 HTML을 이스케이프하세요. 화면 갱신은 innerHTML 대신 textContent를 쓰고, "
        "HTML을 꼭 넣어야 하면 DOMPurify 같은 검증된 정제기를 거치세요. 템플릿의 |safe, th:utext, Html.Raw 사용을 피하세요."
    )
    dom_sink_props = re.compile(r"\.(innerHTML|outerHTML)$")
    js_html_calls = re.compile(r"(^|\.)(write|writeln|insertAdjacentHTML|html|append|prepend|after|before)$")
    resp_sinks = [
        Sink.of(JS, r"^(res|response|reply)\.(send|end|write)$"),
        Sink.of(JAVA, r"getWriter\(\)\.(print|println|write|append|printf|format)$", None),
        Sink.of(CS, r"^(Response\.Write|Html\.Raw|newHtmlString)$"),
        Sink.of(GO, r"^(fmt\.Fprintf|fmt\.Fprint|fmt\.Fprintln|io\.WriteString)$", 1),
        Sink.of(GO, r"^template\.HTML$"),
        Sink.of(PY, r"^(render_template_string|Markup|mark_safe|HttpResponse|HTMLResponse|make_response|Response)$"),
    ]

    def _unsafe_html_flow(self, src: SourceFile, arg: Node) -> Flow:
        context = _context_text(src, arg)
        if ESCAPER_RE.search(context):
            return Flow.SAFE
        flow = assess(src, arg)
        if flow is Flow.TAINTED:
            return flow
        return Flow.SAFE

    def check(self, src: SourceFile) -> list[Violation]:
        if src.kind == "template":
            return self._check_template(src)
        found: list[Violation] = []
        if src.root is None:
            return found
        found.extend(self._dom_assignments(src))
        found.extend(self._jsx(src))
        for call in iter_calls(src):
            if src.lang in JS_FAMILY and self.js_html_calls.search(call.callee):
                if re.search(r"(^|\.)(write|writeln)$", call.callee) and not call.callee.startswith("document."):
                    continue
                arg = call.args[-1] if call.args else None
                if arg is not None and not is_literal(arg) and not ESCAPER_RE.search(_context_text(src, arg)):
                    if call.callee.endswith((".html", ".append", ".prepend", ".after", ".before")) and not re.match(r"(\$|jQuery)", call.callee):
                        continue
                    flow = assess(src, arg)
                    if flow is Flow.TAINTED:
                        found.append(self.at_node(src, call.node, f"외부 입력이 {call.callee}로 HTML에 그대로 삽입됩니다."))
                    elif call.callee.endswith(("insertAdjacentHTML", "document.write", "document.writeln")):
                        found.append(self.at_node(src, call.node, f"{call.callee}에 동적 값을 넣고 있습니다. 이스케이프 또는 정제 여부를 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
                continue
            for sink in self.resp_sinks:
                if src.lang not in sink.langs or not sink.callee.search(call.callee):
                    continue
                indices = range(len(call.args)) if sink.arg is None else [sink.arg]
                for i in indices:
                    if i >= len(call.args):
                        continue
                    arg = call.args[i]
                    if self._unsafe_html_flow(src, arg) is Flow.TAINTED and self._htmlish(src, arg, call.callee):
                        found.append(self.at_node(src, call.node, f"외부 입력이 이스케이프 없이 {call.callee}로 응답에 출력됩니다."))
                        break
                break
        found.extend(self._php_echo(src))
        found.extend(self._python_return_html(src))
        return found

    def _htmlish(self, src: SourceFile, arg: Node, callee: str) -> bool:
        if re.search(r"Markup|mark_safe|render_template_string|Html\.Raw|HtmlString|template\.HTML|getWriter|Response\.Write|Fprint|WriteString|^res\.|^response\.|^reply\.", callee):
            return True
        return bool(re.search(r"<\s*[a-zA-Z/]", _context_text(src, arg)))

    def _dom_assignments(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang not in JS_FAMILY or src.root is None:
            return found
        for node in src.nodes:
            if node.type != "assignment_expression":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or not self.dom_sink_props.search(src.text_of(left)):
                continue
            if is_literal(right) or ESCAPER_RE.search(_context_text(src, right)):
                continue
            if assess(src, right) is Flow.TAINTED:
                found.append(self.at_node(src, node, f"외부 입력이 {src.text_of(left)}에 대입되어 DOM XSS가 발생할 수 있습니다."))
            else:
                found.append(self.at_node(src, node, f"{src.text_of(left)}에 동적 값을 대입합니다. textContent로 바꾸거나 정제 후 사용하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _jsx(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang not in JS_FAMILY or src.root is None:
            return found
        for node in src.nodes:
            if node.type == "jsx_attribute" and "dangerouslySetInnerHTML" in src.text_of(node)[:40]:
                text = src.text_of(node)
                if ESCAPER_RE.search(text):
                    continue
                found.append(self.at_node(src, node, "dangerouslySetInnerHTML을 사용합니다. 정제된 값만 넣는지 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _php_echo(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.PHP or src.root is None:
            return found
        for node in src.nodes:
            if node.type in ("echo_statement", "print_intrinsic"):
                text = src.text_of(node)
                if ESCAPER_RE.search(text):
                    continue
                if expr_has_source(src, node) or any(
                    is_tainted(src, c) for c in node.named_children if c.type != "echo"
                ):
                    found.append(self.at_node(src, node, "외부 입력을 이스케이프 없이 echo 합니다. htmlspecialchars()를 사용하십시오."))
        return found

    def _python_return_html(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.lang is not Lang.PYTHON or src.root is None:
            return found
        for node in src.nodes:
            if node.type != "return_statement" or not node.named_children:
                continue
            value = node.named_children[0]
            if value.type in ("string", "binary_operator") or (
                value.type == "call" and ".format" in src.text_of(value)
            ):
                text = src.text_of(value)
                if re.search(r"<\s*[a-zA-Z/]", text) and not ESCAPER_RE.search(text) and is_tainted(src, value):
                    found.append(self.at_node(src, node, "외부 입력이 이스케이프 없이 HTML 문자열에 결합되어 반환됩니다."))
        return found

    def _check_template(self, src: SourceFile) -> list[Violation]:
        found = []
        pattern = re.compile(r"\|\s*safe\b|th:utext|v-html|@Html\.Raw|\{!!|dangerouslySetInnerHTML|autoescape\s+false|\{%\s*autoescape\s+off")
        for idx, line in enumerate(src.code_lines, start=1):
            if pattern.search(line):
                found.append(self.at_line(src, idx, "템플릿에서 이스케이프를 끄는 구문(|safe, th:utext, v-html, Html.Raw 등)을 사용합니다. 값이 정제되었는지 확인하십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found


class SsrfRule(SinkRule):
    rule_id = "IL-506"
    name = "서버사이드 요청 위조(SSRF) 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-12")
    plain = "받은 주소로 서버가 대신 접속하게 하면 공격자가 내부 서버나 클라우드 인증 정보에 접근하도록 유도할 수 있습니다."
    how_to_fix = "접속 가능한 도메인을 허용 목록으로 제한하고, 내부 IP·메타데이터 주소(169.254.169.254, localhost 등)를 차단하세요. 리다이렉트 추적은 끄세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}의 대상 주소로 쓰입니다. 허용 도메인 목록으로 제한하십시오."
    sinks = [
        Sink.of(PY, r"^(requests\.\w+|httpx\.\w+|urllib\.request\.urlopen|urlopen|urllib3\.\w+|aiohttp\.\w+|session\.\w+|client\.(get|post|request|put|delete)|http\.client\.\w+)$", None),
        Sink.of(JS, r"^(fetch|axios(\.\w+)?|got(\.\w+)?|request|needle\.\w+|https?\.(get|request)|superagent\.\w+|undici\.\w+|\$http\.\w+|ky(\.\w+)?)$", None),
        Sink.of(JAVA, r"^(newURL|newURI|URI\.create|newHttpGet|newHttpPost)$|(?i:rest\w*|template)\.(getForObject|getForEntity|postForObject|postForEntity|exchange)$", None),
        Sink.of(CS, r"^newUri$|WebRequest\.Create$|(?i:http\w*|client\w*|webclient|request\w*)\.(GetAsync|PostAsync|GetStringAsync|GetByteArrayAsync|SendAsync|DownloadString|DownloadFile|DownloadData)$", None),
        Sink.of(GO, r"^(http\.(Get|Post|Head|NewRequest|NewRequestWithContext)|client\.(Get|Do))$", None),
        Sink.of(PHP, r"^(curl_init|get_headers)$", None),
        Sink.of(PHP, r"^curl_setopt$", None),
        Sink.of(RUST, r"^reqwest::\w+$|(^|\.)(get|post)$", None),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        if src.lang in JS_FAMILY and looks_like_browser_script(src):
            return True
        if call.callee.endswith((".get", ".post")) and src.lang is Lang.RUST and "reqwest" not in src.text:
            return True
        if call.callee.startswith("session.") and src.lang is Lang.PYTHON and "requests" not in src.text:
            return True
        return False


class OpenRedirectRule(SinkRule):
    rule_id = "IL-507"
    name = "신뢰되지 않는 URL로 자동접속(오픈 리다이렉트) 탐지"
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-7")
    plain = "받은 주소로 사용자를 보내면 공격자가 진짜 사이트처럼 보이는 링크로 사용자를 피싱 사이트에 보낼 수 있습니다."
    how_to_fix = "이동 가능한 경로를 허용 목록이나 서버 내부 상대 경로로 제한하세요. 외부 값은 목록의 키로만 사용하세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}의 이동 주소로 쓰입니다. 허용된 경로 목록으로 제한하십시오."
    sinks = [
        Sink.of(PY, r"^(redirect|HttpResponseRedirect|RedirectResponse)$"),
        Sink.of(JS, r"(^|\.)redirect$", None),
        Sink.of(JAVA, r"(^|\.)sendRedirect$|^newRedirectView$"),
        Sink.of(CS, r"^(Redirect|RedirectPermanent)$"),
        Sink.of(GO, r"^http\.Redirect$", 2),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PHP:
            for call in iter_calls(src):
                if call.callee == "header" and call.args:
                    text = src.text_of(call.args[0])
                    if re.search(r"(?i)location\s*:", text) and is_tainted(src, call.args[0]):
                        found.append(self.at_node(src, call.node, "외부 입력이 Location 헤더에 쓰입니다. 허용된 경로로 제한하십시오."))
        if src.lang in JS_FAMILY and src.root is not None and not looks_like_browser_script(src):
            for node in src.nodes:
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and re.search(r"(window\.)?location(\.href)?$", src.text_of(left)):
                        if not is_literal(right) and is_tainted(src, right):
                            found.append(self.at_node(src, node, "외부 입력이 location에 대입됩니다. 허용된 경로로 제한하십시오."))
        return found


class LdapInjectionRule(SinkRule):
    rule_id = "IL-508"
    name = "LDAP 삽입 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-10")
    plain = "받은 값이 디렉터리(LDAP) 검색 조건에 섞이면 공격자가 인증을 우회하거나 다른 사용자 정보를 조회할 수 있습니다."
    how_to_fix = "LDAP 필터에 들어가는 값은 이스케이프(ldap.filter.escape_filter_chars, Encoder.encodeForLDAP 등)한 뒤 결합하세요."
    tainted_message = "외부 입력이 LDAP 검색 필터에 결합되어 {callee}로 실행됩니다. 필터 값을 이스케이프하십시오."
    dynamic_message = "LDAP 검색 필터를 변수와 결합해 {callee}로 실행합니다. 값을 이스케이프하십시오."
    sinks = [
        Sink.of(PY, r"\.(search|search_s|search_ext|search_ext_s)$", None),
        Sink.of(JS, r"(^|\.)search$", None),
        Sink.of(JAVA, r"(^|\.)search$", None),
        Sink.of(CS, r"^newDirectorySearcher$", None),
        Sink.of(PHP, r"^ldap_(search|list|read)$", None),
        Sink.of(GO, r"^ldap\.NewSearchRequest$", None),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        text = _context_text(src, arg)
        if re.search(r"(?i)escape_filter|encodeForLDAP|ldap\.EscapeFilter|escapeLDAP", text):
            return True
        return not LDAP_TEXT_RE.search(text)


class XxeRule(BaseRule):
    rule_id = "IL-509"
    name = "부적절한 XML 외부 개체 참조(XXE) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-8")
    plain = "XML 파서가 외부 개체를 읽도록 두면 공격자가 서버의 파일을 읽거나 내부망을 조회할 수 있습니다."
    how_to_fix = (
        "외부 개체와 DTD를 끄세요. Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true) / "
        "Python: defusedxml 사용 / C#: DtdProcessing.Prohibit, XmlResolver = null"
    )
    insecure = {
        Lang.PYTHON: re.compile(r"resolve_entities\s*=\s*True|no_network\s*=\s*False|feature_external_ges\s*,\s*(True|1)|load_dtd\s*=\s*True"),
        Lang.CSHARP: re.compile(r"DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver|ProhibitDtd\s*=\s*false"),
        Lang.PHP: re.compile(r"LIBXML_NOENT|libxml_disable_entity_loader\(\s*false"),
    }
    java_factory = re.compile(
        r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory)\.newInstance\(|new\s+SAXBuilder\(|XMLReaderFactory\.createXMLReader\("
    )
    java_hardening = re.compile(
        r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|ACCESS_EXTERNAL_DTD|external-general-entities|setExpandEntityReferences\(\s*false"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        text = src.code_text
        if src.lang is Lang.JAVA and self.java_factory.search(text) and not self.java_hardening.search(text):
            for idx, line in enumerate(src.code_lines, start=1):
                if self.java_factory.search(line):
                    found.append(self.at_line(src, idx, "XML 파서 팩토리를 만들면서 DTD·외부 개체 차단 설정이 없습니다."))
        elif src.lang in self.insecure:
            for idx, line in enumerate(src.code_lines, start=1):
                if self.insecure[src.lang].search(line):
                    found.append(self.at_line(src, idx, "XML 외부 개체 처리를 허용하는 설정이 있습니다."))
        elif src.lang in JS_FAMILY:
            for idx, line in enumerate(src.code_lines, start=1):
                if re.search(r"noent\s*:\s*true", line):
                    found.append(self.at_line(src, idx, "libxmljs의 noent:true는 외부 개체 치환을 허용합니다."))
        return found


class CsrfDisabledRule(BaseRule):
    rule_id = "IL-510"
    name = "크로스사이트 요청 위조(CSRF) 방어 해제 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-11")
    plain = "로그인한 사용자가 악성 페이지를 열기만 해도 본인 권한으로 송금·삭제 같은 요청이 실행될 수 있습니다."
    how_to_fix = "CSRF 방어를 켜 두세요. 쿠키 인증을 쓰면 CSRF 토큰 또는 SameSite=Lax/Strict 쿠키를 쓰고, 토큰(Authorization 헤더) 방식이면 사유를 문서화하세요."
    patterns = [
        re.compile(r"\.csrf\(\)\s*\.disable\(\)|csrf\(\s*(AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\(\))"),
        re.compile(r"@csrf_exempt|csrf_exempt\(|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False|csrf\.exempt"),
        re.compile(r"\[IgnoreAntiforgeryToken\]"),
        re.compile(r"csrf\s*:\s*false|csrfProtection\s*=\s*false|\bcsrf\(\{\s*cookie\s*:\s*false"),
    ]

    def check_project(self, project: ProjectContext) -> list[Violation]:
        return _csrf_missing(self, project)

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None:
            return []
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            if any(p.search(line) for p in self.patterns):
                found.append(self.at_line(src, idx, "CSRF 방어를 해제하는 설정이 있습니다. 쿠키 기반 인증이면 위험합니다.", confidence=Confidence.REVIEW))
        return found


def _csrf_missing(self: BaseRule, project: ProjectContext) -> list[Violation]:
    text = "\n".join(f.code_text for f in project.source_files(include_tests=True))
    if re.search(r"(?i)csurf|csrf|lusca|samesite|CSRFProtect|flask_wtf|xsrf|antiforgery", text):
        return []
    found = []
    for src in project.source_files():
        if src.lang in JS_FAMILY and re.search(r"express-session|cookie-session", src.code_text):
            routes = len(re.findall(r"\b(?:app|router)\.(?:post|put|patch|delete)\(", text))
            if routes >= 3:
                m = re.search(r"express-session|cookie-session", src.code_text)
                line = src.code_text.count("\n", 0, m.start()) + 1
                found.append(self.at_line(src, line, f"쿠키 세션을 쓰는 Express 앱에 상태 변경 라우트 {routes}개가 있으나 CSRF 방어(csurf, SameSite 설정 등)가 프로젝트 어디에도 보이지 않습니다.", confidence=Confidence.REVIEW))
                break
    for src in project.source_files():
        if src.lang is Lang.PYTHON and re.search(r"\bFlask\(", src.code_text) and re.search(r"\bsession\b", src.code_text):
            posts = len(re.findall(r"methods\s*=\s*\[[^\]]*['\"]POST['\"]|@\w+\.post\(", text))
            if posts >= 3:
                found.append(self.at_line(src, 1, f"세션을 쓰는 Flask 앱에 POST 라우트 {posts}개가 있으나 CSRF 방어(Flask-WTF CSRFProtect 등)가 보이지 않습니다.", confidence=Confidence.REVIEW))
                break
    return found


class HeaderInjectionRule(SinkRule):
    rule_id = "IL-511"
    name = "HTTP 응답분할(헤더 삽입) 탐지"
    severity = Severity.MEDIUM
    gov_standard = mois_ref("1-13")
    plain = "받은 값이 응답 헤더에 섞이면 공격자가 줄바꿈을 넣어 가짜 응답이나 쿠키를 심을 수 있습니다."
    how_to_fix = "헤더·쿠키에 넣는 외부 값에서 CR/LF를 제거하거나 허용 문자만 남기세요. 프레임워크의 헤더 설정 API를 쓰세요."
    dynamic_is_finding = False
    tainted_message = "외부 입력이 {callee}로 응답 헤더에 쓰입니다. 개행 문자를 제거하십시오."
    sinks = [
        Sink.of(JS, r"^(res|response|reply)\.(setHeader|header|set|append|cookie)$", None),
        Sink.of(JAVA, r"(^|\.)(setHeader|addHeader|addCookie)$|^newCookie$", None),
        Sink.of(CS, r"Response\.(AppendHeader|AddHeader|Headers\.Add|Cookies\.Append)$", None),
        Sink.of(GO, r"\.Header\(\)\.(Set|Add)$|^http\.SetCookie$", None),
        Sink.of(PHP, r"^(header|setcookie)$", None),
    ]


class SecurityDecisionInputRule(BaseRule):
    rule_id = "IL-512"
    name = "보안기능 결정에 사용되는 부적절한 입력값 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-15")
    plain = "쿠키나 요청 값으로 '관리자인지'를 판단하면 사용자가 값을 바꿔 관리자 행세를 할 수 있습니다."
    how_to_fix = "권한과 역할은 서버 세션이나 서명된 토큰에서 읽으세요. 쿠키·파라미터·헤더에 담긴 값으로 권한을 결정하지 마세요."
    decision_re = re.compile(r"(?i)\b(is_?admin|admin|role|roles|permission|privilege|superuser|is_?staff)\b")
    if_types = {"if_statement", "if_expression", "ternary_expression", "conditional_expression"}

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        if src.root is None:
            return found
        for node in src.nodes:
            if node.type not in self.if_types:
                continue
            cond = node.child_by_field_name("condition")
            if cond is None:
                continue
            text = src.text_of(cond)
            if not self.decision_re.search(text):
                continue
            if expr_has_source(src, cond) or self._direct_cookie_flag(src, cond):
                found.append(self.at_node(src, node, "요청 값(쿠키·파라미터·헤더)으로 권한 여부를 판단합니다. 서버 측 세션/토큰 정보를 사용하십시오."))
        return found

    def _direct_cookie_flag(self, src: SourceFile, cond: Node) -> bool:
        return is_tainted(src, cond) and bool(re.search(r"(?i)cookie|header|param|query|body", src.text_of(cond)))



XPATH_TEXT_RE = re.compile(r"(?:/{1,2}[A-Za-z_*][\w:*-]*(?:\[|/|\s|$|['\"])|\[@|\bcount\(|\btext\(\))")


class XPathInjectionRule(SinkRule):
    rule_id = "IL-527"
    name = "XML(XPath) 삽입 탐지"
    severity = Severity.HIGH
    gov_standard = mois_ref("1-9")
    plain = "받은 값이 XML 검색식(XPath)에 섞이면 공격자가 조건을 바꿔 다른 사용자의 데이터를 조회하거나 인증을 우회할 수 있습니다."
    how_to_fix = "XPath 변수 바인딩(XPathVariableResolver, lxml의 xpath 변수 인자)을 쓰거나, 값에서 따옴표와 특수문자를 제거·이스케이프하세요."
    tainted_message = "외부 입력이 XPath 식에 결합되어 {callee}로 실행됩니다. 변수 바인딩을 쓰십시오."
    dynamic_message = "XPath 식을 변수와 결합해 {callee}로 실행합니다. 외부 입력이 닿는지 확인하고 변수 바인딩을 쓰십시오."
    sinks = [
        Sink.of(PY, r"\.(xpath|find|findall|iterfind)$"),
        Sink.of(JS, r"(^|\.)(evaluate|select|select1|selectNodes|xpath)$"),
        Sink.of(JAVA, r"(?i:xp\w*|xpath\w*|path\w*)\.(evaluate|compile)$|\.(selectNodes|selectSingleNode)$"),
        Sink.of(CS, r"(^|\.)(SelectNodes|SelectSingleNode|Evaluate)$|XPathExpression\.Compile$"),
        Sink.of(PHP, r"(->|::)xpath$|^xpath_eval$"),
    ]

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        return not XPATH_TEXT_RE.search(_context_text(src, arg))


class TrustBoundaryRule(SinkRule):
    rule_id = "IL-526"
    name = "신뢰 경계 위반 (검증 없는 입력을 세션에 저장) 탐지"
    severity = Severity.MEDIUM
    gov_standard = None
    plain = "검증하지 않은 사용자 입력을 세션에 넣으면, 나중에 서버가 그 값을 '믿을 수 있는 값'으로 오해해 권한 판단이나 쿼리에 그대로 쓰게 됩니다."
    how_to_fix = "세션에는 서버가 검증·생성한 값만 저장하세요. 사용자 입력은 형식·범위를 검증한 뒤에 저장하세요."
    dynamic_is_finding = False
    tainted_message = "검증되지 않은 외부 입력이 {callee}로 세션에 저장됩니다."
    sinks = [
        Sink.of(JAVA, r"(?i:session\w*(?:\(\))?)\.(setAttribute|putValue)$", None),
        Sink.of(PHP, r"^(session_id)$", None),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is Lang.PYTHON and src.root is not None:
            for node in src.nodes:
                if node.type != "assignment":
                    continue
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None and re.match(r"session\[", src.text_of(left)):
                    if is_tainted(src, right) and not ESCAPER_RE.search(src.text_of(right)):
                        found.append(self.at_node(src, node, "검증되지 않은 외부 입력이 session에 저장됩니다."))
        if src.lang in JS_FAMILY and src.root is not None:
            for node in src.nodes:
                if node.type == "assignment_expression":
                    left = node.child_by_field_name("left")
                    right = node.child_by_field_name("right")
                    if left is not None and right is not None and re.match(r"req\.session\.", src.text_of(left)):
                        if is_tainted(src, right):
                            found.append(self.at_node(src, node, "검증되지 않은 외부 입력이 req.session에 저장됩니다."))
        return found



class NoSqlInjectionRule(BaseRule):
    rule_id = "IL-533"
    name = "NoSQL 삽입($where·연산자 주입) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-1")
    plain = "MongoDB 같은 NoSQL도 받은 값이 검색 조건에 섞이면 공격자가 {\"$ne\": null} 같은 연산자를 넣어 로그인을 우회하거나 $where에 자바스크립트를 넣어 서버에서 실행시킬 수 있습니다."
    how_to_fix = "$where는 쓰지 말고 일반 연산자로 조건을 만드세요. 외부 값은 문자열·숫자로 형 변환·검증한 뒤 쿼리 객체에 넣고, 요청 본문 전체(req.body)를 그대로 쿼리에 넘기지 마세요."
    receiver_re = re.compile(r"(?i)(collection|\bdb\b|\bdb\.\w+|mongo|\bcoll\b|users?\b|accounts?\b|\w*Dao\b|\w*Col\b)|(?-i:\w+Model\b)")
    query_methods = re.compile(r"^(find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|aggregate|count|countDocuments|findOneAndUpdate|findOneAndDelete|find_one|update_one|update_many|delete_one|delete_many|count_documents)$")
    auth_keys = re.compile(r"(?i)(user(name)?|email|pass(word)?|token|key|login|id)\b")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.root is None or src.lang not in (JS_FAMILY | {Lang.PYTHON, Lang.JAVA}):
            return []
        found = []
        for node in src.nodes:
            if node.type in ("pair", "property_assignment", "dictionary_pair") or (node.type == "pair" and src.lang is Lang.PYTHON):
                v = self._where_pair(src, node)
                if v is not None:
                    found.append(v)
        for call in iter_calls(src):
            if "." not in call.callee or not call.args:
                continue
            receiver, method = call.callee.rsplit(".", 1)
            if not self.query_methods.match(method) or not self.receiver_re.search(receiver):
                continue
            arg = call.args[0]
            if is_literal(arg):
                continue
            text = src.text_of(arg)
            if arg.type in ("object", "dictionary"):
                bad = self._tainted_auth_value(src, arg)
                if bad:
                    found.append(self.at_node(src, call.node, f"외부 입력({bad})이 검증 없이 NoSQL 조회 조건 값으로 쓰입니다. 객체가 들어오면 연산자 주입이 가능합니다.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
            elif arg.type in ("identifier", "member_expression", "attribute", "subscript") and is_tainted(src, arg) and not re.search(r"String\(|str\(|parseInt|Number\(", text):
                found.append(self.at_node(src, call.node, f"{call.callee}의 조회 조건 전체가 외부 입력입니다. 연산자 주입이 가능합니다.", confidence=Confidence.REVIEW))
        return found

    def _where_pair(self, src: SourceFile, node: Node) -> Violation | None:
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None or src.text_of(key).strip("\"'") != "$where":
            return None
        if is_literal(value):
            return None
        tainted = is_tainted(src, value)
        return self.at_node(
            src,
            node,
            "$where에 동적으로 만든 문자열이 들어갑니다. 서버에서 자바스크립트로 실행되어 코드 삽입이 가능합니다.",
            severity=Severity.CRITICAL if tainted else Severity.HIGH,
            confidence=Confidence.CONFIRMED if tainted else Confidence.REVIEW,
        )

    def _tainted_auth_value(self, src: SourceFile, obj: Node) -> str:
        for pair in obj.named_children:
            if pair.type not in ("pair", "dictionary_pair"):
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None or is_literal(value):
                continue
            if self.auth_keys.search(src.text_of(key)) and is_tainted(src, value) and not re.search(r"String\(|str\(|parseInt|Number\(|toString\(", src.text_of(value)):
                return src.text_of(value)[:40]
        return ""


INJECTION_RULES: list[type[BaseRule]] = [
    SqlInjectionRule,
    PathTraversalRule,
    CodeInjectionRule,
    CommandInjectionRule,
    XssRule,
    SsrfRule,
    OpenRedirectRule,
    LdapInjectionRule,
    XxeRule,
    CsrfDisabledRule,
    HeaderInjectionRule,
    SecurityDecisionInputRule,
    UploadFilenameRule,
    XPathInjectionRule,
    TrustBoundaryRule,
    NoSqlInjectionRule,
]

__all__ = ["INJECTION_RULES"] + [r.__name__ for r in INJECTION_RULES]
