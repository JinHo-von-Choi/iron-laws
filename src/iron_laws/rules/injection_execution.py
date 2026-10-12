"""injection execution 규칙."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    is_literal,
    iter_calls,
    iter_functions,
)
from iron_laws.engine.java_literals import is_closed_java
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
)
from iron_laws.rules.injection_common import (
    DB_RECEIVER_RE,
    DDL_TEXT_RE,
    SQL_TEXT_RE,
    STRONG_SQL_CALLEES,
    SinkRule,
    _context_text,
)
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
)
from iron_laws.standards import mois_ref


class SqlInjectionRule(SinkRule):
    version = 2
    rule_id = "IL-501"
    taint_ctx = Ctx.SQL
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
        Sink.of(PY, r"(^|\.)(fetch|fetchrow|fetchval|fetchmany)$"),  # asyncpg: 질의문을 직접 실행하는 API
        Sink.of(JS, r"(^|\.)(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|queryRawUnsafe|executeRawUnsafe|unsafe|all|get|run|exec)$"),
        Sink.of(JAVA, r"(^|\.)(executeQuery|executeUpdate|execute|executeLargeUpdate|createQuery|createNativeQuery|prepareStatement|prepareCall|queryForObject|queryForList|queryForMap|update|batchUpdate|query)$"),
        Sink.of(CS, r"(^|\.)(ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQuery|QueryAsync|ExecuteAsync|QueryFirst|QuerySingle)$"),
        Sink.of(CS, r"^new(SqlCommand|MySqlCommand|NpgsqlCommand|OleDbCommand|OdbcCommand|SqliteCommand|OracleCommand|SqlDataAdapter)$"),
        Sink.of(GO, r"(^|\.)(Query|QueryRow|Exec|Prepare|Raw)$"),
        Sink.of(GO, r"(^|\.)(QueryContext|QueryRowContext|ExecContext|PrepareContext)$", 1),  # 첫 인자는 context
        Sink.of(GO, r"(^|\.)(Select|Get)$", None),  # sqlx는 (대상, 쿼리, 인자...) 순서
        Sink.of(PHP, r"^(mysqli_query|mysql_query|pg_query|sqlite_query|odbc_exec)$", 1),
        Sink.of(PHP, r"(->|::)(query|exec|prepare|real_query|multi_query)$"),
        Sink.of(CFAM, r"^(mysql_query|mysql_real_query|sqlite3_exec|PQexec|SQLExecDirect)$", 1),
        Sink.of(RUST, r"(^|::|\.)(query|execute|query_as|query_scalar|raw_sql)$"),
    ]

    placeholder_re = re.compile(r"\$\d+|%s|%\(\w+\)s|\?|:\w+|@\w+")
    migration_path_re = re.compile(r"(?i)(migration|alembic|versions|flyway|liquibase|schema|seed)")

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        context = _context_text(src, arg)
        if src.lang is Lang.JAVA and flow is Flow.DYNAMIC and is_closed_java(src, arg):
            return True
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
    taint_ctx = Ctx.CODE
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
        Sink.of(JAVA, r"(^|\.)parseExpression$|^Ognl\.(getValue|parseExpression)$|^MVEL\.(eval|executeExpression|compileExpression)$", 0),
        Sink.of(CS, r"CSharpScript\.(EvaluateAsync|RunAsync)$"),
        Sink.of(PHP, r"^(eval|assert|create_function)$"),
    ]
    SPEL_STANDARD = re.compile(r"\bStandardEvaluationContext\b")
    EVAL_METHODS = frozenset({"getValue", "setValue", "getValueType"})

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang is not Lang.JAVA or src.root is None:
            return found
        # 동적 SpEL 식은 StandardEvaluationContext(형식 참조 T(...)로 임의 클래스 호출 가능)로 평가할 때만 확인 대상이다.
        # SimpleEvaluationContext만 쓰는 함수의 동적 식은 지적하지 않는다
        kept = []
        for v in found:
            spel = "parseExpression" in v.message and "Ognl." not in v.message
            if v.confidence is Confidence.REVIEW and spel and self._simple_context_only_at(src, v.line_number):
                continue  # OGNL·MVEL은 컨텍스트와 무관하게 임의 코드 실행이 가능하므로 동적 식이면 그대로 남긴다
            kept.append(v)
        kept += self._spel_dynamic_parse(src, {v.line_number for v in kept})
        return kept + self._spel_standard_evaluation(src, {v.line_number for v in kept})

    def _spel_dynamic_parse(self, src: SourceFile, reported: set[int]) -> list[Violation]:
        """상수가 아닌 문자열을 SpEL 식으로 파싱하는 호출(SimpleEvaluationContext만 쓰는 함수는 제외). getValue()의 기본 컨텍스트는 StandardEvaluationContext다"""
        found = []
        for call in iter_calls(src):
            if not call.callee.endswith("parseExpression") or call.callee.startswith("Ognl.") or not call.args or call.line in reported:
                continue
            fn = self._function_at(src, call.line)
            text = src.text_of(fn.node) if fn is not None else ""
            arg = src.text_of(call.args[0]).strip()
            constants = {m.group(1) for m in re.finditer(r"\b(\w+)\s*=\s*\"[^\"]*\"\s*;", text) if len(re.findall(rf"\b{re.escape(m.group(1))}\s*=[^=]", text)) == 1}
            if is_literal(call.args[0]) or arg in constants or self._simple_context_only_at(src, call.line):
                continue
            found.append(self.at_node(
                src, call.node,
                f"상수가 아닌 문자열을 SpEL 식으로 파싱합니다({call.callee}). 식 문자열이 설정·입력에서 오면 StandardEvaluationContext(기본 컨텍스트 포함)에서 T(...) 형식 참조로 임의 코드가 실행됩니다. SimpleEvaluationContext로 평가하십시오.",
                severity=Severity.HIGH, confidence=Confidence.REVIEW,
            ))
        return found

    def _function_at(self, src: SourceFile, line: int):
        for fn in iter_functions(src):
            if src.line_of(fn.node) <= line <= fn.node.end_point[0] + 1:
                return fn
        return None

    def _simple_context_only_at(self, src: SourceFile, line: int) -> bool:
        """함수가 SimpleEvaluationContext만 쓴다. Expression.getValue()는 컨텍스트를 주지 않으면 StandardEvaluationContext로 평가하므로
        SimpleEvaluationContext를 명시하지 않은 동적 식은 확인 대상이다"""
        fn = self._function_at(src, line)
        text = src.text_of(fn.node) if fn is not None else ""
        return "SimpleEvaluationContext" in text and not self.SPEL_STANDARD.search(text)

    def _spel_standard_evaluation(self, src: SourceFile, reported: set[int]) -> list[Violation]:
        """상수가 아닌 식(이 함수에서 동적 문자열로 파싱했거나 필드·매개변수로 받은 식)을 StandardEvaluationContext로 평가하는 호출.
        식 문자열이 설정·입력에서 오면 원격 코드 실행이 된다"""
        found = []
        if not self.SPEL_STANDARD.search(src.code_text):
            return found
        calls = [c for c in iter_calls(src) if c.callee.rpartition(".")[2] in self.EVAL_METHODS]
        for fn in iter_functions(src):
            text = src.text_of(fn.node)
            if not self.SPEL_STANDARD.search(text):
                continue
            # 이 함수에서 만들었거나 매개변수·지역 변수로 선언한 StandardEvaluationContext 이름
            contexts = set(re.findall(r"\b(\w+)\s*=\s*new\s+StandardEvaluationContext\s*\(", text)) | set(re.findall(r"\bStandardEvaluationContext\s+(\w+)", text))
            constants = {m.group(1) for m in re.finditer(r"\b(\w+)\s*=\s*\"[^\"]*\"\s*;", text) if len(re.findall(rf"\b{re.escape(m.group(1))}\s*=[^=]", text)) == 1}
            # 이 함수에서 파싱한 식 변수 → 상수 문자열(또는 한 번만 상수를 담은 변수)로 파싱했는가
            parsed_here = {}
            for m in re.finditer(r"\b(\w+)\s*=\s*[^;=]*?\bparseExpression\s*\(\s*(\"(?:[^\"\\\\]|\\\\.)*\"|\w+)\s*([,)]?)", text):
                # 인자 전체가 문자열 하나이거나 상수 하나만 담은 변수여야 상수다("prefix." + 입력은 동적)
                parsed_here[m.group(1)] = bool(m.group(3)) and (m.group(2).startswith('"') or m.group(2) in constants)
            for call in calls:
                if not (fn.node.start_byte <= call.node.start_byte < fn.node.end_byte) or call.line in reported:
                    continue
                receiver, _, method = call.callee.rpartition(".")
                if method not in self.EVAL_METHODS or not receiver or receiver in parsed_here or not re.fullmatch(r"(this\.)?\w+", receiver):
                    continue  # 이 함수에서 파싱한 식은 파싱 지점에서 판정한다
                if not any(src.text_of(a).strip() in contexts for a in call.args):
                    continue
                found.append(self.at_node(
                    src, call.node,
                    f"함수 밖에서 만든 SpEL 식({receiver})을 StandardEvaluationContext로 평가합니다. 식 문자열이 설정·입력에서 오면 T(...) 형식 참조로 임의 코드가 실행됩니다. SimpleEvaluationContext를 쓰십시오.",
                    severity=Severity.HIGH, confidence=Confidence.REVIEW,
                ))
        return found


class CommandInjectionRule(SinkRule):
    rule_id = "IL-504"
    taint_ctx = Ctx.SHELL
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
    explicit_shell_re = re.compile(
        r"""["'](?:sh|bash|zsh|dash|ksh|/bin/(?:ba)?sh|/usr/bin/env|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)["']\s*,\s*(?:\[\s*)?["'](?:-c|/c|/k|-Command|-lc)["']"""
    )
    sinks = [
        Sink.of(PY, r"^(os\.system|os\.popen|commands\.getoutput|pty\.spawn)$"),
        Sink.of(PY, r"^subprocess\.(call|run|Popen|check_output|check_call|getoutput)$"),
        Sink.of(JS, r"(^|\.)(exec|execSync)$"),
        Sink.of(JS, r"(^|\.)(spawn|spawnSync|execFile|execFileSync)$", None),
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
            if self.explicit_shell_re.search(call_text):
                return False  # ["sh", "-c", 입력]은 인자 배열이어도 셸이 문자열을 다시 해석한다
            return arg.type in ("list", "tuple") and not re.search(r"shell\s*=\s*True", call_text)
        if re.search(r"(^|\.)(spawn|spawnSync|execFile|execFileSync)$", callee):
            return not (re.search(r"shell\s*:\s*true", call_text) or self.explicit_shell_re.search(call_text))
        if callee.endswith("exec") and src.lang is Lang.JAVA:
            return arg.type == "array_creation_expression" and not self.shell_word_re.search(call_text)
        if callee in ("newProcessBuilder", "Process.Start") or callee.startswith("exec.Command"):
            if bool(self.shell_word_re.search(call_text)):
                return False
            return flow is not Flow.TAINTED or callee.startswith("exec.Command")
        return False
