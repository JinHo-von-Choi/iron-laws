"""injection execution 규칙."""
import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
    string_value,
)
from iron_laws.engine.java_literals import is_closed_java
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    Ctx,
    is_tainted,
    reaching_definitions,
)
from iron_laws.rules.guards import PassFacts
from iron_laws.rules.injection_common import (
    DB_RECEIVER_RE,
    DDL_TEXT_RE,
    SQL_TEXT_RE,
    STRONG_SQL_CALLEES,
    SinkRule,
    _context_text,
    quote_guard_verdict,
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
    assess,
)
from iron_laws.standards import mois_ref


class SqlInjectionRule(SinkRule):
    version = 4
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
        Sink.of(JAVA, r"(^|\.)(executeQuery|executeUpdate|execute|executeLargeUpdate|createQuery|createNativeQuery|prepareStatement|prepareCall|queryForObject|queryForList|queryForMap|queryForRowSet|addBatch|update|batchUpdate|query)$"),
        Sink.of(CS, r"(^|\.)(ExecuteReader|ExecuteNonQuery|ExecuteScalar|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQuery|QueryAsync|ExecuteAsync|QueryFirst|QuerySingle)$"),
        Sink.of(CS, r"^new(SqlCommand|MySqlCommand|NpgsqlCommand|OleDbCommand|OdbcCommand|SqliteCommand|OracleCommand|SqlDataAdapter)$"),
        Sink.assigned(CS, r"\.CommandText$"),  # cmd.CommandText = 질의, += 조각. 매개변수 바인딩(Parameters.Add)만 쓰면 값에 외부 입력이 없다
        Sink.of(GO, r"(^|\.)(Query|QueryRow|Exec|Prepare|Raw)$"),
        Sink.of(GO, r"(^|\.)(QueryContext|QueryRowContext|ExecContext|PrepareContext)$", 1),  # 첫 인자는 context
        Sink.of(GO, r"(^|\.)(Select|Get)$", None),  # sqlx는 (대상, 쿼리, 인자...) 순서
        Sink.of(PHP, r"^(mysqli_query|mysql_query|pg_query|sqlite_query|odbc_exec)$", 1),
        Sink.of(PHP, r"(->|::)(query|exec|prepare|real_query|multi_query)$"),
        Sink.of(CFAM, r"^(mysql_query|mysql_real_query|sqlite3_exec|PQexec|SQLExecDirect)$", 1),
        Sink.of(RUST, r"(^|::|\.)(query|execute|query_as|query_scalar|raw_sql)$"),
    ]

    placeholder_re = re.compile(r"\$\d+|%s|%\(\w+\)s|\?|:\w+|@\w+")

    def guard_verdict(self, src: SourceFile, call: Call, arg: Node, facts: dict[str, PassFacts]) -> str | None:
        return quote_guard_verdict(self, facts, _context_text(src, arg))
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
    version = 3
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
        Sink.of(CS, r"\.CompileAssemblyFrom(Source|Dom)$", None),
        Sink.of(PHP, r"^(eval|assert|create_function)$"),
    ]
    SPEL_STANDARD = re.compile(r"\bStandardEvaluationContext\b")
    EVAL_METHODS = frozenset({"getValue", "setValue", "getValueType"})

    def guard_verdict(self, src: SourceFile, call: Call, arg: Node, facts: dict[str, PassFacts]) -> str | None:
        """값이 문자열 리터럴 하나인지(앞뒤 따옴표, 안쪽에 같은 따옴표 없음) 확인한 검사는 확인 필요로 낮춘다"""
        if facts and all(f.quoted for f in facts.values()):
            return self.guard_reason(facts)
        return None

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
    version = 3
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
    # 식별자 형식 검사(isidentifier)는 실행할 프로그램 이름을 고르는 것을 막지 못한다
    safe_character_predicates = frozenset({"isalnum", "isalpha", "isdigit", "isdecimal", "isnumeric"})
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
        Sink.of(CFAM, r"^(system|popen|_popen|_wsystem|_wpopen)$"),
        # exec 계열은 실행할 프로그램과 인자를 모두 인자로 받는다(`execl("/bin/sh", "sh", "-c", 명령, NULL)`)
        Sink.of(CFAM, r"^_?w?exec(l|lp|le|v|vp|ve|vpe)$", None),
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

    # 값만 바뀌어도 실행할 프로그램이나 불러올 코드를 바꾸는 환경 변수
    EXEC_ENV_KEYS = frozenset({"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "IFS", "PYTHONPATH", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS"})
    PROCESS_BUILDER_RE = re.compile(r"^(?:new\s+)?(?:java\.lang\.)?ProcessBuilder\s*\(")
    ENV_ENTRY_KEY_RE = re.compile(r'^"([A-Za-z_][A-Za-z0-9_]*)=')

    def check(self, src: SourceFile) -> list[Violation]:
        found = super().check(src)
        if src.lang in JAVA and src.root is not None:
            taken = {v.line_number for v in found}
            found.extend(v for v in self._java_exec_env(src) + self._process_builder_starts(src) if v.line_number not in taken)
        return found

    def _env_verdict(self, key: str | None, key_tainted: bool) -> Confidence:
        """값이 외부 입력인 환경 변수 항목의 판정: 키를 외부 입력이 정하거나 실행을 바꾸는 키면 확정, 그 밖의 고정 키면 확인 필요"""
        if key_tainted or key is None or key in self.EXEC_ENV_KEYS:
            return Confidence.CONFIRMED
        return Confidence.REVIEW

    @staticmethod
    def _env_advice(confidence: Confidence) -> str:
        if confidence is Confidence.CONFIRMED:
            return "이 변수는 실행할 프로그램이나 불러올 라이브러리를 바꿀 수 있으니 고정 값만 넘기십시오."
        return "실행되는 프로그램이 이 변수 값을 명령이나 경로로 쓰는지 확인하십시오."

    def _env_entry_key(self, src: SourceFile, node: Node, depth: int = 0) -> str | None:
        """`"KEY=" + 값` 꼴 항목의 고정 키. 키 자리까지 외부 입력이면 None"""
        while node.type == "parenthesized_expression" and node.named_children:
            node = node.named_children[0]
        if node.type == "binary_expression":
            left = node.child_by_field_name("left")
            return self._env_entry_key(src, left, depth) if left is not None else None
        if node.type == "string_literal":
            m = self.ENV_ENTRY_KEY_RE.match(src.text_of(node))
            return m.group(1) if m else None
        if node.type == "identifier" and depth < 2:
            scope = enclosing_function(node, src.lang) or src.root
            defs = reaching_definitions(src, scope, src.text_of(node), node.start_byte) if scope is not None else []
            return self._env_entry_key(src, defs[0], depth + 1) if len(defs) == 1 else None
        return None

    def _array_items(self, src: SourceFile, node: Node, depth: int = 0) -> list[Node] | None:
        if node.type == "array_initializer":
            return [c for c in node.named_children if "comment" not in c.type]
        if node.type == "array_creation_expression":
            init = next((c for c in node.named_children if c.type == "array_initializer"), None)
            return self._array_items(src, init) if init is not None else None
        if node.type == "identifier" and depth < 2:
            scope = enclosing_function(node, src.lang) or src.root
            defs = reaching_definitions(src, scope, src.text_of(node), node.start_byte) if scope is not None else []
            return self._array_items(src, defs[0], depth + 1) if len(defs) == 1 else None
        return None

    def _java_exec_env(self, src: SourceFile) -> list[Violation]:
        """Runtime.exec(명령, 환경 변수 배열, ...)의 환경 변수 항목을 키 종류별로 판정한다"""
        found = []
        for call in iter_calls(src):
            if not re.search(r"(^|\.)exec$", call.callee) or len(call.args) < 2:
                continue
            envp = call.args[1]
            if is_literal(envp) or not is_tainted(src, envp, ctx=Ctx.SHELL):
                continue
            items = self._array_items(src, envp)
            verdicts = []
            for item in items if items is not None else []:
                if is_literal(item) or not is_tainted(src, item, ctx=Ctx.SHELL):
                    continue
                key = self._env_entry_key(src, item)
                verdicts.append((self._env_verdict(key, key is None), key))
            if items is None:
                verdicts.append((Confidence.REVIEW, None))  # 배열을 어떻게 만들었는지 몰라 키를 알 수 없다
            if not verdicts:
                continue
            confidence = Confidence.CONFIRMED if any(c is Confidence.CONFIRMED for c, _ in verdicts) else Confidence.REVIEW
            keys = ", ".join(sorted({k for _, k in verdicts if k})) or "항목 전체"
            found.append(self.at_node(
                src, call.node, f"외부 입력이 {call.callee}의 환경 변수({keys})로 들어갑니다. " + self._env_advice(confidence),
                confidence=confidence, severity=Severity.CRITICAL if confidence is Confidence.CONFIRMED else Severity.HIGH,
            ))
        return found

    def _process_builder_starts(self, src: SourceFile) -> list[Violation]:
        """ProcessBuilder는 start() 시점의 명령 목록과 환경을 본다. 그 앞의 마지막 command(...)와 environment().put(...)을 따라간다"""
        found = []
        calls = list(iter_calls(src))
        for start in calls:
            m = re.fullmatch(r"(\w+)\.start", start.callee)
            if m is None or start.args:
                continue
            builder = m.group(1)
            scope = enclosing_function(start.node, src.lang)
            if scope is None:
                continue
            defs = reaching_definitions(src, scope, builder, start.node.start_byte)
            if not defs or not all(self.PROCESS_BUILDER_RE.match(src.text_of(d).strip()) for d in defs):
                continue
            before = [c for c in calls if scope.start_byte <= c.node.start_byte and c.node.end_byte <= start.node.start_byte]
            commands = [c for c in before if c.callee == f"{builder}.command" and c.args]
            if commands and any(not is_literal(a) and assess(src, a, ctx=Ctx.SHELL) is Flow.TAINTED for a in commands[-1].args):
                found.append(self.at_node(src, commands[-1].node, f"외부 입력이 {builder}.command로 실행할 명령 목록에 들어가 {builder}.start()로 실행됩니다. 허용 목록으로 검증하십시오."))
            env_holders = {f"{builder}.environment()"}
            for c in before:
                receiver, _, method = c.callee.rpartition(".")
                if method != "put" or len(c.args) < 2:
                    continue
                if receiver not in env_holders:
                    holder_defs = reaching_definitions(src, scope, receiver, c.node.start_byte) if re.fullmatch(r"\w+", receiver) else []
                    if not holder_defs or not all(src.text_of(d).strip() == f"{builder}.environment()" for d in holder_defs):
                        continue
                key, value = c.args[0], c.args[1]
                key_tainted = not is_literal(key) and is_tainted(src, key, ctx=Ctx.SHELL)
                if not key_tainted and (is_literal(value) or not is_tainted(src, value, ctx=Ctx.SHELL)):
                    continue
                name = string_value(src, key) if key.type == "string_literal" else None
                confidence = self._env_verdict(name, key_tainted)
                found.append(self.at_node(
                    src, c.node, f"외부 입력이 {builder}의 환경 변수({name or '키'})로 들어가 {builder}.start()로 실행됩니다. " + self._env_advice(confidence),
                    confidence=confidence, severity=Severity.CRITICAL if confidence is Confidence.CONFIRMED else Severity.HIGH,
                ))
        return found
