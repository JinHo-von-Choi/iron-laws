"""
오철칙 DB 조회 성능 규칙: 한도 없는 조회(PERF-104), 비동기 함수 안의 차단 호출(PERF-105), 한 함수의 과도한 조회(PERF-101)
작성자: 최진호
작성일: 2026-11-12
"""

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import iter_calls, iter_functions
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.rules.architecture import (
    FUNCTION_TYPE_SET,
    DbInLoopRule,
)
from iron_laws.rules.performance import MAX_PER_FILE, PerfRule, _function_of, _loops_around

QUERY_LIMIT = 5  # 한 함수에서 반복문 밖 DB 호출이 이 횟수 이상이면 알린다


SERVER_MARKERS = re.compile(r"(?i)\b(express|fastify|koa|hono|createServer|Bun\.serve|app\.listen|http\.Server|next/server|NextResponse)\b")


SQL_BOUNDED = re.compile(r"(?is)\b(where|limit|group\s+by|top\s+\d|fetch\s+first|rownum|count\s*\(|sum\s*\(|max\s*\(|min\s*\(|avg\s*\()")


BLOCKING_IN_ASYNC = re.compile(
    r"^(time\.sleep|requests\.(get|post|put|patch|delete|head)|urllib\.request\.urlopen|urlopen|subprocess\.(run|call|check_output|check_call)|os\.system|"
    r"fs\.(readFileSync|writeFileSync|appendFileSync|readdirSync|statSync)|execSync|spawnSync|child_process\.(execSync|spawnSync))$"
)


UNBOUNDED_SQL = re.compile(r"(?is)^\s*select\b.+?\bfrom\b")


SQL_LIMITED = re.compile(r"(?is)\b(where|limit|top|fetch\s+first|group\s+by|rownum)\b")


class UnboundedQueryRule(PerfRule):
    rule_id = "PERF-104"
    name = "한도 없는 조회 탐지"
    severity = Severity.LOW
    plain = (
        "조건이나 개수 제한 없이 테이블 전체를 가져오면 데이터가 쌓일수록 한 번의 요청이 점점 무거워지고, 어느 날 서버 메모리가 부족해 멈춥니다. "
        "지금은 행이 100개뿐이라 괜찮아 보여도 10만 개가 되면 같은 코드가 문제를 일으킵니다."
    )
    how_to_fix = (
        "필요한 만큼만 가져오세요: `LIMIT 50`, 페이지 번호(`OFFSET`), 조건(`WHERE`). ORM이면 `.limit(50)`, 슬라이스 `[:50]`, `Paginator`를 쓰세요. "
        "전체가 정말 필요하면 한 번에 다 읽지 말고 `fetchmany(1000)`처럼 나눠서 처리하세요."
    )
    all_call = re.compile(r"(?:^|\.)(fetchall|findAll|findMany)$")
    orm_all = re.compile(r"(?i)(objects|query|session|repo\w*|repository|\w*Repository)\b.*\.all$|\.objects\.all$|\.query\.all$")

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        for call in iter_calls(src):
            if call.line in reported:
                continue
            message = self._unbounded(src, call)
            if message is None:
                continue
            reported.add(call.line)
            found.append(self.at_node(src, call.node, message, severity=Severity.LOW, confidence=Confidence.REVIEW))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    def _unbounded(self, src: SourceFile, call) -> str | None:
        callee = call.callee
        statement = self._statement_text(src, call.node)
        has_limit = re.search(r"(?i)\.limit\(|\[\s*:\s*\d+\s*\]|\bpageable\b|\btake\s*:|\blimit\s*:|\bPageRequest\b|\.paginate\(|Paginator", statement)
        bounded_sql = SQL_BOUNDED.search(statement) is not None
        if callee.endswith(".fetchall") and not has_limit:
            if bounded_sql or self._previous_sql_bounded(src, call.node):
                return None  # 조건·집계가 있는 조회의 결과다
            return "`fetchall()`은 조회 결과를 한 번에 모두 메모리로 가져옵니다. 데이터가 쌓이면 서버 메모리가 부족해질 수 있습니다."
        if callee.endswith(".findAll") and not call.args and not has_limit:
            return "`findAll()`은 테이블 전체를 가져옵니다. 페이지 단위(Pageable)로 가져오세요."
        if callee.endswith(".findMany") and not call.args and not has_limit:
            return "`findMany()`에 조건·개수 제한이 없어 테이블 전체를 가져옵니다."
        if self.orm_all.search(callee) and callee.endswith(".all") and not has_limit and not bounded_sql:
            return "`.all()`은 조건 없이 테이블 전체를 가져옵니다. 개수 제한이나 페이지를 붙이세요."
        if re.search(r"(?:^|\.)(execute|executemany|query|raw|prepareStatement|createQuery|createNativeQuery)$", callee) and call.args:
            first = call.args[0]
            if first.type in ("string", "string_literal", "template_string", "concatenated_string"):
                sql = src.text_of(first).strip("\"'`")
                if UNBOUNDED_SQL.match(sql) and not SQL_LIMITED.search(sql) and not SQL_BOUNDED.search(sql) and not has_limit:
                    return "`SELECT`에 `WHERE`·`LIMIT`이 없어 테이블 전체를 가져옵니다."
        return None

    @staticmethod
    def _previous_sql_bounded(src: SourceFile, node: Node) -> bool:
        """같은 함수에서 이 호출 앞의 가장 가까운 SQL 문자열에 조건·집계가 있는가"""
        fn = _function_of(node)
        text = src.text_of(fn) if fn is not None else src.text
        before = text[: max(0, node.start_byte - (fn.start_byte if fn is not None else 0))]
        sqls = re.findall(r"(?is)(select\b.*?)(?:[\"'`]\s*[,)]|[\"'`]\s*$|\"\"\"|$)", before)
        return bool(sqls) and SQL_BOUNDED.search(sqls[-1]) is not None

    @staticmethod
    def _statement_text(src: SourceFile, node: Node) -> str:
        current = node
        while current.parent is not None and current.parent.type not in FUNCTION_TYPE_SET and current.parent.type not in ("module", "program", "block", "statement_block", "class_body"):
            current = current.parent
        return src.text_of(current)


class BlockingInAsyncRule(PerfRule):
    version = 2
    rule_id = "PERF-105"
    name = "비동기 함수 안의 막는 호출 탐지"
    severity = Severity.MEDIUM
    plain = (
        "비동기(`async`) 서버는 한 줄로 모든 사용자를 처리합니다. 그 안에서 `time.sleep`이나 동기 `requests` 같은 '기다리는 호출'을 하면 그동안 다른 모든 사용자의 요청이 멈춥니다. "
        "한 명이 줄을 서면 뒤 사람이 모두 기다리는 것과 같습니다."
    )
    how_to_fix = (
        "비동기용 짝을 쓰세요. `time.sleep` → `await asyncio.sleep`, `requests` → `httpx.AsyncClient`/`aiohttp`, 파일·외부 프로그램 → `asyncio.to_thread(...)`로 별도 스레드에서 실행. "
        "JS는 `readFileSync` 대신 `await fs.promises.readFile`을 쓰세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        found: list[Violation] = []
        reported: set[int] = set()
        asyncs = [fn for fn in iter_functions(src) if self._is_async(src, fn.node)]
        if not asyncs:
            return []
        server_like = src.lang is Lang.PYTHON or SERVER_MARKERS.search(src.text) is not None  # JS·TS의 CLI 스크립트는 동기 호출이 흔해 서버 코드에서만 본다
        for call in iter_calls(src):
            if call.line in reported or not BLOCKING_IN_ASYNC.match(call.callee) or not server_like:
                continue
            owner = self._owner_async(src, call.node)
            if owner is None:
                continue
            reported.add(call.line)
            light = bool(re.match(r"^fs\.", call.callee))  # 작은 파일의 동기 읽기·쓰기는 영향이 작아 낮게 둔다. sleep·요청·프로그램 실행은 오래 멈춘다
            found.append(self.at_node(src, call.node, "비동기 함수 안에서 기다리는(막는) 호출을 합니다. 다른 모든 요청이 그동안 멈춥니다.", severity=Severity.LOW if light else Severity.MEDIUM, confidence=Confidence.REVIEW))
            if len(found) >= MAX_PER_FILE:
                break
        return found

    @staticmethod
    def _is_async(src: SourceFile, fn: Node) -> bool:
        head = src.text_of(fn)[:40]
        return head.lstrip().startswith("async") or (fn.parent is not None and fn.parent.type == "decorated_definition" and "async def" in src.text_of(fn)[:20])

    def _owner_async(self, src: SourceFile, node: Node) -> Node | None:
        """가장 가까운 함수가 async이면 그 함수(중첩 일반 함수는 제외)"""
        fn = _function_of(node)
        if fn is None:
            return None
        return fn if self._is_async(src, fn) else None


class ManyQueriesRule(PerfRule):
    version = 2
    rule_id = "PERF-101"
    name = "한 함수 안의 DB 조회 과다 탐지"
    severity = Severity.LOW
    plain = (
        "화면 하나를 만들려고 DB에 여러 번 따로 묻는 코드는 한 번에 묻는 코드보다 훨씬 느립니다. DB에 한 번 갔다 오는 데 걸리는 시간이 매번 더해지기 때문입니다. "
        f"한 함수에서 반복문 밖에서도 DB 호출이 {QUERY_LIMIT}번 이상이면 알려 드립니다."
    )
    how_to_fix = (
        "여러 번 묻는 것을 `JOIN`이나 `IN (...)` 조건으로 한 번에 가져오세요. 같은 값을 여러 번 조회하면 변수에 담아 재사용하고, 자주 바뀌지 않는 값은 캐시하세요. "
        "ORM이면 `select_related`/`prefetch_related`(Django), `joinedload`(SQLAlchemy), `include`(Prisma)를 쓰세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        if not self.usable(src):
            return []
        in_loop_lines = {c.line for c in iter_calls(src) if DbInLoopRule._db_call_kind(c.callee, src.lang) and _loops_around(c.node)}
        per_function: dict[int, list] = {}
        for call in iter_calls(src):
            if DbInLoopRule._db_call_kind(call.callee, src.lang) is None or call.line in in_loop_lines:
                continue
            fn = _function_of(call.node)
            if fn is None:
                continue
            per_function.setdefault(fn.id, []).append(call)
        found: list[Violation] = []
        for calls in per_function.values():
            if len(calls) < QUERY_LIMIT:
                continue
            first = min(calls, key=lambda c: c.node.start_byte)
            severity = Severity.MEDIUM if len(calls) >= QUERY_LIMIT * 2 else Severity.LOW
            found.append(
                self.at_node(src, first.node, f"한 함수 안에서 DB를 {len(calls)}번 호출합니다. 한 번에 가져올 수 있는지 확인하세요.", severity=severity, confidence=Confidence.REVIEW)
            )
        return found[:MAX_PER_FILE]
