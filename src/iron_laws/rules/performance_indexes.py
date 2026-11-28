"""
오철칙 인덱스 누락 규칙(PERF-106): 조회 조건에 쓰는 열에 인덱스가 없으면, 행이 늘수록 그 조회가 표 전체를 훑는다.

- 스키마: SQL 파일(DDL·마이그레이션)의 CREATE TABLE(PRIMARY KEY·UNIQUE)·CREATE INDEX, Prisma 스키마(@id·@unique·@@index·@@unique·@@id).
  Prisma 스키마는 점검 대상 확장자가 아니어서 프로젝트 폴더에서 따로 읽는다.
- 조회 조건: 코드 문자열의 SQL `FROM 표 … WHERE 열 =`, Prisma `prisma.모델.findMany|findFirst|findUnique|count({ where: { 열: …`.
- 스키마에 그 표가 있을 때만 판정한다. 복합 인덱스는 첫 열만 인덱스로 본다. 모두 확인 필요(REVIEW)다.
작성자: 최진호
작성일: 2026-11-28
"""

import re

from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile
from iron_laws.rules.performance import PerfRule

CREATE_TABLE = re.compile(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?(?:\w+\.)?(\w+)[`\"\]]?\s*\((.*?)\)\s*;")
CREATE_INDEX = re.compile(r"(?is)create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?[`\"\[]?\w*[`\"\]]?\s+on\s+[`\"\[]?(?:\w+\.)?(\w+)[`\"\]]?\s*(?:using\s+\w+\s*)?\(\s*[`\"\[]?(\w+)")
ALTER_KEY = re.compile(r"(?is)alter\s+table\s+(?:only\s+)?[`\"\[]?(?:\w+\.)?(\w+)[`\"\]]?\s+add\s+(?:constraint\s+\w+\s+)?(?:primary\s+key|unique)\s*(?:\w+\s*)?\(\s*[`\"\[]?(\w+)")
INLINE_KEY = re.compile(r"(?im)^\s*[`\"\[]?(\w+)[`\"\]]?\s+[^,\n]*?\b(?:primary\s+key|unique)\b")
TABLE_KEY = re.compile(r"(?is)\b(?:primary\s+key|unique)\s*(?:\w+\s*)?\(\s*[`\"\[]?(\w+)")
PRISMA_MODEL = re.compile(r"(?ms)^model\s+(\w+)\s*\{(.*?)^\}")
PRISMA_FIELD_KEY = re.compile(r"(?m)^\s*(\w+)\s+\S+[^\n]*@(?:id|unique)\b")
PRISMA_BLOCK_KEY = re.compile(r"@@(?:index|unique|id)\(\s*(?:fields:\s*)?\[\s*(\w+)")
SQL_WHERE = re.compile(r"(?is)\bfrom\s+[`\"\[]?(?:\w+\.)?(\w+)[`\"\]]?(?:\s+(?:as\s+)?(?!where\b)\w+)?\s+where\s+(?:\w+\.)?[`\"\[]?(\w+)[`\"\]]?\s*(?:=|in\b|like\b|>|<)")
PRISMA_WHERE = re.compile(r"\bprisma\.(\w+)\.(?:findMany|findFirst|findFirstOrThrow|findUnique|count|deleteMany|updateMany)\(\s*\{\s*where\s*:\s*\{\s*(\w+)\s*:")


def _schema(project: ProjectContext) -> dict[str, set[str]]:
    """표(소문자) → 인덱스가 있는 열(소문자). 스키마를 찾지 못하면 빈 사전"""
    indexed: dict[str, set[str]] = {}
    for f in project.by_kind("sql"):
        for table, body in CREATE_TABLE.findall(f.text):
            cols = indexed.setdefault(table.lower(), set())
            cols.update(c.lower() for c in INLINE_KEY.findall(body))
            cols.update(c.lower() for c in TABLE_KEY.findall(body))
        for table, col in (*CREATE_INDEX.findall(f.text), *ALTER_KEY.findall(f.text)):
            indexed.setdefault(table.lower(), set()).add(col.lower())
    for rel in sorted(p for p in project.all_paths if p.endswith(".prisma")):
        try:
            text = (project.root / rel).read_text(encoding="utf-8", errors="replace") if project.root.is_dir() else ""
        except OSError:  # iron-laws: ignore[IL-301] 읽지 못한 Prisma 스키마는 인덱스 판정에 쓰지 않는다
            continue
        for model, body in PRISMA_MODEL.findall(text):
            cols = indexed.setdefault(model.lower(), set())
            cols.update(c.lower() for c in PRISMA_FIELD_KEY.findall(body))
            cols.update(c.lower() for c in PRISMA_BLOCK_KEY.findall(body))
    return indexed


class MissingIndexRule(PerfRule):
    rule_id = "PERF-106"
    name = "조회 조건 열의 인덱스 없음"
    severity = Severity.LOW
    plain = "조회 조건에 쓰는 열에 인덱스가 없으면, DB는 행이 늘수록 그 조회마다 표 전체를 훑습니다. 처음에는 빠르다가 데이터가 쌓이면 화면이 느려지고 DB가 바빠집니다."
    how_to_fix = (
        "자주 조회 조건으로 쓰는 열에 인덱스를 마이그레이션으로 더하세요. 예: `CREATE INDEX idx_orders_user_id ON orders (user_id);`, Prisma면 모델에 `@@index([userId])`. "
        "고친 뒤에는 DB의 실행 계획(`EXPLAIN`)에서 표 전체 훑기(Seq Scan·SCAN TABLE)가 사라졌는지 확인하세요."
    )

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        schema = _schema(project)
        if not schema:
            return []
        found: list[Violation] = []
        seen: set[tuple[str, str, str]] = set()
        for f in project.source_files():
            if not self.usable(f):
                continue
            for pattern in (SQL_WHERE, PRISMA_WHERE):
                for m in pattern.finditer(f.text):
                    table, col = m.group(1).lower(), m.group(2).lower()
                    if table not in schema or col in schema[table] or col == "id":
                        continue
                    key = (f.path.as_posix(), table, col)
                    if key in seen:
                        continue
                    seen.add(key)
                    line = f.text.count("\n", 0, m.start()) + 1
                    found.append(
                        self.at_line(
                            f, line,
                            f"표 {m.group(1)}의 {m.group(2)} 열로 조회하는데 스키마에 이 열의 인덱스가 보이지 않습니다. 데이터 10건과 10만 건에서 이 조회 시간이 비슷한지 확인하십시오.",
                            confidence=Confidence.REVIEW,
                        )
                    )
        return found
