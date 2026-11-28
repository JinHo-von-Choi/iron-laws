"""
오철칙 MyBatis 매퍼 색인: 매퍼 XML의 문장(select·insert·update·delete)을 namespace와 id로 모으고, Java 호출을 그 문장에 잇는다

- XML은 정규식으로 읽는다. DTD·외부 개체를 해석하지 않는다.
- 동적 절(<if>·<choose>·<foreach> 등)은 펼치지 않는다. 동적 절 밖의 조건만 확정 조건(where)으로 보고,
  동적 절 안에만 있는 조건은 선택 조건(optional_where)으로 따로 둔다.
- 테이블·열 이름은 SQL 본문에서 정규식으로 뽑는다. 뽑지 못한 문장은 tables가 비어 있다(판정 불가).
- Java 호출은 수신 필드의 선언 형식 → 정규 이름(import·같은 패키지) → 매퍼 namespace 순으로 잇는다.
  매퍼 인터페이스 소스가 없어도 import·패키지로 정규 이름을 정할 수 있으면 잇고, 정하지 못하면 잇지 않는다.
작성자: 최진호
작성일: 2026-11-23
"""

import re
from dataclasses import dataclass, field

from iron_laws.engine.ast_tools import Call
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile

NAMESPACE_RE = re.compile(r"<mapper\b[^>]*\bnamespace\s*=\s*\"([^\"]+)\"")
STATEMENT_RE = re.compile(r"<(select|insert|update|delete)\b([^>]*)>(.*?)</\1\s*>", re.DOTALL | re.IGNORECASE)
ID_RE = re.compile(r"\bid\s*=\s*\"([^\"]+)\"")
DYNAMIC_BLOCK_RE = re.compile(r"<(if|choose|when|otherwise|foreach|bind)\b[^>]*>(?:(?!<\1\b).)*?</\1\s*>", re.DOTALL | re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
CDATA_RE = re.compile(r"<!\[CDATA\[(.*?)\]\]>", re.DOTALL)
TABLE_RE = re.compile(r"(?i)\b(?:from|join|update|into)\s+([A-Za-z_][\w.]*)")
CONDITION_RE = re.compile(r"(?i)\b(?:([A-Za-z_]\w*)\.)?([A-Za-z_]\w*)\s*(?:=|<>|!=|<=|>=|<|>|\bin\b|\blike\b)\s*\(?\s*([#$]\{\s*[^}]+\}|'[^']*'|\d+|[A-Za-z_][\w.]*)")
SET_RE = re.compile(r"(?is)\bset\b(.*?)(?:\bwhere\b|$)")
ASSIGN_RE = re.compile(r"(?i)\b(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)\s*=\s*([#$]\{\s*[^}]+\}|'[^']*'|-?\d+|[A-Za-z_][\w.]*)")
SQL_WORDS = frozenset({"select", "from", "where", "and", "or", "not", "null", "is", "set", "values", "dual", "limit", "offset", "order", "by", "group"})


def _binding(value: str) -> str:
    """#{userId,jdbcType=VARCHAR} → userId, 상수는 그대로"""
    m = re.match(r"[#$]\{\s*([^},\s]+)", value)
    return m.group(1) if m else value


@dataclass(frozen=True)
class MapperStatement:
    namespace: str
    id: str
    kind: str  # select / insert / update / delete
    file: str
    line: int
    tables: tuple[str, ...]
    where: dict[str, str]  # 동적 절 밖의 조건: 열 → 바인딩 이름 또는 상수
    optional_where: dict[str, str]  # 동적 절 안에만 있는 조건
    assignments: dict[str, str]  # UPDATE SET 열 → 값
    dynamic: bool
    sql: str


def _clean(body: str) -> str:
    body = CDATA_RE.sub(lambda m: m.group(1), body)
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", body)).strip()


def _conditions(sql: str) -> dict[str, str]:
    found: dict[str, str] = {}
    parts = re.split(r"(?i)\bwhere\b", sql, maxsplit=1)
    if len(parts) < 2:
        return found
    for m in CONDITION_RE.finditer(parts[1]):
        column = m.group(2).lower()
        if column in SQL_WORDS:
            continue
        found.setdefault(column, _binding(m.group(3)))
    return found


def _strip_dynamic(body: str) -> tuple[str, list[str]]:
    removed: list[str] = []
    while True:
        m = DYNAMIC_BLOCK_RE.search(body)
        if m is None:
            return body, removed
        removed.append(m.group(0))
        body = body[: m.start()] + " " + body[m.end() :]


def parse_mapper(path: str, text: str) -> list[MapperStatement]:
    ns = NAMESPACE_RE.search(text)
    if ns is None:
        return []
    statements: list[MapperStatement] = []
    for m in STATEMENT_RE.finditer(text):
        id_m = ID_RE.search(m.group(2))
        if id_m is None:
            continue
        raw = re.sub(r"(?i)<where\b[^>]*>", " where ", m.group(3))
        raw = re.sub(r"(?i)<set\b[^>]*>", " set ", raw)
        raw = re.sub(r"(?i)<trim\b[^>]*\bprefix\s*=\s*\"\s*(where|set)\s*\"[^>]*>", r" \1 ", raw)
        static, removed = _strip_dynamic(raw)
        full_sql = _clean(raw)
        where = _conditions(_clean(static))
        optional: dict[str, str] = {}
        for block in removed:
            at = raw.find(block)
            if at < 0 or not re.search(r"(?i)\bwhere\b", raw[:at]):
                continue  # WHERE 앞(SET 절 등)의 동적 절은 조건이 아니다
            for column, value in _conditions("where " + _clean(block)).items():
                if column not in where:
                    optional.setdefault(column, value)
        assignments: dict[str, str] = {}
        if m.group(1).lower() == "update":
            set_m = SET_RE.search(full_sql)
            if set_m:
                for a in ASSIGN_RE.finditer(set_m.group(1)):
                    assignments.setdefault(a.group(1).lower(), _binding(a.group(2)))
        tables = tuple(dict.fromkeys(t.rsplit(".", 1)[-1].lower() for t in TABLE_RE.findall(full_sql) if t.lower() not in SQL_WORDS))
        statements.append(
            MapperStatement(
                namespace=ns.group(1).strip(),
                id=id_m.group(1).strip(),
                kind=m.group(1).lower(),
                file=path,
                line=text.count("\n", 0, m.start()) + 1,
                tables=tables,
                where=where,
                optional_where=optional,
                assignments=assignments,
                dynamic=bool(removed),
                sql=full_sql,
            )
        )
    return statements


@dataclass
class MapperIndex:
    by_key: dict[tuple[str, str], MapperStatement] = field(default_factory=dict)
    namespaces: set[str] = field(default_factory=set)
    params: dict[tuple[str, str], list[str]] = field(default_factory=dict)  # (namespace, 메서드) → 바인딩 이름(@Param 값 또는 매개변수 이름)
    unresolved: int = 0  # 매퍼처럼 보이는 호출 가운데 문장에 잇지 못한 수

    @classmethod
    def build(cls, files: list[SourceFile]) -> "MapperIndex":
        index = cls()
        for f in files:
            if f.kind != "xml" or "<mapper" not in f.text:
                continue
            for st in parse_mapper(f.path.as_posix(), f.text):
                index.by_key.setdefault((st.namespace, st.id), st)
                index.namespaces.add(st.namespace)
        for f in files:
            if f.lang is Lang.JAVA and "interface" in f.text:
                index._interface_params(f)
        return index

    def _interface_params(self, src: SourceFile) -> None:
        from iron_laws.engine import xfile_java
        from iron_laws.engine.ast_tools import iter_functions

        package = xfile_java.package_of(src)
        owners: dict[int, str] = {}
        for node in src.nodes:
            if node.type == "interface_declaration" and (name := node.child_by_field_name("name")) is not None:
                namespace = f"{package}.{src.text_of(name)}" if package else src.text_of(name)
                if namespace in self.namespaces and (body := node.child_by_field_name("body")) is not None:
                    owners[body.id] = namespace
        for fn in iter_functions(src):
            namespace = owners.get(fn.node.parent.id) if fn.node.parent is not None else None
            if namespace is None:
                continue
            names = []
            for p in fn.params:
                m = re.search(r'@Param\(\s*(?:value\s*=\s*)?"([^"]+)"', src.text_of(p))
                ident = p.child_by_field_name("name")
                names.append(m.group(1) if m else (src.text_of(ident) if ident is not None else ""))
            self.params[(namespace, fn.name)] = names

    def bindings_of(self, statement: MapperStatement) -> list[str] | None:
        """매퍼 인터페이스 메서드의 바인딩 이름(@Param 값 또는 매개변수 이름). 인터페이스 소스가 없으면 None"""
        return self.params.get((statement.namespace, statement.id))

    def statements(self) -> list[MapperStatement]:
        return [self.by_key[k] for k in sorted(self.by_key)]

    def _namespace_for(self, src: SourceFile, type_name: str) -> str | None:
        from iron_laws.engine import xfile_java

        named, wildcard = xfile_java.imports(src)
        candidates = []
        if type_name in named:
            candidates.append(named[type_name])
        package = xfile_java.package_of(src)
        candidates.append(f"{package}.{type_name}" if package else type_name)
        candidates += [f"{p}.{type_name}" for p in wildcard]
        for c in candidates:
            if c in self.namespaces:
                return c
        simple = [ns for ns in self.namespaces if ns.rsplit(".", 1)[-1] == type_name]
        return simple[0] if len(simple) == 1 else None

    def resolve(self, src: SourceFile, call: Call) -> MapperStatement | None:
        """`필드.메서드(...)` 호출이 매퍼 문장이면 그 문장. Java·Kotlin만 본다."""
        if src.lang not in (Lang.JAVA, Lang.KOTLIN) or not self.by_key:
            return None
        parts = call.callee.split(".")
        if len(parts) < 2:
            return None
        receiver, method = parts[-2], parts[-1]
        from iron_laws.engine import xfile_java

        types = xfile_java._field_types(src).get(receiver)
        if not types or len(types) != 1:
            return None
        namespace = self._namespace_for(src, next(iter(types)))
        if namespace is None:
            return None
        found = self.by_key.get((namespace, method))
        if found is None:
            self.unresolved += 1
        return found
