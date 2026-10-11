"""architecture structure 규칙."""
import re
import zlib
from collections import defaultdict
from pathlib import PurePosixPath

from tree_sitter import Node

from iron_laws.core.config import Limits
from iron_laws.core.models import Confidence, Severity, Violation
from iron_laws.engine.ast_tools import (
    NESTING_TYPES,
    iter_functions,
)
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.python_bindings import is_typer_command
from iron_laws.engine.source import SourceFile
from iron_laws.rules.architecture_common import (
    DB_IMPORT_RE,
    LAYER_LABEL,
    LAYER_RANK,
    MAPPING_ONLY_RE,
    WEB_IMPORT_RE,
    ArchRule,
    _is_generated,
    external_imports,
    infer_layer,
)


class SizeAndComplexityRule(ArchRule):
    version = 2
    rule_id = "ARC-201"
    name = "과도하게 큰 파일·함수·깊은 중첩 탐지"
    severity = Severity.LOW
    plain = "한 함수나 파일이 너무 길고 복잡하면 사람도 AI도 전체를 이해하지 못해, 고칠 때마다 다른 곳이 깨지고 보안 결함을 놓칩니다. AI가 기능을 계속 덧붙이면 한 파일에 모든 것이 쌓이는 경우가 많습니다."
    how_to_fix = "하나의 일만 하는 작은 함수로 나누고, 조건 중첩은 조기 반환(early return)으로 줄이고, 파일은 역할별 모듈로 분리하세요. 매개변수가 많으면 객체로 묶으세요."

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.root is None or src.is_test or _is_generated(src):
            return []
        limits = self.config.limits if self.config is not None else Limits()
        found = []
        total_lines = len(src.lines)
        if total_lines > limits.max_file_lines:
            found.append(
                self.at_line(
                    src,
                    1,
                    f"파일이 {total_lines}줄입니다 (기준 {limits.max_file_lines}줄). 역할별 모듈로 분리하십시오.",
                    severity=Severity.MEDIUM if total_lines > limits.max_file_lines * 2 else Severity.LOW,
                    confidence=Confidence.REVIEW,
                )
            )
        for fn in iter_functions(src):
            if fn.length > limits.max_function_lines:
                found.append(
                    self.at_node(
                        src,
                        fn.node,
                        f"함수 {fn.name}이(가) {fn.length}줄입니다 (기준 {limits.max_function_lines}줄). 작은 함수로 나누십시오.",
                        severity=Severity.MEDIUM if fn.length > limits.max_function_lines * 2 else Severity.LOW,
                        confidence=Confidence.REVIEW,
                    )
                )
            params = [p for p in fn.params if p.type not in ("comment",) and src.text_of(p) not in ("self", "cls")]
            if len(params) > limits.max_parameters and not is_typer_command(src, fn.start_line):
                found.append(self.at_node(src, fn.node, f"함수 {fn.name}의 매개변수가 {len(params)}개입니다 (기준 {limits.max_parameters}개). 객체로 묶으십시오.", confidence=Confidence.REVIEW))
            depth = self._max_nesting(src, fn.node)
            if depth > limits.max_nesting:
                found.append(self.at_node(src, fn.node, f"함수 {fn.name}의 조건·반복 중첩이 {depth}단계입니다 (기준 {limits.max_nesting}단계). 조기 반환으로 줄이십시오.", severity=Severity.MEDIUM, confidence=Confidence.REVIEW))
        return found

    def _max_nesting(self, src: SourceFile, fn_node: Node) -> int:
        best = 0
        stack: list[tuple[Node, int]] = [(c, 0) for c in fn_node.children]
        fn_types = {"function_definition", "function_declaration", "method_declaration", "arrow_function", "function_expression", "lambda", "closure_expression", "function_item"}
        while stack:
            node, depth = stack.pop()
            if node.type in fn_types:
                continue
            new_depth = depth + 1 if node.type in NESTING_TYPES else depth
            best = max(best, new_depth)
            stack.extend((c, new_depth) for c in node.children)
        return best


class LayeringRule(ArchRule):
    rule_id = "ARC-202"
    name = "요청 처리기(컨트롤러)의 데이터베이스 직접 접근 탐지"
    severity = Severity.MEDIUM
    plain = "화면 요청을 받는 코드가 SQL·DB 호출까지 직접 하면 비즈니스 규칙과 보안 검사가 곳곳에 흩어져, 어디서 권한을 확인하는지 아무도 알 수 없게 됩니다."
    how_to_fix = "요청 처리기는 입력 검증과 응답만 맡기고, 업무 규칙은 서비스 계층, DB 접근은 저장소(repository) 계층으로 나누세요."
    route_markers = {
        Lang.PYTHON: re.compile(r"@\s*\w+\.(route|get|post|put|patch|delete)\(|APIRouter|Blueprint|class\s+\w+\((?:\w+\.)*(View|APIView|ViewSet)\)"),
        Lang.JAVA: re.compile(r"@(Rest)?Controller\b"),
        Lang.CSHARP: re.compile(r":\s*(Controller|ControllerBase)\b|\[ApiController\]"),
        Lang.GO: re.compile(r"http\.HandleFunc|gin\.Context|echo\.Context|chi\.|mux\.Router|fiber\.Ctx"),
        Lang.PHP: re.compile(r"extends\s+Controller|Route::(get|post|put|patch|delete)"),
    }
    js_route = re.compile(r"\b(?:app|router|server|api|route)\.(?:get|post|put|patch|delete|use)\(")
    db_markers = {
        Lang.PYTHON: re.compile(r"\.execute(many)?\(|\bcursor\b|session\.(query|add|commit|execute|delete)|db\.session|\.objects\.(filter|get|create|all|update|delete)|sqlite3\.connect|psycopg2|pymysql|\.query\.(filter|get|all)"),
        Lang.JAVA: re.compile(r"JdbcTemplate|EntityManager|DriverManager|createQuery\(|executeQuery\(|createNativeQuery\("),
        Lang.CSHARP: re.compile(r"\bSqlConnection\b|\bSqlCommand\b|DbContext|\.ExecuteReader\(|FromSqlRaw|ExecuteSqlRaw"),
        Lang.GO: re.compile(r"\bsql\.(Open|DB)\b|\bdb\.(Query|Exec|QueryRow|Get|Select)\w*\(|gorm\.|\.Raw\("),
        Lang.PHP: re.compile(r"mysqli_|->query\(|DB::|\bPDO\b"),
    }
    js_db = re.compile(r"\bprisma\.|mongoose|\w+Model\.(find|create|update|delete)|\.query\(\s*[`'\"]|\bknex\(|sequelize|db\.(collection|query|run|all|get)\(|supabase\.from\(|firestore\(\)|\.collection\(|getFirestore|pool\.query|client\.query")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.lang is None or src.root is None or src.is_test:
            return []
        text = src.code_text_without_strings
        if src.lang in JS_FAMILY:
            is_route, db = self.js_route.search(text), self.js_db
        else:
            marker = self.route_markers.get(src.lang)
            is_route = marker.search(text) if marker else None
            db = self.db_markers.get(src.lang)
        if not is_route or db is None:
            return []
        hits = [m for m in db.finditer(text)]
        if not hits:
            return []
        first_line = text.count("\n", 0, hits[0].start()) + 1
        return [
            self.at_line(
                src,
                first_line,
                f"요청 처리 코드와 같은 파일에서 데이터베이스를 직접 호출합니다 ({len(hits)}곳). 서비스/저장소 계층으로 분리하십시오.",
                confidence=Confidence.REVIEW,
            )
        ]


class CircularDependencyRule(ArchRule):
    rule_id = "ARC-203"
    name = "모듈 간 순환 의존 탐지"
    severity = Severity.MEDIUM
    plain = "A가 B를 쓰고 B가 다시 A를 쓰는 순환 구조는 한쪽을 고치면 다른 쪽이 깨지고, 실행 순서에 따라 오류가 나기도 합니다. AI가 파일을 임의로 나누면 자주 생깁니다."
    how_to_fix = "공통으로 쓰는 부분을 제3의 모듈로 빼내거나, 의존 방향이 한쪽으로만 흐르도록(상위→하위) 인터페이스를 도입하세요."

    py_import = re.compile(r"^\s*(?:from\s+(?P<from>\.*[\w.]*)\s+import\s+(?P<names>[^\n#]+)|import\s+(?P<imp>[\w., ]+))", re.MULTILINE)
    js_import = re.compile(r"""(?:import\s+(?!type\b)[^'"\n]*?from\s*|import\s*\(\s*|require\(\s*|export\s+(?!type\b)[^'"\n]*?from\s*|import\s*)['"](?P<path>\.{1,2}/[^'"]*|\.{1,2})['"]""")
    java_pkg = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
    java_imp = re.compile(r"^\s*import\s+([\w.]+)\s*;", re.MULTILINE)

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        graph, edge_line = self._build_graph(project)
        found = []
        for comp in self._sccs(graph):
            if len(comp) < 2:
                continue
            members = sorted(comp)
            first = members[0]
            line = min((edge_line.get((first, t), 1) for t in graph.get(first, ()) if t in comp), default=1)
            src = next(f for f in project.files if f.path.as_posix() == first)
            chain = " → ".join(members[:6]) + (" → …" if len(members) > 6 else "")
            found.append(self.at_line(src, line, f"모듈 {len(members)}개가 서로를 순환 참조합니다: {chain}"))
        return found

    def _build_graph(self, project: ProjectContext):
        files = {f.path.as_posix(): f for f in project.source_files()}
        graph: dict[str, set[str]] = defaultdict(set)
        edge_line: dict[tuple[str, str], int] = {}
        py_modules = {self._py_module(p): p for p in files if p.endswith(".py")}
        java_classes: dict[str, str] = {}
        for p, f in files.items():
            if f.lang is Lang.JAVA:
                m = self.java_pkg.search(f.code_text)
                java_classes[f"{m.group(1)}.{PurePosixPath(p).stem}" if m else PurePosixPath(p).stem] = p
        for path, src in files.items():
            text = src.code_text
            if src.lang is Lang.PYTHON:
                for m in self.py_import.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    for target in self._py_targets(path, m, py_modules):
                        if target != path:
                            graph[path].add(target)
                            edge_line.setdefault((path, target), line)
            elif src.lang in JS_FAMILY:
                for m in self.js_import.finditer(text):
                    target = self._js_resolve(path, m.group("path"), files)
                    if target and target != path:
                        graph[path].add(target)
                        edge_line.setdefault((path, target), text.count("\n", 0, m.start()) + 1)
            elif src.lang is Lang.JAVA:
                for m in self.java_imp.finditer(text):
                    target = java_classes.get(m.group(1))
                    if target and target != path:
                        graph[path].add(target)
                        edge_line.setdefault((path, target), text.count("\n", 0, m.start()) + 1)
        for p in files:
            graph.setdefault(p, set())
        return graph, edge_line

    @staticmethod
    def _py_module(path: str) -> str:
        parts = list(PurePosixPath(path).with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _py_targets(self, path: str, m: re.Match, py_modules: dict[str, str]) -> list[str]:
        targets = []
        pkg_parts = list(PurePosixPath(path).parent.parts)
        if m.group("from") is not None:
            base = m.group("from")
            dots = len(base) - len(base.lstrip("."))
            rest = base.lstrip(".")
            if dots:
                anchor = pkg_parts[: len(pkg_parts) - (dots - 1)] if dots - 1 <= len(pkg_parts) else []
                module = ".".join(anchor + ([rest] if rest else []))
            else:
                module = rest
            candidates = [module] + [f"{module}.{n.strip().split(' as ')[0]}" if module else n.strip().split(" as ")[0] for n in m.group("names").replace("(", "").replace(")", "").split(",") if n.strip()]
            for c in candidates:
                for key in self._module_variants(c, py_modules):
                    targets.append(py_modules[key])
        else:
            for name in m.group("imp").split(","):
                for key in self._module_variants(name.strip().split(" as ")[0], py_modules):
                    targets.append(py_modules[key])
        return targets

    @staticmethod
    def _module_variants(module: str, py_modules: dict[str, str]) -> list[str]:
        if not module:
            return []
        hits = [k for k in py_modules if k == module or k.endswith("." + module)]
        return hits[:1] if hits else []

    @staticmethod
    def _js_resolve(path: str, spec: str, files: dict[str, SourceFile]) -> str | None:
        base = PurePosixPath(path).parent
        target = PurePosixPath(*[p for p in (base / spec).parts if p != "."])
        parts: list[str] = []
        for part in target.parts:
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        stem = "/".join(parts)
        for ext in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"):
            candidate = stem + ext
            if candidate in files:
                return candidate
        return None

    @staticmethod
    def _sccs(graph: dict[str, set[str]]) -> list[set[str]]:
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        on_stack: set[str] = set()
        stack: list[str] = []
        result: list[set[str]] = []
        counter = [0]
        for root in list(graph):
            if root in index:
                continue
            work = [(root, iter(graph[root]))]
            index[root] = low[root] = counter[0]
            counter[0] += 1
            stack.append(root)
            on_stack.add(root)
            while work:
                node, it = work[-1]
                advanced = False
                for nxt in it:
                    if nxt not in graph:
                        continue
                    if nxt not in index:
                        index[nxt] = low[nxt] = counter[0]
                        counter[0] += 1
                        stack.append(nxt)
                        on_stack.add(nxt)
                        work.append((nxt, iter(graph[nxt])))
                        advanced = True
                        break
                    if nxt in on_stack:
                        low[node] = min(low[node], index[nxt])
                if advanced:
                    continue
                work.pop()
                if work:
                    low[work[-1][0]] = min(low[work[-1][0]], low[node])
                if low[node] == index[node]:
                    comp = set()
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.add(w)
                        if w == node:
                            break
                    result.append(comp)
        return result


class DuplicateHelperRule(ArchRule):
    rule_id = "ARC-204"
    name = "동일·유사 함수(중복 헬퍼) 산재 탐지"
    severity = Severity.MEDIUM
    plain = "AI는 새 요청마다 이미 있는 함수를 찾지 않고 비슷한 함수를 새로 만들어, 같은 일을 하는 코드가 여러 파일에 흩어집니다. 한 곳의 버그나 보안 수정이 다른 복사본에는 반영되지 않습니다."
    how_to_fix = "중복된 함수를 하나의 공용 모듈(utils/common)로 모아 한 곳에서 import 해서 쓰세요. 이름만 다른 복사본은 하나를 남기고 호출부를 바꾸세요."
    skip_names = re.compile(r"^(<anonymous>|__init__|__repr__|__str__|__eq__|__hash__|constructor|main|Main|setUp|tearDown|setUpClass|toString|equals|hashCode|init|run|handle|dispatch|render|apply|get|set|build|create|new|default)$")
    trivial = re.compile(r"^(get|set|is|has)[A-Z_]\w*$")
    identifier_types = {"identifier", "property_identifier", "field_identifier", "type_identifier", "variable_name", "name", "shorthand_property_identifier", "shorthand_property_identifier_pattern"}
    BOTTOM_K = 8
    SHINGLE = 5

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        limits = project.config.limits
        funcs = []
        for src in project.source_files():
            if _is_generated(src) or src.root is None:
                continue
            for fn in iter_functions(src):
                if fn.body is None or self.skip_names.match(fn.name) or fn.length < 5:
                    continue
                tokens = self._tokens(src, fn.node)
                if len(tokens) < limits.duplicate_min_nodes:
                    continue
                if self.trivial.match(fn.name) and len(tokens) < limits.duplicate_min_nodes * 2:
                    continue
                # 문자열 hash()는 실행마다 달라져 같은 코드에서 다른 결과가 나온다. 실행과 무관한 해시를 쓴다
                shingles = {zlib.crc32("\x1f".join(tokens[i : i + self.SHINGLE]).encode("utf-8")) for i in range(len(tokens) - self.SHINGLE + 1)}
                funcs.append((src, fn, tokens, shingles))
        if len(funcs) < 2:
            return []

        index: dict[tuple[Lang | None, int], list[int]] = defaultdict(list)
        for i, (src, _, _, shingles) in enumerate(funcs):
            for h in sorted(shingles)[: self.BOTTOM_K]:
                index[(src.lang, h)].append(i)

        parent = list(range(len(funcs)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        compared: set[tuple[int, int]] = set()
        similarity: dict[tuple[int, int], float] = {}
        for bucket in index.values():
            if len(bucket) < 2 or len(bucket) > 60:
                continue
            for a in range(len(bucket)):
                for b in range(a + 1, len(bucket)):
                    i, j = bucket[a], bucket[b]
                    if (i, j) in compared:
                        continue
                    compared.add((i, j))
                    si, sj = funcs[i][3], funcs[j][3]
                    if not (0.5 <= len(si) / max(len(sj), 1) <= 2):
                        continue
                    if funcs[i][0].path == funcs[j][0].path and (funcs[i][1].node.start_byte <= funcs[j][1].node.start_byte < funcs[i][1].node.end_byte):
                        continue
                    sim = len(si & sj) / len(si | sj)
                    if sim >= limits.duplicate_similarity:
                        similarity[(i, j)] = sim
                        parent[find(i)] = find(j)

        clusters: dict[int, list[int]] = defaultdict(list)
        for i in range(len(funcs)):
            clusters[find(i)].append(i)

        found = []
        for members in clusters.values():
            if len(members) < 2:
                continue
            members.sort(key=lambda k: (str(funcs[k][0].path), funcs[k][1].start_line))
            places = [f"{funcs[k][0].path.as_posix()}:{funcs[k][1].start_line}({funcs[k][1].name})" for k in members]
            first = funcs[members[0]]
            exact = len({tuple(funcs[k][2]) for k in members}) == 1
            same_file = len({funcs[k][0].path for k in members}) == 1
            found.append(
                self.at_node(
                    first[0],
                    first[1].node,
                    f"{'동일한' if exact else '거의 같은'} 함수가 {len(members)}곳에 있습니다: {', '.join(places[:6])}{' …' if len(places) > 6 else ''}. 공용 함수로 통합하십시오.",
                    severity=Severity.MEDIUM if not same_file or len(members) > 2 else Severity.LOW,
                )
            )
        found.extend(self._name_families(funcs, {i for m in clusters.values() if len(m) > 1 for i in m}))
        return found

    def _name_families(self, funcs, clustered: set[int]) -> list[Violation]:
        families: dict[tuple[Lang | None, tuple[str, ...]], list[int]] = defaultdict(list)
        for i, (src, fn, _, _) in enumerate(funcs):
            if self._is_method(fn.node):
                continue
            key = tuple(self._name_tokens(fn.name))
            if len(key) >= 2:
                families[(src.lang, key)].append(i)
        found = []
        for (_, key), members in families.items():
            files = {funcs[i][0].path for i in members}
            if len(files) < 3 or all(i in clustered for i in members):
                continue
            members.sort(key=lambda k: (str(funcs[k][0].path), funcs[k][1].start_line))
            first = funcs[members[0]]
            places = [f"{funcs[k][0].path.as_posix()}:{funcs[k][1].start_line}" for k in members]
            found.append(
                self.at_node(
                    first[0],
                    first[1].node,
                    f"이름이 같은 헬퍼 함수 {'_'.join(key)}이(가) {len(files)}개 파일에 따로 구현되어 있습니다: {', '.join(places[:6])}. 하나로 통합했는지 확인하십시오.",
                    severity=Severity.LOW,
                    confidence=Confidence.REVIEW,
                )
            )
        return found

    @staticmethod
    def _is_method(node: Node) -> bool:
        class_types = {"class_definition", "class_declaration", "class_body", "impl_item", "trait_item", "interface_declaration", "struct_declaration", "class_specifier"}
        current = node.parent
        while current is not None:
            if current.type in class_types:
                return True
            current = current.parent
        return False

    @staticmethod
    def _name_tokens(name: str) -> list[str]:
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        return [t.lower() for t in re.split(r"[_\W]+", spaced) if t]

    def _tokens(self, src: SourceFile, fn_node: Node) -> list[str]:
        tokens: list[str] = []
        stack = [fn_node]
        order: list[Node] = []
        while stack:
            node = stack.pop()
            order.append(node)
            stack.extend(reversed(node.children))
        for node in order:
            if not node.is_named or "comment" in node.type:
                continue
            if node.type in self.identifier_types:
                parent = node.parent
                if parent is not None and parent.type in ("call", "call_expression", "method_invocation", "attribute", "member_expression", "field_expression", "member_access_expression", "selector_expression") and node.next_named_sibling is None and parent.child_by_field_name("function") is not None:
                    tokens.append(src.text_of(node))
                elif parent is not None and parent.type in ("attribute", "member_expression", "field_expression", "member_access_expression", "selector_expression", "method_invocation") and node == parent.children[-1]:
                    tokens.append(src.text_of(node))
                else:
                    tokens.append("ID")
            elif node.type in ("string", "string_literal", "interpreted_string_literal", "raw_string_literal", "template_string", "verbatim_string_literal"):
                tokens.append("STR")
            elif "number" in node.type or node.type in ("integer", "float", "integer_literal", "float_literal", "decimal_integer_literal"):
                tokens.append("NUM")
            else:
                tokens.append(node.type)
        return tokens


class NoTestsRule(ArchRule):
    rule_id = "ARC-206"
    name = "테스트 부재 탐지"
    severity = Severity.MEDIUM
    plain = "테스트가 하나도 없으면 AI가 코드를 수정할 때마다 기존 기능이 망가져도 아무도 모릅니다."
    how_to_fix = "핵심 기능(로그인, 결제, 권한, 데이터 변경)부터 테스트를 추가하세요. AI에게 코드를 시킬 때 테스트도 함께 작성하고 통과시키게 하세요."

    def check(self, src: SourceFile) -> list[Violation]:
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        sources = [f for f in project.source_files() if f.kind == "code" and not _is_generated(f)]
        tests = [f for f in project.files if f.is_test and f.lang is not None]
        if len(sources) < 5 or tests:
            return []
        first = sources[0]
        return [
            self.at_line(first, 1, f"소스 파일 {len(sources)}개에 테스트 파일이 하나도 없습니다.", confidence=Confidence.REVIEW)
        ]


class LayerDirectionRule(ArchRule):
    rule_id = "ARC-207"
    name = "계층 위반 및 의존 방향 위반 탐지"
    severity = Severity.MEDIUM
    plain = "화면·요청 처리 → 업무 규칙 → 데이터 접근 순서로만 호출해야 고칠 곳과 보안 검사 위치가 분명해집니다. 아래 계층이 위 계층을 부르거나, 컨트롤러가 DB 드라이버를 직접 쓰면 한 곳을 고칠 때 다른 곳이 깨지고 권한 검사가 빠지는 곳이 생깁니다."
    how_to_fix = "의존은 항상 위에서 아래(컨트롤러 → 서비스 → 저장소)로만 흐르게 하세요. 저장소·서비스가 컨트롤러나 웹 프레임워크 타입을 import 하면 필요한 값만 인자로 받도록 바꾸고, 컨트롤러가 DB를 직접 쓰는 코드는 서비스·저장소로 옮기세요."

    def check_project(self, project: ProjectContext) -> list[Violation]:
        files = {f.path.as_posix(): f for f in project.source_files()}
        layers = {p: infer_layer(f) for p, f in files.items()}
        known = {layer for layer in layers.values() if layer}
        if len(known) < 2:
            return []
        found: list[Violation] = []
        graph, edge_line = CircularDependencyRule()._build_graph(project)
        for source, targets in graph.items():
            la = layers.get(source)
            if la is None:
                continue
            for target in sorted(targets):
                lb = layers.get(target)
                if lb is None or LAYER_RANK[la] <= LAYER_RANK[lb]:
                    if lb is not None and la == "presentation" and lb == "data":
                        found.append(self._edge(files[source], edge_line.get((source, target), 1), f"{LAYER_LABEL[la]} 계층이 서비스 계층을 거치지 않고 데이터 접근 계층({target})을 직접 호출합니다.", Severity.LOW))
                    continue
                found.append(self._edge(files[source], edge_line.get((source, target), 1), f"{LAYER_LABEL[la]} 계층이 상위 계층인 {LAYER_LABEL[lb]} 계층({target})에 의존합니다 (의존 방향 위반).", Severity.MEDIUM))
        for path, src in files.items():
            layer = layers.get(path)
            if layer is None:
                continue
            for spec, line in external_imports(src):
                if MAPPING_ONLY_RE.search(spec):
                    continue  # 엔티티 매핑 어노테이션은 계층 위반이 아니다
                if layer == "presentation" and DB_IMPORT_RE.search(spec):
                    found.append(self._edge(src, line, f"표현(컨트롤러) 계층이 DB 라이브러리 {spec}를 직접 import 합니다.", Severity.MEDIUM))
                elif layer == "service" and DB_IMPORT_RE.search(spec):
                    found.append(self._edge(src, line, f"서비스 계층이 DB 라이브러리 {spec}를 직접 import 합니다. 저장소 계층으로 분리를 검토하십시오.", Severity.LOW))
                elif layer in ("data", "service") and WEB_IMPORT_RE.search(spec):
                    found.append(self._edge(src, line, f"{LAYER_LABEL[layer]} 계층이 웹 프레임워크 {spec}에 의존합니다. 요청·응답 타입은 표현 계층에만 두십시오.", Severity.MEDIUM))
        return found

    def _edge(self, src: SourceFile, line: int, message: str, severity: Severity) -> Violation:
        return self.at_line(src, line, message, severity=severity, confidence=Confidence.REVIEW)
