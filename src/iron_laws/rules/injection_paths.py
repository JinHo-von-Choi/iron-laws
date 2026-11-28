"""injection paths 규칙."""
import re

from tree_sitter import Node

from iron_laws.core.models import Severity, Violation
from iron_laws.engine.ast_tools import (
    CALL_TYPES,
    Call,
    enclosing_function,
    identifiers_in,
    is_literal,
    iter_calls,
    walk,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import (
    ARCHIVE_SOURCE_RE,
    ASSIGN_TYPES,
    Ctx,
    _target_and_value,
    archive_file,
    definitions,
    is_tainted,
    reaching_definitions,
    taint_state,
)
from iron_laws.engine.taint.sanitizers import custom_normalizer
from iron_laws.rules.guards import (
    PassFacts,
    _method_call,
    _negated,
    _or_terms,
    _term_fact,
    _unwrap,
    executes_unconditionally,
    redefined_between,
    runs_before,
    shared_scope,
    terminates,
)
from iron_laws.rules.injection_common import (
    CONFINEMENT_RE,
    FILENAME_RE,
    NORMALIZE_RE,
    SANITIZER_RE,
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


class PathTraversalRule(SinkRule):
    version = 4
    rule_id = "IL-502"
    taint_ctx = Ctx.PATH
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
        # 경로만 받는 열기 함수와 존재 확인. 존재 확인은 파일 유무를 응답으로 드러낸다. 인코딩·모드 인자는 경로가 아니다.
        # 수신자 메서드 싱크(`.exists`)보다 먼저 맞춰야 `os.path.exists`의 인자를 본다
        Sink.of(PY, r"^(codecs\.open|io\.open|os\.path\.(exists|lexists|isfile|isdir))$", 0),
        Sink.of(PY, r"^(open|os\.path\.join|os\.remove|os\.unlink|os\.rmdir|os\.listdir|os\.makedirs|os\.rename|send_file|send_from_directory|FileResponse|Path|pathlib\.Path|shutil\.\w+)$", None),
        Sink.of(PY, r"\.(read_text|write_text|read_bytes|write_bytes|mkdir|unlink|rmdir|rename|touch|exists|is_file|is_dir)$", None),
        Sink.of(JS, r"(^|\.)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync|sendFile|download|rm|rmSync|appendFile|appendFileSync)$|^path\.(join|resolve)$", None),
        Sink.of(JAVA, r"^new(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)$", None),
        Sink.of(JAVA, r"(^|\.)(Paths\.get|Path\.of|getResourceAsStream|Files\.\w+)$", None),
        Sink.of(CS, r"^(?:System\.IO\.)?File\.(ReadAll\w+|WriteAll\w+|Open\w*|Delete|Copy|Move|Create\w*|AppendAll\w+|Exists)$", None),
        Sink.of(CS, r"^new(?:System\.IO\.)?(FileStream|StreamReader|StreamWriter)$|^(?:System\.IO\.)?(Path\.Combine|Directory\.\w+)$", None),
        Sink.of(GO, r"^(os\.(Open|OpenFile|ReadFile|WriteFile|Remove|RemoveAll|Create|Mkdir\w*)|ioutil\.\w+|filepath\.Join|http\.ServeFile)$", None),
        Sink.of(PHP, r"^(file_get_contents|file_put_contents|fopen|readfile|unlink|file|copy|rename|mkdir|rmdir|opendir|scandir|move_uploaded_file)$", None),
        Sink.of(CFAM, r"^(fopen|open|freopen|remove|unlink|rename|opendir)$", None),
        Sink.of(RUST, r"(^|::)(File::open|File::create|read_to_string|fs::read|fs::write|remove_file|Path::new|PathBuf::from)$", None),
    ]

    RECEIVER_PATH_METHODS = re.compile(r"\.(read_text|write_text|read_bytes|write_bytes|open|unlink|rmdir|mkdir|rename|touch|exists|is_file|is_dir)$")
    # 이름이 흔해 경로 객체가 아닌 수신자(ORM 질의 집합의 exists() 등)에도 쓰이는 메서드. 수신자가 경로 객체일 때만 싱크로 본다
    AMBIGUOUS_PATH_METHODS = re.compile(r"\.(exists|is_file|is_dir)$")
    PATH_OBJECT_RE = re.compile(r"\b(?:pathlib\.)?(?:Pure\w*|Posix|Windows)?Path\s*\(")

    def _path_object(self, src: SourceFile, node: Node, depth: int = 3) -> bool:
        """식이 pathlib 경로 객체인지: 식이나 그 식에 쓰인 변수의 정의가 Path(...)로 만든 값을 거친다"""
        if self.PATH_OBJECT_RE.search(src.text_of(node)):
            return True
        if depth <= 0:
            return False
        scope = enclosing_function(node, src.lang) or src.root
        if scope is None:
            return False
        for name in identifiers_in(src, node):
            if any(self._path_object(src, d, depth - 1) for d in reaching_definitions(src, scope, name, node.start_byte)):
                return True
        return False

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        """경로가 인자가 아니라 객체(수신자)에 들어 있는 pathlib 호출은 수신자 식도 본다: `(Path(base) / name).read_text()`"""
        args = super().select_args(src, call, sink)
        if src.lang is Lang.PYTHON and self.RECEIVER_PATH_METHODS.search(call.callee):
            function = call.node.child_by_field_name("function")
            receiver = function.child_by_field_name("object") if function is not None else None
            if receiver is not None:
                if self.AMBIGUOUS_PATH_METHODS.search(call.callee) and not self._path_object(src, receiver):
                    return args  # `os.path.exists(p)`의 수신자 `os.path`, ORM의 `qs.exists()`는 경로 객체가 아니다
                return [receiver, *args]
        if src.lang is Lang.JAVA and args:
            if call.callee in ("Files.write", "Files.writeString", "Files.newBufferedWriter", "Files.newOutputStream"):
                return args[:1]  # 첫 인자만 경로다. 뒤는 쓸 내용·문자셋·열기 옵션이다
            if call.callee == "Files.copy" and len(args) >= 2:
                # Files.copy(InputStream, Path)·Files.copy(Path, OutputStream)의 스트림 쪽은 경로가 아니다
                return [a for a in args[:2] if not self.STREAM_ARG_RE.search(src.text_of(a))] or args[:2]
        return args

    # Commons IO FilenameUtils.normalize는 `..`가 시작 위치 위로 올라가면 null을 돌려준다(라이브러리 동작)
    NULL_ON_ESCAPE_RE = re.compile(r"^(?:org\.apache\.commons\.io\.)?(?:FilenameUtils\.)?normalize(?:NoEndSeparator)?$")
    PATH_VALUE_METHODS = frozenset({"isAbsolute", "getFileName", "getNameCount", "getRoot", "startsWith", "endsWith", "toString", "getParent", "normalize"})

    def _null_checked_normalize(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """arg가 `n = FilenameUtils.normalize(x)`의 결과이고, 싱크보다 앞서 `n == null`이면 끝내는 분기가 있다"""
        if src.lang is not Lang.JAVA:
            return False
        if arg.type != "identifier":
            # `base.resolve(n)`·`base + n`: 식 안의 외부 입력 변수가 모두 null 검사를 거친 normalize 결과인지
            tainted = [n for n in walk(arg) if n.type == "identifier" and is_tainted(src, n, ctx=Ctx.PATH)]
            return bool(tainted) and all(self._null_checked_normalize(src, call, n) for n in tainted)
        scope = enclosing_function(call.node, src.lang)
        if scope is None:
            return False
        name = src.text_of(arg)
        defs = reaching_definitions(src, scope, name, arg.start_byte)
        if len(defs) != 1 or defs[0].type != "method_invocation":
            return False
        callee = next((c.callee for c in iter_calls(src) if c.node.id == defs[0].id), "")
        if not self.NULL_ON_ESCAPE_RE.match(callee) or (callee == "normalize" and "FilenameUtils" not in src.text):
            return False
        for node in walk(scope):
            if node.type != "if_statement" or not runs_before(src, node, call.node, scope):
                continue
            cond = node.child_by_field_name("condition")
            terms = [_unwrap(t) for t in _or_terms(src, cond)] if cond is not None else []
            if any(re.fullmatch(rf"{re.escape(name)}\s*==\s*null|null\s*==\s*{re.escape(name)}", src.text_of(t).strip()) for t in terms) and terminates(src, node.child_by_field_name("consequence")):
                return not redefined_between(src, scope, name, node.end_byte, call.node.start_byte)
        return False

    def _normalized_child_file(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """arg가 `f = new File(기준, n)`의 f이고 n이 null 검사를 거친 FilenameUtils.normalize 결과다"""
        if src.lang is not Lang.JAVA or arg.type != "identifier":
            return False
        scope = enclosing_function(call.node, src.lang)
        defs = reaching_definitions(src, scope, src.text_of(arg), arg.start_byte) if scope is not None else []
        if len(defs) != 1 or defs[0].type != "object_creation_expression":
            return False
        built = next((c for c in iter_calls(src) if c.node.id == defs[0].id), None)
        return built is not None and built.callee == "newFile" and len(built.args) == 2 and self._null_checked_normalize(src, built, built.args[1])

    def _value_only_object(self, src: SourceFile, call: Call) -> bool:
        """경로 객체로 값만 계산한다: `Path.of(x).isAbsolute()`, 또는 `File f = new File(x)`의 모든 사용이 값 계산 메서드"""
        parent = call.node.parent
        if call.callee in ("Paths.get", "Path.of") and parent is not None and parent.type == "method_invocation" and parent.child_by_field_name("object") == call.node:
            return src.text_of(parent.child_by_field_name("name")) in self.PATH_VALUE_METHODS
        if call.callee != "newFile":
            return False
        variable = self._builder_variable(src, call)
        scope = enclosing_function(call.node, src.lang)
        if variable is None or scope is None or len(definitions(src, scope, variable)) != 1:
            return False
        uses = [n for n in walk(scope) if n.type == "identifier" and src.text_of(n) == variable and n.start_byte >= call.node.end_byte]
        if not uses:
            return False
        for use in uses:
            holder = use.parent
            if holder is None or holder.type != "method_invocation" or holder.child_by_field_name("object") != use:
                return False
            if src.text_of(holder.child_by_field_name("name")) not in self.FILE_VALUE_METHODS - {"toPath"}:
                return False
        return True

    COLLECTION_STORE = frozenset({"add", "addAll", "push", "offer", "put", "contains"})

    def _collection_argument(self, src: SourceFile, node: Node) -> bool:
        parent = node.parent
        if parent is None or parent.type != "argument_list" or parent.parent is None or parent.parent.type != "method_invocation":
            return False
        name = parent.parent.child_by_field_name("name")
        return name is not None and src.text_of(name) in self.COLLECTION_STORE

    def _stored_only(self, src: SourceFile, call: Call) -> bool:
        """경로 객체를 만들어 목록에 담기만 한다(이 메서드 안에서는 파일에 접근하지 않는다).
        바로 목록에 넣거나, 담은 변수의 모든 사용이 목록에 넣기·값 계산 메서드일 때다.
        바로 반환하는 경로 객체는 호출자가 곧 그 파일을 쓰는 경우가 많아 지금처럼 판정한다"""
        if self._collection_argument(src, call.node):
            return True
        variable = self._builder_variable(src, call)
        scope = enclosing_function(call.node, src.lang)
        if variable is None or scope is None or len(definitions(src, scope, variable)) != 1:
            return False
        uses = [n for n in walk(scope) if n.type == "identifier" and src.text_of(n) == variable and n.start_byte >= call.node.end_byte]
        stored = False
        for use in uses:
            holder = use.parent
            if self._collection_argument(src, use):
                stored = True
                continue
            if holder is not None and holder.type == "method_invocation" and holder.child_by_field_name("object") == use and src.text_of(holder.child_by_field_name("name")) in self.FILE_VALUE_METHODS - {"toPath"}:
                continue
            return False
        return stored

    STREAM_ARG_RE = re.compile(r"(?i)stream\s*$|getInputStream\s*\(|\bSystem\.(in|out)\b|^\s*new\s+\w*(InputStream|OutputStream)\b")
    # File 객체를 만들어 이름·정규 경로만 계산하는 메서드(파일을 읽거나 쓰지 않는다)
    FILE_VALUE_METHODS = frozenset({"getName", "getCanonicalPath", "getCanonicalFile", "getAbsolutePath", "getAbsoluteFile", "toPath", "getParent", "getParentFile", "getPath", "toURI"})

    BUILDER_RE = re.compile(r"^(os\.path\.join|path\.join|path\.resolve|filepath\.Join|Path|pathlib\.Path|Paths\.get|Path\.of|Path\.Combine|newFile)$")

    @staticmethod
    def _assignment_of(src: SourceFile, call: Call) -> Node | None:
        """호출 결과가 (정규화 함수 등을 거쳐) 변수에 대입되는 대입문"""
        parent = call.node.parent
        passthrough = {"parenthesized_expression", "await_expression", "argument_list", "arguments", *CALL_TYPES.get(src.lang, set())} if src.lang else set()
        while parent is not None and parent.type in passthrough:
            parent = parent.parent
        return parent if parent is not None and parent.type in ASSIGN_TYPES else None

    def _builder_variable(self, src: SourceFile, call: Call) -> str | None:
        """경로를 조립만 하고 변수에 담는 호출이면 그 변수 이름. 실제 접근은 그 변수를 쓰는 뒤쪽 싱크가 판정한다."""
        if not self.BUILDER_RE.search(call.callee):
            return None
        parent = self._assignment_of(src, call)
        if parent is None:
            return None
        left = parent.child_by_field_name("left") or parent.child_by_field_name("name")
        return src.text_of(left).lstrip("$") if left is not None and left.type in ("identifier", "variable_name") else None

    STRONG_CONFINEMENT_RE = re.compile(r"is_relative_to|relative_to\(|commonpath\(|isSubPath|within_base|inside_base|\.relative\(")
    PREFIX_CALL_RE = re.compile(r"\.(startswith|startsWith|StartsWith|HasPrefix)\s*\(")
    SEPARATOR_RE = re.compile(r"separator|\bos\.sep\b|\bsep\b|\+\s*['\"][/\\\\]['\"]|['\"][/\\\\]['\"]\s*\)|[/\\\\]['\"]\s*\)?$")
    PATH_OBJECT_TAIL_RE = re.compile(r"(?:toPath|normalize|toRealPath|toAbsolutePath)\s*\([^()]*\)\s*$|^(?:Paths\.get|Path\.of)\s*\(")

    # 경로 객체를 문자열·File로 바꾸는 호출. 이 호출로 끝나는 식은 Path가 아니다
    PATH_CONVERSION = r"(?:toFile|toString|getPath|getAbsolutePath|getAbsoluteFile|getCanonicalPath|getCanonicalFile)"
    CONVERTED_TAIL_RE = re.compile(rf"\.\s*{PATH_CONVERSION}\s*\(\s*\)\s*$")
    # `path.toFile().getAbsolutePath()`처럼 변수 하나를 바꾸기만 한 식
    CONVERTED_VARIABLE_RE = re.compile(rf"([A-Za-z_]\w*)(?:\s*\.\s*(?:{PATH_CONVERSION}|toPath|toAbsolutePath|normalize|toRealPath)\s*\(\s*\))+")

    def _path_object_text(self, text: str) -> bool:
        """식이 java.nio.file.Path 값이다: Path로 끝나는 호출이거나 Path.of·Paths.get 호출이고, 끝에서 문자열·File로 바꾸지 않는다"""
        return bool(self.PATH_OBJECT_TAIL_RE.search(text)) and not self.CONVERTED_TAIL_RE.search(text)

    @staticmethod
    def _normalizes(src: SourceFile, text: str) -> bool:
        """식이 경로를 정규화한다: 알려진 정규화 함수이거나 사용자 명세가 정규화로 요약한 함수"""
        return bool(NORMALIZE_RE.search(text)) or custom_normalizer(text, src.lang)

    def _prefix_strength(self, src: SourceFile, check: Node) -> str:
        """경로 범위 검사 하나의 강도. 경로 단위 비교(Path.startsWith, is_relative_to, commonpath)와
        구분자를 붙인 문자열 접두사 비교는 strong, 구분자 없는 문자열 접두사 비교(`/data/app2`도 `/data/app`으로 시작)는 weak"""
        text = src.text_of(check)
        if self.STRONG_CONFINEMENT_RE.search(text):
            return "strong"
        for n in walk(check):
            call = _method_call(src, n)
            if call is None or call[1] not in ("startswith", "startsWith", "StartsWith", "HasPrefix") or not call[2]:
                continue
            receiver, _method, args = call
            arg_text = src.text_of(args[0])
            scope = enclosing_function(check, src.lang) or src.root
            arg_defs = " ".join(src.text_of(d) for d in reaching_definitions(src, scope, arg_text, check.start_byte)) if re.fullmatch(r"\w+", arg_text) and scope is not None else ""
            if self.SEPARATOR_RE.search(arg_text) or self.SEPARATOR_RE.search(arg_defs):
                return "strong"
            receiver_defs = " ".join(src.text_of(d) for d in reaching_definitions(src, scope, receiver, check.start_byte)) if re.fullmatch(r"\w+", receiver) and scope is not None else ""
            if src.lang is Lang.JAVA and any(self._path_object_text(t) for t in (receiver, receiver_defs.strip()) if t):
                return "strong"  # java.nio.file.Path.startsWith는 경로 이름 단위로 비교한다
            return "weak"
        return "weak" if "commonprefix" in text else "strong"

    def _check_level(self, src: SourceFile, check: Node, names: set[str], defs_text: str, origin: str | None) -> str | None:
        """긍정형 범위 검사 식 하나(`p.startsWith(base)`)가 names 가운데 하나를 정규화한 뒤 검사하면 그 강도"""
        text = src.text_of(check)
        hit = identifiers_in(src, check) & names
        if not CONFINEMENT_RE.search(text) or not hit:
            return None
        if not (self._normalizes(src, text) or self._normalizes(src, defs_text) or (origin is not None and hit - {origin})):
            return None
        return self._prefix_strength(src, check)

    def _reject_level(self, src: SourceFile, cond: Node, names: set[str], defs_text: str, origin: str | None, inputs: set[str]) -> str | None:
        """참이면 실행을 끊는 조건에서, 통과한 경로에 성립하는 범위 검사의 강도.
        `!C1 || !C2`는 각 검사를 따로 인정한다. `A && !C`는 A가 같은 입력에 `..`가 있는지 보는 검사일 때만 인정하고
        약한 쪽(`..` 차단)을 따른다. 그 밖의 A가 붙으면 C가 실행되지 않는 경로가 남으므로 인정하지 않는다"""
        best = None
        for term in _or_terms(src, cond):
            inner = _negated(term)
            level = None
            if inner is not None:
                level = self._check_level(src, inner, names, defs_text, origin)
            else:
                term = _unwrap(term)
                operator = term.child_by_field_name("operator") if term.type in ("binary_expression", "boolean_operator") else None
                if operator is not None and src.text_of(operator) in ("&&", "and"):
                    left, right = term.child_by_field_name("left"), term.child_by_field_name("right")
                    fact = _term_fact(src, left) if left is not None else None
                    right_inner = _negated(right) if right is not None else None
                    if fact is not None and fact[1] == "contains" and ".." in fact[2] and fact[0] in inputs and right_inner is not None:
                        level = "weak" if self._check_level(src, right_inner, names, defs_text, origin) else None
            if level == "strong" or (level == "weak" and best is None):
                best = level
        return best

    @staticmethod
    def _input_names(src: SourceFile, scope: Node, nodes: list[Node], before: int, depth: int = 2) -> set[str]:
        """경로 식이 쓰는 변수와, 그 변수를 만든 식의 변수(`dirs = name.split(…)`이면 name)를 depth 단계까지 모은다"""
        names = {n for node in nodes for n in identifiers_in(src, node)}
        frontier = set(names)
        for _ in range(depth):
            found = {n for name in frontier for d in reaching_definitions(src, scope, name, before) for n in identifiers_in(src, d)}
            frontier = found - names
            names |= found
        return names

    def _guarded_after(self, src: SourceFile, call: Call, variable: str) -> str | None:
        """조립한 경로 변수가 뒤에서 정규화·범위 검사를 받는지(거부 분기 또는 assert). 받으면 검사의 강도"""
        scope = enclosing_function(call.node, src.lang) or src.root
        if scope is None:
            return None
        assignment = self._assignment_of(src, call)
        defs_text = src.text_of(assignment) if assignment is not None else ""
        inputs = self._input_names(src, scope, call.args, call.node.start_byte)
        # `String c = file.getCanonicalPath(); if (!c.startsWith(base)) throw` — 조립한 경로를 정규화해 담은 변수의 검사도 같은 경로의 검사다
        checked_names = {variable}
        for node in walk(scope):
            if node.type in ASSIGN_TYPES and node.start_byte >= call.node.end_byte:
                left, right = _target_and_value(node)
                if left is not None and right is not None and self._normalizes(src, src.text_of(right)) and variable in identifiers_in(src, right):
                    # 별칭에 다른 값이 다시 대입되면 그 검사는 원래 경로의 검사가 아니다
                    checked_names |= {n for n in identifiers_in(src, left) if len(definitions(src, scope, n)) == 1}
        best = None
        for node in walk(scope):
            if node.type not in ("if_statement", "assert_statement") or node.start_byte < call.node.end_byte:
                continue
            cond = node.child_by_field_name("condition")
            if cond is None and node.type == "assert_statement" and node.named_children:
                cond = node.named_children[0]
            if cond is None:
                continue
            if redefined_between(src, scope, variable, call.node.end_byte, node.start_byte) or not executes_unconditionally(node, shared_scope(node, call.node, scope)):
                continue
            if node.type == "assert_statement":
                level = self._check_level(src, cond, checked_names, defs_text, variable)
            else:
                consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
                level = self._reject_level(src, cond, checked_names, defs_text, variable, inputs) if terminates(src, consequence) else None
            if level == "strong":
                return level
            best = best or level
        return best

    @staticmethod
    def _variable_input(src: SourceFile, scope: Node, name: str) -> bool:
        """함수 안에서 값이 바뀌는 변수(리터럴이 아닌 정의가 있거나 매개변수). 모듈 이름·상수 기준 폴더는 아니다"""
        defs = definitions(src, scope, name)
        if defs:
            return not all(is_literal(d) for d in defs)
        params = scope.child_by_field_name("parameters")
        return params is not None and name in identifiers_in(src, params)

    def _confined(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        """싱크로 가는 경로 변수가 정규화된 뒤 허용 폴더 안인지 검사되는지 본다. 검사되면 그 강도.
        검사 대상 변수가 같아야 하고, 싱크보다 앞서 실행되어야 하며(거부 분기가 끝나거나 싱크가 통과 분기 안에 있음),
        경로가 정규화된 값이어야 한다. 다른 변수를 검사하거나 싱크 뒤에 검사하면 인정하지 않는다."""
        scope = enclosing_function(call.node, src.lang) or src.root
        names = identifiers_in(src, arg)
        if scope is None or not names:
            return None
        defs = [d for n in names for d in reaching_definitions(src, scope, n, arg.start_byte)]
        defs_text = " ".join(src.text_of(d) for d in defs)
        inputs = self._input_names(src, scope, [arg], arg.start_byte)
        # 경로 변수를 정규화해 담은 변수(`String c = file.getCanonicalPath()`) → 원래 변수. 그 변수의 검사도 원래 경로의 검사다
        aliases: dict[str, str] = {}
        for node in walk(scope):
            if node.type in ASSIGN_TYPES and node.end_byte <= call.node.start_byte:
                left, right = _target_and_value(node)
                if left is None or right is None or not self._normalizes(src, src.text_of(right)):
                    continue
                # 상수로만 정의된 기준 폴더 변수는 검사 대상 경로가 아니다
                candidates = [n for n in sorted(identifiers_in(src, right) & names) if self._variable_input(src, scope, n)]
                origin = candidates[0] if candidates else None
                if origin is not None:
                    aliases.update(dict.fromkeys((n for n in identifiers_in(src, left) - names if len(definitions(src, scope, n)) == 1), origin))
        # 검사한 경로 변수를 바꿔 담은 변수(`String s = path.toFile().getAbsolutePath()`) → 원래 변수. 원래 변수의 검사가 이 값의 검사다.
        # 바꿔 담은 뒤 원래 변수가 다시 대입되면 그 뒤의 검사는 다른 값의 검사다
        converted: dict[str, Node] = {}
        for n in names:
            own = definitions(src, scope, n)
            match = self.CONVERTED_VARIABLE_RE.fullmatch(src.text_of(own[0]).strip()) if len(own) == 1 else None
            if match is not None and match.group(1) != n and self._variable_input(src, scope, match.group(1)):
                converted[match.group(1)] = own[0]
        for origin in converted:
            aliases.setdefault(origin, origin)
        checkable = names | set(aliases)
        # 별칭 검사는 정규화 근거가 별칭의 정의에 있다
        alias_defs = " ".join(src.text_of(d) for a in aliases for d in definitions(src, scope, a))
        best = None
        for node in walk(scope):
            if node.type not in ("if_statement", "assert_statement", "if_expression"):
                continue
            cond = node.child_by_field_name("condition")
            if cond is None and node.type == "assert_statement" and node.named_children:
                cond = node.named_children[0]
            if cond is None:
                continue
            used = {
                n
                for n in identifiers_in(src, cond) & checkable
                if n in names or n not in converted or converted[n].end_byte > node.start_byte or not redefined_between(src, scope, n, converted[n].end_byte, node.start_byte)
            }
            checked = {aliases.get(n, n) for n in used}
            if not checked:
                continue
            context = defs_text + (" " + alias_defs if used & set(aliases) else "")
            if node.type == "assert_statement":
                level = None
                if (
                    node.end_byte <= call.node.start_byte
                    and executes_unconditionally(node, shared_scope(node, call.node, scope))
                    and not any(redefined_between(src, scope, n, node.end_byte, call.node.start_byte) for n in checked)
                ):
                    level = self._check_level(src, cond, checkable, context, None)
            else:
                consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
                if consequence is None:
                    continue
                level = None
                if (
                    node.end_byte <= call.node.start_byte
                    and terminates(src, consequence)
                    and executes_unconditionally(node, shared_scope(node, call.node, scope))
                    and not any(redefined_between(src, scope, n, node.end_byte, call.node.start_byte) for n in checked)
                ):
                    level = self._reject_level(src, cond, checkable, context, None, inputs)
                elif (
                    _negated(cond) is None
                    and consequence.start_byte <= call.node.start_byte
                    and call.node.end_byte <= consequence.end_byte
                    and not any(redefined_between(src, scope, n, cond.end_byte, call.node.start_byte) for n in checked)
                ):
                    level = self._check_level(src, cond, checkable, context, None)
            if level == "strong":
                return level
            best = best or level
        return best

    JOIN_RE = re.compile(r"^(os\.path\.join|path\.join|path\.resolve|filepath\.Join|Path|pathlib\.Path|PurePath|Paths\.get|Path\.of|Path\.Combine)$")

    def _fixed_base(self, src: SourceFile, arg: Node, roots: set[str], blocked_slash: bool, depth: int = 0) -> bool:
        """검사한 값 앞에 고정 기준 폴더가 붙는지. 문자열 결합·f-string·`new File(기준, 이름)`은 값이 절대 경로여도 기준 아래에 남는다.
        os.path.join·Path 결합은 절대 경로가 기준을 바꾸므로 '/'까지 막아야 인정한다"""
        node = arg
        while node.type in ("parenthesized_expression",) and node.named_children:
            node = node.named_children[0]
        if node.type == "identifier" and depth < 3:
            scope = enclosing_function(node, src.lang) or src.root
            defs = reaching_definitions(src, scope, src.text_of(node), node.start_byte) if scope is not None else []
            defs = [d for d in defs if not (is_literal(d) or src.text_of(d) in ("None", "null"))]  # 초기값 None·리터럴은 외부 입력 경로가 아니다
            return len(defs) == 1 and self._fixed_base(src, defs[0], roots, blocked_slash, depth + 1)
        if node.type == "string" and src.lang is Lang.PYTHON:
            prefix = ""
            for child in node.children:
                if child.type == "interpolation":
                    if identifiers_in(src, child) & roots:
                        return "/" in prefix and bool(prefix.strip("/'\" fFrR"))
                    prefix += "{x}"
                else:
                    prefix += src.text_of(child)
            return False
        if node.type in ("binary_operator", "binary_expression"):
            operands = []
            stack = [node]
            while stack:
                n = stack.pop()
                if n.type in ("binary_operator", "binary_expression") and src.text_of(n.child_by_field_name("operator") or n) == "+":
                    stack.extend(reversed([c for c in (n.child_by_field_name("left"), n.child_by_field_name("right")) if c is not None]))
                else:
                    operands.append(n)
            first = next((i for i, o in enumerate(operands) if identifiers_in(src, o) & roots), 0)
            return first > 0 and any("/" in src.text_of(o) or "separator" in src.text_of(o) or "sep" in src.text_of(o) for o in operands[:first + 1])
        call = next((c for c in iter_calls(src) if c.node.id == node.id), None)
        if call is not None and len(call.args) >= 2 and not (identifiers_in(src, call.args[0]) & roots):
            if call.callee in ("newFile",) and src.lang is Lang.JAVA:
                return True
            if self.JOIN_RE.match(call.callee):
                return blocked_slash
        return False

    SEPARATOR_TOKEN_RE = re.compile(r"File\.separatorChar|File\.separator|System\.getProperty\(\"file\.separator\"\)|'/'|\"/\"|os\.sep")

    def _path_shape(self, src: SourceFile, node: Node) -> str:
        """경로 식의 비교용 모양: 공백을 지우고 경로 구분자 표기를 하나로 맞춘다"""
        return self.SEPARATOR_TOKEN_RE.sub("SEP", re.sub(r"\s+", "", src.text_of(node)))

    def _same_path_checked(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        """싱크 경로가 앞에서 범위 검사를 받은 경로를 다시 조립한 것이면 그 검사의 강도.
        `new File(base, name)`을 검사하고 `base + File.separator + name`으로 다시 잇거나, `new File(dir + name)`을 검사하고
        같은 식(또는 그 앞부분 `name.substring(0, i)`)으로 다시 만드는 경우다. 그 사이에 쓰인 변수가 다시 대입되면 인정하지 않는다"""
        if src.lang is not Lang.JAVA:
            return None
        scope = enclosing_function(call.node, src.lang)
        if scope is None:
            return None
        expr = arg
        if arg.type == "identifier":
            defs = [d for d in reaching_definitions(src, scope, src.text_of(arg), arg.start_byte) if src.text_of(d) != "null"]
            if len(defs) != 1:
                return None
            expr = defs[0]
        shape = re.sub(r"\.substring\(0,[^()]*\)", "", self._path_shape(src, expr))
        # 앞부분을 자르는 substring(0, i)의 i는 경로의 일부가 아니다. 다시 대입되는지 볼 변수에서 뺀다
        cut = set(re.findall(r"[A-Za-z_]\w*", " ".join(re.findall(r"\.substring\(\s*0\s*,([^()]*)\)", src.text_of(expr)))))
        kept = re.sub(r"\.substring\(\s*0\s*,[^()]*\)", "", src.text_of(expr))
        used = {n for n in identifiers_in(src, expr) if n not in cut or re.search(rf"\b{re.escape(n)}\b", kept)}
        for builder in iter_calls(src):
            if builder.callee not in ("newFile", "Paths.get", "Path.of") or not builder.args or builder.node.end_byte > call.node.start_byte:
                continue
            if not (scope.start_byte <= builder.node.start_byte < scope.end_byte) or builder.node.id == call.node.id:
                continue
            if len(builder.args) == 1:
                forms = {self._path_shape(src, builder.args[0])}
            elif len(builder.args) == 2:
                base, name = (self._path_shape(src, a) for a in builder.args)
                forms = {f"{base}+SEP+{name}"}
            else:
                continue
            if shape not in forms:
                continue
            variable = self._builder_variable(src, builder)
            level = self._guarded_after(src, builder, variable) if variable is not None else None
            if level is None:
                continue
            if any(redefined_between(src, scope, n, builder.node.end_byte, call.node.start_byte) for n in used):
                continue
            return level
        return None

    def entry_confined(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """도우미 함수로 넘기는 인자가 이미 범위 검사를 거쳤으면 그 함수 안의 싱크를 따라가지 않는다"""
        return self._confinement(src, call, arg) == "strong"

    def _confinement(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        """이 싱크 인자가 받는 범위 검사의 강도(strong·weak). 조립한 경로 변수의 뒤쪽 검사, 싱크 앞의 검사,
        검사한 경로를 다시 조립한 경우 가운데 강한 쪽"""
        key = ("path_confinement", call.node.id, arg.id)
        cache = src.__dict__.setdefault("_rule_memo", {})
        if key not in cache:
            variable = self._builder_variable(src, call)
            levels = {self._guarded_after(src, call, variable) if variable is not None else None, self._confined(src, call, arg), self._same_path_checked(src, call, arg)}
            cache[key] = "strong" if "strong" in levels else ("weak" if "weak" in levels else None)
        return cache[key]

    WEAK_PREFIX_REASON = "정규화한 경로를 기준 폴더와 구분자 없이 문자열 접두사로 비교합니다(`/data/app2`도 `/data/app`으로 시작합니다). 경로 단위로 비교하는지 확인이 필요합니다."

    def entry_guard(self, src: SourceFile, call: Call, arg: Node) -> str | None:
        """도우미 함수로 넘기는 경로가 호출하는 곳에서 구분자 없는 접두사 비교만 거쳤으면, 싱크 앞의 같은 검사처럼 확인 필요로 낮춘다"""
        return self.WEAK_PREFIX_REASON if self._confinement(src, call, arg) == "weak" else None

    def guard_verdict(self, src: SourceFile, call: Call, arg: Node, facts: dict[str, PassFacts]) -> str | None:
        """숫자 형식 검사는 지적하지 않는다. `..`를 막고 경로 앞에 고정 기준 폴더가 붙거나,
        정규화한 경로를 구분자 없이 문자열 접두사로 비교하면 확인 필요로 낮춘다"""
        if self._null_checked_normalize(src, call, arg):
            return "FilenameUtils.normalize가 `..` 이탈을 null로 막았지만 이 결합은 절대 경로가 기준 폴더를 바꿀 수 있습니다. File(기준, 이름)으로 잇는지 확인이 필요합니다."
        if src.lang is Lang.JAVA and call.callee in ("newFile", "Paths.get", "Path.of") and self._stored_only(src, call):
            return "이 메서드는 경로 객체를 목록에 담기만 합니다. 그 목록의 파일에 접근하는 호출자에서 검사하는지 확인이 필요합니다."
        if self._confinement(src, call, arg) == "weak":
            return self.WEAK_PREFIX_REASON
        if not facts:
            return None
        if all(f.digits for f in facts.values()):
            return self.GUARD_SKIP
        if all(any(".." in b for b in f.blocked) for f in facts.values()):
            blocked_slash = all("/" in f.blocked or "\\" in f.blocked for f in facts.values())
            if self._fixed_base(src, arg, set(facts), blocked_slash):
                return self.guard_reason(facts)
        return None

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        text = _context_text(src, arg)
        if archive_file(src):
            # File.getName()은 파일 이름만 남기지만 압축 항목의 getName()·getFileName()은 `../`가 든 전체 경로다. 정제로 보지 않는다
            tainted = taint_state(src, call.node, ctx=Ctx.PATH)
            text = ARCHIVE_SOURCE_RE.sub(" ", text)
            text = re.sub(r"\b(\w+)\.(getName|getFileName)\s*\(\s*\)", lambda m: " " if m.group(1) in tainted else m.group(0), text)
        if SANITIZER_RE.search(text) or re.search(r"\.(Body|InputStream|OutputStream|BaseStream)\b", text):
            return True
        parent = call.node.parent
        if (
            call.callee == "newFile"
            and parent is not None
            and parent.type == "method_invocation"
            and parent.child_by_field_name("object") == call.node
            and src.text_of(parent.child_by_field_name("name")) in self.FILE_VALUE_METHODS
        ):
            # `new File(x).getName()`·`new File(x).getCanonicalPath()`는 파일에 접근하지 않고 이름·정규 경로만 계산한다.
            # 실제 접근은 그 값을 쓰는 뒤쪽 싱크가 판정한다
            return True
        if self._value_only_object(src, call):
            return True  # 경로 객체로 이름·정규 경로만 계산한다. 실제 접근은 그 값을 쓰는 뒤쪽 싱크가 판정한다
        if call.callee == "newFile" and len(call.args) == 2 and arg is call.args[1] and self._null_checked_normalize(src, call, arg):
            return True  # File(기준, 자식)은 자식이 절대 경로여도 기준 아래로 잇고, normalize가 `..` 이탈을 null로 막았다
        if self._normalized_child_file(src, call, arg):
            return True  # 위와 같이 만든 File 객체를 그대로 쓴다
        if self._confinement(src, call, arg) == "strong":
            # 경로를 조립한 변수가 뒤에서 정규화·범위 검사를 받거나(접근하는 싱크가 따로 판정한다),
            # 정규화한 같은 변수를 허용 폴더와 비교하는 검사가 싱크보다 앞서 실행된다
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
    version = 2
    rule_id = "IL-513"
    taint_ctx = Ctx.PATH
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
