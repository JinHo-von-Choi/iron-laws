"""
제5철칙: 전수 검증의 원칙 - 코드오류·시간및상태·캡슐화·API오용·메모리 계열 (행안부 2021 구현단계 3~7장)
작성자: 최진호
작성일: 2026-10-04
"""

import re

from tree_sitter import Node

from iron_laws.core.models import Confidence, IronLaw, Severity, Violation
from iron_laws.engine.ast_tools import (
    Call,
    enclosing_function,
    is_literal,
    iter_calls,
    iter_functions,
    walk,
    walk_no_nested_functions,
)
from iron_laws.engine.languages import C_FAMILY, Lang
from iron_laws.engine.source import SourceFile
from iron_laws.engine.taint import ASSIGN_TYPES, _target_and_value, _target_names, is_tainted
from iron_laws.rules.base import BaseRule
from iron_laws.rules.sinks import CS, JAVA, JS, PHP, PY, Sink
from iron_laws.standards import mois_ref


class DeserializationRule(BaseRule):
    rule_id = "IL-515"
    name = "신뢰할 수 없는 데이터의 역직렬화 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("5-5")
    plain = "받은 데이터를 객체로 복원하는 기능(pickle, ObjectInputStream 등)은 데이터 안에 숨긴 코드를 실행시켜 서버를 장악하는 데 쓰입니다."
    how_to_fix = "신뢰할 수 없는 데이터는 JSON 같은 데이터 전용 형식으로 주고받고 스키마로 검증하세요. YAML은 safe_load, Java는 ObjectInputFilter, C#은 BinaryFormatter 대신 System.Text.Json을 쓰세요."
    sinks = [
        Sink.of(PY, r"^(pickle\.(loads?|Unpickler)|cPickle\.loads?|marshal\.loads?|shelve\.open|jsonpickle\.decode|dill\.loads?|yaml\.(load|unsafe_load|full_load)|torch\.load|pandas\.read_pickle|joblib\.load)$", None),
        Sink.of(JS, r"(^|\.)(unserialize|deserialize)$", None),
        Sink.of(JAVA, r"(^|\.)(readObject|readUnshared)$|^newXMLDecoder$|(^|\.)(enableDefaultTyping|activateDefaultTyping)$", None),
        Sink.of(CS, r"^new(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter|ObjectStateFormatter)$", None),
        Sink.of(PHP, r"^unserialize$", None),
    ]
    safe_loader = re.compile(r"SafeLoader|CSafeLoader|safe_load|weights_only\s*=\s*True")
    regexes = [
        (re.compile(r"TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)"), "Json.NET TypeNameHandling이 임의 타입 복원을 허용합니다."),
        (re.compile(r"new\s+Yaml\(\s*\)\s*\.load"), "SnakeYAML 기본 생성자의 load는 임의 객체를 생성합니다."),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if not any(src.lang in s.langs and s.callee.search(call.callee) for s in self.sinks):
                continue
            text = src.text_of(call.node)
            if self.safe_loader.search(text):
                continue
            if call.callee == "numpy.load" and "allow_pickle=True" not in text:
                continue
            if call.callee == "readObject" and src.lang is Lang.JAVA and not re.search(r"ObjectInputStream|ois|in\b", src.text):
                continue
            tainted = any(is_tainted(src, a) for a in call.args)
            found.append(
                self.at_node(
                    src,
                    call.node,
                    f"{call.callee}로 객체를 역직렬화합니다. 신뢰할 수 없는 데이터라면 원격 코드 실행으로 이어질 수 있습니다.",
                    severity=Severity.CRITICAL if tainted else Severity.HIGH,
                )
            )
        if src.lang in (Lang.CSHARP, Lang.JAVA):
            for idx, line in enumerate(src.code_lines, start=1):
                for pattern, message in self.regexes:
                    if pattern.search(line):
                        found.append(self.at_line(src, idx, message))
        return found


class ToctouRule(BaseRule):
    rule_id = "IL-516"
    name = "경쟁조건: 검사시점과 사용시점(TOCTOU) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("3-1")
    plain = "파일이 있는지 확인한 뒤 여는 사이에 다른 프로그램이 파일을 바꿔치기하면, 확인과 실제 사용 결과가 달라집니다."
    how_to_fix = "존재 여부를 미리 확인하지 말고 바로 열고 예외를 처리하세요 (EAFP). 임시 파일은 tempfile/mkstemp처럼 원자적으로 만드세요."
    check_re = re.compile(
        r"^(os\.path\.(exists|isfile|isdir)|os\.access|(fs\.)?(existsSync|accessSync|statSync)|fs\.(exists|access)|File\.Exists|Directory\.Exists|Files\.(exists|isReadable|isWritable)|file_exists|is_file|is_readable|is_writable|access|stat)$|\.exists$|\.isFile$|\.canRead$|\.canWrite$"
    )
    use_re = re.compile(
        r"^(open|fopen|file_get_contents|file_put_contents|unlink|remove|rename|os\.(remove|unlink|rename)|shutil\.\w+|fs\.(readFile|writeFile|unlink|rename|readFileSync|writeFileSync|createReadStream)|File\.(ReadAll\w+|WriteAll\w+|Delete|Open\w*|Copy|Move)|newFileInputStream|newFileOutputStream|newFileReader|newFileWriter|os\.(Open|Create|ReadFile|WriteFile|Remove))$|Files\.(read\w+|write\w*|delete|copy|move)$"
    )

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        calls_by_fn: dict[int, list[Call]] = {}
        for call in iter_calls(src):
            fn = enclosing_function(call.node, src.lang)
            calls_by_fn.setdefault(fn.id if fn is not None else -1, []).append(call)
        for calls in calls_by_fn.values():
            calls.sort(key=lambda c: c.node.start_byte)
            for i, check in enumerate(calls):
                if not self.check_re.search(check.callee):
                    continue
                target = self._target(src, check)
                if not target:
                    continue
                for later in calls[i + 1 :]:
                    if self.use_re.search(later.callee) and later.args and self._norm(src.text_of(later.args[0])) == target:
                        found.append(self.at_node(src, check.node, f"{check.callee}로 확인한 뒤 같은 대상을 {later.callee}로 사용합니다 (검사 시점과 사용 시점 사이 경쟁).", confidence=Confidence.REVIEW))
                        break
        return found

    def _target(self, src: SourceFile, call: Call) -> str:
        if call.args:
            return self._norm(src.text_of(call.args[0]))
        m = re.match(r"(.+)\.(exists|isFile|canRead|canWrite)$", call.callee)
        return self._norm(m.group(1)) if m else ""

    @staticmethod
    def _norm(text: str) -> str:
        return re.sub(r"\s+", "", text)


class InfiniteLoopRule(BaseRule):
    rule_id = "IL-517"
    name = "종료되지 않는 반복문 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.LOW
    gov_standard = mois_ref("3-2")
    plain = "빠져나오는 조건이 없는 반복문은 서버 자원을 계속 먹고 멈추지 않을 수 있습니다."
    how_to_fix = "반복문에 종료 조건(break/return)이나 최대 반복 횟수·타임아웃을 두세요. 데몬이라면 종료 신호를 확인하는 조건을 쓰세요."
    loop_types = {"while_statement", "for_statement", "do_statement", "loop_expression", "while_expression"}
    constant_true = re.compile(r"^\(?\s*(true|True|1)\s*\)?$")
    exits = {"break_statement", "return_statement", "throw_statement", "raise_statement", "break_expression", "return_expression"}
    exit_calls = re.compile(r"\b(exit|sys\.exit|os\._exit|os\.Exit|System\.exit|panic|abort|std::process::exit|Environment\.Exit|die)\b")

    def check(self, src: SourceFile) -> list[Violation]:
        if src.root is None or src.lang is None:
            return []
        found = []
        for node in src.nodes:
            if node.type not in self.loop_types:
                continue
            if not self._infinite(src, node):
                continue
            body = node.child_by_field_name("body") or node
            if self._has_exit(src, body):
                continue
            found.append(self.at_node(src, node, "종료 조건이 없는 무한 반복문입니다. 종료 조건이나 타임아웃을 두십시오.", confidence=Confidence.REVIEW))
        return found

    def _infinite(self, src: SourceFile, node: Node) -> bool:
        if node.type == "loop_expression":
            return True
        cond = node.child_by_field_name("condition")
        if node.type == "for_statement":
            if src.lang is Lang.GO:
                return all(c.type == "block" for c in node.named_children)
            return cond is None and bool(re.match(r"\s*for\s*\(\s*;\s*;\s*\)", src.text_of(node)))
        if cond is None:
            return False
        return bool(self.constant_true.match(src.text_of(cond).strip()))

    def _has_exit(self, src: SourceFile, body: Node) -> bool:
        if src.lang is None:
            return False
        for n in walk_no_nested_functions(body, src.lang):
            if n.type in self.exits:
                return True
            if n.type in ("raise_statement", "throw_statement"):
                return True
        return bool(self.exit_calls.search(src.text_of(body)))


RESOURCE_CALLEES = {
    Lang.PYTHON: re.compile(r"^(open|socket\.socket|sqlite3\.connect|psycopg2\.connect|pymysql\.connect|mysql\.connector\.connect|urllib\.request\.urlopen|tempfile\.NamedTemporaryFile|zipfile\.ZipFile|tarfile\.open)$"),
    Lang.JAVA: re.compile(r"^new(FileInputStream|FileOutputStream|FileReader|FileWriter|BufferedReader|BufferedWriter|Scanner|Socket|ServerSocket|RandomAccessFile|PrintWriter|InputStreamReader|ZipFile)$|(^|\.)(getConnection|createStatement|prepareStatement|openStream|getInputStream|getOutputStream)$"),
    Lang.CSHARP: re.compile(r"^new(StreamReader|StreamWriter|FileStream|SqlConnection|NpgsqlConnection|MySqlConnection|SqliteConnection|TcpClient|BinaryReader|BinaryWriter)$|^File\.(Open\w*|Create\w*)$"),
    Lang.GO: re.compile(r"^(os\.(Open|OpenFile|Create)|sql\.Open|net\.Dial\w*|http\.(Get|Post|Head)|client\.(Get|Do))$"),
    Lang.C: re.compile(r"^(fopen|fdopen|popen|opendir)$"),
    Lang.CPP: re.compile(r"^(fopen|fdopen|popen|opendir)$"),
}
RELEASE_FN = r"(close|Close|dispose|Dispose|release|shutdown|disconnect|fclose|pclose|closedir|unlink)"


class ResourceLeakRule(BaseRule):
    rule_id = "IL-518"
    name = "부적절한 자원 해제 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("5-2")
    plain = "파일·DB 연결을 열고 닫지 않으면 서버가 오래 돌수록 자원이 고갈되어 어느 순간 멈춥니다."
    how_to_fix = "자원은 자동으로 닫히는 구문을 쓰세요. Python: with open(...) / Java: try-with-resources / C#: using / Go: defer f.Close() / C: fclose 보장"
    languages = frozenset(RESOURCE_CALLEES)

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None or src.lang not in RESOURCE_CALLEES:
            return found
        pattern = RESOURCE_CALLEES[src.lang]
        call_nodes = {c.node.id: c for c in iter_calls(src) if pattern.search(c.callee)}
        if not call_nodes:
            return found
        for node in src.nodes:
            if node.type not in ASSIGN_TYPES:
                continue
            left, right = _target_and_value(node)
            if left is None or right is None:
                continue
            call = self._call_in(right, call_nodes)
            if call is None:
                continue
            names = _target_names(src, left)
            names.discard("_")
            names.discard("err")
            if not names:
                continue
            if self._within_managed(src, node):
                continue
            fn = enclosing_function(node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text
            if all(self._released(scope, n) for n in names):
                continue
            found.append(self.at_node(src, node, f"{call.callee}로 연 자원을 닫는 코드가 보이지 않습니다.", confidence=Confidence.REVIEW))
        return found

    def _call_in(self, node: Node, call_nodes: dict) -> Call | None:
        """우변이 자원을 만드는 호출 그 자체(감싸는 await·괄호 제외)일 때만 반환한다."""
        current = node
        while current.type in ("await_expression", "parenthesized_expression", "expression_list") and current.named_children:
            current = current.named_children[-1]
        return call_nodes.get(current.id)

    def _within_managed(self, src: SourceFile, node: Node) -> bool:
        current = node.parent
        while current is not None:
            if current.type in ("with_statement", "using_statement", "resource_specification", "try_with_resources_statement"):
                return True
            current = current.parent
        stmt = node
        while stmt.parent is not None and stmt.type not in ("local_declaration_statement", "local_variable_declaration", "expression_statement"):
            stmt = stmt.parent
        return src.text_of(stmt).lstrip().startswith("using ")

    @staticmethod
    def _released(scope: str, name: str) -> bool:
        n = re.escape(name)
        return bool(
            re.search(rf"\b{n}\b[^;\n]*\.{RELEASE_FN}\(|\b{RELEASE_FN}\(\s*{n}\b|defer\s+{n}\.|defer\s+[^;\n]*{n}\.|closing\(\s*{n}|return\s+{n}\s*(?:[;\n]|$)|yield\s+{n}\s*(?:[;\n]|$)|(self|this)\.\w+\s*=\s*{n}\b|\.Body\.Close\(\)", scope)
        ) or bool(re.search(rf"\b{n}\b\s*\.\s*(Body\s*\.\s*)?{RELEASE_FN}\(", scope))


class NullDereferenceRule(BaseRule):
    rule_id = "IL-519"
    name = "Null Pointer 역참조 가능성 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("5-1")
    plain = "값이 없을 수도 있는데 확인 없이 바로 쓰면 프로그램이 예고 없이 중단됩니다."
    how_to_fix = "반환값이 None/NULL/Optional일 수 있으면 사용 전에 확인하세요. C: if (p == NULL) / Java: Optional.orElseThrow / Python: 결과 None 검사"
    alloc_re = re.compile(r"^(malloc|calloc|realloc|fopen|strdup|fdopen|popen)$")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None:
            return found
        if src.lang in C_FAMILY:
            found.extend(self._c_alloc(src))
        if src.lang is Lang.PYTHON:
            for m in re.finditer(r"\bre\.(match|search|fullmatch)\([^\n]*?\)\.(group|groups|start|end|span)\(", src.code_text):
                line = src.code_text.count("\n", 0, m.start()) + 1
                found.append(self.at_line(src, line, "re.match/search 결과가 None일 수 있는데 바로 .group()을 호출합니다.", confidence=Confidence.REVIEW))
            for m in re.finditer(r"\.get\(\s*[^,()]+\)\.\w+", src.code_text):
                line = src.code_text.count("\n", 0, m.start()) + 1
                found.append(self.at_line(src, line, ".get() 결과가 None일 수 있는데 바로 속성/메서드를 사용합니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        if src.lang is Lang.JAVA:
            for fn in iter_functions(src):
                text = src.text_of(fn.node)
                if re.search(r"\.get\(\)", text) and "Optional" in text and not re.search(r"isPresent\(\)|ifPresent|orElse|orElseThrow|isEmpty\(\)", text):
                    found.append(self.at_node(src, fn.node, "Optional.get()을 isPresent 확인이나 orElseThrow 없이 사용합니다.", confidence=Confidence.REVIEW))
        return found

    def _c_alloc(self, src: SourceFile) -> list[Violation]:
        found = []
        calls = {c.node.id: c for c in iter_calls(src) if self.alloc_re.search(c.callee)}
        for node in src.nodes:
            if node.type not in ASSIGN_TYPES:
                continue
            left, right = _target_and_value(node)
            if left is None or right is None:
                continue
            call = next((calls[n.id] for n in walk(right) if n.id in calls), None)
            if call is None:
                continue
            names = _target_names(src, left)
            fn = enclosing_function(node, src.lang)
            scope = src.text_of(fn) if fn is not None else src.text
            for name in names:
                n = re.escape(name)
                if re.search(rf"!\s*{n}\b|\b{n}\s*(==|!=)\s*(NULL|nullptr|0)\b|(NULL|nullptr)\s*(==|!=)\s*{n}\b|if\s*\(\s*{n}\s*\)|assert\(\s*{n}", scope):
                    continue
                found.append(self.at_node(src, node, f"{call.callee} 결과 {name}의 NULL 여부를 확인하지 않고 사용합니다."))
        return found


class DebugCodeRule(BaseRule):
    rule_id = "IL-520"
    name = "제거되지 않고 남은 디버그 코드 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("6-2")
    plain = "개발할 때 켜 둔 디버그 모드가 배포에도 남으면, 오류 화면에서 코드·환경변수·비밀 값이 그대로 노출되고 원격 코드 실행 통로가 열리기도 합니다."
    how_to_fix = "디버그 설정은 환경변수로 제어하고 운영에서는 끄세요. 예: debug=os.getenv('DEBUG') == '1' / NODE_ENV=production / ASPNETCORE_ENVIRONMENT=Production"
    patterns = [
        (re.compile(r"\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|FLASK_DEBUG\s*=\s*['\"]?1|config\[['\"]DEBUG['\"]\]\s*=\s*True"), "디버그 모드가 켜져 있습니다.", Severity.HIGH),
        (re.compile(r"\bbreakpoint\(\)|\bpdb\.set_trace\(|\bimport\s+i?pdb\b|\bipdb\.set_trace"), "디버거 호출이 남아 있습니다.", Severity.MEDIUM),
        (re.compile(r"^\s*debugger\s*;?\s*$"), "debugger 문이 남아 있습니다.", Severity.MEDIUM),
        (re.compile(r"\bphpinfo\(\)|\bvar_dump\(|\bprint_r\(|\bvar_export\("), "PHP 디버그 출력이 남아 있습니다.", Severity.MEDIUM),
        (re.compile(r"\bDebugger\.(Break|Launch)\(|UseDeveloperExceptionPage\(\)"), "개발자 예외 페이지/디버거가 켜져 있습니다.", Severity.MEDIUM),
        (re.compile(r"_\s+\"net/http/pprof\""), "pprof 디버그 엔드포인트가 노출될 수 있습니다.", Severity.HIGH),
        (re.compile(r"\bdbg!\("), "dbg! 매크로가 남아 있습니다.", Severity.LOW),
        (re.compile(r"NODE_ENV\s*[=:]\s*['\"]?development|ASPNETCORE_ENVIRONMENT\s*[=:]\s*['\"]?Development|FLASK_ENV\s*[=:]\s*['\"]?development|APP_DEBUG\s*=\s*true"), "개발 환경 설정이 배포 파일에 있습니다.", Severity.MEDIUM),
    ]

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for idx, line in enumerate(src.code_lines, start=1):
            for pattern, message, severity in self.patterns:
                if pattern.search(line):
                    if src.is_test:
                        break
                    if src.kind == "env" and "DEBUG" not in line and "ENVIRONMENT" not in line and "NODE_ENV" not in line:
                        break
                    found.append(self.at_line(src, idx, message, severity=severity))
                    break
        return found


class ServletSharedFieldRule(BaseRule):
    rule_id = "IL-521"
    name = "잘못된 세션에 의한 데이터 정보노출 (서블릿 공유 필드) 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("6-1")
    plain = "서블릿은 모든 사용자가 하나의 객체를 공유합니다. 인스턴스 변수에 사용자 정보를 담으면 다른 사용자에게 섞여 보일 수 있습니다."
    how_to_fix = "요청 데이터는 메서드의 지역 변수로 처리하고, 공유가 필요한 값은 final/동기화된 객체로 한정하세요."
    languages = frozenset({Lang.JAVA})

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None:
            return found
        for node in src.nodes:
            if node.type != "class_declaration":
                continue
            header = src.data[node.start_byte : (node.child_by_field_name("body") or node).start_byte].decode("utf-8", "replace")
            if not re.search(r"extends\s+(\w+\.)*(HttpServlet|GenericServlet)\b", header):
                continue
            body = node.child_by_field_name("body")
            if body is None:
                continue
            for child in body.named_children:
                if child.type != "field_declaration":
                    continue
                text = src.text_of(child)
                head = text.split("=")[0]
                if re.search(r"\b(static|final)\b", head):
                    continue
                found.append(self.at_node(src, child, "서블릿 인스턴스 필드는 모든 요청이 공유합니다. 지역 변수로 바꾸십시오."))
        return found


class PrivateArrayExposureRule(BaseRule):
    rule_id = "IL-522"
    name = "Private 배열의 Public 노출 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("6-3", "6-4")
    plain = "private 배열을 그대로 돌려주거나 바깥 배열을 그대로 저장하면, 호출한 쪽이 내부 데이터를 마음대로 바꿀 수 있습니다."
    how_to_fix = "배열은 clone()/Arrays.copyOf()로 복사해서 반환·저장하세요."
    languages = frozenset({Lang.JAVA, Lang.CSHARP})

    def check(self, src: SourceFile) -> list[Violation]:
        found: list[Violation] = []
        for cls in src.nodes:
            if cls.type != "class_declaration":
                continue
            body = cls.child_by_field_name("body")
            fields = self._private_array_fields(src, body) if body is not None else set()
            if body is None or not fields:
                continue
            for method in body.named_children:
                if method.type == "method_declaration":
                    found.extend(self._check_method(src, method, fields))
        return found

    def _check_method(self, src: SourceFile, method: Node, fields: set[str]) -> list[Violation]:
        mbody = method.child_by_field_name("body")
        method_text = src.text_of(method)
        if mbody is None or not re.search(r"\bpublic\b", method_text[: method_text.find("(")]):
            return []
        array_params = self._array_params(src, method)
        found = []
        for n in walk(mbody):
            if n.type == "return_statement" and n.named_children:
                value = src.text_of(n.named_children[0]).replace("this.", "").strip()
                if value in fields:
                    found.append(self.at_node(src, n, f"public 메서드가 private 배열 {value}을(를) 그대로 반환합니다."))
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                if left is None or right is None:
                    continue
                lname = src.text_of(left).replace("this.", "").strip()
                if lname in fields and src.text_of(right).strip() in array_params:
                    found.append(self.at_node(src, n, f"public 메서드의 배열 인자를 private 배열 {lname}에 그대로 할당합니다."))
        return found

    @staticmethod
    def _array_params(src: SourceFile, method: Node) -> set[str]:
        params = method.child_by_field_name("parameters")
        names = set()
        for p in params.named_children if params is not None else []:
            m = re.search(r"(\w+)\s*$", src.text_of(p))
            if "[" in src.text_of(p) and m:
                names.add(m.group(1))
        return names

    def _private_array_fields(self, src: SourceFile, body: Node) -> set[str]:
        names = set()
        for child in body.named_children:
            if child.type != "field_declaration":
                continue
            text = src.text_of(child)
            head = text.split("=")[0].split(";")[0]
            if "private" in head and "[]" in head:
                m = re.search(r"(\w+)\s*$", head.strip())
                if m:
                    names.add(m.group(1))
        return names


class DnsDecisionRule(BaseRule):
    rule_id = "IL-523"
    name = "DNS lookup에 의존한 보안결정 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("7-1")
    plain = "도메인 이름(DNS) 조회 결과는 공격자가 조작할 수 있어서, 접근 허용 여부를 이름으로 판단하면 우회됩니다."
    how_to_fix = "접근 통제는 IP 주소나 인증 정보 같은 위조하기 어려운 값으로 하고, 가능하면 서명된 토큰 인증을 쓰세요."
    dns_re = re.compile(r"gethostbyaddr|gethostbyname|getfqdn|getHostName\(|getCanonicalHostName\(|getRemoteHost\(|GetHostEntry|GetHostName|LookupAddr|getnameinfo|reverse_dns|ReverseLookup", re.IGNORECASE)
    if_types = {"if_statement", "if_expression", "ternary_expression", "conditional_expression", "while_statement"}

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        if src.root is None:
            return found
        for node in src.nodes:
            if node.type not in self.if_types:
                continue
            cond = node.child_by_field_name("condition")
            if cond is not None and self.dns_re.search(src.text_of(cond)):
                found.append(self.at_node(src, node, "DNS 조회 결과로 분기(접근 허용 판단)합니다.", confidence=Confidence.REVIEW))
        return found


class WeakApiRule(BaseRule):
    rule_id = "IL-524"
    name = "취약한 API 사용 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("7-2")
    plain = "예전부터 위험한 것으로 알려진 함수는 안전하게 쓸 방법이 없거나 매우 어렵습니다."
    how_to_fix = "gets 대신 fgets, 임시 파일은 mkstemp를 쓰세요. 서블릿에서는 System.exit 대신 응답을 반환하고, 직접 소켓 대신 컨테이너가 제공하는 API를 쓰세요."

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            if src.lang in C_FAMILY:
                if call.callee == "gets":
                    found.append(self.at_node(src, call.node, "gets()는 입력 길이를 제한할 수 없어 항상 버퍼 오버플로우가 가능합니다. fgets로 교체하십시오.", severity=Severity.CRITICAL))
                elif call.callee in ("tmpnam", "tempnam", "mktemp", "getwd", "cuserid", "ctermid"):
                    found.append(self.at_node(src, call.node, f"{call.callee}()는 경쟁조건·버퍼 문제가 있는 취약한 API입니다. mkstemp/getcwd로 교체하십시오."))
            elif src.lang is Lang.JAVA and re.search(r"HttpServlet|javax\.servlet|jakarta\.servlet", src.text):
                if call.callee in ("System.exit", "Runtime.getRuntime().exit", "Runtime.getRuntime().halt"):
                    found.append(self.at_node(src, call.node, "서블릿 컨테이너 안에서 System.exit를 호출하면 서비스 전체가 종료됩니다."))
                elif call.callee in ("newServerSocket", "newSocket"):
                    found.append(self.at_node(src, call.node, "Java EE 컨테이너 안에서 소켓을 직접 사용합니다.", severity=Severity.LOW, confidence=Confidence.REVIEW))
        return found


class MemorySafetyRule(BaseRule):
    rule_id = "IL-514"
    name = "메모리 버퍼 오버플로우·포맷 스트링·정수 오버플로우 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("1-16", "1-17", "1-14")
    plain = "C/C++에서 버퍼 크기를 확인하지 않고 복사하거나 입력을 포맷 문자열로 쓰면 프로그램을 장악당할 수 있습니다."
    how_to_fix = "strcpy/strcat/sprintf 대신 snprintf, strlcpy, std::string을 쓰세요. printf는 항상 printf(\"%s\", 값) 형태로 호출하세요. 크기 계산 전에 오버플로우를 검사하세요."
    languages = frozenset(C_FAMILY)
    unsafe_copy = re.compile(r"^(strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat|swprintf)$")
    fmt_funcs = {"printf": 0, "fprintf": 1, "sprintf": 1, "snprintf": 2, "syslog": 1, "vprintf": 0, "dprintf": 1, "wprintf": 0, "err": 1, "warn": 0}
    scanf_funcs = re.compile(r"^(scanf|fscanf|sscanf)$")
    alloc = re.compile(r"^(malloc|alloca|calloc|realloc)$")

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for call in iter_calls(src):
            callee = call.callee
            if self.unsafe_copy.search(callee):
                source_arg = call.args[1] if len(call.args) > 1 else None
                if callee in ("sprintf", "vsprintf") and len(call.args) > 2:
                    source_arg = call.args[1]
                fmt_arg = call.args[1] if callee in ("sprintf", "vsprintf", "swprintf") and len(call.args) > 1 else None
                bounded_format = fmt_arg is not None and is_literal(fmt_arg) and not re.search(r"%[^a-zA-Z%]*s|%\[", src.text_of(fmt_arg))
                severity = Severity.LOW if bounded_format else (Severity.HIGH if source_arg is not None and not is_literal(source_arg) else Severity.MEDIUM)
                found.append(self.at_node(src, call.node, f"{callee}는 목적지 버퍼 크기를 검사하지 않습니다. 길이를 제한하는 함수(snprintf/strlcpy)를 쓰십시오.", severity=severity))
            if callee in self.fmt_funcs:
                idx = self.fmt_funcs[callee]
                if len(call.args) > idx and not is_literal(call.args[idx]):
                    arg = call.args[idx]
                    tainted = is_tainted(src, arg, cli=True)
                    if arg.type in ("identifier", "subscript_expression", "field_expression", "call_expression", "pointer_expression", "parenthesized_expression", "cast_expression"):
                        found.append(self.at_node(src, call.node, f"{callee}의 포맷 문자열이 상수가 아닙니다. 외부 입력이면 메모리 변조가 가능합니다.", severity=Severity.CRITICAL if tainted else Severity.HIGH))
            if self.scanf_funcs.search(callee):
                fmt = call.args[0 if callee == "scanf" else 1] if call.args else None
                if fmt is not None and re.search(r"%s|%\[", src.text_of(fmt)) and not re.search(r"%\d+s|%\d+\[", src.text_of(fmt)):
                    found.append(self.at_node(src, call.node, f"{callee}의 %s는 입력 길이를 제한하지 않아 버퍼 오버플로우가 가능합니다. 너비를 지정하십시오(%63s)."))
            if self.alloc.search(callee) and call.args:
                size = call.args[0]
                if size.type == "binary_expression" and re.search(r"[*+]", src.text_of(size)) and not is_literal(size) and is_tainted(src, size, cli=True):
                    found.append(self.at_node(src, call.node, f"{callee}의 크기 계산에 외부 입력이 곱·합으로 쓰여 정수 오버플로우가 가능합니다.", severity=Severity.HIGH))
        return found


class UseAfterFreeRule(BaseRule):
    rule_id = "IL-528"
    name = "해제된 자원 사용 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.HIGH
    gov_standard = mois_ref("5-3")
    plain = "이미 반납(free)한 메모리를 다시 쓰면 프로그램이 예측할 수 없이 동작하고, 공격자가 그 자리를 차지해 실행 흐름을 빼앗을 수 있습니다."
    how_to_fix = "free 직후 포인터를 NULL로 만들고, 해제 뒤에는 그 포인터를 쓰지 마세요. C++에서는 직접 delete 대신 std::unique_ptr, std::vector를 쓰세요."
    languages = frozenset(C_FAMILY)

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        free_calls = [c for c in iter_calls(src) if c.callee in ("free", "kfree", "g_free") and c.args]
        delete_nodes = [n for n in src.nodes if n.type == "delete_expression"]
        events: list[tuple[Node, str, Node]] = [(c.node, src.text_of(c.args[0]).strip(), c.node) for c in free_calls]
        for d in delete_nodes:
            target = d.named_children[-1] if d.named_children else None
            if target is not None:
                events.append((d, src.text_of(target).strip(), d))
        for node, name, free_node in events:
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                continue
            fn = enclosing_function(node, src.lang)
            if fn is None:
                continue
            use = self._first_use_after(src, fn, name, free_node)
            if use is not None:
                found.append(self.at_node(src, use, f"{name}을(를) 해제한 뒤 다시 사용합니다 (해제 위치: {src.line_of(free_node)}줄)."))
        return found

    @staticmethod
    def _first_use_after(src: SourceFile, fn: Node, name: str, free_node: Node) -> Node | None:
        for n in src.nodes:
            if n.type != "identifier" or n.start_byte < free_node.end_byte or n.end_byte > fn.end_byte:
                continue
            if src.text_of(n) != name:
                continue
            parent = n.parent
            if parent is not None and parent.type == "assignment_expression" and parent.child_by_field_name("left") == n:
                return None  # 다시 대입되면 이후 사용은 새 값이다
            if parent is not None and parent.type == "call_expression" and src.text_of(parent).startswith(("free", "g_free")):
                return n  # 이중 해제
            return n
        return None


class UninitializedVariableRule(BaseRule):
    rule_id = "IL-529"
    name = "초기화되지 않은 변수 사용 탐지"
    iron_law = IronLaw.LAW_5
    severity = Severity.MEDIUM
    gov_standard = mois_ref("5-4")
    plain = "값을 넣기 전에 변수를 읽으면 메모리에 남아 있던 임의의 값이 쓰여, 결과가 실행할 때마다 달라지고 정보가 새어 나갑니다."
    how_to_fix = "변수는 선언할 때 반드시 초기값을 주세요. 예: int count = 0; char *p = NULL;"
    languages = frozenset(C_FAMILY)

    def check(self, src: SourceFile) -> list[Violation]:
        found = []
        for node in src.nodes:
            if node.type != "declaration":
                continue
            if any(c.type == "storage_class_specifier" and src.text_of(c) in ("static", "extern") for c in node.children):
                continue
            fn = enclosing_function(node, src.lang)
            if fn is None:
                continue
            for child in node.named_children:
                if child.type not in ("identifier", "pointer_declarator"):
                    continue
                name_node = child if child.type == "identifier" else self._declarator_name(child)
                if name_node is None:
                    continue
                name = src.text_of(name_node)
                use = self._first_event(src, fn, name, node)
                if use == "read":
                    found.append(self.at_node(src, node, f"변수 {name}을(를) 초기화하지 않고 선언한 뒤 값을 읽습니다.", confidence=Confidence.REVIEW))
        return found

    @staticmethod
    def _declarator_name(node: Node) -> Node | None:
        for n in walk(node):
            if n.type == "identifier":
                return n
        return None

    @staticmethod
    def _first_event(src: SourceFile, fn: Node, name: str, decl: Node) -> str | None:
        for n in src.nodes:
            if n.type != "identifier" or n.start_byte < decl.end_byte or n.end_byte > fn.end_byte or src.text_of(n) != name:
                continue
            parent = n.parent
            if parent is None:
                return None
            if parent.type == "assignment_expression" and parent.child_by_field_name("left") == n:
                return "write"
            if parent.type == "pointer_expression" and src.text_of(parent).startswith("&"):
                return "write"
            if parent.type in ("argument_list",) and parent.parent is not None and re.match(r"(scanf|fscanf|sscanf|read|fread|memset|memcpy|strcpy|strncpy|fgets|gets|recv)\b", src.text_of(parent.parent)):
                return "write"
            if parent.type in ("update_expression", "init_declarator", "pointer_declarator", "array_declarator"):
                return None
            return "read"
        return None


CODE_QUALITY_RULES: list[type[BaseRule]] = [
    DeserializationRule,
    ToctouRule,
    InfiniteLoopRule,
    ResourceLeakRule,
    NullDereferenceRule,
    DebugCodeRule,
    ServletSharedFieldRule,
    PrivateArrayExposureRule,
    DnsDecisionRule,
    WeakApiRule,
    MemorySafetyRule,
    UseAfterFreeRule,
    UninitializedVariableRule,
]

