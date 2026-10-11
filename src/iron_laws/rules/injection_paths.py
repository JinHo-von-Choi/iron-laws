"""injection paths 규칙."""
# iron-laws: ignore-file[IL-510] CSRF 해제 구문을 탐지하는 패턴 정의
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
    ASSIGN_TYPES,
    Ctx,
    is_tainted,
    reaching_definitions,
)
from iron_laws.rules.guards import (
    executes_unconditionally,
    redefined_between,
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
    version = 2
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
        Sink.of(PY, r"^(open|os\.path\.join|os\.remove|os\.unlink|os\.rmdir|os\.listdir|os\.makedirs|os\.rename|send_file|send_from_directory|FileResponse|Path|pathlib\.Path|shutil\.\w+)$", None),
        Sink.of(PY, r"\.(read_text|write_text|read_bytes|write_bytes|mkdir|unlink|rmdir|rename|touch)$", None),
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

    RECEIVER_PATH_METHODS = re.compile(r"\.(read_text|write_text|read_bytes|write_bytes|open|unlink|rmdir|mkdir|rename|touch)$")

    def select_args(self, src: SourceFile, call: Call, sink: Sink) -> list[Node]:
        """경로가 인자가 아니라 객체(수신자)에 들어 있는 pathlib 호출은 수신자 식도 본다: `(Path(base) / name).read_text()`"""
        args = super().select_args(src, call, sink)
        if src.lang is Lang.PYTHON and self.RECEIVER_PATH_METHODS.search(call.callee):
            function = call.node.child_by_field_name("function")
            receiver = function.child_by_field_name("object") if function is not None else None
            if receiver is not None:
                return [receiver, *args]
        return args

    BUILDER_RE = re.compile(r"^(os\.path\.join|path\.join|path\.resolve|filepath\.Join|Path|pathlib\.Path|Paths\.get|Path\.of|Path\.Combine)$")

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

    def _guarded_after(self, src: SourceFile, call: Call, variable: str) -> bool:
        """조립한 경로 변수가 뒤에서 정규화·범위 검사를 받는지(거부 분기 또는 assert)"""
        scope = enclosing_function(call.node, src.lang) or src.root
        if scope is None:
            return False
        assignment = self._assignment_of(src, call)
        defs_text = src.text_of(assignment) if assignment is not None else ""
        for node in walk(scope):
            if node.type not in ("if_statement", "assert_statement") or node.start_byte < call.node.end_byte:
                continue
            cond = node.child_by_field_name("condition")
            if cond is None and node.type == "assert_statement" and node.named_children:
                cond = node.named_children[0]
            if cond is None:
                continue
            cond_text = src.text_of(cond)
            if not CONFINEMENT_RE.search(cond_text) or variable not in identifiers_in(src, cond):
                continue
            if not (NORMALIZE_RE.search(cond_text) or NORMALIZE_RE.search(defs_text)):
                continue
            if node.type == "assert_statement":
                if executes_unconditionally(node, scope) and not redefined_between(src, scope, variable, call.node.end_byte, node.start_byte):
                    return True
                continue
            consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
            if (
                consequence is not None
                and re.match(r"\s*\(?\s*(not\b|!)", cond_text)
                and terminates(src, consequence)
                and executes_unconditionally(node, scope)
                and not redefined_between(src, scope, variable, call.node.end_byte, node.start_byte)
            ):
                return True
        return False

    def _confined(self, src: SourceFile, call: Call, arg: Node) -> bool:
        """싱크로 가는 경로 변수가 정규화된 뒤 허용 폴더 안인지 검사되는지 본다.
        검사 대상 변수가 같아야 하고, 싱크보다 앞서 실행되어야 하며(거부 분기가 끝나거나 싱크가 통과 분기 안에 있음),
        경로가 정규화된 값이어야 한다. 다른 변수를 검사하거나 싱크 뒤에 검사하면 인정하지 않는다."""
        scope = enclosing_function(call.node, src.lang) or src.root
        names = identifiers_in(src, arg)
        if scope is None or not names:
            return False
        defs_text = " ".join(src.text_of(d) for n in names for d in reaching_definitions(src, scope, n, arg.start_byte))
        for node in walk(scope):
            if node.type not in ("if_statement", "assert_statement", "if_expression"):
                continue
            cond = node.child_by_field_name("condition")
            if cond is None and node.type == "assert_statement" and node.named_children:
                cond = node.named_children[0]
            if cond is None:
                continue
            cond_text = src.text_of(cond)
            if not CONFINEMENT_RE.search(cond_text) or not (identifiers_in(src, cond) & names):
                continue
            if not (NORMALIZE_RE.search(cond_text) or NORMALIZE_RE.search(defs_text)):
                continue
            checked = identifiers_in(src, cond) & names
            if node.type == "assert_statement":
                if (
                    node.end_byte <= call.node.start_byte
                    and executes_unconditionally(node, scope)
                    and not any(redefined_between(src, scope, n, node.end_byte, call.node.start_byte) for n in checked)
                ):
                    return True
                continue
            consequence = node.child_by_field_name("consequence") or node.child_by_field_name("body")
            if consequence is None:
                continue
            negated = re.match(r"\s*\(?\s*(not\b|!)", cond_text) is not None
            if negated:
                if (
                    node.end_byte <= call.node.start_byte
                    and terminates(src, consequence)
                    and executes_unconditionally(node, scope)
                    and not any(redefined_between(src, scope, n, node.end_byte, call.node.start_byte) for n in checked)
                ):
                    return True
            elif (
                consequence.start_byte <= call.node.start_byte
                and call.node.end_byte <= consequence.end_byte
                and not any(redefined_between(src, scope, n, cond.end_byte, call.node.start_byte) for n in checked)
            ):
                return True
        return False

    def skip_hit(self, src: SourceFile, call: Call, arg: Node, flow: Flow) -> bool:
        text = _context_text(src, arg)
        if SANITIZER_RE.search(text) or re.search(r"\.(Body|InputStream|OutputStream|BaseStream)\b", text):
            return True
        variable = self._builder_variable(src, call)
        if variable is not None and self._guarded_after(src, call, variable):
            return True  # 경로를 조립한 변수가 뒤에서 정규화·범위 검사를 받는다. 접근하는 싱크가 따로 판정한다
        if self._confined(src, call, arg):
            return True  # 정규화한 같은 변수를 허용 폴더와 비교하는 검사가 싱크보다 앞서 실행된다
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
