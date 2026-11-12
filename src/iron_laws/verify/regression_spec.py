"""
회귀시험 명세: 명세 형식(RegressionSpec), 계열별 공격·정상 입력, 지적에서 명세 후보를 제안하는 규칙.
제안한 명세는 검증 근거가 아니다. 사람이 입력·기대 결과·가짜 sink를 확인해 `confirmed: true`로 바꾼 명세만 regression.py가 실행한다.
작성자: 최진호
작성일: 2026-11-12
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from tree_sitter import Node

from iron_laws.core.config import ConfigError
from iron_laws.core.models import Violation
from iron_laws.engine.ast_tools import Func, enclosing_function, iter_functions
from iron_laws.engine.source import SourceFile

RegressionFamily = Literal["command", "path", "sql", "ssrf", "xss"]

FAMILY_OF_RULE: dict[str, RegressionFamily] = {"IL-504": "command", "IL-502": "path", "IL-513": "path", "IL-501": "sql", "IL-506": "ssrf", "IL-505": "xss"}
PAYLOADS = {
    "command": ("x; touch IRON_LAWS_PWNED", "readme.txt"),
    "path": ("../../etc/passwd", "report.txt"),
    "sql": ("' OR '1'='1", "alice"),
    "ssrf": ("http://169.254.169.254/latest/meta-data/", "https://example.com/resource"),  # iron-laws: ignore[AI-101,IL-109] SSRF 회귀시험이 수정본에 넣는 공격 입력
    "xss": ("<script>IL_XSS(1)</script>", "alice"),
}
# 수정이 시험의 입력 하나만 막는지 보려고 같은 결함을 건드리는 다른 입력을 함께 시험한다(명세에 적혀 사람이 확인한다).
VARIANT_PAYLOADS = {
    # 구분자·공백 없는 형태·줄바꿈은 특정 문자만 지우는 수정을 가려낸다
    "command": ("x && touch IRON_LAWS_PWNED", "x | touch IRON_LAWS_PWNED", "$(touch IRON_LAWS_PWNED)", "`touch IRON_LAWS_PWNED`",
                "x;touch IRON_LAWS_PWNED", "x\ntouch IRON_LAWS_PWNED"),
    # 허용 폴더가 어디든 밖으로 나가는 입력만 쓴다. ....//는 '../'를 한 번만 지우는 수정, %2e는 검사 뒤에 디코딩하는 코드를 가려낸다
    "path": ("/etc/passwd", "sub/../../../../../etc/passwd", "../../../../../../../../etc/passwd",
             "....//....//....//....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    # 대소문자·주석 공백은 키워드 차단 목록으로 막은 수정을 가려낸다
    "sql": ("1 OR 1=1", "\" OR \"1\"=\"1", "'; DROP TABLE t--", "' UNION SELECT NULL--", "1 oR 1=1", "1/**/OR/**/1=1"),
    # 루프백·내부망·메타데이터 주소의 여러 표기(축약·10진·16진·IPv6·사용자 정보 속임)는 문자열 비교로 막은 수정을 가려낸다
    "ssrf": ("http://127.0.0.1:8080/admin", "http://localhost/admin", "http://[::1]/admin", "http://2130706433/", "http://0x7f.0.0.1/", "http://127.1/",  # iron-laws: ignore[AI-101,IL-109] SSRF 회귀시험이 수정본에 넣는 공격 입력
             "http://0/", "http://10.0.0.5/", "http://192.168.0.1/", "http://allowed.example.com@169.254.169.254/"),
    # 대소문자·중첩 태그는 `<script>`만 지우는 수정, 따옴표 탈출은 본문만 이스케이프한 수정, javascript: 는 속성 값만 보는 수정을 가려낸다
    "xss": ("<img src=x onerror=IL_XSS(1)>", "\"><svg onload=IL_XSS(1)>", "<ScRiPt>IL_XSS(1)</ScRiPt>", "<scr<script>ipt>IL_XSS(1)</scr</script>ipt>",
            "'><iframe srcdoc=IL_XSS(1)>", "javascript:IL_XSS(1)"),
}
CURSOR_NAMES = {"cur", "cursor", "c"}
CONNECTION_NAMES = {"conn", "connection", "db", "database", "con"}
REQUEST_RE = re.compile(r"\brequest\.(?:args|form|values|json|cookies|headers|get_json|data)\b")


class SourceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["param", "request"]
    param: str = ""  # kind=param: 입력이 들어오는 매개변수 이름


class TargetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    module: str
    function: str
    file: str


class InputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: str = Field(..., min_length=1, description="결함을 건드리는 입력")
    benign: str = Field(..., min_length=1, description="정상 대조군 입력")
    variants: list[str] = Field(default_factory=list, description="같은 결함을 건드리는 다른 입력. 수정이 시험 입력 하나만 막는 것을 가려낸다")


class ExpectSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base: str = Field(default="", description="path 계열: 접근해도 되는 폴더. 비우면 임시 기준 폴더")
    summary: str = Field(default="", description="사람이 읽는 기대 결과")
    allowed_hosts: list[str] = Field(default_factory=list, description="ssrf 계열: 요청해도 되는 호스트. 비우면 내부망·루프백·메타데이터 주소만 결함으로 본다")
    benign_behavior: Literal["report", "require"] = Field(
        default="report", description="정상 입력에서 원본과 수정본의 위험 호출 기록(명령·경로·SQL)이 다르면 report는 표시만, require는 실패로 본다"
    )


class RegressionSpec(BaseModel):
    """검토 가능한 회귀시험 명세. 입력·기대 결과·가짜 sink가 모두 드러나 있다."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    family: RegressionFamily
    finding: str = ""
    target: TargetSpec
    source: SourceSpec
    input: InputSpec
    expect: ExpectSpec = Field(default_factory=ExpectSpec)
    call_args: dict[str, Any] = Field(default_factory=dict)
    fake_globals: dict[str, Any] = Field(default_factory=dict)
    allowed_exceptions: list[str] = Field(default_factory=lambda: ["ValueError", "PermissionError", "RuntimeError"])
    fake_sink: list[str] = Field(default_factory=list, description="가짜로 바꾸는 API. 사람이 확인할 목록이며 harness가 계열별로 설치한다")
    review_notes: list[str] = Field(default_factory=list)
    confirmed: bool = False


FAKE_SINKS = {
    "command": ["os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput", "subprocess.Popen"],
    "path": ["builtins.open", "io.open", "pathlib.Path.open/read_text/read_bytes/write_text/write_bytes", "os.remove/unlink/listdir/makedirs/mkdir/rmdir/stat"],
    "sql": ["sqlite3.connect", "주입된 커서·연결 객체(execute/executemany/executescript 기록)"],
    "ssrf": ["requests.get/post/put/patch/delete/head/options/request·Session", "httpx.get/…/request·Client", "urllib.request.urlopen", "socket.gethostbyname·getaddrinfo(이름 풀이 대역)"],
    "xss": ["flask.Response·make_response·render_template_string(템플릿 원문)", "함수의 반환 문자열", "markupsafe(없으면 대역)"],
}


def load_spec(path: Path) -> RegressionSpec:
    if not path.is_file():
        raise ConfigError(f"회귀시험 명세 파일이 없습니다: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return RegressionSpec(**(data or {}))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValidationError, TypeError) as e:
        raise ConfigError(f"회귀시험 명세를 읽을 수 없습니다: {path} ({e})") from e


def dump_spec(spec: RegressionSpec) -> str:
    return yaml.safe_dump(spec.model_dump(mode="json"), allow_unicode=True, sort_keys=False)


# ---------------------------------------------------------------------------
# 제안: 지적의 근거에서 시험 후보를 만든다 (지원하지 못하는 모양은 이유와 함께 거절한다)
# ---------------------------------------------------------------------------


@dataclass
class Proposal:
    spec: RegressionSpec | None
    reason: str = ""


def _module_name(rel: str) -> str:
    parts = list(Path(rel).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _literal_base(call_text: str) -> str:
    """싱크 호출 식에 적힌 절대 경로 문자열에서 접근 허용 폴더를 추정한다.
    '/srv/uploads/' + name → /srv/uploads, f'/data/{name}' → /data. 추정이 틀릴 수 있어 사람이 확인하도록 명세에 남긴다."""
    for literal in re.findall(r"""['"](/[^'"]*)['"]""", call_text):
        prefix = re.split(r"[{%]", literal, maxsplit=1)[0]
        if not prefix:
            continue
        return (prefix.rstrip("/") if prefix.endswith("/") else str(Path(prefix).parent)) or "/"
    return ""


def propose_spec(root: Path, violation: Violation) -> Proposal:
    family = FAMILY_OF_RULE.get(violation.rule_id)
    if family is None:
        return Proposal(None, f"{violation.rule_id}는 회귀시험을 지원하는 계열(명령 실행·경로 접근·SQL 조립·SSRF·XSS)이 아니다")
    rel = violation.file_path.as_posix()
    if not rel.endswith(".py"):
        return Proposal(None, "Python 파일만 지원한다")
    path = root / rel
    if not path.is_file():
        return Proposal(None, f"파일을 읽을 수 없다: {rel}")
    src = SourceFile(Path(rel), path.read_text(encoding="utf-8", errors="replace"))
    if src.root is None:
        return Proposal(None, "구문 분석하지 못했다")
    located = _target_function(src, violation)
    if isinstance(located, str):
        return Proposal(None, located)
    node, fn_node, func = located
    text = src.text_of(fn_node)
    if re.search(r"\bdjango\b|\brequest\.(?:GET|POST)\b|\bfastapi\b", src.text):
        return Proposal(None, "Flask 계열이 아닌 요청 객체(Django·FastAPI)는 지원하지 않는다")
    params = [src.text_of(p).split(":")[0].split("=")[0].strip() for p in func.params]
    payload, benign = PAYLOADS[family]
    if REQUEST_RE.search(text):
        source = SourceSpec(kind="request")
    else:
        candidate = None
        sink_text = src.text_of(node)
        for name in params:
            if name in CURSOR_NAMES | CONNECTION_NAMES or name in ("self", "cls"):
                continue
            if re.search(rf"\b{re.escape(name)}\b", text) and (candidate is None or re.search(rf"\b{re.escape(name)}\b", sink_text)):
                candidate = name
        if candidate is None:
            return Proposal(None, "입력이 들어오는 요청 값이나 매개변수를 찾지 못했다")
        source = SourceSpec(kind="param", param=candidate)
    notes = [
        f"입력({payload!r})이 {'요청 값' if source.kind == 'request' else '매개변수 ' + source.param}으로 들어간다고 가정한다. 실제 호출 방식과 맞는지 확인하십시오.",
        "정상 대조군 입력이 실제 업무에서 쓰는 값과 비슷한지 확인하십시오. 수정이 정상 기능까지 막으면 통과하지 못합니다.",
    ]
    setup = _family_setup(family, src, node, params, notes)
    if isinstance(setup, str):
        return Proposal(None, setup)
    call_args, base = setup
    for name in params:
        if name not in call_args and not (source.kind == "param" and name == source.param) and name not in ("self", "cls"):
            notes.append(f"매개변수 {name}는 None으로 호출한다. 다른 값이 필요하면 call_args에 적으십시오.")
    expect_summary = {
        "command": "입력이 셸이 해석하는 명령 문자열에 그대로 들어가면 안 된다(인자 배열로 넘기거나 입력을 검증해야 한다).",
        "path": "접근한 경로가 허용 폴더 밖으로 나가면 안 된다(정규화 뒤 허용 폴더 안인지 확인해야 한다).",
        "sql": "입력이 SQL 문자열에 들어가면 안 된다(파라미터 바인딩을 써야 한다).",
        "ssrf": "입력이 내부망·루프백·메타데이터 주소로 향하는 요청이 되면 안 된다(허용 호스트 목록으로 검사하고 이름 풀이 뒤 주소도 확인해야 한다).",
        "xss": "입력이 HTML 출력에서 태그·실행 가능한 속성·script 내용이 되면 안 된다(출력 문맥에 맞게 이스케이프해야 한다).",
    }[family]
    spec = RegressionSpec(
        family=family,
        finding=f"{violation.rule_id}@{rel}:{violation.line_number}",
        target=TargetSpec(module=_module_name(rel), function=func.name, file=rel),
        source=source,
        input=InputSpec(payload=payload, benign=benign, variants=list(VARIANT_PAYLOADS[family])),
        expect=ExpectSpec(base=base, summary=expect_summary),
        call_args=call_args,
        fake_sink=FAKE_SINKS[family],
        review_notes=notes,
        confirmed=False,
    )
    return Proposal(spec)


def _target_function(src: SourceFile, violation: Violation) -> tuple[Node, Node, Func] | str:
    """(지적된 호출, 그 호출을 감싼 함수 노드, 함수 정보). 회귀시험으로 부를 수 없는 위치면 그 이유를 돌려준다."""
    node = None
    for n in src.nodes:
        if n.start_point[0] + 1 == violation.line_number and n.type in ("call", "expression_statement", "return_statement"):
            node = n
            break
    if node is None:
        return "지적된 줄의 호출을 찾지 못했다"
    fn_node = enclosing_function(node, src.lang)
    if fn_node is None:
        return "함수 밖의 코드는 지원하지 않는다(모듈 수준 실행)"
    func = next((f for f in iter_functions(src) if f.node.id == fn_node.id), None)
    if func is None:
        return "함수를 해석하지 못했다"
    parent = fn_node.parent
    while parent is not None:
        if parent.type == "class_definition":
            return "클래스의 메서드는 지원하지 않는다(객체 생성 조건을 알 수 없다)"
        parent = parent.parent
    if src.text_of(fn_node).lstrip().startswith("async def"):
        return "async 함수는 지원하지 않는다"
    if fn_node.parent is not None and fn_node.parent.type == "decorated_definition":
        decorators = " ".join(src.text_of(d) for d in fn_node.parent.named_children if d.type == "decorator")
        if re.search(r"fastapi|django|@(?:app|router)\.(?:get|post)\(.*\bDepends\b", decorators):
            return "Flask 계열이 아닌 프레임워크의 핸들러는 지원하지 않는다"
    return node, fn_node, func


def _family_setup(family: str, src: SourceFile, node: Node, params: list[str], notes: list[str]) -> tuple[dict[str, Any], str] | str:
    """(호출 인자, 허용 폴더). 계열마다 가짜 객체 주입과 확인할 가정을 notes에 더한다. 주입할 수 없으면 그 이유를 돌려준다."""
    call_args: dict[str, Any] = {}
    base = ""
    if family == "sql":
        for name in params:
            if name in CURSOR_NAMES:
                call_args[name] = "$cursor"
            elif name in CONNECTION_NAMES:
                call_args[name] = "$connection"
        if not call_args:
            return "SQL을 실행하는 커서·연결 객체를 매개변수로 주입할 수 없다(전역 연결 등)"
        notes.append("커서·연결 객체는 호출을 기록하는 가짜 객체로 바꿔 넣는다. 실제 DB에는 접속하지 않는다.")
    if family == "path":
        base = _literal_base(src.text_of(node))
        notes.append(f"접근해도 되는 폴더(expect.base)를 {'`' + base + '`' if base else '임시 기준 폴더'}로 가정한다. 맞는지 확인하십시오.")
    if family == "ssrf":
        notes.append("실제 네트워크에는 접속하지 않는다. requests·httpx·urllib 호출은 요청 URL만 기록하고, 이름 풀이는 IP 문자열·localhost 외에는 공개 주소 하나로 돌려주는 대역이다.")
        notes.append("요청해도 되는 호스트가 정해져 있으면 expect.allowed_hosts에 적고, 정상 대조군 입력(input.benign)을 그 호스트의 주소로 바꾸십시오.")
    if family == "xss":
        notes.append("HTML 출력은 함수 반환값과 flask.Response·make_response·render_template_string 호출에서 읽는다. Jinja 템플릿 파일(render_template)의 자동 이스케이프는 시험하지 않는다.")
        notes.append("입력이 다른 문맥(JavaScript 문자열, URL 쿼리)에 들어가는 코드는 이 시험이 결함을 재현하지 못할 수 있다. 그 경우 원본에서 재현되지 않아 근거로 쓰이지 않는다.")
    if family == "command":
        notes.append("실제 셸은 실행하지 않는다. os.system·subprocess 호출은 기록만 하며, 셸이 해석하는 문자열에 입력이 그대로 들어가면 결함으로 본다.")
    return call_args, base
