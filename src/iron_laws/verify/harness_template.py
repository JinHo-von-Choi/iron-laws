"""
오철칙 회귀시험 harness: 격리 환경 안에서 후보·원본 코드를 부르고, 실제 명령·파일·DB 대신 기록 장치(mock sink)로 관측한다
이 파일의 HARNESS_SOURCE는 신뢰된 도구 코드다. 검증할 때마다 작업영역에 복사해 `python -B harness.py spec.json attack|benign`으로 실행한다.
- 실제 셸·네트워크·작업영역 밖 파일 접근은 하지 않는다. 호출은 기록만 하고 가짜 결과를 돌려준다.
- 결과는 `IRON_LAWS_RESULT <봉인값> {json}` 줄로 낸다. 봉인값은 실행마다 도구가 새로 만들어 기준 폴더의 seal 파일로 건네며,
  harness가 후보 코드를 불러오기 전에 읽고 지운다. 출력 함수(os.write)와 종료 함수도 그 전에 잡아 둔다.
  후보 코드가 결과 줄을 흉내 내거나 sys.stdout·os.write를 바꿔도 봉인값이 없어 도구가 받아들이지 않는다(판정 불가로 끝난다).
- 명령 실행 계열은 판정 전에 공격 입력 끝에 카나리아 명령(probe 파일의 값으로 만든 파일 생성)을 붙여 한 번 따로 부른다.
  후보 코드가 기록 장치를 거치지 않고 실제 셸을 부르면 카나리아 파일이 생기고, 도구가 실행이 끝난 뒤 밖에서 확인해 결함 재현으로 판정한다.
  판정 자체는 원래 공격 입력으로 한다.
- 기록 장치는 저수준 경로(posix.system, os.open·posix.open, io.FileIO, _io.open, sqlite3.dbapi2·_sqlite3)에도 건다.
- 같은 프로세스의 메모리를 뒤져 봉인값을 꺼내거나 ctypes로 시스템 호출을 직접 부르는 의도적인 조작까지는 막지 못한다.
작성자: 최진호
작성일: 2026-10-04
"""
# iron-laws: ignore-file[ARC-201] 파일 대부분이 격리 환경에 복사해 실행하는 harness 원문 문자열(HARNESS_SOURCE)이다

HARNESS_SOURCE = r'''
import builtins
import html.parser as html_parser
import importlib
import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
import types

def _seal():
    base = os.path.join(os.getcwd(), "_iron_laws_harness", "base")
    values = []
    for name in ("seal", "probe"):
        path = os.path.join(base, name)
        try:
            with open(path, encoding="utf-8") as handle:
                values.append(handle.read().strip())
            os.remove(path)
        except OSError:
            values.append("")
    write, finish, dumps = os.write, os._exit, json.dumps
    seal = values[0]

    def sealed(payload):
        write(1, ("\nIRON_LAWS_RESULT " + seal + " " + dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
        finish(0)

    return sealed, values[1], base


_SEALED_EMIT, PROBE, PROBE_BASE = _seal()
SPEC_PATH, RAW_MODE = sys.argv[1], sys.argv[2]
MODE, _, VARIANT = RAW_MODE.partition(":")  # `attack:2`는 명세의 변형 입력 2번으로 공격한다
with open(SPEC_PATH, encoding="utf-8") as handle:
    SPEC = json.load(handle)
ROOT = os.getcwd()
HARNESS_DIR = os.path.join(ROOT, "_iron_laws_harness")
BASE = os.path.join(HARNESS_DIR, "base")
os.makedirs(BASE, exist_ok=True)
sys.path.insert(0, ROOT)

FAMILY = SPEC["family"]
if MODE == "attack" and VARIANT:
    VALUE = SPEC["input"].get("variants", [])[int(VARIANT) - 1]
else:
    VALUE = SPEC["input"]["payload"] if MODE == "attack" else SPEC["input"]["benign"]
CALLS = []
URLS = []
HTMLS = []
XSS_TOKEN = "IL_XSS"
real_open = builtins.open


def emit(outcome, reason="", **extra):
    payload = {"outcome": outcome, "reason": reason, "mode": RAW_MODE, "calls": CALLS[:20]}
    payload.update(extra)
    _SEALED_EMIT(payload)


class Part(dict):
    def __init__(self, holder):
        super().__init__()
        self._holder = holder

    def __getitem__(self, key):
        return self._holder["value"]

    def __contains__(self, key):
        return True

    def get(self, key=None, default=None, type=None):
        return self._holder["value"]

    def getlist(self, key=None):
        return [self._holder["value"]]

    def to_dict(self):
        return {}


class FakeRequest:
    """flask.request 대역: 어떤 키로 읽어도 시험 입력이 나온다."""

    def __init__(self):
        self._holder = {"value": ""}
        self.args = Part(self._holder)
        self.form = Part(self._holder)
        self.values = Part(self._holder)
        self.cookies = Part(self._holder)
        self.headers = Part(self._holder)
        self.json = Part(self._holder)
        self.method = "GET"
        self.files = {}
        self.url = "http://harness.invalid/"
        self.path = "/"
        self.remote_addr = "127.0.0.1"

    def set(self, value):
        self._holder["value"] = value

    def get_json(self, *a, **k):
        return self.json

    def get_data(self, *a, **k):
        return self._holder["value"]

    @property
    def data(self):
        return self._holder["value"]


REQUEST = FakeRequest()
REQUEST.set(VALUE)


def passthrough_decorator(*a, **k):
    if len(a) == 1 and callable(a[0]) and not k:
        return a[0]
    return lambda fn: fn


class FakeApp:
    def __init__(self, *a, **k):
        self.config = {}

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return passthrough_decorator


def fake_abort(code=400, *a, **k):
    raise RuntimeError("abort " + str(code))


flask = types.ModuleType("flask")
flask.request = REQUEST
flask.Flask = FakeApp
flask.Blueprint = FakeApp
flask.abort = fake_abort
flask.jsonify = lambda *a, **k: (a, k)
flask.render_template = lambda *a, **k: ""
flask.redirect = lambda *a, **k: ""
flask.make_response = lambda *a, **k: ""
flask.send_file = lambda *a, **k: ""
flask.send_from_directory = lambda *a, **k: ""
flask.session = {}
flask.g = types.SimpleNamespace()
flask.current_app = FakeApp()
flask.Response = lambda *a, **k: ""
sys.modules["flask"] = flask


class FakeCursor:
    rowcount = 0
    lastrowid = 1
    description = None

    def execute(self, sql, params=None, *a, **k):
        CALLS.append({"api": "cursor.execute", "sql": str(sql), "params": repr(params)[:200]})
        return self

    def executemany(self, sql, seq=None, *a, **k):
        CALLS.append({"api": "cursor.executemany", "sql": str(sql), "params": "(many)"})
        return self

    def executescript(self, sql):
        CALLS.append({"api": "cursor.executescript", "sql": str(sql), "params": ""})
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []

    def fetchmany(self, *a):
        return []

    def close(self):
        return None

    def __iter__(self):
        return iter(())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConnection(FakeCursor):
    def cursor(self, *a, **k):
        return FakeCursor()

    def commit(self):
        return None

    def rollback(self):
        return None


def resolve_path(path):
    try:
        return os.path.abspath(os.path.join(os.getcwd(), os.fspath(path)))
    except TypeError:
        return str(path)


def install_sinks():
    if FAMILY == "command":
        shells = ("sh", "bash", "zsh", "dash", "ksh")

        def interpreted(api, args, kwargs):
            first = args[0] if args else kwargs.get("args", "")
            if api in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"):
                return True, str(first)
            if kwargs.get("shell"):
                return True, first if isinstance(first, str) else " ".join(map(str, first))
            if isinstance(first, (list, tuple)):
                names = [os.path.basename(str(x)) for x in first[:1]]
                if names and names[0] in shells and "-c" in [str(x) for x in first]:
                    return True, " ".join(map(str, first))
                return False, " ".join(map(str, first))
            return True, str(first)  # 문자열 하나를 그대로 실행하려는 호출

        def make(api, result):
            def recorder(*args, **kwargs):
                shell, text = interpreted(api, args, kwargs)
                CALLS.append({"api": api, "interpreted": shell, "command": str(text)[:300]})
                return result()
            return recorder

        completed = lambda: types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"", args=[])

        class FakePopen:
            returncode = 0
            def __init__(self, *args, **kwargs):
                shell, text = interpreted("subprocess.Popen", args, kwargs)
                CALLS.append({"api": "subprocess.Popen", "interpreted": shell, "command": str(text)[:300]})
                self.stdout = io.BytesIO(b"")
                self.stderr = io.BytesIO(b"")
            def communicate(self, *a, **k):
                return b"", b""
            def wait(self, *a, **k):
                return 0
            def poll(self):
                return 0
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        os.system = make("os.system", lambda: 0)
        os.popen = make("os.popen", lambda: io.StringIO(""))
        import posix
        posix.system = make("os.system", lambda: 0)  # os.system의 원래 구현. 우회 경로도 기록한다
        subprocess.run = make("subprocess.run", completed)
        subprocess.call = make("subprocess.call", lambda: 0)
        subprocess.check_call = make("subprocess.check_call", lambda: 0)
        subprocess.check_output = make("subprocess.check_output", lambda: b"")
        subprocess.getoutput = make("subprocess.getoutput", lambda: "")
        subprocess.getstatusoutput = make("subprocess.getstatusoutput", lambda: (0, ""))
        subprocess.Popen = FakePopen
    elif FAMILY == "path":
        def fake_open(file, mode="r", *a, **k):
            if not isinstance(file, int):  # 파일 기술자(os.fdopen)는 os.open에서 이미 경로를 기록했다
                CALLS.append({"api": "open", "path": resolve_path(file), "mode": str(mode)})
            return io.BytesIO(b"") if "b" in str(mode) else io.StringIO("")

        import _io
        import pathlib
        import posix

        builtins.open = fake_open
        io.open = fake_open
        _io.open = fake_open  # 모듈 불러오기는 _io.open_code·_io.FileIO를 쓰므로 영향이 없다

        def fake_fileio(file, mode="r", *a, **k):
            return fake_open(file, mode if "b" in str(mode) else str(mode) + "b")

        io.FileIO = fake_fileio

        real_os_open = os.open
        handle, empty_file = tempfile.mkstemp(prefix="iron-laws-empty-")  # 실행마다 새로 만든다(작업 폴더에 남기지 않는다)
        os.close(handle)

        def fake_os_open(path, flags=0, *a, **k):
            CALLS.append({"api": "os.open", "path": resolve_path(path), "mode": str(flags)})
            return real_os_open(empty_file, os.O_RDONLY)  # 실제 파일 대신 빈 일반 파일을 연다

        os.open = fake_os_open
        posix.open = fake_os_open

        def path_method(name, result):
            def method(self, *a, **k):
                CALLS.append({"api": "pathlib.Path." + name, "path": resolve_path(self)})
                return result()
            return method

        pathlib.Path.open = lambda self, mode="r", *a, **k: fake_open(self, mode)
        pathlib.Path.read_text = path_method("read_text", lambda: "")
        pathlib.Path.read_bytes = path_method("read_bytes", lambda: b"")
        pathlib.Path.write_text = path_method("write_text", lambda: 0)
        pathlib.Path.write_bytes = path_method("write_bytes", lambda: 0)

        def os_function(name, result):
            def function(path, *a, **k):
                CALLS.append({"api": "os." + name, "path": resolve_path(path)})
                return result()
            return function

        for name, result in (("remove", lambda: None), ("unlink", lambda: None), ("listdir", lambda: []), ("makedirs", lambda: None), ("mkdir", lambda: None), ("rmdir", lambda: None), ("stat", lambda: os.stat_result((0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0)))):
            setattr(os, name, os_function(name, result))
        os.chdir(BASE)
    elif FAMILY == "ssrf":
        install_http_sinks()
    elif FAMILY == "xss":
        install_html_sinks()
    elif FAMILY == "sql":
        import sqlite3
        import sqlite3.dbapi2

        sqlite3.connect = lambda *a, **k: FakeConnection()
        sqlite3.dbapi2.connect = sqlite3.connect
        try:
            import _sqlite3

            _sqlite3.connect = sqlite3.connect
        except ImportError:
            pass


class FakeHttpResponse:
    status_code = 200
    status = 200
    ok = True
    text = ""
    content = b""
    reason = "OK"
    encoding = "utf-8"

    def __init__(self, url=""):
        self.url = url
        self.headers = {}
        self.history = []

    def json(self, *a, **k):
        return {}

    def raise_for_status(self):
        return None

    def iter_content(self, *a, **k):
        return iter(())

    def iter_bytes(self, *a, **k):
        return iter(())

    def read(self, *a, **k):
        return b""

    def getcode(self):
        return 200

    def info(self):
        return self.headers

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def record_http(api, method, url):
    text = getattr(url, "full_url", url)
    CALLS.append({"api": api, "method": method, "url": str(text)[:300]})
    URLS.append(str(text))
    return FakeHttpResponse(str(text))


def install_http_sinks():
    """requests·httpx·urllib 호출을 기록만 하는 대역으로 바꾼다. 실제 네트워크에는 접속하지 않는다.
    이름 풀이도 대역이다: IP 문자열은 그대로, localhost는 127.0.0.1, 그 밖의 이름은 공개 주소 하나로 돌려준다."""
    import socket
    import urllib.request

    verbs = ("get", "post", "put", "patch", "delete", "head", "options")

    def module_functions(name):
        namespace = {}
        for verb in verbs:
            namespace[verb] = (lambda api, v: lambda *a, **k: record_http(api, v.upper(), a[0] if a else k.get("url", "")))(name + "." + verb, verb)
        namespace["request"] = lambda method, url=None, *a, **k: record_http(name + ".request", str(method).upper(), url if url is not None else (a[0] if a else k.get("url", "")))
        return namespace

    def session_class(name):
        def make_method(verb):
            return lambda self, *a, **k: record_http(name + "." + verb, verb.upper(), a[0] if a else k.get("url", ""))

        members = {verb: make_method(verb) for verb in verbs}
        members["request"] = lambda self, method, url=None, *a, **k: record_http(name + ".request", str(method).upper(), url if url is not None else (a[0] if a else k.get("url", "")))
        members["__init__"] = lambda self, *a, **k: None
        members["__enter__"] = lambda self: self
        members["__exit__"] = lambda self, *a: False
        members["close"] = lambda self: None
        return type("Fake" + name.title() + "Session", (), members)

    class RequestError(Exception):
        pass

    for module_name, session_names in (("requests", ("Session",)), ("httpx", ("Client",))):
        fake = types.ModuleType(module_name)
        for key, value in module_functions(module_name).items():
            setattr(fake, key, value)
        for session_name in session_names:
            setattr(fake, session_name, session_class(module_name))
        fake.RequestException = fake.HTTPError = fake.ConnectionError = fake.Timeout = fake.RequestError = RequestError
        fake.exceptions = types.SimpleNamespace(RequestException=RequestError, HTTPError=RequestError, ConnectionError=RequestError, Timeout=RequestError)
        fake.codes = types.SimpleNamespace(ok=200)
        sys.modules[module_name] = fake
    urllib.request.urlopen = lambda url, *a, **k: record_http("urllib.request.urlopen", "GET", url)

    def resolve(host, ipv4_only=False):
        text = str(host or "")
        if text == "localhost":
            return "127.0.0.1"
        if ":" in text:
            if ipv4_only:
                raise socket.gaierror(-2, "Name or service not known")
            return text
        try:
            socket.inet_aton(text)
            return text
        except OSError:
            return "93.184.216.34"

    socket.gethostbyname = lambda host: resolve(host, True)
    socket.getaddrinfo = lambda host, port=None, *a, **k: [(socket.AF_INET6 if ":" in str(host) else socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolve(host), port or 0))]


def internal_host(host):
    """내부망·루프백·링크 로컬(클라우드 메타데이터)·예약 주소인가. `127.1`·`0x7f.0.0.1`·`2130706433` 같은 축약 표기도 같은 주소로 본다."""
    import ipaddress
    import socket

    name = host.lower().rstrip(".")
    if not name:
        return False
    if name == "localhost" or name.endswith((".localhost", ".internal", ".local")):
        return True
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(name))
        except OSError:
            return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast


def http_violation():
    from urllib.parse import urlsplit

    allowed = [h.lower() for h in SPEC["expect"].get("allowed_hosts", [])]
    for url in URLS:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            return "URL을 해석할 수 없는 값으로 요청했다: " + url[:120]
        if allowed and host and host not in allowed:
            return "허용 목록에 없는 호스트로 요청했다: " + host
        if not allowed and internal_host(host):
            return "내부망·루프백·메타데이터 주소로 요청했다: " + host
    return ""


def text_of_html(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    if isinstance(value, tuple) and value:
        return text_of_html(value[0])
    return ""


def record_html(api, value):
    text = text_of_html(value)
    if text:
        CALLS.append({"api": api, "html": text[:300]})
        HTMLS.append(text[:20000])


def install_html_sinks():
    """flask 응답 생성 함수의 출력 문자열을 기록한다. 반환값도 main()에서 같이 기록한다."""
    import html as html_module

    def response(body="", *a, **k):
        record_html("flask.Response", body)
        return body

    def make_response(body="", *a, **k):
        record_html("flask.make_response", body)
        return body

    def render_template_string(source="", *a, **k):
        record_html("flask.render_template_string", source)  # 템플릿 원문에 입력이 섞이면 이스케이프가 적용되지 않는다
        return ""

    flask.Response = response
    flask.make_response = make_response
    flask.render_template_string = render_template_string
    try:
        import markupsafe  # noqa: F401
    except ImportError:
        class Markup(str):
            @classmethod
            def escape(cls, value):
                return cls(html_module.escape(str(value), quote=True))

        fake = types.ModuleType("markupsafe")
        fake.Markup = Markup
        fake.escape = Markup.escape
        sys.modules["markupsafe"] = fake
        flask.Markup = Markup
        flask.escape = Markup.escape


class _TagCollector(html_parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.dangerous = ""
        self._script = False

    def handle_starttag(self, tag, attrs):
        if XSS_TOKEN in tag:
            self.dangerous = "입력이 태그 이름이 되었다: " + tag[:60]
        self._script = tag == "script"
        for name, value in attrs:
            lowered, text = (name or "").lower(), (value or "")
            if XSS_TOKEN in name or (XSS_TOKEN in text and (lowered.startswith("on") or lowered == "srcdoc" or text.strip().lower().startswith("javascript:"))):
                self.dangerous = "입력이 태그 속성(" + lowered[:30] + ")으로 실행 가능한 위치에 들어갔다"

    def handle_endtag(self, tag):
        self._script = False

    def handle_data(self, data):
        if self._script and XSS_TOKEN in data:
            self.dangerous = "입력이 script 요소 안에 그대로 들어갔다"


def html_violation():
    for text in HTMLS:
        collector = _TagCollector()
        try:
            collector.feed(text)
            collector.close()
        except Exception:
            continue
        if collector.dangerous:
            return collector.dangerous
    return ""


def build_arguments(function):
    values = {}
    markers = {"$cursor": FakeCursor, "$connection": FakeConnection}
    call_args = SPEC.get("call_args", {})
    source = SPEC["source"]
    names = list(inspect.signature(function).parameters)
    for name in names:
        if source["kind"] == "param" and name == source["param"]:
            values[name] = VALUE
        elif name in call_args:
            raw = call_args[name]
            values[name] = markers[raw]() if isinstance(raw, str) and raw in markers else raw
        else:
            parameter = inspect.signature(function).parameters[name]
            if parameter.default is inspect.Parameter.empty and parameter.kind in (parameter.POSITIONAL_OR_KEYWORD, parameter.KEYWORD_ONLY):
                values[name] = None
    return values


def probe_bypass(function):
    """공격 입력 끝에 카나리아 명령을 붙여 한 번 따로 부른다. 기록 장치를 우회해 실제 셸이 실행하면 카나리아 파일이 생기고,
    도구가 실행이 끝난 뒤 밖에서 확인한다. 이 호출의 기록은 판정에 쓰지 않는다(판정은 원래 공격 입력으로 한다)."""
    global VALUE
    attack = VALUE
    VALUE = attack + "; touch " + os.path.join(PROBE_BASE, "canary_" + PROBE)
    REQUEST.set(VALUE)
    try:
        function(**build_arguments(function))
    except BaseException:
        pass
    del CALLS[:]
    VALUE = attack
    REQUEST.set(VALUE)


def probe_base(function):
    """명세에 허용 폴더가 없으면 같은 코드에 정상 입력을 먼저 넣어 접근한 폴더를 허용 폴더로 본다(코드가 정한 기준 폴더)."""
    global VALUE
    attack = VALUE
    VALUE = SPEC["input"]["benign"]
    REQUEST.set(VALUE)
    try:
        function(**build_arguments(function))
    except BaseException:
        pass
    paths = [call["path"] for call in CALLS if call.get("path")]
    del CALLS[:]
    VALUE = attack
    REQUEST.set(VALUE)
    return os.path.dirname(paths[0]) if paths else None


def main():
    target = SPEC["target"]
    if FAMILY in ("ssrf", "xss"):
        install_sinks()  # `from requests import get`·`from flask import Response`가 대역을 가리키도록 불러오기 전에 설치한다
    try:
        module = importlib.import_module(target["module"])
        function = getattr(module, target["function"])
    except BaseException as error:
        emit("error", "import_error: " + type(error).__name__ + ": " + str(error)[:160])
    for name, raw in SPEC.get("fake_globals", {}).items():
        markers = {"$cursor": FakeCursor, "$connection": FakeConnection}
        setattr(module, name, markers[raw]() if raw in markers else raw)
    if SPEC["source"]["kind"] == "request":
        if hasattr(module, "request"):
            module.request = REQUEST
    if FAMILY not in ("ssrf", "xss"):
        install_sinks()
    if MODE == "attack" and FAMILY == "command" and PROBE:
        probe_bypass(function)
    allowed = tuple(SPEC.get("allowed_exceptions", ["ValueError", "PermissionError", "RuntimeError"]))
    observed_base = probe_base(function) if FAMILY == "path" and MODE == "attack" and not SPEC["expect"].get("base") else None
    error_name = ""
    try:
        returned = function(**build_arguments(function))
        if FAMILY == "xss":
            record_html("return", returned)
    except BaseException as error:
        error_name = type(error).__name__
        if error_name not in allowed:
            emit("error", "exception: " + error_name + ": " + str(error)[:160], sink_calls=len(CALLS))
    violation = ""
    if MODE == "attack" and FAMILY == "ssrf":
        violation = http_violation()
    elif MODE == "attack" and FAMILY == "xss":
        violation = html_violation()
    if MODE == "attack":
        for call in CALLS:
            if FAMILY == "command" and call.get("interpreted") and VALUE in call.get("command", ""):
                violation = "입력이 셸이 해석하는 명령 문자열에 그대로 들어갔다: " + call["api"]
            elif FAMILY == "path":
                base = os.path.abspath(SPEC["expect"].get("base") or observed_base or BASE)
                resolved = call.get("path", "")
                if resolved != base and not resolved.startswith(base + os.sep):
                    violation = "접근한 경로가 허용 폴더 밖이다: " + resolved
            elif FAMILY == "sql" and VALUE in call.get("sql", ""):
                violation = "입력이 SQL 문자열에 그대로 들어갔다(바인딩되지 않았다)"
            if violation:
                break
        if violation:
            emit("defect_reproduced", violation, sink_calls=len(CALLS), exception=error_name)
        emit("passed", "입력이 위험한 방식으로 싱크에 닿지 않았다", sink_calls=len(CALLS), exception=error_name)
    # 정상 입력: 막히지 않고 싱크까지 도달해야 한다
    if error_name or not CALLS:
        emit("control_failed", "정상 입력이 막혔거나 싱크에 닿지 않았다" + (": " + error_name if error_name else ""), sink_calls=len(CALLS), exception=error_name)
    emit("passed", "정상 입력이 싱크에 닿았다", sink_calls=len(CALLS))


main()
'''
