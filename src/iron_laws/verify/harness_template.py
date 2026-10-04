"""
오철칙 회귀시험 harness: 격리 환경 안에서 후보·원본 코드를 부르고, 실제 명령·파일·DB 대신 기록 장치(mock sink)로 관측한다
이 파일의 HARNESS_SOURCE는 신뢰된 도구 코드다. 검증할 때마다 작업영역에 복사해 `python -B harness.py spec.json attack|benign`으로 실행한다.
- 실제 셸·네트워크·작업영역 밖 파일 접근은 하지 않는다. 호출은 기록만 하고 가짜 결과를 돌려준다.
- 결과는 마지막 줄 `IRON_LAWS_RESULT {json}`으로 낸다. 오직 도구의 평가 코드만 이 줄을 쓴다.
- 후보 코드가 같은 프로세스 안에서 결과를 조작하는 것까지 막지 못한다. 이 한계는 문서에 밝혀 둔다.
작성자: 최진호
작성일: 2026-10-04
"""

HARNESS_SOURCE = r'''
import builtins
import importlib
import io
import json
import os
import subprocess
import sys
import types

SPEC_PATH, MODE = sys.argv[1], sys.argv[2]
with open(SPEC_PATH, encoding="utf-8") as handle:
    SPEC = json.load(handle)
ROOT = os.getcwd()
HARNESS_DIR = os.path.join(ROOT, "_iron_laws_harness")
BASE = os.path.join(HARNESS_DIR, "base")
os.makedirs(BASE, exist_ok=True)
sys.path.insert(0, ROOT)

FAMILY = SPEC["family"]
VALUE = SPEC["input"]["payload"] if MODE == "attack" else SPEC["input"]["benign"]
CALLS = []
real_open = builtins.open


def emit(outcome, reason="", **extra):
    payload = {"outcome": outcome, "reason": reason, "mode": MODE, "calls": CALLS[:20]}
    payload.update(extra)
    sys.stdout.write("\nIRON_LAWS_RESULT " + json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()
    os._exit(0)


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
        subprocess.run = make("subprocess.run", completed)
        subprocess.call = make("subprocess.call", lambda: 0)
        subprocess.check_call = make("subprocess.check_call", lambda: 0)
        subprocess.check_output = make("subprocess.check_output", lambda: b"")
        subprocess.getoutput = make("subprocess.getoutput", lambda: "")
        subprocess.getstatusoutput = make("subprocess.getstatusoutput", lambda: (0, ""))
        subprocess.Popen = FakePopen
    elif FAMILY == "path":
        def fake_open(file, mode="r", *a, **k):
            CALLS.append({"api": "open", "path": resolve_path(file), "mode": str(mode)})
            return io.BytesIO(b"") if "b" in str(mode) else io.StringIO("")

        builtins.open = fake_open
        io.open = fake_open
        import pathlib

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

        for name, result in (("remove", lambda: None), ("unlink", lambda: None), ("listdir", lambda: []), ("makedirs", lambda: None), ("mkdir", lambda: None), ("rmdir", lambda: None), ("stat", lambda: None)):
            setattr(os, name, os_function(name, result))
        os.chdir(BASE)
    elif FAMILY == "sql":
        import sqlite3
        sqlite3.connect = lambda *a, **k: FakeConnection()


def build_arguments(function):
    import inspect

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


def main():
    target = SPEC["target"]
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
    install_sinks()
    allowed = tuple(SPEC.get("allowed_exceptions", ["ValueError", "PermissionError", "RuntimeError"]))
    error_name = ""
    try:
        function(**build_arguments(function))
    except BaseException as error:
        error_name = type(error).__name__
        if error_name not in allowed:
            emit("error", "exception: " + error_name + ": " + str(error)[:160], sink_calls=len(CALLS))
    violation = ""
    if MODE == "attack":
        for call in CALLS:
            if FAMILY == "command" and call.get("interpreted") and VALUE in call.get("command", ""):
                violation = "입력이 셸이 해석하는 명령 문자열에 그대로 들어갔다: " + call["api"]
            elif FAMILY == "path":
                base = os.path.abspath(SPEC["expect"].get("base") or BASE)
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
