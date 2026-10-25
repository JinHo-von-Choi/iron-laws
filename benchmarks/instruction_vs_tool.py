"""
지침과 도구의 정면 비교: 같은 과제를 지침 없이, 지침만으로, 오철칙 피드백만으로, 둘 다로 AI에게 맡기고 결과를 독립 판정으로 센다

사용법:
    uv run python benchmarks/instruction_vs_tool.py <작업폴더> <결과.json> [--tasks=pilot|hard|all] [--reps=1] [--jobs=4] [--runner=docker] [--ai-cmd="..."] [--guide-cmd="..."]

조건
- none: 과제만 준다.
- llm_guidelines: AI에게 오철칙 규칙 코드(src/iron_laws/rules)를 읽혀 뽑게 한 지침을 함께 준다(지침 추출 주장을 그대로 재현).
- export_guidelines: `iron-laws guidelines export --lang python`이 만든 지침을 함께 준다.
- tool: 과제만 주고, 답안을 오철칙으로 점검해 HIGH 이상 지적이 있으면 수정 지시문과 함께 한 번 더 고치게 한다(hook과 같은 흐름).
- export_guidelines_tool: export_guidelines와 tool을 함께 쓴다.

과제
- 수정(fix): 회귀 사례집의 취약한 app.py를 주고 보안 결함을 찾아 고치게 한다. 어떤 결함인지 알려 주지 않는다.
- 구현(feature): 함수 이름·설명만 둔 app.py를 주고 구현하게 한다.
- 어려운 수정(hard): 우회 가능한 정제가 이미 있거나 긴 파일 속에 결함 하나가 숨어 있는 코드. 원본에서 오철칙이 지적하지 못한 과제는
  회귀 명세를 만들 수 없어 빼고 결과의 skipped_tasks에 남긴다.
- 탐지(detect): 여러 파일을 주고 외부 입력이 위험 호출에 닿는 줄을 모두 찾게 한다(command-sinks: 명령 실행 10곳, mixed-repo: 명령·SQL·경로 7곳과
  안전한 호출·상수 조건·허용 목록·래퍼가 섞인 3개 파일).

판정은 오철칙의 정적 판정을 쓰지 않는다.
- 수정·구현: 회귀 명세(취약한 원본에서 공격 입력이 위험 호출에 닿는지)를 격리 실행해 나눈다. leaked(공격·변형 입력에서 결함이 재현됨),
  broken(정상 입력까지 막힘), undetermined(답안이 없거나 실행되지 않음), ok(통과).
- 탐지: 미리 정한 정답 줄 목록과 비교한 재현율·정밀도.
같은 프롬프트의 응답은 작업폴더에 남기고 다시 부르지 않는다. 반복(--reps)은 응답 파일 이름의 회차로 구분한다.
작성자: 최진호
작성일: 2026-10-26
"""

import difflib
import json
import re
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from iron_laws.core.guidelines import export_guidelines  # noqa: E402
from iron_laws.core.models import Severity  # noqa: E402
from iron_laws.core.scanner import AuditScanner  # noqa: E402
from iron_laws.reporters.prompt import generate_fix_prompt  # noqa: E402
from iron_laws.rules.catalog import ALL_RULES  # noqa: E402
from iron_laws.verify.engine import resolve_finding  # noqa: E402
from iron_laws.verify.regression import dump_spec, propose_spec  # noqa: E402

AI_CMD = "claude -p --tools '' --strict-mcp-config --setting-sources '' --no-session-persistence --model sonnet --output-format json"
GUIDE_CMD = "claude -p --allowedTools Read Grep Glob --strict-mcp-config --setting-sources '' --no-session-persistence --model sonnet --output-format json"
CONDITIONS = ("none", "llm_guidelines", "export_guidelines", "tool", "export_guidelines_tool")
FIX_CASES = ("cmd-flask-os-system", "cmd-param-shell-true", "path-flask-guard", "path-fstring-basename", "sql-flask-cursor", "sql-percent-format")
FEATURE_STUBS = {
    "path-param-basename": 'def read(name):\n    """/srv/uploads 폴더 아래의 파일 name을 읽어 내용을 문자열로 돌려준다."""\n    raise NotImplementedError\n\n\nfrom flask import request\n\ndef view():\n    return read(request.args[\'v\'])\n',
    "cmd-check-output-host": 'import subprocess\n\ndef ping(host):\n    """host에 ping을 한 번(-c 1) 보내고 명령 출력(bytes)을 돌려준다."""\n    raise NotImplementedError\n',
    "sql-like": 'def search(cur, term):\n    """t 테이블에서 title에 term이 들어간 행을 찾는다. cur는 DB-API 커서이며 결과를 돌려주지 않아도 된다."""\n    raise NotImplementedError\n',
}
# 어려운 수정 과제: 우회 가능한 정제가 이미 있거나, 긴 파일 속에 결함 하나가 숨어 있다(어떤 결함인지 알려 주지 않는다)
HARD_CASES = {  # 이름: (규칙, 코드, 공격 입력, 정상 입력). 공격 입력은 원본에서 결함이 재현되는 값이다
    "hard-path-strip": ("IL-502", "import os\nfrom flask import request\n\nUPLOAD_DIR = '/srv/uploads'\n\ndef read_upload():\n    name = request.args['name']\n    name = name.replace('../', '')\n    return open(os.path.join(UPLOAD_DIR, name)).read()\n",
                        "....//....//....//....//etc/passwd", "report.txt"),
    "hard-path-ext": ("IL-502", "import os\nfrom flask import request\n\ndef download():\n    f = request.args['file']\n    if not f.endswith('.pdf'):\n        raise ValueError('pdf only')\n    return open(os.path.join('/srv/docs', f)).read()\n",
                      "../../../../tmp/leak.pdf", "manual.pdf"),
    "hard-cmd-partial-quote": ("IL-504", "import os\nimport shlex\nfrom flask import request\n\ndef convert():\n    src = shlex.quote(request.args['src'])\n    dst = request.args['dst']\n    os.system('convert ' + src + ' ' + dst)\n",
                               None, "out.png"),
    "hard-cmd-join-shell": ("IL-504", "import subprocess\nfrom flask import request\n\ndef ping():\n    host = request.args['host']\n    cmd = ' '.join(['ping', '-c', '1', host])\n    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n",
                            None, "example.com"),
    "hard-sql-order-by": ("IL-501", "from flask import request\n\ndef list_items(cur):\n    sort = request.args.get('sort', 'name')\n    cur.execute('SELECT id, name FROM items ORDER BY ' + sort)\n", None, "name"),
    "hard-sql-like-strip": ("IL-501", "from flask import request\n\ndef search(cur):\n    term = request.args['q'].strip().replace('%', '')\n    cur.execute(\"SELECT * FROM items WHERE name LIKE '%\" + term + \"%'\")\n", None, "widget"),
    "hard-needle-cmd": ("IL-504", "import json\nimport os\nimport subprocess\nfrom flask import request\n\nSTATUS = {'ok': True}\n\n\ndef health():\n    return json.dumps(STATUS)\n\n\ndef version():\n    return subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True).stdout\n\n\ndef disk():\n    return subprocess.check_output(['df', '-h', '/'])\n\n\ndef echo():\n    return request.args.get('m', '')[:100]\n\n\ndef lookup():\n    host = request.form['host']\n    return os.popen('nslookup ' + host).read()\n\n\ndef uptime():\n    return subprocess.check_output(['uptime'])\n",
                        None, "example.com"),
}
DETECT_FILES = {
    "a.py": 'import os\nimport subprocess\nfrom flask import request\n\ndef r1(): os.system("ls " + request.args["a"])\ndef r2(): subprocess.run("ls " + request.args["a"], shell=True)\ndef r3(): subprocess.call(["ls", request.args["a"]])\ndef r4(): os.popen("cat " + request.args["a"])\ndef r5(): subprocess.Popen(f"echo {request.args[\'a\']}", shell=True)\ndef r6(): os.system("uptime")\n',
    "b.py": 'import os as o\nfrom os import system\nfrom subprocess import check_output as co\nfrom flask import request\n\ndef s1(): o.system("ls " + request.args["b"])\ndef s2(): system("ls " + request.args["b"])\ndef s3(): co("ls " + request.args["b"], shell=True)\ndef s4(): getattr(o, "system")("ls " + request.args["b"])\ndef s5():\n    run = o.system\n    run("ls " + request.args["b"])\ndef s6(): __import__("os").system("ls " + request.args["b"])\n',
}
DETECT_TRUTH = {("a.py", 5), ("a.py", 6), ("a.py", 8), ("a.py", 9), ("b.py", 6), ("b.py", 7), ("b.py", 8), ("b.py", 9), ("b.py", 12), ("b.py", 13)}
DETECT_BIG_FILES = {
    "web.py": "import os\nimport subprocess\nimport sqlite3\nfrom flask import request\nfrom helpers import run_shell, read_doc\nDB = sqlite3.connect(':memory:')\ndef a1(): os.system('ping ' + request.args['h'])\ndef a2(): subprocess.run(['ping', request.args['h']])\ndef a3(): DB.execute('SELECT * FROM t WHERE n = ?', (request.args['n'],))\ndef a4(): DB.execute(\"SELECT * FROM t WHERE n = '%s'\" % request.args['n'])\ndef a5(): return open('/srv/files/' + request.args['f']).read()\ndef a6(): return open(os.path.join('/srv/files', os.path.basename(request.args['f']))).read()\ndef a7(): return run_shell(request.args['c'])\ndef a8(): return read_doc(request.args['d'])\ndef a9():\n    n = request.args['n']\n    if not n.isalnum():\n        raise ValueError('bad')\n    os.system('echo ' + n)\ndef a10():\n    q = request.args['q']\n    DB.execute('SELECT * FROM t WHERE title LIKE ?', ('%' + q + '%',))\n",
    "helpers.py": "import os\ndef run_shell(cmd):\n    return os.popen(cmd).read()\ndef read_doc(name):\n    return open('/srv/docs/' + name).read()\ndef safe_tail(n):\n    return os.popen('tail -n %d /var/log/app.log' % int(n)).read()\n",
    "admin.py": "import subprocess as sp\nfrom os import system as sh\nfrom flask import request\ndef b1(): sh('rm -rf /tmp/' + request.form['dir'])\ndef b2(): return sp.check_output('du -sh ' + request.form['dir'], shell=True)\ndef b3(): return sp.check_output(['du', '-sh', request.form['dir']])\ndef b4(conn):\n    table = request.form['table']\n    if table not in ('users', 'orders'):\n        raise ValueError('table')\n    conn.execute('SELECT * FROM ' + table)\ndef b5():\n    cmd = 'ls'\n    if 3 > 4:\n        cmd = 'ls ' + request.form['p']\n    sp.call(cmd, shell=True)\n",
}
# 래퍼를 거치는 흐름은 위험 호출이 있는 줄과 래퍼를 부르는 줄 어느 쪽을 적어도 맞은 것으로 센다
DETECT_BIG_TRUTH = [{("web.py", 7)}, {("web.py", 10)}, {("web.py", 11)}, {("helpers.py", 3), ("web.py", 13)}, {("helpers.py", 5), ("web.py", 14)},
                    {("admin.py", 4)}, {("admin.py", 5)}]
DETECT_TASKS = {
    "command-sinks": (DETECT_FILES, DETECT_TRUTH, "운영체제 명령 실행", ("IL-504",)),
    "mixed-repo": (DETECT_BIG_FILES, DETECT_BIG_TRUTH, "운영체제 명령 실행·SQL 실행·파일 열기", ("IL-501", "IL-502", "IL-504")),
}
TASK_SETS = {"pilot": ("fix", "feature", "command-sinks"), "hard": ("hard", "mixed-repo"), "all": ("fix", "feature", "hard", "command-sinks", "mixed-repo")}
TAIL = "\n\n고친(또는 구현한) app.py 전체를 ```python 코드 블록 하나로만 출력하라(설명 없이).\n\n--- app.py\n"


def _call(cmd: str, prompt: str, cwd: Path) -> dict:
    started = time.monotonic()
    done = subprocess.run(shlex.split(cmd), input=prompt, capture_output=True, text=True, cwd=cwd, timeout=1800)
    try:
        data = json.loads(done.stdout)
    except ValueError:  # iron-laws: ignore[IL-301] JSON이 아닌 응답은 원문을 결과로 두고 사용량 0으로 기록한다
        data = {"result": done.stdout}
    return {"text": data.get("result", ""), "cost_usd": data.get("total_cost_usd", 0.0), "usage": data.get("usage", {}), "seconds": round(time.monotonic() - started, 1)}


def _cached(path: Path, cmd: str, prompt: str, cwd: Path) -> dict:
    stamp = path.with_suffix(".prompt")
    if path.is_file() and stamp.is_file() and stamp.read_text(encoding="utf-8") == prompt:
        return json.loads(path.read_text(encoding="utf-8"))
    result = _call(cmd, prompt, cwd)
    path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    stamp.write_text(prompt, encoding="utf-8")
    return result


def _code(text: str) -> str:
    blocks = re.findall(r"```(?:python|py)?\n(.*?)```", text, re.S)
    return blocks[-1] if blocks else ""


def _code_task(work: Path, kind: str, name: str, rule: str, vulnerable: str, given: str, payload: str | None = None, benign: str | None = None) -> dict | None:
    """취약한 원본과 회귀 명세를 만든다. 오철칙이 원본에서 지적하지 못하면 명세를 만들 수 없어 과제에서 뺀다(그 사실을 남긴다)."""
    project = work / "projects" / name
    project.mkdir(parents=True, exist_ok=True)
    (project / "app.py").write_text(vulnerable, encoding="utf-8")
    report = AuditScanner(project).scan()
    try:
        spec = propose_spec(project, resolve_finding(report, f"{rule}@app.py")).spec
    except ValueError:  # iron-laws: ignore[IL-301] 원본에서 지적이 없으면 명세를 만들 수 없다는 사실을 과제 목록 밖에 남긴다
        spec = None
    if spec is None:
        return None
    updates = {k: v for k, v in (("payload", payload), ("benign", benign)) if v is not None}
    if updates:
        spec = spec.model_copy(update={"input": spec.input.model_copy(update=updates)})
    (work / "specs").mkdir(exist_ok=True)
    (work / "specs" / f"{name}.yml").write_text(dump_spec(spec.model_copy(update={"confirmed": True})), encoding="utf-8")
    return {"kind": kind, "name": name, "rule": rule, "given": given}


def prepare(work: Path, guide_cmd: str, selection: tuple[str, ...]) -> dict:
    from tests.regression_corpus import SUPPORTED

    by_name = {c.name: c for c in SUPPORTED}
    tasks, skipped = [], []
    plans = []
    if "fix" in selection:
        plans += [("fix", n, by_name[n].rule, by_name[n].vulnerable, by_name[n].vulnerable) for n in FIX_CASES]
    if "feature" in selection:
        plans += [("feature", n, by_name[n].rule, by_name[n].vulnerable, FEATURE_STUBS[n]) for n in FEATURE_STUBS]
    if "hard" in selection:
        plans += [("fix", n, rule, code, code, payload, benign) for n, (rule, code, payload, benign) in HARD_CASES.items()]
    for plan in plans:
        task = _code_task(work, *plan)
        (tasks.append(task) if task else skipped.append(plan[1]))
    for name, (files, _truth, _what, _rules) in DETECT_TASKS.items():
        if name not in selection:
            continue
        detect = work / "detect" / name
        detect.mkdir(parents=True, exist_ok=True)
        for rel, text in files.items():
            (detect / rel).write_text(text, encoding="utf-8")
        tasks.append({"kind": "detect", "name": name, "rule": "", "given": ""})
    guides = work / "guides"
    guides.mkdir(exist_ok=True)
    (guides / "export.md").write_text(export_guidelines([cls() for cls in ALL_RULES], languages={"python"}), encoding="utf-8")
    llm = _cached(guides / "llm.json", guide_cmd,
                  "이 저장소는 소스코드 보안·품질 점검 도구다. src/iron_laws/rules/ 아래의 규칙 코드를 읽고, 코딩 에이전트에게 줄 CLAUDE.md 지침으로 "
                  "쓸만한 규칙만 뽑아 마크다운으로 출력하라. 출력은 지침 본문만 쓴다.", ROOT)
    (guides / "llm.md").write_text(llm["text"], encoding="utf-8")
    return {"tasks": tasks, "skipped": skipped, "guides": {"llm_guidelines": llm["text"], "export_guidelines": (guides / "export.md").read_text(encoding="utf-8")}}


def _numbered(text: str) -> str:
    return "\n".join(f"{i:3d}| {line}" for i, line in enumerate(text.splitlines(), start=1))


def _first_prompt(task: dict, guide: str) -> str:
    head = f"작업 지침(CLAUDE.md):\n{guide}\n\n" if guide else ""
    if task["kind"] == "fix":
        return head + "아래 app.py의 보안 결함을 찾아 고쳐라. 원래 기능은 유지하라." + TAIL + task["given"]
    if task["kind"] == "feature":
        return head + "아래 app.py에서 NotImplementedError인 함수의 본문을 설명대로 구현하라. 나머지는 그대로 둔다." + TAIL + task["given"]
    files_, _truth, what, _rules = DETECT_TASKS[task["name"]]
    files = "\n\n".join(f"--- {rel}\n{_numbered(text)}" for rel, text in files_.items())
    return head + (f"아래 파일들에서 외부 입력(request)이 {what}에 위험하게 닿는 곳을 모두 찾아라. 다른 파일의 함수를 거치면 위험한 호출이 있는 줄을 적는다. "
                   "JSON 배열 [{\"file\": 파일 이름, \"line\": 줄 번호}]만 출력하라.\n\n" + files)


def _tool_feedback(task: dict, answer: str, scratch: Path) -> str | None:
    """답안을 오철칙으로 점검해 HIGH 이상 지적이 있으면 되돌릴 지시문, 없으면 None. 탐지 과제는 점검 결과 목록을 준다."""
    if task["kind"] == "detect":
        rules = DETECT_TASKS[task["name"]][3]
        report = AuditScanner(scratch.parent.parent / "detect" / task["name"]).scan()
        rows = [f"- {v.rule_id} {v.file_path.as_posix()}:{v.line_number} {v.confidence.value} {v.message}" for v in report.violations if v.rule_id in rules]
        return "오철칙 정적 점검 결과(참고):\n" + ("\n".join(rows) or "- 지적 없음") + "\n\n위 결과와 코드를 함께 보고 최종 목록을 같은 JSON 형식으로만 출력하라."
    scratch.mkdir(parents=True, exist_ok=True)
    (scratch / "app.py").write_text(answer, encoding="utf-8")
    report = AuditScanner(scratch).scan()
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if not any(order.index(v.severity) >= order.index(Severity.HIGH) for v in report.violations):
        return None
    return "오철칙 점검에서 고쳐야 할 지적이 나왔다. 아래 지시대로 다시 고쳐라.\n\n" + generate_fix_prompt(report, 20)


def run_one(work: Path, task: dict, condition: str, rep: int, guides: dict, ai_cmd: str) -> dict:
    guide = guides["export_guidelines"] if condition.startswith("export") else guides["llm_guidelines"] if condition == "llm_guidelines" else ""
    raw = work / "raw"
    raw.mkdir(exist_ok=True)
    cwd = work / "cwd"
    cwd.mkdir(exist_ok=True)
    key = f"{task['name']}.{condition}.r{rep}"
    prompt = _first_prompt(task, guide)
    first = _cached(raw / f"{key}.1.json", ai_cmd, prompt, cwd)
    calls = [first]
    answer = first["text"] if task["kind"] == "detect" else _code(first["text"])
    if condition.endswith("tool"):
        feedback = _tool_feedback(task, answer, work / "scratch" / key)
        if feedback is not None:
            again = prompt + "\n\n이전 답안:\n" + (answer if task["kind"] == "detect" else f"```python\n{answer}```") + "\n\n" + feedback + ("" if task["kind"] == "detect" else TAIL + answer)
            second = _cached(raw / f"{key}.2.json", ai_cmd, again, cwd)
            calls.append(second)
            answer = second["text"] if task["kind"] == "detect" else _code(second["text"])
    return {"task": task["name"], "kind": task["kind"], "condition": condition, "rep": rep, "answer": answer,
            "calls": len(calls), "cost_usd": round(sum(c["cost_usd"] or 0 for c in calls), 4), "seconds": round(sum(c["seconds"] for c in calls), 1)}


def judge_detect(answer: str, truth=DETECT_TRUTH) -> dict:
    """정답은 줄 집합이거나, 같은 결함을 가리키는 줄들의 묶음 목록이다(묶음 안 어느 줄이든 맞으면 그 결함을 찾은 것이다)."""
    match = re.search(r"\[.*\]", answer, re.S)
    try:
        items = json.loads(match.group(0)) if match else []
    except ValueError:  # iron-laws: ignore[IL-301] JSON으로 읽지 못한 답은 찾은 줄 0개로 센다
        items = []
    found = {(str(i.get("file", "")).split("/")[-1], i.get("line")) for i in items if isinstance(i, dict) and isinstance(i.get("line"), int)}
    groups = [{t} for t in truth] if isinstance(truth, set) else [set(g) for g in truth]
    hit = sum(1 for g in groups if g & found)
    correct = len(found & set().union(*groups))
    return {"found": len(found), "hit": hit, "recall": round(hit / len(groups), 3), "precision": round(correct / len(found), 3) if found else 0.0}


def classify_regression(result) -> str:
    """회귀 검사 결과를 결함 유출(leaked)·정상 기능 손상(broken)·판정 불가(undetermined)·통과(ok)로 나눈다."""
    evidence = result.evidence or {}
    attack = (evidence.get("candidate_attack") or [""])[0]
    control = (evidence.get("candidate_control") or [""])[0]
    if attack == "defect_reproduced" or (evidence.get("variants") or {}).get("failed"):
        return "leaked"
    if result.result == "fail" and control and control != "passed":
        return "broken"
    if result.result == "pass" or (attack == "passed" and control == "passed" and "mutant" in result.reason):
        return "ok"  # 답안은 공격·정상·변형 입력을 모두 통과했다. mutant 확인은 시험의 구별력이지 답안의 판정이 아니다
    return "undetermined"


def judge_code(work: Path, rows: list[dict], tasks: dict, runner: str) -> None:
    from iron_laws.verify.engine import regression_only
    from iron_laws.verify.runner import RunLimits

    image = "iron-laws-verify:py313" if runner == "docker" else None
    for row in rows:
        original = (work / "projects" / row["task"] / "app.py").read_text(encoding="utf-8")
        diff = "".join(difflib.unified_diff(original.splitlines(True), row["answer"].splitlines(True), "a/app.py", "b/app.py"))
        patch = work / "patches" / f"{row['task']}.{row['condition']}.r{row['rep']}.diff"
        patch.parent.mkdir(exist_ok=True)
        patch.write_text(("diff --git a/app.py b/app.py\n" + diff) if diff and row["answer"] else "", encoding="utf-8")
        if not row["answer"]:
            row.update(verdict="undetermined", reason="답안에서 코드를 찾지 못했다")
            continue
        result = regression_only(work / "projects" / row["task"], patch, work / "specs" / f"{row['task']}.yml", runner, image, RunLimits(timeout_s=60))
        row.update(verdict=classify_regression(result), reason=result.reason[:300])


def summarize(rows: list[dict]) -> dict:
    summary: dict[str, dict] = defaultdict(dict)
    for condition in CONDITIONS:
        mine = [r for r in rows if r["condition"] == condition]
        code = [r for r in mine if r["kind"] in ("fix", "feature")]
        detect = [r for r in mine if r["kind"] == "detect"]
        summary[condition] = {
            "code_tasks": len(code),
            **{verdict: sum(r["verdict"] == verdict for r in code) for verdict in ("ok", "leaked", "broken", "undetermined")},
            "detect_recall": [r["recall"] for r in detect],
            "detect_precision": [r["precision"] for r in detect],
            "calls": sum(r["calls"] for r in mine),
            "cost_usd": round(sum(r["cost_usd"] for r in mine), 3),
            "seconds": round(sum(r["seconds"] for r in mine), 1),
        }
    flips = defaultdict(set)
    for r in rows:
        if r["kind"] != "detect":
            flips[(r["task"], r["condition"])].add(r["verdict"])
    unstable = sorted(f"{t}/{c}" for (t, c), seen in flips.items() if len(seen) > 1)
    return {"by_condition": dict(summary), "unstable_across_reps": unstable}


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    options = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    if len(args) != 2:
        print(__doc__)
        return 2
    work, out = Path(args[0]), Path(args[1])
    work.mkdir(parents=True, exist_ok=True)
    ai_cmd, guide_cmd = options.get("ai-cmd", AI_CMD), options.get("guide-cmd", GUIDE_CMD)
    selection = TASK_SETS[options.get("tasks", "pilot")]
    prepared = prepare(work, guide_cmd, selection)
    tasks = {t["name"]: t for t in prepared["tasks"]}
    jobs = [(t, c, r) for r in range(1, int(options.get("reps", "1")) + 1) for t in prepared["tasks"] for c in CONDITIONS]
    with ThreadPoolExecutor(max_workers=int(options.get("jobs", "4"))) as pool:
        rows = list(pool.map(lambda job: run_one(work, job[0], job[1], job[2], prepared["guides"], ai_cmd), jobs))
    for row in rows:
        if row["kind"] == "detect":
            row.update(judge_detect(row["answer"], DETECT_TASKS[row["task"]][1]))
    judge_code(work, [r for r in rows if r["kind"] != "detect"], tasks, options.get("runner", "docker"))
    record = {"ai_cmd": ai_cmd, "guide_cmd": guide_cmd, "reps": int(options.get("reps", "1")), "tasks": options.get("tasks", "pilot"),
              "skipped_tasks": prepared["skipped"], **summarize(rows),
              "rows": [{k: v for k, v in r.items() if k != "answer"} for r in rows]}
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("by_condition", "unstable_across_reps")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
