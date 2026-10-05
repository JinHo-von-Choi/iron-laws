"""
오철칙 v1.4 실행계획(근거 연결·문법·값 추적·출력 안전, 승인 범위와 총비용 지표, 수정 부채 표시, 신뢰 지표)의 실증 측정.

사용법:
    uv run python benchmarks/plan_experiments_v14.py [결과.json] [--baseline v1.3.0 소스 폴더]

같은 표본을 v1.3.0 소스(--baseline)와 현재 소스에 각각 돌려 결과를 나란히 남긴다. 표본은 모두 구현자가 직접 만들고 분류한 것이며
독립 검토자의 분류가 아니다. 효과 주장의 근거가 아니라 회귀 방지와 결함 수정 확인에 쓴다. 변형 건수를 독립 표본 수로 세지 않는다.
- 실험 1 동일 줄 근거 대여: 위험 호출이 자기 지적 없이 근거 충족으로 세어진 수
- 실험 2 문자열과 억제 주석: 문자열 속 지시문이 억제로 인정된 수, 진짜 주석이 사라진 수
- 실험 3 검사한 값의 동일성: 재대입 뒤 검사 면제로 놓친 위험 수, 정상 guard의 오탐 수
- 실험 4 출력 비밀 노출: 모든 출력 형식에서 새어 나온 비밀 조각 수
- 실험 5 승인 범위: 이동·이동과 수정·복제에서 명령 사이의 판정 불일치와 위험한 승계
- 실험 6 파일럿 총비용 판정: 검토 시간만 줄고 총비용이 늘어난 반례의 판정
- 실험 7 수정 부채 표시: 가리는 수정의 표시 수, 정상 수정의 오표시 수 (현재 소스만)
- 실험 8 신뢰 지표와 결정론: 표본 점검의 지표 값, 환경을 바꾼 두 번 실행의 정규화 보고서 일치 (현재 소스만)
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 출력 노출 측정에 쓰는 무효 합성 비밀값이다

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROBE = ROOT / "benchmarks" / "_probe_v14.py"
FORMATS = ["console", "markdown", "json", "sarif", "prompt", "review"]
HEAD = "import os\nimport subprocess\nfrom flask import request\n\ndef f():\n    a = request.args['a']\n"
R, C = "os.system('echo ' + a)", "os.system('ok')"  # 위험 호출, 닫힌 호출


def run_probe(src: Path, items: list[dict]) -> list[dict]:
    env = {**os.environ, "PYTHONPATH": str(src), "PYTHONHASHSEED": "1"}
    result = subprocess.run([sys.executable, str(PROBE)], input=json.dumps({"items": items}), capture_output=True, text=True, env=env, timeout=1800)
    if result.returncode != 0:
        raise RuntimeError(result.stderr[-800:])
    return json.loads(result.stdout)


def both(baseline: Path | None, items: list[dict]) -> tuple[list[dict] | None, list[dict]]:
    return (run_probe(baseline / "src", items) if baseline else None), run_probe(ROOT / "src", items)


# --------------------------------------------------------------------------- 실험 1
SAME_LINE = {
    "risky+closed": [R, C],
    "closed+risky": [C, R],
    "risky+risky": [R, R],
    "risky+risky+risky": [R, R, R],
    "closed+risky+closed": [C, R, C],
    "risky+closed+risky": [R, C, R],
    "closed+closed+risky": [C, C, R],
    "risky+closed+closed": [R, C, C],
}


def exp1(baseline: Path | None) -> dict:
    names = list(SAME_LINE)
    variants = []
    for name in names:
        body = "; ".join(SAME_LINE[name])
        variants += [(f"{name}", HEAD + f"    {body}\n"), (f"{name}|한글주석", HEAD + f"    {body}  # 한글 주석 ✓\n"), (f"{name}|CRLF", (HEAD + f"    {body}\n").replace("\n", "\r\n"))]
    items = [{"kind": "ledger", "files": {"a.py": text}} for _n, text in variants]
    old, new = both(baseline, items)

    def score(results: list[dict] | None) -> dict | None:
        if results is None:
            return None
        false_pass = 0
        rows = []
        for (name, _text), res in zip(variants, results, strict=True):
            risky = SAME_LINE[name.split("|")[0]].count(R)
            line_points = [p for p in res["points"] if p["line"] == 7]
            met_with_finding = sum(1 for p in line_points if p["state"] == "evidence_met" and p["findings"] > 0)
            own_findings = res["findings"]
            over = max(met_with_finding - own_findings, 0)  # 지적 수보다 많은 호출이 지적을 근거로 충족 처리됨
            false_pass += over
            rows.append({"case": name, "risky_calls": risky, "findings": own_findings, "calls_met_by_a_finding": met_with_finding, "borrowed": over, "verifier_ok": res["verifier_ok"]})
        return {"cases": len(results), "borrowed_total": false_pass, "cases_with_borrowing": sum(1 for r in rows if r["borrowed"]), "verifier_rejected": sum(1 for r in rows if not r["verifier_ok"]), "rows": rows}

    return {"v1_3_0": score(old), "current": score(new)}


# --------------------------------------------------------------------------- 실험 2
D = "# iron-laws: ignore[IL-101] 사유가 충분하다"
SUPPRESS = [
    ("yaml-escaped-quote-inside", "a.yml", f"key: 'it''s {D}'\n", 0),
    ("yaml-escaped-quote-two-pairs", "a.yml", f"key: 'a''b''c {D}'\n", 0),
    ("yaml-escaped-quote-then-comment", "a.yml", f"key: 'it''s' {D}\n", 1),
    ("yaml-escaped-quote-at-end-then-comment", "a.yml", f"key: 'a''' {D}\n", 1),
    ("yaml-double-quoted-escape", "a.yml", 'key: "a \\" ' + D + '"\n', 0),
    ("yaml-single-quoted-inner", "a.yml", f"key: 'a {D}'\n", 0),
    ("yaml-real-comment", "a.yml", f'key: "value" {D}\n', 1),
    ("yaml-block-scalar", "a.yml", f"key: |\n  text {D}\nother: 1\n", 0),
    ("yaml-apostrophe-plain", "a.yml", f"desc: it's fine {D}\n", 1),
    ("toml-triple-quote-string", "a.toml", f'k = """\n{D}\n"""\n', 0),
    ("toml-real-comment", "a.toml", f"k = 1 {D}\n", 1),
    ("shell-heredoc", "a.sh", f"cat <<EOF\n{D}\nEOF\n", 0),
    ("shell-two-heredocs", "a.sh", f"cat <<A <<B\n{D}\nA\n{D}\nB\n", 0),
    ("shell-real-comment", "a.sh", f'echo "x" {D}\n', 1),
    ("shell-single-quoted-multiline", "a.sh", f"echo 'one\n{D}'\n", 0),
    ("env-quoted", "a.env", f'KEY="v {D}"\n', 0),
    ("python-string-literal", "a.py", f'x = "{D}"\n', 0),
    ("python-real-comment", "a.py", f"x = 1  {D}\n", 1),
]


def exp2(baseline: Path | None) -> dict:
    items = [{"kind": "suppress", "filename": fn, "text": text} for _n, fn, text, _e in SUPPRESS]
    old, new = both(baseline, items)

    def score(results: list[dict] | None) -> dict | None:
        if results is None:
            return None
        wrong = [n for (n, _f, _t, expected), r in zip(SUPPRESS, results, strict=True) if expected == 0 and r["directives"] > 0]
        lost = [n for (n, _f, _t, expected), r in zip(SUPPRESS, results, strict=True) if expected > 0 and r["directives"] == 0]
        return {"cases": len(results), "string_treated_as_suppression": wrong, "real_comment_lost": lost}

    return {"v1_3_0": score(old), "current": score(new)}


# --------------------------------------------------------------------------- 실험 3
ALLOW_HEAD = 'import os\nfrom flask import request\nALLOWED = ("a", "b")\n\ndef f():\n    cmd = request.args["c"]\n    if cmd not in ALLOWED:\n        return\n'
VALUE_CASES = [
    ("plain-reassign", '    cmd = request.args["d"]\n', True),
    ("augmented", '    cmd += request.args["d"]\n', True),
    ("walrus-in-condition", '    if (cmd := request.args["d"]):\n        pass\n', True),
    ("walrus-statement", '    (cmd := request.args["d"])\n', True),
    ("walrus-in-call", '    print(cmd := request.args["d"])\n', True),
    ("walrus-in-comprehension", '    _ = [cmd := request.args["d"] for _ in range(1)]\n', True),
    ("walrus-other-variable", '    if (n := len(cmd)) > 1:\n        pass\n', False),
    ("no-reassign", "", False),
    ("unrelated-assign", "    other = 1\n", False),
]


def exp3(baseline: Path | None) -> dict:
    items = [{"kind": "scan_rules", "files": {"a.py": ALLOW_HEAD + body + '    os.system("run " + cmd)\n'}} for _n, body, _r in VALUE_CASES]
    old, new = both(baseline, items)

    def score(results: list[dict] | None) -> dict | None:
        if results is None:
            return None
        missed, false_alarm = [], []
        for (name, _body, risky), res in zip(VALUE_CASES, results, strict=True):
            found = any(rule == "IL-504" and conf == "CONFIRMED" for rule, conf in res["findings"])
            if risky and not found:
                missed.append(name)
            if not risky and found:
                false_alarm.append(name)
        return {"risky_cases": sum(1 for c in VALUE_CASES if c[2]), "benign_cases": sum(1 for c in VALUE_CASES if not c[2]), "risky_missed": missed, "benign_false_alarm": false_alarm}

    return {"v1_3_0": score(old), "current": score(new)}


# --------------------------------------------------------------------------- 실험 4
SECRET = "Zq9xKm2LpQw8RtYuVn4B"
LEAK_LINES = [
    ("ts-typed-const", "a.ts", f'const token: string = "{SECRET}"; console.log(eval(req.query.x));\n'),
    ("py-annotation", "a.py", f'api_token: str = "{SECRET}"; exec(input())\n'),
    ("py-generic-annotation", "a.py", f'secret_key: Optional[str] = "{SECRET}"; exec(input())\n'),
    ("rust-typed-let", "a.rs", f'let password: &str = "{SECRET}"; unsafe {{ std::ptr::null::<u8>().read(); }}\n'),
    ("js-quoted-key", "a.js", f'const cfg = {{ "token": "{SECRET}", mode: eval(userInput) }};\n'),
    ("py-plain", "a.py", f'password = "{SECRET}"; exec(input())\n'),
]


def exp4(baseline: Path | None) -> dict:
    fragments = [SECRET[:8], SECRET[6:14], SECRET[-8:]]
    items = [{"kind": "leak", "files": {fn: text}, "fragments": fragments, "formats": FORMATS} for _n, fn, text in LEAK_LINES]
    old, new = both(baseline, items)

    def score(results: list[dict] | None) -> dict | None:
        if results is None:
            return None
        rows = {n: {fmt: len(found) for fmt, found in r["leaked"].items() if found} for (n, _f, _t), r in zip(LEAK_LINES, results, strict=True)}
        return {"cases": len(results), "formats": len(FORMATS), "cases_with_leak": sum(1 for v in rows.values() if v), "leaked_cells": sum(len(v) for v in rows.values()), "leaks": {k: v for k, v in rows.items() if v}}

    return {"v1_3_0": score(old), "current": score(new)}


# --------------------------------------------------------------------------- 실험 5
APP = 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n\ndef other():\n    return 1\n'
SCOPE_CASES = [
    ("safe-move", [{"op": "mv", "from": "app.py", "to": "tools.py"}], False),
    ("move-into-subfolder", [{"op": "mv", "from": "app.py", "to": "pkg/app.py"}], False),
    ("move-and-change-premise", [{"op": "mv", "from": "app.py", "to": "tools.py"}, {"op": "replace", "path": "tools.py", "old": 'os.system("ls " + d)', "new": 'os.system("rm -rf " + d)'}], True),
    ("copy-keeps-original", [{"op": "write", "path": "copy.py", "text": APP}], True),
]


def exp5(baseline: Path | None) -> dict:
    items = [{"kind": "scope", "files": {"app.py": APP}, "finding": "IL-504@app.py:6", "changes": changes} for _n, changes, _r in SCOPE_CASES]
    old, new = both(baseline, items)

    def score(results: list[dict] | None) -> dict | None:
        if results is None:
            return None
        rows = {}
        for (name, _changes, _risky), res in zip(SCOPE_CASES, results, strict=True):
            codes = res["exit_codes"]
            rows[name] = {"exit_codes": codes, "commands_disagree": len({codes["full"], codes["changed"]}) > 1 or len({codes["bundle_full"], codes["bundle_changed"]}) > 1, "errored": any(c == 2 for c in codes.values())}
        safe = [r for (n, _c, risky), r in zip(SCOPE_CASES, rows.values(), strict=True) if not risky]
        risky_rows = [r for (n, _c, risky), r in zip(SCOPE_CASES, rows.values(), strict=True) if risky]
        return {
            "rows": rows,
            "safe_cases_with_disagreement_or_error": sum(1 for r in safe if r["commands_disagree"] or r["errored"]),
            "risky_cases_passed_by_check": sum(1 for r in risky_rows if r["exit_codes"]["full"] == 0 or r["exit_codes"]["changed"] == 0),
        }

    return {"v1_3_0": score(old), "current": score(new)}


# --------------------------------------------------------------------------- 실험 6
PILOT_CASES = [
    ("review-time-down-total-time-up", {"baseline": [40, 0], "bundle": [10, 110]}),
    ("both-improve", {"baseline": [40, 0], "bundle": [20, 2]}),
    ("no-change", {"baseline": [40, 0], "bundle": [40, 0]}),
]


def exp6(baseline: Path | None) -> dict:
    items = [{"kind": "pilot", "per_team": 22, **spec} for _n, spec in PILOT_CASES]
    old, new = both(baseline, items)
    shape = lambda results: None if results is None else {n: r["verdict"] for (n, _s), r in zip(PILOT_CASES, results, strict=True)}  # noqa: E731
    return {"v1_3_0": shape(old), "current": shape(new), "note": "첫 사례는 검토 시간 75% 감소, 총 능동시간 40분에서 120분으로 증가한 반례다. 성공으로 판정하면 결함이다."}


# --------------------------------------------------------------------------- 실험 7
BASE = {
    "command": ('import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n', "IL-504"),
    "path": ('from flask import request\n\ndef read_file():\n    p = request.args["p"]\n    return open(p).read()\n', "IL-502"),
    "sql": ('from flask import request\n\ndef find(cur):\n    n = request.args["n"]\n    cur.execute("SELECT * FROM t WHERE n = \'" + n + "\'")\n', "IL-501"),
}
FIXES = {
    "command": {
        "legit-argv": 'import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    subprocess.run(["ls", d], check=True)\n',
        "legit-allowlist": 'import os\nfrom flask import request\nALLOWED = ("a", "b")\n\ndef run_tool():\n    d = request.args["d"]\n    if d not in ALLOWED:\n        raise ValueError(d)\n    os.system("ls " + d)\n',
        "hide-swallow": 'import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    try:\n        subprocess.run(["ls", d], check=True)\n    except Exception:\n        pass\n',
        "hide-type-ignore": 'import subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    subprocess.run(["ls", d], check=True)  # type: ignore\n',
    },
    "path": {
        "legit-basename": 'import os\nfrom flask import request\n\ndef read_file():\n    p = os.path.basename(request.args["p"])\n    return open(os.path.join("/srv/data", p)).read()\n',
        "legit-realpath": 'import os\nfrom flask import request\n\ndef read_file():\n    p = os.path.realpath(os.path.join("/srv/data", request.args["p"]))\n    if not p.startswith("/srv/data/"):\n        raise ValueError(p)\n    return open(p).read()\n',
        "hide-swallow": 'import os\nfrom flask import request\n\ndef read_file():\n    p = os.path.basename(request.args["p"])\n    try:\n        return open(os.path.join("/srv/data", p)).read()\n    except Exception:\n        pass\n',
        "hide-type-ignore": 'import os\nfrom flask import request\n\ndef read_file():\n    p = os.path.basename(request.args["p"])\n    return open(os.path.join("/srv/data", p)).read()  # type: ignore\n',
    },
    "sql": {
        "legit-param": 'from flask import request\n\ndef find(cur):\n    n = request.args["n"]\n    cur.execute("SELECT * FROM t WHERE n = %s", (n,))\n',
        "legit-param-qmark": 'from flask import request\n\ndef find(cur):\n    n = request.args["n"]\n    cur.execute("SELECT * FROM t WHERE n = ?", (n,))\n',
        "hide-swallow": 'from flask import request\n\ndef find(cur):\n    n = request.args["n"]\n    try:\n        cur.execute("SELECT * FROM t WHERE n = %s", (n,))\n    except Exception:\n        pass\n',
        "hide-type-ignore": 'from flask import request\n\ndef find(cur):\n    n = request.args["n"]\n    cur.execute("SELECT * FROM t WHERE n = %s", (n,))  # type: ignore\n',
    },
}


def exp7() -> dict:
    from iron_laws.core.scanner import AuditScanner
    from iron_laws.verify.debt_delta import compare

    def scan(code: str):
        root = Path(tempfile.mkdtemp(prefix="il-e7-"))
        (root / "app.py").write_text(code, encoding="utf-8")
        return AuditScanner(root).scan()

    rows, hidden_marked, hidden_total, legit_marked, legit_total = [], 0, 0, 0, 0
    for family, fixes in FIXES.items():
        original = scan(BASE[family][0])
        for name, code in fixes.items():
            candidate = scan(code)
            delta = compare(original, candidate).to_dict()
            marked = bool(delta["fix_adjacent_new"])
            target_rule_gone = BASE[family][1] not in {v.rule_id for v in candidate.violations}
            rows.append({"family": family, "fix": name, "new_total": delta["totals"]["new"], "fix_adjacent_new": len(delta["fix_adjacent_new"]), "target_rule_gone": target_rule_gone})
            if name.startswith("hide"):
                hidden_total += 1
                hidden_marked += marked
            else:
                legit_total += 1
                legit_marked += marked
    return {"hiding_fixes": hidden_total, "hiding_marked": hidden_marked, "legitimate_fixes": legit_total, "legitimate_marked": legit_marked, "rows": rows, "note": "표시는 판정에 연결하지 않는다. 표본은 구현자가 분류했다."}


# --------------------------------------------------------------------------- 실험 8
def exp8() -> dict:
    from iron_laws.core.canonical import canonical_projection
    from iron_laws.core.scanner import AuditScanner

    corpora = {
        "clean": {"b.py": "def add(a, b):\n    return a + b\n"},
        "unresolved-command": {"a.py": "import os\n\ndef run(cmd):\n    os.system(cmd)\n"},
        "mixed": {"a.py": APP, "ui/a.js": 'const password = "Zq9xKm2LpQw8RtYu";\n', "ci/deploy.yml": "key: 'it''s fine'\n"},
    }
    metrics = {}
    for name, files in corpora.items():
        root = Path(tempfile.mkdtemp(prefix="il-e8-"))
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        s = AuditScanner(root, gates={"max_analysis_unknown_rate": 0.5}).scan().summary
        metrics[name] = {"analysis_unknown_rate": s.analysis_unknown_rate, "unverified_rule_language_rate": s.unverified_rule_language_rate, "evaluated_pairs": s.evaluated_rule_language_pairs, "gate_exceeded": s.gate_exceeded, "is_passed": s.is_passed}

    def audit(project: Path, cwd: Path, extra: dict) -> dict:
        env = {**os.environ, **extra}
        run = subprocess.run([sys.executable, "-c", "import sys; from iron_laws.cli import app; sys.exit(app())", "audit", str(project), "--format", "json", "--limit", "0", "--allow-empty"], capture_output=True, text=True, env=env, cwd=cwd, timeout=900)
        return json.loads(run.stdout)

    src = ROOT / "src" / "iron_laws"
    a_dir, b_dir = Path(tempfile.mkdtemp(prefix="il-e8a-")) / "one" / "deeper", Path(tempfile.mkdtemp(prefix="il-e8b-"))
    shutil.copytree(src, a_dir / "iron_laws")
    shutil.copytree(src, b_dir / "p")
    first = audit(a_dir / "iron_laws", a_dir, {"TZ": "UTC", "PYTHONHASHSEED": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    second = audit(b_dir / "p", b_dir, {"TZ": "Asia/Seoul", "PYTHONHASHSEED": "7", "LANG": "C", "LC_ALL": "C"})
    return {"trust_metrics": metrics, "determinism": {"files": first["summary"]["total_files_scanned"], "findings": first["summary"]["total_violations"], "projection_equal": canonical_projection(first) == canonical_projection(second), "raw_equal": json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)}}


def main() -> None:
    args = [a for a in sys.argv[1:]]
    baseline = None
    if "--baseline" in args:
        index = args.index("--baseline")
        baseline = Path(args[index + 1])
        del args[index : index + 2]
    out = Path(args[0]) if args else ROOT / "docs" / "benchmark_results" / "plan_experiments_v1_4.json"
    from iron_laws.core.scanner import tool_version

    result = {
        "tool_version": tool_version(),
        "baseline": "v1.3.0" if baseline else None,
        "note": "표본은 구현자가 직접 만들고 분류했다. 독립 검토자의 분류가 아니며 효과 주장의 근거가 아니라 회귀 방지와 결함 수정 확인에 쓴다.",
        "experiment_1_same_line_evidence": exp1(baseline),
        "experiment_2_suppression_grammar": exp2(baseline),
        "experiment_3_value_identity": exp3(baseline),
        "experiment_4_output_secret_exposure": exp4(baseline),
        "experiment_5_approval_scope": exp5(baseline),
        "experiment_6_pilot_total_cost": exp6(baseline),
        "experiment_7_debt_delta": exp7(),
        "experiment_8_trust_and_determinism": exp8(),
        "experiment_9_team_pilot": {"performed": False, "reason": "파일럿 팀이 없다. 도구만 준비했다."},
    }
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(json.dumps({k: v for k, v in result.items() if k.startswith("experiment")}, ensure_ascii=False, indent=2)[:6000] + "\n")


if __name__ == "__main__":
    main()
