"""
수정 지시문 비교: 같은 결함 표본을 두 판의 fix-prompt 지시문으로 AI에게 고치게 하고, 수정안을 같은 조건으로 검증해 결과를 나눠 센다

사용법:
    uv run python benchmarks/fix_prompt_ab.py <작업폴더> <이전 prompt.py> <결과.json> --ai-cmd "<AI 명령>" [--runner=docker] [--jobs=4]

- 표본: tests/regression_corpus.py의 지원 범위 사례(명령 실행·경로 접근·SQL 조립). 사례마다 회귀 명세를 제안받아 확정한 뒤 쓴다.
- 지시문: 이전 판(인자로 준 prompt.py 파일)과 현재 판(iron_laws.reporters.prompt). 두 판 모두 같은 점검 결과로 만든다.
- AI 명령: 표준 입력으로 지시문과 app.py 원문을 받아, 고친 app.py 전체를 ```python 블록으로 내야 한다(예: 도구를 끈 코딩 AI CLI).
  같은 지시문의 응답은 작업폴더에 남기고 다시 부르지 않는다.
- 검증: benchmarks/fix_loop.py와 같은 분류. 회귀 명세의 결함 행동 제거는 격리 실행기(docker 등)가 있을 때만 판정된다.
작성자: 최진호
작성일: 2026-10-12
"""

import difflib
import importlib.util
import json
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fix_loop import run as verify_cases  # noqa: E402

from iron_laws.core.scanner import AuditScanner  # noqa: E402
from iron_laws.reporters import prompt as prompt_current  # noqa: E402
from iron_laws.verify.engine import resolve_finding  # noqa: E402
from iron_laws.verify.regression import dump_spec, propose_spec  # noqa: E402

TAIL = "\n\n위 지시에 따라 아래 app.py를 고쳐라. 고친 app.py 전체를 ```python 코드 블록 하나로만 출력하라(설명 없이).\n\n--- app.py\n"
VARIANTS = ("previous", "current")


def _load_previous(path: Path):
    spec = importlib.util.spec_from_file_location("prompt_previous", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(work: Path, previous: Path) -> list[dict]:
    from tests.regression_corpus import SUPPORTED

    modules = {"previous": _load_previous(previous), "current": prompt_current}
    cases = []
    for case in SUPPORTED:
        project = work / "projects" / case.name
        project.mkdir(parents=True, exist_ok=True)
        (project / "app.py").write_text(case.vulnerable, encoding="utf-8")
        for rel, text in case.extra.items():
            (project / rel).parent.mkdir(parents=True, exist_ok=True)
            (project / rel).write_text(text, encoding="utf-8")
        report = AuditScanner(project).scan()
        spec = propose_spec(project, resolve_finding(report, f"{case.rule}@app.py")).spec
        if spec is None:
            continue
        if case.benign:
            spec = spec.model_copy(update={"input": spec.input.model_copy(update={"benign": case.benign})})
        (work / "specs").mkdir(exist_ok=True)
        (work / "specs" / f"{case.name}.yml").write_text(dump_spec(spec.model_copy(update={"confirmed": True})), encoding="utf-8")
        (work / "prompts").mkdir(exist_ok=True)
        for variant in VARIANTS:
            text = modules[variant].generate_fix_prompt(report, 40) + TAIL + case.vulnerable
            (work / "prompts" / f"{case.name}.{variant}.txt").write_text(text, encoding="utf-8")
        cases.append({"name": case.name, "rule": case.rule})
    return cases


def generate(work: Path, cases: list[dict], ai_cmd: str, jobs: int) -> None:
    (work / "raw").mkdir(exist_ok=True)
    (work / "cwd").mkdir(exist_ok=True)

    def one(name: str, variant: str) -> None:
        prompt = (work / "prompts" / f"{name}.{variant}.txt").read_text(encoding="utf-8")
        out = work / "raw" / f"{name}.{variant}.txt"
        stamp = work / "raw" / f"{name}.{variant}.prompt"
        if out.is_file() and stamp.is_file() and stamp.read_text(encoding="utf-8") == prompt:
            return  # 같은 지시문의 응답은 다시 부르지 않는다
        done = subprocess.run(shlex.split(ai_cmd), input=prompt, capture_output=True, text=True, cwd=work / "cwd", timeout=900)
        out.write_text(done.stdout, encoding="utf-8")
        stamp.write_text(prompt, encoding="utf-8")

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(lambda job: one(*job), [(c["name"], v) for c in cases for v in VARIANTS]))


def manifests(work: Path, cases: list[dict]) -> dict[str, Path]:
    paths = {}
    for variant in VARIANTS:
        rows = []
        for c in cases:
            blocks = re.findall(r"```(?:python|py)?\n(.*?)```", (work / "raw" / f"{c['name']}.{variant}.txt").read_text(encoding="utf-8"), re.S)
            original = (work / "projects" / c["name"] / "app.py").read_text(encoding="utf-8")
            diff = "".join(difflib.unified_diff(original.splitlines(True), (blocks[-1] if blocks else "").splitlines(True), "a/app.py", "b/app.py"))
            (work / "patches").mkdir(exist_ok=True)
            patch = work / "patches" / f"{c['name']}.{variant}.diff"
            patch.write_text(("diff --git a/app.py b/app.py\n" + diff) if diff else "", encoding="utf-8")
            rows.append({"id": c["name"], "project": f"projects/{c['name']}", "patch": f"patches/{patch.name}", "finding": f"{c['rule']}@app.py", "regression_spec": f"specs/{c['name']}.yml"})
        paths[variant] = work / f"manifest.{variant}.json"
        paths[variant].write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return paths


def summarize(cases: list[dict], results: dict[str, dict]) -> dict:
    rule_of = {c["name"]: c["rule"] for c in cases}
    by_rule = {}
    for variant, result in results.items():
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for row in result["rows"]:
            if row["defect_behavior_removed"] != "not_measured":
                counts[rule_of[row["id"]]][1] += 1
                counts[rule_of[row["id"]]][0] += row["defect_behavior_removed"] == "pass"
        by_rule[variant] = {rule: f"{removed}/{measured}" for rule, (removed, measured) in sorted(counts.items())}
    rows = {v: {r["id"]: r["outcome"] for r in results[v]["rows"]} for v in VARIANTS}
    changed = [{"id": n, "previous": rows["previous"][n], "current": rows["current"][n]} for n in rule_of if rows["previous"][n] != rows["current"][n]]
    transitions = Counter(("resolved" if c["previous"] == "resolved" else "other") + "->" + ("resolved" if c["current"] == "resolved" else "other") for c in changed)
    return {
        "cases": len(cases),
        "summary": {v: {k: results[v][k] for k in ("outcomes", "static_resolved_rate", "behavior_removed_rate", "success_rate")} for v in VARIANTS},
        "behavior_removed_by_rule": by_rule,
        "changed_cases": changed,
        "transitions": dict(transitions),
        "rows": {v: results[v]["rows"] for v in VARIANTS},
    }


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    options = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    if len(args) != 3 or "ai-cmd" not in options:
        print(__doc__)
        return 2
    work, previous, out = Path(args[0]), Path(args[1]), Path(args[2])
    work.mkdir(parents=True, exist_ok=True)
    cases = prepare(work, previous)
    generate(work, cases, options["ai-cmd"], int(options.get("jobs", "4")))
    paths = manifests(work, cases)
    results = {v: verify_cases(paths[v], options.get("runner", "auto")) for v in VARIANTS}
    record = {"ai_cmd": options["ai-cmd"], "runner": options.get("runner", "auto"), **summarize(cases, results)}
    out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("cases", "summary", "behavior_removed_by_rule", "transitions")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
