"""
산출물 비교: 같은 결함 표본을 서로 다른 안내물(수정 지시문·검토 묶음·MCP 도구 설명)로 AI에게 고치게 하고, 수정안을 같은 조건으로 검증해 결과를 나눠 센다

사용법:
    uv run python benchmarks/artifact_ab.py <작업폴더> <결과.json> --ai-cmd "<AI 명령>" [--runner=docker] [--jobs=4] [--prepare-only]

- 표본: tests/regression_corpus.py의 지원 범위 사례(명령 실행·경로 접근·SQL 조립). 사례마다 회귀 명세를 제안받아 확정한 뒤 쓴다.
- 안내물: 수정 지시문(reporters/prompt.py), 검토 묶음(core/review_bundle.py), MCP 도구 설명과 check 응답(mcp_server.py), 수정 지시문과 검토 묶음의 합.
- AI 명령: 표준 입력으로 안내물과 app.py 원문을 받아, 고친 app.py 전체를 ```python 블록으로 내야 한다(예: 도구를 끈 코딩 AI CLI).
  같은 안내물의 응답은 작업폴더에 남기고 다시 부르지 않는다.
- 검증: benchmarks/fix_loop.py와 같은 분류. 회귀 명세의 결함 행동 제거는 격리 실행기(docker 등)가 있을 때만 판정된다.
- 비교 기준: 수정 지시문을 기준선으로 두고 다른 안내물이 얼마나 다른 결과를 만드는지 센다.
작성자: 최진호
작성일: 2026-10-20
"""

import difflib
import json
import re
import shlex
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fix_loop import run as verify_cases  # noqa: E402

from iron_laws.core.review_bundle import build_bundle, render_markdown  # noqa: E402
from iron_laws.core.scanner import AuditScanner  # noqa: E402
from iron_laws.mcp_server import TOOL_DESCRIPTIONS  # noqa: E402
from iron_laws.reporters import prompt as prompt_current  # noqa: E402
from iron_laws.verify.engine import resolve_finding  # noqa: E402
from iron_laws.verify.regression import dump_spec, propose_spec  # noqa: E402

TAIL = "\n\n위 지시에 따라 아래 app.py를 고쳐라. 고친 app.py 전체를 ```python 코드 블록 하나로만 출력하라(설명 없이).\n\n--- app.py\n"
VARIANTS = ("fix_prompt", "review_bundle", "mcp_guidance", "fix_prompt_review")
BASELINE = "fix_prompt"
MAX_FINDINGS = 200


def _mcp_check(report) -> str:
    """MCP check 도구가 돌려주는 응답 형태."""
    findings = [
        {
            "rule_id": v.rule_id,
            "path": v.file_path.as_posix(),
            "line": v.line_number,
            "severity": v.severity.value,
            "confidence": v.confidence.value,
            "message": v.message,
            "finding_id": v.finding_id,
        }
        for v in report.violations[:MAX_FINDINGS]
    ]
    return json.dumps(
        {
            "passed": report.summary.is_passed,
            "scan_status": report.summary.scan_status,
            "files_scanned": report.summary.total_files_scanned,
            "findings_total": len(report.violations),
            "findings": findings,
            "truncated": len(report.violations) > MAX_FINDINGS,
        },
        ensure_ascii=False,
        indent=2,
    )


def _variant_text(variant: str, report, scanner) -> str:
    if variant == "fix_prompt":
        return prompt_current.generate_fix_prompt(report, 40)
    if variant == "review_bundle":
        bundle = build_bundle(report, scanner.approval_rows, changed_files=None, command="iron-laws check .", approvals_path=None)
        return render_markdown(bundle)
    if variant == "mcp_guidance":
        guidance = "\n".join(f"- {name}: {text}" for name, text in TOOL_DESCRIPTIONS.items())
        return f"도구 설명\n{guidance}\n\ncheck 응답\n{_mcp_check(report)}"
    if variant == "fix_prompt_review":
        bundle = build_bundle(report, scanner.approval_rows, changed_files=None, command="iron-laws check .", approvals_path=None)
        return prompt_current.generate_fix_prompt(report, 40) + "\n\n검토 묶음\n" + render_markdown(bundle)
    raise ValueError(f"알 수 없는 안내물: {variant}")


def prepare(work: Path) -> list[dict]:
    from tests.regression_corpus import SUPPORTED

    cases = []
    for case in SUPPORTED:
        project = work / "projects" / case.name
        project.mkdir(parents=True, exist_ok=True)
        (project / "app.py").write_text(case.vulnerable, encoding="utf-8")
        for rel, text in case.extra.items():
            (project / rel).parent.mkdir(parents=True, exist_ok=True)
            (project / rel).write_text(text, encoding="utf-8")
        scanner = AuditScanner(project)
        report = scanner.scan()
        spec = propose_spec(project, resolve_finding(report, f"{case.rule}@app.py")).spec
        if spec is None:
            continue
        if case.benign:
            spec = spec.model_copy(update={"input": spec.input.model_copy(update={"benign": case.benign})})
        (work / "specs").mkdir(exist_ok=True)
        (work / "specs" / f"{case.name}.yml").write_text(dump_spec(spec.model_copy(update={"confirmed": True})), encoding="utf-8")
        (work / "prompts").mkdir(exist_ok=True)
        for variant in VARIANTS:
            text = _variant_text(variant, report, scanner) + TAIL + case.vulnerable
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
            return  # 같은 안내물의 응답은 다시 부르지 않는다
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
        counts: dict[str, list[int]] = {}
        for row in result["rows"]:
            if row["defect_behavior_removed"] != "not_measured":
                slot = counts.setdefault(rule_of[row["id"]], [0, 0])
                slot[1] += 1
                slot[0] += row["defect_behavior_removed"] == "pass"
        by_rule[variant] = {rule: f"{removed}/{measured}" for rule, (removed, measured) in sorted(counts.items())}
    outcomes = {v: {r["id"]: r["outcome"] for r in results[v]["rows"]} for v in VARIANTS}
    comparison = {}
    for variant in VARIANTS:
        if variant == BASELINE:
            continue
        changed = [
            {"id": name, "baseline": outcomes[BASELINE][name], "variant": outcomes[variant][name]}
            for name in rule_of
            if outcomes[BASELINE][name] != outcomes[variant][name]
        ]
        transitions = Counter(
            ("resolved" if c["baseline"] == "resolved" else "other") + "->" + ("resolved" if c["variant"] == "resolved" else "other")
            for c in changed
        )
        comparison[variant] = {
            "changed_cases": changed,
            "transitions": dict(transitions),
            "resolved_only_in_variant": sorted(c["id"] for c in changed if c["baseline"] != "resolved" and c["variant"] == "resolved"),
            "resolved_only_in_baseline": sorted(c["id"] for c in changed if c["baseline"] == "resolved" and c["variant"] != "resolved"),
        }
    return {
        "cases": len(cases),
        "baseline": BASELINE,
        "summary": {v: {k: results[v][k] for k in ("outcomes", "static_resolved_rate", "behavior_removed_rate", "success_rate")} for v in VARIANTS},
        "behavior_removed_by_rule": by_rule,
        "comparison_with_baseline": comparison,
        "rows": {v: results[v]["rows"] for v in VARIANTS},
    }


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    options = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    if not args or len(args) > 2:
        print(__doc__)
        return 2
    work = Path(args[0])
    out = Path(args[1]) if len(args) == 2 else None
    work.mkdir(parents=True, exist_ok=True)
    cases = prepare(work)
    if "--prepare-only" in sys.argv:
        print(json.dumps({"cases": len(cases), "prompts": sorted(p.name for p in (work / "prompts").glob("*.txt"))[:8]}, ensure_ascii=False, indent=2))
        return 0
    if "ai-cmd" not in options:
        print(__doc__)
        return 2
    generate(work, cases, options["ai-cmd"], int(options.get("jobs", "4")))
    paths = manifests(work, cases)
    results = {v: verify_cases(paths[v], options.get("runner", "auto")) for v in VARIANTS}
    record = {"ai_cmd": options["ai-cmd"], "runner": options.get("runner", "auto"), **summarize(cases, results)}
    if out is not None:
        out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: record[k] for k in ("cases", "summary", "behavior_removed_by_rule", "comparison_with_baseline")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
