"""
CWEval(기능과 보안을 함께 평가하는 LLM 코드 생성 평가 세트) 사례로 오철칙의 탐지·오탐을 잰다.

사용법:
    git clone --depth 1 https://github.com/Co1lin/CWEval.git <폴더>
    uv run python benchmarks/cweval.py <폴더> [--langs py,js,go] [-o docs/benchmark_results/cweval.json]

사례(CWEval의 Apache-2.0 데이터. 저장소에 복사하지 않고 내려받은 폴더에서 읽는다):
- 취약 사례: Python은 `*_test.py`의 `*_unsafe` 함수, JavaScript·Go는 `*_unsafe.*` 파일. 정답은 사례의 CWE와 같은 CWE가 붙은 지적이다.
- 안전 사례: `*_task.*`의 `BEGIN SOLUTION` 이후 참조 구현. 정답은 사례의 CWE와 같은 CWE가 붙은 지적이 없는 것이다.
결과는 같은 CWE의 지적(확정·확인 필요 전체)과 확정 지적을 따로 세고, 같은 CWE의 지적은 없지만 다른 규칙의 지적이 있는 취약 사례 수(`unsafe_only_other_cwe`)도 남긴다.
CWE 번호는 지적의 기준 팩 항목과 행안부 항목 설명의 `(CWE-n)` 표기에서 읽는다. 사례는 함수 하나짜리라 프레임워크 연결이 빠져 있고,
CWEval이 재는 기능·보안 동시 통과율(Func-Sec)은 오철칙이 재는 대상이 아니므로 쓰지 않는다.
작성자: 최진호
작성일: 2026-11-10
"""

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from iron_laws.core.scanner import AuditScanner, tool_version  # noqa: E402

CASE_DIR = Path("benchmark") / "core"
EXTENSIONS = {"py": ".py", "js": ".js", "go": ".go"}
CWE_RE = re.compile(r"cwe_0*(\d+)_(\d+)")
SKIPPED_IMPORTS = {"pytest"}


def _cwe_of(name: str) -> int | None:
    match = CWE_RE.search(name)
    return int(match.group(1)) if match else None


def python_unsafe_source(test_file: Path) -> str | None:
    """`*_test.py`에서 `*_unsafe` 함수와 그 함수가 쓸 수 있는 import·상수·도우미 함수만 뽑는다(시험 함수·안전 구현 제외)."""
    text = test_file.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        print(f"건너뜀: {test_file.name} 문법 오류 ({exc.msg})", file=sys.stderr)
        return None
    parts: list[str] = []
    has_unsafe = False
    for node in tree.body:
        segment = ast.get_source_segment(text, node) or ""
        if isinstance(node, ast.Import):
            if not any(alias.name.split(".")[0] in SKIPPED_IMPORTS for alias in node.names):
                parts.append(segment)
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module not in SKIPPED_IMPORTS and not module.startswith("cwe_"):
                parts.append(segment)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith(("test", "_test")) or node.name.endswith("_safe"):
                continue
            has_unsafe = has_unsafe or node.name.endswith("_unsafe")
            parts.append(segment)
        elif isinstance(node, ast.Assign) and not any(isinstance(t, ast.Name) and t.id.startswith("pytest") for t in node.targets):
            parts.append(segment)
    return "\n\n".join(parts) + "\n" if has_unsafe else None


def collect_cases(dataset: Path, languages: list[str]) -> list[dict]:
    cases: list[dict] = []
    for lang in languages:
        folder = dataset / CASE_DIR / lang
        if not folder.is_dir():
            continue
        extension = EXTENSIONS[lang]
        for task in sorted(folder.glob(f"cwe_*_task{extension}")):
            stem = task.name.split("_task")[0]
            cwe = _cwe_of(stem)
            if cwe is None:
                continue
            safe = task.read_text(encoding="utf-8", errors="replace")
            if "BEGIN SOLUTION" in safe:
                safe = safe.split("BEGIN SOLUTION", 1)[1]
            if lang == "py":
                unsafe = python_unsafe_source(folder / f"{stem}_test.py")
            else:
                path = folder / f"{stem}_unsafe{extension}"
                unsafe = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else None
            cases.append({"id": f"{stem}-{lang}", "lang": lang, "cwe": cwe, "kind": "safe", "source": safe, "extension": extension})
            if unsafe is not None:
                cases.append({"id": f"{stem}-{lang}", "lang": lang, "cwe": cwe, "kind": "unsafe", "source": unsafe, "extension": extension})
    return cases


def cwes_of(violation) -> set[int]:
    """지적에 붙은 CWE 번호. 기준 팩의 CWE 항목과 행안부 항목 설명의 `(CWE-n, …)` 표기를 모두 읽는다."""
    found = {int(m) for s in violation.standards for m in re.findall(r"^CWE-(\d+)$", s.item_id)}
    gov = violation.gov_standard
    if gov is not None:
        found |= {int(m) for m in re.findall(r"CWE-(\d+)", f"{gov.clause_id} {gov.description}")}
    return found


def scan_case(case: dict, work: Path) -> dict:
    folder = work / f"{case['kind']}-{case['id']}"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"app{case['extension']}").write_text(case["source"], encoding="utf-8")
    report = AuditScanner(folder).scan()
    same = [v for v in report.violations if case["cwe"] in cwes_of(v)]
    return {
        "id": case["id"],
        "lang": case["lang"],
        "cwe": case["cwe"],
        "kind": case["kind"],
        "same_cwe": sorted({v.rule_id for v in same}),
        "same_cwe_confirmed": sorted({v.rule_id for v in same if v.confidence.value == "CONFIRMED"}),
        "other_rules": sorted({v.rule_id for v in report.violations if case["cwe"] not in cwes_of(v)}),
    }


def summarize(results: list[dict]) -> dict:
    summary: dict[str, dict] = {}
    for lang in sorted({r["lang"] for r in results}):
        rows = [r for r in results if r["lang"] == lang]
        unsafe = [r for r in rows if r["kind"] == "unsafe"]
        safe = [r for r in rows if r["kind"] == "safe"]
        summary[lang] = {
            "unsafe_cases": len(unsafe),
            "unsafe_detected_same_cwe": sum(1 for r in unsafe if r["same_cwe"]),
            "unsafe_detected_confirmed": sum(1 for r in unsafe if r["same_cwe_confirmed"]),
            "unsafe_only_other_cwe": sum(1 for r in unsafe if not r["same_cwe"] and r["other_rules"]),
            "safe_cases": len(safe),
            "safe_flagged_same_cwe": sum(1 for r in safe if r["same_cwe"]),
            "safe_flagged_confirmed": sum(1 for r in safe if r["same_cwe_confirmed"]),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("dataset", type=Path, help="내려받은 CWEval 폴더")
    parser.add_argument("--langs", default="py,js,go", help="쉼표로 구분한 언어(py, js, go)")
    parser.add_argument("-o", "--output", type=Path, default=ROOT / "docs" / "benchmark_results" / "cweval.json")
    args = parser.parse_args()
    languages = [name.strip() for name in args.langs.split(",") if name.strip() in EXTENSIONS]
    cases = collect_cases(args.dataset, languages)
    if not cases:
        print("사례를 찾지 못했습니다. CWEval 폴더와 --langs를 확인하십시오.", file=sys.stderr)
        return 2
    commit = subprocess.run(["git", "-C", str(args.dataset), "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603, S607
    with tempfile.TemporaryDirectory() as tmp:
        results = [scan_case(case, Path(tmp)) for case in cases]
    payload = {"dataset": "CWEval", "dataset_commit": commit, "tool_version": tool_version(), "summary": summarize(results), "cases": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
