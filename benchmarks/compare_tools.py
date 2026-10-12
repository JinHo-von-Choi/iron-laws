"""
경쟁 도구 동일 조건 비교: 같은 사례 묶음을 오철칙·Semgrep·CodeQL로 점검하고 같은 기준으로 센다

사용법:
    uv run python benchmarks/compare_tools.py <작업 폴더> [--semgrep "uvx --from semgrep==1.180.0 semgrep"] [--codeql <codeql 실행 파일>] [원시결과.json]

사례(의미 변형 사례집 tests/semantic_corpus.py·semantic_holdout.py의 Python·JavaScript·TypeScript·Java 사례):
개발용 사례는 오철칙을 만들며 맞춘 사례라 오철칙에 유리하다. 결과는 전체와 평가용(holdout)을 나눠 쓰며, 공정한 비교는 평가용이다.
- risky: 외부 입력이 위험 호출에 닿는 코드(정답: 탐지)
- benign: 같은 모양이지만 정제·허용 목록·인자 배열 등으로 안전한 코드(정답: 탐지 안 함)
- bypass: risky의 외부 입력 읽기를 다른 파일의 함수로 옮긴 코드. 동작은 risky와 같다(정답: 탐지. 탐지하면 우회 수정을 거부한 것)
도구의 결과는 사례 주 파일의 지적 중 사례 규칙의 CWE와 같은 CWE가 붙은 것만 센다. 오철칙은 확정 지적만 탐지로 세고,
위험 사례를 확정하지 못했지만 확인 필요 지적이나 근거 공백으로 드러낸 비율을 따로 센다.
규칙팩·버전·실행 시간을 결과에 함께 남긴다. 사례가 합성 코드라는 한계가 있다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.semantic_corpus import DEV_SCAN, render, xf_source_helper  # noqa: E402
from tests.semantic_holdout import HOLDOUT_SCAN  # noqa: E402

RULE_CWE = {"IL-501": {89}, "IL-502": {22, 23, 36, 73}, "IL-503": {94, 95}, "IL-504": {77, 78}, "IL-505": {79, 80}, "IL-506": {918}, "IL-508": {90}, "IL-511": {113}, "IL-527": {643}}
LANG = {".py": "python", ".js": "javascript", ".ts": "javascript", ".java": "java"}


def materialize(work: Path) -> list[dict]:
    cases = []
    holdout_ids = {c.id for c in HOLDOUT_SCAN}
    for case in [*DEV_SCAN, *HOLDOUT_SCAN]:
        if case.ext not in LANG or case.rule not in RULE_CWE:
            continue
        forms = {"risky": (render(case.risky, case.ext), {}), "benign": (render(case.benign, case.ext), {})}
        bypass = xf_source_helper(render(case.risky, case.ext), case.ext)
        if bypass is not None:
            forms["bypass"] = bypass
        for form, (code, extra) in forms.items():
            folder = work / LANG[case.ext] / f"{case.id}__{form}"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"app{case.ext}").write_text(code, encoding="utf-8")
            for name, text in {**case.files, **extra}.items():
                (folder / name).write_text(text, encoding="utf-8")
            split = "holdout" if case.id in holdout_ids else "dev"
            cases.append({"id": case.id, "form": form, "rule": case.rule, "lang": LANG[case.ext], "split": split, "dir": folder.relative_to(work).as_posix(), "main": f"app{case.ext}"})
    return cases


def _cwe_numbers(tags) -> set[int]:
    found = set()
    for tag in tags or []:
        text = str(tag).lower()
        for part in text.replace("external/cwe/", "").replace("cwe-", " ").replace(":", " ").split():
            if part.isdigit():
                found.add(int(part))
    return found


def run_iron_laws(work: Path, cases: list[dict]) -> tuple[dict, dict]:
    from iron_laws.core.scanner import AuditScanner, tool_version

    started = time.perf_counter()
    hits: dict[str, str] = {}
    for c in cases:
        report = AuditScanner(work / c["dir"]).scan()
        mine = [v for v in report.violations if v.rule_id == c["rule"] and v.file_path.as_posix() == c["main"]]
        gaps = [p for p in (report.coverage_ledger.points if report.coverage_ledger else []) if p.path == c["main"] and p.state in ("unsupported", "unresolved", "budget_exceeded")]
        if any(v.confidence.value == "CONFIRMED" for v in mine):
            hits[c["dir"]] = "detected"
        elif mine or gaps:
            hits[c["dir"]] = "surfaced"
        else:
            hits[c["dir"]] = "missed"
    return hits, {"tool": "iron-laws", "version": tool_version(), "config": "기본 규칙(확정 지적만 탐지로 셈)", "seconds": round(time.perf_counter() - started, 1)}


def run_semgrep(work: Path, cases: list[dict], command: str) -> tuple[dict, dict]:
    started = time.perf_counter()
    out = work / "semgrep.json"
    argv = [*shlex.split(command), "scan", "--config", "p/default", "--json", "--metrics", "off", "--quiet", "-o", str(out), str(work)]
    subprocess.run(argv, capture_output=True, text=True, timeout=3600)
    data = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else {"results": []}
    version = subprocess.run([*shlex.split(command), "--version"], capture_output=True, text=True).stdout.strip()
    by_file: dict[str, set[int]] = {}
    for r in data.get("results", []):
        path = Path(r["path"]).resolve().relative_to(work.resolve()).as_posix()
        meta = (r.get("extra") or {}).get("metadata") or {}
        by_file.setdefault(path, set()).update(_cwe_numbers(meta.get("cwe") if isinstance(meta.get("cwe"), list) else [meta.get("cwe")]))
    hits = {c["dir"]: ("detected" if by_file.get(f"{c['dir']}/{c['main']}", set()) & RULE_CWE[c["rule"]] else "missed") for c in cases}
    return hits, {"tool": "semgrep", "version": version, "config": "p/default(레지스트리, 실행 시점 규칙)", "seconds": round(time.perf_counter() - started, 1), "errors": len(data.get("errors", []))}


def run_codeql(work: Path, cases: list[dict], codeql: str) -> tuple[dict, dict]:
    started = time.perf_counter()
    by_file: dict[str, set[int]] = {}
    version = subprocess.run([codeql, "version", "--format=terse"], capture_output=True, text=True).stdout.strip()
    for lang in sorted({c["lang"] for c in cases}):
        db = work / f"codeql-db-{lang}"
        create = [codeql, "database", "create", str(db), f"--language={lang}", f"--source-root={work / lang}", "--overwrite"]
        if lang == "java":
            create.append("--build-mode=none")
        subprocess.run(create, capture_output=True, text=True, timeout=3600)
        sarif = work / f"codeql-{lang}.sarif"
        subprocess.run([codeql, "database", "analyze", str(db), f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls", "--format=sarif-latest", f"--output={sarif}", "--threads=0"], capture_output=True, text=True, timeout=3600)
        if not sarif.is_file():
            continue
        data = json.loads(sarif.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            rules = {r["id"]: r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
            for res in run.get("results", []):
                rule = rules.get(res.get("ruleId"), {})
                tags = (rule.get("properties") or {}).get("tags") or []
                for loc in res.get("locations", []):
                    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                    by_file.setdefault(f"{lang}/{uri}", set()).update(_cwe_numbers(tags))
    hits = {c["dir"]: ("detected" if by_file.get(f"{c['dir']}/{c['main']}", set()) & RULE_CWE[c["rule"]] else "missed") for c in cases}
    return hits, {"tool": "codeql", "version": version, "config": "<언어>-security-extended.qls(번들 기본 쿼리팩), Java는 build-mode=none", "seconds": round(time.perf_counter() - started, 1)}


def summarize(cases: list[dict], hits: dict) -> dict:
    return {"all": _summary(cases, hits), "holdout": _summary([c for c in cases if c["split"] == "holdout"], hits)}


def _summary(cases: list[dict], hits: dict) -> dict:
    def rate(form: str, outcome: str) -> tuple[int, int]:
        rows = [c for c in cases if c["form"] == form]
        return sum(1 for c in rows if hits.get(c["dir"]) == outcome), len(rows)

    risky_hit, risky_n = rate("risky", "detected")
    benign_hit, benign_n = rate("benign", "detected")
    bypass_hit, bypass_n = rate("bypass", "detected")
    surfaced, _ = rate("risky", "surfaced")
    return {
        "risky_detected": f"{risky_hit}/{risky_n}",
        "benign_flagged": f"{benign_hit}/{benign_n}",
        "bypass_rejected": f"{bypass_hit}/{bypass_n}",
        "missed_but_surfaced_as_unknown": f"{surfaced}/{risky_n - risky_hit}",
    }


def main(work: Path, semgrep: str | None, codeql: str | None, raw: Path | None) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    work.mkdir(parents=True, exist_ok=True)
    cases = materialize(work)
    results = {}
    runners = [("iron-laws", lambda: run_iron_laws(work, cases))]
    if semgrep:
        runners.append(("semgrep", lambda: run_semgrep(work, cases, semgrep)))
    if codeql:
        runners.append(("codeql", lambda: run_codeql(work, cases, codeql)))
    for name, run in runners:
        hits, info = run()
        results[name] = {**info, **summarize(cases, hits), "per_case": hits}
        print(name, {k: v for k, v in results[name].items() if k != "per_case"}, flush=True)
    if raw is not None:
        raw.write_text(json.dumps({"cases": len(cases), "results": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    args = sys.argv[1:]
    semgrep_cmd = args[args.index("--semgrep") + 1] if "--semgrep" in args else None
    codeql_bin = args[args.index("--codeql") + 1] if "--codeql" in args else None
    positional = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] not in ("--semgrep", "--codeql"))]
    if not positional:
        print(__doc__)
        sys.exit(2)
    main(Path(positional[0]), semgrep_cmd, codeql_bin, Path(positional[1]) if len(positional) > 1 else None)
