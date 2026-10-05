"""
의존성 권고 판정을 OSV 서버의 판정과 대조한다(교차 대조).

사용법:
    uv run python benchmarks/deps_osv_crosscheck.py [결과.json] [--db 저장폴더]

대상 패키지마다 (1) OSV에서 그 패키지의 모든 권고를 받아 오프라인 DB 폴더로 저장하고, (2) 배포된 버전 가운데 일부(권고 경계 버전 포함)를 골라
(3) 우리 해석기가 영향 아래라고 보는 권고 묶음과 OSV 서버(`/v1/querybatch`)가 영향 아래라고 보는 권고 묶음을 비교한다.
별칭(GHSA·CVE·PYSEC)은 같은 권고로 합쳐 센다. 이 측정은 판정 일치를 보며 탐지 성능이나 우위를 주장하지 않는다.
네트워크가 필요하다(PyPI·npm 레지스트리, api.osv.dev). 표본 패키지는 개발팀이 골랐다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
import random
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from iron_laws.deps.osv import AdvisoryDb, _add, is_affected  # noqa: E402
from iron_laws.deps.versions import normalize_name, parse_version  # noqa: E402

PACKAGES = {
    "PyPI": ["requests", "urllib3", "django", "jinja2", "pyyaml", "flask", "pillow", "cryptography", "werkzeug", "numpy"],
    "npm": ["lodash", "minimist", "express", "axios", "jsonwebtoken", "semver", "moment", "ws", "tar", "node-fetch"],
}
VERSIONS_PER_PACKAGE = 40


def get(url: str, data: dict | None = None):
    request = urllib.request.Request(url, data=json.dumps(data).encode() if data else None, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def advisories_of(ecosystem: str, name: str) -> list[dict]:
    ids: list[str] = []
    token = None
    while True:
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if token:
            body["page_token"] = token
        page = get("https://api.osv.dev/v1/query", body)
        ids += [v["id"] for v in page.get("vulns") or []]
        token = page.get("next_page_token")
        if not token:
            break
    return [get(f"https://api.osv.dev/v1/vulns/{i}") for i in sorted(set(ids))]


def releases(ecosystem: str, name: str) -> list[str]:
    if ecosystem == "PyPI":
        return list(get(f"https://pypi.org/pypi/{name}/json")["releases"].keys())
    return list(get(f"https://registry.npmjs.org/{name}")["versions"].keys())


def canonical(groups: list[set[str]], ids: set[str]) -> frozenset[int]:
    return frozenset(i for i, g in enumerate(groups) if g & ids)


def main() -> None:
    args = sys.argv[1:]
    db_dir = Path("/tmp/iron-laws-osv-db")
    if "--db" in args:
        db_dir = Path(args[args.index("--db") + 1])
        del args[args.index("--db") : args.index("--db") + 2]
    out = Path(args[0]) if args else ROOT / "docs" / "benchmark_results" / "deps_osv_crosscheck.json"
    rng = random.Random(20261005)
    rows, summary = [], {}
    for ecosystem, names in PACKAGES.items():
        for name in names:
            raws = advisories_of(ecosystem, name)
            folder = db_dir / ecosystem / name
            folder.mkdir(parents=True, exist_ok=True)
            db = AdvisoryDb()
            for raw in raws:
                (folder / f"{raw['id']}.json").write_text(json.dumps(raw), encoding="utf-8")
                _add(db, raw)
            groups: list[set[str]] = []
            for raw in raws:
                names_ = {raw["id"], *raw.get("aliases", [])}
                merged = [g for g in groups if g & names_]
                for g in merged:
                    groups.remove(g)
                groups.append(set().union(names_, *merged))
            all_versions = [v for v in releases(ecosystem, name) if parse_version(ecosystem, v) is not None]
            boundary = {value for raw in raws for item in raw.get("affected", []) for r in item.get("ranges", []) for e in r.get("events", []) for value in e.values() if value != "0"}
            boundary_present = [v for v in all_versions if v in boundary]
            pool = [v for v in all_versions if v not in set(boundary_present)]
            sample = sorted(set(boundary_present[:15] + rng.sample(pool, min(VERSIONS_PER_PACKAGE - min(15, len(boundary_present)), len(pool)))))
            truth = get(
                "https://api.osv.dev/v1/querybatch",
                {"queries": [{"package": {"name": name, "ecosystem": ecosystem}, "version": v} for v in sample]},
            )["results"]
            exact = 0
            tp = fp = fn = 0
            git_explained = 0  # 우리가 놓친 권고 중, GIT 범위(introduced 0)가 있어 OSV 서버가 옛 버전까지 영향 아래로 본 것
            diffs = []
            raw_by_id = {raw["id"]: raw for raw in raws}
            for version, result in zip(sample, truth, strict=True):
                theirs = canonical(groups, {v["id"] for v in result.get("vulns") or []})
                ours_ids = {a.id for a, aff in db.for_package(ecosystem, name) if is_affected(aff, version) is True}
                ours = canonical(groups, ours_ids)
                tp += len(ours & theirs)
                fp += len(ours - theirs)
                fn += len(theirs - ours)
                for vid in {v["id"] for v in result.get("vulns") or []}:
                    if canonical(groups, {vid}) <= (theirs - ours):
                        raw = raw_by_id.get(vid, {})
                        has_git_zero = any(r.get("type") == "GIT" and {"introduced": "0"} in r.get("events", []) for item in raw.get("affected", []) for r in item.get("ranges", []))
                        git_explained += 1 if has_git_zero else 0
                if ours == theirs:
                    exact += 1
                else:
                    diffs.append({"version": version, "only_ours": len(ours - theirs), "only_osv": len(theirs - ours)})
            rows.append({"ecosystem": ecosystem, "package": normalize_name(ecosystem, name), "advisories": len(raws), "versions": len(sample), "exact": exact, "tp": tp, "fp": fp, "fn": fn, "fn_with_git_range": git_explained, "differences": diffs[:5]})
        eco = [r for r in rows if r["ecosystem"] == ecosystem]
        summary[ecosystem] = {
            "packages": len(eco),
            "versions": sum(r["versions"] for r in eco),
            "exact_version_agreement": round(sum(r["exact"] for r in eco) / max(sum(r["versions"] for r in eco), 1), 4),
            "tp": sum(r["tp"] for r in eco),
            "fp": sum(r["fp"] for r in eco),
            "fn": sum(r["fn"] for r in eco),
            "fn_with_git_range": sum(r["fn_with_git_range"] for r in eco),
        }
    out.write_text(json.dumps({"note": "OSV 서버 판정과의 일치 측정이다. 표본 패키지는 개발팀이 골랐고 탐지 성능이나 우위의 증거가 아니다.", "summary": summary, "rows": rows}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
