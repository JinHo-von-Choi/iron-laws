"""
오철칙 AI 수정 성공률 측정기(benchmarks/fix_loop.py) 분류 시험: 정상 수정·우회·미해결·신규 지적·신규 부채를 구분한다
작성자: 최진호
작성일: 2026-10-12
"""

import difflib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))

from fix_loop import run  # noqa: E402

ORIGINAL = "import os\nimport subprocess\nfrom flask import request\n\n\ndef run():\n    name = request.args['d']\n    os.system('ls ' + name)\n    return 'ok'\n"
FIXES = {
    "proper": ORIGINAL.replace("    os.system('ls ' + name)\n", "    subprocess.run(['ls', name], check=False)\n"),
    "suppressed": ORIGINAL.replace("    os.system('ls ' + name)\n", "    os.system('ls ' + name)  # iron-laws: ignore[IL-504]\n"),
    "unrelated": ORIGINAL.replace("    return 'ok'\n", "    return 'done'\n"),
    "new-finding": ORIGINAL.replace("    os.system('ls ' + name)\n", "    subprocess.run(['ls', name], check=False)\n    eval(request.args['x'])\n"),
    "swallowed": ORIGINAL.replace("    os.system('ls ' + name)\n", "    try:\n        subprocess.run(['ls', name], check=False)\n    except Exception:\n        pass\n"),
}


def test_outcomes_are_classified(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(ORIGINAL, encoding="utf-8")
    cases = []
    for name, fixed in FIXES.items():
        patch = "".join(difflib.unified_diff(ORIGINAL.splitlines(True), fixed.splitlines(True), "a/app.py", "b/app.py"))
        (tmp_path / f"{name}.diff").write_text(patch, encoding="utf-8")
        cases.append({"id": name, "project": "proj", "patch": f"{name}.diff", "finding": "IL-504@app.py:8"})
    (tmp_path / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
    result = run(tmp_path / "cases.json", runner="none")
    outcome = {r["id"]: r["outcome"] for r in result["rows"]}
    assert outcome["proper"] == "resolved"
    assert outcome["suppressed"] == "bypass"
    assert outcome["unrelated"] == "static_not_resolved"
    assert outcome["swallowed"] == "resolved_with_new_debt"
    assert outcome["new-finding"] == "new_findings"  # 대상 지적이 사라져도 새 HIGH 이상 지적을 만들면 해결로 세지 않는다
    assert result["behavior_removed_rate"] is None  # 회귀 명세가 없으면 결함 행동 제거는 측정하지 않는다
    assert result["success_rate"] == 0.2
