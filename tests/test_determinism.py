"""
오철칙 결정론 게이트: 같은 코드는 작업 경로·환경·해시 씨앗·병렬 처리 여부와 무관하게 같은 보고서(정규화 투영)를 낸다
원시 바이트 동일은 요구하지 않는다. 제외 목록(IGNORED_POINTERS)의 값만 달라질 수 있다.
작성자: 최진호
작성일: 2026-10-05
"""
# iron-laws: ignore-file[IL-101] 시험 입력으로 쓰는 무효 합성 비밀값이다

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from iron_laws.core.canonical import IGNORED_POINTERS, canonical_projection, projection_digest

FIXTURE = {
    "web/app.py": 'import os\nfrom flask import request\n\ndef run():\n    os.system("ls " + request.args["d"])\n    token = "AbCdEf123456GhIjKl7890"\n',
    "web/한글 폴더/util.py": "def helper(x):\n    return x + 1\n\ndef helper2(x):\n    return x + 1\n",
    "ui/a.js": 'const cfg = { "token": "Zq9xKm2LpQw8RtYuVn4B", mode: eval(userInput) };\n',
    "ci/deploy.yml": "key: 'it''s fine'\npassword: hunter2hunter2hunter2\n",
}


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def _audit(project: Path, cwd: Path, env_extra: dict[str, str]) -> dict:
    env = {**os.environ, **env_extra}
    result = subprocess.run(
        [sys.executable, "-c", "import sys; from iron_laws.cli import app; sys.exit(app())", "audit", str(project), "--format", "json", "--limit", "0", "--allow-empty"],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=600,
    )
    assert result.returncode in (0, 1), result.stderr[-500:]
    return json.loads(result.stdout)


def test_projection_removes_only_the_listed_pointers():
    report = {"document_id": "A", "audit_date": "d", "target_path": "/x", "metadata": {"repo_relative_prefix": "p", "config_source": "c", "keep": 1}, "violations": [{"line_number": 3}]}
    assert json.loads(canonical_projection(report)) == {"metadata": {"keep": 1}, "violations": [{"line_number": 3}]}
    assert projection_digest(report) == projection_digest({**report, "document_id": "B", "target_path": "/y"})
    assert projection_digest(report) != projection_digest({**report, "violations": [{"line_number": 4}]})
    assert all(reason for _pointer, reason in IGNORED_POINTERS)  # 제외 목록의 모든 항목은 사유를 가진다


def test_the_projection_is_key_order_independent():
    assert canonical_projection({"b": 1, "a": {"d": 1, "c": 2}}) == canonical_projection({"a": {"c": 2, "d": 1}, "b": 1})


@pytest.mark.parametrize("many_files", [False, True], ids=["serial", "parallel-eligible"])
def test_the_same_code_gives_the_same_report_in_different_environments(tmp_path: Path, many_files: bool):
    files = dict(FIXTURE)
    if many_files:  # 파일 수가 병렬 처리 기준을 넘도록 채운다
        files.update({f"pkg/m{i}.py": f"def f{i}(x):\n    return x + {i}\n" for i in range(320)})
    first, second = tmp_path / "one" / "deeper" / "proj", tmp_path / "two" / "p"
    _write(first, files)
    shutil.copytree(first, second)
    a = _audit(first, tmp_path, {"TZ": "UTC", "PYTHONHASHSEED": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    b = _audit(second, second, {"TZ": "Asia/Seoul", "PYTHONHASHSEED": "7", "LANG": "C", "LC_ALL": "C"})
    assert a["summary"]["scan_status"] == b["summary"]["scan_status"] == "complete"
    assert canonical_projection(a) == canonical_projection(b)
    assert a["target_path"] != b["target_path"]  # 제외 대상의 값은 실제로 달랐다


def test_a_changed_file_changes_the_projection(tmp_path: Path):
    project = tmp_path / "proj"
    _write(project, FIXTURE)
    before = _audit(project, tmp_path, {})
    (project / "web" / "app.py").write_text('import os\nfrom flask import request\n\ndef run():\n    os.system("ls")\n', encoding="utf-8")
    after = _audit(project, tmp_path, {})
    assert projection_digest(before) != projection_digest(after)
