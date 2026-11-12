"""
AI 수정 지시문 비교 실험이 함께 쓰는 단계: 지시문마다 AI 명령을 불러 응답을 받고, 응답을 패치 검증 목록으로 바꾼다.
작성자: 최진호
작성일: 2026-11-12
"""

import difflib
import json
import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def generate(work: Path, cases: list[dict], ai_cmd: str, jobs: int, variants: tuple[str, ...]) -> None:
    """prompts/의 지시문마다 AI 명령을 불러 raw/에 응답을 남긴다. 같은 지시문의 응답이 이미 있으면 다시 부르지 않는다."""
    (work / "raw").mkdir(exist_ok=True)
    (work / "cwd").mkdir(exist_ok=True)

    def one(name: str, variant: str) -> None:
        prompt = (work / "prompts" / f"{name}.{variant}.txt").read_text(encoding="utf-8")
        out = work / "raw" / f"{name}.{variant}.txt"
        stamp = work / "raw" / f"{name}.{variant}.prompt"
        if out.is_file() and stamp.is_file() and stamp.read_text(encoding="utf-8") == prompt:
            return
        done = subprocess.run(shlex.split(ai_cmd), input=prompt, capture_output=True, text=True, cwd=work / "cwd", timeout=900)
        out.write_text(done.stdout, encoding="utf-8")
        stamp.write_text(prompt, encoding="utf-8")

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(lambda job: one(*job), [(c["name"], v) for c in cases for v in variants]))  # iron-laws: ignore[PERF-102] variants는 비교할 지시문 방식 이름 몇 개다


def manifests(work: Path, cases: list[dict], variants: tuple[str, ...]) -> dict[str, Path]:
    """응답의 마지막 코드 블록을 원본 app.py와 비교한 패치로 만들고, 방식별 패치 검증 목록(manifest)을 쓴다."""
    paths = {}
    for variant in variants:
        rows = []
        for c in cases:  # iron-laws: ignore[PERF-102] variants는 비교할 지시문 방식 이름 몇 개다
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
