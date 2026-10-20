"""
교훈 저장소 시험
작성자: 최진호
작성일: 2026-10-20
"""

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.experience import (
    STATE_ACTIVE,
    STATE_INVALID,
    STATE_STALE,
    ExperienceStore,
    rule_note,
    spec_fragment_entries,
)

runner = CliRunner()

SPEC = {
    "version": 1,
    "sanitizers": [
        {
            "id": "esc",
            "family": "command",
            "context": "shell",
            "languages": ["python"],
            "name": r"(^|\.)esc\b",
            "positive": "import subprocess\nfrom flask import request\ndef h():\n    cmd = request.args['d']\n    subprocess.run(cmd, shell=True)\n",
            "negative": "import subprocess\ndef h():\n    subprocess.run('ls', shell=True)\n",
        }
    ],
}


def _spec_file(tmp_path: Path) -> Path:
    path = tmp_path / "spec.yml"
    path.write_text(yaml.safe_dump(SPEC, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return path


def test_명세_항목이_교훈으로_남는다(tmp_path: Path):
    spec = _spec_file(tmp_path)
    store = ExperienceStore(tmp_path / "exp.jsonl")

    entries = spec_fragment_entries(spec, "esc는 셸 인자를 그대로 넘기지 않는다", {"IL-504": 3})
    for entry in entries:
        store.add(entry)

    items = store.entries(rule_versions={"IL-504": 3})
    assert len(items) == 1
    assert items[0].state == STATE_ACTIVE
    assert items[0].entry.lesson == "esc는 셸 인자를 그대로 넘기지 않는다"
    assert items[0].entry.rule_id == "IL-504"
    assert items[0].entry.basis["rule_version"] == 3
    assert items[0].entry.evidence["spec_digest"]


def test_규칙_버전이_바뀌면_다시_볼_것이_된다(tmp_path: Path):
    spec = _spec_file(tmp_path)
    store = ExperienceStore(tmp_path / "exp.jsonl")
    for entry in spec_fragment_entries(spec, "교훈", {"IL-504": 3}):
        store.add(entry)

    items = store.entries(rule_versions={"IL-504": 4})

    assert items[0].state == STATE_STALE
    assert "바뀌었다" in items[0].reason


def test_무효로_만든_교훈은_사라진다(tmp_path: Path):
    store = ExperienceStore(tmp_path / "exp.jsonl")
    entry = rule_note("IL-504", "틀린 고치기", {"IL-504": 3})
    store.add(entry)

    store.invalidate(entry.id, "실제로는 문제가 없었다")

    items = store.entries(rule_versions={"IL-504": 3})
    assert items[0].state == STATE_INVALID
    assert items[0].reason == "실제로는 문제가 없었다"


def test_기록을_고치면_연결이_끊긴다(tmp_path: Path):
    path = tmp_path / "exp.jsonl"
    store = ExperienceStore(path)
    store.add(rule_note("IL-504", "교훈 하나", {"IL-504": 3}))
    store.add(rule_note("IL-504", "교훈 둘", {"IL-504": 3}))

    assert ExperienceStore(path).verify_chain() == []

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["reason"] = "고쳐 쓴 기록"
    lines[0] = json.dumps(record, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    problems = ExperienceStore(path).verify_chain()
    assert problems
    assert any("해시" in item for item in problems)


def test_명령으로_교훈을_남기고_보인다(tmp_path: Path):
    spec = _spec_file(tmp_path)
    store_file = tmp_path / "exp.jsonl"

    added = runner.invoke(app, ["experience", "add", "--spec", str(spec), "--lesson", "이 프로젝트의 esc를 신뢰한다", "--file", str(store_file)])
    assert added.exit_code == 0

    listed = runner.invoke(app, ["experience", "list", "--file", str(store_file)])
    assert listed.exit_code == 0
    assert "이 프로젝트의 esc를 신뢰한다" in listed.output

    verified = runner.invoke(app, ["experience", "verify", "--file", str(store_file)])
    assert verified.exit_code == 0


def test_명령은_명세와_규칙_중_하나만_받는다(tmp_path: Path):
    spec = _spec_file(tmp_path)
    store_file = tmp_path / "exp.jsonl"

    both = runner.invoke(app, ["experience", "add", "--spec", str(spec), "--rule", "IL-504", "--lesson", "x", "--file", str(store_file)])
    assert both.exit_code == 2

    neither = runner.invoke(app, ["experience", "add", "--lesson", "x", "--file", str(store_file)])
    assert neither.exit_code == 2


def test_명세_초안_지시문에_교훈이_들어간다(tmp_path: Path):
    from iron_laws.core.spec_draft import llm_prompt

    prompt = llm_prompt({"version": 1}, [], lessons=["이 프로젝트의 esc는 이미 확인했다"])

    assert "이 프로젝트의 esc는 이미 확인했다" in prompt
    assert "교훈" in prompt


def test_초안_지시문은_교훈이_없으면_그대로다(tmp_path: Path):
    from iron_laws.core.spec_draft import llm_prompt

    plain = llm_prompt({"version": 1}, [])
    with_lessons = llm_prompt({"version": 1}, [], lessons=["교훈"])

    assert plain != with_lessons
    assert "교훈" not in plain
