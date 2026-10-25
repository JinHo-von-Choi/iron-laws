"""
오철칙 사용자 명세 시험: 예제로 확인된 명세만 불러오고, 소스·싱크·정제 함수가 점검에 반영된다. 초안 생성과 LLM 제안 병합.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import ConfigError, IronLawsConfig, Policies
from iron_laws.core.scanner import AuditScanner

runner = CliRunner()
SPEC = {
    "version": 1,
    "sinks": [{
        "id": "legacy-run", "family": "command", "languages": ["python"], "callee": r"(^|\.)legacy_run$", "arg": 0,
        "positive": "from flask import request\nfrom tools import legacy_run\n\ndef f():\n    legacy_run(request.args['c'])\n",
        "negative": "from tools import legacy_run\n\ndef f():\n    legacy_run('uptime')\n",
    }],
    "sources": [{
        "id": "lambda-event", "family": "command", "languages": ["python"], "pattern": r"\bevent\s*\[",
        "positive": "import os\n\ndef handler(event, context):\n    os.system('ls ' + event['dir'])\n",
        "negative": "import os\n\ndef handler(event, context):\n    os.system('ls /tmp')\n",
    }],
    "sanitizers": [{
        "id": "harden-arg", "family": "command", "context": "shell", "languages": ["python"], "name": r"(^|\.)harden_arg$",
        "positive": "import os\nfrom flask import request\n\ndef f():\n    os.system('ls ' + request.args['d'])\n",
        "negative": "import os\nfrom flask import request\nfrom tools import harden_arg\n\ndef f():\n    os.system('ls ' + harden_arg(request.args['d']))\n",
    }],
}


def _write_spec(tmp_path: Path, spec: dict) -> Path:
    path = tmp_path / "spec.yml"
    path.write_text(yaml.safe_dump(spec, allow_unicode=True), encoding="utf-8")
    return path


def test_valid_spec_passes_check_and_changes_findings(tmp_path: Path):
    spec = _write_spec(tmp_path, SPEC)
    assert runner.invoke(app, ["spec", "check", str(spec)]).exit_code == 0
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.py").write_text("import os\nfrom flask import request\nfrom tools import legacy_run, harden_arg\n\ndef a():\n    legacy_run(request.args['c'])\n\ndef b(event, context):\n    os.system('ls ' + event['x'])\n\ndef c():\n    os.system('ls ' + harden_arg(request.args['d']))\n", encoding="utf-8")
    plain = {v.line_number for v in AuditScanner(project).scan().violations if v.rule_id == "IL-504" and v.confidence.value == "CONFIRMED"}
    with_spec = {v.line_number for v in AuditScanner(project, IronLawsConfig(policies=Policies(custom_spec=str(spec)))).scan().violations if v.rule_id == "IL-504" and v.confidence.value == "CONFIRMED"}
    assert plain == {12}
    assert with_spec == {6, 9}  # 새 싱크·새 소스는 잡고, 사람이 확인한 정제 함수를 거친 흐름은 지적하지 않는다
    assert {v.line_number for v in AuditScanner(project).scan().violations if v.rule_id == "IL-504" and v.confidence.value == "CONFIRMED"} == {12}  # 명세 없는 점검에 남지 않는다


def test_spec_sources_and_sanitizers_apply_only_to_their_languages(tmp_path: Path):
    spec = _write_spec(tmp_path, SPEC)
    project = tmp_path / "p"
    project.mkdir()
    (project / "app.js").write_text(
        "const { exec } = require('child_process');\napp.get('/a', (req, res) => {\n  exec('ls ' + harden_arg(req.query.d));\n});\n"
        "function handler(event) {\n  exec('ls ' + event['x']);\n}\n",
        encoding="utf-8",
    )
    found = {v.line_number for v in AuditScanner(project, IronLawsConfig(policies=Policies(custom_spec=str(spec)))).scan().violations if v.rule_id == "IL-504" and v.confidence.value == "CONFIRMED"}
    assert found == {3}  # python으로 확인한 정제 함수는 JavaScript에서 지적을 지우지 않고, python 소스 패턴은 JavaScript 값을 오염으로 만들지 않는다


def test_wrong_or_missing_examples_are_refused(tmp_path: Path):
    bad = json.loads(json.dumps(SPEC))
    bad["sinks"][0]["negative"] = bad["sinks"][0]["positive"]
    spec = _write_spec(tmp_path, bad)
    assert runner.invoke(app, ["spec", "check", str(spec)]).exit_code == 1
    with pytest.raises(ConfigError, match="예제"):
        AuditScanner(tmp_path, IronLawsConfig(policies=Policies(custom_spec=str(spec)))).scan()
    empty = json.loads(json.dumps(SPEC))
    empty["sources"][0]["negative"] = ""
    (tmp_path / "e").mkdir()
    empty_spec = _write_spec(tmp_path / "e", empty)
    with pytest.raises(ConfigError, match="양성·음성"):
        AuditScanner(tmp_path, IronLawsConfig(policies=Policies(custom_spec=str(empty_spec)))).scan()


def test_draft_finds_candidates_and_merges_llm_output(tmp_path: Path):
    project = tmp_path / "p"
    project.mkdir()
    (project / "tools.py").write_text("import subprocess\n\ndef legacy_run(cmd):\n    subprocess.call(cmd, shell=True)\n\ndef sanitize_arg(value):\n    return value.replace(\"'\", '')\n", encoding="utf-8")
    (project / "fn.py").write_text("def lambda_handler(event, context):\n    return event['x']\n", encoding="utf-8")
    fake = tmp_path / "llm.py"
    fake.write_text("import sys\nsys.stdin.read()\nprint('sinks:\\n  - id: from-llm\\n    family: sql\\n    callee: \"run_query$\"\\n    positive: ignored\\n')\n", encoding="utf-8")
    result = runner.invoke(app, ["spec", "draft", str(project), "--llm-cmd", f"{sys.executable} {fake}"])
    assert result.exit_code == 0, result.output
    draft = yaml.safe_load(result.stdout)
    ids = {e["id"] for kind in ("sources", "sinks", "sanitizers") for e in draft[kind]}
    assert {"wrapper-legacy_run", "sanitizer-sanitize_arg", "lambda-event"} <= ids and "from-llm" not in ids
    rejected = next(e for e in draft["rejected"] if e["id"] == "from-llm")  # 음성 예제가 없어 확인할 수 없는 제안은 뺀다
    assert rejected["origin"] == "llm" and rejected["kind"] == "sinks" and rejected["positive"] == ""


LLM_ENTRIES = """sinks:
  - id: run-query
    family: sql
    languages: [python]
    callee: "run_query$"
    arg: 0
    positive: |
      from flask import request
      def view():
          run_query("select * from t where id=" + request.args["id"])
    negative: |
      def view():
          run_query("select 1")
  - id: wrong-example
    family: sql
    languages: [python]
    callee: "other_query$"
    positive: |
      def view():
          other_query("select 1")
    negative: |
      def view():
          other_query("select 2")
sanitizers:
  - id: clean-id
    family: sql
    languages: [python]
    name: "clean_id$"
    context: sql
    positive: |
      from flask import request
      def view(cursor):
          cursor.execute("select * from t where id=" + request.args["id"])
    negative: |
      from flask import request
      def view(cursor):
          cursor.execute("select * from t where id=" + clean_id(request.args["id"]))
"""


def test_llm_proposals_are_judged_by_their_own_examples(tmp_path: Path):
    from iron_laws.core.spec_draft import check_llm_entries, merge_llm

    draft = {"version": 1, "sources": [], "sinks": [], "sanitizers": []}
    assert merge_llm(draft, LLM_ENTRIES) == 3
    counts = check_llm_entries(draft)
    assert counts == {"passed": 1, "rejected": 1, "needs_review": 1}
    sink = next(e for e in draft["sinks"] if e["id"] == "run-query")
    assert sink["positive"] and sink["negative"]  # 소스·싱크는 지적을 늘리기만 하므로 맞은 예제를 채운다
    sanitizer = next(e for e in draft["sanitizers"] if e["id"] == "clean-id")
    assert sanitizer["positive"] == "" and sanitizer["proposed_negative"]  # 정제 함수는 사람이 옮겨야 불러온다
    assert [e["id"] for e in draft["rejected"]] == ["wrong-example"] and "positive" in draft["rejected"][0]["why"]
