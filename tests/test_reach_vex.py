"""
오철칙 취약 의존성 도달성과 OpenVEX 시험
- 영향 함수 정보가 있는 권고만 reachable·no_evidence를 판정하고, 없으면 undetermined다.
- OpenVEX는 affected·under_investigation만 자동으로 쓰고, not_affected는 사람이 남긴 판정(justification)에서만 나온다.
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def _advisory(aid: str, name: str, functions: list[str] | None) -> dict:
    affected = {"package": {"ecosystem": "PyPI", "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.0"}]}]}
    if functions is not None:
        affected["ecosystem_specific"] = {"affected_functions": functions}
    return {"id": aid, "modified": "2026-01-01T00:00:00Z", "summary": "x", "affected": [affected], "database_specific": {"severity": "HIGH"}}


def _project(tmp_path: Path, code: str) -> tuple[Path, Path]:
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    (project / "requirements.txt").write_text("PyYAML==5.3\nrequests==2.0\n", encoding="utf-8")
    (project / "app.py").write_text(code, encoding="utf-8")
    db = tmp_path / "osv"
    db.mkdir()
    (db / "a.json").write_text(json.dumps(_advisory("GHSA-yaml-load", "pyyaml", ["yaml.load"])), encoding="utf-8")
    (db / "b.json").write_text(json.dumps(_advisory("GHSA-req", "requests", None)), encoding="utf-8")
    return project, db


def _statuses(result) -> dict[str, str]:
    return {s["vulnerability"]["name"]: s["status"] for s in json.loads(result.stdout)["statements"]}


def test_reachable_no_evidence_and_undetermined(tmp_path: Path):
    project, db = _project(tmp_path, "import yaml\n\ndef read(text):\n    return yaml.load(text)\n")
    data = json.loads(runner.invoke(app, ["deps", str(project), "--advisory-db", str(db), "--format", "json", "--reachability"]).stdout)
    reach = {a["id"]: a["reachability"] for lock in data["locks"] for f in lock["findings"] for a in f["advisories"]}
    assert reach["GHSA-yaml-load"]["status"] == "reachable" and reach["GHSA-yaml-load"]["locations"] == ["app.py:4"]
    assert reach["GHSA-req"]["status"] == "undetermined"
    project2, db2 = _project(tmp_path / "b", "import yaml\n\ndef read(text):\n    return yaml.safe_load(text)\n")
    data = json.loads(runner.invoke(app, ["deps", str(project2), "--advisory-db", str(db2), "--format", "json", "--reachability"]).stdout)
    assert {a["id"]: a["reachability"]["status"] for lock in data["locks"] for f in lock["findings"] for a in f["advisories"]}["GHSA-yaml-load"] == "no_evidence"


def test_openvex_statuses_and_human_decisions(tmp_path: Path):
    project, db = _project(tmp_path, "import yaml\n\ndef read(text):\n    return yaml.load(text)\n")
    base = ["deps", str(project), "--advisory-db", str(db), "--format", "openvex", "--timestamp", "2026-10-12T00:00:00Z"]
    result = runner.invoke(app, base)
    doc = json.loads(result.stdout)
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert _statuses(result) == {"GHSA-yaml-load": "affected", "GHSA-req": "under_investigation"}
    decisions = tmp_path / "vex.json"
    decisions.write_text(json.dumps([{"vulnerability": "GHSA-req", "product": "pkg:pypi/requests@2.0", "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "프록시 기능을 쓰지 않는다", "author": "보안팀"}]), encoding="utf-8")
    assert _statuses(runner.invoke(app, [*base, "--vex-decisions", str(decisions)]))["GHSA-req"] == "not_affected"
    decisions.write_text(json.dumps([{"vulnerability": "GHSA-req", "product": "pkg:pypi/requests@2.0", "status": "not_affected", "justification": "looks fine", "impact_statement": "x", "author": "y"}]), encoding="utf-8")
    assert runner.invoke(app, [*base, "--vex-decisions", str(decisions)]).exit_code == 2
