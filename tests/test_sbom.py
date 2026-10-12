"""
오철칙 SBOM 시험: 버전 단위 간선(npm 설치 위치 해석, pnpm 여러 버전), 관계 없는 입력의 무추정, 공식 스키마 오프라인 검증
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.deps.graph import build_graph

runner = CliRunner()
SCHEMAS = Path(__file__).parent / "fixtures" / "sbom_schemas"
LOCK = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "^4", "qs": "6.5.0"}},
        "node_modules/express": {"version": "4.17.0", "dependencies": {"qs": "^6.7.0", "debug": "2.6.9"}},
        "node_modules/express/node_modules/qs": {"version": "6.7.0"},
        "node_modules/qs": {"version": "6.5.0"},
        "node_modules/debug": {"version": "2.6.9"},
    },
}
PNPM = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1
        version: 1.0.0
      c:
        specifier: ^1
        version: 1.1.0
packages:
  a@1.0.0: {resolution: {integrity: x}}
  b@1.0.0: {resolution: {integrity: x}}
  b@2.0.0: {resolution: {integrity: x}}
  c@1.1.0: {resolution: {integrity: x}}
snapshots:
  a@1.0.0:
    dependencies:
      b: 1.0.0
  b@1.0.0: {}
  b@2.0.0: {}
  c@1.1.0:
    dependencies:
      b: 2.0.0
"""


def _validator(name: str) -> Draft7Validator:
    resources = []
    for f in SCHEMAS.glob("*.json"):
        data = json.loads(f.read_text(encoding="utf-8"))
        resources.append((data.get("$id", f.name), Resource.from_contents(data)))
        resources.append((f.name, Resource.from_contents(data)))
    registry = Registry().with_resources(resources)
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=registry)


def test_npm_edges_follow_install_location(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK))
    g = build_graph(tmp_path / "package-lock.json")
    assert g.edges["express@4.17.0"] == {"qs@6.7.0", "debug@2.6.9"}  # 이름이 같은 최상위 qs@6.5.0이 아니다
    assert g.nodes["qs@6.5.0"].direct is True and g.nodes["qs@6.7.0"].direct is not True


def test_pnpm_keeps_every_version_with_its_own_edges(tmp_path: Path):
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM)
    g = build_graph(tmp_path / "pnpm-lock.yaml")
    assert {"b@1.0.0", "b@2.0.0"} <= set(g.nodes)
    assert g.edges["a@1.0.0"] == {"b@1.0.0"} and g.edges["c@1.1.0"] == {"b@2.0.0"}


@pytest.mark.parametrize("fmt,schema", [("cyclonedx", "bom-1.6.schema.json"), ("spdx", "spdx-2.3.schema.json")])
def test_sbom_documents_validate_against_official_schemas(tmp_path: Path, fmt, schema):
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK))
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM)
    result = runner.invoke(app, ["sbom", str(tmp_path), "--format", fmt, "--timestamp", "2026-10-12T00:00:00Z", "--name", "app"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    errors = sorted(_validator(schema).iter_errors(doc), key=str)
    assert errors == [], [e.message for e in errors[:3]]
    again = json.loads(runner.invoke(app, ["sbom", str(tmp_path), "--format", fmt, "--timestamp", "2026-10-12T00:00:00Z", "--name", "app"]).stdout)
    assert again == doc  # 같은 입력·시각이면 같은 문서


def test_cyclonedx_dependencies_are_version_level(tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK))
    doc = json.loads(runner.invoke(app, ["sbom", str(tmp_path), "--timestamp", "2026-10-12T00:00:00Z"]).stdout)
    deps = {d["ref"]: d["dependsOn"] for d in doc["dependencies"]}
    assert deps["pkg:npm/express@4.17.0"] == ["pkg:npm/debug@2.6.9", "pkg:npm/qs@6.7.0"]
    assert sorted(deps["root-application"]) == ["pkg:npm/express@4.17.0", "pkg:npm/qs@6.5.0"]


def test_requirements_only_input_has_no_invented_relations(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\nurllib3==2.2.2\n")
    doc = json.loads(runner.invoke(app, ["sbom", str(tmp_path), "--timestamp", "2026-10-12T00:00:00Z"]).stdout)
    assert len(doc["components"]) == 2 and doc["dependencies"] == []
    assert runner.invoke(app, ["sbom", str(tmp_path / "nothing")]).exit_code == 2


def test_spdx_ids_stay_distinct_when_names_differ_only_in_replaced_characters():
    from iron_laws.deps.sbom import _spdx_id

    a, b = _spdx_id("pkg:npm/a_b@1.0.0"), _spdx_id("pkg:npm/a-b@1.0.0")
    assert a != b and all(ch.isalnum() or ch in ".-" for ch in a.removeprefix("SPDXRef-"))
