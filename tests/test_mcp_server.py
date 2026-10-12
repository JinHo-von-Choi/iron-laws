"""
오철칙 MCP 서버 시험: 경로 경계, 시험 명령 프리셋, 서버 설정 위치, 도구 설명의 자체 점검
작성자: 최진호
작성일: 2026-10-12
"""

import asyncio
import json
import os
from pathlib import Path

import pytest

from iron_laws.core.config import ConfigError
from iron_laws.core.paths import OutsideRootError, resolve_within
from iron_laws.core.scanner import AuditScanner
from iron_laws.mcp_server import (
    INSTRUCTIONS,
    TOOL_DESCRIPTIONS,
    IronLawsTools,
    ToolInputError,
    load_settings,
)

APP = "import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n"


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(APP, encoding="utf-8")
    return root


def test_resolve_within_rejects_escape_and_symlinks(project: Path, tmp_path: Path):
    assert resolve_within(project, "app.py") == (project / "app.py").resolve()
    (tmp_path / "secret.txt").write_text("x", encoding="utf-8")
    os.symlink(tmp_path / "secret.txt", project / "link.txt")
    for bad in ("../secret.txt", str(tmp_path / "secret.txt"), "link.txt"):
        with pytest.raises(OutsideRootError):
            resolve_within(project, bad)


def test_check_and_explain_and_fix_prompt(project: Path):
    tools = IronLawsTools(load_settings(project, None))
    result = tools.check(".")
    assert not result["passed"]
    assert any(f["rule_id"] == "IL-504" and f["path"] == "app.py" and f["line"] == 5 for f in result["findings"])
    assert tools.explain("il-504")["rule_id"] == "IL-504"
    assert "IL-504" in tools.fix_prompt(".", 10)
    with pytest.raises(ToolInputError):
        tools.check("../")
    with pytest.raises(ToolInputError):
        tools.check(".", max_analysis_unknown_rate=2.0)


def test_scan_skips_symlinked_files_outside_the_root(project: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(APP, encoding="utf-8")
    os.symlink(outside / "secret.py", project / "linked.py")
    (project / "inside.py").symlink_to(project / "app.py")
    tools = IronLawsTools(load_settings(project, None))
    paths = {f["path"] for f in tools.check(".")["findings"]}
    assert "linked.py" not in paths and {"app.py", "inside.py"} <= paths
    with pytest.raises(ToolInputError):
        tools.verify_patch(".", "app.py")


def test_scan_rejects_config_file_linked_outside_the_root(project: Path, tmp_path: Path):
    (tmp_path / "cfg.yml").write_text("fail_on: LOW\n", encoding="utf-8")
    os.symlink(tmp_path / "cfg.yml", project / ".iron-laws.yml")
    with pytest.raises(ToolInputError):
        IronLawsTools(load_settings(project, None)).check(".")


def test_server_config_must_live_outside_the_root(project: Path, tmp_path: Path):
    inside = project / "server.yml"
    inside.write_text("test_presets: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(project, inside)
    outside = tmp_path / "server.yml"
    outside.write_text("test_presets:\n  unit:\n    command: [python, -m, pytest, -q]\n    timeout: 60\n", encoding="utf-8")
    settings = load_settings(project, outside)
    assert settings.test_presets["unit"].command == ["python", "-m", "pytest", "-q"]
    (tmp_path / "bad.yml").write_text("test_presets:\n  x:\n    command: 'rm -rf /'\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_settings(project, tmp_path / "bad.yml")


def test_verify_patch_accepts_only_server_presets_and_paths_inside(project: Path, tmp_path: Path):
    tools = IronLawsTools(load_settings(project, None))
    (tmp_path / "outside.diff").write_text("", encoding="utf-8")
    with pytest.raises(ToolInputError):
        tools.verify_patch(".", str(tmp_path / "outside.diff"))
    (project / "fix.diff").write_text("", encoding="utf-8")
    with pytest.raises(ToolInputError, match="시험 프리셋"):
        tools.verify_patch(".", "fix.diff", test_preset="python -c 'import os'")


def test_verify_patch_reports_static_result_and_regression_separately(project: Path):
    patch = (
        "--- a/app.py\n+++ b/app.py\n@@ -2,4 +2,5 @@\n from flask import request\n+import subprocess\n \n def run():\n"
        "-    os.system('ls ' + request.args['d'])\n+    subprocess.run(['ls', request.args['d']], check=False)\n"
    )
    (project / "fix.diff").write_text(patch, encoding="utf-8")
    result = IronLawsTools(load_settings(project, None)).verify_patch(".", "fix.diff", finding="IL-504@app.py:5")
    assert result["verdict"] in ("verified", "failed", "undeterminable")
    assert result["static_finding_resolved"] == "pass"
    assert result["defect_behavior_removed"] == "not_requested"
    assert result["receipt_digest"]


def test_tool_descriptions_pass_the_agent_rule_file_check(tmp_path: Path):
    """도구 설명은 에이전트 규칙 파일 검사기(AIA-101)를 통과해야 한다: 숨은 지시·보이지 않는 문자·비밀 유출 지시가 없다."""
    root = tmp_path / "desc"
    root.mkdir()
    (root / "AGENTS.md").write_text(INSTRUCTIONS + "\n\n" + "\n\n".join(f"## {k}\n{v}" for k, v in TOOL_DESCRIPTIONS.items()), encoding="utf-8")
    assert [v for v in AuditScanner(root).scan().violations if v.rule_id == "AIA-101"] == []


def test_registered_tools_over_the_sdk(project: Path):
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP

    tools = IronLawsTools(load_settings(project, None))
    server = FastMCP("iron-laws", instructions=INSTRUCTIONS)
    for name, description in TOOL_DESCRIPTIONS.items():
        server.tool(name=name, description=description)(getattr(tools, name))
    listed = asyncio.run(server.list_tools())
    assert sorted(t.name for t in listed) == sorted(TOOL_DESCRIPTIONS)
    check = next(t for t in listed if t.name == "check")
    assert "command" not in json.dumps(check.inputSchema)  # 임의 명령을 받는 입력이 없다
    verify = next(t for t in listed if t.name == "verify_patch")
    assert "test_preset" in verify.inputSchema["properties"] and "test_cmd" not in verify.inputSchema["properties"]
