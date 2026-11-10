"""
Claude Code 플러그인 묶음 시험: 매니페스트·훅·MCP 정의가 읽히고, 훅이 docs/ci의 설정과 같은 세 시점을 같은 명령에 연결한다.
작성자: 최진호
작성일: 2026-11-10
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(rel: str) -> dict:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def test_manifest_and_marketplace_name_the_same_plugin():
    plugin, market = load(".claude-plugin/plugin.json"), load(".claude-plugin/marketplace.json")
    assert plugin["name"] == "iron-laws" and plugin["license"].startswith("AGPL")
    assert [entry["name"] for entry in market["plugins"]] == [plugin["name"]] and market["plugins"][0]["source"] == "./"


def test_plugin_hooks_match_the_documented_claude_code_settings():
    plugin_hooks = load("hooks/hooks.json")["hooks"]
    documented = load("docs/ci/claude-code-settings.json")["hooks"]
    assert plugin_hooks == documented
    assert set(plugin_hooks) == {"SessionStart", "PostToolUse", "Stop"}
    assert all(hook["command"].startswith("iron-laws hook claude-code") for group in plugin_hooks.values() for entry in group for hook in entry["hooks"])


def test_mcp_server_is_limited_to_the_project_folder():
    server = load(".mcp.json")["mcpServers"]["iron-laws"]
    assert server["command"] == "iron-laws" and server["args"] == ["mcp", "--root", "${CLAUDE_PROJECT_DIR}"]
