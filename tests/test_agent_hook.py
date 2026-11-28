"""
오철칙 코딩 에이전트 훅 시험(Claude Code PostToolUse 입력 형식)
작성자: 최진호
작성일: 2026-10-12
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from iron_laws.cli import app

runner = CliRunner()


def _payload(root: Path, rel: str) -> str:
    return json.dumps({"tool_name": "Write", "cwd": str(root), "tool_input": {"file_path": rel}})


def test_hook_returns_2_with_findings_for_the_agent(tmp_path: Path):
    (tmp_path / "app.py").write_text("import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n", encoding="utf-8")
    result = runner.invoke(app, ["hook", "claude-code"], input=_payload(tmp_path, "app.py"))
    assert result.exit_code == 2
    assert "IL-504" in result.stderr and "app.py:5" in result.stderr


def test_hook_passes_clean_files_and_non_files(tmp_path: Path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert runner.invoke(app, ["hook", "claude-code"], input=_payload(tmp_path, "ok.py")).exit_code == 0
    assert runner.invoke(app, ["hook", "claude-code"], input=json.dumps({"tool_input": {}})).exit_code == 0
    assert runner.invoke(app, ["hook", "other"], input="{}").exit_code == 2


RISKY = "import os\nfrom flask import request\n\ndef run():\n    os.system('ls ' + request.args['d'])\n"


def _run(agent: str, payload: dict, *extra: str):
    return runner.invoke(app, ["hook", agent, *extra], input=json.dumps(payload))


def test_codex_post_edit_reads_files_from_apply_patch(tmp_path: Path):
    (tmp_path / "app.py").write_text(RISKY, encoding="utf-8")
    patch = "*** Begin Patch\n*** Update File: app.py\n@@\n-x\n+y\n*** End Patch\n"
    payload = {"hook_event_name": "PostToolUse", "session_id": "codex-edit-1", "cwd": str(tmp_path), "tool_name": "apply_patch", "tool_input": {"command": patch}}
    result = _run("codex", payload)
    assert result.exit_code == 2 and "IL-504" in result.stderr


def test_codex_post_edit_ignores_shell_commands(tmp_path: Path):
    (tmp_path / "app.py").write_text(RISKY, encoding="utf-8")
    payload = {"hook_event_name": "PostToolUse", "session_id": "codex-edit-2", "cwd": str(tmp_path), "tool_name": "Bash", "tool_input": {"command": "cat app.py"}}
    assert _run("codex", payload).exit_code == 0


def test_stop_checks_files_edited_in_the_session(tmp_path: Path):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    edit = {"hook_event_name": "PostToolUse", "session_id": "claude-stop-1", "cwd": str(tmp_path), "tool_input": {"file_path": "ok.py"}}
    assert _run("claude-code", edit).exit_code == 0
    (tmp_path / "ok.py").write_text(RISKY, encoding="utf-8")
    stop = {"hook_event_name": "Stop", "session_id": "claude-stop-1", "cwd": str(tmp_path), "stop_hook_active": False}
    result = _run("claude-code", stop)
    assert result.exit_code == 2 and "끝내기 전에" in result.stderr and "IL-504" in result.stderr
    assert _run("claude-code", {**stop, "stop_hook_active": True}).exit_code == 0


def test_stop_without_edits_passes(tmp_path: Path):
    stop = {"hook_event_name": "Stop", "session_id": "codex-stop-none", "cwd": str(tmp_path)}
    result = _run("codex", stop)
    assert result.exit_code == 0 and result.stderr == "" and result.stdout == ""


def test_cursor_records_edits_and_stop_sends_followup(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text(RISKY, encoding="utf-8")
    edit = {"hook_event_name": "afterFileEdit", "conversation_id": "cursor-1", "workspace_roots": [str(tmp_path)], "file_path": str(target), "edits": []}
    result = _run("cursor", edit)
    assert result.exit_code == 0 and result.stdout == ""
    stop = {"hook_event_name": "stop", "conversation_id": "cursor-1", "workspace_roots": [str(tmp_path)], "status": "completed", "loop_count": 0}
    result = _run("cursor", stop)
    assert result.exit_code == 0
    assert "IL-504" in json.loads(result.stdout)["followup_message"]
    assert _run("cursor", {**stop, "loop_count": 3}).stdout == ""


def test_session_start_injects_rules_for_project_languages(tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    claude = _run("claude-code", {"hook_event_name": "SessionStart", "session_id": "s", "cwd": str(tmp_path), "source": "startup"})
    assert claude.exit_code == 0 and "python" in claude.stdout.lower()
    cursor = _run("cursor", {"hook_event_name": "sessionStart", "session_id": "s", "workspace_roots": [str(tmp_path)]})
    assert json.loads(cursor.stdout)["additional_context"] == claude.stdout.strip() or "python" in json.loads(cursor.stdout)["additional_context"].lower()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _run("codex", {"hook_event_name": "SessionStart", "session_id": "s", "cwd": str(empty)}).stdout == ""


def test_unknown_events_and_bad_input_are_handled(tmp_path: Path):
    assert _run("codex", {"hook_event_name": "UserPromptSubmit", "cwd": str(tmp_path)}).exit_code == 0
    assert runner.invoke(app, ["hook", "codex"], input="[1]").exit_code == 2


def _git(root: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args], cwd=root, check=True, capture_output=True)


def _edit(agent_session: str, root: Path, rel: str):
    return _run("claude-code", {"hook_event_name": "PostToolUse", "session_id": agent_session, "cwd": str(root), "tool_input": {"file_path": rel}})


def test_editing_guideline_and_hook_files_is_reported(tmp_path: Path):
    (tmp_path / "CLAUDE.md").write_text("# 규칙\n", encoding="utf-8")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("메모\n", encoding="utf-8")
    result = _edit("prot-1", tmp_path, "CLAUDE.md")
    assert result.exit_code == 2 and "정책·지침 파일" in result.stderr and "CLAUDE.md" in result.stderr
    assert _edit("prot-2", tmp_path, ".claude/settings.json").exit_code == 2
    assert _edit("prot-3", tmp_path, "notes.md").exit_code == 0


def test_config_changes_that_weaken_detection_are_listed(tmp_path: Path):
    config = tmp_path / ".iron-laws.yml"
    config.write_text("fail_on: HIGH\nexcludes: [node_modules]\nlimits:\n  max_function_lines: 80\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    config.write_text("fail_on: CRITICAL\nexcludes: [node_modules, src]\ndisabled_rules: [IL-504]\nlimits:\n  max_function_lines: 400\n", encoding="utf-8")
    result = _edit("prot-4", tmp_path, ".iron-laws.yml")
    assert result.exit_code == 2
    assert "fail_on을 HIGH에서 CRITICAL" in result.stderr and "점검 제외 경로 추가: src" in result.stderr
    assert "끈 규칙 추가: IL-504" in result.stderr and "limits.max_function_lines를 80에서 400" in result.stderr


def test_agent_cannot_unprotect_files_in_the_same_session(tmp_path: Path):
    config = tmp_path / ".iron-laws.yml"
    config.write_text("policies:\n  protected_paths: ['deploy/*.yml']\n  protected_paths_exclude: ['CLAUDE.md']\n", encoding="utf-8")
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "x.yml").write_text("a: 1\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("# 규칙\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    config.write_text("fail_on: HIGH\n", encoding="utf-8")  # 보호 경로 설정을 지웠다
    assert _edit("prot-5", tmp_path, "deploy/x.yml").exit_code == 2
    assert _edit("prot-6", tmp_path, "CLAUDE.md").exit_code == 0  # 커밋된 설정이 CLAUDE.md를 제외했다
    removed = _edit("prot-7", tmp_path, ".iron-laws.yml")
    assert removed.exit_code == 2 and "보호 경로 제거: deploy/*.yml" in removed.stderr


def test_cursor_reports_protected_edits_at_stop(tmp_path: Path):
    target = tmp_path / "AGENTS.md"
    target.write_text("# 규칙\n", encoding="utf-8")
    base = {"conversation_id": "cursor-prot", "workspace_roots": [str(tmp_path)]}
    assert _run("cursor", {**base, "hook_event_name": "afterFileEdit", "file_path": str(target), "edits": []}).stdout == ""
    stop = _run("cursor", {**base, "hook_event_name": "stop", "status": "completed", "loop_count": 0})
    assert "AGENTS.md" in json.loads(stop.stdout)["followup_message"]


SECRET = 'API_KEY = "AKIAIOSFODNN7ABCDEFG"\n'


def test_subfolder_edit_uses_project_config(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text('disabled_rules: ["IL-101"]\nexcludes: ["generated"]\n', encoding="utf-8")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(SECRET + RISKY, encoding="utf-8")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "client.py").write_text(RISKY, encoding="utf-8")
    result = _run("claude-code", {"hook_event_name": "PostToolUse", "cwd": str(tmp_path), "tool_input": {"file_path": "app/main.py"}})
    assert result.exit_code == 2
    assert "IL-101" not in result.stderr  # 프로젝트 루트 설정에서 끈 규칙
    assert "IL-504" in result.stderr and "app/main.py:" in result.stderr  # 프로젝트 기준 경로로 알린다
    excluded = _run("claude-code", {"hook_event_name": "PostToolUse", "cwd": str(tmp_path), "tool_input": {"file_path": "generated/client.py"}})
    assert excluded.exit_code == 0  # 설정에서 제외한 폴더


def test_existing_findings_in_baseline_do_not_block(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text(RISKY, encoding="utf-8")
    assert runner.invoke(app, ["baseline", "create", str(tmp_path), "-o", str(tmp_path / ".iron-laws-baseline.json")]).exit_code == 0
    payload = {"hook_event_name": "PostToolUse", "cwd": str(tmp_path), "tool_input": {"file_path": "app/main.py"}}
    assert _run("claude-code", payload).exit_code == 0  # 기준선에 있던 지적
    (tmp_path / "app" / "main.py").write_text(RISKY + "\ndef again():\n    os.system('rm ' + request.args['f'])\n", encoding="utf-8")
    result = _run("claude-code", payload)
    assert result.exit_code == 2 and "app/main.py:8" in result.stderr  # 새로 생긴 지적만 알린다


HELPER = "def normalize_phone(raw):\n    digits = ''.join(ch for ch in raw if ch.isdigit())\n    if digits.startswith('82'):\n        digits = '0' + digits[2:]\n    if len(digits) == 11:\n        return digits[:3] + '-' + digits[3:7] + '-' + digits[7:]\n    if len(digits) == 10:\n        return digits[:3] + '-' + digits[3:6] + '-' + digits[6:]\n    return digits\n"


def test_new_duplicate_function_is_reported_once_in_production(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text("stage: production\n", encoding="utf-8")
    (tmp_path / "util.py").write_text(HELPER, encoding="utf-8")
    (tmp_path / "views.py").write_text("x = 1\n", encoding="utf-8")
    session = {"session_id": "dup-1", "cwd": str(tmp_path)}
    assert _run("claude-code", {**session, "hook_event_name": "SessionStart"}).exit_code == 0
    (tmp_path / "views.py").write_text(HELPER.replace("normalize_phone", "format_phone"), encoding="utf-8")
    edit = {**session, "hook_event_name": "PostToolUse", "tool_input": {"file_path": "views.py"}}
    first = _run("claude-code", edit)
    assert first.exit_code == 2 and "format_phone" in first.stderr and "util.py:1" in first.stderr
    assert "format_phone" not in _run("claude-code", edit).stderr  # 같은 알림은 한 번만
    (tmp_path / ".iron-laws.yml").write_text("stage: launch\n", encoding="utf-8")
    other = {"session_id": "dup-2", "cwd": str(tmp_path)}
    _run("claude-code", {**other, "hook_event_name": "SessionStart"})
    (tmp_path / "views2.py").write_text(HELPER.replace("normalize_phone", "clean_phone"), encoding="utf-8")
    assert "clean_phone" not in _run("claude-code", {**other, "hook_event_name": "PostToolUse", "tool_input": {"file_path": "views2.py"}}).stderr  # launch는 중복을 막지 않는다


def test_stop_reports_layer_violation_from_edited_file(tmp_path: Path):
    (tmp_path / ".iron-laws.yml").write_text(
        "stage: production\narchitecture:\n  layers:\n    - {name: api, paths: ['app/api/**']}\n    - {name: repo, paths: ['app/repo/**']}\n", encoding="utf-8"
    )
    for rel in ("app/__init__.py", "app/api/__init__.py", "app/repo/__init__.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("", encoding="utf-8")
    (tmp_path / "app/api/users.py").write_text("def get_users():\n    return []\n", encoding="utf-8")
    (tmp_path / "app/repo/users.py").write_text("from app.api.users import get_users\n", encoding="utf-8")
    session = {"session_id": "layer-1", "cwd": str(tmp_path)}
    assert _run("claude-code", {**session, "hook_event_name": "PostToolUse", "tool_input": {"file_path": "app/repo/users.py"}}).exit_code == 0
    stop = _run("claude-code", {**session, "hook_event_name": "Stop"})
    assert stop.exit_code == 2 and "ARC-207" in stop.stderr and "app/repo/users.py:1" in stop.stderr
