"""
코딩 에이전트 훅: 편집 직후, 종료 직전, 세션 시작 세 시점의 입력 해석과 응답 조립.
입력·응답 형식은 에이전트별 공식 훅 문서를 따른다.
- Claude Code: PostToolUse·Stop은 종료코드 2와 표준 오류로 되돌리고, SessionStart는 표준 출력 글을 문맥으로 쓴다.
- Codex CLI: PostToolUse·Stop은 종료코드 2와 표준 오류로 되돌리고, SessionStart는 표준 출력 글을 문맥으로 쓴다.
  apply_patch의 `tool_input.command`에 든 패치 본문에서 바뀐 파일을 읽는다.
- Cursor: afterFileEdit는 응답 통로가 없어 편집한 파일만 기록하고, stop이 `followup_message`로, sessionStart가 `additional_context`로 알린다.
작성자: 최진호
작성일: 2026-11-10
"""

import fnmatch
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.models import Severity, Violation

logger = logging.getLogger(__name__)

AGENTS = ("claude-code", "codex", "cursor")
EDIT_EVENTS = {"posttooluse", "afterfileedit"}
STOP_EVENTS = {"stop"}
START_EVENTS = {"sessionstart"}
PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add File|Update File|Move to): (.+?)\s*$", re.MULTILINE)
MAX_RECORDED_FILES = 200
MAX_START_TEXT = 8000
CURSOR_FOLLOWUP_LIMIT = 3
BASELINE_NAME = ".iron-laws-baseline.json"
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
LOCKED_PROTECTED = (".iron-laws.yml", ".iron-laws.yaml", ".iron-laws-contract.yml", ".iron-laws-approvals*", ".iron-laws-baseline*", ".iron-laws-experience*", ".iron-laws-runner.yml")
DEFAULT_PROTECTED = (
    "CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursor/rules/*", ".cursor/hooks.json",
    ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/*", ".codex/*", ".mcp.json",
)


@dataclass
class HookEvent:
    kind: str  # edit, stop, start, ignore
    session: str
    cwd: Path
    files: list[Path] = field(default_factory=list)
    continuing: bool = False  # 이 종료가 앞선 훅 응답으로 이어진 것인가


@dataclass
class HookResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""


def _event_name(payload: dict, forced: str | None) -> str:
    name = forced or str(payload.get("hook_event_name") or "")
    return name.replace("-", "").replace("_", "").lower()


def _working_dir(payload: dict) -> Path:
    cwd = payload.get("cwd")
    roots = payload.get("workspace_roots")
    if not cwd and isinstance(roots, list) and roots and isinstance(roots[0], str):
        cwd = roots[0]
    return Path(str(cwd)) if cwd else Path(".")


def _patch_files(text: str) -> list[str]:
    return PATCH_FILE_RE.findall(text) if "*** Begin Patch" in text else []


def edited_paths(payload: dict) -> list[str]:
    """편집 입력에서 바뀐 파일 경로를 꺼낸다. 경로를 알 수 없는 입력은 빈 목록이다."""
    tool_input = payload.get("tool_input")
    paths: list[str] = []
    if isinstance(tool_input, dict):
        for key in ("file_path", "path"):
            if isinstance(tool_input.get(key), str) and tool_input[key]:
                paths.append(tool_input[key])
        command = tool_input.get("command")
        if not paths and isinstance(command, str):
            paths.extend(_patch_files(command))
    if not paths and isinstance(payload.get("file_path"), str) and payload["file_path"]:
        paths.append(payload["file_path"])
    return paths


def parse_event(payload: dict, forced: str | None = None) -> HookEvent:
    name = _event_name(payload, forced)
    session = str(payload.get("session_id") or payload.get("conversation_id") or "default")
    cwd = _working_dir(payload)
    if name in START_EVENTS or name == "start":
        return HookEvent("start", session, cwd)
    if name in STOP_EVENTS:
        continuing = bool(payload.get("stop_hook_active")) or int(payload.get("loop_count") or 0) >= CURSOR_FOLLOWUP_LIMIT
        return HookEvent("stop", session, cwd, continuing=continuing)
    if name and name not in EDIT_EVENTS and name != "edit":
        return HookEvent("ignore", session, cwd)
    files = []
    for raw in edited_paths(payload):
        path = Path(raw)
        files.append(path if path.is_absolute() else cwd / path)
    return HookEvent("edit", session, cwd, files)


def _state_file(agent: str, session: str) -> Path:
    user = getattr(os, "getuid", lambda: 0)()
    directory = Path(tempfile.gettempdir()) / f"iron-laws-hook-{user}"
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory / f"{agent}-{hashlib.sha256(session.encode('utf-8')).hexdigest()[:16]}.json"


def recorded_files(agent: str, session: str) -> list[Path]:
    try:
        data = json.loads(_state_file(agent, session).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("훅 상태 파일을 읽지 못해 빈 목록으로 처리합니다: %s", exc)
        return []
    return [Path(item) for item in data if isinstance(item, str)] if isinstance(data, list) else []


def record_files(agent: str, session: str, files: list[Path]) -> None:
    """세션에서 편집한 파일을 임시 폴더에 기록한다. 프로젝트 안에는 아무것도 쓰지 않는다."""
    current = recorded_files(agent, session)
    known = {p.as_posix() for p in current}
    merged = current + [f for f in files if f.as_posix() not in known]
    try:
        _state_file(agent, session).write_text(json.dumps([p.as_posix() for p in merged[-MAX_RECORDED_FILES:]]), encoding="utf-8")
    except OSError as exc:
        logger.debug("훅 상태 파일을 쓰지 못했습니다: %s", exc)
        return


def _git_root(folder: Path) -> Path | None:
    for candidate in (folder, *folder.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def project_root(target: Path, cwd: Path | None = None) -> Path:
    """편집한 파일이 속한 프로젝트 루트. 파일의 폴더에서 위로 올라가며 설정 파일이 있는 첫 폴더를 찾는다.
    올라가는 범위는 git 루트까지(git이 없으면 작업 폴더까지)이며, 설정 파일이 없으면 그 범위의 끝이 루트다."""
    from iron_laws.core.config import CONFIG_NAMES

    folder = target.resolve().parent
    limit = _git_root(folder)
    if limit is None and cwd is not None and folder.is_relative_to(cwd.resolve()):
        limit = cwd.resolve()
    for candidate in (folder, *folder.parents):
        if any((candidate / name).is_file() for name in CONFIG_NAMES):
            return candidate
        if candidate == limit:
            return candidate
    return folder


def _scan_in_project(target: Path, cwd: Path | None) -> tuple[list[Violation], str | None]:
    """파일 하나를 그 파일이 속한 프로젝트의 설정·기준선·상대 경로로 점검한다. 설정에서 제외한 파일이면 빈 결과다.
    기준선이 있으면 기준선에 없던 지적과 다시 볼 지적만 돌려준다. 함께 돌려주는 값은 그 프로젝트 설정의 단계(stage)다."""
    from iron_laws.core.baseline import load_baseline
    from iron_laws.core.config import ConfigError, load_config
    from iron_laws.core.scanner import AuditScanner

    root = project_root(target, cwd)
    config, _source = load_config(root)
    rel = target.resolve().relative_to(root)
    if AuditScanner(root, config=config.model_copy(deep=True))._matching_exclude(target.resolve()) is not None:
        return [], config.stage
    baseline_path = root / BASELINE_NAME
    baseline = None
    if baseline_path.is_file():
        try:
            baseline = load_baseline(baseline_path)
        except ConfigError as exc:
            logger.debug("기준선을 읽지 못해 기준선 없이 점검합니다: %s", exc)
    scanner = AuditScanner(target, config=config, baseline=baseline)
    scanner.single_file_rel = rel
    violations = scanner.scan().violations
    if baseline is not None:
        violations = [v for v in violations if v.baseline_status is None or v.baseline_status.value in ("new", "review")]
    return violations, config.stage


def blocking_findings(files: list[Path], threshold: Severity, cwd: Path | None = None) -> list[tuple[Path, Violation]]:
    """막을 지적. 프로젝트 설정에 단계(stage)가 있으면 단계 정책으로, 없으면 threshold 이상 심각도로 정한다(core/gating.py)"""
    from iron_laws.core.gating import blocks, stage_policy

    found: list[tuple[Path, Violation]] = []
    for target in files:
        if not target.is_file():
            continue
        violations, stage = _scan_in_project(target, cwd)
        policy = stage_policy(stage, threshold.value)
        found.extend((target, v) for v in violations if blocks(v.rule_id, v.severity.value, v.confidence.value, v.layer.value, policy, threshold.value, v.tags))
    return found


def _index_file(agent: str, session: str) -> Path:
    return _state_file(agent, session).with_suffix(".functions.json")


def _project_config(target: Path, cwd: Path | None):
    from iron_laws.core.config import load_config

    root = project_root(target, cwd)
    return root, load_config(root)[0]


def build_session_index(agent: str, session: str, cwd: Path) -> None:
    """세션 시작 때 프로젝트 함수 지문 색인을 임시 폴더에 남긴다(편집 중 새 중복 알림용). 상한을 넘으면 남기지 않는다"""
    from iron_laws.core import hook_index
    from iron_laws.core.config import ConfigError

    try:
        root, config = _project_config(cwd.resolve() / "_", cwd)
    except ConfigError as exc:
        logger.debug("설정을 읽지 못해 함수 색인을 만들지 않습니다: %s", exc)
        return
    _state_file(agent, session).with_suffix(".notes.json").unlink(missing_ok=True)  # 세션을 새로 시작하면 알린 기록과 색인을 새로 쓴다
    _index_file(agent, session).unlink(missing_ok=True)
    index = hook_index.build(root, config)
    if index is not None:
        hook_index.save(_index_file(agent, session), index)


def duplicate_notes(agent: str, session: str, files: list[Path], threshold: Severity, cwd: Path | None) -> str:
    """이번 세션에 새로 만든 함수가 이미 있는 함수와 거의 같으면 알린다. 단계 정책이 ARC-204를 막을 때(production, 또는 threshold가 MEDIUM 이하)만 알린다.
    같은 알림은 세션에서 한 번만 한다"""
    from iron_laws.core import hook_index
    from iron_laws.core.gating import blocks, stage_policy

    index = hook_index.load(_index_file(agent, session))
    if index is None:
        return ""
    seen_file = _state_file(agent, session).with_suffix(".notes.json")
    try:
        seen = set(json.loads(seen_file.read_text(encoding="utf-8")))
    except (OSError, ValueError):  # iron-laws: ignore[IL-301] 알린 기록이 없으면 처음 알리는 것으로 본다
        seen = set()
    lines: list[str] = []
    for target in files:
        root, config = _project_config(target, cwd)
        if not blocks("ARC-204", "MEDIUM", "CONFIRMED", "ARCHITECTURE", stage_policy(config.stage, threshold.value), threshold.value):
            continue
        for hint in hook_index.new_duplicates(index, target, target.resolve().relative_to(root).as_posix(), config):
            key = f"{hint.path}:{hint.name}:{hint.other_path}:{hint.other_name}"
            if key not in seen:
                seen.add(key)
                lines.append(f"- ARC-204 {hint.text()}")
    if not lines:
        return ""
    try:
        seen_file.write_text(json.dumps(sorted(seen)), encoding="utf-8")
    except OSError as exc:
        logger.debug("알린 기록을 쓰지 못했습니다: %s", exc)
    return "오철칙: 이미 있는 함수와 거의 같은 함수를 새로 만들었습니다.\n" + "\n".join(lines) + "\n"


STRUCTURE_SECONDS = 30.0


def structure_findings(files: list[Path], threshold: Severity, cwd: Path | None) -> list[tuple[Path, Violation]]:
    """종료 직전에 프로젝트 전체로 순환(ARC-203)·계층 위반(ARC-207)을 보고, 이번 세션에 편집한 파일의 지적 가운데 막을 것만 돌려준다"""
    from iron_laws.core.baseline import load_baseline
    from iron_laws.core.config import ConfigError
    from iron_laws.core.gating import blocks, stage_policy
    from iron_laws.core.scanner import AuditScanner

    by_root: dict[Path, list[Path]] = {}
    for target in files:
        if target.is_file():
            by_root.setdefault(project_root(target, cwd), []).append(target)
    found: list[tuple[Path, Violation]] = []
    for root, targets in by_root.items():
        try:
            _root, config = _project_config(targets[0], cwd)
            baseline = load_baseline(root / BASELINE_NAME) if (root / BASELINE_NAME).is_file() else None
        except ConfigError as exc:
            logger.debug("구조 점검을 건너뜁니다: %s", exc)
            continue
        policy = stage_policy(config.stage, threshold.value)
        scoped = config.model_copy(deep=True)
        scoped.enabled_rules = ["ARC-203", "ARC-207"]
        scoped.limits.max_wall_seconds = STRUCTURE_SECONDS
        report = AuditScanner(root, config=scoped, baseline=baseline).scan()
        rels = {t.resolve().relative_to(root).as_posix(): t for t in targets}
        for v in report.violations:
            target = rels.get(v.file_path.as_posix())
            if target is None or (baseline is not None and v.baseline_status is not None and v.baseline_status.value == "existing"):
                continue
            if blocks(v.rule_id, v.severity.value, v.confidence.value, v.layer.value, policy, threshold.value, v.tags):
                found.append((target, v))
    return found


def feedback_text(found: list[tuple[Path, Violation]], threshold: Severity, limit: int, action: str) -> str:
    names = sorted({target.name for target, _ in found})
    label = names[0] if len(names) == 1 else f"{names[0]} 외 {len(names) - 1}개 파일"
    lines = [f"오철칙: {label}에 {threshold.value} 이상 지적 {len(found)}건이 있습니다. {action}"]
    for _, v in found[:limit]:
        lines.append(f"- {v.rule_id} {v.severity.value} {v.file_path.as_posix()}:{v.line_number} {v.message}")
        if v.how_to_fix:
            lines.append(f"  고치는 방법: {v.how_to_fix}")
    return "\n".join(lines) + "\n"


def _respond(agent: str, kind: str, text: str, event: HookEvent) -> HookResult:
    """점검 결과 글을 에이전트가 받는 형식으로 바꾼다."""
    if kind == "start":
        if agent == "cursor":
            return HookResult(0, json.dumps({"additional_context": text}, ensure_ascii=False))
        return HookResult(0, text)
    if agent == "cursor":
        return HookResult(0, json.dumps({"followup_message": text}, ensure_ascii=False))
    return HookResult(2, "", text)


def start_text(cwd: Path, threshold: Severity) -> str:
    """프로젝트 언어에 해당하는 규칙만 지침으로 내보낸다. 언어를 알 수 없으면 빈 글이다."""
    from iron_laws.core.guidelines import export_guidelines
    from iron_laws.core.support_matrix import LANG_ORDER
    from iron_laws.engine.languages import detect_language
    from iron_laws.rules.catalog import ALL_RULES

    allowed = {lang.value for lang in LANG_ORDER}
    languages: set[str] = set()
    base = cwd.resolve()
    if not base.is_dir():
        return ""
    skipped = {"node_modules", "venv", "dist", "build", "target", "vendor"}
    for root, dirs, names in os.walk(base):
        depth = len(Path(root).relative_to(base).parts)
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in skipped] if depth < 3 else []
        for name in names:
            lang = detect_language(Path(name))
            if lang is not None and lang.value in allowed:
                languages.add(lang.value)
    if not languages:
        return ""
    from iron_laws.core.config import ConfigError, load_config

    try:
        stage = load_config(project_root(base / "_", base))[0].stage
    except ConfigError as exc:
        logger.debug("설정을 읽지 못해 단계 없이 지침을 만듭니다: %s", exc)
        stage = None
    text = export_guidelines([cls() for cls in ALL_RULES], threshold, languages, Severity.HIGH, stage)
    if len(text) > MAX_START_TEXT:
        text = text[:MAX_START_TEXT].rsplit("\n", 1)[0] + "\n…(이하 생략. 전체는 `iron-laws guidelines export`)\n"
    return text


def handle(agent: str, payload: dict, threshold: Severity, limit: int, forced: str | None = None) -> HookResult:
    event = parse_event(payload, forced)
    if event.kind == "ignore":
        return HookResult()
    if event.kind == "start":
        build_session_index(agent, event.session, event.cwd)
        text = start_text(event.cwd, threshold)
        return _respond(agent, "start", text, event) if text else HookResult()
    if event.kind == "stop":
        if event.continuing:
            return HookResult()
        recorded = recorded_files(agent, event.session)[-50:]
        found = blocking_findings(recorded, threshold, event.cwd) + structure_findings(recorded, threshold, event.cwd)
        parts = [feedback_text(found, threshold, limit, "끝내기 전에 고치십시오.")] if found else []
        if agent == "cursor":  # 편집 직후에 알릴 수 없었으므로 새 중복도 종료 때 알린다
            notes = duplicate_notes(agent, event.session, recorded, threshold, event.cwd)
            parts += [notes] if notes else []
        if agent == "cursor":  # 편집 직후에 알릴 수 없었으므로 종료 때 보호 경로 변경도 알린다
            root, globs = protected_globs(event.cwd)
            touched = [f for f in recorded if f.is_file() and is_protected(f, root, globs)]
            if touched:
                parts.insert(0, protected_notice(touched, root))
        if not parts:
            return HookResult()
        return _respond(agent, "stop", "".join(parts), event)
    files = [f for f in event.files if f.is_file()]
    if not files:
        return HookResult()
    record_files(agent, event.session, files)
    if agent == "cursor":
        return HookResult()  # afterFileEdit는 응답을 에이전트에 전달하지 못한다. stop에서 알린다
    root, globs = protected_globs(event.cwd)
    touched = [f for f in files if is_protected(f, root, globs)]
    found = blocking_findings(files, threshold, event.cwd)
    parts = [protected_notice(touched, root)] if touched else []
    if found:
        parts.append(feedback_text(found, threshold, limit, "고친 뒤 다시 저장하십시오."))
    notes = duplicate_notes(agent, event.session, files, threshold, event.cwd)
    if notes:
        parts.append(notes)
    if not parts:
        return HookResult()
    return _respond(agent, "edit", "".join(parts), event)


def _head_text(root: Path, rel: str) -> str | None:
    """git에 올라간 마지막 커밋의 파일 내용. git이 없거나 추적하지 않는 파일이면 None."""
    try:
        done = subprocess.run(["git", "-C", str(root), "show", f"HEAD:./{rel}"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("git show를 실행하지 못했습니다: %s", exc)
        return None
    return done.stdout if done.returncode == 0 else None


def _yaml_mapping(text: str | None) -> dict:
    import yaml

    if text is None:
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.debug("정책 파일 YAML을 읽지 못했습니다: %s", exc)
        return {}
    return data if isinstance(data, dict) else {}


def _policy_root(cwd: Path) -> tuple[Path, Path | None]:
    from iron_laws.core.config import find_config_file

    config = find_config_file(cwd, None, search_parents=True)
    return (config.parent if config is not None else cwd.resolve()), config


def protected_globs(cwd: Path) -> tuple[Path, tuple[str, ...]]:
    """(프로젝트 폴더, 보호 경로 패턴). 사용자 설정은 마지막 커밋의 내용을 쓴다. 에이전트가 같은 세션에서 설정을 고쳐 보호를 풀지 못하게 한다."""
    root, config = _policy_root(cwd)
    policies: dict = {}
    if config is not None:
        committed = _head_text(root, config.name)
        policies = (_yaml_mapping(committed if committed is not None else config.read_text(encoding="utf-8", errors="replace")).get("policies")) or {}
    extra = [g for g in policies.get("protected_paths", []) if isinstance(g, str)] if isinstance(policies, dict) else []
    excluded = {g for g in policies.get("protected_paths_exclude", []) if isinstance(g, str)} if isinstance(policies, dict) else set()
    return root, (*LOCKED_PROTECTED, *[g for g in DEFAULT_PROTECTED if g not in excluded], *extra)


def is_protected(path: Path, root: Path, globs: tuple[str, ...]) -> bool:
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        logger.debug("프로젝트 밖 경로라 보호 대상이 아닙니다: %s", exc)
        return False
    return any(fnmatch.fnmatch(rel, g) or ("/" not in g and fnmatch.fnmatch(rel.rsplit("/", 1)[-1], g)) for g in globs)


def policy_changes(path: Path, root: Path) -> list[str]:
    """설정 파일을 마지막 커밋과 비교해 탐지를 약하게 만드는 변경을 적는다. 비교할 수 없으면 빈 목록이다."""
    if path.name not in (".iron-laws.yml", ".iron-laws.yaml"):
        return []
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
        now = _yaml_mapping(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as exc:
        logger.debug("설정 파일을 비교하지 못했습니다: %s", exc)
        return []
    before_text = _head_text(root, rel)
    if before_text is None:
        return []
    before = _yaml_mapping(before_text)
    notes: list[str] = []
    order = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}
    old_fail, new_fail = str(before.get("fail_on", "HIGH")).upper(), str(now.get("fail_on", "HIGH")).upper()
    if order.get(new_fail, 0) > order.get(old_fail, 0):
        notes.append(f"fail_on을 {old_fail}에서 {new_fail}로 올렸습니다(차단 기준이 느슨해짐)")
    stages = ("prototype", "launch", "production")
    old_stage, new_stage = before.get("stage"), now.get("stage")
    if old_stage in stages and (new_stage not in stages or stages.index(new_stage) < stages.index(old_stage)):
        notes.append(f"단계를 {old_stage}에서 {new_stage or '(없음)'}로 낮췄습니다(통과를 막는 지적이 줄어듦)")
    for key, label in (("excludes", "점검 제외 경로"), ("disabled_rules", "끈 규칙")):
        added = sorted(set(map(str, now.get(key) or [])) - set(map(str, before.get(key) or [])))
        if added:
            notes.append(f"{label} 추가: {', '.join(added)}")
    for key, value in (now.get("limits") or {}).items() if isinstance(now.get("limits"), dict) else []:
        old = (before.get("limits") or {}).get(key) if isinstance(before.get("limits"), dict) else None
        if isinstance(value, (int, float)) and isinstance(old, (int, float)) and value > old and not key.startswith("min"):
            notes.append(f"limits.{key}를 {old}에서 {value}로 올렸습니다")
    old_policies, new_policies = before.get("policies") or {}, now.get("policies") or {}
    if isinstance(old_policies, dict) and isinstance(new_policies, dict):
        lost = sorted(set(map(str, old_policies.get("protected_paths") or [])) - set(map(str, new_policies.get("protected_paths") or [])))
        if lost:
            notes.append(f"보호 경로 제거: {', '.join(lost)}")
        gained = sorted(set(map(str, new_policies.get("protected_paths_exclude") or [])) - set(map(str, old_policies.get("protected_paths_exclude") or [])))
        if gained:
            notes.append(f"보호 경로 제외 추가: {', '.join(gained)}")
    return notes


def protected_notice(files: list[Path], root: Path) -> str:
    lines = ["오철칙: 에이전트가 정책·지침 파일을 고쳤습니다. 사용자가 이 파일을 고치라고 요청한 것이 아니면 되돌리고, 요청한 것이면 변경 내용을 사용자에게 알리십시오."]
    for path in files:
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:  # iron-laws: ignore[IL-301] 점검 폴더 밖의 파일은 상대 경로가 없으니 파일 이름만 알린다
            rel = path.name
        lines.append(f"- {rel}")
        lines.extend(f"  {note}" for note in policy_changes(path, root))
    return "\n".join(lines) + "\n"
