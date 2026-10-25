"""
오철칙 MCP 서버(stdio): 코딩 에이전트가 점검·설명·수정 지시문·패치 검증·의존성 점검을 도구로 부른다

- 모든 경로 입력(path, patch_path, regression_spec, advisory_db)은 서버를 띄울 때 정한 기준 폴더(--root) 안에서만 받는다.
  심볼릭 링크를 풀어 밖을 가리키면 거부한다.
- 패치 검증의 시험 명령은 MCP 입력으로 받지 않는다. 서버 운영자가 점검 폴더 밖의 서버 설정 파일에 정의한 test_presets의 이름만 받는다.
  저장소 안의 설정 파일(.iron-laws.yml, 실행 정책 파일)은 시험 명령·실행 이미지의 근거로 쓰지 않는다.
- 도구 처리 함수(IronLawsTools)는 MCP SDK 없이 쓸 수 있다. SDK는 serve()에서만 불러온다(선택 extra `iron-laws[mcp]`).
작성자: 최진호
작성일: 2026-10-12
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from iron_laws.core.config import ConfigError
from iron_laws.core.paths import OutsideRootError, resolve_within

MAX_FINDINGS = 200
DEFAULT_PRESET_IMAGE = "python:3.13-slim"

INSTRUCTIONS = (
    "오철칙(iron-laws) 소스코드 보안·품질 점검 도구입니다. 경로는 서버 기준 폴더 안의 상대 경로로 주십시오. "
    "check로 지적을 받고, explain으로 규칙을 확인하고, 고친 뒤 verify_patch로 같은 조건에서 검증하십시오. "
    "'확인 필요' 지적은 사람이 판단할 항목이며 통과는 안전 증명이 아닙니다."
)

TOOL_DESCRIPTIONS = {
    "check": "폴더나 파일을 점검해 요약과 지적 목록(규칙, 위치, 심각도, 확정 여부, 메시지)을 돌려줍니다. changed_since를 주면 그 git 기준 이후 바뀐 파일의 지적만 판정에 씁니다.",
    "explain": "규칙 하나의 이름, 심각도, 근거 기준, 왜 문제인지, 고치는 방법을 돌려줍니다.",
    "fix_prompt": "점검 결과를 코딩 에이전트가 따라 고칠 수 있는 지시문으로 돌려줍니다. limit은 담을 최대 지적 수입니다.",
    "verify_patch": "unified diff 패치를 원본과 같은 정책·조건으로 검증하고 판정(verified, failed, undeterminable)과 항목별 근거를 돌려줍니다. 시험은 서버 운영자가 정한 test_preset 이름으로만 실행합니다. regression_spec을 주면 결함 행동 제거 여부를 정적 지적 소멸과 따로 돌려줍니다.",
    "deps": "잠금 파일의 고정 버전을 받아 둔 OSV 권고 목록과 맞춰 취약 의존성과 수정 경계를 돌려줍니다. 네트워크를 쓰지 않습니다.",
}


@dataclass
class TestPreset:
    command: list[str]
    runner: str = "auto"
    image: str = DEFAULT_PRESET_IMAGE
    timeout: int = 180


@dataclass
class ServerSettings:
    root: Path
    test_presets: dict[str, TestPreset] = field(default_factory=dict)


def load_settings(root: Path, server_config: Path | None) -> ServerSettings:
    """기준 폴더와 서버 설정을 읽는다. 서버 설정 파일이 기준 폴더 안에 있으면 거부한다(점검 대상 저장소가 시험 명령을 정하게 하지 않는다)."""
    try:
        base = Path(root).resolve(strict=True)
    except OSError as e:
        raise ConfigError(f"기준 폴더가 없습니다: {root}") from e
    if not base.is_dir():
        raise ConfigError(f"기준 폴더가 폴더가 아닙니다: {root}")
    settings = ServerSettings(base)
    if server_config is None:
        return settings
    config_path = Path(server_config).resolve()
    if config_path == base or base in config_path.parents:
        raise ConfigError("서버 설정 파일은 기준 폴더 밖에 두어야 합니다(점검 대상 저장소 안의 설정은 시험 명령의 근거로 쓰지 않습니다)")
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"서버 설정 파일을 읽을 수 없습니다: {e}") from e
    presets = data.get("test_presets", {}) if isinstance(data, dict) else {}
    if not isinstance(presets, dict):
        raise ConfigError("test_presets는 이름 → {command: [...]} 형식이어야 합니다")
    for name, spec in presets.items():
        command = spec.get("command") if isinstance(spec, dict) else None
        if not (isinstance(command, list) and command and all(isinstance(c, str) and c for c in command)):
            raise ConfigError(f"test_presets.{name}.command는 비어 있지 않은 문자열 목록이어야 합니다")
        settings.test_presets[str(name)] = TestPreset(
            command=list(command),
            runner=str(spec.get("runner", "auto")),
            image=str(spec.get("image", DEFAULT_PRESET_IMAGE)),
            timeout=int(spec.get("timeout", 180)),
        )
    return settings


class ToolInputError(ValueError):
    """도구 입력이 허용 범위를 벗어났다"""


class IronLawsTools:
    def __init__(self, settings: ServerSettings):
        self.settings = settings

    def _path(self, value: str | None, must_exist: bool = True) -> Path:
        if value is None or value == "":
            value = "."
        try:
            resolved = resolve_within(self.settings.root, value)
        except OutsideRootError as e:
            raise ToolInputError(str(e)) from e
        if must_exist and not resolved.exists():
            raise ToolInputError(f"경로가 없습니다: {value}")
        return resolved

    def _reject_outside_links(self, target: Path) -> None:
        """패치 검증은 대상 폴더를 복사해 쓰므로, 기준 폴더 밖을 가리키는 심볼릭 링크가 하나라도 있으면 거부한다."""
        if not target.is_dir():
            return
        for dirpath, dirnames, filenames in os.walk(target):
            for name in [*dirnames, *filenames]:
                entry = Path(dirpath) / name
                if entry.is_symlink() and not entry.resolve().is_relative_to(self.settings.root.resolve()):
                    raise ToolInputError(f"기준 폴더 밖을 가리키는 심볼릭 링크가 있습니다: {entry.relative_to(target).as_posix()}")

    def _scan(self, path: str, changed_since: str | None = None, fail_on: str | None = None, gates: dict[str, float] | None = None):
        from iron_laws.commands.common import _changed_files, _renamed_paths
        from iron_laws.core.config import find_config_file
        from iron_laws.core.models import Severity
        from iron_laws.core.scan_options import ScanOptions
        from iron_laws.core.scanner import AuditScanner

        target = self._path(path)
        config_file = find_config_file(target)
        if config_file is not None:
            self._path(str(config_file))  # 설정 파일도 기준 폴더 안이어야 한다(심볼릭 링크로 밖을 가리키면 거부)
        options = ScanOptions(
            root_path=target,
            confine_root=self.settings.root,
            changed_files=_changed_files(target, changed_since) if changed_since else None,
            changed_since=changed_since,
            renames=_renamed_paths(target, changed_since) if changed_since else None,
            gates=gates,
        )
        scanner = AuditScanner.from_options(options)
        if fail_on:
            try:
                scanner.config.fail_on = Severity(fail_on.upper())
            except ValueError as e:
                raise ToolInputError("fail_on은 CRITICAL, HIGH, MEDIUM, LOW 중 하나여야 합니다") from e
            scanner.fail_on_source = "MCP 입력"
        return scanner.scan(), target

    def check(self, path: str = ".", changed_since: str | None = None, fail_on: str | None = None,
              max_analysis_unknown_rate: float | None = None, max_unverified_rule_language_rate: float | None = None) -> dict[str, Any]:
        gates = {k: v for k, v in (("max_analysis_unknown_rate", max_analysis_unknown_rate), ("max_unverified_rule_language_rate", max_unverified_rule_language_rate)) if v is not None}
        for value in gates.values():
            if not 0.0 <= value <= 1.0:
                raise ToolInputError("비율 상한은 0과 1 사이여야 합니다")
        report, _ = self._scan(path, changed_since, fail_on, gates or None)
        summary = report.summary
        findings = [
            {
                "rule_id": v.rule_id,
                "path": v.file_path.as_posix(),
                "line": v.line_number,
                "severity": v.severity.value,
                "confidence": v.confidence.value,
                "message": v.message,
                "finding_id": v.finding_id,
            }
            for v in report.violations[:MAX_FINDINGS]
        ]
        return {
            "passed": summary.is_passed,
            "scan_status": summary.scan_status,
            "files_scanned": summary.total_files_scanned,
            "findings_total": len(report.violations),
            "findings": findings,
            "truncated": len(report.violations) > MAX_FINDINGS,
            "diagnostics": [{"kind": d.kind, "severity": d.severity, "message": d.message} for d in report.diagnostics[:50]],
        }

    def explain(self, rule_id: str) -> dict[str, Any]:
        from iron_laws.core.scanner import get_active_rules

        wanted = rule_id.strip().upper()
        for rule in get_active_rules():
            if rule.rule_id.upper() == wanted:
                std = rule.gov_standard
                return {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "severity": rule.severity.value,
                    "basis": f"{std.standard_name} - {std.clause_id}" if std else "",
                    "why": rule.plain,
                    "how_to_fix": rule.how_to_fix,
                }
        raise ToolInputError(f"규칙을 찾을 수 없습니다: {rule_id}")

    def fix_prompt(self, path: str = ".", limit: int = 40) -> str:
        from iron_laws.reporters.prompt import generate_fix_prompt

        if not 0 <= limit <= 500:
            raise ToolInputError("limit은 0~500이어야 합니다")
        report, _ = self._scan(path)
        return generate_fix_prompt(report, limit)

    def verify_patch(self, path: str, patch_path: str, finding: str | None = None, test_preset: str | None = None,
                     regression_spec: str | None = None) -> dict[str, Any]:
        from iron_laws.verify.engine import RunnerPolicy, VerifyOptions, verify_patch
        from iron_laws.verify.runner import RunLimits

        original = self._path(path)
        self._reject_outside_links(original)
        patch = self._path(patch_path)
        spec = self._path(regression_spec) if regression_spec else None
        preset = None
        if test_preset is not None:
            preset = self.settings.test_presets.get(test_preset)
            if preset is None:
                raise ToolInputError(f"서버 설정에 없는 시험 프리셋입니다: {test_preset} (사용 가능: {', '.join(sorted(self.settings.test_presets)) or '없음'})")
        policy = RunnerPolicy(image=preset.image if preset else DEFAULT_PRESET_IMAGE, allowed_commands=[preset.command] if preset else [], limits={})
        options = VerifyOptions(
            finding=finding,
            test_cmd=list(preset.command) if preset else None,
            runner=preset.runner if preset else "auto",
            image=preset.image if preset else DEFAULT_PRESET_IMAGE,
            limits=RunLimits(timeout_s=preset.timeout if preset else 180),
            regression_spec=spec,
            runner_policy=policy,
        )
        receipt = verify_patch(original, patch, options)
        regression = next((c for c in receipt.checks if c.id == "regression_test"), None)
        return {
            "verdict": receipt.verdict.overall,
            "label": receipt.verdict.label,
            "caveat": receipt.verdict.caveat,
            "checks": [{"id": c.id, "title": c.title, "result": c.result, "reason": c.reason} for c in receipt.checks],
            "static_finding_resolved": next((c.result for c in receipt.checks if c.id == "target_resolved"), None),
            "defect_behavior_removed": regression.result if regression is not None else "not_requested",
            "bypass_changes": receipt.bypass_changes,
            "receipt_digest": receipt.receipt_digest,
        }

    def deps(self, path: str, advisory_db: str) -> dict[str, Any]:
        from iron_laws.deps import report as dep_report
        from iron_laws.deps.advise import analyze
        from iron_laws.deps.lockfiles import find_lock_files, parse_lock
        from iron_laws.deps.osv import load_db

        target = self._path(path)
        db = load_db(self._path(advisory_db))
        if db.count == 0:
            raise ToolInputError("권고 목록이 비어 있습니다(비어 있는 목록을 '취약점 없음'으로 보지 않습니다)")
        locks, results = [], []
        for file in find_lock_files(target):
            self._path(str(file))  # 찾은 잠금 파일도 기준 폴더 안이어야 한다(심볼릭 링크로 밖을 가리키면 거부)
            lock = parse_lock(file)
            locks.append(lock)
            results.append(analyze(lock, db))
        return dep_report.build(locks, results, db)


def serve(settings: ServerSettings) -> None:
    """stdio MCP 서버를 띄운다. MCP SDK(선택 extra `iron-laws[mcp]`)가 필요하다."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:
        raise ConfigError("MCP 서버에는 선택 의존성이 필요합니다: pip install 'iron-laws[mcp]'") from e
    tools = IronLawsTools(settings)
    server = FastMCP("iron-laws", instructions=INSTRUCTIONS)
    for name, description in TOOL_DESCRIPTIONS.items():
        server.tool(name=name, description=description)(getattr(tools, name))
    server.run("stdio")
