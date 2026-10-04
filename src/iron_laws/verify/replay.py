"""
오철칙 검증 재실행: 기록된 입력·정책·조건으로 깨끗한 새 작업영역에서 다시 검증하고 결과가 재현되는지 비교한다
재실행은 이전 실행의 임시 작업영역·캐시를 쓰지 않는다. 입력(원본 트리·patch)의 해시가 기록과 다르면 재현이 아니라 '입력 불일치'다.
작성자: 최진호
작성일: 2026-10-04
"""

from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.config import ConfigError
from iron_laws.verify.engine import VerifyOptions, verify_patch
from iron_laws.verify.patchfile import inspect_patch
from iron_laws.verify.receipt import Receipt
from iron_laws.verify.runner import RunLimits
from iron_laws.verify.snapshot import scan_tree


@dataclass
class ReplayOutcome:
    reproduced: bool
    receipt: Receipt
    differences: list[str] = field(default_factory=list)


def options_from_record(record: dict) -> VerifyOptions:
    limits = RunLimits(**{k: v for k, v in (record.get("limits") or {}).items() if k in RunLimits.__dataclass_fields__})
    return VerifyOptions(
        finding=record.get("finding"),
        config_path=Path(record["config_path"]) if record.get("config_path") else None,
        contract_path=Path(record["contract_path"]) if record.get("contract_path") else None,
        test_cmd=record.get("test_cmd"),
        runner=record.get("runner", "auto"),
        image=record.get("image"),
        limits=limits,
        require_tests=record.get("require_tests", True),
        max_files=record.get("max_files", 5),
        allow_paths=tuple(record.get("allow_paths") or ()),
        regression_spec=Path(record["regression_spec"]) if record.get("regression_spec") else None,
    )


def replay_receipt(recorded: Receipt, original: Path, patch: Path, runner=None) -> ReplayOutcome:
    if not recorded.verify_seal():
        raise ConfigError("기록의 내용 해시가 맞지 않습니다(기록이 변경되었거나 손상되었습니다)")
    differences: list[str] = []
    original_digest = scan_tree(original.resolve()).digest
    patch_digest = inspect_patch(patch).digest
    if original_digest != recorded.inputs.get("original_tree"):
        differences.append("원본 트리의 해시가 기록과 다르다(입력 불일치)")
    if patch_digest != recorded.inputs.get("patch"):
        differences.append("patch의 해시가 기록과 다르다(입력 불일치)")
    fresh = verify_patch(original, patch, options_from_record(recorded.options), runner)
    before = {c.id: c.result for c in recorded.checks}
    after = {c.id: c.result for c in fresh.checks}
    for check_id in sorted(set(before) | set(after)):
        if before.get(check_id) != after.get(check_id):
            differences.append(f"항목 {check_id}: 기록 {before.get(check_id)} → 재실행 {after.get(check_id)}")
    for key in ("scanner", "config", "contract", "runner_policy"):
        if recorded.digests.get(key) != fresh.digests.get(key):
            differences.append(f"조건 해시 {key}가 다르다")
    if recorded.verdict.overall != fresh.verdict.overall:
        differences.append(f"종합 판정: 기록 {recorded.verdict.overall} → 재실행 {fresh.verdict.overall}")
    return ReplayOutcome(reproduced=not differences, receipt=fresh, differences=differences)
