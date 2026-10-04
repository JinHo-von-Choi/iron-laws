"""
오철칙 우회 변경 탐지: 경고가 사라진 이유가 '고쳐서'가 아니라 '가려서'인지 가린다
시험 삭제·skip 증가·단언 약화·정책 약화·baseline 재생성·무시 주석 추가·시험 기반 파일 변경을 각각 별도 변경으로 표시한다.
경고가 사라졌다는 사실만으로 수정으로 인정하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from iron_laws.core.paths import is_test_path

POLICY_FILES = (
    ".iron-laws.yml",
    ".iron-laws.yaml",
    ".iron-laws-contract.yml",
    ".iron-laws-baseline.json",
    ".iron-laws-approvals.jsonl",
    ".iron-laws-runner.yml",
)
TEST_INFRA_NAMES = frozenset({"conftest.py", "pytest.ini", "tox.ini", "setup.cfg", "sitecustomize.py", "usercustomize.py", "noxfile.py", "jest.config.js", "jest.config.ts", "vitest.config.ts", "vitest.config.js"})
SKIP_RE = re.compile(
    r"@pytest\.mark\.(?:skip|xfail)\b|pytest\.(?:skip|xfail)\(|@unittest\.(?:skip|expectedFailure)|\bunittest\.skip|"
    r"\b(?:it|test|describe)\.(?:skip|todo|fixme)\b|\bx(?:it|describe|test)\(|@Disabled\b|@Ignore\b|\[Ignore|\[Skip|#\[ignore\b|t\.Skip\("
)
ASSERT_RE = re.compile(r"^\s*assert\b|\bself\.assert\w+\(|\bexpect\(|\bassert[A-Z]\w*\(|\bt\.(?:Error|Fatal)f?\(", re.MULTILINE)
TRIVIAL_ASSERT_RE = re.compile(r"^\s*assert\s+(?:True|1)\s*(?:#.*)?$", re.MULTILINE)
TEST_FUNC_RE = re.compile(r"^\s*(?:async\s+)?def\s+test_\w+|\b(?:it|test)\(\s*['\"`]|@Test\b|\bfunc\s+Test\w+\(", re.MULTILINE)
IGNORE_RE = re.compile(r"iron-laws:\s*ignore|#\s*nosec\b|#\s*noqa\b|#\s*type:\s*ignore|//\s*eslint-disable|@SuppressWarnings|#\s*pragma:\s*no cover|//\s*nolint")


@dataclass
class BypassChange:
    kind: str  # test_deleted / test_removed / test_modified / skip_added / assertion_weakened / policy_changed / baseline_changed / ignore_added / config_weakened / test_infra_changed / test_added_untrusted
    path: str
    detail: str


def _read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        return ""  # 원본에 없거나 후보에서 지워진 파일. 읽기 오류는 숨기지 않고 그대로 올라간다
    return path.read_text(encoding="utf-8", errors="replace")


def _count(pattern: re.Pattern[str], text: str) -> int:
    return len(pattern.findall(text))


def _config_weakened(original: str, candidate: str) -> list[str]:
    try:
        before = yaml.safe_load(original) or {}
        after = yaml.safe_load(candidate) or {}
    except yaml.YAMLError:
        return ["설정 파일을 해석할 수 없어 약화 여부를 판단하지 못했다"]
    if not isinstance(before, dict) or not isinstance(after, dict):
        return ["설정 파일 구조가 바뀌었다"]
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings: list[str] = []
    if len(after.get("disabled_rules") or []) > len(before.get("disabled_rules") or []):
        findings.append("disabled_rules가 늘었다")
    if len(after.get("excludes") or []) > len(before.get("excludes") or []):
        findings.append("excludes가 늘었다")
    if before.get("enabled_rules") is None and after.get("enabled_rules") is not None:
        findings.append("enabled_rules로 규칙 집합을 좁혔다")
    elif before.get("enabled_rules") and after.get("enabled_rules") and len(after["enabled_rules"]) < len(before["enabled_rules"]):
        findings.append("enabled_rules가 줄었다")
    if order.get(str(after.get("fail_on", "HIGH")), 3) > order.get(str(before.get("fail_on", "HIGH")), 3):
        findings.append("fail_on 기준이 완화되었다(실패 임계치가 더 높은 심각도로 올라갔다)")
    for key, value in (after.get("limits") or {}).items():
        old = (before.get("limits") or {}).get(key)
        if isinstance(value, (int, float)) and isinstance(old, (int, float)) and value > old and key != "duplicate_similarity":
            findings.append(f"limits.{key}를 늘렸다({old} → {value})")
    return findings


def detect_bypasses(original: Path, candidate: Path, touched: list[str], deleted: list[str], extra_policy_files: tuple[str, ...] = ()) -> list[BypassChange]:
    """patch가 건드린 파일을 원본·후보에서 비교해 우회 변경을 찾는다."""
    changes: list[BypassChange] = []
    policy_names = set(POLICY_FILES) | set(extra_policy_files)
    for rel in sorted(set(touched)):
        name = Path(rel).name
        in_original = (original / rel).is_file()
        in_candidate = (candidate / rel).is_file()
        before, after = _read(original, rel), _read(candidate, rel)
        if rel in policy_names or name in policy_names:
            kind = "baseline_changed" if "baseline" in name else "policy_changed"
            changes.append(BypassChange(kind, rel, "검증 정책·기준선 파일을 patch가 바꾸려 했다"))
            if name in (".iron-laws.yml", ".iron-laws.yaml") and in_original and in_candidate:
                for detail in _config_weakened(before, after):
                    changes.append(BypassChange("config_weakened", rel, detail))
            continue
        if name in TEST_INFRA_NAMES or name.endswith(".pth"):
            changes.append(BypassChange("test_infra_changed", rel, "시험 실행 환경을 바꾸는 파일을 patch가 바꾸려 했다"))
        if is_test_path(Path(rel)):
            if not in_candidate and in_original:
                changes.append(BypassChange("test_deleted", rel, "시험 파일을 삭제했다"))
                continue
            if not in_original:
                changes.append(BypassChange("test_added_untrusted", rel, "patch가 새로 추가한 시험은 신뢰된 시험에 포함하지 않는다"))
                continue
            if _count(TEST_FUNC_RE, after) < _count(TEST_FUNC_RE, before):
                changes.append(BypassChange("test_removed", rel, f"시험 함수가 줄었다({_count(TEST_FUNC_RE, before)} → {_count(TEST_FUNC_RE, after)})"))
            if _count(SKIP_RE, after) > _count(SKIP_RE, before):
                changes.append(BypassChange("skip_added", rel, f"skip·xfail이 늘었다({_count(SKIP_RE, before)} → {_count(SKIP_RE, after)})"))
            if _count(ASSERT_RE, after) < _count(ASSERT_RE, before) or _count(TRIVIAL_ASSERT_RE, after) > _count(TRIVIAL_ASSERT_RE, before):
                changes.append(BypassChange("assertion_weakened", rel, "단언이 줄었거나 무의미한 단언(assert True)이 늘었다"))
            if before != after and not any(c.path == rel for c in changes):
                changes.append(BypassChange("test_modified", rel, "원본 시험의 내용을 patch가 바꿨다. 신뢰된 시험은 원본 그대로 실행한다"))
        if in_candidate and _count(IGNORE_RE, after) > _count(IGNORE_RE, before):
            changes.append(BypassChange("ignore_added", rel, f"무시 주석이 늘었다({_count(IGNORE_RE, before)} → {_count(IGNORE_RE, after)})"))
    for rel in deleted:
        if is_test_path(Path(rel)) and not any(c.path == rel and c.kind == "test_deleted" for c in changes):
            changes.append(BypassChange("test_deleted", rel, "시험 파일을 삭제했다"))
    return changes
