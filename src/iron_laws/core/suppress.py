"""
오철칙 지적 억제 주석 처리: 사유가 있는 억제만 인정한다
작성자: 최진호
작성일: 2026-10-04
"""

import re
from dataclasses import dataclass, field

from iron_laws.core.models import Violation

SUPPRESS_RE = re.compile(
    r"iron-laws:\s*(?P<kind>ignore-file|ignore)\s*\[(?P<ids>[^\]]+)\]\s*(?P<reason>[^\n]*)"
)
MIN_REASON_LENGTH = 3
FILE_DIRECTIVE_WINDOW = 30


@dataclass
class FileSuppressions:
    file_rules: set[str] = field(default_factory=set)
    line_rules: dict[int, set[str]] = field(default_factory=dict)

    def covers(self, violation: Violation) -> bool:
        if violation.rule_id in self.file_rules:
            return True
        for line in (violation.line_number, violation.line_number - 1):
            if violation.rule_id in self.line_rules.get(line, ()):
                return True
        return False


def _clean_reason(raw: str) -> str:
    return re.sub(r"(\*/|-->|\"\"\"|''')\s*$", "", raw).strip()


def parse_suppressions(lines: list[str]) -> FileSuppressions:
    result = FileSuppressions()
    for idx, line in enumerate(lines, start=1):
        m = SUPPRESS_RE.search(line)
        if not m:
            continue
        if len(_clean_reason(m.group("reason"))) < MIN_REASON_LENGTH:
            continue
        ids = {i.strip() for i in m.group("ids").split(",") if i.strip()}
        if m.group("kind") == "ignore-file":
            if idx <= FILE_DIRECTIVE_WINDOW:
                result.file_rules |= ids
        else:
            result.line_rules.setdefault(idx, set()).update(ids)
    return result
