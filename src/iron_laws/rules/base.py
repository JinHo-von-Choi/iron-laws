"""
오철칙 Base Rule Class
작성자: 최진호
작성일: 2026-10-04
"""

from abc import ABC
from pathlib import Path

from tree_sitter import Node

from iron_laws.core.config import IronLawsConfig
from iron_laws.core.models import (
    CodeFix,
    Confidence,
    GovStandard,
    IronLaw,
    RuleLayer,
    Severity,
    Violation,
)
from iron_laws.engine.languages import Lang
from iron_laws.engine.project import ProjectContext
from iron_laws.engine.source import SourceFile

SEVERITY_DOWN = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.LOW,
}


class BaseRule(ABC):
    rule_id: str
    name: str
    iron_law: IronLaw
    severity: Severity
    gov_standard: GovStandard | None
    layer: RuleLayer = RuleLayer.STANDARD
    include_tests: bool = False
    languages: frozenset[Lang] | None = None
    plain: str = ""
    how_to_fix: str = ""
    config: IronLawsConfig | None = None

    def configure(self, config: IronLawsConfig) -> None:
        self.config = config

    def applies_to(self, src: SourceFile) -> bool:
        if self.languages is None:
            return True
        return src.lang in self.languages

    def check(self, src: SourceFile) -> list[Violation]:
        """파일 단위 검사 후 위반 사항 리스트 반환. 프로젝트 단위 규칙은 구현하지 않아도 된다."""
        return []

    def check_project(self, project: ProjectContext) -> list[Violation]:
        """프로젝트 전체를 보아야 하는 검사. 기본은 없음"""
        return []

    def violation(
        self,
        file_path: Path,
        line_number: int,
        snippet: str,
        message: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        fix: CodeFix | None = None,
        how_to_fix: str | None = None,
        column: int = 1,
    ) -> Violation:
        return Violation(
            rule_id=self.rule_id,
            rule_name=self.name,
            iron_law=self.iron_law,
            severity=severity or self.severity,
            file_path=file_path,
            line_number=line_number,
            column=column,
            snippet=snippet.strip()[:300],
            message=message,
            gov_standard=self.gov_standard,
            fix=fix,
            layer=self.layer,
            confidence=confidence,
            plain=self.plain,
            how_to_fix=how_to_fix if how_to_fix is not None else self.how_to_fix,
        )

    def at_node(
        self,
        src: SourceFile,
        node: Node,
        message: str,
        **kwargs,
    ) -> Violation:
        line = src.line_of(node)
        return self.violation(
            src.path, line, src.snippet_at(line), message, column=node.start_point[1] + 1, **kwargs
        )

    def at_line(self, src: SourceFile, line: int, message: str, **kwargs) -> Violation:
        return self.violation(src.path, line, src.snippet_at(line), message, **kwargs)

    @staticmethod
    def downgrade(severity: Severity) -> Severity:
        return SEVERITY_DOWN[severity]
