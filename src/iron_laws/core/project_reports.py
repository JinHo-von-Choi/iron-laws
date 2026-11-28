"""
오철칙 프로젝트 단위 보고 자료: 라우트 접근통제 행렬, 조회문별 소속 확인 표, 지원 종료 판정, 매퍼 분석 규모.
규칙 활성화와 관계없이 점검마다 만들어 보고서 metadata에 싣는다.
작성자: 최진호
작성일: 2026-11-23
"""

from dataclasses import dataclass, field

from iron_laws.core.models import Diagnostic
from iron_laws.engine.project import ProjectContext

# 라우트 색인을 만들다 구문 트리가 예상과 다를 때 날 수 있는 오류. 점검은 계속하고 진단으로 남긴다
INDEX_ERRORS = (ValueError, KeyError, AttributeError, IndexError, TypeError, RecursionError)


@dataclass
class ProjectReports:
    routes: list[dict] = field(default_factory=list)
    tenancy: list[dict] | None = None
    eol: object = None  # review_rules_versions.EolReport
    counters: dict[str, int] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)


def collect_project_reports(project: ProjectContext, baseline_loaded: bool) -> ProjectReports:
    from iron_laws.rules.review_rules_versions import eol_report

    out = ProjectReports()
    if baseline_loaded and project.baseline_routes is None:
        out.diagnostics.append(
            Diagnostic(kind="baseline", severity="info", message="기준선에 라우트 목록이 없어 공격 표면 비교(AI-127)를 하지 않았습니다. 기준선을 다시 만들면 비교합니다.")
        )
    try:
        out.routes = [r.as_row() for r in project.routes()]
    except INDEX_ERRORS as error:
        out.diagnostics.append(Diagnostic(kind="rule_error", severity="error", message=f"라우트 색인 작성 중 오류: {type(error).__name__}"))
    if project.config.tenancy.active:
        from iron_laws.rules.ai_code_tenancy import tenancy_rows

        out.tenancy = [row.as_row() for row, _src, _node in tenancy_rows(project)]
    out.eol = eol_report(project)
    if out.eol.error is not None:
        out.diagnostics.append(
            Diagnostic(kind="eol_data", severity="error", message=f"지원 종료 자료를 읽지 못해 지원 종료 판정을 하지 않았습니다(내장 목록으로 대체하지 않음): {out.eol.error}")
        )
    mappers = project.cache.get("mappers_built") and project.mappers()
    if mappers:
        out.counters = {"mapper_statements": len(mappers.by_key), "mapper_unresolved_calls": mappers.unresolved}
    return out
