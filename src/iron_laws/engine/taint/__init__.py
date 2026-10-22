"""
오철칙 오염 추적: 외부 입력에서 시작해 어떤 변수가 오염되는지 함수 안 실행 순서를 따라 계산한다
- paths: 오염 경로(변수·필드·상수 키)
- sources: 외부 입력 소스(웹 요청·압축 항목·명령행 인자)
- sanitizers: 문맥별 정제 함수
- resolve: 호출 대상 해석(같은 파일·import·다른 파일)
- interpreter: 실행 순서를 따르는 흐름 해석기
- predicates: 식의 오염 판정
작성자: 최진호
작성일: 2026-10-22
"""

from iron_laws.engine.taint.definitions import (
    definitions as definitions,
)
from iron_laws.engine.taint.definitions import (
    reaching_definitions as reaching_definitions,
)
from iron_laws.engine.taint.interpreter import (
    expr_tainted as expr_tainted,
)
from iron_laws.engine.taint.interpreter import (
    is_tainted as is_tainted,
)
from iron_laws.engine.taint.interpreter import (
    taint_state as taint_state,
)
from iron_laws.engine.taint.nodes import (
    CONDITIONAL_TYPES as CONDITIONAL_TYPES,
)
from iron_laws.engine.taint.nodes import (
    MAX_HELPER_DEPTH as MAX_HELPER_DEPTH,
)
from iron_laws.engine.taint.nodes import (
    TaintResult as TaintResult,
)
from iron_laws.engine.taint.paths import (
    ASSIGN_TYPES as ASSIGN_TYPES,
)
from iron_laws.engine.taint.paths import (
    _target_and_value as _target_and_value,
)
from iron_laws.engine.taint.paths import (
    _target_names as _target_names,
)
from iron_laws.engine.taint.paths import (
    access_path as access_path,
)
from iron_laws.engine.taint.paths import (
    path_root as path_root,
)
from iron_laws.engine.taint.paths import (
    reads_tainted as reads_tainted,
)
from iron_laws.engine.taint.paths import (
    tainted_roots as tainted_roots,
)
from iron_laws.engine.taint.resolve import (
    param_name as param_name,
)
from iron_laws.engine.taint.resolve import (
    resolve_any as resolve_any,
)
from iron_laws.engine.taint.resolve import (
    resolve_helper as resolve_helper,
)
from iron_laws.engine.taint.sanitizers import (
    SANITIZER_FN_RE as SANITIZER_FN_RE,
)
from iron_laws.engine.taint.sanitizers import (
    Ctx as Ctx,
)
from iron_laws.engine.taint.sanitizers import (
    custom_sanitizer_match as custom_sanitizer_match,
)
from iron_laws.engine.taint.sanitizers import (
    sanitizer_name_matches as sanitizer_name_matches,
)
from iron_laws.engine.taint.sanitizers import (
    set_custom_spec as set_custom_spec,
)
from iron_laws.engine.taint.sources import (
    ARCHIVE_IMPORT_RE as ARCHIVE_IMPORT_RE,
)
from iron_laws.engine.taint.sources import (
    ARCHIVE_SOURCE_RE as ARCHIVE_SOURCE_RE,
)
from iron_laws.engine.taint.sources import (
    CLI_SOURCE_RE as CLI_SOURCE_RE,
)
from iron_laws.engine.taint.sources import (
    WEB_SOURCE_RE as WEB_SOURCE_RE,
)
from iron_laws.engine.taint.sources import (
    _text_without_plain_strings as _text_without_plain_strings,
)
from iron_laws.engine.taint.sources import (
    archive_file as archive_file,
)
from iron_laws.engine.taint.sources import (
    expr_has_source as expr_has_source,
)
from iron_laws.engine.taint.sources import (
    extra_sources as extra_sources,
)

__all__ = [
    "ARCHIVE_IMPORT_RE",
    "ARCHIVE_SOURCE_RE",
    "ASSIGN_TYPES",
    "CLI_SOURCE_RE",
    "CONDITIONAL_TYPES",
    "Ctx",
    "MAX_HELPER_DEPTH",
    "SANITIZER_FN_RE",
    "TaintResult",
    "WEB_SOURCE_RE",
    "_target_and_value",
    "_target_names",
    "_text_without_plain_strings",
    "access_path",
    "archive_file",
    "custom_sanitizer_match",
    "definitions",
    "expr_has_source",
    "expr_tainted",
    "extra_sources",
    "is_tainted",
    "param_name",
    "path_root",
    "reaching_definitions",
    "reads_tainted",
    "resolve_any",
    "resolve_helper",
    "sanitizer_name_matches",
    "set_custom_spec",
    "tainted_roots",
    "taint_state",
]
