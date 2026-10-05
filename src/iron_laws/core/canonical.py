"""
오철칙 보고서 정규화 투영: 같은 코드를 점검한 두 번의 JSON 보고서가 같은 내용인지 바이트 단위로 비교하기 위한 형식
실행마다 달라지는 값(문서번호, 점검 일자, 작업 경로)은 JSON Pointer 목록으로 고정해 제거하고 키 순서를 고정한다.
원시 보고서의 바이트 동일은 요구하지 않는다. 제거 목록 밖의 값이 다르면 점검 결과가 실행 환경에 따라 달라진 것이다.
작성자: 최진호
작성일: 2026-10-05
"""

import hashlib
import json
from typing import Any

# 실행 환경에 따라 달라질 수 있어 비교에서 제외하는 값. 목록을 늘릴 때는 사유를 함께 적는다.
IGNORED_POINTERS: tuple[tuple[str, str], ...] = (
    ("/document_id", "점검 시각으로 만든 문서번호"),
    ("/audit_date", "점검 일자"),
    ("/target_path", "점검 대상의 절대 경로"),
    ("/metadata/repo_relative_prefix", "저장소 안에서 점검 대상까지의 상대 경로(작업 경로에 따라 달라짐)"),
    ("/metadata/config_source", "설정 파일의 경로 표시"),
    ("/coverage_ledger/contract_source", "계약 파일의 경로 표시"),
)


def _drop(data: Any, tokens: list[str]) -> None:
    if not tokens:
        return
    head, rest = tokens[0], tokens[1:]
    if isinstance(data, dict):
        if head not in data:
            return
        if not rest:
            del data[head]
        else:
            _drop(data[head], rest)
    elif isinstance(data, list) and head.isdigit() and int(head) < len(data):
        _drop(data[int(head)], rest)


def canonical_projection(report: dict[str, Any]) -> str:
    """제외 목록의 값을 지우고 키 순서·구분자를 고정한 JSON 문자열."""
    copy = json.loads(json.dumps(report, ensure_ascii=False))
    for pointer, _reason in IGNORED_POINTERS:
        _drop(copy, pointer.lstrip("/").split("/"))
    return json.dumps(copy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def projection_digest(report: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_projection(report).encode("utf-8")).hexdigest()
