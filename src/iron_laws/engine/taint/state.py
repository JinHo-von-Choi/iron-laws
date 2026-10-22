"""
오철칙 흐름 해석기의 공통 상태: 재귀 진행 중 함수, 깊이, 끊은 지점, 지점 분석 진행 여부
모듈마다 따로 들고 있으면 서로를 참조하는 두 모듈이 같은 값을 보지 못한다. 한곳에 모아 둔다.
작성자: 최진호
작성일: 2026-10-22
"""

from iron_laws.engine.taint.sanitizers import Ctx

IN_PROGRESS: set[tuple[str, int, frozenset[str], Ctx]] = set()
DEPTH = 0
CUTS: list[tuple[str, int, frozenset[str], Ctx]] = []  # 재귀로 끊은 함수 키. 끊은 결과는 호출 경로에 따라 달라지므로 캐시하지 않는다
POINT_ACTIVE = False  # 한 지점 안에서 함수 간 해석이 진행 중인지
