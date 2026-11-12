"""파일 간 호출 해석 결과. 언어별 해석기(xfile_*.py)와 프로젝트 색인(xfile.py)이 함께 쓴다."""

from typing import NamedTuple


class ResolveResult(NamedTuple):
    targets: list  # [(SourceFile, Func)]
    gap: str | None = None  # 프로젝트 안의 대상으로 보이지만 정할 수 없을 때의 사유
