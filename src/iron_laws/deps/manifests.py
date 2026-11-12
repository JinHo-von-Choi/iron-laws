"""
Python 매니페스트 읽기: pyproject.toml의 직접 의존 이름과 requirements 파일의 `==` 고정 줄 형식.
락 파일 해석(lockfiles.py)과 버전 단위 그래프(graph.py)가 함께 쓴다.
작성자: 최진호
작성일: 2026-11-12
"""

import re
import tomllib
from pathlib import Path

from iron_laws.deps.versions import normalize_name

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+_-]+)")


def pyproject_direct(path: Path) -> set[str]:
    """pyproject.toml의 [project].dependencies와 Poetry 의존 표에 적힌 직접 의존 이름. 파일이 없으면 빈 집합"""
    names: set[str] = set()
    if not path.is_file():
        return names
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for req in (data.get("project") or {}).get("dependencies") or []:
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(req))
        if m:
            names.add(normalize_name("PyPI", m.group(1)))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name in (poetry.get(section) or {}):
            if name.lower() != "python":
                names.add(normalize_name("PyPI", name))
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            names.add(normalize_name("PyPI", name))
    return names
