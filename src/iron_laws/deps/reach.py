"""
오철칙 취약 의존성 도달성: 권고가 영향 함수를 알려 줄 때만 프로젝트 코드가 그 함수를 부르는지 본다

- reachable: 패키지를 가져와 영향 함수를 부르는 호출이 있다(위치를 함께 남긴다).
- no_evidence: 영향 함수 정보는 있지만 그 함수를 부르는 호출을 찾지 못했다. 간접 호출·동적 호출은 찾지 못하므로 '도달하지 않음'이 아니다.
- undetermined: 권고에 영향 함수 정보가 없다.
작성자: 최진호
작성일: 2026-10-12
"""

import re
from dataclasses import dataclass, field

from iron_laws.engine.ast_tools import iter_calls
from iron_laws.engine.languages import JS_FAMILY, Lang
from iron_laws.engine.source import SourceFile


@dataclass
class Reach:
    status: str
    reason: str
    locations: list[str] = field(default_factory=list)


def _python_module(package: str) -> str:
    return re.sub(r"[-.]", "_", package).lower()


def _aliases(src: SourceFile, ecosystem: str, package: str, symbols: list[str]) -> set[str]:
    """이 파일에서 패키지(또는 그 하위 모듈)를 가리키는 지역 이름. Python은 배포 이름과 import 이름이 다를 수 있어(PyYAML→yaml)
    영향 함수 경로의 첫 부분도 모듈 후보로 쓴다."""
    names: set[str] = set()
    text = src.code_text
    if ecosystem == "PyPI" and src.lang is Lang.PYTHON:
        modules = {_python_module(package)} | {s.split(".", 1)[0] for s in symbols if "." in s}
        for module in sorted(re.escape(m) for m in modules):
            for m in re.finditer(rf"(?m)^\s*import\s+({module}(?:\.\w+)*)(?:\s+as\s+(\w+))?", text):
                names.add(m.group(2) or m.group(1))
            for m in re.finditer(rf"(?m)^\s*from\s+{module}(?:\.\w+)*\s+import\s+(.+)$", text):
                for part in m.group(1).strip("()").split(","):
                    bits = part.strip().split(" as ")
                    if bits[0].strip():
                        names.add((bits[1] if len(bits) > 1 else bits[0]).strip())
    elif ecosystem == "npm" and src.lang in JS_FAMILY:
        quoted = re.escape(package)
        for m in re.finditer(rf"import\s+(?:\*\s+as\s+)?(\w+)?\s*,?\s*(?:\{{([^}}]*)\}})?\s*from\s+['\"]{quoted}(?:/[^'\"]*)?['\"]", text):
            if m.group(1):
                names.add(m.group(1))
            for part in (m.group(2) or "").split(","):
                bits = part.strip().split(" as ")
                if bits[0].strip():
                    names.add((bits[1] if len(bits) > 1 else bits[0]).strip())
        for m in re.finditer(rf"(?:const|let|var)\s+(\w+|\{{[^}}]*\}})\s*=\s*require\(\s*['\"]{quoted}(?:/[^'\"]*)?['\"]\s*\)", text):
            target = m.group(1)
            names |= {t.strip().split(":")[-1].strip() for t in target.strip("{}").split(",") if t.strip()} if target.startswith("{") else {target}
    return names


def reachability(sources: list[SourceFile], ecosystem: str, package: str, symbols: list[str]) -> Reach:
    if not symbols:
        return Reach("undetermined", "권고에 영향 함수 정보가 없다")
    wanted = {s.rsplit(".", 1)[-1].rsplit("::", 1)[-1] for s in symbols}
    locations: list[str] = []
    imported = False
    for src in sources:
        aliases = _aliases(src, ecosystem, package, symbols)
        if not aliases:
            continue
        imported = True
        for call in iter_calls(src):
            last = call.callee.rsplit(".", 1)[-1]
            head = call.callee.split(".", 1)[0]
            if last in wanted and (head in aliases or call.callee in aliases):
                locations.append(f"{src.path.as_posix()}:{call.line}")
    if locations:
        return Reach("reachable", f"영향 함수({', '.join(sorted(wanted))})를 부르는 호출이 있다", sorted(locations)[:20])
    if imported:
        return Reach("no_evidence", "패키지를 가져오지만 영향 함수를 부르는 호출을 찾지 못했다(간접·동적 호출은 찾지 못한다)")
    return Reach("no_evidence", "코드에서 이 패키지를 가져오는 곳을 찾지 못했다(간접 의존이거나 동적 사용일 수 있다)")
