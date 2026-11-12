"""
오철칙 패키지 색인 내려받기: 레지스트리의 전체 이름 목록을 받아 `index build`가 읽는 원본으로 만든다.
네트워크를 쓰는 곳은 이 모듈과 `iron-laws index fetch`뿐이다. `check`·`audit`는 만들어 둔 색인만 읽는다.
- pypi: PEP 691 JSON(`https://pypi.org/simple/`)의 `projects` 전체.
- npm: CouchDB 복제 엔드포인트(`https://replicate.npmjs.com/_all_docs`)의 모든 행(수백 MB). 행 수가 `total_rows`에 못 미치면 중간에 끊긴 것으로 본다.
목록이 끝까지 오지 않았으면 색인을 만들지 않는다(부분 목록으로 '없는 이름'을 판정하지 않기 위해서다).
작성자: 최진호
작성일: 2026-11-10
"""

import json
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, Self

PYPI_URL = "https://pypi.org/simple/"
NPM_URL = "https://replicate.npmjs.com/_all_docs"
USER_AGENT = "iron-laws-index-fetch"
MIN_NAMES = {"pypi": 100_000, "npm": 1_000_000}  # 이보다 적으면 잘못된 응답으로 본다
NPM_ROW = re.compile(r'^\{"id":"((?:[^"\\]|\\.)*)"')
NPM_TOTAL = re.compile(r'"total_rows":(\d+)')
CHUNK = 1 << 20


class FetchError(Exception):
    """목록을 끝까지 받지 못했거나 응답 형식이 맞지 않을 때"""


class Response(Protocol):
    """opener가 돌려주는 응답: with 문으로 열고 나눠 읽는다(urllib의 HTTPResponse와 같은 모양)."""

    def read(self, amt: int, /) -> bytes: ...

    def __enter__(self) -> Self: ...

    def __exit__(self, *exc: object) -> None: ...


Opener = Callable[[urllib.request.Request, float], Response]


def _open(request: urllib.request.Request, timeout: float) -> Response:
    return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310  # URL은 위 두 상수만 쓴다


def _fetch_pypi(destination: Path, opener: Opener, timeout: float, minimum: int) -> tuple[str, int]:
    request = urllib.request.Request(PYPI_URL, headers={"Accept": "application/vnd.pypi.simple.v1+json", "User-Agent": USER_AGENT})
    with opener(request, timeout) as response:
        body = bytearray()
        while chunk := response.read(CHUNK):
            body += chunk
    try:
        data = json.loads(bytes(body))
        names = [item["name"] for item in data["projects"] if isinstance(item, dict) and isinstance(item.get("name"), str)]
    except (ValueError, KeyError, TypeError) as e:
        raise FetchError(f"PyPI 응답을 해석하지 못했습니다: {e}") from e
    if len(names) < minimum:
        raise FetchError(f"PyPI 이름이 {len(names)}개뿐입니다. 전체 목록이 아니라서 색인을 만들지 않습니다")
    destination.write_text("\n".join(names) + "\n", encoding="utf-8")
    return PYPI_URL, len(names)


def _fetch_npm(destination: Path, opener: Opener, timeout: float, minimum: int) -> tuple[str, int]:
    request = urllib.request.Request(NPM_URL, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    total: int | None = None
    count = 0
    with opener(request, timeout) as response, destination.open("w", encoding="utf-8") as out:
        for raw in response:
            line = raw.decode("utf-8", errors="replace")
            if total is None and (found := NPM_TOTAL.search(line)):
                total = int(found.group(1))
            row = NPM_ROW.match(line)
            if row is None:
                continue
            try:
                name = json.loads('"' + row.group(1) + '"')
            except ValueError:  # iron-laws: ignore[IL-301] JSON 문자열로 풀리지 않는 줄은 패키지 이름이 아니다
                continue
            if name.startswith("_design/"):
                continue
            out.write(name + "\n")
            count += 1
    if total is None or count < total - 1000 or count < minimum:  # 설계 문서 등 몇 행은 이름이 아니다
        raise FetchError(f"npm 목록이 끝까지 오지 않았습니다(받은 행 {count}개, 전체 {total}개). 색인을 만들지 않습니다")
    return NPM_URL, count


def fetch_names(ecosystem: str, destination: Path, opener: Opener = _open, timeout: float = 600, minimum: int | None = None) -> tuple[str, int]:
    """(출처 URL, 이름 수). destination에 한 줄에 이름 하나씩 쓴다."""
    floor = MIN_NAMES.get(ecosystem, 0) if minimum is None else minimum
    if ecosystem == "pypi":
        return _fetch_pypi(destination, opener, timeout, floor)
    if ecosystem == "npm":
        return _fetch_npm(destination, opener, timeout, floor)
    raise FetchError("내려받기를 지원하는 에코시스템은 pypi와 npm입니다")
