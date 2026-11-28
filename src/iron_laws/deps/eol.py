"""
지원 종료(EOL) 판정: 오프라인 지원 종료 자료(endoflife.date 제품별 JSON)로 런타임·OS 이미지·DB 이미지·Java 직접 의존성의 지원 종료를 판정한다.

- 자료 폴더: 제품별 `<제품>.json`(주기 목록)과 `manifest.json`(source, fetched_at, products, sha256). `iron-laws index fetch --eol`로 만든다.
- 판정 기준일은 자료 수집일(fetched_at)이다. 같은 코드·같은 자료면 언제 돌려도 결과가 같다.
- 자료에 없는 제품, 주기를 맞출 수 없는 버전은 판정하지 않는다(추정하지 않는다).
- 자료를 지정했는데 읽을 수 없으면 EolDataError를 낸다. 호출한 쪽은 다른 목록으로 대체하지 않고 오류 진단을 낸다.
작성자: 최진호
작성일: 2026-11-23
"""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

EOL_SOURCE = "https://endoflife.date/api"  # iron-laws: ignore[AI-101] 지원 종료 자료의 공개 출처 하나뿐이며 index fetch --eol만 쓴다
# 오철칙이 판정하는 제품. index fetch --eol이 받는 목록이기도 하다
EOL_PRODUCTS = (
    "centos", "debian", "ubuntu", "alpine", "rhel", "rocky-linux", "almalinux", "amazon-linux",
    "nodejs", "python", "eclipse-temurin", "amazon-corretto", "azul-zulu",
    "mysql", "mariadb", "postgresql", "redis", "mongodb", "nginx",
    "spring-boot", "spring-framework", "log4j", "tomcat",
)
DOCKER_IMAGES = {
    "centos": "centos", "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "rockylinux": "rocky-linux", "almalinux": "almalinux",
    "amazonlinux": "amazon-linux", "node": "nodejs", "python": "python", "eclipse-temurin": "eclipse-temurin", "amazoncorretto": "amazon-corretto",
    "azul/zulu-openjdk": "azul-zulu", "mysql": "mysql", "mariadb": "mariadb", "postgres": "postgresql", "redis": "redis", "mongo": "mongodb",
    "nginx": "nginx", "tomcat": "tomcat",
}
MAVEN_PRODUCTS = (
    (re.compile(r"^org\.springframework\.boot:"), "spring-boot"),
    (re.compile(r"^org\.springframework:spring-"), "spring-framework"),
    (re.compile(r"^log4j:log4j$|^org\.apache\.logging\.log4j:log4j-(core|api)$"), "log4j"),
    (re.compile(r"^org\.apache\.tomcat\.embed:tomcat-embed-core$"), "tomcat"),
)


class EolDataError(ValueError):
    """지원 종료 자료를 읽을 수 없다"""


@dataclass(frozen=True)
class EolData:
    path: str
    fetched_at: date
    sha256: str
    products: dict[str, list[dict]]

    def describe(self) -> dict:
        return {"source": self.path, "fetched_at": self.fetched_at.isoformat(), "sha256": self.sha256[:16], "products": len(self.products)}


def load_eol_data(path: str | Path) -> EolData:
    folder = Path(path)
    manifest_path = folder / "manifest.json"
    if not manifest_path.is_file():
        raise EolDataError(f"지원 종료 자료 폴더에 manifest.json이 없습니다: {folder}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        fetched = date.fromisoformat(str(manifest["fetched_at"])[:10])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise EolDataError(f"manifest.json을 읽지 못했습니다: {e}") from e
    products: dict[str, list[dict]] = {}
    digest = hashlib.sha256()
    for name in sorted(manifest.get("products") or []):
        file = folder / f"{name}.json"
        try:
            raw = file.read_bytes()
            cycles = json.loads(raw)
        except (OSError, ValueError) as e:
            raise EolDataError(f"{file.name}을(를) 읽지 못했습니다: {e}") from e
        if not isinstance(cycles, list) or not all(isinstance(c, dict) and "cycle" in c for c in cycles):
            raise EolDataError(f"{file.name}의 형식이 제품 주기 목록이 아닙니다")
        digest.update(name.encode() + b"\0" + raw)
        products[name] = cycles
    if not products:
        raise EolDataError("지원 종료 자료에 제품이 없습니다")
    expected = str(manifest.get("sha256") or "")
    if expected and expected != digest.hexdigest():
        raise EolDataError("지원 종료 자료의 내용이 manifest.json의 sha256과 다릅니다(손상되었거나 바뀐 자료)")
    return EolData(folder.as_posix(), fetched, digest.hexdigest(), products)


@dataclass(frozen=True)
class EolVerdict:
    product: str
    version: str
    cycle: str
    eol: str  # 날짜 또는 '종료(날짜 미상)'
    url: str


def judge(data: EolData, product: str, version: str) -> EolVerdict | None:
    """자료 수집일 기준으로 지원이 끝난 주기면 판정, 아니거나 판정할 수 없으면 None"""
    cycles = data.products.get(product)
    if not cycles or not version:
        return None
    version = version.strip().lstrip("v")
    matches = [c for c in cycles if version == str(c["cycle"]) or version.startswith(f"{c['cycle']}.") or version.startswith(f"{c['cycle']}-")]
    if not matches:
        return None
    cycle = max(matches, key=lambda c: len(str(c["cycle"])))
    eol = cycle.get("eol")
    url = f"https://endoflife.date/{product}"
    if eol is True:
        return EolVerdict(product, version, str(cycle["cycle"]), "종료(날짜 미상)", url)
    if isinstance(eol, str):
        try:
            when = date.fromisoformat(eol[:10])
        except ValueError:  # iron-laws: ignore[IL-301] 날짜를 해석할 수 없는 주기는 판정하지 않는다
            return None
        if when <= data.fetched_at:
            return EolVerdict(product, version, str(cycle["cycle"]), when.isoformat(), url)
    return None


def docker_product(image: str) -> tuple[str, str] | None:
    """`centos:7` → ('centos', '7'). 레지스트리 접두(docker.io/library/)는 뗀다. 태그가 없거나 latest면 None"""
    ref = re.sub(r"^(?:docker\.io/)?(?:library/)?", "", image.strip())
    name, _, tag = ref.partition(":")
    tag = tag.split("@", 1)[0]
    product = DOCKER_IMAGES.get(name.lower())
    version = re.match(r"v?(\d+(?:\.\d+)*)", tag)
    if product is None or version is None:
        return None
    return product, version.group(1)


def maven_product(coordinate: str) -> str | None:
    for pattern, product in MAVEN_PRODUCTS:
        if pattern.search(coordinate):
            return product
    return None


Opener = Callable[[str, float], bytes]


def _download(url: str, timeout: float) -> bytes:
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": "iron-laws-index-fetch", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310  # URL은 EOL_SOURCE 상수와 고정 제품 이름으로만 만든다
        return response.read()


def fetch_eol_data(out: Path, fetched_at: str, timeout: float = 60, opener: Opener = _download) -> dict:
    """EOL_PRODUCTS의 주기 목록을 받아 폴더에 쓴다. 하나라도 받지 못하면 폴더를 만들지 않는다."""
    payloads: dict[str, bytes] = {}
    for product in EOL_PRODUCTS:
        raw = opener(f"{EOL_SOURCE}/{product}.json", timeout)
        cycles = json.loads(raw)
        if not isinstance(cycles, list):
            raise EolDataError(f"{product}의 응답이 주기 목록이 아닙니다")
        payloads[product] = raw
    out.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    for product in sorted(payloads):
        (out / f"{product}.json").write_bytes(payloads[product])
        digest.update(product.encode() + b"\0" + payloads[product])
    manifest = {"source": EOL_SOURCE, "fetched_at": fetched_at, "products": sorted(payloads), "sha256": digest.hexdigest()}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest
