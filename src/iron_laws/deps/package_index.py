"""
오철칙 오프라인 패키지 색인: 레지스트리에 실제로 있는 패키지 이름과 (선택) 최초 게시일

색인 폴더 구성:
    manifest.json   {"format": 1, "ecosystems": {"npm": {"file": "npm.tsv.gz", "source": "...", "collected_at": "2026-10-01T00:00:00Z",
                                                  "complete": true, "sha256": "...", "count": 123}}}
    npm.tsv.gz      한 줄에 `이름` 또는 `이름<TAB>최초 게시일(YYYY-MM-DD)`. 이름은 에코시스템 규칙으로 정규화되어 있다.

색인은 사용자가 받아 둔 원본 목록을 `iron-laws index build`로 바꾼 것이다. 오철칙은 레지스트리에 접속하지 않는다.
판정 기준 시각은 실행 날짜가 아니라 색인 수집 시각(collected_at)이다. 그래서 같은 색인이면 결과가 같다.
작성자: 최진호
작성일: 2026-10-12
"""

import gzip
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from functools import cache
from pathlib import Path

ECOSYSTEMS = ("npm", "pypi", "pypi-modules")  # pypi-modules: 배포 패키지가 제공하는 최상위 import 이름
NEW_PACKAGE_DAYS = 90


class PackageIndexError(Exception):
    """색인을 읽을 수 없거나 내용이 기록과 맞지 않을 때"""


def normalize(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503
    if ecosystem == "pypi-modules":
        return name.strip().lower()
    return name.strip().lower()


@dataclass
class EcosystemIndex:
    ecosystem: str
    complete: bool
    collected_at: date
    source: str
    names: set[str] = field(default_factory=set)
    first_published: dict[str, date] = field(default_factory=dict)

    def knows(self, name: str) -> bool:
        return normalize(self.ecosystem, name) in self.names

    def is_new(self, name: str) -> int | None:
        """색인 수집 시각 기준 최초 게시 후 지난 날 수가 NEW_PACKAGE_DAYS 이내이면 그 날 수"""
        published = self.first_published.get(normalize(self.ecosystem, name))
        if published is None:
            return None
        days = (self.collected_at - published).days
        return days if 0 <= days <= NEW_PACKAGE_DAYS else None


@dataclass
class PackageIndex:
    root: str
    ecosystems: dict[str, EcosystemIndex]

    def usable(self, ecosystem: str) -> EcosystemIndex | None:
        found = self.ecosystems.get(ecosystem)
        return found if found is not None and found.complete else None


def _date(text: str) -> date:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).date()


@cache
def load_index(root: str) -> PackageIndex:
    base = Path(root)
    try:
        manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PackageIndexError(f"색인 manifest.json을 읽지 못했습니다: {e}") from e
    if not isinstance(manifest, dict) or manifest.get("format") != 1 or not isinstance(manifest.get("ecosystems"), dict):
        raise PackageIndexError("색인 manifest.json 형식이 맞지 않습니다(format 1, ecosystems 필요)")
    ecosystems: dict[str, EcosystemIndex] = {}
    for eco, meta in manifest["ecosystems"].items():
        if eco not in ECOSYSTEMS or not isinstance(meta, dict):
            continue
        path = base / str(meta.get("file", ""))
        try:
            raw = path.read_bytes()
        except OSError as e:
            raise PackageIndexError(f"{eco} 색인 파일을 읽지 못했습니다: {e}") from e
        if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
            raise PackageIndexError(f"{eco} 색인 파일의 sha256이 manifest.json과 다릅니다")
        index = EcosystemIndex(eco, bool(meta.get("complete")), _date(str(meta.get("collected_at"))), str(meta.get("source", "")))
        for line in gzip.decompress(raw).decode("utf-8").splitlines():
            name, _, published = line.partition("\t")
            if not name:
                continue
            index.names.add(name)
            if published:
                index.first_published[name] = date.fromisoformat(published)
        ecosystems[eco] = index
    return PackageIndex(str(base), ecosystems)


def _read_source(source: Path) -> list[tuple[str, str]]:
    """원본 목록: JSON 배열(이름 또는 {name, created}), PyPI Simple API JSON({"projects": [...]}), 또는 줄마다 `이름[,\\t ]날짜`"""
    text = source.read_text(encoding="utf-8")
    rows: list[tuple[str, str]] = []
    if text.lstrip().startswith(("[", "{")):
        data = json.loads(text)
        items = data.get("projects", []) if isinstance(data, dict) else data  # PyPI Simple API JSON(PEP 691)은 {"projects": [{"name": ..}]}
        for item in items:
            if isinstance(item, str):
                rows.append((item, ""))
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                rows.append((item["name"], str(item.get("created") or item.get("first_published") or "")[:10]))
        return rows
    for line in text.splitlines():
        parts = re.split(r"[\t,]|\s+", line.strip(), maxsplit=1)
        if parts and parts[0] and not parts[0].startswith("#"):
            rows.append((parts[0], parts[1].strip()[:10] if len(parts) > 1 else ""))
    return rows


def build_index(ecosystem: str, source: Path, out: Path, source_name: str, collected_at: str, complete: bool) -> dict:
    """사용자가 받아 둔 원본 목록을 압축 색인으로 바꾸고 manifest.json을 갱신한다."""
    if ecosystem not in ECOSYSTEMS:
        raise PackageIndexError(f"지원하는 에코시스템은 {', '.join(ECOSYSTEMS)}입니다")
    _date(collected_at)
    entries: dict[str, str] = {}
    for name, published in _read_source(source):
        key = normalize(ecosystem, name)
        if published and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published):
            published = ""
        if key not in entries or (published and (not entries[key] or published < entries[key])):
            entries[key] = published
    body = "\n".join(f"{n}\t{d}" if d else n for n, d in sorted(entries.items())).encode("utf-8")
    raw = gzip.compress(body, mtime=0)
    out.mkdir(parents=True, exist_ok=True)
    file_name = f"{ecosystem}.tsv.gz"
    (out / file_name).write_bytes(raw)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {"format": 1, "ecosystems": {}}
    manifest["ecosystems"][ecosystem] = {
        "file": file_name,
        "source": source_name,
        "collected_at": collected_at,
        "complete": complete,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "count": len(entries),
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    load_index.cache_clear()
    return manifest["ecosystems"][ecosystem]
