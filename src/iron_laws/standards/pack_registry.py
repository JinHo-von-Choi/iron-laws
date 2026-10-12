"""
오철칙 기준 팩: 기준(행안부 가이드, OWASP Top 10, CWE Top 25 등)마다 항목 목록과 규칙 대응표를 따로 둔다

- 팩 파일: standards/packs/<pack_id>/pack.yml (id, title, edition, source_url, retrieved_at, sha256, items[], mapping, verified_edition, verified_sha256)
- sha256은 항목과 대응표의 정규화 내용 해시다. 파일을 고치고 해시를 갱신하지 않으면 팩을 불러오지 않는다.
- 대응표는 사람이 원문과 대조해 확인했을 때 verified_edition·verified_sha256에 그 판본과 해시를 적는다. 판본이나 내용이 바뀌면
  두 값이 맞지 않게 되어 자동으로 '미확인'으로 돌아간다.
- 행안부 2021 구현단계 팩은 규칙에 붙은 근거(gov_standard)에서 만든다. 기존 대응을 그대로 쓰며 확인된 대응으로 본다.
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import json
from functools import cache
from importlib.resources import files

import yaml
from pydantic import BaseModel, Field

MOIS_PACK_ID = "mois-2021-impl"


class PackItem(BaseModel):
    id: str
    name: str
    rank: int | None = None


class StandardPack(BaseModel):
    id: str
    title: str
    edition: str
    source_url: str = ""
    retrieved_at: str = ""
    sha256: str = ""
    items: list[PackItem]
    mapping: dict[str, list[str]] = Field(default_factory=dict)
    verified_edition: str | None = None
    verified_sha256: str | None = None

    def content_sha256(self) -> str:
        body = {"items": [i.model_dump() for i in self.items], "mapping": {k: sorted(v) for k, v in sorted(self.mapping.items())}}
        return hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True).encode()).hexdigest()

    @property
    def mapping_verified(self) -> bool:
        return self.verified_edition == self.edition and self.verified_sha256 == self.content_sha256()

    def item(self, item_id: str) -> PackItem | None:
        return next((i for i in self.items if i.id == item_id), None)

    def describe(self) -> dict:
        return {
            "id": self.id, "title": self.title, "edition": self.edition, "source_url": self.source_url,
            "retrieved_at": self.retrieved_at, "sha256": self.content_sha256(), "mapping_verified": self.mapping_verified,
        }


class PackError(ValueError):
    """팩 파일이 형식에 맞지 않거나 기록된 해시와 내용이 다르다"""


def _file_packs() -> list[StandardPack]:
    root = files("iron_laws.standards").joinpath("packs")
    packs = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        pack_file = entry.joinpath("pack.yml")
        if not pack_file.is_file():
            continue
        pack = StandardPack(**yaml.safe_load(pack_file.read_text(encoding="utf-8")))
        if pack.id != entry.name:
            raise PackError(f"팩 폴더 이름과 id가 다릅니다: {entry.name} / {pack.id}")
        if pack.sha256 != pack.content_sha256():
            raise PackError(f"{pack.id} 팩의 sha256이 내용과 다릅니다(항목·대응표를 고친 뒤 해시를 갱신하지 않음)")
        unknown = {i for ids in pack.mapping.values() for i in ids} - {i.id for i in pack.items}
        if unknown:
            raise PackError(f"{pack.id} 대응표가 없는 항목을 가리킵니다: {sorted(unknown)}")
        packs.append(pack)
    return packs


def _mois_pack() -> StandardPack:
    from iron_laws.reporters.coverage import rule_item_ids
    from iron_laws.rules.catalog import ALL_RULES
    from iron_laws.standards.registry import _impl_doc, impl_items

    mapping: dict[str, list[str]] = {}
    for rule_cls in ALL_RULES:
        rule = rule_cls()
        ids = rule_item_ids(rule)
        if ids:
            mapping[rule.rule_id] = ids
    doc = _impl_doc()
    pack = StandardPack(
        id=MOIS_PACK_ID,
        title=doc["standard_name"],
        edition=str(doc.get("edition", "2021-11")),
        source_url="",
        retrieved_at="",
        items=[PackItem(id=i.id, name=i.name) for i in impl_items().values()],
        mapping=mapping,
    )
    pack.sha256 = pack.content_sha256()
    pack.verified_edition, pack.verified_sha256 = pack.edition, pack.sha256  # 규칙마다 사람이 정한 근거에서 만든 대응이다
    return pack


@cache
def all_packs() -> tuple[StandardPack, ...]:
    return (_mois_pack(), *_file_packs())


def refs_for(rule_id: str) -> list[dict]:
    """규칙 하나가 가리키는 모든 팩의 항목"""
    found = []
    for pack in all_packs():
        for item_id in pack.mapping.get(rule_id, []):
            item = pack.item(item_id)
            found.append({
                "pack_id": pack.id, "edition": pack.edition, "item_id": item_id,
                "item_name": item.name if item else "", "mapping_verified": pack.mapping_verified,
            })
    return found
