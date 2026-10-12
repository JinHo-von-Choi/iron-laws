"""
오철칙 OpenVEX 0.2.0 출력: 취약 의존성 점검 결과를 VEX 문장으로 쓴다

- 자동으로는 affected(영향 함수를 부르는 호출이 확인됨)와 under_investigation(그 밖의 모든 경우)만 쓴다.
- not_affected는 사람이 남긴 VEX 판정 기록에 OpenVEX justification이 있을 때만 쓴다. 도구가 '영향 없음'을 스스로 주장하지 않는다.
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from iron_laws.deps.sbom import purl

JUSTIFICATIONS = frozenset({
    "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist",
})


class VexDecisionError(ValueError):
    """VEX 판정 기록이 형식에 맞지 않는다"""


def load_decisions(path: Path) -> list[dict[str, Any]]:
    """사람이 남긴 판정 기록: [{vulnerability, product(purl), status: not_affected, justification, impact_statement, author}]"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise VexDecisionError(f"VEX 판정 기록을 읽을 수 없습니다: {e}") from e
    if not isinstance(data, list):
        raise VexDecisionError("VEX 판정 기록은 JSON 배열이어야 합니다")
    for i, d in enumerate(data):
        if not isinstance(d, dict) or d.get("status") != "not_affected":
            raise VexDecisionError(f"{i}번째 판정: status는 not_affected만 기록합니다(affected·under_investigation은 도구가 정한다)")
        if d.get("justification") not in JUSTIFICATIONS:
            raise VexDecisionError(f"{i}번째 판정: justification은 {', '.join(sorted(JUSTIFICATIONS))} 중 하나여야 합니다")
        for key in ("vulnerability", "product", "author", "impact_statement"):
            if not str(d.get(key) or "").strip():
                raise VexDecisionError(f"{i}번째 판정: {key}가 필요합니다")
    return data


def openvex(data: dict[str, Any], decisions: list[dict[str, Any]], tool_version: str, timestamp: str) -> dict[str, Any]:
    human = {(d["vulnerability"], d["product"]): d for d in decisions}
    statements = []
    for lock in data["locks"]:
        for f in lock["findings"]:
            product = purl("npm" if f["ecosystem"] == "npm" else "PyPI", f["package"], f["version"])
            for adv in f["advisories"]:
                names = [adv["id"], *adv.get("aliases", [])]
                decision = next((human[(n, product)] for n in names if (n, product) in human), None)
                reach = adv.get("reachability") or {}
                statement: dict[str, Any] = {
                    "vulnerability": {"name": adv["id"], **({"aliases": adv["aliases"]} if adv.get("aliases") else {})},
                    "products": [{"@id": product}],
                }
                if decision is not None:
                    statement.update(status="not_affected", justification=decision["justification"], impact_statement=f"{decision['impact_statement']} (판정: {decision['author']})")
                elif reach.get("status") == "reachable":
                    statement.update(status="affected", action_statement=f"{f.get('fix_boundary') or '권고의 수정 버전'} 이상으로 올리십시오. 호출 위치: {', '.join(reach.get('locations', [])[:5])}")
                else:
                    statement.update(status="under_investigation", status_notes=reach.get("reason") or "도달성을 판정하지 않았다")
                statements.append(statement)
    body = json.dumps(statements, sort_keys=True, ensure_ascii=False)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/iron-laws/{hashlib.sha256(body.encode()).hexdigest()[:32]}",
        "author": f"iron-laws {tool_version}",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }
