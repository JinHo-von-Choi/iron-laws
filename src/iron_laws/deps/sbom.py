"""
오철칙 SBOM 생성: 잠금 파일의 버전 단위 의존 그래프를 CycloneDX 1.6 또는 SPDX 2.3 JSON으로 쓴다

- 구성요소 식별자는 package URL(purl)이다. 같은 이름@버전이 여러 위치에 설치되어도 구성요소 하나로 둔다.
- 간선은 graph.py가 해석한 버전 단위 관계만 쓴다. 관계 정보가 없는 입력(requirements)은 루트에서 모든 구성요소로 잇지 않고 관계를 비워 둔다.
- 일련번호·문서 이름공간은 내용 해시에서 만들어 같은 입력이면 같은 문서가 된다. 생성 시각은 인자로 받는다.
작성자: 최진호
작성일: 2026-10-12
"""

import hashlib
import json
import re
import uuid
from urllib.parse import quote

from iron_laws.deps.graph import DependencyGraph


def purl(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, base = name.split("/", 1)
            return f"pkg:npm/{quote(scope)}/{quote(base)}@{quote(version)}"
        return f"pkg:npm/{quote(name)}@{quote(version)}"
    return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{quote(version)}"


def _merged(graphs: list[DependencyGraph]) -> tuple[dict[str, tuple], dict[str, set[str]], set[str], list[str]]:
    components: dict[str, tuple] = {}
    edges: dict[str, set[str]] = {}
    direct: set[str] = set()
    notes: list[str] = []
    for g in graphs:
        ids = {}
        for node in g.nodes.values():
            ref = purl(node.ecosystem, node.name, node.version)
            ids[node.id] = ref
            prior = components.get(ref)
            dev = node.dev if prior is None else (prior[3] and node.dev)
            components[ref] = (node.ecosystem, node.name, node.version, dev)
            if node.direct:
                direct.add(ref)
        for parent, children in g.edges.items():
            edges.setdefault(ids[parent], set()).update(ids[c] for c in children if c in ids)
        notes += [f"{g.source}: {n}" for n in g.notes]
    return components, edges, direct, notes


def _digest(components, edges) -> str:
    body = json.dumps([sorted(components), sorted((k, sorted(v)) for k, v in edges.items())])
    return hashlib.sha256(body.encode()).hexdigest()


def cyclonedx(graphs: list[DependencyGraph], project: str, tool_version: str, timestamp: str) -> dict:
    components, edges, direct, notes = _merged(graphs)
    serial = uuid.UUID(_digest(components, edges)[:32], version=5)
    root = "root-application"
    has_graph = all(g.has_graph for g in graphs)
    deps = [{"ref": root, "dependsOn": sorted(direct)}] if has_graph else []
    deps += [{"ref": ref, "dependsOn": sorted(edges.get(ref, set()))} for ref in sorted(components)] if has_graph else []
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "iron-laws", "version": tool_version}]},
            "component": {"type": "application", "bom-ref": root, "name": project},
            "properties": [{"name": "iron-laws:note", "value": n} for n in notes],
        },
        "components": [
            {"type": "library", "bom-ref": ref, "name": name, "version": version, "purl": ref, "scope": "optional" if dev else "required"}
            for ref, (_eco, name, version, dev) in sorted(components.items())
        ],
        "dependencies": deps,
    }
    if not doc["metadata"]["properties"]:
        del doc["metadata"]["properties"]
    return doc


def _spdx_id(ref: str) -> str:
    """SPDX 식별자는 영문·숫자·.·-만 쓸 수 있다. 바꾼 글자 때문에 서로 다른 purl(a_b와 a-b)이 같은 식별자가 되지 않도록 purl의 해시를 붙인다."""
    readable = re.sub(r"[^A-Za-z0-9.-]", "-", ref.removeprefix("pkg:"))
    return f"SPDXRef-Package-{readable}-{hashlib.sha256(ref.encode('utf-8')).hexdigest()[:12]}"


def spdx(graphs: list[DependencyGraph], project: str, tool_version: str, timestamp: str) -> dict:
    components, edges, direct, notes = _merged(graphs)
    digest = _digest(components, edges)
    root_id = "SPDXRef-Package-root"
    packages = [{"SPDXID": root_id, "name": project, "downloadLocation": "NOASSERTION", "filesAnalyzed": False}]
    for ref, (_eco, name, version, _dev) in sorted(components.items()):
        packages.append({
            "SPDXID": _spdx_id(ref), "name": name, "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": ref}],
        })
    relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    if all(g.has_graph for g in graphs):
        relationships += [{"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": _spdx_id(r)} for r in sorted(direct)]
        relationships += [
            {"spdxElementId": _spdx_id(parent), "relationshipType": "DEPENDS_ON", "relatedSpdxElement": _spdx_id(child)}
            for parent in sorted(edges) for child in sorted(edges[parent])
        ]
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project}-sbom",
        "documentNamespace": f"https://spdx.org/spdxdocs/iron-laws/{project}-{digest[:32]}",
        "creationInfo": {"created": timestamp, "creators": [f"Tool: iron-laws-{tool_version}"]},
        "packages": packages,
        "relationships": relationships,
    }
    if notes:
        doc["comment"] = " / ".join(notes)
    return doc
