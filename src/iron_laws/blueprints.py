"""
오철칙 구조 틀(blueprint): 많이 쓰는 스택의 기본 계층 구조를 구조 계약, 에이전트 지침 한 절, 폴더 뼈대로 만든다.

- 구조 계약은 .iron-laws.yml의 architecture 절이며 ARC-207이 판정한다(strict: true).
- 지침 문장 가운데 규칙 ID를 단 문장은 오철칙이 점검으로 강제하고, "(안내)" 문장은 에이전트가 읽고 따르는 안내다.
- 기존 지침 파일(AGENTS.md·CLAUDE.md)에는 표시 주석으로 감싼 절만 넣고, 다시 실행하면 그 절만 바꾼다.
- 틀 본문의 지문(digest)을 표시 주석에 남겨, 틀이 바뀌었는지 알 수 있게 한다.
작성자: 최진호
작성일: 2026-11-28
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

MARK_START = "<!-- iron-laws:blueprint:start"
MARK_END = "<!-- iron-laws:blueprint:end -->"
SECTION_RE = re.compile(re.escape(MARK_START) + r".*?" + re.escape(MARK_END), re.DOTALL)


@dataclass(frozen=True)
class Blueprint:
    key: str
    title: str
    layers: list[dict]
    forbidden: list[dict]
    folders: dict[str, str]  # 폴더 → 한 줄 설명
    rules: list[str]  # 점검으로 강제하는 지침(규칙 ID 포함)
    notes: list[str] = field(default_factory=list)  # 안내 지침

    def contract(self) -> dict:
        return {"layers": self.layers, "forbidden": self.forbidden, "strict": True}

    def digest(self) -> str:
        body = json.dumps({"layers": self.layers, "forbidden": self.forbidden, "folders": self.folders, "rules": self.rules, "notes": self.notes}, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]

    def guideline_section(self) -> str:
        lines = [f"{MARK_START} {self.key} {self.digest()} -->", f"## 프로젝트 구조 ({self.title})", ""]
        lines += [f"- `{folder}/`: {desc}" for folder, desc in self.folders.items()]
        lines += ["", "지켜야 할 것(오철칙이 점검합니다):"]
        lines += [f"- {rule}" for rule in self.rules]
        lines += ["", "안내:"]
        lines += [f"- {note}" for note in self.notes]
        lines += [MARK_END]
        return "\n".join(lines) + "\n"


BLUEPRINTS = {
    "nextjs": Blueprint(
        key="nextjs",
        title="Next.js App Router + DB",
        layers=[
            {"name": "ui", "paths": ["app/**", "components/**"], "kind": "presentation"},  # iron-laws: ignore[ARC-205] 구조 계약 kind 값이라 설정 형식(core/config.py)과 같은 글자를 쓴다
            {"name": "actions", "paths": ["server/actions/**"], "kind": "presentation"},
            {"name": "services", "paths": ["server/services/**"], "kind": "service"},
            {"name": "db", "paths": ["server/db/**"], "kind": "data"},
            {"name": "shared", "paths": ["lib/**", "types/**"]},
        ],
        forbidden=[{"from": "components/**", "to": "server/**", "reason": "화면 부품은 서버 코드를 직접 부르지 않고 props나 Server Action으로 받는다"}],
        folders={
            "app": "화면과 라우트(page.tsx, layout.tsx, route.ts)",
            "components": "여러 화면이 함께 쓰는 화면 부품",
            "server/actions": "화면에서 부르는 Server Action('use server'). 입력을 검사하고 서비스를 부른다",
            "server/services": "업무 규칙. 권한 확인과 계산을 여기서 한다",
            "server/db": "DB 접근(Prisma·Supabase 클라이언트, 조회 함수)",
            "lib": "어디서나 쓰는 도우미 함수",
        },
        rules=[
            "[ARC-207] 의존은 app·components → server/actions → server/services → server/db 방향으로만 흐릅니다. 반대로 import하지 않습니다.",
            "[ARC-207] components/는 server/ 아래 코드를 import하지 않습니다.",
            "[ARC-203] 모듈끼리 서로 import하는 순환을 만들지 않습니다.",
            "[ARC-204] 새 함수를 만들기 전에 lib/와 server/services/에 같은 일을 하는 함수가 있는지 찾아 씁니다.",
            "[IL-525] 데이터를 바꾸는 Server Action과 route.ts 핸들러는 로그인 사용자를 먼저 확인합니다.",
        ],
        notes=[
            "새 기능은 server/db → server/services → server/actions → app 순서로 파일 하나씩 더합니다.",
            "비밀값은 서버 코드에서만 process.env로 읽고, NEXT_PUBLIC_ 이름으로 노출하지 않습니다.",
            "화면에서 DB 결과를 그대로 넘기지 말고 필요한 필드만 골라 넘깁니다.",
        ],
    ),
    "fastapi": Blueprint(
        key="fastapi",
        title="FastAPI",
        layers=[
            {"name": "routers", "paths": ["app/api/**"], "kind": "presentation"},
            {"name": "services", "paths": ["app/services/**"], "kind": "service"},
            {"name": "repositories", "paths": ["app/repositories/**", "app/models/**"], "kind": "data"},
            {"name": "schemas", "paths": ["app/schemas/**"]},
            {"name": "core", "paths": ["app/core/**"]},
        ],
        forbidden=[{"from": "app/schemas/**", "to": "app/repositories/**", "reason": "요청·응답 모델은 DB 모델을 몰라야 한다"}],
        folders={
            "app/api": "라우터(APIRouter). 요청을 검사하고 서비스를 부른다",
            "app/services": "업무 규칙. 권한 확인과 계산을 여기서 한다",
            "app/repositories": "DB 접근(세션, 쿼리)",
            "app/models": "DB 모델(SQLAlchemy 등)",
            "app/schemas": "요청·응답 모델(Pydantic)",
            "app/core": "설정(환경 변수 읽기), 보안 도우미",
            "tests": "시험(pytest)",
        },
        rules=[
            "[ARC-207] 의존은 app/api → app/services → app/repositories 방향으로만 흐릅니다. 반대로 import하지 않습니다.",
            "[ARC-202] 라우터에서 DB 세션이나 쿼리를 직접 쓰지 않고 서비스를 부릅니다.",
            "[ARC-203] 모듈끼리 서로 import하는 순환을 만들지 않습니다.",
            "[ARC-204] 새 함수를 만들기 전에 app/services/와 app/core/에 같은 일을 하는 함수가 있는지 찾아 씁니다.",
            "[IL-525] 데이터를 바꾸는 라우터에는 로그인 사용자를 확인하는 의존성(Depends)을 붙입니다.",
        ],
        notes=[
            "새 기능은 app/models·app/repositories → app/services → app/api 순서로 파일 하나씩 더합니다.",
            "설정과 비밀값은 app/core/config.py에서 환경 변수로 읽습니다.",
            "응답에는 DB 모델 대신 app/schemas의 응답 모델을 씁니다.",
        ],
    ),
}


def detect(root: Path) -> str | None:
    """이미 있는 코드에서 가장 가까운 틀. package.json에 next가 있으면 nextjs, Python 코드가 fastapi를 import하면 fastapi"""
    package = root / "package.json"
    if package.is_file():
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # iron-laws: ignore[IL-301] 읽지 못하는 package.json은 스택 판단에 쓰지 않는다
            data = {}
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})} if isinstance(data, dict) else {}  # iron-laws: ignore[ARC-205] package.json의 키 이름이다
        if "next" in deps:
            return "nextjs"
    for path in sorted(root.rglob("*.py"))[:500]:
        if any(part in ("node_modules", ".venv", "venv", "site-packages") for part in path.parts):
            continue
        try:
            if re.search(r"^\s*(?:from|import)\s+fastapi\b", path.read_text(encoding="utf-8", errors="replace"), re.MULTILINE):
                return "fastapi"
        except OSError:  # iron-laws: ignore[IL-301] 읽지 못하는 파일은 스택 판단에서 뺀다
            continue
    return None


def contract_yaml(bp: Blueprint) -> str:
    return yaml.safe_dump({"architecture": bp.contract()}, allow_unicode=True, sort_keys=False)


def merge_section(existing: str | None, section: str) -> str:
    """지침 파일 본문에 틀 절을 넣는다. 이미 있으면 그 절만 바꾸고, 없으면 끝에 붙인다"""
    if existing is None:
        return section
    if SECTION_RE.search(existing):
        return SECTION_RE.sub(lambda _m: section.rstrip("\n"), existing, count=1)
    return existing.rstrip("\n") + "\n\n" + section


def apply(root: Path, bp: Blueprint, stage: str | None = None) -> list[str]:
    """틀을 파일로 쓴다. 만든 것과 바꾼 것을 사람이 읽는 문장 목록으로 돌려준다. 기존 설정 파일의 다른 내용과 기존 파일은 덮어쓰지 않는다"""
    from iron_laws.core.config import CONFIG_NAMES

    done: list[str] = []
    config = next((root / n for n in CONFIG_NAMES if (root / n).is_file()), None)
    if config is None:
        body: dict = {"stage": stage} if stage else {}
        body["architecture"] = bp.contract()
        (root / CONFIG_NAMES[0]).write_text("# 오철칙 (Iron Laws) 프로젝트 설정 파일\n" + yaml.safe_dump(body, allow_unicode=True, sort_keys=False), encoding="utf-8")
        done.append(f"{CONFIG_NAMES[0]}를 만들었습니다(구조 계약 포함).")
    elif re.search(r"(?m)^architecture:", config.read_text(encoding="utf-8")):
        done.append(f"{config.name}에 이미 architecture 절이 있어 바꾸지 않았습니다. 틀의 계약과 다르면 직접 맞추십시오.")
    else:
        with config.open("a", encoding="utf-8") as fh:
            fh.write("\n" + contract_yaml(bp))
        done.append(f"{config.name} 끝에 구조 계약(architecture 절)을 더했습니다.")
    targets = [root / n for n in ("AGENTS.md", "CLAUDE.md") if (root / n).is_file()] or [root / "AGENTS.md"]
    for target in targets:
        before = target.read_text(encoding="utf-8") if target.is_file() else None
        target.write_text(merge_section(before, bp.guideline_section()), encoding="utf-8")
        done.append(f"{target.name}에 프로젝트 구조 절을 {'넣었습니다' if before is None or MARK_START not in before else '바꿨습니다'}.")
    for folder in bp.folders:
        path = root / folder
        if not path.exists():
            path.mkdir(parents=True)
            (path / ".gitkeep").write_text("", encoding="utf-8")
            done.append(f"{folder}/ 폴더를 만들었습니다.")
    return done
