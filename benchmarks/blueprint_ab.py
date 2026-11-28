# iron-laws: ignore-file[IL-519] 과제별 pytest 시험 코드를 문자열로 담은 측정기다. 문자열 속 코드는 이 파일의 실행 경로가 아니다
"""
구조 틀(init --stack) 효과 측정: 같은 기능 요청을 AI에게 틀 없이·틀과 함께 시키고, 기능 시험을 통과한 결과만 구조 지표로 비교한다.

사용법:
    uv run python benchmarks/blueprint_ab.py <작업폴더> <결과.json> --ai-cmd "<AI 명령>" [--jobs=4] [--image=iron-laws-blueprint:py313]

- 과제: FastAPI + SQLite 기능 6개. 과제마다 pytest 시험(TestClient)이 있다.
- 방식: plain(기능 설명만), blueprint(기능 설명 + `init --stack fastapi`의 지침 절과 폴더).
- 기능 시험은 생성된 코드를 네트워크 없는 컨테이너에서 돌린다. 이미지에 fastapi·sqlalchemy·httpx·pytest가 있어야 한다:
    docker build -t iron-laws-blueprint:py313 -f benchmarks/blueprint_ab.Dockerfile benchmarks
- 구조 지표는 두 방식에 같은 규칙으로 잰다: ARC-202(라우터의 DB 직접 접근), ARC-203(순환), ARC-204(중복 함수), ARC-201(큰 함수).
  blueprint 방식에는 틀의 구조 계약 위반(ARC-207)도 함께 센다. plain 방식은 틀의 폴더를 쓰지 않으므로 계약 위반을 세지 않는다.
- 응답은 작업 폴더에 남으며 같은 지시문이면 다시 부르지 않는다.
작성자: 최진호
작성일: 2026-11-28
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ab_common import generate  # noqa: E402

from iron_laws.blueprints import BLUEPRINTS  # noqa: E402
from iron_laws.core.config import IronLawsConfig  # noqa: E402
from iron_laws.core.scanner import AuditScanner  # noqa: E402

VARIANTS = ("plain", "blueprint")
NEUTRAL_RULES = ("ARC-201", "ARC-202", "ARC-203", "ARC-204")
FORMAT = (
    "결과는 파일마다 ```python 코드 블록 하나로 내고, 블록 첫 줄에 `# file: <경로>` 주석을 적으십시오. 설명은 쓰지 마십시오.\n"
    "앱 객체는 `app/main.py`의 `app`이어야 하고, `app/__init__.py`도 만드십시오. DB는 SQLAlchemy와 SQLite를 쓰고,"
    " 연결 주소는 환경 변수 DATABASE_URL(기본 `sqlite:///./app.db`)에서 읽으십시오. 앱을 불러올 때 표를 만드십시오.\n"
)
TASKS = [
    {
        "name": "notes",
        "spec": "메모 API: POST /notes(본문 {title, body}, 201과 {id, title, body}), GET /notes/{id}(없으면 404), GET /notes(목록).",
        "test": "def test_notes(client):\n    r = client.post('/notes', json={'title': 't', 'body': 'b'})\n    assert r.status_code == 201\n    i = r.json()['id']\n    assert client.get(f'/notes/{i}').json()['title'] == 't'\n    assert client.get('/notes/99999').status_code == 404\n    assert len(client.get('/notes').json()) >= 1\n",
    },
    {
        "name": "users",
        "spec": "회원 API: POST /users(본문 {email, name}, 201과 {id, email, name}, 같은 email이면 409), GET /users/{id}(없으면 404).",
        "test": "def test_users(client):\n    r = client.post('/users', json={'email': 'a@x.io', 'name': 'a'})\n    assert r.status_code == 201\n    assert client.post('/users', json={'email': 'a@x.io', 'name': 'b'}).status_code == 409\n    assert client.get(f\"/users/{r.json()['id']}\").json()['email'] == 'a@x.io'\n    assert client.get('/users/99999').status_code == 404\n",
    },
    {
        "name": "todos",
        "spec": "할 일 API: POST /todos(본문 {title}, 201과 {id, title, done:false}), PATCH /todos/{id}/done(done을 true로, 없으면 404), GET /todos?done=true(끝난 것만).",
        "test": "def test_todos(client):\n    a = client.post('/todos', json={'title': 'a'}).json()['id']\n    client.post('/todos', json={'title': 'b'})\n    assert client.patch(f'/todos/{a}/done').status_code == 200\n    done = client.get('/todos', params={'done': 'true'}).json()\n    assert [t['id'] for t in done] == [a]\n    assert client.patch('/todos/99999/done').status_code == 404\n",
    },
    {
        "name": "inventory",
        "spec": "재고 API: POST /items(본문 {name, qty}, 201과 {id, name, qty}), POST /items/{id}/consume(본문 {amount}, 재고가 모자라면 400, 성공하면 남은 {id, name, qty}), GET /items/{id}(없으면 404).",
        "test": "def test_inventory(client):\n    i = client.post('/items', json={'name': 'n', 'qty': 5}).json()['id']\n    assert client.post(f'/items/{i}/consume', json={'amount': 3}).json()['qty'] == 2\n    assert client.post(f'/items/{i}/consume', json={'amount': 3}).status_code == 400\n    assert client.get(f'/items/{i}').json()['qty'] == 2\n    assert client.get('/items/99999').status_code == 404\n",
    },
    {
        "name": "bookmarks",
        "spec": "북마크 API: POST /bookmarks(본문 {url, tags: [문자열]}, 201과 {id, url, tags}), GET /bookmarks?tag=x(그 태그가 있는 것만).",
        "test": "def test_bookmarks(client):\n    client.post('/bookmarks', json={'url': 'https://a.io', 'tags': ['x', 'y']})\n    client.post('/bookmarks', json={'url': 'https://b.io', 'tags': ['y']})\n    got = client.get('/bookmarks', params={'tag': 'x'}).json()\n    assert [b['url'] for b in got] == ['https://a.io']\n    assert sorted(got[0]['tags']) == ['x', 'y']\n",
    },
    {
        "name": "comments",
        "spec": "글·댓글 API: POST /posts(본문 {title}, 201과 {id, title}), POST /posts/{id}/comments(본문 {text}, 201, 글이 없으면 404), GET /posts/{id}/comments(목록, 글이 없으면 404).",
        "test": "def test_comments(client):\n    p = client.post('/posts', json={'title': 't'}).json()['id']\n    assert client.post(f'/posts/{p}/comments', json={'text': 'c'}).status_code == 201\n    assert [c['text'] for c in client.get(f'/posts/{p}/comments').json()] == ['c']\n    assert client.post('/posts/99999/comments', json={'text': 'c'}).status_code == 404\n    assert client.get('/posts/99999/comments').status_code == 404\n",
    },
]
CONFTEST = (
    "import os, tempfile\n\nimport pytest\n\nos.environ['DATABASE_URL'] = 'sqlite:///' + os.path.join(tempfile.mkdtemp(), 'test.db')\n\n"
    "@pytest.fixture\ndef client():\n    from fastapi.testclient import TestClient\n    from app.main import app\n    with TestClient(app) as c:\n        yield c\n"
)


def prompt(task: dict, variant: str) -> str:
    head = f"FastAPI로 다음 기능을 만드십시오.\n\n{task['spec']}\n\n{FORMAT}"
    if variant == "plain":
        return head
    bp = BLUEPRINTS["fastapi"]
    return head + "\n이 프로젝트는 아래 구조를 따릅니다. 파일은 이 폴더 구조에 맞춰 나누십시오.\n\n" + bp.guideline_section()


def prepare(work: Path) -> None:
    (work / "prompts").mkdir(parents=True, exist_ok=True)
    for task in TASKS:
        for variant in VARIANTS:
            (work / "prompts" / f"{task['name']}.{variant}.txt").write_text(prompt(task, variant), encoding="utf-8")


def materialize(work: Path, name: str, variant: str) -> Path:
    """응답의 코드 블록을 `# file:` 경로대로 프로젝트 폴더에 쓰고, 기능 시험을 넣는다"""
    raw = (work / "raw" / f"{name}.{variant}.txt").read_text(encoding="utf-8")
    project = work / "projects" / f"{name}.{variant}"
    shutil.rmtree(project, ignore_errors=True)
    project.mkdir(parents=True)
    for block in re.findall(r"```(?:python|py)?\n(.*?)```", raw, re.S):
        m = re.match(r"#\s*file:\s*(\S+)\s*\n", block)
        if not m or ".." in m.group(1) or m.group(1).startswith("/"):
            continue
        target = project / m.group(1)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(block[m.end():], encoding="utf-8")
    task = next(t for t in TASKS if t["name"] == name)
    (project / "_bench_tests").mkdir()
    (project / "_bench_tests" / "conftest.py").write_text(CONFTEST, encoding="utf-8")
    (project / "_bench_tests" / f"test_{name}.py").write_text(task["test"], encoding="utf-8")
    return project


def functional(project: Path, image: str) -> bool:
    """네트워크 없는 컨테이너에서 기능 시험을 돌린다. 원본은 읽기 전용으로 붙이고 컨테이너 안에서 복사해 돌린다"""
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--pull", "never", "--memory", "512m", "-v", f"{project.resolve()}:/src:ro", image,
        "sh", "-c", "cp -r /src /tmp/w && cd /tmp/w && python -m pytest -q -p no:cacheprovider _bench_tests",
    ]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False).returncode == 0
    except subprocess.TimeoutExpired:  # iron-laws: ignore[IL-301] 시간 안에 끝나지 않은 기능 시험은 실패로 센다
        return False


def structure(project: Path, variant: str) -> dict:
    config = IronLawsConfig(excludes=[*IronLawsConfig().excludes, "_bench_tests"])
    if variant == "blueprint":
        config.architecture = IronLawsConfig(architecture=BLUEPRINTS["fastapi"].contract()).architecture
    violations = AuditScanner(project, config=config).scan().violations
    counts = {rule: sum(1 for v in violations if v.rule_id == rule) for rule in NEUTRAL_RULES}
    if variant == "blueprint":
        counts["ARC-207"] = sum(1 for v in violations if v.rule_id == "ARC-207")
    counts["files"] = len([p for p in project.rglob("*.py") if "_bench_tests" not in p.parts])
    return counts


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    options = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    if len(args) != 2 or "ai-cmd" not in options:
        print(__doc__)
        return 2
    work, out = Path(args[0]), Path(args[1])
    prepare(work)
    generate(work, TASKS, options["ai-cmd"], int(options.get("jobs", 4)), VARIANTS)
    image = options.get("image", "iron-laws-blueprint:py313")
    rows = []
    for task in TASKS:
        for variant in VARIANTS:
            project = materialize(work, task["name"], variant)
            passed = functional(project, image)
            rows.append({"task": task["name"], "variant": variant, "functional": passed, **(structure(project, variant) if passed else {})})
    summary = {}
    for variant in VARIANTS:
        ok = [r for r in rows if r["variant"] == variant and r["functional"]]
        summary[variant] = {"functional": f"{len(ok)}/{len(TASKS)}", **{k: sum(r.get(k, 0) for r in ok) for k in (*NEUTRAL_RULES, "files")}}
        if variant == "blueprint":
            summary[variant]["ARC-207"] = sum(r.get("ARC-207", 0) for r in ok)
    record = {"ai_cmd": options["ai-cmd"], "image": image, "summary": summary, "rows": rows}
    out.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
