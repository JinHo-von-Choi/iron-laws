"""
오철칙 구조 진단 시험: 구조가 알려진 합성 프로젝트(양호·순환·허브·계층 붕괴·총체적 붕괴)를 크기별로 만들어 구간과 1순위 문제가 의도와 맞는지 본다.
표본은 개발팀이 만들고 분류했다. 개발용은 임계를 정할 때 보았고, 평가용은 개발용과 크기·이름 규칙을 다르게 해 임계를 맞춘 뒤 한 번만 평가했다.
사전 등록 기준: 평가용 10개 중 구간과 1순위 문제가 모두 일치하는 것이 9개 이상. 소스 10개 미만은 판정 불가.
작성자: 최진호
작성일: 2026-10-05
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.architecture import diagnose
from iron_laws.architecture.metrics import collect
from iron_laws.cli import app

cli = CliRunner()


def write(root: Path, rel: str, text: str) -> None:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def small_fn(name: str, body: str = "return x + 1") -> str:
    return f"def {name}(x):\n    {body}\n"


def add_tests(root: Path, names: list[str], prefix: str) -> None:
    for name in names:
        write(root, f"tests/test_{name}.py", f"import {prefix}{name}\n\ndef test_{name}():\n    assert {prefix}{name}.f_{name}(1) == 2\n")


def healthy(root: Path, n: int, style: str) -> None:
    """모델 → 저장소 → 서비스 → 처리기 한 방향으로만 의존하고 시험이 있다."""
    layers = {"models": [], "repo": [], "services": [], "api": []}
    for i in range(n):
        layers[list(layers)[i % 4]].append(i)
    names = []
    for layer, ids in layers.items():
        for i in ids:
            name = f"{style}{layer}_{i}"
            below = list(layers)[list(layers).index(layer) - 1] if layer != "models" else None
            imports = ""
            if below and layers[below]:
                imports = f"from {style}pkg.{below} import {style}{below}_{layers[below][0]}\n"
            write(root, f"{style}pkg/{layer}/{name}.py", imports + small_fn(f"f_{name}"))
            names.append(f"{layer}.{name}")
    for name in names:
        short = name.split(".")[-1]
        write(root, f"tests/test_{short}.py", f"def test_{short}():\n    assert 1\n  # {short}\n")


def cyclic(root: Path, n: int, style: str) -> None:
    for i in range(n):
        nxt = (i + 1) % n
        write(root, f"{style}ring/m{i}.py", f"from {style}ring import m{nxt}\n" + small_fn(f"f_m{i}"))
    for i in range(n):
        write(root, f"tests/test_m{i}.py", f"def test_m{i}():\n    assert 1\n")


def hub(root: Path, n: int, style: str) -> None:
    leaves = max(n // 3, 3)
    users = n - leaves - 1
    for i in range(leaves):
        write(root, f"{style}leaf/l{i}.py", small_fn(f"f_l{i}"))
    imports = "".join(f"from {style}leaf import l{i}\n" for i in range(leaves))
    write(root, f"{style}hub/service.py", imports + small_fn("run"))
    for i in range(users):
        write(root, f"{style}use/u{i}.py", f"from {style}hub import service\n" + small_fn(f"f_u{i}"))
    for i in range(leaves):
        write(root, f"tests/test_l{i}.py", f"def test_l{i}():\n    assert 1\n")
    for i in range(users):
        write(root, f"tests/test_u{i}.py", f"def test_u{i}():\n    assert 1\n")
    write(root, "tests/test_service.py", "def test_service():\n    assert 1\n")


def layering(root: Path, n: int, style: str) -> None:
    for i in range(n):
        if i % 2 == 0:
            body = f"from flask import Flask\napp = Flask(__name__)\n\n@app.get('/r{i}')\ndef handler_{i}(cursor):\n    cursor.execute('SELECT 1 FROM t{i}')\n    return 1\n"
        else:
            body = small_fn(f"f_{style}{i}")
        write(root, f"{style}web/w{i}.py", body)
    for i in range(n):
        write(root, f"tests/test_w{i}.py", f"def test_w{i}():\n    assert 1\n")


def collapsed(root: Path, n: int, style: str) -> None:
    """순환 + 계층 위반 + 시험 없음"""
    for i in range(n):
        nxt = (i + 1) % n
        body = f"from {style}mess import m{nxt}\n" + (f"from flask import Flask\napp = Flask(__name__)\n\n@app.get('/r{i}')\ndef handler_{i}(cursor):\n    cursor.execute('SELECT 1')\n    return 1\n" if i % 2 == 0 else small_fn(f"f_m{i}"))
        write(root, f"{style}mess/m{i}.py", body)


TYPES = {
    "healthy": (healthy, "양호", None),
    "cyclic": (cyclic, "주의", "cycles"),
    "hub": (hub, "주의", "god_module"),
    "layering": (layering, "주의", "layering"),
    "collapsed": (collapsed, "붕괴", "cycles_first"),
}
DEV = [(kind, n, "") for kind in TYPES for n in (12, 30)]
HOLDOUT = [(kind, n, "x_") for kind in TYPES for n in (45, 90)]


def run_case(tmp_path: Path, kind: str, n: int, style: str) -> dict:
    root = tmp_path / f"{kind}{n}"
    TYPES[kind][0](root, n, style)
    return diagnose.evaluate(collect(root))


def matches(kind: str, data: dict) -> bool:
    _gen, band, first = TYPES[kind]
    first_key = data["steps"][0]["key"] if data["steps"] else None
    return data["band"] == band and first_key == first


@pytest.mark.parametrize(("kind", "n", "style"), DEV, ids=[f"dev-{k}-{n}" for k, n, _s in DEV])
def test_development_projects_get_the_intended_band_and_first_step(tmp_path: Path, kind: str, n: int, style: str):
    data = run_case(tmp_path, kind, n, style)
    _gen, band, first = TYPES[kind]
    assert data["band"] == band, (data["band"], data["reason"], {k: v["label"] for k, v in data["indicators"].items()})
    assert (data["steps"][0]["key"] if data["steps"] else None) == first, [s["key"] for s in data["steps"]]


def test_held_out_projects_meet_the_preregistered_agreement(tmp_path: Path):
    results = {(kind, n): matches(kind, run_case(tmp_path, kind, n, style)) for kind, n, style in HOLDOUT}
    agreed = sum(results.values())
    assert agreed >= 9, {k: v for k, v in results.items() if not v}
    # 평가용은 개발용과 크기(45·90 대 12·30)와 이름 규칙이 다르다
    assert {n for _k, n, _s in HOLDOUT}.isdisjoint({n for _k, n, _s in DEV})


def test_a_project_under_ten_files_is_not_judged(tmp_path: Path):
    root = tmp_path / "tiny"
    cyclic(root, 4, "")
    data = diagnose.evaluate(collect(root))
    assert data["band"] == "판정 불가" and "10개 미만" in data["reason"]


def test_a_stable_models_module_that_everyone_imports_is_not_a_hub(tmp_path: Path):
    root = tmp_path / "stable"
    write(root, "pkg/models.py", small_fn("f_models"))
    for i in range(30):
        write(root, f"pkg/m{i}.py", "from pkg import models\n" + small_fn(f"f_m{i}"))
        write(root, f"tests/test_m{i}.py", f"def test_m{i}():\n    assert 1\n")
    data = diagnose.evaluate(collect(root))
    assert data["indicators"]["god_module"]["state"] == "ok" and data["band"] == "양호"


def test_when_there_are_no_tests_and_the_cycle_is_large_the_first_step_breaks_one_link(tmp_path: Path):
    data = run_case(tmp_path, "collapsed", 30, "")
    assert data["steps"][0]["key"] == "cycles_first" and "인터페이스" in data["steps"][0]["how"]
    assert any("전부 다시 쓰지" in x for x in data["dont"])


def test_metrics_are_deterministic_for_the_same_code(tmp_path: Path):
    root = tmp_path / "det"
    hub(root, 30, "")
    first, second = collect(root).to_dict(), collect(root).to_dict()
    first.pop("root"), second.pop("root")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_cli_markdown_json_prompt_and_compare(tmp_path: Path):
    root = tmp_path / "proj"
    collapsed(root, 30, "")
    md = cli.invoke(app, ["architecture", str(root)])
    assert md.exit_code == 0 and "구간: 붕괴" in md.stdout and "먼저 풀 문제" in md.stdout and "하지 말 것" in md.stdout and "구조의 한 단면" in md.stdout
    saved = tmp_path / "before.json"
    saved.write_text(cli.invoke(app, ["architecture", str(root), "--format", "json"]).stdout, encoding="utf-8")
    assert json.loads(saved.read_text())["schema"] == "iron-laws.architecture/1"
    prompt = cli.invoke(app, ["architecture", str(root), "--format", "prompt"]).stdout
    assert "하나만 수행" in prompt and "동작을 바꾸지 마세요" in prompt
    for i in range(30):  # 순환을 끊는다
        (root / f"mess/m{i}.py").write_text(small_fn(f"f_m{i}"))
    again = cli.invoke(app, ["architecture", str(root), "--compare", str(saved)])
    assert "이전 진단과 비교" in again.stdout and "개선" in again.stdout
    assert cli.invoke(app, ["architecture", str(root), "--format", "xml"]).exit_code == 2
    assert cli.invoke(app, ["architecture", str(tmp_path / "none")]).exit_code == 2
