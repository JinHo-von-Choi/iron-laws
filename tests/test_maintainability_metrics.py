"""
오철칙 유지보수 지표 시험: 자주 바뀌는 파일과 두 모듈에 겹친 정규식을 찾아 낸다
- 변경 집중: 최근 커밋에서 자주 바뀌면서 큰 파일을 앞세운다
- 중복 정규식: 두 모듈 이상에 같은 모양으로 정의된 정규식을 찾는다
작성자: 최진호
작성일: 2026-10-22
"""

import subprocess
from pathlib import Path

from iron_laws.architecture.metrics import _duplicate_patterns, collect
from iron_laws.core.scanner import AuditScanner

PATTERN = r"(?i)admin|user|delete|payment|account|order"


def _scanner(root: Path):
    return AuditScanner(root)


def test_a_pattern_defined_in_two_modules_is_found(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.py").write_text(f"import re\nP = re.compile({PATTERN!r})\n", encoding="utf-8")
    (tmp_path / "b" / "y.py").write_text(f"import re\nP = re.compile({PATTERN!r})\n", encoding="utf-8")
    sources = _scanner(tmp_path)._read_sources()
    found = _duplicate_patterns(sources)
    assert found == [PATTERN]


def test_a_pattern_defined_once_is_not_found(tmp_path: Path):
    (tmp_path / "a.py").write_text(f"import re\nP = re.compile({PATTERN!r})\n", encoding="utf-8")
    sources = _scanner(tmp_path)._read_sources()
    assert _duplicate_patterns(sources) == []


def test_a_short_pattern_is_not_treated_as_a_duplicate(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.py").write_text("import re\nP = re.compile('abc')\n", encoding="utf-8")
    (tmp_path / "b" / "y.py").write_text("import re\nP = re.compile('abc')\n", encoding="utf-8")
    sources = _scanner(tmp_path)._read_sources()
    assert _duplicate_patterns(sources) == []


def test_the_hotspot_indicator_names_the_often_changed_file(tmp_path: Path):
    env = {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
    }

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True, env=env)

    git("init", "-q")
    (tmp_path / "hot.py").write_text("x = 1\n" * 200, encoding="utf-8")
    (tmp_path / "cold.py").write_text("y = 2\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "init")
    for i in range(3):
        (tmp_path / "hot.py").write_text(f"x = {i}\n" + "x = 1\n" * 199, encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", f"change {i}")

    metrics = collect(tmp_path)
    paths = [h.path for h in metrics.hotspots]
    assert paths, "변경 이력에서 핫스팟을 찾아야 한다"
    assert paths[0].endswith("hot.py")
    assert metrics.hotspots[0].changes >= 3


def test_without_git_history_the_hotspot_list_is_empty_and_noted(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    metrics = collect(tmp_path)
    assert metrics.hotspots == []
    assert any("git" in note for note in metrics.notes)
