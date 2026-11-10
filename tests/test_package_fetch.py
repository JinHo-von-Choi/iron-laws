"""
오철칙 패키지 색인 내려받기 시험: 실제 네트워크 없이 대역 응답으로 확인한다. 끝까지 오지 않은 목록은 색인이 되지 않는다.
작성자: 최진호
작성일: 2026-11-10
"""

import io
import json
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.deps.package_fetch import FetchError, fetch_names
from iron_laws.deps.package_index import build_index

runner = CliRunner()


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


def opener(body: bytes):
    return lambda request, timeout: FakeResponse(body)


def test_pypi_names_are_written_one_per_line(tmp_path: Path):
    body = json.dumps({"projects": [{"name": "requests"}, {"name": "Flask"}, {"name": "numpy"}]}).encode()
    target = tmp_path / "names.txt"
    url, count = fetch_names("pypi", target, opener(body), minimum=3)
    assert (url, count) == ("https://pypi.org/simple/", 3) and target.read_text().split() == ["requests", "Flask", "numpy"]


def test_partial_pypi_list_is_refused(tmp_path: Path):
    body = json.dumps({"projects": [{"name": "requests"}]}).encode()
    with pytest.raises(FetchError, match="전체 목록이 아니라서"):
        fetch_names("pypi", tmp_path / "names.txt", opener(body), minimum=1000)
    with pytest.raises(FetchError, match="해석하지 못했습니다"):
        fetch_names("pypi", tmp_path / "names.txt", opener(b"<html>"), minimum=1)


NPM_BODY = (
    b'{"total_rows":4,"offset":0,"rows":[\n'
    b'{"id":"-","key":"-","value":{"rev":"1-a"}},\n'
    b'{"id":"@scope/pkg","key":"@scope/pkg","value":{"rev":"1-b"}},\n'
    b'{"id":"_design/app","key":"_design/app","value":{"rev":"1-c"}},\n'
    b'{"id":"left-pad","key":"left-pad","value":{"rev":"1-d"}}\n'
    b']}\n'
)


def test_npm_rows_are_streamed_and_design_documents_skipped(tmp_path: Path):
    target = tmp_path / "names.txt"
    url, count = fetch_names("npm", target, opener(NPM_BODY), minimum=3)
    assert count == 3 and target.read_text().split() == ["-", "@scope/pkg", "left-pad"]


def test_truncated_npm_list_is_refused(tmp_path: Path):
    cut = NPM_BODY.replace(b"4", b"5000000", 1)  # total_rows는 많은데 받은 행은 적다
    with pytest.raises(FetchError, match="끝까지 오지 않았습니다"):
        fetch_names("npm", tmp_path / "names.txt", opener(cut), minimum=1)


def test_unknown_ecosystem_is_refused(tmp_path: Path):
    with pytest.raises(FetchError):
        fetch_names("cargo", tmp_path / "names.txt", opener(b""))


def test_fetch_command_reports_failure_without_writing_an_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: FakeResponse(b"<html>"))
    out = tmp_path / "idx"
    result = runner.invoke(app, ["index", "fetch", "--ecosystem", "pypi", "--out", str(out)])
    assert result.exit_code == 2 and "색인을 만들지 못했습니다" in result.output and not (out / "manifest.json").exists()


def _index(tmp_path: Path, collected_at: str) -> Path:
    names = tmp_path / "names.txt"
    names.write_text("requests\nflask\n", encoding="utf-8")
    out = tmp_path / "idx"
    build_index("pypi", names, out, "test", collected_at, True)
    return out


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests\n", encoding="utf-8")
    return project


def test_check_never_touches_the_network_and_warns_about_an_old_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def blocked(*a, **k):
        raise AssertionError("check는 네트워크를 쓰지 않는다")

    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    index = _index(tmp_path, "2020-01-01T00:00:00Z")
    result = runner.invoke(app, ["check", str(_project(tmp_path)), "--package-index", str(index)])
    assert "패키지 색인(pypi)이" in result.stderr and "index fetch" in result.stderr


def test_warning_is_off_when_the_limit_is_zero_or_the_index_is_fresh(tmp_path: Path):
    project = _project(tmp_path)
    (project / ".iron-laws.yml").write_text("policies:\n  package_index_max_age_days: 0\n", encoding="utf-8")
    old = _index(tmp_path, "2020-01-01T00:00:00Z")
    assert "패키지 색인" not in runner.invoke(app, ["check", str(project), "--package-index", str(old)]).stderr
    (project / ".iron-laws.yml").unlink()
    from datetime import UTC, datetime

    fresh = _index(tmp_path / "f", datetime.now(UTC).strftime("%Y-%m-%dT00:00:00Z")) if (tmp_path / "f").mkdir() is None else None
    assert "패키지 색인" not in runner.invoke(app, ["check", str(project), "--package-index", str(fresh)]).stderr
