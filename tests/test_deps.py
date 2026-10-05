"""
오철칙 의존성 권고(deps) 시험: OSV 영향 구간 해석, 알려진 수정 경계, 락 파일 해석(직접·전이·그래프), 보고서와 종료코드.
권고 자료는 OSV 스키마를 따라 개발팀이 만든 합성 표본이다. 실제 OSV 서버 판정과의 대조는 benchmarks/deps_osv_crosscheck.py가 한다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
import socket
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.deps import report as dep_report
from iron_laws.deps.advise import analyze
from iron_laws.deps.lockfiles import (
    parse_lock,
    parse_package_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_uv_lock,
)
from iron_laws.deps.osv import AdvisoryDb, Affected, Range, is_affected, load_db, parse_advisory
from iron_laws.deps.versions import parse_semver

cli = CliRunner()


def advisory(id_: str, name: str, events: list[dict], *, ecosystem: str = "PyPI", versions: list[str] | None = None, aliases: list[str] | None = None, severity: str = "HIGH", withdrawn: str | None = None, kind: str | None = None, modified: str = "2026-09-20T00:00:00Z") -> dict:
    raw: dict = {
        "id": id_,
        "aliases": aliases or [],
        "summary": f"{id_} 요약",
        "modified": modified,
        "database_specific": {"severity": severity},
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": kind or ("SEMVER" if ecosystem == "npm" else "ECOSYSTEM"), "events": events}], **({"versions": versions} if versions else {})}],
    }
    if withdrawn:
        raw["withdrawn"] = withdrawn
    return raw


def db_of(*raws: dict) -> AdvisoryDb:
    db = AdvisoryDb()
    for raw in raws:
        adv = parse_advisory(raw)
        if adv is not None:
            db.add(adv)
    return db


def affected_of(raw: dict) -> Affected:
    return parse_advisory(raw).affected[0]


# ---------------------------------------------------------------------------
# 영향 구간 해석
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("events", "version", "expected"),
    [
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "1.9.9", True),
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "2.0.0", False),
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "2.0.1", False),
        ([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], "0.9.0", False),
        ([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}], "1.0.0", True),
        ([{"introduced": "0"}, {"last_affected": "1.5.0"}], "1.5.0", True),
        ([{"introduced": "0"}, {"last_affected": "1.5.0"}], "1.5.1", False),
        ([{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}], "1.5.0", False),
        ([{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}], "2.0.5", True),
        ([{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"fixed": "2.1.0"}], "2.1.0", False),
        ([{"introduced": "0"}, {"limit": "3.0.0"}], "2.9.0", True),
        ([{"introduced": "0"}, {"limit": "3.0.0"}], "3.0.0", False),
        ([{"fixed": "2.0.0"}, {"introduced": "0"}], "1.0.0", True),  # 이벤트 순서가 뒤섞여 있어도 버전순으로 해석한다
    ],
)
def test_osv_ranges(events, version, expected):
    assert is_affected(affected_of(advisory("A-1", "pkg", events)), version) is expected


def test_pep440_ordering_is_used_for_pypi():
    aff = affected_of(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "2.0"}]))
    assert is_affected(aff, "2.0rc1") is True and is_affected(aff, "2.0") is False and is_affected(aff, "2.0.post1") is False and is_affected(aff, "1!1.0") is False


def test_semver_prerelease_ordering_is_used_for_npm():
    aff = affected_of(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}], ecosystem="npm"))
    assert is_affected(aff, "2.0.0-rc.1") is True and is_affected(aff, "2.0.0") is False and is_affected(aff, "1.10.0") is True
    assert parse_semver("1.0.0-alpha") < parse_semver("1.0.0-alpha.1") < parse_semver("1.0.0-alpha.beta") < parse_semver("1.0.0-beta") < parse_semver("1.0.0-beta.2") < parse_semver("1.0.0-beta.11") < parse_semver("1.0.0-rc.1") < parse_semver("1.0.0")


def test_explicit_versions_list_is_honored():
    raw = advisory("A-1", "pkg", [], versions=["1.0.0", "1.0.1"])
    raw["affected"][0]["ranges"] = []
    aff = affected_of(raw)
    assert is_affected(aff, "1.0.1") is True and is_affected(aff, "1.0.2") is False


def test_git_only_range_and_unparsable_versions_are_undetermined_not_clean():
    git = affected_of(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "abc123"}], kind="GIT"))
    assert is_affected(git, "1.0.0") is None
    normal = affected_of(advisory("A-2", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}]))
    assert is_affected(normal, "not-a-version") is None


def test_withdrawn_and_unsupported_ecosystem_advisories_are_ignored():
    assert parse_advisory(advisory("A-1", "pkg", [{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z")) is None
    assert parse_advisory(advisory("A-2", "pkg", [{"introduced": "0"}], ecosystem="Go")) is None


# ---------------------------------------------------------------------------
# 권고 합치기와 알려진 수정 경계
# ---------------------------------------------------------------------------


def lock_of(tmp_path: Path, packages: dict[str, str]) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text("".join(f"{n}=={v}\n" for n, v in packages.items()), encoding="utf-8")
    return path


def test_aliases_are_merged_into_one_finding(tmp_path: Path):
    db = db_of(
        advisory("GHSA-aaaa", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}], aliases=["CVE-2026-1"]),
        advisory("PYSEC-1", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}], aliases=["CVE-2026-1"], severity="미상"),
    )
    findings, _ = analyze(parse_requirements(lock_of(tmp_path, {"pkg": "1.0.0"})), db)
    assert len(findings) == 1 and len(findings[0].hits) == 1 and findings[0].hits[0].id == "GHSA-aaaa" and "PYSEC-1" in findings[0].hits[0].aliases


def test_fix_boundary_skips_a_candidate_that_is_inside_a_later_vulnerable_interval(tmp_path: Path):
    db = db_of(
        advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "1.2.0"}]),
        advisory("A-2", "pkg", [{"introduced": "1.1.0"}, {"fixed": "1.4.0"}]),
    )
    findings, _ = analyze(parse_requirements(lock_of(tmp_path, {"pkg": "1.0.0"})), db)
    assert findings[0].fix_boundary == "1.4.0"  # 1.2.0은 A-1을 벗어나지만 A-2의 영향 아래다


def test_fix_boundary_reports_major_change_and_missing_fix(tmp_path: Path):
    db = db_of(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}]), advisory("A-2", "other", [{"introduced": "0"}, {"last_affected": "9.9.9"}]))
    findings, _ = analyze(parse_requirements(lock_of(tmp_path, {"pkg": "1.9.0", "other": "1.0.0"})), db)
    by = {f.package: f for f in findings}
    assert by["pkg"].fix_boundary == "2.0.0" and by["pkg"].fix_boundary_same_major is False
    assert by["other"].fix_boundary is None and "수정 버전이 없습니다" in by["other"].fix_note


def test_a_clean_version_is_not_reported_and_an_unparsable_one_is_undetermined(tmp_path: Path):
    db = db_of(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "2.0.0"}]))
    findings, undetermined = analyze(parse_requirements(lock_of(tmp_path, {"pkg": "2.0.0"})), db)
    assert findings == [] and undetermined == []
    path = tmp_path / "requirements.txt"
    path.write_text("pkg==weird!version\n")
    findings, undetermined = analyze(parse_requirements(path), db)
    assert findings == [] and [u.package for u in undetermined] == ["pkg"]  # 해석할 수 없는 설치 버전은 깨끗함이 아니라 판정 불가다


def test_severity_is_the_highest_among_merged_advisories_and_findings_are_sorted(tmp_path: Path):
    db = db_of(
        advisory("A-1", "low", [{"introduced": "0"}, {"fixed": "2"}], severity="LOW"),
        advisory("A-2", "crit", [{"introduced": "0"}, {"fixed": "2"}], severity="CRITICAL"),
        advisory("A-3", "unk", [{"introduced": "0"}, {"fixed": "2"}], severity="미상"),
    )
    findings, _ = analyze(parse_requirements(lock_of(tmp_path, {"low": "1", "crit": "1", "unk": "1"})), db)
    assert [f.package for f in findings] == ["crit", "low", "unk"]


# ---------------------------------------------------------------------------
# 락 파일 해석
# ---------------------------------------------------------------------------

UV_LOCK = """version = 1
[[package]]
name = "myapp"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "web" }, { name = "left-pad" }]

[[package]]
name = "web"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "Deep_Lib" }]

[[package]]
name = "deep-lib"
version = "0.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "left-pad"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_uv_lock_gives_versions_direct_transitive_and_the_graph(tmp_path: Path):
    path = tmp_path / "uv.lock"
    path.write_text(UV_LOCK)
    lock = parse_uv_lock(path)
    by = {p.name: p for p in lock.packages}
    assert set(by) == {"web", "deep-lib", "left-pad"} and "myapp" not in by
    assert by["web"].direct is True and by["deep-lib"].direct is False and by["deep-lib"].parents == {"web"}
    assert lock.capabilities == {"versions": True, "direct_transitive": True, "graph": True}
    db = db_of(advisory("A-1", "deep-lib", [{"introduced": "0"}, {"fixed": "0.6.0"}]))
    findings, _ = analyze(lock, db)
    assert findings[0].direct is False and findings[0].via_direct == ["web"] and findings[0].fix_boundary == "0.6.0"


def test_poetry_lock_needs_pyproject_for_direct_dependencies(tmp_path: Path):
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "a"\nversion = "1.0.0"\n[package.dependencies]\nb = ">=1"\n\n[[package]]\nname = "b"\nversion = "2.0.0"\n')
    lock = parse_poetry_lock(tmp_path / "poetry.lock")
    assert all(p.direct is None for p in lock.packages) and lock.capabilities["direct_transitive"] is False and lock.notes
    (tmp_path / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = "^3.12"\na = "^1.0"\n')
    lock = parse_poetry_lock(tmp_path / "poetry.lock")
    by = {p.name: p for p in lock.packages}
    assert by["a"].direct is True and by["b"].direct is False and by["b"].parents == {"a"}


def test_requirements_have_versions_only(tmp_path: Path):
    path = tmp_path / "requirements.txt"
    path.write_text("# 주석\nrequests==2.31.0  # 인라인\nDjango[argon2]==4.2.1 ; python_version>'3.8'\nflask>=2.0\n-r other.txt\nnumpy==1.26.0 --hash=sha256:abc\n")
    lock = parse_requirements(path)
    assert {p.name: p.version for p in lock.packages} == {"requests": "2.31.0", "django": "4.2.1", "numpy": "1.26.0"}
    assert all(p.direct is None for p in lock.packages) and lock.capabilities["direct_transitive"] is False


PACKAGE_LOCK_V3 = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"express": "^4.0.0"}, "devDependencies": {"jest": "^29"}},
        "node_modules/express": {"version": "4.17.0", "dependencies": {"qs": "6.5.0"}},
        "node_modules/qs": {"version": "6.5.0"},
        "node_modules/jest": {"version": "29.0.0", "dev": True},
        "node_modules/express/node_modules/qs": {"version": "6.7.0"},
    },
}


def test_package_lock_v3_direct_transitive_dev_and_nested_versions(tmp_path: Path):
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(PACKAGE_LOCK_V3))
    lock = parse_package_lock(path)
    by = {(p.name, p.version): p for p in lock.packages}
    assert by[("express", "4.17.0")].direct is True and by[("qs", "6.5.0")].direct is False and by[("jest", "29.0.0")].dev is True
    assert ("qs", "6.7.0") in by  # 중첩 설치된 같은 이름의 다른 버전도 따로 점검한다
    db = db_of(advisory("A-1", "qs", [{"introduced": "0"}, {"fixed": "6.5.3"}], ecosystem="npm"))
    findings, _ = analyze(lock, db)
    assert [(f.package, f.version) for f in findings] == [("qs", "6.5.0")] and findings[0].via_direct == ["express"]


def test_package_lock_v1_uses_the_manifest_for_direct_dependencies(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"a": "^1"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "requires": {"b": "^2"}}, "b": {"version": "2.0.0"}}}))
    lock = parse_package_lock(tmp_path / "package-lock.json")
    by = {p.name: p for p in lock.packages}
    assert by["a"].direct is True and by["b"].direct is False and by["b"].parents == {"a"}


PNPM_LOCK = """lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      axios:
        specifier: ^1.0.0
        version: 1.5.0
packages:
  axios@1.5.0:
    resolution: {integrity: sha512-x}
  follow-redirects@1.15.0:
    resolution: {integrity: sha512-y}
snapshots:
  axios@1.5.0:
    dependencies:
      follow-redirects: 1.15.0
  follow-redirects@1.15.0: {}
"""


def test_pnpm_lock_v9(tmp_path: Path):
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(PNPM_LOCK)
    by = {p.name: p for p in parse_pnpm_lock(path).packages}
    assert by["axios"].direct is True and by["follow-redirects"].direct is False and by["follow-redirects"].parents == {"axios"}


# ---------------------------------------------------------------------------
# 보고서와 명령
# ---------------------------------------------------------------------------


def write_project(tmp_path: Path, modified: str = "2026-09-20T00:00:00Z") -> tuple[Path, Path]:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "uv.lock").write_text(UV_LOCK)
    osv = tmp_path / "osv"
    osv.mkdir()
    (osv / "A-1.json").write_text(json.dumps(advisory("GHSA-x", "deep-lib", [{"introduced": "0"}, {"fixed": "0.6.0"}], aliases=["CVE-2026-9"], modified=modified)))
    return project, osv


def test_cli_markdown_json_prompt_and_exit_codes(tmp_path: Path):
    project, osv = write_project(tmp_path)
    md = cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv)])
    assert md.exit_code == 1
    assert "먼저 할 일" in md.stdout and "락 파일" in md.stdout and "web" in md.stdout and "알려진 권고와 버전이 겹친다" in md.stdout
    data = json.loads(cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv), "--format", "json"]).stdout)
    finding = data["locks"][0]["findings"][0]
    assert data["schema"] == "iron-laws.deps/1" and finding["package"] == "deep-lib" and finding["via_direct"] == ["web"] and finding["fix_boundary"] == "0.6.0"
    prompt = cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv), "--format", "prompt"]).stdout
    assert "다른 패키지는 건드리지 마세요" in prompt and "deep-lib" in prompt
    assert cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv), "--fail-on", "never"]).exit_code == 0
    assert cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv), "--fail-on", "critical"]).exit_code == 0  # 심각도 HIGH는 critical 기준 미만


def test_empty_or_missing_advisory_db_is_an_input_error_not_a_clean_result(tmp_path: Path):
    project, _ = write_project(tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.invoke(app, ["deps", str(project), "--advisory-db", str(empty)]).exit_code == 2
    assert cli.invoke(app, ["deps", str(project), "--advisory-db", str(tmp_path / "none")]).exit_code == 2
    assert cli.invoke(app, ["deps", str(tmp_path / "none"), "--advisory-db", str(empty)]).exit_code == 2


def test_stale_snapshot_is_warned_and_no_lock_file_is_stated(tmp_path: Path):
    project, osv = write_project(tmp_path, modified="2025-01-01T00:00:00Z")
    db = load_db(osv)
    assert dep_report.snapshot_age_days(db, date(2026, 10, 5)) > 30
    assert "새로 받아서" in cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv)]).stdout
    bare = tmp_path / "bare"
    bare.mkdir()
    out = cli.invoke(app, ["deps", str(bare), "--advisory-db", str(osv)])
    assert out.exit_code == 0 and "락 파일을 찾지 못했습니다" in out.stdout


def test_zip_dumps_in_osv_layout_are_read(tmp_path: Path):
    import zipfile

    folder = tmp_path / "db" / "PyPI"
    folder.mkdir(parents=True)
    with zipfile.ZipFile(folder / "all.zip", "w") as z:
        z.writestr("A-1.json", json.dumps(advisory("A-1", "pkg", [{"introduced": "0"}, {"fixed": "2"}])))
    db = load_db(tmp_path / "db")
    assert db.count == 1 and db.for_package("PyPI", "Pkg")


def test_the_command_never_touches_the_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def refuse(*_a, **_k):
        raise AssertionError("네트워크를 쓰면 안 된다")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    project, osv = write_project(tmp_path)
    assert cli.invoke(app, ["deps", str(project), "--advisory-db", str(osv)]).exit_code == 1


def test_parse_lock_rejects_unknown_files(tmp_path: Path):
    path = tmp_path / "Cargo.lock"
    path.write_text("")
    with pytest.raises(ValueError):
        parse_lock(path)


def test_range_dataclass_roundtrip():
    assert Range("SEMVER", [("introduced", "0")]).kind == "SEMVER"
