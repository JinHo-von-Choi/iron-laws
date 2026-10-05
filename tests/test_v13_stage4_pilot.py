"""
오철칙 v1.3 4단계(PR-10) 파일럿 준비 도구 시험
- 이 시험은 도구의 동작(배정·기록·요약·계측의 내용)을 확인한다. 합성 값으로 만든 기록이며 어떤 팀의 실제 성과도 아니다.
- 파일럿 자체(3~5팀, 60~100건)는 이 저장소에서 수행하지 않았다.
작성자: 최진호
작성일: 2026-10-05
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.config import ConfigError
from iron_laws.core.metrics import METRICS_SCHEMA
from iron_laws.core.pilot import (
    PilotStore,
    assign,
    flag_risk,
    record_dropout,
    record_review,
    summarize,
)

cli = CliRunner()


def test_assignment_is_balanced_within_blocks_and_reproducible(tmp_path: Path):
    arms = []
    for index in range(20):
        arms.append(assign(PilotStore(tmp_path / "a.jsonl"), "team-a", f"pr-{index}", "medium", seed=7)["arm"])
    again = []
    for index in range(20):
        again.append(assign(PilotStore(tmp_path / "b.jsonl"), "team-a", f"pr-{index}", "medium", seed=7)["arm"])
    assert arms == again  # 같은 씨앗이면 재현된다
    for block in range(10):
        assert sorted(arms[2 * block : 2 * block + 2]) == ["baseline", "bundle"]  # 크기 2 블록마다 두 조건이 한 번씩
    assert arms != ["baseline", "bundle"] * 10  # 순서는 무작위다(고정 교대가 아니다)


def test_strata_and_teams_are_balanced_independently(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b"):
        for stratum in ("small", "large"):
            got = [assign(store, team, f"{team}-{stratum}-{i}", stratum, seed=3)["arm"] for i in range(4)]
            assert got.count("baseline") == 2 and got.count("bundle") == 2


def test_same_pr_is_never_exposed_twice_and_unassigned_pr_cannot_be_recorded(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    assign(store, "a", "pr-1", "small", 1)
    with pytest.raises(ConfigError):
        assign(store, "a", "pr-1", "small", 1)
    with pytest.raises(ConfigError):
        record_review(store, "pr-404", 10)
    record_review(store, "pr-1", 12)
    with pytest.raises(ConfigError):
        record_review(store, "pr-1", 5)  # 같은 PR의 결과를 두 번 기록하지 않는다
    with pytest.raises(ConfigError):
        record_review(store, "pr-1", -1)


def _fill(store: PilotStore, team: str, baseline_minutes: float, bundle_minutes: float, n: int, seed: int = 1, setup: float = 20) -> None:
    for i in range(n):
        arm = assign(store, team, f"{team}-{i}", "medium", seed)["arm"]
        record_review(store, f"{team}-{i}", baseline_minutes if arm == "baseline" else bundle_minutes, setup_minutes=setup if i == 0 else 0, overhead_minutes=2 if arm == "bundle" else 0)


def test_summary_refuses_to_judge_a_small_sample(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _fill(store, "a", 40, 20, 10)
    result = summarize(store)
    assert result["verdict"] == "insufficient_sample" and not result["sample"]["sufficient"]
    assert result["comparison"]["median_reduction"] == 0.5  # 값은 보여 주되 판정하지 않는다
    assert any("팀" in r for r in result["sample"]["reasons"])


def test_summary_evaluates_the_targets_only_when_the_sample_is_sufficient(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b", "c"):
        _fill(store, team, 40, 24, 22)  # 팀별 22건, 총 66건
    result = summarize(store)
    assert result["sample"]["sufficient"] and result["verdict"] == "targets_met"
    assert result["checks"] == {"setup_within_30_minutes": True, "median_reduction_at_least_30_percent": True, "p75_not_worse": True, "no_risk_increase": True}
    # 총 시간(추가 시간 포함)은 따로 보고된다
    assert result["arms"]["bundle"]["total_minutes"]["median"] == 26
    worse = PilotStore(tmp_path / "w.jsonl")
    for team in ("a", "b", "c"):
        _fill(worse, team, 40, 38, 22)
    assert summarize(worse)["verdict"] == "targets_not_met"


def test_one_risk_in_the_bundle_arm_turns_the_automation_off(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b", "c"):
        _fill(store, team, 40, 24, 22)
    bundle_pr = next(r["pr"] for r in store.records() if r["kind"] == "assign" and r["arm"] == "bundle")
    flag_risk(store, bundle_pr, "dangerous_inheritance", "승계가 위험했다")
    result = summarize(store)
    assert result["automation"] == "manual_review_only" and result["checks"]["no_risk_increase"] is False
    assert result["verdict"] == "targets_not_met"
    with pytest.raises(ConfigError):
        flag_risk(store, bundle_pr, "other")


def test_dropouts_are_kept_in_the_report(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _fill(store, "a", 30, 20, 4)
    record_dropout(store, "a", "도입 부담")
    result = summarize(store)
    assert result["dropouts"] == 1 and result["teams"]["a"]["dropouts"] == 1 and result["teams"]["a"]["assigned"] == 4


def test_pilot_cli_round_trip_and_stores_no_content(tmp_path: Path):
    path = tmp_path / "p.jsonl"
    arm = cli.invoke(app, ["pilot", "assign", "pr-1", "--team", "a", "--seed", "5", "--store", str(path)])
    assert arm.exit_code == 0 and arm.stdout.strip() in ("baseline", "bundle")
    assert cli.invoke(app, ["pilot", "assign", "pr-1", "--team", "a", "--store", str(path)]).exit_code == 2
    assert cli.invoke(app, ["pilot", "record", "pr-1", "--minutes", "12", "--setup-minutes", "15", "--store", str(path)]).exit_code == 0
    assert cli.invoke(app, ["pilot", "record", "pr-9", "--minutes", "12", "--store", str(path)]).exit_code == 2
    summary = cli.invoke(app, ["pilot", "summary", "--json", "--store", str(path)])
    assert summary.exit_code == 0 and json.loads(summary.stdout)["verdict"] == "insufficient_sample"
    assert set(json.loads(line)["kind"] for line in path.read_text().splitlines()) == {"assign", "review"}
    table = cli.invoke(app, ["pilot", "summary", "--store", str(path)])
    assert "표본 부족" in table.stdout


def test_metrics_are_opt_in_and_contain_no_paths_code_or_messages(tmp_path: Path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "secret_named_file.py").write_text('import os\nfrom flask import request\n\ndef f():\n    os.system("ls " + request.args["d"])\n    token = "AbCdEf123456GhIjKl"\n')
    off = cli.invoke(app, ["check", str(project)])
    assert off.exit_code == 1 and not list(tmp_path.glob("*.jsonl"))
    metrics = tmp_path / "m.jsonl"
    on = cli.invoke(app, ["check", str(project), "--metrics", str(metrics)])
    assert on.exit_code == 1
    text = metrics.read_text()
    assert "secret_named_file" not in text and "AbCdEf123456" not in text and "request.args" not in text and str(project) not in text
    record = json.loads(text.splitlines()[0])
    assert record["schema"] == METRICS_SCHEMA and record["command"] == "check" and record["files_scanned"] == 1
    assert record["findings"]["total"] >= 1 and record["elapsed_s"] >= 0 and "unknown_rate" in record["contract"]
    cli.invoke(app, ["audit", str(project), "--format", "json", "--metrics", str(metrics)])
    assert len(metrics.read_text().splitlines()) == 2
