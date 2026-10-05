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
    close_risk,
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
    assert result["comparison"]["median_reduction"] == 0.45  # 총 능동 시간(22분 대 40분) 기준. 값은 보여 주되 판정하지 않는다
    assert result["comparison"]["review_only"]["median_reduction"] == 0.5  # 순수 검토 시간은 보조 지표다
    assert any("팀" in r for r in result["sample"]["reasons"])


def test_summary_evaluates_the_targets_only_when_the_sample_is_sufficient(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b", "c"):
        _fill(store, team, 40, 24, 22)  # 팀별 22건, 총 66건
    result = summarize(store)
    assert result["sample"]["sufficient"] and result["verdict"] == "targets_met"
    assert result["checks"] == {"setup_within_30_minutes": True, "median_reduction_at_least_20_percent": True, "p75_not_worse": True, "no_risk_increase": True}
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


def _one_team_fill(store: PilotStore, baseline: tuple[float, float], bundle: tuple[float, float], n: int = 22) -> None:
    """(검토 분, 추가 분)을 조건별로 채운다. 세 팀이 모두 같은 값을 쓴다."""
    for team in ("a", "b", "c"):
        for i in range(n):
            arm = assign(store, team, f"{team}-{i}", "medium", 1)["arm"]
            minutes, overhead = baseline if arm == "baseline" else bundle
            record_review(store, f"{team}-{i}", minutes, setup_minutes=10 if i == 0 else 0, overhead_minutes=overhead)


def test_a_review_time_gain_that_costs_more_total_time_is_not_a_success(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _one_team_fill(store, baseline=(40, 0), bundle=(10, 110))  # 검토는 짧아졌지만 총 120분으로 늘었다
    result = summarize(store)
    assert result["comparison"]["review_only"]["median_reduction"] == 0.75
    assert result["comparison"]["median_reduction"] < 0 and result["verdict"] == "targets_not_met"
    assert result["checks"]["median_reduction_at_least_20_percent"] is False and result["checks"]["p75_not_worse"] is False


def test_total_time_p75_worsening_blocks_even_when_the_median_improves(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b", "c"):
        for i in range(22):
            arm = assign(store, team, f"{team}-{i}", "medium", 2)["arm"]
            slow_tail = i % 4 == 0
            record_review(store, f"{team}-{i}", 20 if arm == "bundle" else 40, overhead_minutes=(100 if slow_tail else 0) if arm == "bundle" else 0)
    result = summarize(store)
    assert result["comparison"]["median_reduction"] >= 0.2 and result["comparison"]["p75_change"] > 0
    assert result["checks"]["p75_not_worse"] is False and result["verdict"] == "targets_not_met"


def test_setup_time_is_amortized_and_reported_without_changing_the_primary_metric(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _one_team_fill(store, baseline=(40, 0), bundle=(20, 2))
    result = summarize(store)
    assert result["arms"]["bundle"]["total_minutes"]["median"] == 22
    assert result["arms"]["bundle"]["total_minutes_with_amortized_setup"]["median"] > 22
    assert result["arms"]["baseline"]["total_minutes_with_amortized_setup"]["median"] == 40


def test_risk_rates_carry_their_denominators_and_exceptions_are_not_misaccepts(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _one_team_fill(store, baseline=(40, 0), bundle=(20, 2))
    prs = [r["pr"] for r in store.records() if r["kind"] == "assign" and r["arm"] == "bundle"]
    flag_risk(store, prs[0], "legitimate_exception", "승인된 예외")
    result = summarize(store)
    bundle = result["arms"]["bundle"]
    assert bundle["legitimate_exceptions"] == 1 and bundle["confirmed_misaccepts"]["count"] == 0
    assert bundle["confirmed_misaccepts"]["of"] == bundle["risk_accepted_rate"]["of"] > 0
    assert result["automation"] == "allowed" and result["verdict"] == "targets_met"


def test_review_outcome_and_flag_feed_the_same_risk_count(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    for team in ("a", "b", "c"):
        for i in range(22):
            arm = assign(store, team, f"{team}-{i}", "medium", 3)["arm"]
            record_review(store, f"{team}-{i}", 40 if arm == "baseline" else 20, outcome="misaccept" if (team, i, arm) == ("a", 0, "bundle") else "")
    bundle_first = next(r["pr"] for r in store.records() if r["kind"] == "assign" and r["arm"] == "bundle")
    flag_risk(store, bundle_first, "misaccept", "같은 사건")
    result = summarize(store)
    assert result["arms"]["bundle"]["flagged_risks"] == 1  # PR당 한 번만 센다
    assert result["automation"] == "manual_review_only"


def test_outcome_alone_turns_the_automation_off(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    arm = assign(store, "a", "pr-1", "small", 1)["arm"]
    record_review(store, "pr-1", 10, outcome="dangerous_inheritance")
    result = summarize(store)
    assert result["automation"] == ("manual_review_only" if arm == "bundle" else "allowed")


def test_an_investigation_is_kept_apart_until_it_is_closed(tmp_path: Path):
    store = PilotStore(tmp_path / "s.jsonl")
    _one_team_fill(store, baseline=(40, 0), bundle=(20, 2))
    pr = next(r["pr"] for r in store.records() if r["kind"] == "assign" and r["arm"] == "bundle")
    flag_risk(store, pr, "misaccept", "확인 중", status="investigating")
    open_result = summarize(store)
    assert open_result["verdict"] == "investigation_pending" and open_result["investigating"] == 1
    assert open_result["automation"] == "pending_investigation" and open_result["arms"]["bundle"]["flagged_risks"] == 0
    close_risk(store, pr, "misaccept", confirmed=False, note="정당한 예외로 분류")
    cleared = summarize(store)
    assert cleared["investigating"] == 0 and cleared["verdict"] == "targets_met" and cleared["arms"]["bundle"]["legitimate_exceptions"] == 1
    flag_risk(store, pr, "misaccept", "다시 확인 중", status="investigating")
    close_risk(store, pr, "misaccept", confirmed=True)
    confirmed = summarize(store)
    assert confirmed["automation"] == "manual_review_only" and confirmed["verdict"] == "targets_not_met"
    with pytest.raises(ConfigError):
        close_risk(store, pr, "misaccept", confirmed=True)  # 조사 중인 사건이 없다
    with pytest.raises(ConfigError):
        flag_risk(store, pr, "misaccept", status="maybe")


def test_pilot_cli_flag_status_close_and_summary_columns(tmp_path: Path):
    path = tmp_path / "p.jsonl"
    arm = cli.invoke(app, ["pilot", "assign", "pr-1", "--team", "a", "--seed", "5", "--store", str(path)]).stdout.strip()
    assert cli.invoke(app, ["pilot", "record", "pr-1", "--minutes", "12", "--store", str(path)]).exit_code == 0
    assert cli.invoke(app, ["pilot", "flag", "pr-1", "--kind", "misaccept", "--status", "investigating", "--store", str(path)]).exit_code == 0
    assert cli.invoke(app, ["pilot", "flag", "pr-1", "--kind", "misaccept", "--status", "maybe", "--store", str(path)]).exit_code == 2
    summary = json.loads(cli.invoke(app, ["pilot", "summary", "--json", "--store", str(path)]).stdout)
    assert summary["verdict"] == "investigation_pending" and summary["investigating"] == 1
    assert cli.invoke(app, ["pilot", "close", "pr-1", "--kind", "misaccept", "--confirmed", "--store", str(path)]).exit_code == 0
    assert cli.invoke(app, ["pilot", "close", "pr-1", "--kind", "misaccept", "--confirmed", "--store", str(path)]).exit_code == 2
    closed = json.loads(cli.invoke(app, ["pilot", "summary", "--json", "--store", str(path)]).stdout)
    assert closed["investigating"] == 0 and closed["automation"] == ("manual_review_only" if arm == "bundle" else "allowed")
    assert "주 지표는 총 능동 시간" in cli.invoke(app, ["pilot", "summary", "--store", str(path)]).stdout


@pytest.mark.parametrize(("status", "expected_exit"), [("none", 0), ("investigating", 1), ("confirmed", 1)])
def test_pilot_state_closes_the_review_bundle_gate(tmp_path: Path, status: str, expected_exit: int):
    """파일럿에서 오승인이 확인되거나 조사 중이면 review-bundle은 필수 행동을 내어 CI 종료코드를 바꾼다. 문자열만 바꾸고 통과시키지 않는다."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    store = tmp_path / "pilot.jsonl"
    for index in range(2):  # 같은 팀·층에서 두 번 배정하면 baseline·bundle이 한 번씩 나온다
        arm = assign(PilotStore(store), "a", f"pr-{index}", "small", 1)["arm"]
        if arm == "bundle":
            bundle_pr = f"pr-{index}"
    if status != "none":
        flag_risk(PilotStore(store), bundle_pr, "misaccept", "시험", status="investigating" if status == "investigating" else "confirmed")
    result = cli.invoke(app, ["review-bundle", str(project), "--pilot-store", str(store), "--format", "json"])
    assert result.exit_code == expected_exit, result.stdout + result.stderr
    kinds = [a["kind"] for a in json.loads(result.stdout)["actions"]]
    assert ("manual_review_required" in kinds) == (status != "none")
    without = cli.invoke(app, ["review-bundle", str(project), "--format", "json"])
    assert without.exit_code == 0  # 파일럿 기록을 주지 않으면 기존 동작 그대로다
