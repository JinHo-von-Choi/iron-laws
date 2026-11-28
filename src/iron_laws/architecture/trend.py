"""
오철칙 구조 추이: 점검할 때마다 구조 지표의 상태와 계열별 지적 수를 .iron-laws-health.jsonl에 한 줄 남기고,
같은 브랜치의 직전 기록과 비교해 나빠진 지표를 보여 준다. 자주 바뀌면서 지적이 있는 파일 상위 3개를 먼저 볼 곳으로 낸다.

- 합성 점수는 만들지 않는다. 지표마다 상태(양호·주의·붕괴)를 그대로 비교한다.
- 기록에는 시각, 브랜치, 커밋, 규칙 집합 지문, 지표 상태, 계열별 지적 수만 남기고 코드와 파일 경로는 남기지 않는다.
작성자: 최진호
작성일: 2026-11-28
"""

import json
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

HEALTH_FILE = ".iron-laws-health.jsonl"
RANK = {"ok": 0, "warn": 1, "bad": 2}
STATE_LABEL = {"ok": "양호", "warn": "주의", "bad": "붕괴"}
LAYER_LABEL = {"STANDARD": "보안 기준", "AI_CODE": "AI 코드 보정", "AI_ATTACK": "AI 공격면", "ARCHITECTURE": "구조", "PERFORMANCE": "성능", "OPERATIONS": "운영"}


def _git(root: Path, *args: str) -> str:
    try:
        done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):  # iron-laws: ignore[IL-301] git이 없으면 브랜치·커밋을 비워 둔다
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def make_record(root: Path, data: dict, report) -> dict:
    return {
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "commit": _git(root, "rev-parse", "--short", "HEAD"),
        "ruleset": report.metadata.get("ruleset", {}).get("hash", ""),
        "band": data["band"],
        "indicators": {key: ind["state"] for key, ind in data["indicators"].items()},
        "findings": dict(sorted(Counter(v.layer.value for v in report.violations).items())),
    }


def previous(root: Path, branch: str) -> dict | None:
    path = root / HEALTH_FILE
    if not path.is_file():
        return None
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:  # iron-laws: ignore[IL-301] 깨진 줄은 비교에 쓰지 않는다
            continue
        if isinstance(row, dict) and row.get("branch") == branch:
            last = row
    return last


def append(root: Path, record: dict) -> None:
    with (root / HEALTH_FILE).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def worsened(before: dict, after: dict, data: dict) -> list[str]:
    """직전 기록보다 나빠진 지표와 늘어난 계열별 지적 수"""
    lines = []
    for key, state in after["indicators"].items():
        was = before.get("indicators", {}).get(key)
        if was in RANK and RANK[state] > RANK[was]:
            ind = data["indicators"][key]
            lines.append(f"- {ind['name']}: {STATE_LABEL[was]} → {STATE_LABEL[state]} ({ind['value']})")
    for layer, count in after["findings"].items():
        was = before.get("findings", {}).get(layer, 0)
        if count > was:
            lines.append(f"- {LAYER_LABEL.get(layer, layer)} 지적 {was}건 → {count}건")
    if before.get("ruleset") and before.get("ruleset") != after["ruleset"]:
        lines.append("- (규칙 집합이 바뀌어 지적 수 차이에는 규칙 변경도 섞여 있습니다)")
    return lines


def hot_files(data: dict, report, limit: int = 3) -> list[str]:
    """자주 바뀌는 파일 가운데 지적이 있는 파일. 변경 집중 지표의 순서를 따른다"""
    counts = Counter(v.file_path.as_posix() for v in report.violations)
    hot = (data["indicators"].get("hotspots") or {}).get("files") or []
    return [f"- {path}: 지적 {counts[path]}건" for path in hot if counts.get(path)][:limit]


def markdown(root: Path, data: dict, report) -> str:
    """기록을 남기고 비교 결과를 마크다운으로 돌려준다"""
    record = make_record(root, data, report)
    before = previous(root, record["branch"])
    append(root, record)
    lines = ["## 지난번과 비교", ""]
    if before is None:
        lines.append(f"첫 기록입니다. 다음 실행부터 비교합니다({HEALTH_FILE}).")
    else:
        worse = worsened(before, record, data)
        lines.append(f"직전 기록: {before.get('time', '?')} (커밋 {before.get('commit') or '?'})")
        lines.extend(worse or ["- 나빠진 지표가 없습니다."])
    lines += ["", "## 먼저 볼 파일(자주 바뀌고 지적이 있음)", ""]
    lines.extend(hot_files(data, report) or ["- 해당하는 파일이 없습니다(git 이력이 없거나 자주 바뀌는 파일에 지적이 없음)."])
    return "\n".join(lines)
