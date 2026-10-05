"""
구조 진단: 계측값을 지표별 상태(양호·주의·붕괴)와 프로젝트 구간으로 바꾸고, 먼저 풀 문제와 단계별 개선안을 만든다.
- 임계는 파일·함수 수에 대한 비율과 순환 묶음 크기로 정하며 아래 THRESHOLDS가 기본값이다. 보고서에 적용값을 남긴다.
- 소스 파일이 MIN_FILES개 미만이면 구간을 판정하지 않는다.
- 개선 순서는 기본이 `시험 → 순환 → 계층 → 중복 → 큰 함수·파일`이다. 시험이 없고 순환이 크면 시험을 쓸 수 없으므로 순환 안의 연결 하나를 끊는 것을 먼저 제안한다.
- 지표는 구조의 한 단면이며 설계의 좋고 나쁨을 보증하지 않는다.
작성자: 최진호
작성일: 2026-10-05
"""

from typing import Any

from iron_laws.architecture.metrics import MIN_FILES, Metrics

SCHEMA = "iron-laws.architecture/1"
THRESHOLDS = {
    "cycles": {"warn_ratio": 0.0, "bad_ratio": 0.10, "bad_size": 8},  # 순환에 든 파일 비율, 가장 큰 묶음의 파일 수
    "god_module": {"warn_fan_in": (5, 0.25), "bad_fan_in": (10, 0.40), "warn_fan_out": (12, 0.30), "hub_min_out_warn": 4, "hub_min_out_bad": 8},  # (최소 개수, 전체 대비 비율) 중 큰 쪽
    "large_functions": {"warn_ratio": 0.05, "bad_ratio": 0.15},
    "large_files": {"warn_ratio": 0.05, "bad_ratio": 0.15},
    "layering": {"warn_ratio": 0.0, "bad_ratio": 0.10},  # 파일 수 대비 위반 파일 수
    "duplicates": {"warn_ratio": 0.03, "bad_ratio": 0.10},  # 함수 수 대비 중복 지적 수
    "tests": {"ok_ratio": 0.5, "warn_ratio": 0.2},  # 시험이 있는 모듈 비율(이 이상이면 양호)
}
LABEL = {"ok": "양호", "warn": "주의", "bad": "붕괴"}
INDICATOR_NAME = {
    "tests": "시험 안전망",
    "cycles": "순환 의존",
    "god_module": "한 모듈에 쏠림",
    "layering": "계층 경계",
    "duplicates": "중복 함수",
    "large_functions": "큰 함수",
    "large_files": "큰 파일",
}
DONT = (
    "한 번에 전부 다시 쓰지 마세요. 동작이 바뀌어도 알아챌 수 없습니다.",
    "시험 없이 파일을 옮기거나 쪼개지 마세요. 어디가 깨졌는지 알 수 없습니다.",
    "순환 의존을 그대로 둔 채 계층(폴더)만 새로 만들지 마세요. 순환이 새 폴더 사이로 옮겨 갈 뿐입니다.",
)


def _limit(spec: tuple[int, float], n: int) -> int:
    return max(spec[0], int(spec[1] * n + 0.999))


def evaluate(m: Metrics) -> dict[str, Any]:
    n = max(m.files, 1)
    t = THRESHOLDS
    indicators: dict[str, dict[str, Any]] = {}

    def put(key: str, state: str, value: str, detail: str, files: list[str] | None = None) -> None:
        indicators[key] = {"name": INDICATOR_NAME[key], "state": state, "label": LABEL[state], "value": value, "detail": detail, "files": (files or [])[:8]}

    ratio = m.files_in_cycles / n
    state = "ok" if m.files_in_cycles == 0 else "bad" if ratio > t["cycles"]["bad_ratio"] or m.largest_cycle >= t["cycles"]["bad_size"] else "warn"
    put("cycles", state, f"순환 {len(m.cycles)}묶음, 파일 {m.files_in_cycles}개({ratio:.0%}), 가장 큰 묶음 {m.largest_cycle}개", "서로를 불러 쓰는 모듈 묶음입니다. 한쪽을 고치면 다른 쪽이 깨집니다.", m.cycles[0] if m.cycles else [])

    g = t["god_module"]
    warn_in, bad_in, warn_out = _limit(g["warn_fan_in"], n), _limit(g["bad_fan_in"], n), _limit(g["warn_fan_out"], n)
    # 많이 불리기만 하는 모듈(자료형·상수)은 안정적이라 문제가 아니다. 많이 불리면서 동시에 많이 부르는 중심 모듈(허브)을 본다.
    bad_hubs = [h for h in m.hubs if h.fan_in >= bad_in and h.fan_out >= g["hub_min_out_bad"]]
    warn_hubs = [h for h in m.hubs if h.fan_in >= warn_in and h.fan_out >= g["hub_min_out_warn"]]
    out_n = m.top_fan_out[0].fan_out if m.top_fan_out else 0
    state = "bad" if bad_hubs else "warn" if warn_hubs or out_n >= warn_out else "ok"
    hub = (bad_hubs or warn_hubs or m.hubs[:1])
    value = f"중심 모듈 {hub[0].path}: {hub[0].fan_in}곳에서 불리고 {hub[0].fan_out}곳을 호출" if hub else "중심 모듈 없음"
    if out_n >= warn_out and not (bad_hubs or warn_hubs):
        value = f"가장 많이 부르는 모듈 {m.top_fan_out[0].path}: {out_n}곳을 호출"
    put("god_module", state, value, "한 모듈이 너무 많은 곳과 얽혀 있으면 그 모듈을 고칠 때 전체가 흔들립니다.", [h.path for h in (bad_hubs or warn_hubs or m.hubs[:1])] or [s.path for s in m.top_fan_out[:1]])

    lf = len(m.large_functions) / max(m.functions, 1)
    state = "ok" if lf <= t["large_functions"]["warn_ratio"] else "bad" if lf > t["large_functions"]["bad_ratio"] else "warn"
    put("large_functions", state, f"기준을 넘는 함수 {len(m.large_functions)}개(전체 함수의 {lf:.0%})", "함수가 길면 읽기도 시험하기도 어렵습니다.", m.large_functions)
    lg = len(m.large_files) / n
    state = "ok" if lg <= t["large_files"]["warn_ratio"] else "bad" if lg > t["large_files"]["bad_ratio"] else "warn"
    put("large_files", state, f"기준을 넘는 파일 {len(m.large_files)}개(전체 파일의 {lg:.0%})", "파일 하나에 일이 몰려 있습니다.", m.large_files)

    lv = len(m.layering_files) / n
    state = "ok" if m.layering_violations == 0 else "bad" if lv > t["layering"]["bad_ratio"] else "warn"
    put("layering", state, f"계층 경계를 넘는 파일 {len(m.layering_files)}개(위반 {m.layering_violations}건)", "화면·요청 처리 코드가 DB를 직접 건드리는 식으로 역할이 섞였습니다.", m.layering_files)

    dr = m.duplicate_findings / max(m.functions, 1)
    state = "ok" if dr <= t["duplicates"]["warn_ratio"] else "bad" if dr > t["duplicates"]["bad_ratio"] else "warn"
    put("duplicates", state, f"중복 함수 지적 {m.duplicate_findings}건(전체 함수의 {dr:.0%})", "같은 일을 하는 함수가 여러 곳에 있으면 하나를 고쳐도 나머지가 남습니다.", m.duplicate_files)

    tr = m.modules_with_tests / n
    state = "ok" if tr >= t["tests"]["ok_ratio"] else "warn" if tr >= t["tests"]["warn_ratio"] else "bad"
    put("tests", state, f"시험이 있는 모듈 {m.modules_with_tests}개(전체의 {tr:.0%})", "시험이 없으면 구조를 고치다 동작이 바뀌어도 알 수 없습니다.", [])

    bad = [k for k, v in indicators.items() if v["state"] == "bad"]
    warn = [k for k, v in indicators.items() if v["state"] == "warn"]
    if m.files < MIN_FILES:
        band, reason = "판정 불가", f"소스 파일이 {m.files}개로 {MIN_FILES}개 미만이라 구간을 판정하지 않습니다. 지표만 참고하세요."
    elif len(bad) >= 3 or ("cycles" in bad and ({"layering", "god_module"} & set(bad))):
        band, reason = "붕괴", f"'붕괴' 지표 {len(bad)}개: " + ", ".join(INDICATOR_NAME[k] for k in bad)
    elif bad or len(warn) >= 3 or {"cycles", "god_module", "layering"} & set(warn):
        band, reason = "주의", "붕괴 지표: " + (", ".join(INDICATOR_NAME[k] for k in bad) or "없음") + f" / 주의 지표 {len(warn)}개(" + ", ".join(INDICATOR_NAME[k] for k in warn) + ")"
    else:
        band, reason = "양호", "붕괴·다수 주의 지표가 없습니다."
    steps = _steps(m, indicators, bad_states=set(bad))
    return {
        "schema": SCHEMA,
        "root": m.root,
        "band": band,
        "reason": reason,
        "size": {"files": m.files, "functions": m.functions, "lines": m.lines, "languages": m.languages},
        "thresholds": THRESHOLDS,
        "indicators": indicators,
        "steps": steps,
        "dont": list(DONT),
        "notes": m.notes[:10],
        "limits": "지표는 구조의 한 단면입니다. 설계가 좋은지 나쁜지, 유지보수 비용이 얼마인지는 알려 주지 않습니다. 시험 유무는 파일 이름과 가져오기로 추정한 값입니다.",
    }


def _steps(m: Metrics, ind: dict[str, dict[str, Any]], bad_states: set[str]) -> list[dict[str, Any]]:
    """먼저 풀 문제를 순서대로. 시험이 없고 순환이 크면 시험을 쓸 수 없으니 순환 안의 연결 하나를 끊는 것을 먼저 둔다."""
    problems = [k for k in ("tests", "cycles", "god_module", "layering", "duplicates", "large_functions", "large_files") if ind[k]["state"] != "ok"]
    if "cycles" in problems and ind["tests"]["state"] == "bad" and ind["cycles"]["state"] == "bad":
        problems.remove("cycles")
        problems.insert(0, "cycles_first")
    steps: list[dict[str, Any]] = []
    for key in problems:
        steps.append(_step(key, m, ind))
    return steps[:5]


def _step(key: str, m: Metrics, ind: dict[str, dict[str, Any]]) -> dict[str, Any]:
    first_cycle = m.cycles[0] if m.cycles else []
    table = {
        "tests": ("가장 중요한 모듈에 시험부터 쓰세요", [s.path for s in m.top_fan_in[:3]], "지금 동작을 그대로 확인하는 시험(입력과 결과를 적어 두는 시험)을 3개 쓰세요. 코드는 건드리지 마세요."),
        "cycles_first": ("순환 안의 연결 하나를 끊으세요", first_cycle, "순환 묶음에서 가장 적게 불리는 모듈이 다른 모듈을 부르는 곳 하나를 골라, 부르는 쪽이 인터페이스(약속)만 알도록 바꾸세요. 한 곳만 바꾸고 멈추세요."),
        "cycles": ("순환 의존을 끊으세요", first_cycle, "순환 묶음에서 두 모듈이 함께 쓰는 부분을 제3의 모듈로 빼내세요. 한 묶음씩, 한 번에 연결 하나만 바꾸세요."),
        "god_module": ("중심 모듈의 역할을 하나씩 떼어 내세요", ind["god_module"]["files"], "중심 모듈이 하는 일 중 서로 관계없는 하나를 골라 새 모듈로 옮기세요. 부르는 쪽의 import만 바꾸고 한 번에 한 역할만 옮기세요."),
        "layering": ("계층 경계를 세우세요", m.layering_files, "요청 처리 코드에 든 DB 호출을 서비스·저장소 함수로 옮기세요. 파일 하나씩 옮기고 시험을 돌려 확인하세요."),
        "duplicates": ("중복 함수를 하나로 모으세요", m.duplicate_files, "같은 일을 하는 함수 둘 중 하나를 골라 공용 모듈로 옮기고, 다른 쪽의 호출을 그쪽으로 바꾸세요. 한 쌍씩 하세요."),
        "large_functions": ("가장 긴 함수를 나누세요", m.large_functions, "가장 긴 함수 하나를 골라 이름 붙일 수 있는 덩어리로 나누세요. 나누기 전에 그 함수를 부르는 시험을 하나 쓰세요."),
        "large_files": ("가장 큰 파일을 역할별로 나누세요", m.large_files, "가장 큰 파일 하나를 골라 역할별 파일 둘로 나누세요. import 경로만 바꾸고 동작은 바꾸지 마세요."),
    }
    title, files, how = table[key]
    state_key = "cycles" if key == "cycles_first" else key
    return {
        "key": key,
        "title": title,
        "why": ind[state_key]["detail"],
        "files": files[:6],
        "how": how,
        "keep_behavior": "동작을 바꾸지 않아야 합니다. 시험이 그대로 통과하면 됩니다.",
        "verify": "끝나면 `iron-laws architecture --compare 이전.json`으로 이 지표가 나아졌는지 확인하세요.",
    }


def compare(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    lines = [f"구간: {before['band']} → {after['band']}"]
    for key, now in after["indicators"].items():
        was = before["indicators"].get(key)
        if was is None:
            continue
        mark = "개선" if _rank(now["state"]) < _rank(was["state"]) else "악화" if _rank(now["state"]) > _rank(was["state"]) else "변화 없음"
        lines.append(f"- {now['name']}: {was['label']} → {now['label']} ({mark}) | {was['value']} → {now['value']}")
    return lines


def _rank(state: str) -> int:
    return {"ok": 0, "warn": 1, "bad": 2}[state]


def markdown(d: dict[str, Any]) -> str:
    out = ["# 프로젝트 구조 진단", "", f"**구간: {d['band']}** - {d['reason']}", ""]
    size = d["size"]
    out.append(f"소스 파일 {size['files']}개, 함수 {size['functions']}개, 코드 {size['lines']}줄 ({', '.join(f'{k} {v}' for k, v in size['languages'].items())}).")
    out += ["", "| 지표 | 상태 | 값 |", "|---|---|---|"]
    for v in d["indicators"].values():
        out.append(f"| {v['name']} | {v['label']} | {v['value']} |")
    if d["steps"]:
        out += ["", "## 먼저 풀 문제 (위에서부터 하나씩)", ""]
        for i, step in enumerate(d["steps"], start=1):
            out += [f"{i}. **{step['title']}**", f"   - 왜: {step['why']}", f"   - 어디: {', '.join(step['files']) if step['files'] else '프로젝트 전체'}", f"   - 어떻게: {step['how']}", f"   - 조건: {step['keep_behavior']}", f"   - 확인: {step['verify']}"]
    else:
        out += ["", "개선이 필요한 지표가 없습니다."]
    out += ["", "## 하지 말 것", ""] + [f"- {x}" for x in d["dont"]]
    out += ["", f"> {d['limits']}"]
    return "\n".join(out)


def prompt(d: dict[str, Any]) -> str:
    if not d["steps"]:
        return "구조 개선이 필요한 지표가 없습니다."
    step = d["steps"][0]
    return (
        "다음 구조 개선 단계 하나만 수행해 주세요. 다른 개선은 하지 마세요.\n\n"
        f"- 할 일: {step['title']}\n- 왜: {step['why']}\n- 대상: {', '.join(step['files']) if step['files'] else '프로젝트 전체'}\n- 방법: {step['how']}\n\n"
        "규칙: 1) 동작을 바꾸지 마세요(기존 시험이 그대로 통과해야 합니다). 2) 이 단계 하나에 PR 하나만 만드세요. 3) 범위를 넘는 파일은 건드리지 마세요. "
        "4) 끝나면 `iron-laws architecture --compare 이전.json`으로 지표를 확인하세요."
    )
