"""
실측 누락 순환: 고정 커밋의 실제 프로젝트를 점검해 이전 기록과 달라진 보안 지적을 사람이 분류할 대기열로 만든다

사용법:
    uv run python benchmarks/realworld_loop.py <작업 폴더> [--fetch] [--update]

- 프로젝트 목록: benchmarks/realworld/projects.json(이름, 주소, 커밋). 커밋이 고정되어 있으므로 차이는 오철칙의 변화다.
- 기록: benchmarks/realworld/<이름>.json(보안 규칙 지적의 규칙·경로·줄·심각도·확정 여부). --update를 주면 이번 결과로 바꾼다.
- 대기열: <작업 폴더>/triage.md. 새로 생긴 지적과 사라진 지적을 프로젝트별로 적는다. 사람이 TP/FP와 사유를 분류하고,
  오탐·미탐으로 확인된 것은 tests/counterexamples/에 반례로 고정한다(docs/COUNTEREXAMPLES.md).
- 달라진 지적이 있으면 종료코드 1(정기 실행이 사람의 분류를 요청하는 신호), 없으면 0.
작성자: 최진호
작성일: 2026-10-12
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SECURITY_PREFIXES = ("IL-1", "IL-5", "AI-1", "AIA-")


def checkout(work: Path, project: dict, fetch: bool) -> Path | None:
    target = work / project["name"]
    if (target / ".git").is_dir():
        head = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        return target if head == project["commit"] else None
    if not fetch:
        return None
    target.mkdir(parents=True, exist_ok=True)
    for args in (["init", "-q"], ["remote", "add", "origin", project["url"]], ["fetch", "-q", "--depth", "1", "origin", project["commit"]], ["checkout", "-q", "FETCH_HEAD"]):
        if subprocess.run(["git", "-C", str(target), *args], capture_output=True).returncode != 0:
            return None
    return target


def findings(root: Path) -> list[list]:
    from iron_laws.core.scanner import AuditScanner

    report = AuditScanner(root).scan()
    return sorted(
        [v.rule_id, v.file_path.as_posix(), v.line_number, v.severity.value, v.confidence.value]
        for v in report.violations if v.rule_id.startswith(SECURITY_PREFIXES)
    )


def main(work: Path, fetch: bool, update: bool) -> int:
    from iron_laws.core.scanner import tool_version

    projects = json.loads((ROOT / "realworld" / "projects.json").read_text(encoding="utf-8"))
    lines = [f"# 실측 누락 순환 대기열 (오철칙 {tool_version()})", ""]
    changed = False
    for project in projects:
        root = checkout(work, project, fetch)
        if root is None:
            lines += [f"## {project['name']}", "- 받지 못했거나 커밋이 다르다(점검하지 않음).", ""]
            continue
        current = findings(root)
        record_path = ROOT / "realworld" / f"{project['name']}.json"
        previous = json.loads(record_path.read_text(encoding="utf-8"))["findings"] if record_path.is_file() else None
        lines.append(f"## {project['name']} ({project['commit'][:12]})")
        if previous is None:
            lines.append(f"- 첫 기록: 보안 지적 {len(current)}건")
        else:
            new = [f for f in current if f not in previous]
            gone = [f for f in previous if f not in current]
            changed |= bool(new or gone)
            lines += [f"- 새 지적 {len(new)}건, 사라진 지적 {len(gone)}건"]
            lines += [f"  - [ ] 새로 생김 {f[0]} {f[1]}:{f[2]} {f[3]}·{f[4]} — 분류: TP/FP, 사유:" for f in new[:50]]
            lines += [f"  - [ ] 사라짐 {f[0]} {f[1]}:{f[2]} {f[3]}·{f[4]} — 분류: 오탐 제거/미탐 발생, 사유:" for f in gone[:50]]
        lines.append("")
        if update or previous is None:
            record_path.write_text(json.dumps({"tool_version": tool_version(), "commit": project["commit"], "findings": current}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    work.mkdir(parents=True, exist_ok=True)
    (work / "triage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 1 if changed else 0


if __name__ == "__main__":
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not positional:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(Path(positional[0]), "--fetch" in sys.argv, "--update" in sys.argv))
