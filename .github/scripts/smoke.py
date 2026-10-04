"""
설치한 wheel이 운영체제·파이썬 버전과 무관하게 동작하는지 확인하는 smoke test
소스 트리가 아니라 설치된 패키지를 `python -m iron_laws.cli`로 실행한다.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# iron-laws: ignore[IL-101] 마스킹 동작을 확인하려는 명백한 무효 합성값이다
SECRET_LINE = 'password = "ActualHardcodedPassword123!"\n'


for _stream in (sys.stdout, sys.stderr):
    _stream.reconfigure(encoding="utf-8", errors="replace")  # 이 스크립트의 한글 출력이 cp1252에서 죽지 않게 한다


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "iron_laws.cli", *args], capture_output=True, text=True, encoding="utf-8")


def expect(condition: bool, message: str) -> None:
    if not condition:
        print(f"실패: {message}")
        sys.exit(1)
    print(f"통과: {message}")


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    sample = root / "한글 폴더" / "hash#name.py"
    sample.parent.mkdir()
    sample.write_text(SECRET_LINE, encoding="utf-8")

    expect(run("--help").returncode == 0, "--help")
    expect(run("coverage").returncode == 0, "coverage")
    expect(run("support", "IL-501").returncode == 0, "support IL-501")

    checked = run("check", str(root))
    expect(checked.returncode == 1, "비밀값이 있으면 check 종료코드 1")

    sarif = run("audit", str(root), "--format", "sarif")
    data = json.loads(sarif.stdout)
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    expect("hash%23name.py" in uri, f"SARIF 경로 인코딩 ({uri})")
    expect("ActualHardcodedPassword123" not in sarif.stdout, "SARIF에 비밀 원문이 없음")

    prompt = run("fix-prompt", str(root))
    expect("ActualHardcodedPassword123" not in prompt.stdout, "수정 지시문에 비밀 원문이 없음")

    empty = root / "empty"
    empty.mkdir()
    expect(run("check", str(empty)).returncode == 2, "빈 폴더는 종료코드 2")
    expect(run("check", str(root / "없는 경로")).returncode == 2, "없는 경로는 종료코드 2")

    (root / "ok").mkdir()
    (root / "ok" / "a.py").write_text("x = 1\n", encoding="utf-8")
    expect(run("check", str(root / "ok")).returncode == 0, "문제 없는 코드는 종료코드 0")

print("smoke test 완료")
