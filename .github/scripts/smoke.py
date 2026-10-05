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


def expect(condition: bool, message: str, result: subprocess.CompletedProcess[str] | None = None) -> None:
    if not condition:
        print(f"실패: {message}")
        if result is not None:  # 운영체제별 실패를 로그만으로 진단할 수 있게 출력을 남긴다
            print(f"  종료코드 {result.returncode}\n  stdout: {result.stdout[-800:]}\n  stderr: {result.stderr[-800:]}")
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
    expect(checked.returncode == 1, "비밀값이 있으면 check 종료코드 1", checked)

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

# ---- 패치 검증·승인 기록(격리 실행기 없이 정적 단계만): 어느 운영체제에서도 같은 판정이어야 한다 ----
with tempfile.TemporaryDirectory() as tmp:
    project = Path(tmp) / "proj"
    project.mkdir()
    vulnerable = 'import os\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    os.system("ls " + d)\n'
    (project / "app.py").write_text(vulnerable, encoding="utf-8", newline="\n")
    fixed = 'import os\nimport subprocess\nfrom flask import request\n\ndef run_tool():\n    d = request.args["d"]\n    subprocess.run(["ls", d], check=True)\n'
    patch = Path(tmp) / "fix.diff"
    patch.write_text(
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1,6 +1,7 @@\n import os\n+import subprocess\n from flask import request\n \n def run_tool():\n     d = request.args[\"d\"]\n-    os.system(\"ls \" + d)\n+    subprocess.run([\"ls\", d], check=True)\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt = Path(tmp) / "receipt.json"
    undetermined = run("verify-patch", str(project), "--patch", str(patch), "--finding", "IL-504@app.py:6", "--runner", "none", "-o", str(receipt))
    expect(undetermined.returncode == 2, "격리 실행기가 없으면 시험을 실행하지 않고 판정 불가(종료코드 2)")
    relaxed = run("verify-patch", str(project), "--patch", str(patch), "--finding", "IL-504@app.py:6", "--runner", "none", "--no-require-tests")
    expect(relaxed.returncode == 0, "정적 검사만으로는 --no-require-tests에서 통과(종료코드 0)")
    hidden = Path(tmp) / "hide.diff"
    hidden.write_text(
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -3,4 +3,4 @@\n \n def run_tool():\n     d = request.args[\"d\"]\n-    os.system(\"ls \" + d)\n+    os.system(\"ls \" + d)  # iron-laws: ignore[IL-504] 내부 도구라 괜찮다\n",
        encoding="utf-8",
        newline="\n",
    )
    refused = run("verify-patch", str(project), "--patch", str(hidden), "--finding", "IL-504@app.py:6", "--runner", "none", "--no-require-tests")
    expect(refused.returncode == 1, "경고를 가리는 패치는 수정으로 인정하지 않음(종료코드 1)")
    expect((project / "app.py").read_text(encoding="utf-8") == vulnerable, "원본은 수정되지 않음")
    store = Path(tmp) / "approvals.jsonl"
    added = run("approvals", "add", str(project), "--finding", "IL-504@app.py", "--reason", "관리자 전용 화면", "--store", str(store))
    expect(added.returncode == 0, "승인 기록 추가")
    expect(run("approvals", "status", str(project), "--store", str(store)).returncode == 0, "승인이 유효함")
    expect(run("approvals", "verify", "--store", str(store)).returncode == 0, "승인 기록 해시 연결 이상 없음")
    expect(run("review-bundle", str(project), "--approvals", str(store)).returncode == 0, "변경이 없으면 검토 묶음에 필수 행동이 없음")
    report_file = Path(tmp) / "report.json"
    audit = run("audit", str(project), "--format", "json", "--approvals", str(store), "-o", str(report_file))
    expect(audit.returncode == 0, "승인된 지적은 통과로 계산됨")
    expect(run("evidence", "verify", str(report_file)).returncode == 0, "보고서의 불변식에 모순이 없음")
    broken = json.loads(report_file.read_text(encoding="utf-8"))
    broken["summary"]["total_violations"] += 7
    broken_file = Path(tmp) / "broken.json"
    broken_file.write_text(json.dumps(broken), encoding="utf-8")
    expect(run("evidence", "verify", str(broken_file)).returncode == 1, "손상된 보고서는 독립 검증기가 거부함")
    broken["schema_version"] = "0.9"
    broken_file.write_text(json.dumps(broken), encoding="utf-8")
    expect(run("evidence", "verify", str(broken_file)).returncode == 2, "지원하지 않는 버전은 통과가 아니라 판정 불가")
    (project / "app.py").write_text(vulnerable + "\ndef api():\n    return run_tool()\n", encoding="utf-8", newline="\n")
    expect(run("approvals", "status", str(project), "--store", str(store)).returncode == 1, "새 호출자가 생기면 승인을 다시 검토")
    expect(run("review-bundle", str(project), "--approvals", str(store)).returncode == 1, "승인 전제가 바뀌면 검토 묶음이 필수 행동을 낸다")

# ---- 파일럿 기록과 계측: 경로·코드를 담지 않는 로컬 파일 ----
with tempfile.TemporaryDirectory() as tmp:
    pilot = Path(tmp) / "pilot.jsonl"
    arm = run("pilot", "assign", "pr-1", "--team", "a", "--store", str(pilot))
    expect(arm.returncode == 0 and arm.stdout.strip() in ("baseline", "bundle"), "파일럿 조건 배정")
    expect(run("pilot", "assign", "pr-1", "--team", "a", "--store", str(pilot)).returncode == 2, "같은 PR은 두 번 배정하지 않음")
    expect(run("pilot", "summary", "--store", str(pilot)).returncode == 0, "표본이 부족하면 판정하지 않고 종료코드 0")
    metrics = Path(tmp) / "metrics.jsonl"
    sample_dir = Path(tmp) / "secret_named_dir"
    sample_dir.mkdir()
    (sample_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
    expect(run("check", str(sample_dir), "--metrics", str(metrics)).returncode == 0, "계측과 함께 check")
    expect("secret_named_dir" not in metrics.read_text(encoding="utf-8"), "계측 기록에 경로가 없음")

print("smoke test 완료")
