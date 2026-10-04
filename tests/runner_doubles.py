"""
오철칙 시험 전용 실행기 대역
- LocalTestRunner는 호스트에서 명령을 실행한다. 제품에는 없는 시험용 클래스이며, 우리가 만든 시험 입력(위험한 호출을 가짜 sink로 기록만 하는 harness 등)을
  실행하는 용도로만 쓴다. 제품의 격리 정책(호스트 실행 금지)을 검증하는 시험은 이 클래스를 쓰지 않는다.
- ScriptedRunner는 미리 정한 결과를 순서대로 돌려준다.
작성자: 최진호
작성일: 2026-10-04
"""

import sys

from iron_laws.verify.runner import Runner, RunResult


class LocalTestRunner(Runner):
    name = "local-test-double"

    def available(self) -> tuple[bool, str]:
        return True, ""

    def build_command(self, workdir, argv, limits, container_name):
        argv = [sys.executable if a == "python" else a for a in argv]
        return ["env", "-C", str(workdir), "PYTHONDONTWRITEBYTECODE=1", *argv]


class ScriptedRunner(Runner):
    name = "scripted"

    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def available(self) -> tuple[bool, str]:
        return True, ""

    def build_command(self, workdir, argv, limits, container_name):
        raise AssertionError("사용하지 않는다")

    def run(self, workdir, argv, limits, allowed=None):
        self.calls.append(workdir)
        return self.results.pop(0)


def passed(**counts) -> RunResult:
    return RunResult(status="passed", exit_code=0, backend="scripted", counts=counts or {"passed": 3})
