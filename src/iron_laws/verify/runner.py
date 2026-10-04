"""
오철칙 격리 실행기: 비신뢰 코드(후보 patch가 적용된 저장소)의 시험을 자격증명 없는 일회용 환경에서만 실행한다
- 격리 환경(docker 또는 bubblewrap)을 얻지 못하면 시험을 실행하지 않고 '검증 불가'로 남긴다. 호스트 실행으로 자동 대체하지 않는다.
- 네트워크는 끊고, host home·SSH agent·cloud 자격증명·Docker socket은 마운트하지 않으며, 비특권 사용자·읽기 전용 루트를 쓴다.
- 신뢰된 명령 목록(argv)만 실행한다. 임의 shell 문자열은 실행하지 않는다.
- 프로세스·CPU·메모리·시간·출력량을 제한하고, 상한에 닿으면 실패가 아니라 '미확인'(limit_reached)으로 기록한다.
- 컨테이너 격리만으로 완전한 격리를 보증하지 않는다. 고위험 비신뢰 코드에는 microVM 같은 추가 경계를 검토해야 한다.
작성자: 최진호
작성일: 2026-10-04
"""

import re
import shutil
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from iron_laws.core.redaction import limit, redact_text

DEFAULT_ALLOWED_COMMANDS = [["python", "-m", "pytest"], ["python", "-m", "unittest"], ["pytest"]]
SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"})
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
EXCERPT_CHARS = 2000


@dataclass
class RunLimits:
    cpus: float = 2.0
    memory_mib: int = 2048
    timeout_s: int = 180
    output_bytes: int = 1_048_576
    attempts: int = 2
    pids: int = 256
    tmpfs_mib: int = 256


@dataclass
class RunResult:
    status: str  # passed / failed / timeout / output_limit / resource_limit / isolation_unavailable / infrastructure_error / not_allowed
    exit_code: int | None = None
    duration_s: float = 0.0
    limit_reached: bool = False
    backend: str = ""
    image: str = ""
    image_id: str = ""
    command: list[str] = field(default_factory=list)
    attempts: int = 0
    excerpt: str = ""
    counts: dict[str, int] = field(default_factory=dict)  # 출력에서 읽은 시험 건수. 비신뢰 출력이므로 판정이 아니라 참고(0건 시험·skip 증가 탐지)에만 쓴다
    notes: list[str] = field(default_factory=list)


def validate_command(argv: list[str], allowed: list[list[str]]) -> str | None:
    """실행해도 되는 명령인지 확인한다. 문제가 있으면 사유를 돌려준다."""
    if not argv:
        return "명령이 비어 있다"
    if any(("\0" in a or "\n" in a) for a in argv):
        return "명령 인자에 NUL이나 줄바꿈이 있다"
    if Path(argv[0]).name.lower() in SHELL_NAMES:
        return "shell을 직접 실행하는 명령은 허용하지 않는다"
    for entry in allowed:
        if argv[: len(entry)] == entry:
            return None
    return f"신뢰된 명령 목록에 없는 명령이다: {' '.join(argv[:3])}"


def parse_test_counts(output: str) -> dict[str, int]:
    """pytest·unittest 요약 줄에서 건수를 읽는다. 시험이 출력한 문자열이므로 판정 근거가 아니다."""
    counts: dict[str, int] = {}
    tail = "\n".join(output.splitlines()[-40:])
    for key in ("passed", "failed", "skipped", "xfailed", "xpassed", "error", "errors", "deselected"):
        m = re.search(rf"(\d+) {key}\b", tail)
        if m:
            counts["error" if key == "errors" else key] = int(m.group(1))
    m = re.search(r"Ran (\d+) tests?", tail)
    if m:
        counts["ran"] = int(m.group(1))
    if re.search(r"no tests ran|collected 0 items", tail):
        counts["no_tests"] = 1
    return counts


def _excerpt(output: str) -> str:
    text = ANSI_RE.sub("", output)
    lines = text.splitlines()[-25:]
    return limit(redact_text("\n".join(lines)), EXCERPT_CHARS)


class Runner(ABC):
    name = "none"

    @abstractmethod
    def available(self) -> tuple[bool, str]: ...

    @abstractmethod
    def build_command(self, workdir: Path, argv: list[str], limits: RunLimits, container_name: str) -> list[str]: ...

    def image_info(self) -> tuple[str, str]:
        return "", ""

    def kill(self, container_name: str) -> None:
        return None

    def run(self, workdir: Path, argv: list[str], limits: RunLimits, allowed: list[list[str]] | None = None) -> RunResult:
        result = RunResult(status="isolation_unavailable", backend=self.name, command=list(argv))
        problem = validate_command(argv, allowed if allowed is not None else DEFAULT_ALLOWED_COMMANDS)
        ok, reason = self.available()  # 이미지 ID는 가용성을 확인하는 과정에서 알게 된다. 그 뒤에 읽는다
        image, image_id = self.image_info()
        result.image, result.image_id = image, image_id
        if problem:
            result.status = "not_allowed"
            result.notes.append(problem)
            return result
        if not ok:
            result.notes.append(reason)  # 격리를 얻지 못하면 시험 실패가 아니라 검증 불가다. 호스트에서 대신 실행하지 않는다
            return result
        last: RunResult = result
        for attempt in range(1, max(1, limits.attempts) + 1):
            last = self._run_once(workdir, argv, limits, image, image_id)
            last.attempts = attempt
            if last.status not in ("infrastructure_error",):
                break  # 시험이 통과·실패·시간초과한 것은 재시도하지 않는다. 실행기 자체의 오류만 재시도한다
        return last

    def _run_once(self, workdir: Path, argv: list[str], limits: RunLimits, image: str, image_id: str) -> RunResult:
        name = f"iron-laws-{uuid.uuid4().hex[:12]}"
        command = self.build_command(workdir, argv, limits, name)
        result = RunResult(status="infrastructure_error", backend=self.name, image=image, image_id=image_id, command=list(argv))
        started = time.monotonic()
        buffer = bytearray()
        over = threading.Event()
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)  # noqa: S603
        except OSError as e:
            result.notes.append(f"실행기를 시작하지 못했다: {e}")
            return result

        def pump() -> None:
            """출력을 상한까지만 보관한다. 상한을 넘은 뒤에도 끝까지 읽어서 버린다. 읽지 않으면 컨테이너 쪽 출력이 막혀 `docker kill`도 멈춘다."""
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    return
                room = limits.output_bytes - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
                if len(chunk) > room:
                    over.set()

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        deadline = started + limits.timeout_s
        timed_out = False
        while True:
            try:
                proc.wait(timeout=0.01)
                break
            except subprocess.TimeoutExpired:
                pass
            if over.is_set():
                break
            if time.monotonic() > deadline:
                timed_out = True
                break
        if timed_out or over.is_set():
            self.kill(name)
            proc.kill()
        proc.wait()
        reader.join(timeout=5)
        result.duration_s = round(time.monotonic() - started, 2)
        output = bytes(buffer).decode("utf-8", errors="replace")
        result.excerpt = _excerpt(output)
        result.counts = parse_test_counts(output)
        result.exit_code = proc.returncode
        if timed_out:
            result.status, result.limit_reached = "timeout", True
            result.notes.append(f"시간 상한 {limits.timeout_s}초에 도달했다")
        elif over.is_set():
            result.status, result.limit_reached = "output_limit", True
            result.notes.append(f"출력 상한 {limits.output_bytes} bytes에 도달했다")
        elif proc.returncode in (137, -9):
            result.status, result.limit_reached = "resource_limit", True
            result.notes.append("강제 종료(SIGKILL)되었다. 메모리 상한 등 자원 상한에 도달했을 수 있어 시험 실패로 세지 않는다")
        elif proc.returncode == 0:
            result.status = "passed"
        elif proc.returncode in (125, 126, 127) or self.is_runner_error(proc.returncode, output):
            result.status = "infrastructure_error"
            result.notes.append("실행기 또는 명령 시작 오류로 시험이 실행되지 않았다")
        else:
            result.status = "failed"
        return result

    def is_runner_error(self, exit_code: int | None, output: str) -> bool:
        return False


class DockerRunner(Runner):
    name = "docker"

    def __init__(self, image: str):
        self.image = image
        self._image_id = ""

    def available(self) -> tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "docker가 설치되어 있지 않다"
        try:
            info = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=20)  # noqa: S603, S607
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"docker를 실행하지 못했다: {e}"
        if info.returncode != 0:
            return False, "docker 데몬에 연결하지 못했다"
        try:
            inspect = subprocess.run(  # noqa: S603
                ["docker", "image", "inspect", "--format", "{{.Id}}", self.image], capture_output=True, text=True, timeout=20  # noqa: S607
            )
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"docker 이미지를 확인하지 못했다: {e}"
        if inspect.returncode != 0:
            return False, f"이미지 {self.image}가 로컬에 없다. 시험 중에는 네트워크를 쓰지 않으므로 준비 단계에서 미리 받아 두어야 한다"
        self._image_id = inspect.stdout.strip()
        return True, ""

    def image_info(self) -> tuple[str, str]:
        return self.image, self._image_id

    def kill(self, container_name: str) -> None:
        """상한에 닿은 컨테이너를 정리한다. 정리 명령이 늦어져도 검증 전체가 멈추지 않게 오류를 삼키되 기록은 호출부가 남긴다."""
        for command in (["docker", "kill", container_name], ["docker", "rm", "-f", container_name]):
            try:
                subprocess.run(command, capture_output=True, timeout=30, check=False)  # noqa: S603
            except (OSError, subprocess.SubprocessError):
                continue

    def build_command(self, workdir: Path, argv: list[str], limits: RunLimits, container_name: str) -> list[str]:
        return [
            "docker", "run", "--rm", "--name", container_name,
            "--pull", "never",  # 시험 중 이미지를 내려받지 않는다
            "--network", "none",
            "--read-only", "--tmpfs", f"/tmp:rw,nosuid,size={limits.tmpfs_mib}m",
            "--cpus", str(limits.cpus), "--memory", f"{limits.memory_mib}m", "--memory-swap", f"{limits.memory_mib}m",
            "--pids-limit", str(limits.pids),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONHASHSEED=0", "-e", "PYTHONUNBUFFERED=1",
            "-v", f"{workdir.resolve()}:/work:rw", "-w", "/work",
            self.image, *argv,
        ]  # 마운트는 작업영역 하나뿐이다. host home·SSH agent·cloud 자격증명·Docker socket은 없다


class BwrapRunner(Runner):
    name = "bwrap"

    def __init__(self) -> None:
        self._probe: tuple[bool, str] | None = None

    def _base(self, workdir: Path) -> list[str]:
        return [
            "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",  # noqa: S108 - 격리 안의 tmpfs
            "--bind", str(workdir.resolve()), "/work", "--chdir", "/work",
            "--clearenv", "--setenv", "HOME", "/tmp", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",  # noqa: S108
        ]

    def available(self) -> tuple[bool, str]:
        if self._probe is None:
            if shutil.which("bwrap") is None:
                self._probe = (False, "bubblewrap(bwrap)가 설치되어 있지 않다")
            else:
                import tempfile

                with tempfile.TemporaryDirectory() as tmp:
                    try:
                        probe = subprocess.run([*self._base(Path(tmp)), "true"], capture_output=True, text=True, timeout=20)  # noqa: S603
                        ok = probe.returncode == 0
                        self._probe = (ok, "" if ok else f"bubblewrap 격리를 만들지 못했다: {(probe.stderr or '').strip()[:120]}")
                    except (OSError, subprocess.SubprocessError) as e:
                        self._probe = (False, f"bubblewrap을 실행하지 못했다: {e}")
        return self._probe

    def build_command(self, workdir: Path, argv: list[str], limits: RunLimits, container_name: str) -> list[str]:
        return [*self._base(workdir), *argv]


class NoRunner(Runner):
    name = "none"

    def __init__(self, reason: str = "격리 실행기를 쓰지 않도록 지정되었다") -> None:
        self.reason = reason

    def available(self) -> tuple[bool, str]:
        return False, self.reason

    def build_command(self, workdir: Path, argv: list[str], limits: RunLimits, container_name: str) -> list[str]:
        raise RuntimeError("NoRunner는 명령을 만들지 않는다")


def select_runner(preference: str, image: str) -> Runner:
    """auto는 docker, bubblewrap 순으로 격리를 얻을 수 있는 실행기를 고른다. 어느 것도 없으면 NoRunner(호스트 실행 없음)"""
    if preference == "none":
        return NoRunner()
    candidates: list[Runner] = []
    if preference in ("auto", "docker"):
        candidates.append(DockerRunner(image))
    if preference in ("auto", "bwrap"):
        candidates.append(BwrapRunner())
    reasons = []
    for runner in candidates:
        ok, reason = runner.available()
        if ok:
            return runner
        reasons.append(f"{runner.name}: {reason}")
    return NoRunner("격리 환경을 얻지 못했다 — " + "; ".join(reasons))
