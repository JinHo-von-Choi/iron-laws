"""
오철칙 patch 입력 검사와 적용
patch는 비신뢰 입력이다. 적용 전에 경로·종류·크기를 확인하고, 적용은 후보 작업영역 안에서만 한다.
git 훅이나 설치 스크립트는 실행하지 않는다. (git apply는 훅을 실행하지 않고, 저장소 밖 임시 폴더에서만 쓴다)
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

MAX_PATCH_BYTES = 2_000_000
DIFF_HEADER_RE = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(?P<path>.+?)(?:\t.*)?$")
GIT_HEADER_RE = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
# 후보 patch가 건드리면 안 되는 저장소 내부·실행 위험 경로
FORBIDDEN_PARTS = (".git", ".githooks", ".husky")


@dataclass
class PatchInfo:
    digest: str
    size: int
    files: list[str] = field(default_factory=list)  # patch가 건드리는 경로
    created: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    binary: bool = False
    problems: list[str] = field(default_factory=list)  # 안전하지 않은 점. 하나라도 있으면 적용하지 않는다


def _unsafe_path(path: str) -> str | None:
    if path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path):
        return f"절대 경로: {path}"
    parts = Path(path.replace("\\", "/")).parts
    if ".." in parts:
        return f"작업영역 밖으로 나가는 경로: {path}"
    if any(part in FORBIDDEN_PARTS for part in parts):
        return f"저장소 내부·훅 경로: {path}"
    if "\0" in path:
        return "경로에 NUL 문자가 있다"
    return None


def inspect_patch(patch_path: Path) -> PatchInfo:
    raw = patch_path.read_bytes()
    info = PatchInfo(digest=hashlib.sha256(raw).hexdigest(), size=len(raw))
    if len(raw) > MAX_PATCH_BYTES:
        info.problems.append(f"patch가 너무 크다({len(raw)} bytes)")
        return info
    text = raw.decode("utf-8", errors="replace")
    seen: set[str] = set()
    pending_rename: str | None = None
    for line in text.splitlines():
        if line.startswith("GIT binary patch") or line.startswith("Binary files "):
            info.binary = True
            info.problems.append("바이너리 patch는 지원하지 않는다")
        if line.startswith(("new file mode", "old mode", "new mode")) and "120000" in line:
            info.problems.append("symlink를 만드는 patch는 지원하지 않는다")
        if line.startswith("rename from "):
            pending_rename = line[len("rename from ") :]
        elif line.startswith("rename to ") and pending_rename is not None:
            info.renamed.append((pending_rename, line[len("rename to ") :]))
            pending_rename = None
        m = GIT_HEADER_RE.match(line)
        if m:
            for path in (m.group("a"), m.group("b")):
                if path not in seen:
                    seen.add(path)
                    info.files.append(path)
        else:
            m = DIFF_HEADER_RE.match(line)
            if m and m.group("path") != "/dev/null" and not line.startswith("--- a/dev/null"):
                path = m.group("path")
                if path not in seen:
                    seen.add(path)
                    info.files.append(path)
        if line.startswith("--- /dev/null"):
            info.created.append("")  # 다음 +++ 줄에서 경로를 채운다
        if line.startswith("+++ ") and info.created and info.created[-1] == "":
            info.created[-1] = line[4:].removeprefix("b/").split("\t")[0]
        if line.startswith("+++ /dev/null"):
            info.deleted.append("")
    for path in info.files:
        problem = _unsafe_path(path)
        if problem:
            info.problems.append(problem)
    if not info.files:
        info.problems.append("patch에서 변경된 파일을 찾지 못했다(unified diff 형식이 아니다)")
    info.created = [p for p in info.created if p]
    return info


def apply_patch(patch_path: Path, workdir: Path) -> tuple[bool, str]:
    """workdir 안에서 patch를 적용한다. 저장소가 아닌 임시 폴더이므로 git 훅·설정이 끼어들지 않는다."""
    env = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": str(workdir), "PATH": "/usr/bin:/bin:/usr/local/bin"}
    checked = subprocess.run(
        ["git", "apply", "--check", "--whitespace=nowarn", str(patch_path.resolve())],
        cwd=workdir, capture_output=True, text=True, env=env, timeout=60,
    )
    if checked.returncode != 0:
        return False, (checked.stderr or checked.stdout).strip()[:500]
    applied = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", str(patch_path.resolve())],
        cwd=workdir, capture_output=True, text=True, env=env, timeout=60,
    )
    if applied.returncode != 0:
        return False, (applied.stderr or applied.stdout).strip()[:500]
    return True, ""
