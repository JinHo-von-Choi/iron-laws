"""
오철칙 스냅샷: 원본과 후보 작업영역의 내용 해시를 고정하고 안전하게 복사한다
- dirty working tree도 실제 파일 내용으로 고정한다. (git 상태가 아니라 파일을 읽는다)
- 작업영역 밖을 가리키는 symlink, 특수 파일, 너무 큰 파일은 복사하지 않고 위험으로 기록한다.
- 해시는 무결성 근거일 뿐 코드의 안전성이나 작성자 진위를 증명하지 않는다.
작성자: 최진호
작성일: 2026-10-04
"""

import hashlib
import os
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path

# 스냅샷에서 제외하는 폴더. 저장소 내부 상태와 의존성·캐시는 검증 입력이 아니다.
SNAPSHOT_EXCLUDE_DIRS = frozenset({".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv", "venv", ".tox"})
MAX_FILE_BYTES = 5_000_000
MAX_TOTAL_BYTES = 200_000_000
MAX_FILES = 20_000


@dataclass
class Snapshot:
    root: Path
    files: dict[str, str] = field(default_factory=dict)  # 상대 경로 → 내용 해시
    risks: list[str] = field(default_factory=list)  # 복사하지 못한 위험 항목(밖을 가리키는 symlink 등)
    total_bytes: int = 0

    @property
    def digest(self) -> str:
        h = hashlib.sha256()
        for rel in sorted(self.files):
            h.update(rel.encode("utf-8", errors="surrogateescape"))
            h.update(b"\0")
            h.update(self.files[rel].encode())
            h.update(b"\n")
        return h.hexdigest()


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_tree(root: Path) -> Snapshot:
    """root의 파일 목록과 내용 해시를 만든다. 복사는 하지 않는다."""
    snap = Snapshot(root=root)
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SNAPSHOT_EXCLUDE_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as e:
                snap.risks.append(f"{rel}: 읽을 수 없다 ({e.strerror or e})")
                continue
            if stat.S_ISLNK(mode):
                target = os.path.realpath(path)
                if not (target == str(root) or target.startswith(str(root) + os.sep)):
                    snap.risks.append(f"{rel}: 작업영역 밖을 가리키는 symlink")
                else:
                    snap.files[rel] = "symlink:" + os.readlink(path)
                continue
            if not stat.S_ISREG(mode):
                snap.risks.append(f"{rel}: 일반 파일이 아닌 특수 파일")
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                snap.risks.append(f"{rel}: 파일이 너무 크다({path.stat().st_size} bytes)")
                continue
            snap.total_bytes += path.stat().st_size
            if len(snap.files) >= MAX_FILES or snap.total_bytes > MAX_TOTAL_BYTES:
                snap.risks.append("작업영역이 너무 커서 일부를 스냅샷에 담지 못했다")
                return snap
            try:
                snap.files[rel] = _hash_file(path)
            except OSError as e:
                snap.risks.append(f"{rel}: 읽을 수 없다 ({e.strerror or e})")
    return snap


def materialize(snapshot: Snapshot, destination: Path, read_only: bool = False) -> Path:
    """스냅샷의 파일을 destination으로 복사한다. 위험 항목은 복사하지 않는다."""
    destination.mkdir(parents=True, exist_ok=True)
    for rel, digest in snapshot.files.items():
        source = snapshot.root / rel
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if digest.startswith("symlink:"):
            os.symlink(digest[len("symlink:") :], target)
            continue
        shutil.copyfile(source, target)
        shutil.copymode(source, target)
    if read_only:
        for path in sorted(destination.rglob("*"), reverse=True):
            if path.is_symlink():
                continue
            path.chmod(path.stat().st_mode & ~0o222)
    return destination


def make_writable(path: Path) -> None:
    """읽기 전용으로 만든 작업영역을 지울 수 있게 되돌린다."""
    for p in [path, *path.rglob("*")]:
        if p.is_symlink():
            continue
        try:
            p.chmod(p.stat().st_mode | 0o200 | (0o100 if p.is_dir() else 0))
        except OSError:
            continue
