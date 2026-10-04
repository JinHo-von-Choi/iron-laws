"""
오철칙 Configuration Module
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.models import Severity
from iron_laws.engine.languages import EXTENSION_TO_LANG

DEFAULT_EXCLUDES = [
    ".git",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    ".next*",
    ".nuxt*",
    ".svelte-kit*",
    ".vercel",
    ".output",
    ".expo",
    ".dart_tool",
    ".angular",
    ".turbo",
    ".cache",
    ".parcel-cache",
    ".gradle",
    ".idea",
    ".vscode",
    "out",
    "coverage",
    "vendor",
    "third_party",
    "storybook-static",
    "generated",
    "__generated__",
    "generated-assets",
    "*-build",
    "*-dist",
    "*.min.js",
    "*.min.css",
    "*.bundle.js",
    "*.map",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "*.lock",
]

CONFIG_AND_TEMPLATE_EXTENSIONS = [
    ".sql",
    ".sh",
    ".xml",
    ".yml",
    ".yaml",
    ".json",
    ".properties",
    ".toml",
    ".rules",
    ".html",
    ".htm",
    ".jinja",
    ".j2",
    ".cshtml",
    ".gradle",
    ".md",
]
# 언어 정의에 있는 확장자는 모두 기본 점검 대상이다. 두 목록이 어긋나 파일이 조용히 빠지는 일을 막는다.
DEFAULT_EXTENSIONS = [*EXTENSION_TO_LANG, *CONFIG_AND_TEMPLATE_EXTENSIONS]

SPECIAL_FILE_PATTERNS = [
    "Dockerfile",
    "Dockerfile.*",
    "*.dockerfile",
    ".env",
    ".env.*",
    "*.env",
    "requirements*.txt",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".java-version",
    ".tool-versions",
]


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_function_lines: int = Field(default=80, gt=0)
    max_file_lines: int = Field(default=600, gt=0)
    max_parameters: int = Field(default=7, gt=0)
    max_nesting: int = Field(default=5, gt=0)
    duplicate_min_nodes: int = Field(default=40, gt=0)
    duplicate_similarity: float = Field(default=0.9, gt=0, le=1)
    max_file_bytes: int = Field(default=1_000_000, gt=0)
    max_cross_file_lookups: int = Field(default=20000, ge=0)


class Policies(BaseModel):
    """발주사·기관이 정한 최소 버전 등 프로젝트별 정책"""

    model_config = ConfigDict(extra="forbid")

    min_versions: dict[str, str] = Field(
        default_factory=dict,
        description="이름별 최소 버전. 예: {spring-boot: '4.0.8', java: '21', node: '22'}",
    )


class ConfigError(Exception):
    """설정 파일을 읽거나 검증할 수 없을 때 발생"""


class InputPathError(ConfigError):
    """점검 대상 경로가 없을 때 발생"""


class IronLawsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: Severity = Field(
        default=Severity.HIGH, description="CI 실패 기준 심각도 (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    excludes: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    include_extensions: list[str] = Field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    limits: Limits = Field(default_factory=Limits)
    policies: Policies = Field(default_factory=Policies)
    respect_gitignore: bool = Field(default=False, description="true면 .gitignore에 걸리는 파일과 폴더를 점검하지 않는다 (기본은 점검)")
    enabled_rules: list[str] | None = None
    disabled_rules: list[str] = Field(default_factory=list)


CONFIG_NAMES = (".iron-laws.yml", ".iron-laws.yaml")


def find_config_file(root_path: Path, explicit: Path | None = None, search_parents: bool = False) -> Path | None:
    """설정 파일 위치를 정한다. 우선순위: --config > 점검 폴더 > (선택) 상위 폴더 탐색"""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"설정 파일이 없습니다: {explicit}")
        return explicit
    base = (root_path if root_path.is_dir() else root_path.parent).resolve()
    folders = [base, *base.parents] if search_parents else [base]
    for folder in folders:
        for name in CONFIG_NAMES:
            candidate = folder / name
            if candidate.exists():
                return candidate
    return None


def load_config(
    root_path: Path, config_path: Path | None = None, search_parents: bool = False
) -> tuple[IronLawsConfig, str]:
    """(설정, 출처)를 돌려준다. 출처는 '기본값' 또는 사용한 설정 파일 경로"""
    config_file = find_config_file(root_path, config_path, search_parents)
    if config_file is None:
        return IronLawsConfig(), "기본값"

    try:
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"설정 파일을 읽을 수 없습니다: {config_file} ({e})") from e

    if data is None:
        data = {}  # 비어 있는 파일은 기본 설정이다. false, 0, 빈 배열 같은 값은 아래에서 오류가 된다
    if not isinstance(data, dict):
        raise ConfigError(f"설정 파일의 최상위 구조는 매핑이어야 합니다: {config_file}")

    try:
        return IronLawsConfig(**data), str(config_file)
    except ValidationError as e:
        raise ConfigError(f"설정 파일 검증 실패: {config_file}\n{e}") from e
