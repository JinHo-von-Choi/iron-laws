"""
오철칙 Configuration Module
작성자: 최진호
작성일: 2026-10-04
"""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from iron_laws.core.models import Severity

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

DEFAULT_EXTENSIONS = [
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".java",
    ".cs",
    ".go",
    ".rs",
    ".php",
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".cxx",
    ".hpp",
    ".hh",
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

    max_function_lines: int = 80
    max_file_lines: int = 600
    max_parameters: int = 7
    max_nesting: int = 5
    duplicate_min_nodes: int = 40
    duplicate_similarity: float = 0.9
    max_file_bytes: int = 1_000_000


class Policies(BaseModel):
    """발주사·기관이 정한 최소 버전 등 프로젝트별 정책"""

    model_config = ConfigDict(extra="forbid")

    min_versions: dict[str, str] = Field(
        default_factory=dict,
        description="이름별 최소 버전. 예: {spring-boot: '4.0.8', java: '21', node: '22'}",
    )


class ConfigError(Exception):
    """설정 파일을 읽거나 검증할 수 없을 때 발생"""


class IronLawsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on: Severity = Field(
        default=Severity.HIGH, description="CI 실패 기준 심각도 (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    excludes: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    include_extensions: list[str] = Field(default_factory=lambda: list(DEFAULT_EXTENSIONS))
    limits: Limits = Field(default_factory=Limits)
    policies: Policies = Field(default_factory=Policies)
    enabled_rules: list[str] | None = None
    disabled_rules: list[str] = Field(default_factory=list)


def load_config(root_path: Path) -> IronLawsConfig:
    base = root_path if root_path.is_dir() else root_path.parent
    config_file = base / ".iron-laws.yml"
    if not config_file.exists():
        config_file = base / ".iron-laws.yaml"
    if not config_file.exists():
        return IronLawsConfig()

    try:
        data = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError) as e:
        raise ConfigError(f"설정 파일을 읽을 수 없습니다: {config_file} ({e})") from e

    if not isinstance(data, dict):
        raise ConfigError(f"설정 파일의 최상위 구조는 매핑이어야 합니다: {config_file}")

    try:
        return IronLawsConfig(**data)
    except ValidationError as e:
        raise ConfigError(f"설정 파일 검증 실패: {config_file}\n{e}") from e
