"""ai_code 계열의 공유 AST·판정 기반."""
import json

from iron_laws.core.models import RuleLayer
from iron_laws.engine.routes import (
    AUTH_MARKER as AUTH_MARKER,
)
from iron_laws.engine.routes import (
    PUBLIC_PATH as PUBLIC_PATH,
)
from iron_laws.engine.routes import (
    ROUTE_DECORATOR as ROUTE_DECORATOR,
)
from iron_laws.engine.routes import (
    SENSITIVE_PATH as SENSITIVE_PATH,
)
from iron_laws.rules.base import BaseRule

CODE_KINDS = {"code"}


MAX_PER_FILE = 25


class AiRule(BaseRule):
    layer = RuleLayer.AI_CODE
    gov_standard = None


def _levenshtein(a: str, b: str) -> int:
    """전위(인접 글자 교환)를 1회로 세는 편집 거리"""
    if abs(len(a) - len(b)) > 2:
        return 3
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


POPULAR_PY = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "pytest", "boto3", "scipy", "matplotlib", "pillow", "openai", "anthropic", "langchain",
    "beautifulsoup4", "lxml", "aiohttp", "httpx", "uvicorn", "gunicorn", "celery", "redis", "psycopg2", "pymysql", "cryptography", "pyjwt", "bcrypt", "passlib", "python-dotenv",
    "pyyaml", "jinja2", "click", "typer", "rich", "tqdm", "scikit-learn", "tensorflow", "torch", "transformers", "streamlit", "selenium", "playwright", "alembic", "websockets",
    "python-dateutil", "pytz", "setuptools", "wheel", "urllib3", "certifi", "colorama", "attrs", "six", "markdown", "docker", "paramiko", "pexpect", "tornado", "starlette", "sentry-sdk",
}


POPULAR_NPM = {
    "react", "react-dom", "next", "express", "lodash", "axios", "typescript", "vue", "angular", "svelte", "webpack", "vite", "eslint", "prettier", "jest", "mocha", "chai", "moment",
    "dayjs", "uuid", "dotenv", "cors", "body-parser", "mongoose", "sequelize", "prisma", "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "socket.io", "ws", "chalk", "commander",
    "yargs", "inquirer", "nodemon", "ts-node", "tailwindcss", "postcss", "autoprefixer", "redux", "zustand", "swr", "tanstack", "react-router-dom", "styled-components", "classnames",
    "cheerio", "puppeteer", "playwright", "firebase", "supabase", "openai", "anthropic", "zod", "joi", "yup", "helmet", "morgan", "multer", "nodemailer", "stripe", "node-fetch", "cross-env",
}


def _load_json_object(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # iron-laws: ignore[IL-301] 해석 실패는 None 반환으로 호출자에게 전달한다
        return None
    return data if isinstance(data, dict) else None
