# 구조 틀 측정(benchmarks/blueprint_ab.py)의 기능 시험용 이미지. 생성된 코드는 네트워크 없이 이 이미지에서 돈다.
FROM python:3.13-slim
RUN pip install --no-cache-dir "fastapi==0.118.0" "sqlalchemy==2.0.43" "httpx==0.28.1" "pytest==8.4.2" "pydantic==2.11.9"
