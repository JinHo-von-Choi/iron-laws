# 기여 안내

오철칙은 AI가 만든 코드의 보안·구조·타입 결함을 점검하는 도구입니다. 결함을 덮지 않는다는 원칙을 이 저장소의 코드에도 똑같이 적용합니다.

## 개발 환경

패키지 관리는 [uv](https://github.com/astral-sh/uv)를 씁니다.

```bash
git clone https://github.com/JinHo-von-Choi/iron-laws.git
cd iron-laws

uv sync --all-extras --dev   # 가상환경과 의존성 설치
uv run pytest -q             # 시험
uv run ruff check .          # 린트
uv run iron-laws check .     # 오철칙으로 이 저장소 점검
```

## 기여 절차

1. 이슈로 개선점이나 새 규칙을 제안합니다. 오탐·미탐은 "반례 제보" 양식을 씁니다([docs/COUNTEREXAMPLES.md](docs/COUNTEREXAMPLES.md)).
2. 브랜치를 만듭니다(`feat/rule-name`, `fix/issue-description`).
3. 코드를 씁니다.
   - 새 규칙에는 양성(잡아야 하는 코드)·음성(잡으면 안 되는 코드) 사례를 `tests/`에 더합니다.
   - 규칙을 더하거나 사례를 바꾸면 지원 행렬을 다시 만듭니다: `uv run python benchmarks/build_support_manifest.py` 실행 뒤 `uv run iron-laws support > docs/SUPPORT_MATRIX.md`.
   - 규칙의 판정 방식을 바꾸면 그 규칙의 `version`을 올립니다. 실측 순환(`benchmarks/realworld_loop.py`)은 고정 커밋 프로젝트의 지적이 달라졌는데 판 번호가 그대로인 규칙을 종료코드 3으로 알립니다.
4. `uv run iron-laws check .`가 통과하는지 확인합니다.
5. 사용자에게 보이는 변경은 `CHANGELOG.md`의 `[Unreleased]`에 적습니다.
6. Pull Request를 올립니다.

## 시험과 측정

```bash
uv run pytest -q                                   # 전체. docker 이미지가 없으면 격리 실행 시험은 건너뜀
uv run python benchmarks/plan_experiments.py       # 패치 검증·회귀시험·승인 기록 표본 측정
uv run python benchmarks/plan_experiments_v13.py   # 보고서 모순 검사·변형 사례집·변형 입력·승인 승계 측정
uv run python benchmarks/plan_experiments_v14.py out.json --baseline <이전 판 소스 폴더>   # 이전 판과 같은 표본으로 비교
```

- 공개 벤치마크(OWASP Benchmark Java·Python, Juliet, CWE-Bench-Java), 다른 도구와의 비교, 수정 지시문 비교의 측정 도구와 재현 명령은 [docs/ACCURACY.md](docs/ACCURACY.md) §3·§6·§7에 있습니다. 측정 수치가 바뀌면 `docs/benchmark_results/`의 기록 파일과 ACCURACY를 함께 고칩니다.
- 격리 실행 시험은 미리 만든 docker 이미지가 있어야 돕니다. 시험 중에는 네트워크를 쓰지 않습니다.
- `tests/runner_doubles.py`의 `LocalTestRunner`는 호스트에서 명령을 실행하는 **시험 전용 대역**입니다. 저장소가 직접 만든 입력(위험한 호출을 기록만 하는 시험 실행기 등)을 돌릴 때만 쓰고, 제품 코드에 넣지 않으며, "호스트에서 실행하지 않는다"는 정책을 검증하는 시험에는 쓰지 않습니다.

## 코드 원칙

- 빈 catch 블록이나 오류를 삼키는 코드는 받지 않습니다.
- 모든 규칙은 쉬운 설명(`plain`)과 고치는 방법(`how_to_fix`)을 갖춥니다. 행안부 항목에 근거하면 `mois_ref`로 번호를 연결하고, 근거가 없으면 `gov_standard = None`으로 두어 자체 규칙임을 드러냅니다.
- 오탐을 줄이는 변경에는 그 오탐을 재현하는 사례(`tests/test_regressions.py`)를 함께 넣습니다.
- 억제 주석에는 사유를 적습니다.
- 커밋 메시지에 Co-Authored-By 줄을 넣지 않습니다.

## 사례집 규칙

- 사례는 정상·위험 짝으로 더합니다(`tests/repair_cases.py`, `tests/semantic_corpus.py`).
- 개발용 사례(`semantic_corpus.py`)는 엔진을 고칠 때 봐도 됩니다. 평가용 사례(`semantic_holdout.py`)는 엔진을 맞추려고 보지 않습니다.
- 평가용 사례가 실패해 엔진을 고쳤다면 그 사례를 개발용으로 옮기고 `MOVED_TO_DEV`에 적은 뒤, 같은 유형의 새 평가용 사례를 만듭니다.
- 개발용과 평가용은 (유형, 스타일)이 겹치면 안 됩니다. 옮긴 사례의 유형만 예외이며 시험이 이를 확인합니다.
- 정답은 사람이 정합니다. LLM의 자기 평가는 정답으로 쓰지 않습니다.
- 한 사례의 변형 수백 건을 독립 결함 수백 개로 세지 않습니다. 원본 수와 변형 수, 위험 놓침·정상 차단·판정 변화·`확인 필요`를 따로 적습니다.
- 고객 코드를 사례집에 옮기지 않습니다. 같은 동작을 하는 짧은 합성 사례를 만들고, 원본과 동작이 같은지 사람이 확인합니다.
- 판정을 바꾸는 변경에는 바뀐 판정 사례, 짝이 되는 정상 사례, 출력 상태와 이유 코드, 호환성 영향, 비용 변화를 CHANGELOG와 해당 문서에 남깁니다.
