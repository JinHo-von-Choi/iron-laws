# 오철칙 (Iron Laws) 기여 가이드라인

오철칙 프로젝트에 기여해주셔서 감사합니다. 본 프로젝트는 SI 감리에서 자주 지적되는 항목을 정리해 AI가 만든 코드의 보안·구조·타입 결함을 점검하며, 결함에 대한 타협 없는 엄격성을 기본 철학으로 합니다.

## 개발 환경 설정

본 프로젝트는 빠르고 안정적인 패키지 관리를 위해 [uv](https://github.com/astral-sh/uv)를 표준 도구로 사용합니다.

```bash
# 저장소 복제
git clone https://github.com/JinHo-von-Choi/iron-laws.git
cd iron-laws

# 가상환경 및 의존성 설치
uv sync --all-extras --dev

# 테스트 실행
uv run pytest -v

# 린트 및 포맷 검사
uv run ruff check .
```

## 기여 절차

1. Issue를 생성하여 개선 사항 또는 신규 규칙 제안
2. 기능 브랜치 생성 (`feat/rule-name` 또는 `fix/issue-description`)
3. 코드 작성. 새 규칙은 양성·음성 사례를 `tests/`에 추가하고, `uv run python benchmarks/build_support_manifest.py`로 지원 행렬 자료를 갱신한 뒤 `docs/SUPPORT_MATRIX.md`를 다시 생성합니다(`iron-laws support > ...`). 규칙의 판정 의미를 바꾸면 규칙의 `version`을 올립니다
4. 오철칙 자체 진단 통과 확인:
   ```bash
   uv run iron-laws check .
   ```
5. 사용자에게 보이는 변경은 `CHANGELOG.md`의 `[Unreleased]` 항목에 적습니다
6. Pull Request 제출

## 시험 실행

```bash
uv run pytest -q                       # 전체(격리 실행 시험은 docker 이미지가 없으면 skip)
uv run python benchmarks/plan_experiments.py       # 패치 검증·회귀시험·승인 추적 표본 측정
uv run python benchmarks/plan_experiments_v13.py   # 근거 일치·변형 사례집·변형 입력·승인 승계 측정
uv run python benchmarks/plan_experiments_v14.py out.json --baseline <이전 버전 소스 폴더>   # 이전 버전과 같은 표본 비교
```

격리 실행 시험은 준비 단계에서 만든 이미지가 있어야 돌아갑니다(시험 중에는 네트워크를 쓰지 않으므로 미리 받아 둡니다).
`tests/runner_doubles.py`의 `LocalTestRunner`는 호스트에서 명령을 실행하는 **시험 전용 대역**입니다. 우리가 만든 입력(위험한 호출을 기록만 하는 harness 등)을 돌리는 데만 쓰고, 제품 코드에 넣지 않으며, 호스트 실행 금지 정책을 검증하는 시험에는 쓰지 않습니다.
표본(`tests/regression_corpus.py`, 장부·승인 시험의 표본)은 개발팀이 직접 분류한 것이라 효과 주장의 근거로 쓰지 않습니다.

## 코딩 원칙 (오철칙 준수)
- 빈 catch 블록이나 에러를 삼키는 코드는 절대로 머지되지 않습니다.
- 모든 규칙은 쉬운 설명(`plain`)과 고치는 방법(`how_to_fix`)을 갖추고, 행안부 항목에 근거하면 `mois_ref`로 번호를 연결하며 근거가 없으면 `gov_standard = None`으로 두어 자체 규칙임을 드러냅니다.
- 오탐을 줄이는 변경은 오탐을 재현하는 회귀 사례(`tests/test_regressions.py`)와 함께 제출합니다.
- 규칙을 숨기려고 억제 주석을 쓰려면 사유를 적어야 합니다.
- Co-Authored-By 라인은 커밋 메시지에 포함하지 않습니다.

## 사례집과 평가용(holdout) 규칙

- 사례는 정상·위험 짝으로 추가합니다(`tests/repair_cases.py`, `tests/semantic_corpus.py`).
- 개발용(`semantic_corpus.py`)은 엔진을 고칠 때 봐도 됩니다. 평가용(`semantic_holdout.py`)은 엔진을 조정하려고 보지 않습니다. 평가용 사례가 실패해 엔진을 고쳤다면 그 사례를 개발용으로 옮기고(`MOVED_TO_DEV`에 적고) 같은 유형의 새 평가용 사례로 바꿉니다. 평가용과 개발용은 (유형, 스타일)이 겹치면 안 됩니다. 옮긴 사례의 유형만 예외이며, 시험이 그 목록을 따로 확인합니다.
- 사례의 정답은 사람이 정합니다. LLM의 자기평가는 정답으로 쓰지 않습니다. 구현자가 직접 정한 표본은 독립 검토가 아니므로 문서에 그렇게 적습니다.
- 변형 수백 건을 독립 결함 수백 개로 세지 않습니다. 보고는 원본 수와 변형 수, 위험 미탐·정상 오차단·판정 변화·unknown을 따로 씁니다.
- 고객 코드를 사례집으로 자동 반출하지 않습니다. 같은 동작을 나타내는 합성 최소 사례를 만들고 원본과 같은 동작인지 사람이 확인합니다.
- 새 판정 변경에는 바뀐 판정 사례, 대응 정상 사례, 출력 상태와 이유 코드, 호환성 영향, 비용 변화를 CHANGELOG와 해당 문서에 남깁니다.
