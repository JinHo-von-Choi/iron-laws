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
3. 코드 작성. 새 규칙은 양성·음성 사례를 `tests/`에 추가
4. 오철칙 자체 진단 통과 확인:
   ```bash
   uv run iron-laws check .
   ```
5. Pull Request 제출

## 코딩 원칙 (오철칙 준수)
- 빈 catch 블록이나 에러를 삼키는 코드는 절대로 머지되지 않습니다.
- 모든 규칙은 쉬운 설명(`plain`)과 고치는 방법(`how_to_fix`)을 갖추고, 행안부 항목에 근거하면 `mois_ref`로 번호를 연결하며 근거가 없으면 `gov_standard = None`으로 두어 자체 규칙임을 드러냅니다.
- 오탐을 줄이는 변경은 오탐을 재현하는 회귀 사례(`tests/test_regressions.py`)와 함께 제출합니다.
- 규칙을 숨기려고 억제 주석을 쓰려면 사유를 적어야 합니다.
- Co-Authored-By 라인은 커밋 메시지에 포함하지 않습니다.
