# 사용법

명령, 종료코드, 설정, 보고서 사용법입니다. 설치와 첫 점검은 [README](../README.md)에 있습니다.

## 명령 목록

```bash
iron-laws check .                          # 점검. HIGH 이상 지적이 있으면 종료코드 1
iron-laws fix-prompt .                     # 코딩 AI에게 붙여 넣을 수정 지시문
iron-laws audit . --format markdown -o report.md     # 행안부 49개 항목별 점검 현황
iron-laws audit . --format sarif -o iron-laws.sarif  # GitHub Code Scanning용 SARIF
iron-laws explain IL-501                   # 규칙 하나를 쉬운 말로 설명
iron-laws rules                            # 규칙 목록
iron-laws coverage                         # 행안부 49개 항목 중 무엇을 점검하는지
iron-laws deps . --advisory-db ./osv       # 취약한 의존성과 올릴 버전
iron-laws architecture .                   # 프로젝트 전체 구조 진단
iron-laws support                          # 언어·규칙별 구현·시험 현황
iron-laws routes .                         # 웹 주소(라우트)별 로그인·권한 검사 여부
iron-laws init                             # 기본 설정 파일 .iron-laws.yml 만들기
iron-laws guidelines export -o 지침.md      # 코딩 에이전트 지침(CLAUDE.md용)
iron-laws check . --build-manifest git     # git 추적 파일과 대조해 빠진 파일과 이유 보기
```

## 지적이 많은 프로젝트에 도입하기

처음부터 모든 지적을 고치기 어려우면 새로 생긴 문제만 보도록 범위를 줄입니다.

```bash
iron-laws baseline create .                              # 지금 있는 지적을 기준선으로 기록
iron-laws check . --baseline .iron-laws-baseline.json    # 기준선 이후 새로 생긴 지적만 판정
iron-laws check . --changed-since origin/main            # 바뀐 파일의 지적만 표시
iron-laws feedback add IL-501 src/a.py:3 --verdict false-positive --minutes 10   # '확인 필요' 지적을 검토한 결과 기록
```

기준선에는 그때의 점검 비용(시간, 초당 파일 수)도 남습니다. 기준선 이후 점검이 2배 넘게 느려지면 비율로 알려 줍니다. 절대 시간은 장비마다 달라서 같은 장비, 같은 작업 프로세스 수에서만 비교하십시오.

## 종료코드

| 종료코드 | `check`·`audit` | `evidence verify`·`review-bundle`·`approvals status`·`verify-patch` |
|---|---|---|
| `0` | 통과 | 모순 없음, 할 일 없음, 모든 승인 유효, 검증 통과 |
| `1` | 기준 심각도 이상의 지적이 있거나, 신뢰 지표가 상한을 넘음 | 모순 발견, 할 일 있음, 다시 볼 승인 있음, 검증 실패 |
| `2` | 잘못된 입력·설정, 점검한 파일 0개, 점검을 끝까지 하지 못함(규칙 오류, 파일 읽기 실패, 보고서 내부 모순) | 판정할 수 없음(지원하지 않는 형식, 필요한 정보 누락, 격리 실행 실패) 또는 입력 오류 |

- 점검을 끝까지 하지 못하면 등급과 통과를 정하지 않고 보고서의 `diagnostics`에 이유를 남깁니다. 없는 경로, 등록되지 않은 규칙 ID, 범위를 벗어난 설정값, 점검한 파일 0개도 통과로 치지 않습니다. 빈 폴더 점검이 의도라면 `--allow-empty`를 씁니다.
- `--approvals`나 `--baseline`을 쓰면 새 지적과 다시 볼 지적만으로 통과를 정하므로, 등급이 F여도 통과일 수 있습니다.
- `fix-prompt`는 지시문을 만드는 명령이라 지적이 있어도 종료코드가 0입니다. 배포 관문에는 `check`나 `audit`을 쓰십시오.

## AI 수정본 검증과 승인 기록

AI가 고친 코드를 받아들일 때 무엇을 확인했고 무엇을 확인하지 못했는지 기록으로 남깁니다. 동작과 안전 장치는 [PATCH_VERIFICATION.md](PATCH_VERIFICATION.md)에 있습니다.

```bash
iron-laws verify-patch ./proj --patch ../fix.diff --finding IL-504@app.py:8 \
  --runner docker --image iron-laws-verify:py313 \
  --test-cmd python --test-cmd -m --test-cmd pytest --test-cmd -q -o ../receipt.json
iron-laws regression propose . --finding IL-504@app.py -o spec.yml   # 결함을 가려내는 회귀시험 초안
iron-laws approvals add . --finding IL-504@app.py --reason "사유" --store 승인기록.jsonl --sign-key ~/.ssh/id_ed25519
iron-laws approvals checkpoint --store 승인기록.jsonl -o /안전한/위치/체크포인트.json --sign-key ~/.ssh/id_ed25519
iron-laws check . --approvals 승인기록.jsonl --allowed-signers 허용서명자   # 서명과 전제가 맞는 승인만 받아들임
iron-laws review-bundle . --approvals 승인기록.jsonl   # 코드 변경이 각 승인에 준 영향
iron-laws audit . --format json -o ../report.json && iron-laws evidence verify ../report.json
iron-laws check . --contract .iron-laws-contract.yml   # 팀이 정한 근거 요구를 채웠는지
iron-laws check . --max-analysis-unknown-rate 0.3 --max-unverified-rule-language-rate 0.5
```

- `--finding`에는 `iron-laws check` 출력의 위치를 그대로 씁니다(`규칙@경로:줄` 또는 `규칙@경로`).
- `verify-patch`에는 docker와 시험용 이미지가 필요합니다(`docker build -t iron-laws-verify:py313 .`). Dockerfile 예시는 [PATCH_VERIFICATION.md](PATCH_VERIFICATION.md) §4에 있습니다. `--test-cmd`를 주지 않으면 시험을 돌리지 않고 `판정 불가`(종료코드 2)로 끝납니다.
- patch, 보고서, 검증 기록(Receipt), 승인 기록은 점검하는 폴더 밖에 두십시오. 안에 두면 다음 점검 대상이 되어 원본의 해시가 달라집니다.
- 보고서의 신뢰 지표 두 개에 상한을 둘 수 있습니다. `analysis_unknown_rate`는 근거 장부의 호출 가운데 분석을 끝내지 못한 비율이고, `unverified_rule_language_rate`는 이번 점검에 쓰인 (규칙, 언어) 조합 가운데 시험으로 확인되지 않은 비율입니다. 상한을 넘으면 통과 대신 재검토(종료코드 1)입니다.

'통과'는 정한 검사 조건을 채웠다는 뜻입니다. 코드가 안전하다는 보증도, 취약점이 없다는 증명도, 수정 전후 동작이 같다는 증명도 아닙니다. 분석하지 못한 부분과 돌리지 않은 검사는 결과 옆에 표시합니다.

## 지적 억제

오탐이거나 의도한 예외는 사유를 적어야 억제됩니다. 사유가 없는 억제 주석은 무시합니다.

```python
except ImportError:  # iron-laws: ignore[IL-301] 선택 의존성이 없으면 기능을 끈다
    yaml = None
```

```python
# iron-laws: ignore-file[IL-102] 취약 알고리즘을 탐지하는 패턴 정의 파일   (파일 상단 30줄 안)
```

만료일도 둘 수 있습니다(`# iron-laws: ignore[IL-101] until=2026-12-31 사유`). 만료된 억제는 적용하지 않고 보고서에 드러냅니다. 쓰이지 않은 억제와 등록되지 않은 규칙 ID도 알려 줍니다.

## 설정 (`.iron-laws.yml`)

```yaml
fail_on: HIGH            # CRITICAL, HIGH, MEDIUM, LOW
excludes: [".git", "node_modules", "dist"]
disabled_rules: ["ARC-206"]
policies:
  ledger_include_spec_points: false   # 켜면 사용자 명세의 싱크를 근거 장부에도 반영
  # protected_paths: ["deploy/*.yml"]         # 에이전트 훅이 편집을 알릴 경로를 더함
  # protected_paths_exclude: ["CLAUDE.md"]    # 기본 보호 경로에서 뺌
limits:
  max_function_lines: 80
  max_file_lines: 600
  max_parameters: 7
  max_nesting: 5
  duplicate_similarity: 0.9
  max_workers: 32              # 파일별 규칙을 나눠 처리하는 작업 프로세스 수
  parallel_min_files: 50       # 이 파일 수 이상이면 나눠 처리
  max_wall_seconds: 120        # 점검 시간 상한. 넘으면 통과로 보지 않음
```

- 점검 폴더의 `.iron-laws.yml`을 씁니다. `--config 파일`로 지정하면 그 파일이 우선하고, `--search-parents`를 주면 상위 폴더에서도 찾습니다.
- `fail_on`은 `--fail-on` 옵션, 설정 파일, 기본값(HIGH) 순으로 정합니다. 어느 것을 썼는지 보고서에 남습니다.
- 설정 오류와 알 수 없는 키는 무시하지 않고 종료코드 2로 알립니다.
- 압축·생성 파일은 점검하지 않고 보고서의 `skipped_files`에 이유와 함께 남깁니다.
- `limits.max_wall_seconds`를 넘으면 `scan_status`가 `incomplete`가 되고 종료코드는 2입니다. 명령행에서는 `--max-wall-seconds`로 덮어씁니다.
- `.gitignore`에 걸리는 파일도 기본으로 점검합니다. `.env`처럼 비밀값이 들어가는 파일을 놓치지 않기 위해서입니다. 빼려면 `respect_gitignore: true`를 씁니다.
- 프로젝트 구조 계약은 [ARCHITECTURE.md](ARCHITECTURE.md), 사용자 명세는 [CUSTOMIZATION.md](CUSTOMIZATION.md)에 있습니다.

## CI 연결

GitHub Actions 예시입니다.

```yaml
name: Iron Laws
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv tool install git+https://github.com/JinHo-von-Choi/iron-laws.git
      - run: iron-laws audit . --format sarif -o iron-laws.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: iron-laws.sarif
      - run: iron-laws check . --fail-on HIGH
```

GitLab은 `audit --format gitlab-codequality`로 merge request의 Code Quality 위젯에 지적을 표시합니다. 예시는 [ci/gitlab-ci.yml](ci/gitlab-ci.yml)에 있고, 기준선과 같은 지문을 쓰므로 코드가 같으면 같은 지적으로 이어집니다. pre-commit 설정은 [ci/pre-commit-config.yaml](ci/pre-commit-config.yaml)에 있습니다.

## 보고서

### 감리 대응 보고서

```bash
iron-laws audit . --format mois-report -o 감리대응.md
```

행안부 구현단계 49개 항목마다 다음을 적습니다.

- 지적
- 남겨 둔 지적(억제 주석의 사유·만료일, 승인 기록)
- 점검하지 못한 이유(규칙이 없거나 사람이 확인할 항목, 근거 장부에서 확인하지 못한 호출, 건너뛴 파일)

출력 파일을 `.docx`로 주면 Word 문서(`pip install 'iron-laws[docx]'`), `.hwpx`로 주면 한글 문서(`pip install 'iron-laws[hwpx]'`)로 씁니다. 한글 프로그램은 필요 없습니다.

마크다운·감리 대응·Word 보고서에는 '점검 비용과 확인하지 못한 범위' 절이 들어갑니다. 점검 시간, 초당 파일 수, 최대 메모리, 확인하지 못한 보안 관심 지점 수, 미검증 (규칙, 언어) 조합 수를 적습니다. 이 수치는 프로그램이 스스로 확인한 범위이며, 확인하지 못한 곳이 안전하다는 뜻은 아닙니다. 보고서 파일 형식은 [REPORT_FORMATS.md](REPORT_FORMATS.md)에 있습니다.

### 편집기와 검토 보조

- **LSP 서버** `iron-laws lsp`: 편집기에 연결하면 파일을 열거나 고칠 때마다 점검해 진단으로 보여 줍니다. 저장하지 않은 내용도 점검하며 파일 하나 단위로 봅니다.
- **LLM 검토 의견** `check`·`audit --triage-model "<명령>"`: '확인 필요' 지적을 지정한 LLM 명령에 보내고, 돌아온 의견(`likely_true`·`likely_false`·`unsure`)을 보고서의 `review_opinion`에만 담습니다. 판정·심각도·통과 여부는 바꾸지 않습니다.
  - 보내는 코드는 비밀값을 가린 조각입니다.
  - 지적마다 결함 종류별 판정 기준, 엔진이 확인한 입력 유입→전파→싱크 위치, 같은 규칙에 사람이 남긴 판단(승인 사유, 교훈)을 함께 보냅니다.
  - `likely_false`에는 근거(상수, 정제 함수, 실행되지 않는 분기, 외부 입력 아님 같은 이유와 줄, 이름)를 요구합니다. 그 근거를 코드와 엔진의 입력 경로로 대조해 `corroborated`(확인), `unsupported`(확인 못 함), `contradicted`(엔진 근거와 모순)를 남깁니다.
- **AI 습관 추이** `iron-laws habits`: 점검할 때마다 다섯 습관(하드코딩, 구조 붕괴, 삼킨 예외, 중복 함수, 타입 회피)의 1천 줄당 지적 수를 `.iron-laws-habits.jsonl`에 기록하고 처음, 직전, 최근 값을 보여 줍니다. 코드와 경로는 기록하지 않습니다.
