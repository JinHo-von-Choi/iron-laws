<div align="center">

<img src="assets/logo.png" alt="오철칙 (Iron Laws) Logo" width="600" />

# 오철칙 (五鐵則) — Iron Laws

**AI로 만든 프로젝트가 보안 사고와 유지보수 지옥이 되기 전에 잡아 주는 점검 도구**  
대기업·공공기관 SI 감리에서 자주 지적되는 항목을 AI 시대에 맞게 정리했습니다

[![CI](https://github.com/JinHo-von-Choi/iron-laws/actions/workflows/ci.yml/badge.svg)](https://github.com/JinHo-von-Choi/iron-laws/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

</div>

---

## 왜 만들었나

요즘은 개발을 배우지 않은 사람도 AI와 함께 서비스를 만듭니다. 화면이 뜨고 기능이 돌아가는 것을 확인하면 "완성"처럼 보입니다. 하지만 AI는 **돌아가는 결과물**을 목표로 코드를 짜기 때문에, 보안과 구조는 뒷전이 되기 쉽습니다. 그리고 만드는 사람은 무엇이 위험한지, 무엇이 나중에 발목을 잡을지 알아볼 기준이 없습니다.

그 결과는 비슷합니다.

- 어느 날 API 키가 깃허브에 올라가 요금 폭탄이나 계정 탈취를 당한다.
- 로그인 없이 누구나 다른 사람의 데이터를 보고 지울 수 있는 상태로 배포된다.
- 오류가 나도 아무 기록이 없어서 원인을 찾을 수 없다.
- 같은 기능을 하는 함수가 파일마다 따로 있어서, 하나를 고치면 다른 곳이 깨진다.
- 기능을 덧붙일수록 코드가 뒤엉켜 AI도 사람도 손을 못 댄다.

저는 대기업과 공공기관의 SI 프로젝트에서 감리를 받으며, 감리자들이 코드에서 무엇을 먼저 보는지 오래 경험했습니다. 오철칙은 그 경험을 정리해서 **전문 감리자가 없는 환경의 AI 개발자**가 같은 눈높이로 자기 프로젝트를 점검할 수 있게 만든 도구입니다.

## 어떻게 돕는가

**1. 찾아냅니다.**  
보안 결함뿐 아니라 AI 특유의 습관까지 봅니다. 코드에 박아 넣은 주소·키·경로, 로그 없이 삼킨 예외, 흩어진 중복 함수, `any`와 `type: ignore`로 덮은 타입, 인증 없는 관리 API, 접근 규칙이 없는 Supabase·Firebase, 커밋된 `.env`, 모듈 순환 참조까지 점검합니다.

**2. 쉬운 말로 설명합니다.**  
"SQL Injection(CWE-89)" 대신 "화면에서 받은 값이 그대로 DB 명령에 섞이면 공격자가 데이터를 빼내거나 지울 수 있습니다"라고 말합니다. 지적마다 왜 위험한지와 어떻게 고치는지가 붙습니다.

**3. AI에게 고치게 합니다.**  
`iron-laws fix-prompt`는 찾아낸 문제를 심각도 순으로 모아, 사용하는 AI 코딩 도구에 **그대로 붙여넣을 수 있는 수정 지시문**으로 만들어 줍니다. 지시문에는 "오류를 조용히 삼키지 않는다", "비밀을 코드에 쓰지 않는다", "이미 있는 함수를 다시 만들지 않는다" 같은 수정 원칙도 함께 들어갑니다. 보안을 몰라도 점검, 수정 요청, 재점검의 순환을 돌릴 수 있습니다.

```text
AI로 만든다 → iron-laws check → iron-laws fix-prompt → AI에게 붙여넣어 수정 → 다시 check
```

> 작성자의 SI 감리 경험을 바탕으로 정리한 점검 도구이며, 공식 인증 도구나 감리 증빙이 아닙니다. 개발 중 사전 점검과 개선에 쓰십시오.

---

## 설치

```bash
# uv 권장
uv tool install git+https://github.com/JinHo-von-Choi/iron-laws.git

# 또는 pip
pip install git+https://github.com/JinHo-von-Choi/iron-laws.git
```

파서는 패키지에 포함되어 있어 네트워크 없이 동작합니다.

## 빠른 시작

```bash
iron-laws check .                          # 점검. HIGH 이상이 있으면 종료코드 1
iron-laws fix-prompt .                     # 코딩 AI에게 붙여넣을 수정 지시문
iron-laws audit . --format markdown -o report.md     # 행안부 49개 항목별 점검 현황 보고서
iron-laws audit . --format sarif -o iron-laws.sarif  # GitHub Code Scanning 연동
iron-laws explain IL-501                   # 규칙 하나를 쉬운 말로 설명
iron-laws rules                            # 규칙 목록
iron-laws coverage                         # 행안부 49개 항목 중 점검하는 것
iron-laws support                          # 언어·규칙별 구현·검증 현황
iron-laws init                             # .iron-laws.yml 생성
```

기존 프로젝트에 도입할 때는 지적의 범위를 줄여 씁니다.

```bash
iron-laws baseline create .                              # 현재 지적을 기준선으로 기록
iron-laws check . --baseline .iron-laws-baseline.json    # 새로 생긴 지적만 판정
iron-laws check . --changed-since origin/main            # 바뀐 파일의 지적만 표시
iron-laws feedback add IL-501 src/a.py:3 --verdict false-positive --minutes 10   # '확인 필요' 검토 결과 기록
```

AI가 만든 수정의 검증과 승인 기록은 아래 명령을 씁니다. 설명은 다음 절에 있습니다.

```bash
iron-laws check . --contract .iron-laws-contract.yml   # 요구한 분석 근거가 충족됐는지(계약 예시: docs/PATCH_VERIFICATION.md §1)
iron-laws verify-patch ./proj --patch ../fix.diff --finding IL-504@app.py:8 \
  --runner docker --image iron-laws-verify:py313 \
  --test-cmd python --test-cmd -m --test-cmd pytest --test-cmd -q -o ../receipt.json
iron-laws regression propose . --finding IL-504@app.py -o spec.yml   # 결함을 구별하는 회귀시험 후보
iron-laws approvals add . --finding IL-504@app.py --reason "사유" --store 승인기록.jsonl
iron-laws check . --approvals 승인기록.jsonl           # 전제가 유지되는 승인만 받아들임
iron-laws review-bundle . --approvals 승인기록.jsonl   # 변경이 승인 전제에 준 영향 한 묶음
iron-laws audit . --format json -o ../report.json && iron-laws evidence verify ../report.json
iron-laws check . --max-analysis-unknown-rate 0.3 --max-unverified-rule-language-rate 0.5
```

- `--finding`의 줄 번호는 `iron-laws check` 출력의 값을 그대로 씁니다(`RULE@경로:줄` 또는 `RULE@경로`).
- `verify-patch`는 docker와 시험 이미지가 필요합니다(`docker build -t iron-laws-verify:py313 .`, Dockerfile은 [PATCH_VERIFICATION.md](docs/PATCH_VERIFICATION.md) §4). `--test-cmd`가 없으면 시험을 실행하지 않고 `판정 불가`(종료코드 2)로 끝납니다.
- patch·보고서·Receipt·승인 기록은 점검 폴더 밖에 둡니다. 안에 두면 다음 점검 대상이 되고 원본 해시가 달라집니다.

종료코드는 명령마다 같은 뜻입니다.

| 종료코드 | `check`·`audit` | `evidence verify`·`review-bundle`·`approvals status`·`verify-patch` |
|---|---|---|
| `0` | 통과 | 모순 없음 / 필수 행동 없음 / 모든 승인 유효 / 검증 항목 통과 |
| `1` | 설정한 심각도 이상의 지적, 또는 신뢰 지표 상한 초과 | 모순 발견 / 필수 행동 있음 / 재검토할 승인 있음 / 검증 실패 |
| `2` | 잘못된 입력·설정, 점검 대상 0개, 점검이 끝까지 되지 않음(규칙 오류·파일 읽기 실패·내부 모순) | 판정 불가(지원하지 않는 버전·누락·격리 실패)·입력 오류 |

- 불완전한 점검은 등급과 통과를 확정하지 않고 `diagnostics`에 사유를 남깁니다. 없는 경로, 등록되지 않은 규칙 ID, 범위를 벗어난 제한값, 점검 대상이 0개인 경우도 통과가 아닙니다(의도한 경우 `--allow-empty`).
- `--approvals`·`--baseline`을 쓰면 신규·재검토 지적만으로 통과를 판정하므로 등급이 F여도 통과일 수 있습니다.
- `fix-prompt`는 지시문 생성이 목적이라 지적이 있어도 종료코드 0입니다. 배포 관문에는 `check`나 `audit`을 씁니다.

---

## AI가 만든 수정의 검증과 승인 근거

AI가 고친 코드를 승인할 때 "무엇을 확인했고 무엇을 확인하지 못했는지"가 사라지지 않게 남기는 기능입니다. 안전 경계와 측정 결과는 [docs/PATCH_VERIFICATION.md](docs/PATCH_VERIFICATION.md)에 있습니다.

| 기능 | 하는 일 |
|---|---|
| 근거 계약과 검사 공백 장부 | 점검이 끝난 것과 요구한 근거가 충족된 것을 구별합니다. 명령 실행·경로 접근·SQL 조립 호출마다 근거 상태를 적고, 입력 출처를 확정하지 못한 호출을 깨끗함으로 바꾸지 않습니다. 같은 줄의 다른 호출이 낸 지적은 근거로 쓰지 않습니다. |
| 패치 검증(`verify-patch`) | 원본과 수정본을 같은 정책으로 점검하고, 시험 삭제·skip 증가·무시 주석·정책 약화 같은 우회 변경을 따로 표시합니다. 시험은 자격증명 없는 일회용 격리 환경에서만 돌리며, 격리를 얻지 못하면 `판정 불가`입니다. 결과는 Receipt 파일에 남습니다. |
| 수정이 만든 부채 | 수정 전후의 지적을 하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피별로 해결·유지·신규·이동으로 나눕니다. 지적을 고치지 않고 `except: pass`나 `# type: ignore`로 가린 수정은 "수정 지점과 같은 함수의 신규 부채"로 보입니다. 표시만 하며 통과·실패에는 쓰이지 않습니다. |
| 회귀시험 | 원본에서 결함 때문에 실패하고, 수정본에서 통과하고, 수정을 되돌린 코드에서 다시 실패하는지 세 번 반복해 확인합니다. |
| 승인 기록 | 사유와 전제를 남기고, 호출자·흐름·정제 함수·접근 범위·규칙 의미가 바뀌면 해당 승인만 다시 검토하게 합니다. 복제된 취약 코드와 전제가 바뀐 이동은 승인을 물려받지 않습니다. |
| 검토 묶음(`review-bundle`) | 변경이 승인 전제에 준 영향을 승인별 유지·무효화·판정 불가와 이유로 보여 줍니다. 호출 대상을 알 수 없는 경계와 점검하지 못한 파일은 영향 없음으로 보지 않고 재검토 범위를 넓힙니다. |
| 독립 검증기(`evidence verify`) | 보고서와 Receipt가 서로 모순되는지 엔진과 별도의 코드로 확인합니다. 없는 지적을 가리키거나, 근거 없이 충족이라 하거나, 만료·복제본의 승인을 쓴 보고서를 잡습니다. `check`·`audit`도 내보내기 전에 같은 검증을 거치고, 모순이 있으면 통과가 아니라 점검 불완전(종료코드 2)입니다. ([EVIDENCE_VERIFICATION.md](docs/EVIDENCE_VERIFICATION.md)) |
| 신뢰 지표와 상한 | 보고서에 `analysis_unknown_rate`(해석을 끝내지 못한 보안 관심 지점의 비율)와 `unverified_rule_language_rate`(양성·음성 시험이 모두 없는 규칙×언어 조합의 비율)를 남깁니다. 미검증 조합이 있으면 통과 표시에 "단, 미검증 조합 포함"이 붙고, 상한 옵션을 넘으면 통과 대신 재검토(종료코드 1)입니다. |
| 파일럿 기록 | `iron-laws pilot`과 `--metrics`로 팀의 검토 시간과 위험 수용을 로컬에 기록합니다(경로·코드는 저장하지 않으며 `--metrics`는 기본 꺼짐). 주 지표는 총 능동시간입니다. 확인된 오승인이나 조사 중인 사건이 있으면 `review-bundle --pilot-store`가 자동 판정을 닫고 수동 검토(종료코드 1)로 돌립니다. |

'통과'는 지정한 검사 계약을 충족했다는 뜻입니다. 안전성, 취약점 없음, 동작의 완전한 동등성을 증명하지 않습니다. PASS는 ① 필수 계약이 적용 대상이고 ② 필수 검사가 지정한 코드·정책에 대해 끝났고 ③ 요구 근거가 있고 유효하며 ④ 차단할 위반이 없다는 뜻이며, 분석 한계와 미실행은 결과 옆에 표시합니다.

---

## 점검 영역 (규칙 90개)

| 분류 | 내용 | 근거 표기 |
|---|---|---|
| 기준 규칙 (IL-1xx, 3xx, 5xx) | 행안부 구현단계 49개 항목 전체: SQL·명령어·경로·코드 삽입, XSS, SSRF, XXE, 하드코딩된 비밀, 취약 암호, 인증서 검증 해제, 오류 처리, 역직렬화, 메모리 안전성 등 | 항목 번호와 CWE |
| AI 코드 보정 (AI-1xx) | 하드코딩 설정값, 비밀 기본값 폴백, 프런트엔드 노출 비밀, 커밋된 `.env`, CORS, Supabase RLS·Firebase 규칙, Docker·CI 위험 설정, 의존성 오타·미고정, 민감정보 로깅, IDOR, 쿠키 속성 | 오철칙 자체 규칙 |
| 구조 (ARC-2xx) | 과대한 함수·파일, 요청 처리기의 DB 직접 접근, 계층 위반과 의존 방향 위반(하위 계층이 상위 계층을 import, 컨트롤러가 서비스 없이 저장소 호출, 컨트롤러·서비스의 DB 드라이버 직접 사용, 서비스·저장소의 웹 프레임워크 의존), 순환 의존, 중복·유사 함수, 반복된 문자열 상수, 테스트 부재 | 오철칙 자체 규칙 |
| 타입 안전성 (TYP-3xx) | TypeScript `any`·`@ts-ignore`·`tsconfig` 느슨함, Python `type: ignore`·`cast`, Java 원시 타입, C# `dynamic`·`#nullable disable`, Go·Rust·C++·PHP·JS의 타입 우회 | 오철칙 자체 규칙 |

참고한 공개 가이드(행안부 SW 개발보안 가이드)의 항목과 대응하는 규칙에는 항목 번호를 붙이고, 대응이 없는 규칙은 보고서에 `오철칙 자체 품질 규칙 (참고 가이드 항목 외)`로 구분 표기합니다.
49개 항목 모두에 점검 규칙이 있으며(2-16 인증시도 제한은 IL-532), 설계단계 20개 항목도 구현 규칙과 대응시켜 `iron-laws coverage`와 마크다운 보고서에 보여 줍니다. 5-3, 5-4 등 일부 항목은 C/C++에만 적용됩니다. `지적 없음`은 탑재된 규칙 범위에서 발견되지 않았다는 뜻입니다.

### 지원 언어

| 수준 | 언어 | 내용 |
|---|---|---|
| 깊게 | Python, JavaScript/TypeScript, Java, C# | 구문 분석, 외부 입력 추적(함수 안 분기 합류·같은 파일 도우미 함수, Python은 파일 간), 전체 규칙 |
| 기본 | Go, PHP | 구문 분석, 주요 주입·오류 처리·암호 규칙 |
| 제한 | Rust, C/C++ | 오류 처리, 메모리·포맷 문자열·API, 타입 우회 |
| 설정·정의 파일 | SQL, YAML, JSON, `.env`, Dockerfile, Compose, GitHub Actions, XML(MyBatis), HTML 템플릿 | 비밀, 접근 규칙(RLS·Firebase), 배포 설정, 템플릿 이스케이프 |

---

## 쉬운 설명과 수정 지시문

모든 지적에는 세 가지가 붙습니다: 무슨 문제인지, 왜 위험한지(쉬운 말), 어떻게 고치는지. `fix-prompt`는 지적을 심각도 순으로 모아 코딩 AI에게 줄 지시문으로 바꿉니다. 지시문에는 "오류를 조용히 삼키지 않는다, 비밀을 코드에 쓰지 않는다, 타입 검사를 덮지 않는다, 중복 함수를 새로 만들지 않는다" 같은 수정 원칙이 함께 들어갑니다.

## 지적을 억제하려면

오탐이거나 의도한 예외는 사유를 적어야만 억제됩니다. 사유가 없는 억제 주석은 무시됩니다.

```python
except ImportError:  # iron-laws: ignore[IL-301] 선택 의존성이 없으면 기능을 끈다
    yaml = None
```

```python
# iron-laws: ignore-file[IL-102] 취약 알고리즘을 탐지하는 패턴 정의 파일   (파일 상단 30줄 안)
```

## 설정 (`.iron-laws.yml`)

```yaml
fail_on: HIGH            # CRITICAL, HIGH, MEDIUM, LOW
excludes: [".git", "node_modules", "dist"]
disabled_rules: ["ARC-206"]
limits:
  max_function_lines: 80
  max_file_lines: 600
  max_parameters: 7
  max_nesting: 5
  duplicate_similarity: 0.9
```

설정 파일은 점검 폴더의 `.iron-laws.yml`을 쓰고, `--config 파일`로 지정하면 그것이 우선하며 `--search-parents`를 주면 상위 폴더에서도 찾습니다. `fail_on`의 우선순위는 `--fail-on` 옵션 > 설정 파일 > 기본값(HIGH)이고, 어느 것을 썼는지 보고서에 남습니다. 억제 주석에는 만료일을 둘 수 있습니다(`# iron-laws: ignore[IL-101] until=2026-12-31 사유`). 만료된 억제는 적용되지 않고 보고서에 드러나며, 사용되지 않은 억제와 등록되지 않은 규칙 ID도 알려 줍니다. 설정 오류와 알 수 없는 키는 조용히 무시하지 않고 종료코드 2로 알려 줍니다. 압축·생성 파일은 점검하지 않고 보고서의 `skipped_files`에 사유와 함께 남깁니다.

## GitHub Actions

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

---

## 한계

- 실행 순서를 따르는 흐름 분석(분기·반복·예외를 합쳐서 판정)은 함수 안에서 합니다. 같은 파일의 도우미 함수는 호출 깊이 4단계까지 따라가고, **Python은 import를 따라 다른 파일의 함수까지**(시범 지원, 해석 횟수 상한 있음) 따라갑니다. 그 밖의 언어에서 파일 사이 호출로 전달되는 입력은 놓치거나 확인이 필요한 지적(`확인 필요`)으로만 보고합니다. 정제 함수는 자기가 막는 문맥(HTML·SQL·셸·경로 등)에서만 인정합니다.
- 정확도 측정에 쓴 표본은 개발팀이 직접 분류한 것입니다. 외부 전문가의 독립 평가와 실제 팀 도입 결과는 아직 없습니다([docs/PATCH_VERIFICATION.md](docs/PATCH_VERIFICATION.md) §6).
- 안전 조건(허용 목록 검사·경로 범위 검사)은 검사가 모든 경로에서 싱크 앞에 실행되고 검사한 값이 싱크까지 바뀌지 않을 때만 인정합니다. 갈래마다 따로 검사하는 코드(한 갈래는 허용 목록, 다른 갈래는 범위 검사)처럼 경로별로 안전한 경우는 알아보지 못해 확정 지적이 남을 수 있습니다. 독립 검증기는 구조적 모순만 잡고 엔진이 일관되게 만든 의미 오류는 잡지 못합니다.
- 통과 결과만으로 배포를 승인하지 마십시오. 기존 테스트, 코드 검토, 다른 보안 점검과 함께 쓰는 보조 도구입니다.
- 비밀값이 들어 있는 코드 줄은 모든 보고서와 AI 수정 지시문에서 값을 가려서(`****`) 출력합니다. 다만 규칙이 비밀로 인식하지 못한 값까지 가려 주는 것은 아니므로 지시문을 외부 AI에 붙여넣기 전에 한 번 읽어 보십시오.
- 정확도 수치와 측정 방법은 [docs/ACCURACY.md](docs/ACCURACY.md), 언어·규칙별 검증 현황은 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md), 보고서 형식과 호환 정책은 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)에 있습니다. OWASP Benchmark(Java) 점수는 XSS +45%, 취약 암호 +77%인 반면 SQL 삽입은 +26%, 명령어 삽입은 +14%에 그칩니다. 안전하게 가려진 사례에서 오탐이 남기 때문입니다.
- 존재하지 않는 패키지를 지어낸 경우(AI의 허위 의존성)는 저장소 조회 없이 알 수 없어, 인기 패키지와 철자가 비슷한 이름만 지적합니다.

## 참고 문서와 이용 조건

점검 항목은 작성자의 SI 감리 경험을 바탕으로 정리했고, 항목 번호는 아래 공개 문서를 참고 표기했습니다.

- 행정안전부 「소프트웨어 개발보안 가이드」(2021.11): 공공데이터포털 이용허락범위 제한 없음, 한국인터넷진흥원 게시본은 공공누리 제1유형(출처표시). 항목 번호·명칭과 CWE 대응만 데이터로 옮겼고 본문과 예제 코드는 포함하지 않습니다. 출처: 행정안전부, 한국인터넷진흥원.
- 국가정보원 「국가 사이버보안 기본지침」 제13조제2항 누출금지정보 항목명 (국가사이버안보센터 공개 문서).
- 한국인터넷진흥원 「암호 알고리즘 및 키 길이 이용 안내서」는 이름만 언급하고 내용은 복제하지 않습니다. 알고리즘별 유효기간 표는 반영하지 않았습니다.

오철칙은 위 기관의 공식 도구가 아니며 승인이나 보증을 받지 않았습니다. 기관 로고와 명의를 사용하지 않습니다. 이용 조건은 기관이 바꿀 수 있고, 이 내용은 법률 자문이 아닙니다.

## 5대 철칙

| 번호 | 철칙 | 원칙 |
|:---:|:---|:---|
| 제1철칙 | 타협과 묵인은 없다 | 하드코딩된 시크릿, 취약 암호, 꺼 둔 인증서 검증 같은 결함에 "일정이 급해서"라는 변명은 받지 않는다. |
| 제2철칙 | 근거 규정 없는 지적은 잡담이다 | 모든 지적은 행안부 항목 번호와 결합하고, 근거가 없으면 자체 규칙임을 밝힌다. |
| 제3철칙 | 병신같이 덮지 않는다 | 삼킨 예외, 꺼 둔 테스트, 항상 통과하는 인증, 타입 검사 회피를 지적한다. |
| 제4철칙 | 대안 없는 비판은 직무유기다 | 모든 지적에 고치는 방법과 AI용 수정 지시문을 제공한다. |
| 제5철칙 | 전수 검증의 원칙 | 입력 경로를 추적하고 구조·중복·순환 의존까지 점검하며, 점검하지 못한 항목은 숨기지 않는다. |

## 라이선스

[MIT License](LICENSE) — Copyright (c) 2026 Jinho Von Choi (최진호)
