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
iron-laws check .                       # 터미널에서 점검 (HIGH 이상이 있으면 종료코드 1)
iron-laws fix-prompt .                  # 코딩 AI에게 붙여넣을 수정 지시문 만들기
iron-laws audit . --format markdown -o report.md   # 49개 항목별 점검 현황이 포함된 보고서
iron-laws audit . --format sarif -o iron-laws.sarif  # GitHub Code Scanning 연동
iron-laws explain IL-501                # 규칙 하나를 쉬운 말로 설명
iron-laws coverage                      # 행안부 49개 항목 중 무엇을 점검하는지 확인
iron-laws rules                         # 탑재된 규칙 전체
iron-laws init                          # .iron-laws.yml 설정 파일 생성
iron-laws support                       # 언어·규칙별 구현·검증 현황 (파서 있음 ≠ 검증됨)
iron-laws baseline create .             # 현재 지적을 승인된 부채로 기록
iron-laws check . --baseline .iron-laws-baseline.json   # 새로 생긴 지적만 판정
iron-laws check . --changed-since origin/main           # 바뀐 파일의 지적만 표시 (전체 점검과 정기 대조)
iron-laws feedback add IL-501 src/a.py:3 --verdict false-positive --minutes 10   # '확인 필요' 검토 결과 기록
```

종료코드는 `0` 통과, `1` 설정한 심각도 이상의 지적 발견, `2` 잘못된 입력·설정 오류, 점검한 파일이 없는 경우, 또는 점검이 끝까지 이루어지지 않은 경우(규칙 오류·파일 읽기 실패 등)입니다. 불완전한 점검은 등급과 통과를 확정하지 않고 보고서의 `diagnostics`에 사유를 남깁니다. 없는 경로, 등록되지 않은 규칙 ID, 범위를 벗어난 제한값, 점검 대상 파일이 0개인 경우는 통과로 처리하지 않습니다(점검 대상이 비어 있는 것이 의도라면 `--allow-empty`). `fix-prompt`는 지시문 생성이 목적이라 지적이 있어도 종료코드 0이므로, 배포 관문에는 `check`나 `audit`를 쓰십시오.

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
- 통과 결과만으로 배포를 승인하지 마십시오. 기존 테스트, 코드 검토, 다른 보안 점검과 함께 쓰는 보조 도구입니다.
- 비밀값이 들어 있는 코드 줄은 모든 보고서와 AI 수정 지시문에서 값을 가려서(`****`) 출력합니다. 다만 규칙이 비밀로 인식하지 못한 값까지 가려 주는 것은 아니므로 지시문을 외부 AI에 붙여넣기 전에 한 번 읽어 보십시오.
- 정확도 수치와 측정 방법은 [docs/ACCURACY.md](docs/ACCURACY.md), 언어·규칙별 검증 현황은 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md), 보고서 형식과 호환 정책은 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)에 있습니다. OWASP Benchmark(Java) 기준으로 XSS 점수 +45%, 취약 암호 +77%이지만 SQL 삽입 +26%, 명령어 삽입 +14%로, 안전하게 가려진 사례에서 오탐이 남아 있습니다.
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
