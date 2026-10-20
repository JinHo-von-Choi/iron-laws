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
보안 결함뿐 아니라 AI 특유의 습관까지 봅니다. 코드에 박아 넣은 주소·키·경로, 로그 없이 삼킨 예외, 흩어진 중복 함수, `any`와 `type: ignore`로 덮은 타입, 인증 없는 관리 API, 접근 규칙이 없는 Supabase·Firebase, 커밋된 `.env`, 모듈 순환 참조까지 점검합니다. 반복문 안의 DB 조회·인터넷 요청, 데이터가 늘면 급격히 느려지는 중첩 반복, AI 코딩 도구 규칙 파일에 숨은 지시, 취약점이 보고된 의존성 버전, 프로젝트 전체의 구조 상태도 봅니다.

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
iron-laws deps . --advisory-db ./osv       # 잠금 파일의 취약 의존성과 수정 경계
iron-laws architecture .                   # 프로젝트 전체 구조 진단
iron-laws support                          # 언어·규칙별 구현·검증 현황
iron-laws routes .                         # 웹 라우트별 인증·인가 행렬
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

## 코딩 에이전트에서 쓰기: MCP 서버

Claude Code, Cursor 같은 코딩 에이전트가 점검과 검증을 직접 부를 수 있게 MCP 서버(stdio)를 제공합니다.

```bash
pip install 'iron-laws[mcp]'
iron-laws mcp --root /path/to/project --server-config ~/.config/iron-laws/server.yml
```

```yaml
# server.yml (점검 대상 폴더 밖에 둡니다)
test_presets:
  unit:
    command: [python, -m, pytest, -q]
    image: python:3.13-slim
    timeout: 180
```

- 도구: `check`, `explain`, `fix_prompt`, `verify_patch`, `deps`. 입력 이름은 CLI 옵션과 같습니다.
- 경로 입력은 `--root` 안에서만 받습니다. 심볼릭 링크를 풀어 밖을 가리키면 거부합니다.
- 에이전트는 시험 명령을 직접 넘길 수 없고, 서버 설정에 정의된 `test_presets`의 이름만 고를 수 있습니다. 서버 설정 파일이 점검 폴더 안에 있으면 서버를 띄우지 않으며, 저장소 안의 설정은 시험 명령과 실행 이미지의 근거로 쓰지 않습니다.
- `verify_patch`에 `regression_spec`을 주면 정적 지적이 사라졌는지와 별도로 결함 행동이 사라졌는지(원본 실패·수정본 통과·되돌린 코드 실패)를 돌려줍니다.

**훅으로 자동 점검하기**

| 대상 | 설정 | 동작 |
|---|---|---|
| Claude Code | [docs/ci/claude-code-settings.json](docs/ci/claude-code-settings.json)의 `hooks`를 `.claude/settings.json`에 넣습니다 | 파일을 고칠 때마다 `iron-laws hook claude-code`가 그 파일을 점검하고, HIGH 이상 지적이 있으면 지적과 고치는 방법을 에이전트에게 돌려줍니다(종료코드 2). PostToolUse 입력 형식은 Claude Code 2.1.296으로 시험했습니다. |
| pre-commit | [docs/ci/pre-commit-config.yaml](docs/ci/pre-commit-config.yaml) | 커밋 전에 `iron-laws check .`를 실행하고 HIGH 이상 지적이 있으면 커밋을 막습니다. pre-commit 4.3.0으로 시험했습니다. |
| GitHub Actions | [docs/ci/github-actions.yml](docs/ci/github-actions.yml) | SARIF를 Code Scanning에 올리고 HIGH 이상이면 실패합니다. |
| GitLab CI | [docs/ci/gitlab-ci.yml](docs/ci/gitlab-ci.yml) | merge request Code Quality 위젯에 지적을 표시합니다. |

## 점검 영역 (규칙 104개)

| 분류 | 내용 | 근거 표기 |
|---|---|---|
| 기준 규칙 (IL-1xx, 3xx, 5xx) | 행안부 구현단계 49개 항목 전체: SQL·명령어·경로·코드 삽입(압축 해제 경로 조작, SpEL·OGNL 표현식 포함), XSS, SSRF, XXE, 하드코딩된 비밀, 취약 암호, 인증서 검증 해제, 오류 처리, 역직렬화, 메모리 안전성 등 | 항목 번호와 CWE |
| AI 코드 보정 (AI-1xx) | 하드코딩 설정값, 비밀 기본값 폴백, 프런트엔드 노출 비밀, 커밋된 `.env`, CORS, Supabase RLS·Firebase 규칙, Docker·CI 위험 설정, 의존성 오타·미고정, 민감정보 로깅, IDOR, 쿠키 속성 | 오철칙 자체 규칙 |
| 구조 (ARC-2xx) | 과대한 함수·파일, 요청 처리기의 DB 직접 접근, 계층 위반과 의존 방향 위반(하위 계층이 상위 계층을 import, 컨트롤러가 서비스 없이 저장소 호출, 컨트롤러·서비스의 DB 드라이버 직접 사용, 서비스·저장소의 웹 프레임워크 의존), 순환 의존, 중복·유사 함수, 반복된 문자열 상수, 테스트 부재 | 오철칙 자체 규칙 |
| AI 에이전트 공격면 (AIA-1xx) | AI 코딩 도구 규칙 파일(`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.mdc` 등)에 사람 눈에 안 보이는 문자로 숨긴 지시와 비밀 유출·무단 실행을 시키는 문장, MCP 서버 설정의 버전 미고정 실행·평문 비밀·원격 서버 인증 누락, `trust_remote_code=True`와 위험한 모델 불러오기, LLM 응답을 검증 없이 실행·명령·SQL에 쓰는 코드, 웹 입력이 시스템 지시 자리에 들어가는 코드, MCP 서버 도구 설명의 숨은 지시와 무검증 경로·명령 인자 | 오철칙 자체 규칙, OWASP LLM·Agentic 참조 |
| 성능 (PERF-1xx) | 한 함수의 DB 조회 과다, 중첩 반복과 반복 안의 리스트 찾기, 반복 안의 인터넷 요청·`await` 순차 대기, 한도 없는 `SELECT`, 비동기 함수 안의 막는 호출 | 오철칙 자체 규칙. 모두 `확인 필요` 등급 |
| 타입 안전성 (TYP-3xx) | TypeScript `any`·`@ts-ignore`·`tsconfig` 느슨함, Python `type: ignore`·`cast`, Java 원시 타입, C# `dynamic`·`#nullable disable`, Go·Rust·C++·PHP·JS의 타입 우회 | 오철칙 자체 규칙 |

참고한 공개 가이드(행안부 SW 개발보안 가이드)의 항목과 대응하는 규칙에는 항목 번호를 붙이고, OWASP Top 10:2025·OWASP 에이전트 Top 10 2026·CWE Top 25 2025·국가정보원 AI보안 가이드북(2025)의 대응 항목은 보고서 `standards`와 `iron-laws coverage --standard`로 함께 보여 줍니다(대응표는 각 판본 원문과 대조해 확인했고, 판본이나 대응이 바뀌면 다시 확인하기 전까지 `미확인`으로 표시). 그 밖에 대응이 없는 규칙은 보고서에 `오철칙 자체 품질 규칙 (참고 가이드 항목 외)`로 구분 표기합니다.
49개 항목 모두에 점검 규칙이 있으며(2-16 인증시도 제한은 IL-532), 설계단계 20개 항목도 구현 규칙과 대응시켜 `iron-laws coverage`와 마크다운 보고서에 보여 줍니다. 5-3, 5-4 등 일부 항목은 C/C++에만 적용됩니다. `지적 없음`은 탑재된 규칙 범위에서 발견되지 않았다는 뜻입니다.

### 지원 언어

| 수준 | 언어 | 내용 |
|---|---|---|
| 깊게 | Python, JavaScript/TypeScript, Java, C#, Go, PHP | 구문 분석, 외부 입력 추적(함수 안 분기 합류·객체 필드 한 단계·같은 파일 도우미 함수), 파일 간 추적(Python, JavaScript/TypeScript, Java static·주입 필드, Go 같은 패키지·import, PHP require·static), 전체 규칙 |
| 기본 | Kotlin | 구문 분석, Spring `@RequestParam`·Ktor `call.parameters` 입력에서 명령·SQL 등 JVM 싱크까지의 추적 |
| 제한 | Rust, C/C++ | 오류 처리, 메모리·포맷 문자열·API, 타입 우회 |
| 설정·정의 파일 | SQL, YAML, JSON, `.env`, Dockerfile, Compose, GitHub Actions, XML(MyBatis), HTML 템플릿 | 비밀, 접근 규칙(RLS·Firebase), 배포 설정, 템플릿 이스케이프 |

---

## 의존성 취약점과 구조 진단

**취약한 의존성: `iron-laws deps`**

`uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`(`==` 고정)에 적힌 버전이 알려진 취약점 권고(OSV)에 걸리는지 보고, 어느 버전 이상으로 올리면 그 권고가 사라지는지 알려 줍니다.

```bash
# 권고 목록을 한 번 받아 둔다(에코시스템별 all.zip)
mkdir -p osv/PyPI osv/npm
curl -o osv/PyPI/all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
curl -o osv/npm/all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip

iron-laws deps . --advisory-db osv                 # 마크다운 보고서
iron-laws deps . --advisory-db osv --format prompt # 코딩 AI에 붙여넣을 업그레이드 지시문
iron-laws deps . --advisory-db osv --fail-on high  # HIGH 이상 권고가 있으면 종료코드 1
```

- 점검 중에는 네트워크를 쓰지 않고 코드나 의존성 목록을 어디로도 보내지 않습니다. 권고 목록은 직접 받아 둔 파일을 씁니다.
- `--reachability`를 붙이면 권고가 영향 함수를 알려 줄 때 코드가 그 함수를 부르는지 봅니다(`reachable`·`no_evidence`·`undetermined`). `no_evidence`는 호출을 찾지 못했다는 뜻이지 영향이 없다는 뜻이 아닙니다.
- `--format openvex`는 OpenVEX 0.2.0 문서를 씁니다. 자동으로는 `affected`(영향 함수 호출 확인)와 `under_investigation`만 쓰고, `not_affected`는 `--vex-decisions`로 준 사람의 판정 기록에 OpenVEX justification이 있을 때만 씁니다.
- "수정 경계"는 권고가 말하는 수정 버전입니다. 그 버전이 앱과 호환된다는 보증이 아니므로, 올린 뒤 테스트를 돌리십시오. 직접 의존인지 간접 의존인지, 어떤 패키지가 끌어오는지 함께 보여 줍니다.
- 권고가 Git 커밋 범위만 주거나 해석할 수 없으면 "영향 여부 판정 불가"로 따로 표시합니다. 영향이 없다는 뜻이 아닙니다.
- 잠금 파일이 없으면 버전을 알 수 없어 점검하지 않습니다.

**SBOM: `iron-laws sbom`**

잠금 파일로 CycloneDX 1.6 또는 SPDX 2.3 JSON SBOM을 만듭니다. 구성요소는 package URL로 적고, 의존 관계는 잠금 파일이 알려 주는 버전 단위 관계만 씁니다(npm은 실제 설치 위치 해석 순서, pnpm은 버전별). `requirements.txt`처럼 관계 정보가 없는 입력은 관계를 추정하지 않고 비워 둡니다.

```bash
iron-laws sbom . --format cyclonedx -o sbom.cdx.json
iron-laws sbom . --format spdx -o sbom.spdx.json --timestamp 2026-10-12T00:00:00Z
```

**존재하지 않는 패키지 이름: `--package-index`**

AI가 지어낸 패키지 이름은 나중에 누군가 같은 이름으로 악성 패키지를 올리면 그대로 설치됩니다. 레지스트리의 전체 이름 목록을 받아 오프라인 색인으로 만들어 두면, `check`·`audit`가 `package.json`, `requirements*.txt`, `pyproject.toml`과 잠금 파일(직접·간접 의존 모두)의 이름을 색인과 맞춥니다.

```bash
# PyPI 전체 이름 목록(PEP 691 JSON)을 받아 색인으로 바꾼다
curl -H "Accept: application/vnd.pypi.simple.v1+json" -o pypi.json https://pypi.org/simple/
iron-laws index build --ecosystem pypi --source pypi.json --out pkg-index \
  --source-name "pypi.org/simple" --collected-at 2026-10-01T00:00:00Z --complete

iron-laws audit . --package-index pkg-index
```

- 색인에 없는 이름은 `확인 필요`(MEDIUM), 인기 패키지와 한 글자 다른 이름은 `확인 필요`(HIGH)로 알리며, 둘이 겹치면 한 지적으로 합칩니다.
- 최초 게시일이 들어 있는 목록이면 색인 수집 시각 기준 90일 이내에 처음 게시된 패키지도 알립니다. 기준이 실행 날짜가 아니므로 같은 색인이면 결과가 같습니다.
- `--complete`를 붙이지 않은 색인(일부 목록)이나 이 프로젝트가 쓰는 에코시스템의 색인이 없으면 "없는 이름"은 판정하지 않고 진단으로 알립니다. 색인 파일이 manifest.json의 sha256과 다르면 쓰지 않습니다.
- `workspace:`·`file:`·Git·URL 의존과 설정 `policies.private_packages`(예: `['@acme/*']`)에 맞는 사설 패키지는 공개 색인과 맞추지 않습니다.
- 코드의 import 이름도 맞춥니다: JavaScript·TypeScript는 npm 색인으로, Python은 모듈→배포 매핑 색인(`--ecosystem pypi-modules`, 한 줄에 `모듈 배포이름`)이 있을 때만 판정합니다. 표준 라이브러리·Node 내장 모듈·프로젝트 안의 모듈은 제외합니다.

**프로젝트 구조 진단: `iron-laws architecture`**

파일 단위 지적과 별개로, 프로젝트 전체의 구조 상태를 `양호`, `주의`, `붕괴`, `판정 불가`로 보여 주고 먼저 풀 문제와 단계별 개선안을 제시합니다. 판정 근거는 순환 의존 묶음의 크기, 많은 곳에서 불러 쓰면서 많은 곳을 부르는 허브 모듈, 큰 함수와 큰 파일의 비율, 계층 위반과 중복 함수 수, 테스트 모듈 비율입니다.

```bash
iron-laws architecture .                          # 진단과 단계별 개선안
iron-laws architecture . --format prompt          # 먼저 풀 문제 한 단계를 코딩 AI 지시문으로
iron-laws architecture . --format json -o now.json
iron-laws architecture . --compare before.json    # 이전 진단과 지표 비교
```

개선안은 한 번에 갈아엎지 않고 "순환 끊기 → 허브 쪼개기 → 큰 함수 나누기"처럼 작은 단계로 나뉩니다. 지표는 구조의 한 단면이며 설계가 좋은지 나쁜지를 보증하지 않습니다.

---

## 편집기·검토 보조

- **LSP 서버** `iron-laws lsp`: 편집기에 연결하면 파일을 열거나 고칠 때마다 그 내용을 점검해 진단으로 보여 줍니다(저장하지 않은 내용 포함, 파일 한 개 단위).
- **LLM 검토 의견** `check`·`audit --triage-model "<명령>"`: '확인 필요' 지적을 지정한 LLM 명령에 묶어 보내고 의견(`likely_true`·`likely_false`·`unsure`)을 보고서의 `review_opinion`에만 담습니다. 판정·심각도·통과 여부는 바꾸지 않으며, 보내는 코드는 비밀값을 가린 조각입니다.
- **AI 습관 추이** `iron-laws habits`: 점검마다 다섯 습관(하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피)의 1천 줄당 지적 수를 `.iron-laws-habits.jsonl`에 기록하고 처음·직전·최근 값을 보여 줍니다. 코드·경로는 기록하지 않습니다.

## 감리 대응 보고서

`iron-laws audit . --format mois-report -o 감리대응.md`는 행안부 구현단계 49개 항목별로 지적, 잔존(억제 주석의 사유·만료일, 승인 기록), 미점검 사유(규칙 미탑재·수동 확인 항목, 근거 장부의 공백, 건너뛴 파일)를 정리합니다. 출력 파일을 `.docx`로 주면 Word 문서로(선택 의존성 `pip install 'iron-laws[docx]'`), `.hwpx`로 주면 한글 문서로(선택 의존성 `pip install 'iron-laws[hwpx]'`, 한글 프로그램 없이 만듭니다) 씁니다.

## 쉬운 설명과 수정 지시문

모든 지적에는 세 가지가 붙습니다: 무슨 문제인지, 왜 위험한지(쉬운 말), 어떻게 고치는지. `fix-prompt`는 지적을 심각도 순으로 모아 코딩 AI에게 줄 지시문으로 바꿉니다. 지시문에는 "오류를 조용히 삼키지 않는다, 비밀을 코드에 쓰지 않는다, 타입 검사를 덮지 않는다, 중복 함수를 새로 만들지 않는다" 같은 수정 원칙이 함께 들어갑니다.

## 프로젝트 고유의 입력·위험 함수 알려 주기

사내 프레임워크의 입력 함수나 명령 실행을 감싼 함수처럼 오철칙이 모르는 것은 사용자 명세로 더합니다. 초안은 코드에서 후보를 찾아 만들고(`--llm-cmd`로 LLM 제안을 더할 수 있습니다), 사람이 각 항목에 지적되어야 하는 코드(`positive`)와 지적되지 않아야 하는 코드(`negative`)를 채웁니다. 모든 예제가 기대대로 판정될 때만 불러오며, 하나라도 어긋나면 점검을 시작하지 않습니다.

```bash
iron-laws spec draft . -o iron-laws-spec.yml      # 후보 초안(예제는 비어 있음)
iron-laws spec check iron-laws-spec.yml           # 예제 확인(어긋나면 종료코드 1)
iron-laws spec check iron-laws-spec.yml --against .   # 적용 전후 비교(저장소를 주면)
# .iron-laws.yml
# policies:
#   custom_spec: iron-laws-spec.yml
```

명세는 소스·싱크·정제 함수를 더한다. 더하는 것만으로는 지적이 줄지 않는다. 줄게 할 수 있는 것은 정제 함수 선언뿐이라, 적용 전에 같은 저장소를 같은 조건으로 두 번 돌려 비교한다. `--against`는 기준 스캔(명세 없음)과 후보 스캔(명세 적용)의 차를 본다.

| 판정 | 뜻 | 종료코드 |
|---|---|---|
| `ok` | 탐지가 줄지 않았다 | 0 |
| `review` | 정제 함수 선언 때문에 사라진 지적이 있어 사람이 확인해야 한다 | 1 |
| `blocked` | 사유 없는 감소·점검 불완전 등 채택하면 안 되는 상태다 | 1 |

비교 결과는 보고서와 별개 산출물이다(`--format console|markdown|json`, `--output`). 계약 언어와 장부 계열 밖은 대조하지 않고, 명세에 그 밖의 계열 항목이 있으면 그 사실을 결과에 밝힌다.

명세를 적용한 상태에서 근거 장부를 돌릴 때 명세의 싱크를 장부 지점으로 반영하고 싶으면 `policies.ledger_include_spec_points: true`를 켠다(기본은 꺼짐). 켜면 명세가 더한 싱크가 장부 지점으로 나타나고 장부 상태가 바뀔 수 있다. 명세가 선언한 정제 함수에 기대는 지점은 근거 종류가 `declared_sanitizer`로 표시되며, 선언이 사실을 대신하지 않는다는 사실이 장부 한계에 남는다. 명세의 내용은 `digests.spec` 지문으로 기록되어 명세가 바뀌면 실행 식별자(`run_id`)가 달라진다.

## 교훈 저장소

채택한 명세와 규칙에 대해 무엇을 왜 넣었는지 남겨 두면 다음 초안과 검토에 그대로 쓸 수 있다. 소스 코드는 저장하지 않고 판단의 근거가 되는 이름·조건·이유만 남긴다. 기록은 추가 전용으로 해시로 이어 붙으므로 지워지지 않고 무엇이 언제 왜 들어왔는지 남는다.

```bash
iron-laws experience add --spec iron-laws-spec.yml --lesson "이 저장소는 내부 API 응답을 이미 정규화한 뒤 셸에 넘긴다"
iron-laws experience add --rule IL-504 --lesson "인자 배열로 넘기면 셸 해석이 없다"
iron-laws experience list --rule IL-504            # 남겨 둔 교훈 보기
iron-laws experience invalidate E-9f3a2b1c4d5e6 --reason "정규화 함수가 바뀌었다"
iron-laws experience verify                        # 기록 연결이 온전한지 확인
```

`iron-laws explain IL-504`는 그 규칙에 붙은 교훈을 함께 보여 주고, `iron-laws spec draft --llm-cmd`는 관련 교훈을 지시문에 넣어 준다. 규칙 버전이나 명세 내용이 바뀌면 그 교훈은 `stale`(다시 볼 것)로 표시된다.

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
policies:
  ledger_include_spec_points: false   # 켜면 사용자 명세의 싱크를 검사 공백 장부에도 반영
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

GitLab에서는 `audit --format gitlab-codequality`로 merge request의 Code Quality 위젯에 지적을 표시합니다. 예시는 [docs/ci/gitlab-ci.yml](docs/ci/gitlab-ci.yml)에 있습니다. 지문은 기준선과 같은 지문을 써서 코드가 같으면 같은 지적으로 이어집니다.

---

## 한계

- 실행 순서를 따르는 흐름 분석(분기·반복·예외를 합쳐서 판정)은 함수 안에서 합니다. 도우미 함수는 호출 깊이 4단계까지 따라가고, 파일 사이 호출은 Python·JavaScript/TypeScript·Java·Go·PHP에서 import·require·static 호출·주입 필드를 따라 해석합니다(해석 횟수 상한 있음). 상속·추상 메서드·리플렉션을 거치는 호출과 한도에 걸린 경로는 놓치거나 `확인 필요`·검사 공백으로 남습니다. 정제 함수는 자기가 막는 문맥(HTML·SQL·셸·경로 등)에서만 인정합니다.
- 안전 조건(허용 목록 검사·경로 범위 검사)은 검사가 모든 경로에서 싱크 앞에 실행되고 검사한 값이 싱크까지 바뀌지 않을 때만 인정합니다. 갈래마다 따로 검사하는 코드(한 갈래는 허용 목록, 다른 갈래는 범위 검사)처럼 경로별로 안전한 경우는 알아보지 못해 확정 지적이 남을 수 있습니다. 독립 검증기는 구조적 모순만 잡고 엔진이 일관되게 만든 의미 오류는 잡지 못합니다.
- 통과 결과만으로 배포를 승인하지 마십시오. 기존 테스트, 코드 검토, 다른 보안 점검과 함께 쓰는 보조 도구입니다.
- 비밀값이 들어 있는 코드 줄은 모든 보고서와 AI 수정 지시문에서 값을 가려서(`****`) 출력합니다. 다만 규칙이 비밀로 인식하지 못한 값까지 가려 주는 것은 아니므로 지시문을 외부 AI에 붙여넣기 전에 한 번 읽어 보십시오.
- 정확도 수치와 측정 방법은 [docs/ACCURACY.md](docs/ACCURACY.md), 언어·규칙별 검증 현황은 [docs/SUPPORT_MATRIX.md](docs/SUPPORT_MATRIX.md), 보고서 형식과 호환 정책은 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)에 있습니다. OWASP Benchmark(Java) 확정 점수는 XSS +53.5%, 취약 암호 +76.7%인 반면 SQL 삽입은 +33.2%, 명령어 삽입은 +17.2%에 그칩니다. 안전하게 가려진 사례에서 오탐이 남기 때문입니다. 실제 오픈소스 CVE(CWE-Bench-Java)에서는 경로 조작 재현율이 35%이고, 명령 삽입·XSS·코드 삽입은 확정 지적으로 잡지 못했습니다(ACCURACY §6.4).
- 성능 규칙(PERF)은 코드의 모양만 봅니다. 데이터 크기와 실제 느림은 재지 못하므로 모두 `확인 필요` 등급이며, 지적된 줄이 정말 큰 데이터를 도는지 직접 확인해야 합니다. 편집 거리 같은 표 채우기 알고리즘처럼 곱 크기가 본래 필요한 반복도 지적될 수 있습니다. 측정 결과는 [docs/ACCURACY.md](docs/ACCURACY.md) §5입니다.
- 존재하지 않는 패키지 이름(AI의 허위 의존성)은 `--package-index`로 레지스트리 색인을 준 경우에만 판정합니다. 색인이 없으면 인기 패키지와 철자가 비슷한 이름만 지적합니다.

## 참고 문서와 이용 조건

점검 항목은 작성자의 SI 감리 경험을 바탕으로 정리했고, 항목 번호는 아래 공개 문서를 참고 표기했습니다.

- 행정안전부 「소프트웨어 개발보안 가이드」(2021.11): 공공데이터포털 이용허락범위 제한 없음, 한국인터넷진흥원 게시본은 공공누리 제1유형(출처표시). 항목 번호·명칭과 CWE 대응만 데이터로 옮겼고 본문과 예제 코드는 포함하지 않습니다. 출처: 행정안전부, 한국인터넷진흥원.
- 국가정보원 「국가 사이버보안 기본지침」 제13조제2항 누출금지정보 항목명 (국가사이버안보센터 공개 문서).

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
