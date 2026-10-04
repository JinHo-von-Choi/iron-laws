# 정확도 측정 기록

이 문서는 오철칙의 탐지 정확도를 측정한 방법과 결과, 그리고 한계를 있는 그대로 기록한다.

## 1. 규칙별 사례 시험

`tests/` 아래에 규칙마다 양성(탐지해야 함)과 음성(탐지하면 안 됨) 사례를 언어별로 둔다.
- `test_rule_cases.py`: 행안부 구현단계 규칙(주입, 암호, 오류 처리, 메모리 등) 209건
- `test_ai_arch_typing_cases.py`: AI 생성 코드 보정, 구조, 타입 안전성 규칙 88건
- `test_regressions.py`: 실제 프로젝트 점검과 벤치마크에서 발견한 오탐·미탐을 고정한 회귀 사례와 억제·생성 파일·CLI 형식 시험
- `test_plan_features.py`: 분기 합류·반복 흐름, 문맥별 정제, 파일 간 해석, 진단, 기준선, 억제 만료, 설정 선택, 근거(evidence), 지원 행렬 시험
- `test_review_findings.py`: 외부 평가에서 재현된 결함(잘못된 입력의 통과 처리, 억제 구문 오인식, 싱크 시점의 변수 상태, API 인자 위치, XXE 설정 값, 템플릿 연결, 출력 안전성)을 전체 CLI 경로로 고정한 시험

사례는 실제 점검에서 확인한 오탐을 바탕으로 계속 늘린다.

## 2. 실제 프로젝트 점검을 통한 오탐 정리

Java, JavaScript, Python, C#, Go, Rust, PHP, C/C++ 오픈소스·자체 프로젝트 수천 개 파일을 점검해 CRITICAL·HIGH 지적을 직접 분류했다.
이 과정에서 다음을 고쳤다.
- 압축·생성 파일과 빌드 산출물 제외
- 명령행 인자(argv, stdin)를 웹 입력과 구분 (개발 도구 스크립트의 오탐 제거)
- 브라우저 스크립트의 `fetch`를 SSRF로 보던 오탐 제거
- 환경변수 이름 상수, 비밀 값 참조(`$VAR`)를 비밀로 보던 오탐 제거
- DDL, EF Core 보간 쿼리, 요청 본문 스트림 같은 안전한 패턴 제외
- 속성 이름(`import.meta.url`)이 변수로 오염되던 문제 수정

## 3. OWASP Benchmark v1.2 (Java, 2,740개 테스트)

측정 대상은 BenchmarkJava 커밋 `8b67a88d73b2594570fc21150705283de884620b`이다. 측정 도구는 `benchmarks/owasp_benchmark.py`이다. 점수는 `TPR - FPR`이다.
`확정`은 외부 입력 도달이 코드에서 확인된 지적만 센 결과, `전체`는 확인 필요 지적까지 센 결과다.

| 분류 | 확정 TPR | 확정 FPR | 확정 점수 | 전체 점수 |
|---|---|---|---|---|
| SQL 삽입 (sqli) | 75.0% | 49.1% | +25.9% | +5.6% |
| XSS (xss) | 86.2% | 41.1% | +45.0% | +45.0% |
| 명령어 삽입 (cmdi) | 50.8% | 36.8% | +14.0% | +14.0% |
| 경로 조작 (pathtraver) | 88.7% | 62.2% | +26.5% | +26.5% |
| LDAP 삽입 (ldapi) | 88.9% | 53.1% | +35.8% | +0.0% |
| XPath 삽입 (xpathi) | 93.3% | 70.0% | +23.3% | +0.0% |
| 취약 암호 (crypto) | 100.0% | 23.3% | +76.7% | +76.7% |
| 취약 해시 (hash) | 69.0% | 0.0% | +69.0% | +69.0% |
| 쿠키 보안 속성 (securecookie) | 0.0% | 0.0% | 0.0% | +100.0% |
| 신뢰 경계 (trustbound) | 78.3% | 74.4% | +3.9% | +3.9% |
| 예측 가능한 난수 (weakrand) | 0.0% | 0.0% | 0.0% | 0.0% |

### 해석과 한계
- OWASP Benchmark는 안전한 사례를 일부러 도우미 클래스, 상수로 결정되는 분기, 컬렉션 경유로 감춰 정적 분석의 오탐을 유도한다. 오철칙은 함수 안의 흐름(분기 합류, 같은 파일 도우미 함수 요약, 문맥별 정제 함수 이름 인식)과 Python의 파일 간 호출만 추적하고, Java 등의 파일 사이 호출과 상수 조건 계산은 하지 않는다. 그래서 FPR이 높다.
- `weakrand` 0%는 의도한 결과다. 오철칙은 토큰·인증번호처럼 보안 문맥에서 쓰인 난수만 지적하며, 문맥 없는 `Random`은 지적하지 않는다.
- `securecookie`는 Secure·HttpOnly 누락 여부를 사람이 확인해야 해서 `확인 필요`로만 보고한다.
- 함수 안의 흐름은 실행 순서를 따르며, 분기(if·switch·try)는 갈래별로 실행해 합치고 반복문은 두 번 돌려 반복 간 전달을 반영한다. 한 갈래에서만 안전하게 바뀐 변수는 오염된 채로 남고, 모든 갈래에서 안전하게 바뀐 변수만 깨끗해진다. 완전한 제어 흐름 그래프나 상수 조건 계산은 하지 않는다(OWASP Benchmark 오탐의 주된 원인).
- 같은 파일의 도우미 함수는 호출부에서 외부 입력이 매개변수로 넘어갈 때 함수 안의 싱크까지, 반환값이 오염되는지까지 추적한다(호출 깊이 4단계, 재귀·순환 import는 보수적으로 오염으로 본다). Python은 import를 따라 다른 파일의 함수도 같은 방식으로 추적한다(시범 지원, `limits.max_cross_file_lookups`가 상한이며 넘으면 진단으로 남긴다). Java 등 다른 언어는 파일을 넘는 추적이 없다.
- 이 측정에서 파일 간 해석과 분기 합류 도입 전후의 OWASP Benchmark 수치는 같았다(Benchmark는 한 파일 안에서 완결되는 사례라 새로 잡은 경로와 새 오탐이 모두 0건). 새 기능의 효과는 §1의 사례 시험과 실제 프로젝트 점검(WebGoat 도우미 함수 안 SQL 삽입 4건 신규 탐지, DVWA에서 이스케이프된 입력 7건이 CRITICAL에서 확인 필요로 하향)으로만 확인했다.
- 정제 함수는 프로젝트에 정의되어 있으면 이름이 아니라 본문 동작을 따르고, 외부 라이브러리 함수는 이름으로 판단하되 **도달하는 곳의 문맥(HTML·SQL·셸·경로·URL·LDAP·XPath·헤더)에 유효한 정제만** 인정한다. HTML 이스케이프는 SQL 삽입·명령어 삽입을 막지 못하고, `normalize`·`abspath`는 경로 이탈 검사 없이는 정제로 보지 않는다. 다만 이름이 맞다고 해서 실제로 안전한 것은 아니다(예: 따옴표 없는 숫자 문맥에서의 SQL 이스케이프).
- 이 결과는 Java에만 해당한다. 다른 언어는 §1의 사례 시험과 §2의 실제 프로젝트 점검으로만 확인했고, 공개 벤치마크 수치는 아직 없다.
- 이 수치를 국정원 인증 도구의 정확도와 비교하거나 감리 증빙으로 쓰면 안 된다.

## 4. 패치 검증 기능의 표본 측정

근거 계약·패치 검증·회귀시험·승인 추적의 표본 측정은 [docs/PATCH_VERIFICATION.md](PATCH_VERIFICATION.md) §6과 `docs/benchmark_results/plan_experiments.json`에 있다. 구현자가 직접 분류한 표본이며 독립 검토나 실사용 파일럿 결과가 아니다. 위 OWASP Benchmark(Java) 수치는 이번 변경 전후로 같다(새 기능은 Python 중심이다).

## 5. 재현

측정은 도구 버전, 데이터 커밋, 명령, 원시 건수(TP·FN·FP·TN)를 함께 남긴다. 이번 측정의 원시 결과는 `docs/benchmark_results/owasp_confirmed.json`, `owasp_all.json`이다.
점수 비교는 같은 데이터 커밋에서만 한다. 한 언어의 점수를 전체 정확도로 합산하지 않는다.

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
git -C BenchmarkJava checkout 8b67a88d73b2594570fc21150705283de884620b
uv run python benchmarks/owasp_benchmark.py BenchmarkJava confirmed docs/benchmark_results/owasp_confirmed.json
uv run python benchmarks/owasp_benchmark.py BenchmarkJava all docs/benchmark_results/owasp_all.json
```

처리 시간과 최대 메모리는 같은 장비·같은 저장소에서 수정 전후를 비교해 기록한다. 이번 변경(흐름 분석 교체, 파일 간 해석)의 측정: flask(소스 약 5천 파일 규모) 4.9초 → 5.4초, WebGoat 8.9초 → 9.3초, 최대 메모리 약 80~120MB로 큰 차이가 없었다. 속도 향상을 약속하지 않는다.
