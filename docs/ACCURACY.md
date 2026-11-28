# 정확도 측정

오철칙의 탐지 정확도를 잰 방법, 결과, 한계다. 점수는 같은 데이터·같은 판끼리만 비교하고, 한 언어의 점수를 전체 정확도로 합치지 않는다.

## 1. 규칙별 사례 시험

`tests/` 아래에 규칙마다 양성(잡아야 하는 코드)과 음성(잡으면 안 되는 코드) 사례를 언어별로 둔다. 양성·음성이 모두 있는 (규칙, 언어) 조합이 '검증'이며, 현황은 [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md)에 있다.

| 파일 | 다루는 것 |
|---|---|
| `test_rule_cases.py` | 행안부 구현단계 규칙(삽입, 암호, 오류 처리, 메모리 등) |
| `test_ai_arch_typing_cases.py` | AI 코드 보정, 구조, 타입 안전성 규칙 |
| `test_support_cells.py` | 한쪽 사례만 있던 규칙×언어 칸, TypeScript 칸 |
| `test_go_php_cases.py` | Go·PHP 외부 입력 흐름과 정제, Kotlin, Go·PHP 파일 간 호출 |
| `test_field_flow.py` | 객체 필드·상수 키 단위의 오염 구분 |
| `test_archive_paths.py` | 압축 해제 경로 조작(Zip Slip), 프레임워크 요청 경로, Java 응답 출력 XSS |
| `test_spel_injection.py` | SpEL·OGNL 표현식 삽입의 확정·확인 필요·지적 없음 |
| `test_regressions.py` | 실제 점검과 벤치마크에서 찾은 오탐·미탐, 억제·생성 파일·CLI 형식 |
| `test_plan_features.py` | 갈래·반복 흐름, 문맥별 정제, 파일 간 해석, 진단, 기준선, 억제 만료, 설정 선택, 근거(evidence) |
| `test_review_findings.py` | 외부 평가에서 재현된 결함을 CLI 전체 경로로 고정한 시험 |
| `test_flow_definitions.py` | 입력 원천·싱크·정제 정의마다 지적해야 할 코드와 지적하지 말아야 할 코드 |
| `test_auth_flow.py`, `test_auth_flow_cases.py` | 인증 흐름·소속 경계·세션·감사 기록·지원 종료 규칙 |

## 2. 실제 프로젝트

Java, JavaScript, Python, C#, Go, Rust, PHP, C/C++ 오픈소스 프로젝트 수천 개 파일의 CRITICAL·HIGH 지적을 사람이 하나씩 분류했다. 여기서 나온 오탐 유형은 다음처럼 처리한다.
- 압축·생성 파일과 빌드 산출물은 점검하지 않는다.
- 명령행 인자(argv, stdin)는 웹 입력과 구분한다. 개발 도구 스크립트를 웹 취약점으로 지적하지 않는다.
- 브라우저 스크립트의 `fetch`는 SSRF로 보지 않는다.
- 환경변수 이름 상수와 비밀 값 참조(`$VAR`)는 비밀로 보지 않는다.
- DDL, EF Core 보간 쿼리, 요청 본문 스트림은 안전한 패턴으로 본다.
- 속성 이름(`import.meta.url`)은 변수로 보지 않는다.

### 실측 순환 프로젝트

`benchmarks/realworld/projects.json`의 고정 커밋 프로젝트를 점검하고, 이전 기록과 달라진 보안 지적을 사람이 분류한다(`benchmarks/realworld_loop.py`). 커밋이 고정되어 있으므로 지적이 달라지면 오철칙이 바뀐 것이다.

| 프로젝트 | 지적 | 공개 API 모드에서 늘어나는 `확인 필요` |
|---|---:|---:|
| WebGoat | 526 | 18 |
| NodeGoat | 42 | 0 |
| juice-shop | 1,279 | 11 |
| spring-petclinic | 16 | 0 |

- WebGoat `SerializationHelper.java:23`의 역직렬화는 `확인 필요`다. 데이터가 메서드 매개변수이고 프로젝트 안에 이 메서드를 부르는 곳이 없어 출처를 알 수 없다. 요청 값을 역직렬화하는 `InsecureDeserializationTask.java:45`는 확정이다.
- juice-shop `server.ts:271`(`path.resolve`)·`:276`(`fs.readFile`)의 `확인 필요` 2건은 오탐이다. 정규화한 경로를 구분자 없이 `startsWith`로 기준 폴더와 비교해서 `확인 필요`로 냈지만, 경로가 `/`로 시작하는 `req.path`를 `path.normalize`로 정리한 값이라 기준 폴더 밖으로 나가지 못한다.
- 공개 API 모드에서 늘어나는 지적은 모두 `확인 필요`이고, 확정 지적은 두 모드가 같다.

## 3. OWASP Benchmark v1.2 (Java, 2,740개 테스트)

- 데이터: BenchmarkJava 커밋 `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`
- 측정 도구: `benchmarks/owasp_benchmark.py`, 측정 판: CHANGELOG의 Unreleased
- 저장소 루트를 점검해 도우미 클래스(`helpers`)와 설정 파일(`src/main/resources/benchmark.properties`)까지 분석하고, 채점은 `testcode` 아래 사례 파일만 한다.
- 점수 = TPR(취약 사례를 잡은 비율) − FPR(안전 사례를 잘못 잡은 비율)
- `확정`은 외부 입력이 닿는 것이 코드에서 확인된 지적만, `전체`는 `확인 필요` 지적까지 센 결과다.

| 분류 | 확정 TPR | 확정 FPR | 확정 점수 | 전체 점수 |
|---|---|---|---|---|
| SQL 삽입 (sqli) | 100.0% | 0.0% | +100.0% | +69.8% |
| XSS (xss) | 100.0% | 0.0% | +100.0% | +100.0% |
| 명령어 삽입 (cmdi) | 100.0% | 0.0% | +100.0% | +100.0% |
| 경로 조작 (pathtraver) | 100.0% | 0.0% | +100.0% | +100.0% |
| LDAP 삽입 (ldapi) | 100.0% | 0.0% | +100.0% | +56.2% |
| XPath 삽입 (xpathi) | 100.0% | 0.0% | +100.0% | +80.0% |
| 취약 암호 (crypto) | 100.0% | 0.0% | +100.0% | +100.0% |
| 취약 해시 (hash) | 100.0% | 0.0% | +100.0% | +100.0% |
| 쿠키 보안 속성 (securecookie) | 0.0% | 0.0% | +0.0% | +100.0% |
| 신뢰 경계 (trustbound) | 100.0% | 0.0% | +100.0% | +100.0% |
| 예측 가능한 난수 (weakrand) | 0.0% | 0.0% | +0.0% | +0.0% |

`전체` 점수가 확정보다 낮은 SQL·LDAP·XPath는 안전 사례의 값이 리플렉션(`ThingFactory`)으로 만든 객체를 거치거나, 상수를 돌려주는 도우미 메서드의 값을 라이브러리 함수(Base64 인코딩·디코딩 등)로 가공해 상수인지 계산하지 못한 것이다. 이런 값을 SQL 문자열에 이으면 `확인 필요`로 남는다. 이 벤치마크는 원인을 찾는 데도 쓰였으므로, 같은 모양을 다른 이름·구조로 쓴 반례를 `tests/test_flow_definitions.py`에 따로 둔다.

원시 결과는 `docs/benchmark_results/owasp_confirmed.json`, `owasp_all.json`이며, 사례별 판정이 `outcomes`에 있다.

### 해석과 한계
- OWASP Benchmark는 안전한 사례를 도우미 클래스, 상수로 정해지는 분기, 컬렉션 경유 같은 방법으로 일부러 감춰 정적 분석의 오탐을 끌어낸다. 오철칙은 상수 조건(if·조건식·switch), 같은 블록에서 만든 지역 List·Map(Python은 list·dict·configparser), 같은 파일에 하나뿐인 도우미의 상수 반환값을 계산해 실행되지 않는 갈래와 상수 원소를 뺀다. 리플렉션(`ThingFactory`)처럼 계산하지 않는 경로는 `확인 필요`로 남아 전체 점수에 반영된다.
- 도우미 클래스(`SeparateClassRequest`)로 입력을 읽는 사례는 지역 객체의 메서드 추적으로 잡는다. 같은 클래스의 `getTheValue`는 상수 `"bar"`를 돌려주므로 그 메서드를 쓰는 사례는 상수로 본다.
- `weakrand` 0%는 의도한 결과다. 오철칙은 토큰·인증번호처럼 보안 문맥에서 쓰인 난수만 지적하며, 문맥 없는 `Random`은 지적하지 않는다.
- `securecookie`는 Secure·HttpOnly 누락 여부를 사람이 확인해야 해서 `확인 필요`로만 보고한다.
- 함수 안의 흐름은 실행 순서를 따른다. 분기(if·switch·try)는 갈래마다 따로 따라간 뒤 합치고, 반복문은 두 번 돌려 다음 회차로 넘어가는 값을 반영한다. 한 갈래에서만 안전해진 변수는 오염된 채로 남고, 모든 갈래에서 안전해진 변수만 깨끗하다. 객체 필드와 상수 키는 한 단계까지 구분한다(`obj.field`, `d['k']`).
- 도우미 함수는 외부 입력이 매개변수로 넘어갈 때 함수 안의 위험 호출까지, 그리고 반환값이 오염되는지까지 따라간다. 호출 깊이는 4단계까지다. 4단계를 넘거나 상한에 걸린 함수는 깨끗하다고 보지 않고 인자의 오염이 반환값으로 이어진다고 본다. 재귀 호출은 오염된 인자가 넘어가면 오염으로 보고, 오염된 인자 없이 도는 재귀는 다른 반환 경로의 오염만 따른다.
- 다른 파일의 함수도 같은 방식으로 따라간다.

  | 언어 | 따라가는 호출 |
  |---|---|
  | Python | import |
  | JavaScript·TypeScript | ESM(named·default·namespace·재내보내기 1단계), CommonJS(`module.exports`, `exports.a`, `require` 구조분해), 상대 경로, tsconfig `paths` 단일 와일드카드 별칭 |
  | Java | 명시 import·같은 패키지·와일드카드 import로 찾은 클래스의 static 메서드, 주입 필드의 인스턴스 메서드(필드 형식이 클래스이거나, 구현이 하나 또는 `@Primary`가 하나인 인터페이스) |
  | Go | 같은 패키지의 다른 파일 함수, `go.mod` 모듈 경로와 맞는 프로젝트 폴더의 내보낸 함수 |
  | PHP | require·include한 파일의 함수, 프로젝트에서 하나뿐인 함수·클래스의 static 메서드 |

  Python과 Java는 지역 변수로 만든 객체(`w = mod.Cls(…)`, `Cls w = new Cls(…)`, Python `Cls(…).method()`)의 메서드도 그 클래스에서 찾는다. C#, Kotlin, Rust, C/C++는 파일을 넘어 따라가지 않는다.
- 후보가 둘 이상이거나 동적 `import()`·계산된 `require`처럼 대상을 정할 수 없으면 "찾지 못함"으로 세어 보고서 `metadata.cross_file.by_language`의 `resolution_gap_rate`에 남긴다. `limits.max_cross_file_lookups`는 위험 호출 하나를 판정할 때 다른 파일을 찾아가는 횟수 상한이며, 넘으면 진단으로 남긴다. 결과는 병렬 프로세스 수와 무관하다.
- 실제 프로젝트에서 확인한 효과: WebGoat의 도우미 함수 안 SQL 삽입 4건을 새로 잡았고, DVWA에서 이스케이프된 입력 7건이 CRITICAL에서 `확인 필요`로 내려갔다. 파일 간 추적으로 달라진 지적의 분류는 `docs/benchmark_results/xfile_js.json`, `xfile_java.json`에 있다.
- 정제 함수는 프로젝트에 정의되어 있으면 이름이 아니라 본문 동작을 따르고, 외부 라이브러리 함수는 이름으로 판단하되 **도달하는 곳의 문맥(HTML·SQL·셸·경로·URL·LDAP·XPath·헤더)에 유효한 정제만** 인정한다. HTML 이스케이프는 SQL 삽입·명령어 삽입을 막지 못하고, `normalize`·`abspath`는 경로 이탈 검사 없이는 정제로 보지 않는다. 다만 이름이 맞다고 해서 실제로 안전한 것은 아니다(예: 따옴표 없는 숫자 문맥에서의 SQL 이스케이프).
- 이 결과는 Java에만 해당한다. Python·C/C++·C#의 공개 벤치마크 결과는 §6에 있다.
- 이 수치를 국정원 인증 도구의 정확도와 비교하거나 감리 증빙으로 쓰면 안 된다.

- Java SQL 문자열이 상수인지는 상수로만 끝나는 분기, 프로젝트에 하나뿐인 static 도우미의 반환값, `java.util.List.of`와 상수 인덱스 `get`까지만 따진다. 객체 변경, 외부 호출로 넘긴 값, 이름이 같은 클래스·변수, 따라가지 못한 반환값은 상수로 보지 않는다.

## 4. 변형 사례집과 AI 수정 결과

근거 장부·패치 검증·회귀시험·승인 기록의 표본 측정은 [PATCH_VERIFICATION.md](PATCH_VERIFICATION.md) §6에 있다. 이 기능들은 위 OWASP Benchmark(Java) 수치에 영향이 없다.

### 4.1 의미 변형 사례집

정상·위험 코드 짝에 의미를 바꾸지 않는 변형 6종(이름 바꾸기, 주석 넣기, 빈 줄, 관련 없는 함수를 앞·뒤에 추가, 따옴표 모양)을 적용해 판정이 뒤집히는지 본다.

- 개발용(`tests/semantic_corpus.py`): 엔진을 고칠 때 보는 사례. flask·express·plain·plain-java 스타일.
- 평가용(`tests/semantic_holdout.py`): 엔진 조정에 쓰지 않는 사례. django·php-raw·spring·fastapi 스타일.
- 원본 수와 변형 수, 위험 탐지와 정상 유지는 합치지 않고 따로 적는다.

| 구분 | 원본 | 변형 | 위험 미탐 | 정상 오차단 | 판정 변화 | 확인 필요로만 나온 정상 |
|---|---|---|---|---|---|---|
| 개발용 검사 30쌍 | 위험 30·정상 30 | 위험 180·정상 180 | 0 | 0 | 0 | 42/210 |
| 평가용 검사 15쌍 | 위험 15·정상 15 | 위험 90·정상 90 | 0 | 0 | 0 | 7/105 |

- 승인 사례(개발용 6·평가용 3)는 위험한 승계 0, 불필요한 재검토 0이다. 출력·억제 사례(개발용 4·평가용 3)는 오처리 0이다.
- 평가용 사례가 실패하면 엔진을 고치고, 그 사례를 개발용으로 옮긴 뒤, 같은 유형의 새 평가용 사례를 만든다. 옮긴 사례 목록은 `tests/semantic_holdout.py`의 `MOVED_TO_DEV`에 있다.
- `확인 필요`는 판단을 보류한 것이다. 정상 사례에서는 따로 세고, 위험 변형이 `확인 필요`로만 나오면 잡은 것이 아니라 놓친 것으로 센다.
- 파일 경계를 넘는 변형 3종은 따로 잰다: ① 외부 입력을 다른 파일의 '그대로 돌려주는 함수'에 통과시키기, ② 두 파일을 거치는 함수 사슬에 통과시키기, ③ 외부 입력을 읽는 일 자체를 다른 파일의 함수로 옮기기. 적용할 수 없는 언어(Python·JavaScript·TypeScript 외)의 사례는 빼고 센다. 위험 변형 개발용 81건·평가용 21건을 모두 잡았고, 정상 변형(개발용 63건·평가용 21건)을 막은 경우는 없다. ③은 호출 지점에 입력이 드러나지 않아 파일 간 추적 없이는 잡을 수 없다.
- 라이브러리 경계를 넘는 변형 3종도 따로 잰다: ① 외부 입력을 다른 파일 클래스의 메서드로 읽기(`Incoming(request).read_args(key)`, Python만), ② 사전에 넣었다 꺼내기, ③ 문자열 분리·결합으로 다시 만들기. 위험 변형 개발용 78건·평가용 21건을 모두 잡았고 정상 변형(개발용 63건·평가용 21건)을 막은 경우는 없다. 지역 객체의 메서드 추적을 넣기 전에는 ①을 개발용 22건·평가용 7건 모두 놓쳤고, ②·③은 그때도 모두 잡았다.

### 4.2 실제 프로젝트 점검 시간과 재현성

오픈소스 Python·TypeScript·Go 프로젝트(파일 1,371개)와 Java·JavaScript 프로젝트(파일 2,940개)를 1.3.0으로 점검했다.
- 점검 시간은 각각 약 37초, 약 42초다.
- 에이전트 훅의 세션 함수 색인은 함수 약 1,300개인 프로젝트(이 저장소, juice-shop)에서 약 2~3초, 편집한 파일 하나의 새 중복 대조는 40ms 이하였다.
- Python 해시 시드를 바꿔도 결과가 같다(2,736건, 같은 목록).
- 보고서 모순 검사가 두 보고서에서 모순을 찾지 못했다.

### 4.3 수정 지시문 판에 따른 AI 수정 결과

회귀시험 표본 21건(명령 실행·경로 접근·SQL 조립 각 7건)을 두 판의 `fix-prompt` 지시문으로 AI에게 고치게 하고 결과를 비교했다.

- 1.5.0 지시문: 지적과 고치는 방법
- 1.6.0 지시문: 위에 더해 금지하는 수정(억제 주석, 시험 삭제, 예외 삼키기, 도우미 함수로 옮기기)과 규칙별 '이렇게 고치지 마세요 / 이렇게 고치세요' 예
- 수정안은 `benchmarks/fix_loop.py`의 분류로 검증했고, 결함 동작 제거는 확정한 회귀시험을 docker 격리 실행으로 판정했다.
- AI: Claude Code 2.1.296의 sonnet(도구 끔), 사례·판마다 응답 한 번
- 측정 도구 `benchmarks/fix_prompt_ab.py`, 원시 결과 `docs/benchmark_results/fix_prompt_ab.json`

| 지시문 | 해결 | 정적 지적 소멸 | 결함 동작 제거 | 결함 동작 제거(IL-501 / IL-502 / IL-504) | 새 지적 | 판정 불가 |
|---|---|---|---|---|---|---|
| 1.5.0 | 13/21 | 18/21 | 14/21 | 7/7 · 4/7 · 3/7 | 1 | 2 |
| 1.6.0 | 16/21 | 18/21 | 17/21 | 7/7 · 6/7 · 4/7 | 0 | 1 |

사례별로는 3건이 해결로 바뀌었고, 2건은 실패 유형만 바뀌었으며(정적 지적이 남음 ↔ 결함 동작이 남음), 해결에서 실패로 바뀐 사례는 없다. 표본이 작고, 응답을 한 번씩만 받았고, 모델 하나의 결과라서 이 차이를 지시문의 효과로 단정하지 않는다. 명령 실행은 두 판 모두 결함 동작 제거가 절반 남짓으로, 지시문만으로는 풀리지 않는다.

### 4.4 안내물에 따른 AI 수정 결과

같은 결함 표본 21건을 네 가지 안내물로 AI에게 고치게 하고 비교했다.

- 안내물: 수정 지시문(기준), 검토 묶음, MCP 도구 설명과 `check` 응답, 수정 지시문 + 검토 묶음
- 검증 방법은 §4.3과 같다.
- AI: Claude Code 2.1.304의 sonnet(파일·셸 도구 없음), 사례·안내물마다 응답 한 번
- 측정 도구 `benchmarks/artifact_ab.py`, 원시 결과 `docs/benchmark_results/artifact_ab.json`

| 안내물 | 해결 | 정적 지적 소멸 | 결함 동작 제거 | 결함 동작 제거(IL-501 / IL-502 / IL-504) | 새 지적 | 판정 불가 |
|---|---|---|---|---|---|---|
| 수정 지시문(기준) | 14/21 | 18/21 | 15/21 | 7/7 · 4/7 · 4/7 | 0 | 2 |
| 검토 묶음 | 9/21 | 12/21 | 15/21 | 7/7 · 5/7 · 3/7 | 0 | 1 |
| MCP 도구 설명 | 10/21 | 12/21 | 18/21 | 7/7 · 5/7 · 6/7 | 0 | 1 |
| 수정 지시문+검토 묶음 | 14/21 | 17/21 | 16/21 | 7/7 · 5/7 · 4/7 | 0 | 0 |

- 수정 지시문(기준)보다 해결이 많은 안내물은 없다.
- 검토 묶음과 MCP 도구 설명은 결함 동작 제거가 각각 15/21·18/21이지만, 정적 지적이 남거나 다른 검증에 걸리는 사례가 늘어 해결은 9/21·10/21로 기준(14/21)보다 낮다.
- 수정 지시문 + 검토 묶음은 해결 14/21로 기준과 같고, 결함 동작 제거는 16/21로 한 건 많다. 기준에서 해결이던 2건이 다른 결과로, 다른 결과이던 2건이 해결로 바뀌었다.
- 표본이 작고, 응답을 한 번씩만 받았고, 모델 하나의 결과라서 안내물 사이의 차이를 그 안내물의 효과로 단정하지 않는다.

### 4.5 구조 틀에 따른 AI 생성 결과

같은 FastAPI 기능 요청 6개(메모, 회원, 할 일, 재고, 북마크, 글·댓글)를 AI에게 틀 없이, 그리고 `init --stack fastapi`의 지침 절과 함께 시켰다.

- 기능 시험(pytest, TestClient)을 통과한 결과만 구조 지표로 비교한다. 생성된 코드는 네트워크 없는 컨테이너에서 돌린다.
- AI: Claude Code CLI의 sonnet(도구 끔), 과제·방식마다 응답 한 번
- 측정 도구 `benchmarks/blueprint_ab.py`, 기능 시험 이미지 `benchmarks/blueprint_ab.Dockerfile`, 원시 결과 `docs/benchmark_results/blueprint_ab.json`

| 방식 | 기능 시험 통과 | 라우터의 DB 직접 접근(ARC-202) | 순환(ARC-203) | 중복 함수(ARC-204) | 큰 함수(ARC-201) | 구조 계약 위반(ARC-207) | 파이썬 파일 수 |
|---|---|---|---|---|---|---|---|
| 틀 없음 | 6/6 | 6 | 0 | 0 | 0 | - | 20 |
| 틀과 함께 | 6/6 | 0 | 0 | 0 | 0 | 0 | 103 |

- 틀 없이 만든 6개는 모두 라우터, DB 모델, 세션을 `app/main.py` 한 파일에 두고 핸들러에서 DB를 직접 불렀다. 틀과 함께 만든 6개는 라우터 → 서비스 → 저장소로 나뉘었고 계약 위반이 없었다.
- 기능 크기가 작아 순환·중복·큰 함수는 두 방식 모두 0이다. 이 차이가 큰 프로젝트에서도 같은지는 재지 않았다.
- 표본이 작고 응답을 한 번씩만 받았으며 모델 하나의 결과다.

```bash
docker build -t iron-laws-blueprint:py313 -f benchmarks/blueprint_ab.Dockerfile benchmarks
uv run python benchmarks/blueprint_ab.py work docs/benchmark_results/blueprint_ab.json \
  --ai-cmd="claude -p --tools '' --strict-mcp-config --setting-sources '' --no-session-persistence --model sonnet"
```

## 5. 의존성 권고·성능·AI 공격면 규칙

### 5.1 의존성 권고(`iron-laws deps`)

- **OSV 서버 판정과 비교**(`docs/benchmark_results/deps_osv_crosscheck.json`): 같은 (패키지, 버전)을 OSV 서버에 물어 결과를 맞춰 봤다. PyPI 10개 패키지·400개 버전은 96.5%가 일치했고, 잘못 잡은 것 0건, 놓친 것 14건이다. 놓친 14건은 모두 Git 커밋 범위만 있는 권고이며 도구는 이를 `판정 불가`로 표시한다. npm 10개 패키지·391개 버전과 Maven 10개 패키지·370개 버전은 모두 일치했다.
- **실제 잠금 파일**(`docs/benchmark_results/deps_real_locks.json`): 잠금 파일 40개(uv 7, poetry 2, package-lock 26, pnpm 5), 패키지 13,426개에서 도구가 취약으로 본 (패키지, 버전) 537건이 OSV 서버 판정과 모두 같았고 한쪽에만 있는 것은 없었다. `판정 불가`는 6건이다.
- 같은 OSV 데이터를 쓰는 두 구현의 비교라서 OSV 데이터 자체의 오류는 드러나지 않는다.

### 5.2 성능 규칙(PERF)

실제 프로젝트 점검 결과에서 규칙별 표본을 뽑아 하나씩 판정했다.

| 규칙 | 표본 판정 |
|---|---|
| PERF-102 중첩 반복·리스트 찾기 | 21건 중 6~7건이 해당 패턴(약 30%) |
| PERF-103 반복 안 인터넷 요청 | 3건 중 2건이 해당 패턴 |

실측 순환 프로젝트 4개에서 PERF-106(조회 조건 열의 인덱스 없음)과 목록 API의 PERF-104를 하나씩 확인했다.

| 규칙 | 지적 | 판정 |
|---|---|---|
| PERF-106 | WebGoat 15건(나머지 3개 프로젝트는 SQL 스키마나 Prisma 스키마가 없어 0건) | 15건 모두 마이그레이션에 그 열의 인덱스가 없다(실습용 표) |
| PERF-104 목록 API(MEDIUM) | WebGoat `GET /requests`, spring-petclinic `GET /vets` | 2건 모두 페이지 없이 `findAll()` 결과 전체를 돌려준다 |

PERF-102는 절반 이상이 문제가 아닌 지적이라 `확인 필요`로만 보고한다. 오탐은 크기가 고정된 목록, 대기·재시도·먼저 성공하면 멈추는 순차 요청, 한 묶음씩 처리하는 반복, 바깥 반복의 항목에서 나온 값을 도는 안쪽 반복, 편집 거리 계산처럼 원래 이중 반복이 필요한 알고리즘에서 나온다. PERF-105(비동기 함수 안의 파일·프로세스 호출)는 시작 시 한 번 실행되는 코드도 지적할 수 있어, 요청마다 실행되는 경로인지 확인해야 한다.

### 5.3 AI 에이전트 공격면 규칙(AIA)

AIA-101·102·106은 양성·음성 사례 시험(`tests/test_ai_attack_cases.py`)으로 검증한다. 비밀 유출을 시키는 문장은 목적지(URL·주소)가 함께 있을 때만 지적한다. 실제 프로젝트 점검에서는 지적이 나온 사례가 없어 실제 환경의 정밀도는 측정하지 못했다.

### 5.4 지침 대조(`iron-laws guidelines check`)

GitHub 코드 검색에서 "never"를 담은 공개 CLAUDE.md 가운데 포크가 아니고 500자 이상인 파일 20개를 대조했다.

- 지시 문장 207개 중 대응 규칙이 있는 문장은 8개(차단 4, 보고 4), 강제 수단 없음은 199개였다. 강제 수단 없음에는 보안과 무관한 작업 절차 문장(커밋 형식, 빌드 순서, 도구 사용법)이 대부분이다.
- 대응한 8개를 사람이 확인한 결과 8개가 맞았다(정밀도 8/8). 주제어와 지시어가 같은 문장에 있을 때만 잇는다(지시 문장이 It·This로 시작하면 앞 문장을 이어받는다). 그래서 주제어가 같은 줄의 다른 문장에만 있는 지시(예: "`.env.op`에는 비밀 참조만 둔다. Never plain values")는 잇지 못한다.
- 대응하지 못한 문장의 재현율(규칙이 있는데 잇지 못한 비율)은 표본이 작아 수치로 내지 않는다.
- 판정자 한 명(개발자)의 분류이며 독립 검토가 아니다.

### 5.5 파일 목록 대조(`--build-manifest git`)

실측 순환의 고정 커밋 프로젝트 4개와 이 저장소를 git 추적 파일 목록과 대조했다.

| 프로젝트 | 목록 | 분석 | 건너뜀 | 제외 설정 | 점검하지 않는 확장자 | 사유 없이 빠짐 |
|---|---|---|---|---|---|---|
| juice-shop | 1,300 | 1,002 | 1 | 2 | 295 | 0 |
| NodeGoat | 111 | 80 | 0 | 20 | 11 | 0 |
| WebGoat | 1,358 | 826 | 10 | 13 | 509 | 0 |
| spring-petclinic | 132 | 101 | 0 | 0 | 31 | 0 |
| iron-laws | 306 | 302 | 0 | 1 | 3 | 0 |

점검하지 않는 확장자는 대부분 이미지·글꼴·문서 파일이다. 파일 목록 대조는 파일 단위의 분모이며, 분석한 파일 안의 위험 호출을 모두 찾았다는 뜻은 아니다.

Python 위험 모듈의 별칭(`import os as o`), 가져온 이름(`from os import system`), 변수에 담은 함수(`run = os.system` 뒤의 `run(...)`), 상수 이름의 `getattr(os, "system")(...)`, `__import__("os").system(...)`으로 부른 명령 실행도 지적과 근거 장부 지점으로 나온다. `getattr`의 속성 이름이 변수인 경우처럼 호출 대상을 실행 중에 정하는 형태는 찾지 못한다.

### 5.6 LLM 검토 의견의 근거 대조(`--triage-model`)

`--triage-model`은 `확인 필요` 지적마다 LLM의 의견을 붙인다. 의견은 판정을 바꾸지 않는다. 아래는 `claude -p`(Claude Code CLI 기본 모델)에 지적마다 한 번씩 물은 결과다.

**OWASP Benchmark Java.** `확인 필요` 지적 가운데 정답이 취약인 30건과 취약하지 않은 30건을 무작위로 골랐다(seed 7).

| 표본 | likely_true | unsure | likely_false | 근거 확인(corroborated) |
|---|---|---|---|---|
| 취약 30건 | 30 | 0 | 0 | 0 |
| 취약하지 않음 30건 | 1 | 26 | 3 | 0 |

- 취약 30건은 모두 쿠키 보안 속성 규칙(AI-115)의 지적이고, 취약하지 않은 30건은 SQL·LDAP·XPath 삽입 지적이다. 오염 추적 규칙의 `확인 필요` 지적은 OWASP Benchmark Java·Python 모두 정답이 취약하지 않은 사례에만 남는다. 그래서 오염 추적 지적이 진짜 결함을 덮을 위험은 이 표본으로 잴 수 없고, 아래 CWE-Bench-Java 표본으로 잰다.
- 오탐 의견 3건의 근거는 모두 '상수'였다. 그 상수가 지적한 줄에 직접 쓰이지 않아 셋 다 `unsupported`다.

**CWE-Bench-Java.** 공개 API 모드(§6.4)에서 데이터가 지목한 메서드 안에 `확인 필요` 지적이 있는 18개 사례의 지적을 물었다. 취약한 쪽의 지적은 결함이 있는 메서드에 붙은 지적이다.

| 표본 | 지적 | likely_true | unsure | likely_false | 근거 확인 | 엔진 근거와 모순(contradicted) |
|---|---|---|---|---|---|---|
| 취약한 쪽(14개 사례) | 79 | 45 | 29 | 5 | 0 | 4 |
| 고친 쪽(15개 사례) | 70 | 8 | 52 | 9 | 0 | 4 |

- 취약한 쪽 지적 5건(6.3%)이 오탐 의견을 받았다(tika 2, yamcs 2, uima-uimaj 1). 그중 4건은 '외부 입력이 아니다'라는 근거가 엔진이 확인한 입력 유입과 맞지 않아 `contradicted`이고, 1건은 근거를 확인하지 못해 `unsupported`다. 근거가 확인된 오탐 의견은 없으므로, 근거 대조 결과를 기준으로 삼으면 이 표본에서 진짜 결함을 덮은 의견은 0건이다.
- 정규 경로를 구분자 없이 `startsWith`로 비교한 뒤의 지적(yamcs, Graylog, hapifhir)에는 공개 API 모드에서도 그 사유가 함께 실린다. yamcs·hapifhir의 이런 지적은 의견이 접두사 비교를 결함으로 짚어 `likely_true`였고, Graylog 취약한 쪽 2건은 같은 한계를 적고 `unsure`였다. 오탐 의견을 받은 것은 없다.
- 고친 쪽 지적 1건(zip4j)은 의견을 받지 못했다.
- 응답은 지적마다 한 번이며, 모델 하나의 결과다.

### 5.7 근거 장부의 Java·JavaScript·TypeScript 지점

실측 순환의 WebGoat(Java·JS)와 juice-shop(TS)에서 장부가 만든 지점을, 장부와 따로 만든 소스 텍스트 정규식 검색(시험·문자열 제외, 여러 줄에 걸친 호출 때문에 3줄 차이까지 같은 지점)과 대조했다.

| 프로젝트 | 계열 | 정규식으로 찾은 곳 | 장부에 없는 곳 |
|---|---|---|---|
| WebGoat | SQL | 35 | 0 |
| WebGoat | 경로 | 45 | 0 |
| juice-shop | SQL(sequelize.query) | 3 | 0 |
| juice-shop | 경로(fs·sendFile·download) | 46 | 0 |

- JavaScript의 SQL 위험 호출 이름(`get`·`all`·`run`·`query`)은 라우터·HTTP·설정 객체에도 있어서, Python 밖의 언어에서는 DB 객체에서 부른 호출과 SQL 실행에만 쓰는 이름만 SQL 지점으로 센다. 이 제한 전 juice-shop의 SQL 지점은 501곳이었고 대부분 `config.get`·`app.get`·`this.http.get`이었다. 제한 뒤 22곳이다.
- 정규식 검색도 놓치는 형태가 있으므로 "장부에 없는 곳 0"은 이 정규식 기준이다.

### 5.8 운영 기본기 규칙(OPS)

실측 순환의 고정 커밋 프로젝트 4개에서 OPS 규칙의 판정을 사람이 확인했다.

| 프로젝트 | OPS-101 CI 시험 | OPS-102 마이그레이션 | OPS-103 상태 확인 |
|---|---|---|---|
| WebGoat | 지적 없음(CI가 빌드·시험) | 지적 없음(Flyway) | 지적 없음(Spring Boot Actuator) |
| NodeGoat | 지적 없음 | 지적 없음 | 지적: Dockerfile에 HEALTHCHECK·상태 확인 주소 없음(맞음) |
| juice-shop | 지적 없음 | 지적: sequelize를 쓰는데 마이그레이션 없음(맞음) | 지적: 앱 서비스에 상태 확인 없음(맞음) |
| spring-petclinic | 지적 없음 | 지적: JPA를 쓰고 `schema.sql` 초기화 스크립트만 있음(규칙 정의대로 맞음) | 지적 없음(앱을 빌드하는 Dockerfile 없음) |

지적 4건은 모두 규칙의 정의에 맞았다. 표본이 4개라 정밀도를 수치로 내지 않는다.

- 상태 확인 근거는 그 근거가 의미 있는 파일에서만 인정한다. Dockerfile의 `HEALTHCHECK`, compose에서 이 저장소를 빌드하는 서비스(`build:`가 있는 서비스)의 `healthcheck`, Kubernetes 워크로드의 프로브, 빌드 파일의 Actuator 의존성이다. juice-shop의 compose에 있는 redis·mongo의 healthcheck와 예제 YAML의 healthcheck는 앱의 근거로 보지 않는다.

## 6. 다른 언어의 공개 벤치마크와 도구 비교

### 6.1 OWASP Benchmark for Python 0.1

- 데이터: BenchmarkPython 커밋 `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`(사례 1,230개)
- 측정 도구: `benchmarks/owasp_benchmark_python.py`. 저장소 루트를 점검해 `helpers` 모듈까지 분석하고 `testcode`의 사례 파일만 채점한다.
- 표의 수는 확정 지적 기준 TP/FN/FP/TN이고, 마지막 열은 `확인 필요`까지 센 점수다.

| 분류 | 확정 TP/FN/FP/TN | 확정 TPR | 확정 FPR | 전체 점수 |
|---|---|---|---|---|
| cmdi | 13/0/0/7 | 100.0% | 0.0% | +85.7% |
| codeinj | 20/0/0/33 | 100.0% | 0.0% | +63.6% |
| deserialization | 18/0/0/36 | 100.0% | 0.0% | +100.0% |
| hash | 0/71/0/80 | 0.0% | 0.0% | +100.0% |
| ldapi | 16/0/0/13 | 100.0% | 0.0% | +92.3% |
| pathtraver | 65/0/0/103 | 100.0% | 0.0% | +73.8% |
| redirect | 13/0/0/21 | 100.0% | 0.0% | +100.0% |
| securecookie | 0/24/0/15 | 0.0% | 0.0% | +100.0% |
| sqli | 5/0/0/11 | 100.0% | 0.0% | +100.0% |
| trustbound | 18/0/0/19 | 100.0% | 0.0% | +100.0% |
| weakrand | 0/99/0/227 | 0.0% | 0.0% | +0.0% |
| xpathi | 51/0/0/135 | 100.0% | 0.0% | +48.2% |
| xss | 31/0/1/57 | 100.0% | 1.7% | +98.3% |
| xxe | 8/0/0/20 | 100.0% | 0.0% | +100.0% |

확정 오탐 1건(xss, BenchmarkTest00364)은 문자 허용 목록으로 이스케이프하는 프로젝트 함수 본문을 정제로 알아보지 못한 사례다. hash·weakrand·securecookie는 확정 지적을 내지 않는 분류다.

`전체` 점수가 낮은 경로·XPath·코드 실행은 검사 분기를 거친 안전 사례가 `확인 필요`로 남은 것이다. 원시 결과는 `docs/benchmark_results/owasp_python_confirmed.json`, `owasp_python_all.json`이다.

### 6.2 Juliet Test Suite 1.3 (C/C++, C#)

측정 도구는 `benchmarks/juliet.py`이며, 오철칙 규칙과 대응하는 CWE만 잰다(대응표는 결과 파일의 `cwe_rule_map`). 범주별 수치는 `docs/benchmark_results/juliet_c.json`, `juliet_cs.json`에 있고, `with_review`에 확인 필요까지 센 결과, `by_kind`에 하위 판정(IL-514는 복사·서식·입력 너비·크기 계산)별 사례 수가 있다. 아래 표는 주요 범주의 확정 지적 기준 결과다. bad 확정 TP는 '잡은 수 / bad 사례 수'다.

| 언어 | 범주 | bad 확정 TP | good 확정 FP | 판정 근거 |
|---|---|---|---|---|
| C/C++ | CWE-78 명령 삽입 | 1,200 / 4,800 | 0 | 출력 인자 입력(`fgets`·`recv`), `getenv`, `exec` 계열 싱크, 객체형 매크로 |
| C/C++ | CWE-23·36 경로 조작 | 각 400 / 2,400 | 0 | 같은 입력 정의, 매크로로 감싼 `fopen`·`open` |
| C/C++ | CWE-134 서식 문자열 | 960 / 2,880 | 630 | 리터럴만 복사한 버퍼를 서식으로 쓰면 지적하지 않는다 |
| C/C++ | CWE-121 스택 넘침 | 364 / 4,944 | 0 | `strcpy`·`strcat`의 원본 길이와 목적지 크기를 비교한다. 계산할 수 없으면 확인 필요(bad 540, good 540) |
| C/C++ | CWE-122 힙 넘침 | 80 / 5,922 | 0 | 같은 비교. 확인 필요 bad 924, good 924 |
| C/C++ | CWE-124·127 버퍼 앞쪽 쓰기·읽기 | 각 68 / 2,048 | 0 | 음수 오프셋은 확정. 확인 필요 bad 284, good 284 |
| C# | CWE-89 SQL | 342 / 999 | 0 | `HttpRequest` 형식 매개변수·네트워크 스트림 입력, `CommandText` 대입 싱크 |
| C# | CWE-78·23·36·643·94 | 각 126 / 370 | 0(CWE-94는 126) | 같은 입력 정의, `File.Exists`, `CompileAssemblyFromSource` |
| C# | CWE-90 LDAP | 120 / 370 | 0 | `DirectorySearcher.Filter` 대입 |
| C# | CWE-80·83 XSS | 240 / 666, 120 / 333 | 0 | `HttpResponse.Write` |
| C# | CWE-601 리다이렉트 | 126 / 333 | 0 | `HttpResponse.Redirect` |
| C# | CWE-113 응답 분할 | 378 / 999 | 0 | `new HttpCookie`의 값, URL 인코딩을 헤더 정제로 인정 |

- 대응 규칙이 없는 범주는 재지 않는다. C/C++ 118개 범주 가운데 88개, C# 105개 범주 가운데 75개가 '대응 규칙 없음'이며, 잰 범주는 결과 파일의 `categories`에 있다.
- CWE-134는 서식 함수가 `snprintf` 매크로, `vfprintf`·`vprintf`를 감싼 함수, 넓은 문자 `fwprintf`인 사례를 확정으로 잡지 못한다.
- C/C++ 메모리 범주는 버퍼 크기를 계산할 수 있을 때만 확정으로 낸다. 포인터의 포인터, 함수 매개변수로 넘긴 버퍼, 다른 함수에서 채운 버퍼는 크기를 정하지 못해 확인 필요로 낸다.
- C/C++ 입력 범주의 남은 미탐은 다른 함수·다른 파일을 거치는 데이터 흐름 변형(Juliet의 42~68번)과 C++ 컨테이너·클래스 변형(72~84번)이다. C/C++은 파일을 넘어 추적하지 않는다.
- C# 범주의 남은 미탐은 데이터베이스·파일·환경 변수에서 읽는 변형과 다른 메서드를 거치는 변형이다. CWE-94의 good 확정 FP 126건은 `int.Parse`가 성공한 경우에만 원래 문자열을 코드에 넣는 변형으로, 형식 변환의 성공을 검사로 알아보지 못한다.

### 6.3 Semgrep·CodeQL과의 같은 조건 비교

- 사례: §4.1의 위험·정상 짝, 그리고 외부 입력을 읽는 부분을 다른 파일 함수로 옮긴 변형('우회 거부'는 이 변형을 잡은 수)
- 개발용 사례는 오철칙을 만들며 맞춘 사례라 공정한 비교는 평가용이다.
- 측정 도구 `benchmarks/compare_tools.py`, 원시 결과 `docs/benchmark_results/compare_tools.json`

| 도구 | 평가용 위험 탐지 | 평가용 정상 오탐 | 평가용 우회 거부 | 전체 위험 탐지 | 전체 정상 오탐 | 전체 우회 거부 |
|---|---|---|---|---|---|---|
| iron-laws 1.6.0 | 9/9 | 0/9 | 7/7 | 36/36 | 0/36 | 34/34 |
| semgrep 1.180.0 | 5/9 | 2/9 | 2/7 | 28/36 | 17/36 | 8/34 |
| codeql 2.27.2 | 0/9 | 1/9 | 0/7 | 19/36 | 11/36 | 19/34 |

사례는 짧은 합성 코드라 프레임워크 연결(Express 앱 생성, Django URL 연결 등)이 빠진 경우가 많다. CodeQL은 이런 연결로 외부 입력을 알아보므로 JavaScript 0건, Java 1건으로 실제보다 낮게 나온다. Semgrep 규칙은 측정 시점의 레지스트리 `p/default`다. 같은 조건에서 각 도구가 어떻게 판정하는지 보여 줄 뿐, 실제 프로젝트에서의 우열을 뜻하지 않는다.

### 6.4 CWE-Bench-Java(실제 오픈소스 CVE)

- 데이터: CWE-Bench-Java 커밋 `afe0ebd0adc237abb46255f9cd479b1d71819136`(사례 120개)
- 측정 도구 `benchmarks/cwe_bench_java.py`, 원시 결과 `docs/benchmark_results/cwe_bench_java.json`(기본 설정)과 `cwe_bench_java_public_api.json`(공개 API 모드)
- 사례마다 취약한 커밋과 고친 커밋의 프로젝트 전체를 점검한다. 데이터가 지목한 취약 메서드 안에 해당 규칙(CWE-22 → IL-502, CWE-78 → IL-504, CWE-79 → IL-505, CWE-94 → IL-503)의 지적이 있으면 취약한 쪽은 TP, 고친 쪽은 FP로 센다.
- 커밋을 받지 못했거나 지목한 메서드를 찾지 못한 쪽은 TN·FN에 넣지 않고 '분석하지 못함'으로 따로 센다. 짧은 해시로 적힌 커밋(cxf, activemq, nifi의 고친 쪽)은 저장소 이력에서 전체 해시를 찾아 받는다. 지금 남은 '분석하지 못함'은 모두 지목한 메서드를 찾지 못한 경우다.
- 확정은 확정 지적만, 전체는 `확인 필요`까지 센 결과다.

```bash
git clone https://github.com/iris-sast/cwe-bench-java.git <폴더>
uv run python benchmarks/cwe_bench_java.py <폴더> afe0ebd0adc237abb46255f9cd479b1d71819136 <작업 폴더> --fetch docs/benchmark_results/cwe_bench_java.json
uv run python benchmarks/cwe_bench_java.py <폴더> afe0ebd0adc237abb46255f9cd479b1d71819136 <작업 폴더> --fetch --public-api docs/benchmark_results/cwe_bench_java_public_api.json
```

| 분류 | 확정 TP/FN/FP/TN | 확정 재현율 | 확정 오탐률 | 전체 TP/FN/FP/TN | 분석하지 못함(취약/고친 쪽) |
|---|---|---|---|---|---|
| CWE-22 경로 조작 | 14/37/3/49 | 27.5% | 5.8% | 17/34/7/45 | 4 / 3 |
| CWE-78 명령 삽입 | 0/12/0/12 | 0.0% | 0.0% | 0/12/0/12 | 1 / 1 |
| CWE-79 XSS | 0/28/0/28 | 0.0% | 0.0% | 0/28/0/28 | 3 / 3 |
| CWE-94 코드 삽입 | 0/18/0/20 | 0.0% | 0.0% | 2/16/2/18 | 3 / 1 |

지적한 줄이 수정에서 바뀌지 않아 두 쪽에 똑같이 나오면, 그 지적은 결함을 잡은 근거로 보지 않는다. 아래 짝 표가 그 구분이다.

사례별로 두 쪽의 판정을 짝으로 보면 경로 조작은 다음과 같다.

| 짝(취약/고친 쪽) | 사례 | 뜻 |
|---|---|---|
| TP/TN | 10 | 취약한 쪽만 지적해 수정 전후를 가른다. 5건은 지적한 줄 자체는 수정에서 바뀌지 않았고, 다른 곳의 수정으로 지적이 사라졌다 |
| TP/FP | 3 | 두 쪽을 가르지 못한다. 3건 모두 지적한 줄이 수정에서 바뀌지 않았다 |
| FN/TN | 36 | 놓쳤다 |
| 따로 센 사례 | 1 | uima-uimaj. 데이터가 고친 쪽으로 지정한 커밋에 보안 수정이 없다(실제 수정은 두 커밋 뒤). `benchmarks/cwe_bench_java_notes.json`에 근거가 있다 |
| 짝을 이루지 못함 | 5 | 한쪽을 분석하지 못했다. alibaba one-java-agent는 취약한 쪽 TP다 |

두 쪽을 가르지 못하는 TP/FP 3건은 다음과 같다.

- DependencyCheck: 경로 검사가 지목한 메서드가 아니라 다른 메서드에 있다.
- zt-zip: 고친 쪽도 압축 항목의 중간 폴더를 만들 때(`ZipUtil.java:1223`) 기준 폴더를 검사하지 않는다. 남은 약점을 짚은 지적이다.
- plexus-utils: 고친 쪽 검사는 `f.getAbsolutePath().startsWith(dir.getAbsolutePath())`다. 오철칙은 앞선 `resolveFile`이 경로를 정규화하는지 알지 못하고, 이 비교는 구분자 없는 문자열 접두사 비교라 기준 폴더 검사로 인정하지 않는다.

hapifhir의 두 CVE는 같은 코드를 서로 다르게 분류한다. `TerminologyCacheManager`의 압축 해제 코드는 CVE-2023-24057에서는 고친 쪽이고 CVE-2023-28465에서는 취약한 쪽이다. 이 코드는 정규화한 경로를 기준 폴더와 구분자 없이 문자열 접두사로 비교한 뒤(`path.startsWith(targetDir)`) 다른 파일의 쓰기 함수에 넘긴다. 오철칙은 이 지적을 `확인 필요`로 낸다. 그래서 CVE-2023-24057은 TP/TN, CVE-2023-28465는 확정으로 보면 FN/TN, `확인 필요`까지 세면 TP/TN이다.

경로 조작에서 놓친 사례와 다른 CWE에서 잡지 못한 사례는 대체로 다음과 같다.

- 라이브러리 함수 자체의 검증 결함: 공개 메서드의 매개변수가 입력이라 외부 입력 흐름이 코드에 없다(commons-io, ESAPI, myfaces, antisamy, json-sanitizer, sling-xss, hibernate-validator 등). CWE-79 사례의 다수가 XSS 방어 라이브러리 자체의 결함이다.
- 웹 요청이 아닌 입력: Jenkins 작업 설정 값(perfecto), 디렉터리 서비스의 그룹 이름(nifi), 라우트 정의(spring-cloud-gateway)처럼 프레임워크 고유의 입력 모델이 필요하다.
- 셸 삽입이 아닌 명령 결함: git 인자 삽입(git-client-plugin), 역직렬화를 거친 명령 실행(xstream), 스크립트 샌드박스 우회(Jenkins).
- 상속·추상 메서드를 거치는 흐름(plexus-archiver), 경로 API를 직접 부르지 않는 결함(retrofit, rocketmq, keycloak 등).

경로 조작에서 `확인 필요`까지 세면 기본 설정에서 karaf, uima-uimaj, hapifhir CVE-2023-28465의 취약한 쪽을 더 잡는다. 반면 zip4j, DSpace CVE-2022-31194, uima-uimaj, hapifhir CVE-2023-24057의 고친 쪽에도 지적이 남아 오탐이 4건 는다.

CWE-94의 `확인 필요` 2건(spring-cloud-gateway, spring-boot-admin)은 상수가 아닌 SpEL 식 평가를 짚었지만, 고친 쪽에도 같은 지적이 남아 둘을 가르지 못한다(평가 컨텍스트를 다른 함수에서 바꿔 고쳤다).

공개 API 모드(`--public-api`)는 공개 메서드의 매개변수를 입력으로 보고 그 지적을 `확인 필요`로 낸다. 그래서 확정 수치는 모든 CWE에서 기본 설정과 같다. 경로 조작의 전체 수치는 23/28/16/36(재현율 45.1%, 오탐률 30.8%)이 된다. 새로 잡는 취약한 쪽은 tika, Graylog, mina-sshd, yamcs 2건, ESAPI의 6건이고, ESAPI를 뺀 5건은 고친 쪽에도 지적이 남는다. 이미 잡던 hutool, kubernetes-client, DSpace CVE-2022-31195, goomph도 고친 쪽에 지적이 생긴다. 라이브러리 결함을 찾는 데는 쓸 수 있지만 수정 여부를 가르지는 못한다. 명령 삽입·XSS·코드 삽입은 두 모드의 결과가 같다.

LLM 명세 초안(`spec draft --llm-cmd "claude -p"`)으로 명령 삽입·코드 삽입 30개 사례를 따로 쟀다. 사례마다 취약한 쪽 초안을 만들고, 제안한 예제대로 판정된 LLM 항목만 명세로 채택했다.

- 놓친 단계: 26건은 데이터가 지목한 메서드 안에 오철칙이 아는 명령·코드 실행 호출이 없다(싱크 단계). 4건(spring-boot-admin, plexus-utils CVE-2017-1000487, perfecto, spring-cloud-gateway)은 그런 호출이 있지만 외부 입력이 이어진 것을 확인하지 못했다(원천·전달 단계).
- 채택한 항목: 싱크 6건(dolphinscheduler `SwitchTaskUtils.evaluate` 2건, spring-framework `evaluateBshScript`·`ExpressionEvaluatorManager.evaluate`, spring-cloud-gateway `ShortcutConfigurable.getValue`, nifi `N1qlQuery.simple`). 나머지 제안은 오철칙이 이미 아는 싱크를 다시 냈거나, 예제가 기대대로 판정되지 않아 빠졌다.
- 결과: 자기 초안을 채택한 5개 사례와, 자기를 뺀 나머지 초안을 합쳐 채택한 30개 사례 모두 확정·전체 판정이 기본 설정과 같았다. 새 정탐은 없고, 초안을 만들 때 쓰지 않은 프로젝트에서 생긴 새 확정 오탐도 0건이다.

### 6.5 CWEval(AI 생성 코드 평가 세트)

[CWEval](https://github.com/Co1lin/CWEval)(Apache-2.0)은 LLM이 쓴 코드의 기능과 보안을 함께 보는 평가 세트이며, CWE마다 취약한 참조 구현과 안전한 참조 구현이 있다. 오철칙이 재는 것은 기능·보안 동시 통과율이 아니라 **취약 참조 구현에서 같은 CWE의 지적을 내는지**와 **안전 참조 구현에서 같은 CWE의 지적을 내지 않는지**다. 평가 세트 커밋은 `e9a2a124c8c5`다.

| 언어 | 취약 사례 | 같은 CWE 지적 (확정) | 공개 API 모드의 같은 CWE 지적 (확정) | 안전 사례 | 같은 CWE 오탐 (확정) |
|---|---:|---:|---:|---:|---:|
| Python | 21 | 6 (3) | 8 (3) | 25 | 0 (0) |
| JavaScript | 23 | 6 (4) | 7 (4) | 23 | 1 (0) |
| Go | 19 | 3 (2) | 3 (2) | 19 | 0 (0) |

- 같은 CWE는 지적의 기준 팩 항목과 행안부 항목 설명의 `(CWE-n)` 표기에서 읽는다.
- 사례는 함수 하나짜리 참조 구현이라 프레임워크의 입력 연결이 없다. 기본 설정은 일반 함수의 매개변수를 외부 입력으로 보지 않으므로 외부 입력 추적에 기대는 규칙의 탐지가 낮게 나온다. 실제 프로젝트의 탐지율이 아니라 이 평가 세트에서의 값이다.
- 공개 API 모드(`policies.entry_points: public_api`, `--entry-points public_api`)는 공개 함수의 매개변수를 입력으로 보고 그 지적을 `확인 필요`로 낸다. 그래서 같은 CWE 지적은 Python 2건(경로·코드 실행), JavaScript 1건(경로) 늘고 확정 수는 같다. 안전 사례의 판정은 두 모드가 같다.
- 매개변수로 받은 데이터를 복원하는 역직렬화 사례는 데이터 출처를 알 수 없어 `확인 필요`다(IL-515).
- 취약 참조 구현의 정답 CWE가 오철칙의 대응 CWE와 다른 경우(예: NoSQL 삽입 CWE-943에 SQL 삽입 CWE-89)는 같은 CWE로 세지 않는다.
- 사례별 결과는 [docs/benchmark_results/cweval.json](benchmark_results/cweval.json)과 `cweval_public_api.json`에 있다. 평가 세트는 저장소에 넣지 않고 내려받아 읽는다.

```bash
git clone --depth 1 https://github.com/Co1lin/CWEval.git <폴더>
uv run python benchmarks/cweval.py <폴더>
uv run python benchmarks/cweval.py <폴더> --entry-points public_api -o docs/benchmark_results/cweval_public_api.json
```

## 7. 재현

측정 결과에는 도구 버전, 데이터 커밋, 명령, 원시 건수(TP·FN·FP·TN)를 함께 적는다. OWASP Benchmark(Java) 재현:

```bash
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git
git -C BenchmarkJava checkout 10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17
uv run python benchmarks/owasp_benchmark.py BenchmarkJava confirmed docs/benchmark_results/owasp_confirmed.json
uv run python benchmarks/owasp_benchmark.py BenchmarkJava all docs/benchmark_results/owasp_all.json
```

수정 지시문 비교(§4.3)는 AI 명령을 직접 정한다. 응답은 작업 폴더에 남으며 같은 지시문이면 다시 부르지 않는다.

```bash
git show v1.5.0:src/iron_laws/reporters/prompt.py > prompt_previous.py
uv run python benchmarks/fix_prompt_ab.py work prompt_previous.py docs/benchmark_results/fix_prompt_ab.json \
  --ai-cmd="claude -p --tools '' --strict-mcp-config --setting-sources '' --no-session-persistence --model sonnet" --runner=docker
```

안내물 비교(§4.4)도 AI 명령을 직접 정한다. 도구 없는 AI로 돌리려면 도구 목록이 빈 에이전트를 지정한다.

```bash
uv run python benchmarks/artifact_ab.py work docs/benchmark_results/artifact_ab.json \
  --ai-cmd="claude -p --agents '{\"fixer\":{\"description\":\"코드 수정 보조자\",\"prompt\":\"파일과 셸을 쓰지 않는다. 고친 파일 전체를 하나의 python 코드 블록으로만 출력한다.\",\"tools\":[]}}' --agent fixer --no-session-persistence --model sonnet" --runner=docker
```

### 처리 시간

처리 시간은 같은 장비·같은 저장소에서 작업 프로세스 수를 고정하고 3회 반복한 중앙값이다(`benchmarks/bench_common.py`의 `timed_scan`). flask(약 5천 파일)는 5.4초, WebGoat는 9.3초이고, 최대 메모리는 약 80~120MB다.
