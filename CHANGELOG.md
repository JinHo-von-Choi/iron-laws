# 변경 이력

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고, 버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.
보고서 JSON의 `schema_version`은 도구 버전과 별개로 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)의 호환 정책을 따릅니다.

## [Unreleased]

## [1.11.0] - 2026-10-26

### Changed
- 보고서 형식 버전을 1.8로 올린다. `metadata.file_coverage`와 `review_opinion`의 `basis`·`check`를 추가했고, 독립 검증기가 상태별 수의 합과 사유 없이 빠진 파일의 진단 여부를 대조한다.
- Python에서 위험 호출을 정의한 표준 모듈(os, os.path, subprocess, shutil, pickle, marshal, shelve, yaml, sqlite3, commands, pty)의 별칭, 가져온 이름, 변수에 담은 함수, 상수 이름의 `getattr`, `__import__`·`importlib.import_module`로 부른 호출을 모듈 경로로 풀어 찾는다(`import os as o` → `o.system`은 `os.system`, `from pickle import loads` → `loads`는 `pickle.loads`, `run = os.system` 뒤의 `run`은 `os.system`). 그 이름이 매개변수나 대입으로 다시 묶였으면 풀지 않는다. 판정이 바뀐 규칙의 판 번호를 올린다: IL-502는 3, IL-504·IL-515·IL-516·IL-518·PERF-105는 2.
- 흐름 해석이 코드만으로 정해지는 값을 계산한다. 조건이 상수인 if·조건식, 선택값이 상수인 switch(break까지의 이어짐 포함)와 Python `match`는 실행되는 갈래만 따라간다. 같은 블록에서 만들고 add·put(상수 키)·remove·clear만 한 지역 List·Map(Python은 list·dict·configparser)에서 상수 위치·키로 꺼낸 리터럴, 같은 파일에 하나뿐인 메서드가 돌려주는 상수는 깨끗한 값으로 본다. 값이 조금이라도 불확실하면(다시 대입, 매개변수, 다른 메서드 호출, 갈래·반복 안의 변경) 지금처럼 모든 갈래를 따라간다. 외부 입력 추적을 쓰는 규칙의 판 번호를 올린다: IL-501·IL-508은 3, IL-503·IL-505·IL-506·IL-507·IL-511·IL-512·IL-513·IL-514·IL-526·IL-527·IL-533·IL-104·IL-107·IL-112·AI-112·AI-113·AI-115·AIA-103·AIA-104·AIA-105·AIA-108은 2.
- 명령 실행·SQL 규칙이 검증으로 인정하는 조건을 넓힌다. 허용 목록 검사에 더해 문자 종류 검사(`isalnum`·`isalpha`·`isdigit`·`isdecimal`·`isnumeric`·`isidentifier`)와 영문·숫자·밑줄·하이픈만 허용하는 `re.fullmatch`(또는 끝이 고정된 `re.match`) 검사를 거부 분기가 실행을 끊고 값이 바뀌지 않을 때 인정한다.

### Added
- `iron-laws guidelines export`: 규칙을 코딩 에이전트 지침(CLAUDE.md·AGENTS.md에 붙여 넣을 마크다운)으로 내보낸다. 줄마다 그 지침을 무엇이 확인하는지(차단·실행 검증·보고)와 양성·음성 시험으로 검증된 언어를 붙인다.
- `iron-laws guidelines check <지침 파일>`: 지침 파일의 지시 문장마다 대응하는 규칙과 강제 수단을 보여 준다. 대응 규칙이 없는 문장은 '강제 수단 없음'으로 표시한다. `--fail-on-unenforced`를 주면 그런 문장이 있을 때 종료코드 1이다.
- 승인 기록 서명: `approvals add --sign-key`로 승인에 OpenSSH 서명(이름공간 `iron-laws-approval`)을 붙인다. `check`·`audit`·`review-bundle`·`approvals verify`에 `--allowed-signers`를 주면 서명이 틀린 승인을, `--require-signed-approvals`(`approvals verify`는 `--require-signed`)를 더하면 서명 없는 승인도 `invalid`로 보고 쓰지 않는다. 서명 대상은 순번·앞 기록 해시를 뺀 승인 내용이라 보존기간 정리 뒤에도 유지된다.
- `approvals checkpoint`: 기록 수와 마지막 해시를 서명해 남긴다. `approvals verify --checkpoint`가 체크포인트 이전 기록의 삭제·되돌리기·사슬 재작성을 알아챈다.
- `--build-manifest auto|git|tsc|go|file:<목록>`: 오철칙 밖에서 얻은 파일 목록과 분석한 파일을 대조해 파일마다 상태(분석·건너뜀·제외 설정·점검하지 않는 확장자·점검 폴더 밖·파일 없음·사유 없이 빠짐)를 보고서 `metadata.file_coverage`에 남긴다. 사유 없이 빠진 파일이 있으면 경고하고, `--require-full-coverage`면 점검을 끝내지 못한 것으로 본다(종료코드 2). 목록을 만들지 못하면 대조하지 않았다고 밝힌다.
- 회귀시험 결과 봉인: harness 결과 줄에 실행마다 새로 만든 봉인값을 붙이고, 봉인값이 없는 결과는 받아들이지 않는다. 수정본 코드가 결과 줄을 흉내 내거나 출력을 바꿔 통과를 꾸미는 경우를 막는다.
- 명령 실행 계열 회귀시험은 공격 입력에 카나리아 명령을 붙인 호출을 한 번 따로 해서, 수정본이 기록 장치를 우회해 실제 셸을 실행하면 결함 재현으로 판정한다. 기록 장치를 저수준 경로(`posix.system`, `os.open`, `io.FileIO`, `_io.open`, `sqlite3.dbapi2`)에도 건다.
- `--triage-model`의 `likely_false` 의견에 근거(`basis`: constant·sanitized_by·unreachable·not_external, 줄, 이름)를 요구하고, 코드와 엔진의 입력 경로로 대조한 결과를 `review_opinion.check`(corroborated·unsupported·contradicted)에 남긴다. 판정은 바꾸지 않는다.
- `spec draft --llm-cmd`: LLM이 항목과 함께 낸 양성·음성 예로 항목을 바로 판정한다. 예가 어긋나거나 없는 항목은 `rejected`로 빼고, 소스·싱크는 예가 맞으면 예를 채운다. 정제 함수는 예가 맞아도 `proposed_positive`·`proposed_negative`에만 두어 사람이 옮기기 전에는 불러오지 않는다.
- 근거 장부를 Java·JavaScript·TypeScript로 넓힌다. 계약의 기본 언어가 python·java·javascript·typescript·tsx가 된다. Python 밖의 언어는 리터럴·상수 조건·지역 컬렉션·같은 파일 도우미의 반환값으로 정해지는 값만 닫힌 값으로 보고 그 밖은 '확인 못 함'으로 남긴다. SQL 지점은 DB 객체에서 부른 호출과 SQL 실행에만 쓰는 이름으로 한정한다(라우터 `app.get`, 설정 `config.get`은 지점이 아니다).
- 마크다운 보고서의 검사 공백 장부에 같은 위험 함수를 여러 곳에서 부르는 경우의 표(곳 수, 근거 확인, 지적, 확인 못 함)를 둔다.
- 실측 순환(`benchmarks/realworld_loop.py`) 기록에 규칙별 판 번호를 남긴다. 지적이 달라졌는데 판 번호가 기록과 같은 규칙은 대기열 맨 앞에 적고 종료코드 3으로 끝난다.

### Fixed
- 회귀시험 하네스의 오판: 경로 계열의 가짜 `os.stat`이 `None`을 돌려 `os.path.isfile` 검사를 하는 올바른 수정이 실패로 나오던 것, 가짜 `os.open`이 문자 장치를 열어 `S_ISREG` 검사가 실패하던 것, `os.fdopen`이 넘긴 파일 기술자 번호를 경로로 기록하던 것을 고친다. 명세에 허용 폴더가 없으면 같은 코드에 정상 입력을 먼저 넣어 접근한 폴더를 허용 폴더로 쓴다(코드가 정한 기준 폴더 안의 접근을 이탈로 보지 않는다).
- 회귀시험 변형 입력을 원본에서 재현되지 않는 것까지 수정본에 돌린다. `../`를 한 번만 지우는 필터처럼 수정이 원본에 없던 우회 입력을 만드는 경우를 실패로 판정한다. 변형 입력에 공백 없는 구분자·줄바꿈·`....//`·URL 인코딩·대소문자 섞인 키워드·주석 공백을 더한다.
- 정상 입력에서 원본과 수정본이 위험 호출에 넘긴 내용(명령·경로·SQL)을 비교해 회귀시험 근거에 남긴다. 명세의 `expect.benign_behavior: require`면 달라졌을 때 실패로 본다.
- 같은 지적을 철회한 뒤 같은 초에 다시 승인하면 승인 ID가 겹쳐 철회 기록이 두 승인을 함께 가리키던 것을 고친다. 겹치면 순번을 섞어 새 ID를 만든다.

## [1.10.0] - 2026-10-25

### Changed
- 판정이 바뀐 규칙의 판 번호를 올린다: IL-301·IL-307·AI-101·ARC-212는 3, IL-102·IL-530·PERF-101은 2. 기준선의 이 규칙 지적은 같은 파일에서 같은 모양으로 하나만 대응될 때 재검토로 이어지고, 그렇지 않으면 새 지적으로 나온다. 이 규칙들에 걸린 승인은 재검토가 필요하다.
- AI-101 지적은 코드 줄과 메시지에서 주소를 가리지 않고 보여 준다. 계정 정보(`user:pass@`), 비밀 이름의 질의 값(`?password=`), 토큰처럼 긴 조각이 있는 주소와 같은 줄의 다른 따옴표 값은 계속 가린다. 메시지의 주소에서는 질의와 조각을 뺀다. 규칙이 비밀이 아니라고 판정한 값을 알리는 `BaseRule.public_values`를 추가했다.

### Fixed
- IL-301: 좁은 예외를 잡아 지적·진단을 돌려주거나 실패 목록(`problems`·`errors`·`missing`·`notes` 등)에 담아 함수 밖으로 넘기는 처리를 예외 은폐로 보지 않는다. 지역 목록은 처리 뒤에 다시 쓰일 때만 인정한다.
- IL-307: 함수 이름을 낱말로 나눠 낱말 머리에서만 민감 이름을 찾는다. `assignment`·`design`·`signature`·`checkout`·`payload`는 더 이상 검증 함수로 보지 않는다. `tryparse`·`safedecode`처럼 접두어가 붙어 한 낱말이 된 이름은 찾고, `signature`는 `hmac`·`jwt`·`webhook` 같은 서명 낱말과 함께 쓰일 때 민감 이름으로 본다. 반환 타입이 `Violation | None`인 함수의 `return None`은 '찾은 것이 없다'로 본다.
- ARC-212·PERF-101: `report`·`reporters`를 DB 저장소 이름(`repo`)으로 보지 않는다. `repositories`·`userRepo`는 계속 DB 저장소로 본다.
- IL-102: 따옴표 안의 소스 파일 경로(`"lessons/challenge7/MD5.java"`)를 약한 해시 사용으로 보지 않는다. 같은 줄의 실제 해시 호출은 계속 지적한다.
- IL-530: 저장 호출 표시어를 문자열 밖에서만 찾는다. 표시어를 문자열로 정의한 파일을 업로드 코드로 보지 않는다. 내용 판정 라이브러리(Tika·python-magic·file-type 등)는 운영 코드의 실제 사용으로만 인정한다. 주석·문자열·시험 코드에 이름만 있으면 클라이언트 Content-Type 의존 지적을 계속 낸다.
- AI-101: OpenVEX 문서의 판본 붙은 `@context` 이름 공간(`https://openvex.dev/ns/v0.2.0`)을 환경 설정 주소로 보지 않는다.

## [1.9.0] - 2026-10-22

### Added
- 점검 비용 장부: 보고서 `execution.cost`에 경과 시간·CPU 시간·최대 메모리·초당 파일 수·작업 프로세스 수·단계별 시간을 남긴다. 같은 코드의 두 보고서를 비교할 때 제외된다.
- 시간 상한 `limits.max_wall_seconds`와 `--max-wall-seconds`: 상한을 넘으면 `scan_status`가 `incomplete`가 되고 종료코드는 2다.
- 작업 프로세스 수 설정 `limits.max_workers`와 `limits.parallel_min_files`.
- 기준선에 점검 비용을 함께 남기고, 기준선 시점보다 2배 넘게 느려지면 비율로 알린다(`cost` 진단).
- `iron-laws architecture`에 두 지표를 더한다: 최근 커밋에서 자주 바뀌면서 큰 파일(변경 집중), 두 모듈 이상에 같은 모양으로 정의된 정규식(중복 정규식).
- 보고서(마크다운·감리 대응 보고서·docx)에 '점검 비용과 확인하지 못한 범위' 절을 둔다. 확인하지 못한 범위와 분모를 함께 적는다.

### Changed
- 보고서 형식 버전을 1.7로 올린다. `execution.cost`를 추가했다.
- 파일별 규칙을 나눠 처리하는 작업 프로세스 수를 8개에서 32개로 올리고, 나눠 처리 대상 파일 수를 300개에서 50개로 낮춘다. 72코어 장비에서 자기 감사 56.2초 → 9.3초가 되었다.
- `.samcheonpo`·`.serena` 폴더는 기본 제외 목록에 넣었다. 분석 도구가 저장한 코드 사본이라 같은 지적이 여러 번 나오는 원인이 됐다.
- `.gitignore`에 걸리는 파일은 기본으로 점검한다. `.env`처럼 비밀값이 들어갈 수 있는 파일을 놓치지 않기 위한 기본값이다.
- `verify-patch`가 `.gitignore`를 바꾸는 patch를 정책 변경으로 보고 원본으로 되돌린다. 제외 규칙을 바꿔 지적을 숨기는 길을 막는다.
- 계층 추정이 폴더 이름으로도 판단한다(`core`·`domain`은 서비스 계층, `reporters`·`cli`는 표현 계층). ARC-207의 판정 의미가 달라져 판 번호를 2로 올렸다.
- 규칙 등록 목록을 없앤다. `iron_laws.rules` 패키지의 규칙 클래스를 찾아 자동으로 등록하므로 규칙을 빠뜨릴 수 없다.

### Fixed
- 근거 장부가 지점마다 모든 지적을 훑어 찾던 것을 (규칙, 경로, 줄) 색인으로 바꾼다.
- 모듈 최상위 재대입 이름과 import 이름을 호출마다 다시 찾던 것을 파일마다 한 번만 계산한다.
- `AiRule`이 두 모듈에 따로 정의되어 있던 것을 한곳으로 모은다.
- 라우트·인증 정규식이 엔진과 규칙 모듈에 따로 정의되어 있던 것을 한곳으로 모은다.
- `core`가 `reporters`를 불러오던 의존을 없앤다(지원 행렬 계산을 `core/support_matrix.py`로 옮김).

### Changed (구조)
- `engine/taint.py`를 `engine/taint/` 패키지로 나눈다: `paths`·`sources`·`sanitizers`·`resolve`·`nodes`·`definitions`·`interpreter`·`state`. 되풀이 상태는 `state.py` 한곳에 모았다. 흐름 해석기·분석 캐시·식의 오염 판정은 서로를 부르는 한 덩어리라 `interpreter.py`에 함께 둔다.
- `verify/engine.py::_verify`(180줄)를 다섯 단계 함수로, `core/scan_result.py::_assemble_report`(154줄)를 요약·메타데이터·실행기록 함수로 나눈다.

## [1.8.0] - 2026-10-21

### Added
- `iron-laws spec check --against <저장소>`: 명세를 적용하기 전과 후를 같은 조건에서 두 번 돌려 비교한다. 명세 때문에 사라진 지적과 그 원인 후보(선언한 정제 함수), 근거 상태가 낮아진 검사 지점을 밝히고, 비교를 믿을 수 없으면 채택을 보류한다. 결과 형식은 console·markdown·json.
- 교훈 저장소 `iron-laws experience add|list|invalidate|verify`: 채택한 명세와 규칙에 대한 교훈을 남긴다. 기록은 추가 전용으로 해시로 이어 붙는다. `iron-laws explain`이 그 규칙의 교훈을 함께 보여 주고, `spec draft --llm-cmd`가 관련 교훈을 지시문에 넣어 준다. 규칙 버전이나 명세 내용이 바뀌면 '다시 볼 것'으로 표시한다.
- 설정 `policies.ledger_include_spec_points`: 켜면 사용자 명세의 싱크가 검사 공백 장부에도 지점으로 나타난다. 기본은 꺼짐이다.
- 산출물 비교 측정기 `benchmarks/artifact_ab.py`: 수정 지시문·검토 묶음·MCP 도구 설명을 같은 결함 표본으로 비교한다.

### Changed
- 보고서 형식 버전을 1.6으로 올린다. 장부 `digests.spec`, 장부 지점의 근거 종류 `declared_sanitizer`, `metadata.custom_spec`를 추가했다.
- `iron-laws spec check`의 예제 검증이 항목 하나만 명세에 넣어 판정한다. 다른 항목이 이 항목의 예제에 영향을 주지 않는다. 항목당 점검이 두 번에서 한 번으로 줄었다.
- 검사 공백 장부의 `digests`에 적용된 사용자 명세의 지문(`spec`)을 담는다. 명세 내용이 바뀌면 실행 식별자(`run_id`)가 달라진다.
- 명세로 선언한 정제 함수에 기대는 지점은 근거 종류가 `declared_sanitizer`로 표시되고 그 사실을 장부의 한계로 밝힌다. 근거를 확보했다고 말하면서 닫힌 값이라고 말하던 자리를 정정한다.


## [1.7.0] - 2026-10-12

### Added
- `--format mois-report`의 출력 파일을 `.hwpx`로 주면 한글 문서(HWPX)로 쓴다. 선택 의존성 `iron-laws[hwpx]`(python-hwpx)이며 한글 프로그램 없이 만든다.

### Changed
- OWASP Top 10:2025, OWASP Top 10 for Agentic Applications 2026, 2025 CWE Top 25, 국가정보원 AI보안 가이드북(2025) 팩의 대응표를 각 판본 원문과 대조해 확인했다. 보고서와 `iron-laws coverage --standard`에 확인된 대응으로 표시된다.

## [1.6.0] - 2026-10-12

### Added
- 코드 삽입(IL-503)이 Java 표현식 언어(SpEL `parseExpression`, OGNL, MVEL)를 본다. 외부 입력이 식에 닿으면 확정 지적이다. 상수가 아닌 SpEL 식을 파싱하거나 함수 밖에서 만든 식을 `StandardEvaluationContext`로 평가하면(형식 참조 `T(...)`로 임의 코드 실행 가능, 컨텍스트 없는 `getValue()`도 이 컨텍스트를 쓴다) 확인 필요 지적이다. `SimpleEvaluationContext`만 쓰는 함수와 상수 식은 지적하지 않는다.
- XSS(IL-505)가 Java에서 응답의 `getWriter()`·`getOutputStream()`을 변수에 담아 쓰는 출력(`PrintWriter out = resp.getWriter(); out.print(...)`)과 `printf`·`format`의 모든 인자를 본다. 출력보다 앞서 같은 경로에서 `setContentType("application/json")`으로 JSON 응답을 정한 출력은 제외한다.
- `benchmarks/cwe_bench_java.py`가 확정 지적 기준과 확인 필요 지적까지 센 기준(`with_review`)을 함께 기록한다.
- Kotlin(.kt, .kts) 구문 분석과 외부 입력 추적: Spring `@RequestParam`·Ktor `call.parameters`·`call.request.queryParameters` 입력, `"$name"`·`${...}` 문자열 템플릿, JVM 싱크(명령 실행·JDBC 등).
- Go 파일 간 해석(같은 패키지의 다른 파일 함수, import 경로 끝부분과 맞는 프로젝트 폴더의 내보낸 함수)과 PHP 파일 간 해석(require·include한 파일의 함수, 프로젝트에서 유일한 함수·클래스의 static 메서드). Go·PHP 주요 보안 규칙의 양성·음성 사례로 검증 칸을 늘렸다.
- `check`·`audit --triage-model "<명령>"`: '확인 필요' 지적에 LLM 검토 의견을 `review_opinion`으로만 붙인다(판정은 바꾸지 않음, 비밀값을 가린 코드 조각만 보냄).
- `iron-laws lsp`: 편집기용 LSP 서버(표준 입출력, 저장하지 않은 내용도 점검).
- `iron-laws habits`: 다섯 습관의 1천 줄당 지적 수를 기록하고 추이를 보여 준다.
- 실측 누락 순환 `benchmarks/realworld_loop.py`와 주간 워크플로: 고정 커밋 실제 프로젝트의 보안 지적 변화를 분류 대기열로 만든다.
- 지원 행렬의 공개 벤치마크 표시에 OWASP Benchmark Python, CWE-Bench-Java, Juliet C/C++·C#를 더했다.
- `audit --format mois-report`: 행안부 구현단계 49개 항목별 지적·잔존과 사유(억제 주석·승인)·미점검 사유(장부 공백·미탑재·건너뛴 파일)를 정리한 감리 대응 보고서. `.docx` 출력은 선택 의존성 `iron-laws[docx]`.
- 보고서 `metadata.suppressions`: 억제된 지적의 규칙·위치·사유·만료일.
- 취약 의존성 도달성 `deps --reachability`: 권고의 영향 함수 정보(OSV `affected_functions`, `imports[].symbols`)가 있을 때만 코드의 호출을 찾아 `reachable`·`no_evidence`·`undetermined`로 표시한다.
- `deps --format openvex`: OpenVEX 0.2.0 문서. 자동 판정은 `affected`·`under_investigation`만이고, `not_affected`는 `--vex-decisions`의 사람 판정(justification 필수)에서만 나온다.
- **AIA-107** 브라우저에서 모델 키로 LLM을 직접 부르는 코드, **AIA-108** 웹 입력을 받는 LLM 호출의 출력 상한 부재, **AIA-109** 개인정보 필드를 외부 LLM으로 보내는 코드.
- 수정 지시문에 우회 수정 금지 목록(억제 주석·테스트 skip·예외 삼키기·도우미로 옮기기)과 규칙별 반례(잘못된 수정·올바른 수정)를 넣었다.
- 반례 접수: 이슈 양식(`.github/ISSUE_TEMPLATE/counterexample.yml`), 처리 절차(`docs/COUNTEREXAMPLES.md`), 처리된 반례의 사례 시험(`tests/counterexamples/`).
- 경쟁 도구 비교 측정기 `benchmarks/compare_tools.py`(오철칙·Semgrep·CodeQL, 개발용·평가용 사례를 나눠 집계).
- **사용자 명세** `iron-laws spec draft|check`와 설정 `policies.custom_spec`: 프로젝트 고유의 소스·싱크·정제 함수를 더한다. 초안은 코드 후보(감싼 싱크 함수, 정제 함수 이름, Lambda event 등)와 선택적 LLM 제안(`--llm-cmd`)으로 만들고, 모든 항목의 양성·음성 예제가 기대대로 판정될 때만 불러온다.
- import 이름 점검: 패키지 색인이 있으면 JavaScript·TypeScript import 이름을 npm 색인과, Python import 이름을 모듈→배포 매핑 색인(`pypi-modules`)과 맞춘다. 매핑 색인이 없으면 Python import는 판정하지 않는다.
- 지적이 30건을 넘으면 콘솔 보고서가 먼저 고칠 3건과 다음 명령을 보여 준다.
- 검증 기록 서명: `verify-patch --sign ssh:<키>`가 기록 옆에 OpenSSH 서명(`.sig`, 이름공간 `iron-laws-receipt`)을 남기고, `evidence verify --allowed-signers`가 서명을 확인한다.
- `iron-laws sbom --format cyclonedx|spdx`: 잠금 파일로 CycloneDX 1.6·SPDX 2.3 JSON SBOM을 만든다. 구성요소는 purl, 관계는 버전 단위(관계 정보가 없는 입력은 추정하지 않음). 같은 입력·시각이면 같은 문서다.
- AI 수정 성공률 측정기 `benchmarks/fix_loop.py`: 지적별 패치 검증 결과를 해결·신규 부채 동반 해결·새 지적 발생·그 밖의 검증 실패·결함 행동 미제거·정적 지적 잔존·우회·시험 실패·판정 불가로 나누고, 정적 지적 소멸률과 결함 행동 제거율을 따로 낸다.
- 수정 지시문 비교 측정기 `benchmarks/fix_prompt_ab.py`: 같은 결함 표본을 두 판의 `fix-prompt` 지시문으로 사용자가 지정한 AI 명령에 고치게 하고, 수정안을 같은 조건으로 검증해 규칙별 결함 행동 제거율을 비교한다. 결과는 docs/ACCURACY.md §4.3에 있다.
- `iron-laws hook claude-code`: Claude Code PostToolUse 훅. 고친 파일을 점검해 기준 이상 지적이 있으면 지적과 고치는 방법을 에이전트에게 돌려준다(종료코드 2). pre-commit 훅 정의(`.pre-commit-hooks.yaml`)와 Claude Code·pre-commit·GitHub Actions·GitLab CI 설정 예시(`docs/ci/`).
- **AIA-103** LLM 응답(소스 종류 `ai_response`)이 검증 없이 코드 실행·명령·SQL 싱크에 닿는 코드. 웹 입력만으로 닿는 흐름은 IL-50x가 알리므로 겹쳐 내지 않는다.
- **AIA-104** 웹 요청의 값이 LLM 시스템 지시 자리(`role: system`, `system=`, `SystemMessage`)에 들어가는 코드. 사용자 메시지 자리는 대상이 아니다.
- **AIA-105** MCP 서버 구현의 도구 설명에 숨은 지시(보이지 않는 글자·비밀 유출·무단 실행 문장), 도구 인자를 검증 없이 파일 경로·명령으로 쓰는 코드.
- 의미 변형 사례집에 AI 공격면 정상·위험 짝 4개를 추가했다.
- **라우트 접근통제 행렬** `iron-laws routes`: Flask·FastAPI·Django(urls.py)·Express·Next.js(app/**/route, pages/api)·Spring·ASP.NET 라우트마다 인증(yes/no/unknown)과 인가(yes/no/unknown/n/a)를 근거와 함께 보인다. 인가 yes는 역할·권한 검사가 있거나 데이터 조회보다 먼저 현재 사용자와 대상의 소유 관계를 비교할 때만이다. 보고서 `metadata.routes`에 요약과 중요 기능 라우트 행이 실린다.
- `audit --format gitlab-codequality`: GitLab merge request Code Quality 보고서. 지문은 기준선 지문을 쓴다. 예시 `docs/ci/gitlab-ci.yml`.
- **기준 팩**: 기준마다 항목과 규칙 대응표를 `standards/packs/<id>/pack.yml`로 둔다. OWASP Top 10:2025, OWASP Top 10 for Agentic Applications 2026, 2025 CWE Top 25, 국가정보원 국가·공공기관 AI보안 가이드북(2025-12, 위협 T01~T15·A01~A11, 대책 M01~M30·A-M01~A-M17) 팩을 추가했고 대응표는 사람이 그 판본으로 확인하기 전까지 `미확인`으로 표시한다(판본·내용이 바뀌면 확인 표시가 자동으로 풀린다). `iron-laws coverage --standard <팩>`.
- 보고서 형식 1.5: 지적의 `standards`(팩·판본·항목·대응표 확인 여부), 선택형 `review_opinion`, `metadata.standard_packs`. `gov_standard`는 그대로 둔다. 독립 검증기는 1.5를 읽고 기준 참조가 팩 목록과 맞는지 확인한다.
- 공개 벤치마크 측정기: `benchmarks/owasp_benchmark_python.py`(OWASP Benchmark for Python), `benchmarks/juliet.py`(Juliet C/C++·C# 1.3, CWE 대응표 포함), `benchmarks/cwe_bench_java.py`(CWE-Bench-Java 함수 단위). 데이터셋 커밋·해시가 다르면 종료코드 2.
- **MCP 서버** `iron-laws mcp --root <폴더>`(stdio, 선택 의존성 `iron-laws[mcp]`): `check`·`explain`·`fix_prompt`·`verify_patch`·`deps` 도구. 경로 입력은 기준 폴더 안만 받고(심볼릭 링크 해석 포함), 시험 명령은 점검 폴더 밖 서버 설정의 `test_presets` 이름으로만 받는다. `regression_spec`을 주면 결함 행동 제거 여부를 정적 지적 소멸과 따로 돌려준다.
- 보고서 `metadata.cross_file.by_language`: 파일 간 해석 횟수와 한도에 걸린 위치 수를 호출한 파일의 언어별로 보여 준다.
- 공통 측정기 `benchmarks/bench_common.py`: 사례(파일·줄 범위 또는 진입 함수·기대 CWE·취약/안전·제외 사유)에 지적을 대응시키고, 분석하지 못한 사례는 TN·FN이 아니라 따로 센다. OWASP Benchmark 측정기가 이를 쓴다.
- 의미 변형 사례집에 파일 경계를 넘는 변형 3종(그대로 돌려주는 함수, 두 파일 사슬, 다른 파일 함수 안에서 외부 입력 읽기)과 kill-rate 평가를 추가했다.
- JavaScript·TypeScript 파일 간 오염 추적: ESM(named·default·namespace·재내보내기 1단계), CommonJS(`module.exports`, `exports.a`, `require` 구조분해·속성), 상대 경로·확장자 후보·`/index.*`, tsconfig `paths` 단일 와일드카드 별칭. 후보가 둘 이상이거나 동적 `import()`·계산된 `require`면 해석 공백으로 센다.
- Java 파일 간 오염 추적: 명시 import·같은 패키지·와일드카드 import로 찾은 클래스의 static 메서드. 동명 클래스·같은 인자 수 중복 정의는 해석 공백, 시험 소스 클래스는 후보에서 뺀다.
- 보고서 `metadata.cross_file.by_language`에 `resolution_gaps`·`resolution_gap_rate`를 추가했다.
- 존재하지 않는 패키지 이름 점검: `iron-laws index build`로 받아 둔 레지스트리 이름 목록을 오프라인 색인으로 만들고, `check`·`audit --package-index`(또는 설정 `policies.package_index`)로 `package.json`·`requirements*.txt`·`pyproject.toml`·잠금 파일의 이름을 맞춘다. 색인에 없는 이름(MEDIUM)·색인 수집 시각 기준 90일 이내 게시(MEDIUM)·철자 유사(HIGH)를 한 지적으로 합치며 모두 확인 필요다. 사설 패키지 패턴은 `policies.private_packages`로 뺀다.

### Changed
- 흐름 해석이 블록·람다 바로 아래의 문장마다 직전 상태를 기록한다(Kotlin처럼 문장 노드 이름이 없는 문법에서도 상태를 조회한다).
- 규칙은 98개에서 104개가 됐다.
- Java 파일 간 해석이 주입 필드 호출(`field.method()`, `this.field.method()`)을 따른다: 필드 형식이 클래스면 그 클래스, 인터페이스면 구현이 하나일 때(여럿이면 `@Primary`가 하나일 때) 그 구현의 인스턴스 메서드. `@Profile`이 붙은 구현이 섞이거나 구현이 모호하면 해석 공백, 지역 변수·매개변수가 필드 이름을 가리면 해석하지 않는다.
- IL-525가 라우트 행렬을 쓴다. 중요 기능 라우트(민감한 GET 포함)에 인증 근거가 없으면 MEDIUM, 전역 설정(Spring 보안 체인의 경로 규칙, Next.js 미들웨어 matcher, 라우트보다 뒤에 등록한 Express 미들웨어)이 이 경로에 적용되는지 정할 수 없으면 LOW로 알리며 모두 확인 필요다. Spring 보안 설정의 `permitAll`·경로별 인증 규칙과 ASP.NET `[AllowAnonymous]`를 평가한다.
- 오염 추적이 객체 필드와 상수 키를 한 단계까지 구분한다(`obj.field`, `d['k']`, `d.get('k')`, `map.put("k", v)`/`map.get("k")`). 다른 필드·키는 오염되지 않고, 필드에 깨끗한 값을 다시 넣으면 그 필드는 깨끗하다. 객체를 통째로 넘기거나 메서드를 부르면 필드 하나라도 오염이면 오염이다. 상수가 아닌 키와 더 깊은 경로는 객체 전체로 본다.
- 오염된 인자 없이 도는 재귀·순환 호출의 반환값은 오염 없음에서 시작해 다른 반환 경로의 오염을 따른다(최소 고정점). 외부 입력이 없는 재귀 함수(디렉터리 순회 등)를 오염으로 보지 않는다. 오염된 인자가 재귀로 넘어가면 이전처럼 오염으로 본다.
- `limits.max_cross_file_lookups`는 점검 전체가 아니라 관심 지점(호출 하나의 판정)마다 적용되는 해석 횟수 상한이다.
- 분석 한도 진단의 건수는 한도에 걸린 서로 다른 위치(함수·호출)의 수다.

### Fixed
- Java 서블릿 요청 입력을 변수 이름이 `request`일 때만 인식하던 문제를 고쳤다. `req`·`httpRequest`·`pReq`처럼 흔한 이름의 `getParameter`·`getHeader` 등도 외부 입력이다.
- 라우트 행렬이 다른 Express 라우터에 건 인증 미들웨어를 `app` 라우트에도 적용하던 문제를 고쳤다. 라우터에 건 미들웨어는 그 라우터의 라우트에만 적용한다.
- 경로 조작(IL-502)이 압축 해제 경로 조작(Zip Slip)을 놓치던 문제를 고쳤다. 압축·메일 첨부 API(`java.util.zip`·`java.util.jar`·commons-compress·zip4j·plexus-archiver·javax.mail, Python `zipfile`·`tarfile`, JavaScript adm-zip·yauzl·unzipper 등)를 가져온 파일에서 항목 이름(`entry.getName()`, `getNextEntry()`, `namelist()`, `entry.entryName` 등)을 외부 입력으로 본다. 압축 항목의 `getName()`·`getFileName()`은 파일 이름만 남기는 정제로 보지 않는다.
- Flink `HandlerRequest.getPathParameter`, Vert.x `RoutingContext.normalisedPath`·`pathParam`, Undertow `HttpServerExchange.getRelativePath` 등 요청 경로·파라미터를 외부 입력으로 본다.
- 반복문이나 분기 안에서 항목마다 하는 기준 폴더 검사(`if (!f.toPath().normalize().startsWith(dir)) throw`)를 인정하지 않아 오탐을 내던 문제를 고쳤다. 검사와 접근을 함께 감싸는 가장 가까운 블록 안에서 검사가 무조건 실행되는지 본다. 다른 조건문 안에만 있는 검사는 계속 인정하지 않는다.
- 기준 폴더 검사와 접근이 같은 조건문의 서로 다른 분기에 있으면 검사를 인정하지 않는다.
- 정규화한 경로를 다른 변수에 담아 검사하는 형태(`String c = f.getCanonicalPath(); if (!c.startsWith(base)) throw`)를 같은 경로의 검사로 인정한다.
- Java `new File(x).getName()`·`new File(x).getCanonicalPath()`처럼 파일에 접근하지 않고 이름·정규 경로만 계산하는 `new File`을 경로 접근으로 지적하지 않는다. `Files.copy(in, target)`의 스트림·내용 인자를 경로 인자로 보지 않는다.
- `iron-laws deps`가 `pnpm-lock.yaml`에서 같은 이름의 패키지를 첫 버전만 점검하던 문제를 고쳤다. 모든 버전을 점검한다.
- `package-lock.json`의 의존 관계를 이름으로 합쳐, 중첩 설치된 다른 버전을 쓰는 패키지를 최상위 버전의 부모로 표시하던 문제를 고쳤다. npm의 설치 위치 해석 순서를 따른다.
- JavaScript·TypeScript에서 `obj.f = 외부 입력` 뒤 `obj.f`를 쓰는 흐름을 놓치던 문제를 고쳤다.
- Python에서 `obj.f`에 상수를 넣으면 객체 전체의 오염이 지워지던 문제를 고쳤다.
- 식 안에 끼어 있는 프로젝트 함수 호출이 함수 안에서 읽은 외부 입력을 돌려줄 때(`'ls ' + read_input(request)`) 식 전체를 오염으로 보지 않던 문제를 고쳤다. 인자 자리의 이런 호출도 도우미 매개변수를 오염시킨다.
- 매개변수·지역 변수가 import 이름을 가리는 호출을 import 대상으로 해석하지 않는다.
- 도우미 함수 호출이 4단계를 넘어 끝까지 따라가지 못한 경로를 안전으로 판정하던 문제를 고쳤다. 판정 불가로 두고 인자의 오염이 결과로 전해진다고 보며, 분석 한도 진단과 장부의 `budget_exceeded`로 남긴다.
- Python에서 import한 함수와 같은 이름의 메서드·지역 함수가 있으면 지역 쪽만 따라가던 문제를 고쳤다. 메서드는 맨 이름 호출의 대상에서 빼고, import와 지역 정의가 함께 있으면 양쪽을 모두 따라가며, 모듈 최상위에서 다시 대입한 이름은 특정 함수로 해석하지 않는다.
- 병렬 점검의 작업 프로세스 수나 파일을 분석한 순서에 따라 지적·장부 상태·분석 한도 건수가 달라질 수 있던 문제를 고쳤다. 작업 프로세스의 한도 건수와 해석 통계를 합산하고, 메모리 절약으로 버린 구문 트리를 파일 간 해석에서 다시 쓰지 않는다.
- IL-101이 형식 표기가 붙은 비밀번호 대입(TypeScript `password: string = "..."`, Python `password: str = "..."`)을 놓치던 문제를 고쳤다.
- IL-101이 `bypass`·`passed`처럼 `pass`가 다른 단어의 일부인 이름과, `34/34` 같은 비율·f-string 자리표시자만 있는 값을 비밀번호로 지적하던 문제를 고쳤다.
- IL-502가 C#에서 `System.IO.File.ReadAllText(...)`처럼 이름 공간을 붙여 부른 파일 API를 싱크로 보지 않던 문제를 고쳤다.
- Python에서 `d[1]`과 `d["1"]`을 같은 칸으로 보아, 문자열 키에 상수를 넣으면 정수 키의 오염이 지워지던 문제를 고쳤다.
- 사용자 명세(`policies.custom_spec`)의 소스·정제 함수가 `languages`에 적지 않은 언어에도 적용되던 문제를 고쳤다.
- 라우트 행렬이 `app.use('/public', authenticate)`처럼 경로를 준 인증 미들웨어를 모든 라우트의 인증으로 보던 문제를 고쳤다. 그 경로 아래 라우트에만 적용한다.
- Go 파일 간 해석이 표준 라이브러리(`strings` 등)나 다른 모듈의 import를 같은 이름의 프로젝트 폴더로 연결하던 문제를 고쳤다. `go.mod`의 모듈 경로로 import 경로를 맞춘다.
- `iron-laws mcp`의 점검이 기준 폴더 밖을 가리키는 심볼릭 링크 파일을 읽던 문제를 고쳤다. 그런 파일은 건너뛰고, 밖을 가리키는 설정 파일과 링크가 든 폴더의 패치 검증은 거부한다.
- 독립 검증기가 `standards`나 `metadata.standard_packs`의 형식이 틀린 보고서에서 멈추던 문제를 고쳤다. `standards.shape` 문제로 보고한다.
- SPDX 출력에서 이름이 바뀐 글자만 다른 패키지(`a_b`와 `a-b`)가 같은 `SPDXID`를 받던 문제를 고쳤다.
- `--triage-model` 응답의 `verdict`가 문자열이 아니면 점검이 멈추던 문제를 고쳤다. 그 항목만 버린다.
- 한 줄에 중첩된 위험 호출(`open(os.path.join(BASE, f))`)이 있으면 장부가 바깥 호출의 지적을 안쪽 지점에 연결하고, 점검 결과의 자체 정합성 검사가 이를 모순으로 보아 점검 전체를 불완전으로 끝내던 문제를 고쳤다. 장부 지점에 연결한 열을 `linked_columns`로 남긴다.

## [1.5.0] - 2026-10-11

### Added
- **취약 의존성 권고** `iron-laws deps`: `uv.lock`·`poetry.lock`·`package-lock.json`(v1~3)·`pnpm-lock.yaml`(v6·v9)·`requirements.txt`(`==`)의 고정 버전을 OSV 권고와 맞춰 보고, 권고가 사라지는 수정 경계와 직접·간접 의존 여부를 보여 준다. 오프라인으로 동작하고 마크다운·JSON·AI 지시문 출력과 `--fail-on`을 지원한다. Git 범위만 있는 권고는 `판정 불가`로 따로 표시한다.
- **구조 진단** `iron-laws architecture`: 순환 의존, 허브 모듈, 큰 함수·파일 비율, 계층 위반·중복 함수 수, 테스트 모듈 비율로 `양호·주의·붕괴·판정 불가`를 내고 단계별 개선안을 낸다. `--format prompt`는 먼저 풀 문제 한 단계를 AI 지시문으로, `--compare`는 이전 진단과의 지표 변화를 보여 준다.
- **AI 에이전트 공격면 규칙(AIA)**: AIA-101(AI 코딩 도구 규칙 파일에 숨은 지시: 눈에 안 보이는 유니코드 채널, 비밀 유출·무단 실행 지시문), AIA-102(MCP 서버 설정: 버전 미고정 실행, 평문 비밀, 인증 없는 원격 서버), AIA-106(`trust_remote_code=True` 등 위험한 모델 불러오기). `.mdc`, `.cursorrules`, `.windsurfrules`를 문서로 읽는다.
- **성능 규칙(PERF)**: PERF-101(한 함수의 DB 조회 과다), PERF-102(중첩 반복·반복 안 리스트 찾기), PERF-103(반복 안 인터넷 요청·순차 `await`), PERF-104(한도 없는 조회), PERF-105(비동기 함수 안의 막는 호출). 모두 `확인 필요` 등급이다.
- 검토 보고서에 "AI 에이전트 공격면"과 "성능" 묶음이 생겼다.
- OSV 서버와의 일치 측정: `benchmarks/deps_osv_crosscheck.py`, 실제 잠금 파일 40개 측정 결과 `docs/benchmark_results/deps_real_locks.json`.

### Changed
- 실행 의존성에 `packaging`이 추가됐다(PEP 440 버전 비교).
- 규칙은 90개에서 98개가 됐다.

### Fixed
- 회귀시험 하네스 JSON, 독립 근거 검증기의 중첩 입력, 파일럿 JSONL의 형식·수치 검증을 강화해 잘못된 입력을 traceback이나 잘못된 결과로 처리하지 않는다.
- 컨테이너 정리의 시간 예산과 실패 근거를 남기고, 작업영역 정리 실패를 기록·경고하며 Receipt를 정리 후 재봉인한다. 정리 오류가 원래 검증 예외를 덮지 않는다.
- 정규식 호출과 LDAP·DB 호출, port와 timeout, 최소·지원·고정 버전, 실제 assert 도우미, 실패 진단·허용 목록 성공·업무 실패 반환을 구분해 오탐을 줄인다. 불명확한 바인딩·위험 입력은 면제하지 않는다.

### Analysis and maintenance
- Python Path의 mkdir·unlink·rmdir·rename·touch 모델과 정상·위험·미해석 사례를 추가했다. Java SQL은 상수 분기·유일한 정적 도우미·불변 컬렉션의 제한 근거만 확인하며 별도 평가 사례를 둔다. 새 공개 벤치마크 수치는 측정하지 않았다.
- CLI 명령군, 스캔 옵션·결과·근거, 장부 값 해석, 패치 비교 문맥과 큰 규칙 모듈을 분리했다. 기존 공개 진입점·옵션·보고서 스키마는 유지하고 함수·처리기별 호출 인덱스를 재사용한다.
- 검증된 규칙·언어 조합은 115/874에서 121/874로 늘었다. CI는 전체 공백 원인과 분모를 기록하고 명시된 고정 범위에만 block 계약과 unknown·미검증 0 상한을 적용한다.
- 판정 의미가 바뀐 12개 규칙의 version을 2로 올렸다. 기존 기준선·승인은 해당 규칙에 대해 재검토될 수 있다. 보고서 JSON schema_version은 1.4를 유지한다.

## [1.4.0] - 2026-10-05

보고서 JSON `schema_version`이 `1.3`에서 `1.4`로 올랐다. 키를 더했고 기존 키는 유지한다. 독립 검증기는 1.3과 1.4를 모두 읽는다.

### Added
- **수정이 만든 부채 표시**: `verify-patch`의 Receipt(`debt_delta`)가 수정 전후의 지적을 하드코딩·구조 붕괴·삼킨 예외·중복 헬퍼·타입 회피별로 해결·유지·신규·이동으로 나누고, 수정 지점과 같은 함수에 새로 생긴 지적을 따로 보여 준다. 통과·실패에는 쓰이지 않는다.
- **신뢰 지표**: `summary`의 `analysis_unknown_rate`(해석을 끝내지 못한 보안 관심 지점의 비율), `unverified_rule_language_rate`(양성·음성 시험이 없는 규칙×언어 조합의 비율), 지적별 `verification_grade`. 미검증 조합이 있으면 통과 표시에 "단, 미검증 조합 포함"이 붙는다.
- **상한 옵션**: `check`·`audit`의 `--max-analysis-unknown-rate`, `--max-unverified-rule-language-rate`. 넘으면 통과가 아니라 재검토(종료코드 1)이며 `summary.gates`·`gate_exceeded`에 남는다. 독립 검증기가 상한 초과 통과와 지표 불일치를 찾는다.
- **정규화 보고서** `iron_laws.core.canonical`: 문서번호·일자·절대 경로를 뺀 보고서로 같은 코드의 점검 결과를 비교한다. 작업 경로·시간대·언어 설정·해시 씨앗·병렬 처리를 바꿔도 같다.
- **파일럿**: 위험 사건 종류 `legitimate_exception`과 상태 `--status investigating`, 조사를 닫는 `pilot close`, 설치 시간 상각값 보고, `review-bundle --pilot-store`(확인된 오승인이나 조사 중인 사건이 있으면 필수 행동으로 종료코드 1).
- `--changed-since`가 이름이 바뀐 파일의 이전·새 경로를 `metadata.scope.renames`에 남긴다.
- `ruleset.hash`에 지원 현황 지문(`ruleset.support_manifest`)이 들어간다.
- 이전 버전과 같은 표본을 비교하는 `benchmarks/plan_experiments_v14.py`, 결과 `docs/benchmark_results/plan_experiments_v1_4.json`.

### Changed
- 파일럿 요약의 주 지표는 총 능동시간(검토 + 추가 시간)이고 중앙값 감소 목표는 20%, 75백분위 악화 없음이다. 순수 검토 시간은 보조 지표다. 위험 수용은 분모와 함께 비율로 보고하며 확인된 오승인과 정당한 예외를 구분한다. 조사 중인 사건이 있으면 판정은 `investigation_pending`이다. 검토 기록의 결과 메모와 위험 기록은 같은 집계에 들어간다.
- 같은 줄의 다른 호출이 낸 지적은 근거로 쓰지 않는다. 지적은 열이 같은 호출에 연결되고, `open(os.path.join(...))`처럼 서로 안에 들어 있는 호출은 한 흐름으로 보아 같은 지적을 쓴다. 나란히 있는 두 번째 위험 호출은 확정 지적이 따로 없으면 `unresolved`로 남아 사람이 확인한다.
- 독립 검증기는 `--changed-since`에서 이름이 바뀐 파일의 승인을 현재 지적과 맺어 확인한다.

### Fixed
- YAML 작은따옴표 문자열 안의 `''` 뒤에 오는 문구, shell의 복수 here-document(`cat <<A <<B`) 두 번째 본문의 문구가 억제 주석으로 인정되던 문제.
- 검사 뒤 `:=`로 값을 다시 대입해도 허용 목록 검사의 면제가 유지되던 문제.
- 타입 지정이 붙은 비밀 이름 대입(`token: string = "..."`, `api_token: str = "..."`)의 값 조각이 다른 규칙의 출력에 남던 문제.
- 승인한 파일을 옮긴 뒤 `check --changed-since`와 `review-bundle --changed-since`가 점검 불완전(종료코드 2)으로 끝나던 문제.
- 검토 시간만 줄고 총 능동시간이 늘어도 파일럿 판정이 목표 충족으로 나오던 문제.

## [1.3.0] - 2026-10-05

판정 신뢰성과 검토 비용 개선. 알려진 잘못된 통과를 고치고, 지적·장부·승인이 같은 실제 근거를 참조하는지 따로 검증하며, 변경 영향에 맞춘 검토 묶음을 더했다.
보고서 JSON `schema_version`이 `1.2`에서 `1.3`으로 올랐다. 키를 더했고 기존 키는 유지하지만, 장부 `finding`의 의미가 좁아졌다(아래 '호환성').

**업그레이드할 때 할 일**
1. 1.2 보고서를 읽는 도구가 있으면 다시 점검하거나 `evidence upgrade`로 옮긴다. 1.2 보고서는 독립 검증기에서 판정 불가다.
2. 승인 기록은 `approvals status`로 확인한다. 흐름에 동적 호출이 있는 승인과 형식 검증에 실패한 승인은 재검토 대상이 될 수 있다.
3. CI에서 종료코드 2가 새로 나올 수 있다. 보고서를 내보내기 전 검증에서 모순을 찾으면 통과로 내보내지 않고 점검 불완전으로 처리한다.
4. ARC-204(중복 함수) 결과가 이전 실행과 달라질 수 있다. 1.2.0은 실행마다 결과가 달랐으므로 기준선에 ARC-204가 있으면 `baseline create`로 다시 만든다.

### Added
- **독립 검증기**(`evidence verify`, `evidence upgrade`): 점검 보고서와 검증 기록의 구조적 모순(없는 지적을 가리킴, 근거 없는 '근거 충족', 다른 파일·규칙의 지적 연결, 차단 사유와 상태의 불일치, 설명할 수 없는 통과, 만료·손상·복제본·다른 정책의 승인 재사용, 다른 checkout의 코드)을 엔진과 독립으로 찾는다. 표준 라이브러리만 쓴다. 지원하지 않는 버전·누락은 통과가 아니라 판정 불가(종료코드 2). 이전 형식 보고서는 근거를 복원할 수 없는 지점이 20% 이상이면 옮기지 않고 재점검으로 넘긴다. 문제 코드와 한계는 [docs/EVIDENCE_VERIFICATION.md](docs/EVIDENCE_VERIFICATION.md)
- 내보내기 관문: `check`·`audit`가 보고서를 내보내기 전에 같은 검증을 거친다. 모순이 있으면 통과가 아니라 `consistency` 오류 진단과 점검 불완전(종료코드 2)으로 표시한다
- 보고서 1.3: 지적마다 `finding_id`, `execution`(실행 식별·코드·도구·설정·계약 지문), `approval_checks[]`, 장부의 `run_id`·`requirements`·지점별 `finding_ids`·`evidence_kind`(finding / closed_value / guard / none)·`suppressed_rules`·`column`, `metadata.scope.changed_paths`, Receipt의 `evidence`(원본·후보 실행 식별과 지적 참조)
- **검토 묶음**(`review-bundle`): 바뀐 전제, 승인별 유지·무효화·판정 불가와 각각의 이유·근거 ID, 필수 행동, 남은 공백, 재현 정보를 구조화된 근거에서 결정적으로 만든다. 호출 대상을 알 수 없는 동적 호출 경계와 점검하지 못한 파일은 영향 없음이 아니라 넓힌 재검토 범위와 공백으로 표시한다
- 승인 `invalid` 상태: 기록의 유효기간 날짜·생성 시각·ID·대상·정책·사유와 파일 전체의 해시 연결을 같은 검증으로 확인해, 실패한 승인은 유효한 승인으로 받아들이지 않는다(`approvals status`·`verify`·`prune`·`check`·`audit`·검토 묶음이 같은 입구를 쓴다)
- 회귀시험의 **변형 입력**(`input.variants`): 시험 입력 하나만 막는 수정(정확한 입력 차단, 한 글자 필터)을 같은 결함을 건드리는 다른 입력으로 가려낸다
- 파일럿 준비: `pilot assign|record|flag|dropout|summary`(같은 PR을 두 조건에 모두 배정하지 않는 교차 배정, 검토 시간·추가 시간·위험 수용 기록, 표본이 부족하면 판정하지 않음)와 `--metrics`(건수·시간·식별 해시만, 경로·코드·메시지 없음, 기본 꺼짐). 파일럿 자체는 수행하지 않았다
- 의미 변형 사례집(개발용·평가용)과 평가기, 벤치마크 `benchmarks/plan_experiments_v13.py`, 결과 `docs/benchmark_results/plan_experiments_v1_3.json`

### Changed
- 안전 면제(허용 목록 검사 `x not in (...)`, 경로 범위 검사)는 검사가 **모든 경로에서 싱크 앞에 실행**되고(`return`·`raise`·`break` 등 최상위 문장, 종료 호출), 검사한 값이 싱크까지 **바뀌지 않을 때**만 인정한다. 검사 뒤 재대입·증분 대입, 조건부로만 실행되는 검사, 문자열 속 `return`, 중첩된 조건 안의 `return`, 검사하지 않은 다른 값의 사용은 면제하지 않는다
- 장부는 지적을 규칙이 실제로 낸 확정 지적(`finding_id`)에서만 가져온다(흐름을 따로 평가해 지적이 있다고 추정하지 않음). 억제는 그 계열 규칙의 지적에만 적용한다(같은 줄의 다른 계열로 번지지 않음). 상태는 차단 사유가 하나라도 있으면 `unmet`이며 `not_applicable`이 이를 가리지 않는다
- 승인 전제 비교는 호출자·호출 함수를 `경로::이름`으로 구분한다(같은 이름의 다른 파일 함수는 다른 대상). 독스트링만 바뀐 변경은 전제를 바꾸지 않는다. 호출 대상을 알 수 없는 동적 호출이 흐름 안에 새로 생기면 재검토 대상이다(1.2.0에서 만든 승인 가운데 흐름에 동적 호출이 있는 것은 한 번 재검토 대상이 될 수 있다)
- `approvals prune`은 지우는 조건이 하나다(만료·철회·삭제 표시 **그리고** `--before` 이전에 만든 승인). 깨진 기록은 정리하지 않는다. `approvals queue`가 `--contract`를 받는다
- 비밀 가림: 길이를 제한하기 전의 원문을 먼저 가린 뒤 제한한다. 비밀 규칙이 지적하지 않은 줄이라도 `password`·`token`·`secret`·`api_key` 등에 대입된 값은(영문자만 있어도) 다른 규칙의 출력에서 가린다. 길이 제한으로 잘린 긴 비밀의 앞·뒤 조각(8자 이상)도 가린다(console·markdown·json·sarif·prompt·review 모두)
- 억제 주석: YAML·shell의 여러 줄 따옴표 문자열, YAML 이스케이프된 큰따옴표, shell `$'...'`·백슬래시 이스케이프 안의 문구는 주석이 아니다. YAML 값 중간의 작은따옴표(`it's`)는 문자열을 열지 않는다
- 도달하는 문맥이 정해져 있으면(셸·경로·SQL 등) 그 문맥에 유효한 정제 함수 호출은 문자열 결합 안에 중첩되어 있어도 그 호출 범위만 깨끗하다(`'ls ' + shlex.quote(request.args['d'])` 확정 지적 → 확인 필요)

### Fixed
- JS 템플릿 문자열·PHP `{}` 보간 안의 입력 원천이 지워져 경로 지적(IL-502)을 놓치던 문제
- 경로 범위 검사 뒤에 다른 값을 대입해 싱크에 쓰는 코드가 안전으로 처리되던 문제
- Java XXE: 첫 사용 뒤에 설정을 되돌려 두 번째 사용이 위험해지는 코드, 같은 이름으로 팩토리를 다시 만드는 코드를 놓치던 문제. 한글 주석이 있는 파일에서 설정 위치가 어긋나 위험 사례를 놓치던 문제(주석의 바이트 수와 글자 수 차이)
- 손상된 `expires`가 `verify`에서는 오류인데 `check`에서는 승인으로 받아들여지던 문제
- 같은 줄에 같은 호출이 둘 이상 있을 때 장부 지점 id가 중복되던 문제(실제 프로젝트 점검에서 독립 검증기가 발견)
- ARC-204(중복 함수 탐지)가 실행마다(Python 해시 시드에 따라) 다른 결과를 내던 문제. 같은 코드인데 결과가 달라지면 기준선·승인과의 대응이 실행마다 어긋난다

### 비용·호환성
- 점검 시간: 같은 코드에서 실제 프로젝트 두 곳(파일 1,371개, 2,940개)의 점검 시간이 35.8초 → 36.6초, 41.9초 → 41.7초로 거의 같다([docs/ACCURACY.md](docs/ACCURACY.md) §4.1). 시험 시간이 늘었다(전체 시험 약 150초 → 약 260초: 변형 사례집과 변형 입력 격리 시험)
- 호환성: 보고서 `schema_version` 1.3은 1.2에 키를 더했다. 장부의 `finding` 의미가 '규칙이 낸 확정 지적이 있음'으로 좁아졌다(허용 목록·범위 검사를 통과한 지점은 지적 없이 `guard` 근거로 `evidence_met`). 1.2 보고서는 독립 검증기에서 판정 불가이며 `evidence upgrade` 또는 재점검이 필요하다. 승인 기록 파일 형식은 그대로다

### 알려진 한계
- 갈래마다 따로 검사하는 코드(한 갈래는 허용 목록, 다른 갈래는 범위 검사)처럼 경로별로 안전한 경우는 알아보지 못해 확정 지적이 남을 수 있다(실제 프로젝트 점검에서 1건 확인)
- 독립 검증기는 구조적 모순만 잡는다. 외부 도구 결과 가져오기, 팀 파일럿, 경쟁 도구 비교는 이번 범위에서 수행하지 않았다

## [1.2.0] - 2026-10-05

### Added
- **근거 계약과 검사 공백 장부**(`--contract`, `coverage_ledger`): 검사 완료(`scan_status`)와 근거 충족(`contract_status`)을 구별한다. Python의 명령 실행·경로 접근·SQL 조립 관심 지점마다 근거 충족 / 미지원 / 해석 미확정 / 예산 초과 / 정책 제외를 기록하고, 분모(발견한 지점, 분류하지 못한 파일)를 함께 공개한다. 보고 모드와 차단 모드, 계약 파일이 변경에 포함되면 `policy_change_review`
- **패치 검증**(`verify-patch`)과 검증 기록(Receipt), 재실행(`--replay`): 원본·후보 스냅샷 해시, 동결된 정책과 원본 시험, 우회 변경 탐지(시험 삭제·skip 증가·단언 약화·무시 주석·정책 약화·baseline 재생성·시험 기반 파일 변경), 동일 조건 정적 검사, 변경 범위, 격리 시험 실행. 항목 결과는 통과 / 실패 / 미실행 / 판정 불가로 구분
- **격리 실행기**: docker 또는 bubblewrap, 네트워크 차단, 비특권 사용자, 자원·시간·출력 상한, 신뢰된 명령 목록. 격리를 얻지 못하면 호스트 실행으로 대체하지 않고 판정 불가
- **회귀시험**(`regression propose|check`, `verify-patch --regression`): 지적에서 시험 후보를 제안하고, 사람이 확정한 명세를 mock sink harness로 원본 실패·후보 통과·mutant 재실패·세 번 반복 일치로 검증
- **승인 기록**(`approvals add|list|status|queue|stats|revoke|verify|forget|prune`, `--approvals`): 사유·전제·정책·Receipt를 추가 전용 해시 연결 기록으로 남기고, 승인 전제(호출자·흐름·호출 함수·정제 함수·접근 범위·규칙 의미·정책)가 바뀌면 관련 승인만 재검토. 복제본은 승인을 물려받지 않음
- `baseline migrate`(승인된 부채로만 옮김, 승인으로 승격하지 않음), `kind: debt`
- JSON `schema_version` 1.2: `coverage_ledger`, `approval_*`, `unobserved_count`
- 벤치마크: `benchmarks/plan_experiments.py`(표본 측정과 원시 결과)
- Python: asyncpg `fetch`·`fetchrow`·`fetchval` SQL 싱크, pathlib 수신자 경로(`(Path(base) / name).read_text()`), 허용 목록 검사(`x not in (...)` → 거부) 인식, `range()`·`enumerate()` 순번과 중첩된 `len()`·`int()`를 오염으로 보지 않음

### Changed
- 기준선 대응을 전체 지적 집합에서 일대일로 먼저 확정하고 표시 범위를 줄인다. 원본이 남은 복제본은 승인을 물려받지 않고, 파일이 없거나 읽지 못한 항목은 해소가 아니라 미확인
- `--changed-since`가 NUL 구분 git 경로를 쓴다(한글·공백·탭·개행·인용부호 경로, 하위 폴더, 스테이징·미추적 파일)
- 억제 지시문은 YAML·shell·TOML·SQL·Dockerfile의 문자열·여러 줄 문자열·here-document 안에서는 주석으로 인정하지 않는다
- 비밀 가림: 원문을 먼저 가린 뒤 길이를 제한하고, 같은 줄의 다른 규칙·message·evidence·진단과 알려진 토큰 형식(GitHub·OpenAI·AWS·Slack·JWT·개인키·URL 인증정보·Authorization·명령행 비밀번호)에도 적용
- 여러 단계 도우미 함수 호출(깊이 4)을 따라가고, 경로 검증은 대상 변수·실행 순서·정규화를 확인하며, XXE는 메서드 범위와 최종 설정 상태를 따른다
- 모든 명령이 불완전·빈 점검 상태를 보존한다. 사람이 읽는 메시지는 stderr로 보내 JSON·SARIF stdout을 오염시키지 않는다
- 릴리스는 시험·린트·자체 점검·3개 OS wheel smoke를 통과해야 게시되고, 태그와 패키지 버전이 같아야 한다
- 지원 행렬의 '모델·패턴'을 '적용(싱크 정의)·적용(패턴)'으로 바꾸고 적용 선언이 분석 보증이 아님을 명시
- `limits.max_cross_file_lookups` 기본값 2000 → 20000(장부 작성이 별도 해석 허용량을 씀)

## [1.1.1] - 2026-10-04

### Fixed
- Windows 등 출력 인코딩이 UTF-8이 아닌 환경(cp1252·cp949)에서 한글 출력이 `UnicodeEncodeError`로 중단되던 문제. CLI 시작 시 출력 인코딩을 UTF-8로 맞춘다 (1.1.0에서 Windows wheel smoke로 발견)

### Changed
- README와 정확도 문서에서 "같은 파일 안만 추적한다"는 옛 설명을 현재 동작(함수 안 분기 합류, Python 파일 간 추적)으로 정정

## [1.1.0] - 2026-10-04

외부 평가 보고서(v1.0.0 대상)에서 재현된 결함과 실행계획(P0~P2)을 반영했다.

### Added
- **점검 완료 상태**: `scan_status`(complete / incomplete / empty)와 구조화된 `diagnostics`. 규칙 오류·파일 읽기 실패·파서 실패는 오류로 기록하고 등급을 `불완전`, 종료코드를 2로 처리한다. 인코딩 문제(CP949 해석 포함)·구문 오류·병렬 처리 중단 후 재시도·분석 한도 초과도 기록한다
- **기준선(baseline)**: `baseline create` / `baseline diff`, `--baseline`. 줄 번호가 아니라 규칙·파일·함수·코드 모양의 지문으로 식별하므로 줄이 밀리거나 파일을 옮겨도 같은 지적으로 인식한다. 규칙 `version`이 바뀌면 `review`로 돌리고, 불완전·빈 점검은 기준선으로 만들 수 없다
- `--changed-since REF`: 바뀐 파일의 지적만 표시하고 범위 제한을 보고서에 표시
- 억제 주석 만료일(`until=YYYY-MM-DD`), 사용되지 않은 억제·등록되지 않은 규칙 ID·만료일 형식 오류 알림
- 설정 선택: `--config`, `--search-parents`, `--respect-gitignore`(설정의 `respect_gitignore`). `fail_on` 우선순위(명령행 > 설정 파일 > 기본값)와 출처를 보고서에 기록
- 지적별 판단 근거 `evidence`(입력 유입 → 전파 → 싱크의 위치와 변수 이름, 코드 원문 제외), SARIF `codeFlows`·`partialFingerprints`·`baselineState`
- 보고서 메타데이터: 도구·규칙셋 버전과 해시, 설정 출처·해시, 언어별 파일 수, 제외 패턴별 건수, 지원하지 않는 확장자별 파일 수, 파일 간 해석 횟수
- Python 파일 간 호출 해석(시범 지원): import를 따라 다른 파일 함수의 반환값 오염과 매개변수 → 싱크 도달을 추적. `limits.max_cross_file_lookups`로 상한을 두고 넘으면 진단으로 남긴다
- 같은 파일·다른 파일의 도우미 함수 안 싱크 추적 (호출부에서 외부 입력이 넘어갈 때 확정 지적)
- `iron-laws support`와 `docs/SUPPORT_MATRIX.md`: 언어·규칙별 구현·시험 검증·공개 벤치마크 현황. 시험 사례에서 자동으로 세며 CI가 최신 여부를 확인한다
- `iron-laws feedback add|summary`: `확인 필요` 지적의 채택·오탐·검토 시간 기록
- CI: Linux·Windows·macOS × Python 3.12·3.13 wheel smoke test(`.github/scripts/smoke.py`)
- 벤치마크 원시 결과(`docs/benchmark_results/`)에 도구 버전·데이터 커밋·TP/FN/FP/TN 기록

### Changed
- 흐름 분석을 실행 순서를 따르는 해석기로 교체: if·switch·try는 갈래별로 실행해 합치고 반복문은 두 번 돌린다. 싱크 뒤의 재대입이 앞선 위험한 사용을 가리지 않는다
- 정제 함수는 도달하는 문맥(HTML·SQL·셸·경로·URL·LDAP·XPath·헤더)에 유효한 것만 인정한다. HTML 이스케이프는 SQL·셸을, `normalize`·`abspath`는 경로 이탈 검사 없이 경로를 정제하지 못한다. 프로젝트에 정의된 함수는 이름이 아니라 본문 동작을 따른다
- SSRF는 요청 본문이 아니라 접속 대상 인자만 본다. Go `QueryContext`는 둘째 인자를 쿼리로 본다. `sh -c` 같은 명시적 셸 실행 배열을 탐지한다. XXE는 설정 값과 적용 대상 객체를 구분한다. 템플릿 파일(HTML·Jinja·Razor)이 XSS 규칙으로 연결되고 `.cts`가 점검 대상에 포함된다. 인증 호출을 주석(TODO)으로 해소하지 않는다
- 억제 주석은 실제 주석에서만 인정한다 (문자열 안의 문구는 무시)
- 비밀값이 든 코드 줄(IL-101, IL-108, IL-111, AI-101~104)은 모든 보고서 형식에서 `****`로 가린다. `fix-prompt`는 `확인 필요` 표시와 확인 지침을 유지한다. SARIF 위치는 저장소 루트 기준 상대 경로이며 인코딩된다. 콘솔이 소스·경로의 `[/oops]` 같은 문자열 때문에 중단되지 않는다
- 없는 경로, 점검 파일 0개, 등록되지 않은 규칙 ID, 빈 `enabled_rules`, 범위를 벗어난 제한값, 잘못된 YAML·UTF-8 설정은 통과가 아니라 종료코드 2다 (`--allow-empty`로 빈 점검만 허용)
- JSON 보고서 `schema_version` 1.1 (`diagnostics`, `evidence`, `fingerprint`, `baseline_status` 등 추가)
- 릴리즈 워크플로가 `.whl`·`.tar.gz`만 첨부한다

### Fixed
- 정확도 문서의 SQL 삽입 `전체` 점수(-1.0% → +5.6%) 정정

## [1.0.0] - 2026-10-04

최초 공개 릴리즈. 행안부 SW 개발보안 가이드(2021) 구현단계 49개 항목 전체와 설계단계 20개 항목에 대응하는 규칙 90개, tree-sitter 기반 분석 엔진(Python, JavaScript/TypeScript, Java, C#, Go, Rust, PHP, C/C++), AI 생성 코드 보정·구조·타입 안전성 규칙, 콘솔·마크다운·JSON·SARIF·AI 수정 지시문·검토 의견서 출력, `coverage`·`explain` 명령, OWASP Benchmark(Java) 정확도 측정 도구와 기록을 포함한다.
