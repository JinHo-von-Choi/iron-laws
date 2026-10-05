# 변경 이력

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고, 버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.
보고서 JSON의 `schema_version`은 도구 버전과 별개로 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)의 호환 정책을 따릅니다.

## [Unreleased]

## [1.3.0] - 2026-10-05

판정 신뢰성과 검토 비용 개선. 알려진 잘못된 통과를 닫고, 지적·장부·승인이 같은 실제 근거를 참조하는지 독립적으로 검증하며, 변경 영향에 맞춘 검토 묶음을 더했다.
보고서 JSON `schema_version`이 `1.2`에서 `1.3`으로 올랐다(키 추가만. 기존 키는 유지된다).

### Added
- **독립 검증기**(`evidence verify`, `evidence upgrade`): 점검 보고서와 검증 기록의 구조적 모순(없는 지적을 가리킴, 근거 없는 '근거 충족', 다른 파일·규칙의 지적 연결, 차단 사유와 상태의 불일치, 설명할 수 없는 통과, 만료·손상·복제본·다른 정책의 승인 재사용, 다른 checkout의 코드)을 엔진과 독립으로 찾는다. 표준 라이브러리만 쓴다. 지원하지 않는 버전·누락은 통과가 아니라 판정 불가(종료코드 2). 이전 형식 보고서는 근거를 복원할 수 없는 지점이 20% 이상이면 옮기지 않고 재점검으로 넘긴다. 문제 코드와 한계는 [docs/EVIDENCE_VERIFICATION.md](docs/EVIDENCE_VERIFICATION.md)
- 내보내기 관문: `check`·`audit`가 보고서를 내보내기 전에 같은 검증을 거친다. 모순이 있으면 통과가 아니라 `consistency` 오류 진단과 점검 불완전(종료코드 2)으로 표시한다
- 보고서 1.3: 지적마다 `finding_id`, `execution`(실행 식별·코드·도구·설정·계약 지문), `approval_checks[]`, 장부의 `run_id`·`requirements`·지점별 `finding_ids`·`evidence_kind`(finding / closed_value / guard / none)·`suppressed_rules`·`column`, `metadata.scope.changed_paths`, Receipt의 `evidence`(원본·후보 실행 식별과 지적 참조)
- **검토 묶음**(`review-bundle`): 바뀐 전제, 승인별 유지·무효화·판정 불가와 각각의 이유·근거 ID, 필수 행동, 남은 공백, 재현 정보를 구조화된 근거에서 결정적으로 만든다. 호출 대상을 알 수 없는 동적 호출 경계와 점검하지 못한 파일은 영향 없음이 아니라 넓힌 재검토 범위와 공백으로 표시한다
- 승인 `invalid` 상태: 기록의 유효기간 날짜·생성 시각·ID·대상·정책·사유와 파일 전체의 해시 연결을 같은 검증으로 확인해, 실패한 승인은 유효한 승인으로 받아들이지 않는다(`approvals status`·`verify`·`prune`·`check`·`audit`·검토 묶음이 같은 입구를 쓴다)
- 회귀시험의 **변형 입력**(`input.variants`): 시험 입력 하나만 막는 수정(정확한 입력 차단, 한 글자 필터)을 같은 결함을 건드리는 다른 입력으로 가려낸다
- 파일럿 준비: `pilot assign|record|flag|dropout|summary`(같은 PR을 두 조건에 노출하지 않는 교차 배정, 검토 시간·추가 시간·위험 수용 기록, 표본이 부족하면 판정하지 않음)와 `--metrics`(건수·시간·식별 해시만, 경로·코드·메시지 없음, 기본 꺼짐). 파일럿 자체는 수행하지 않았다
- 의미 변형 사례집(개발용·평가용)과 평가기, 벤치마크 `benchmarks/plan_experiments_v13.py`, 결과 `docs/benchmark_results/plan_experiments_v1_3.json`

### Changed
- 안전 면제(허용 목록 검사 `x not in (...)`, 경로 범위 검사)는 검사가 **모든 경로에서 싱크 앞에 실행**되고(`return`·`raise`·`break` 등 최상위 문장, 종료 호출), 검사한 값이 싱크까지 **바뀌지 않을 때**만 인정한다. 검사 뒤 재대입·증분 대입, 조건부로만 실행되는 검사, 문자열 속 `return`, 중첩된 조건 안의 `return`, 검사하지 않은 다른 값의 사용은 면제하지 않는다
- 장부는 지적을 규칙이 실제로 낸 확정 지적(`finding_id`)에서만 가져온다(흐름을 따로 평가해 지적이 있다고 추정하지 않음). 억제는 그 계열 규칙의 지적에만 적용한다(같은 줄의 다른 계열로 번지지 않음). 상태는 차단 사유가 하나라도 있으면 `unmet`이며 `not_applicable`이 이를 가리지 않는다
- 승인 전제 비교는 호출자·호출 함수를 `경로::이름`으로 구분한다(같은 이름의 다른 파일 함수는 다른 대상). 독스트링만 바뀐 변경은 전제를 바꾸지 않는다. 호출 대상을 알 수 없는 동적 호출이 흐름 안에 새로 생기면 재검토 대상이다(1.2.0 승인 중 흐름에 동적 호출이 있는 것은 한 번 재검토 대상이 될 수 있다)
- `approvals prune`은 지우는 조건이 하나다(만료·철회·삭제 표시 **그리고** `--before` 이전에 만든 승인). 깨진 기록은 정리하지 않는다. `approvals queue`가 `--contract`를 받는다
- 비밀 가림: 길이를 제한하기 전의 원문을 먼저 가린 뒤 제한한다. 비밀 규칙이 지적하지 않은 줄이라도 `password`·`token`·`secret`·`api_key` 등에 대입된 값은(영문자만 있어도) 다른 규칙의 출력에서 가린다. 길이 제한으로 잘린 긴 비밀의 앞·뒤 조각(8자 이상)도 가린다(console·markdown·json·sarif·prompt·review 모두)
- 억제 주석: YAML·shell의 여러 줄 따옴표 문자열, YAML 이스케이프된 큰따옴표, shell `$'...'`·백슬래시 이스케이프 안의 문구는 주석이 아니다. YAML 값 중간의 작은따옴표(`it's`)는 문자열을 열지 않는다
- 도달하는 문맥이 정해져 있으면(셸·경로·SQL 등) 그 문맥에 유효한 정제 함수 호출은 문자열 결합 안에 중첩되어 있어도 그 호출 범위만 깨끗하다(`'ls ' + shlex.quote(request.args['d'])` 확정 지적 → 확인 필요)

### Fixed
- JS 템플릿 문자열·PHP `{}` 보간 안의 입력 원천이 지워져 경로 지적(IL-502)을 놓치던 문제
- 경로 범위 검사 뒤에 다른 값을 대입해 싱크에 쓰는 코드가 안전으로 처리되던 문제
- Java XXE: 첫 사용 뒤에 설정을 되돌려 두 번째 사용이 위험해지는 코드, 같은 이름으로 팩토리를 다시 만드는 코드를 놓치던 문제. 설정 위치를 계산할 때 주석의 바이트·글자 수 차이로 한글 주석이 있는 파일에서 위험 사례를 놓치던 문제
- 손상된 `expires`가 `verify`에서는 오류인데 `check`에서는 승인으로 받아들여지던 문제
- 같은 줄에 같은 호출이 둘 이상 있을 때 장부 지점 id가 중복되던 문제(실제 프로젝트 점검에서 독립 검증기가 발견)
- ARC-204(중복 함수 탐지)가 실행마다(Python 해시 시드에 따라) 다른 결과를 내던 문제. 같은 코드의 점검 결과가 실행에 따라 달라지면 승인·기준선 대응이 흔들린다

### 비용·호환성
- 점검 시간: 같은 코드에서 실제 프로젝트 두 곳(파일 1,371개, 2,940개)의 점검 시간이 35.8초 → 36.6초, 41.9초 → 41.7초로 거의 같다([docs/ACCURACY.md](docs/ACCURACY.md) §4.1). 시험 시간이 늘었다(전체 시험 약 150초 → 약 260초: 변형 사례집과 변형 입력 격리 시험)
- 호환성: 보고서 `schema_version` 1.3은 1.2에 키를 더했다. 장부의 `finding` 의미가 '규칙이 낸 확정 지적이 있음'으로 좁아졌다(허용 목록·범위 검사를 통과한 지점은 지적 없이 `guard` 근거로 `evidence_met`). 1.2 보고서는 독립 검증기에서 판정 불가이며 `evidence upgrade` 또는 재점검이 필요하다. 승인 기록 파일 형식은 그대로다

### 알려진 한계
- 갈래마다 따로 검사하는 코드(한 갈래는 허용 목록, 다른 갈래는 범위 검사)처럼 경로별로 안전한 경우는 알아보지 못해 확정 지적이 남을 수 있다(실제 프로젝트 점검에서 1건 확인)
- 독립 검증기는 구조적 모순만 잡는다. 평가용 사례집도 구현자가 만든 것이라 독립 검토가 아니다. 외부 도구 결과 가져오기, 팀 파일럿, 경쟁 도구 비교는 이번 범위에서 수행하지 않았다

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
