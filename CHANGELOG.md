# 변경 이력

형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따르고, 버전은 [유의적 버전](https://semver.org/lang/ko/)을 따릅니다.
보고서 JSON의 `schema_version`은 도구 버전과 별개로 [docs/REPORT_FORMATS.md](docs/REPORT_FORMATS.md)의 호환 정책을 따릅니다.

## [Unreleased]

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
