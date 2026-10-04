# 보고서 형식과 호환 정책

## JSON (`audit --format json`)

최상위 키: `schema_version`, `document_id`, `title`, `auditor`, `audit_date`, `target_path`, `summary`, `violations`, `diagnostics`, `metadata`.

### 버전 정책
- `schema_version`은 `주.부` 형식이다. 현재 `1.1`.
- 키를 **추가**하면 부 버전을 올린다. 소비하는 쪽은 모르는 키를 무시해야 한다.
- 키를 **삭제하거나 의미를 바꾸면** 주 버전을 올리고 CHANGELOG에 알린다. 주 버전이 같으면 기존 키는 유지된다.
- 기준선 파일(`.iron-laws-baseline.json`)은 별도의 `schema_version`(정수)을 가진다. 형식이 바뀌면 이전 기준선은 읽지 않고 다시 만들도록 안내한다.

### `summary`
| 키 | 의미 |
|---|---|
| `scan_status` | `complete`(끝까지 점검) / `incomplete`(일부를 점검하지 못함, 오류 진단 있음) / `empty`(점검한 파일 0개) |
| `grade` | A+~F. `incomplete`면 `불완전`, `empty`면 `점검 없음`이며 어느 쪽도 통과로 판정하지 않는다 |
| `is_passed` | `--fail-on` 기준 통과 여부. 기준선을 쓰면 신규·재검토 지적만 센다 |
| `new_count`, `existing_count`, `resolved_count` | 기준선을 쓸 때만 채워진다 |

### `violations[]`
기존 키에 더해 다음이 있다.
- `fingerprint`: 규칙·파일·함수·코드 모양으로 만든 지문. 줄 번호가 밀려도 같다.
- `scope_name`: 지적이 속한 함수 이름(구문 분석 언어)
- `rule_version`: 규칙 판정 의미의 버전. 올라가면 기준선의 기존 지적이 `review`로 바뀐다.
- `evidence[]`: 입력 유입 → 전파 → 싱크의 `role`·`file_path`·`line`·`note`. **코드 원문과 값은 담지 않는다.** 외부 입력 흐름을 추적하는 규칙에서만 채워진다.
- `baseline_status`: `new` / `existing` / `review` (기준선을 쓸 때만)
- `snippet`: 비밀값이 있을 수 있는 규칙(IL-101, IL-108, IL-111, AI-101~104)은 값을 `****`로 가린 줄이다.

### `diagnostics[]`
`kind`(read, encoding, parse, rule_error, worker, analysis_limit, suppression, baseline), `severity`(info, warning, error), `message`, `file_path`, `line`.
`error`가 하나라도 있으면 `scan_status`가 `incomplete`다.

### `metadata`
`tool_version`, `ruleset`(규칙 수·해시·규칙별 버전), `config`·`config_source`·`config_hash`·`fail_on_source`, `files_by_language`, `skipped_files`, `excluded_summary`(제외 패턴별 파일·폴더 수), `unscanned_by_extension`(지원하지 않는 확장자 파일 수), `cross_file`(파일 간 해석 횟수와 한도 초과 수), `repo_relative_prefix`, `scope`(`--changed-since` 사용 시), `baseline`.

## SARIF (`audit --format sarif`)
- 버전 2.1.0. 결과 위치는 **저장소 루트(`.git`이 있는 가장 가까운 상위 폴더) 기준 상대 경로**이고 `uriBaseId`는 `%SRCROOT%`, 경로 구간은 URI 인코딩된다.
- `partialFingerprints["ironLaws/v1"]`에 지문, `baselineState`에 기준선 대비 상태(`new`/`unchanged`), `codeFlows`에 입력 유입 → 전파 → 싱크 흐름을 담는다.
- GitHub Code Scanning 업로드 전체 흐름은 이 저장소의 시험에서 실행하지 않았다. 생성물의 구조와 경로 규격만 시험한다.

## 마크다운·검토 의견서·수정 지시문
- 마크다운 보고서에는 점검 완료 상태, 도구·규칙셋 버전, 설정 출처, 점검 진단, 판단 근거, 기준선 대비 상태가 들어간다.
- 수정 지시문(`fix-prompt`)은 `확인 필요` 지적에 "먼저 흐름을 확인하라"는 지침을 붙이고, 기준선을 쓰면 신규·재검토 지적만 담는다. 비밀값은 가려서 담는다.
