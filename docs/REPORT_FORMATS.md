# 보고서 형식과 호환 정책

## JSON (`audit --format json`)

최상위 키: `schema_version`, `document_id`, `title`, `auditor`, `audit_date`, `target_path`, `summary`, `violations`, `diagnostics`, `coverage_ledger`, `execution`, `approval_checks`, `metadata`.

### 버전 정책
- `schema_version`은 `주.부` 형식이다. 현재 `1.3`(1.3에서 `finding_id`·`execution`·`approval_checks`와 장부 근거 필드를 추가했다). 독립 검증기는 지원하는 버전만 확인하며, 그 밖의 버전은 통과가 아니라 `판정 불가`로 끝낸다([EVIDENCE_VERIFICATION.md](EVIDENCE_VERIFICATION.md)).
- 키를 **추가**하면 부 버전을 올린다. 소비하는 쪽은 모르는 키를 무시해야 한다.
- 키를 **삭제하거나 의미를 바꾸면** 주 버전을 올리고 CHANGELOG에 알린다. 주 버전이 같으면 기존 키는 유지된다.
- 기준선 파일(`.iron-laws-baseline.json`)은 별도의 `schema_version`(정수)을 가진다. 형식이 바뀌면 이전 기준선은 읽지 않고 다시 만들도록 안내한다.

### `summary`
| 키 | 의미 |
|---|---|
| `scan_status` | `complete`(끝까지 점검) / `incomplete`(일부를 점검하지 못함, 오류 진단 있음) / `empty`(점검한 파일 0개) |
| `grade` | A+~F. `incomplete`면 `불완전`, `empty`면 `점검 없음`이며 어느 쪽도 통과로 판정하지 않는다 |
| `is_passed` | `--fail-on` 기준 통과 여부. 기준선을 쓰면 신규·재검토 지적만 센다 |
| `new_count`, `existing_count`, `resolved_count`, `unobserved_count` | 기준선을 쓸 때만 채워진다. 기준선 대응은 전체 지적 집합에서 확정한 뒤 표시 범위(`--changed-since`)를 줄인다. 파일이 없거나 읽지 못한 항목은 해소가 아니라 `unobserved_count`다 |
| `contract_status`, `contract_mode` | 근거 계약 충족 여부(`met` / `unmet` / `policy_change_review` / `not_applicable`)와 모드. `scan_status`와 별개다 |
| `approvals_valid`, `approvals_review`, `approvals_unobserved` | 승인 기록(`--approvals`)을 쓸 때만 채워진다 |

### `violations[]`
기존 키에 더해 다음이 있다.
- `fingerprint`: 규칙·파일·함수·코드 모양으로 만든 지문. 줄 번호가 밀려도 같다.
- `finding_id`: 이 점검 실행의 지적 식별자(`F-` + 규칙·경로·줄·열·지문의 해시). 장부·승인·검증 기록이 같은 지적을 가리키는 키다. 줄이 밀리면 바뀌므로 실행을 넘어 같은 지적을 맺을 때는 `fingerprint`를 쓴다.
- `scope_name`: 지적이 속한 함수 이름(구문 분석 언어)
- `rule_version`: 규칙 판정 의미의 버전. 올라가면 기준선의 기존 지적이 `review`로 바뀐다.
- `evidence[]`: 입력 유입 → 전파 → 싱크의 `role`·`file_path`·`line`·`note`. **코드 원문과 값은 담지 않는다.** 외부 입력 흐름을 추적하는 규칙에서만 채워진다.
- `baseline_status`: `new` / `existing` / `review` (기준선을 쓸 때만)
- `approval_status`: `approved` / `needs_review` / `expired` / `revoked` / `invalid`(승인 기록의 무결성·형식 검증에 실패) / `none` (승인 기록을 쓸 때만), `approval_id`, `approval_reasons`(승인을 유지할 수 없는 이유)
- `snippet`: 비밀값이 있을 수 있는 규칙(IL-101, IL-108, IL-111, AI-101~104)은 값을 `****`로 가린 줄이다.

### `coverage_ledger`
`contract_*`(버전·모드·범위·해시·출처), `digests`(code·tool·config·contract), `run_id`(지문 묶음에서 만든 실행 식별자 `R-…`), `requirements`(계열별 필수 여부·차단 상태. 독립 검증기가 차단 사유를 다시 계산하는 입력), `families[]`(계열별 지점 수와 상태별 수), `points[]`(계열·경로·줄·열·호출·상태·이유·범위 안 여부·지적 여부), `files[]`(분류: analyzed / unsupported_language / out_of_scope / policy_excluded / unclassified), `unclassified_changed_files`, `status`, `blockers`, `limitations`. 자세한 의미는 [PATCH_VERIFICATION.md](PATCH_VERIFICATION.md).

`points[]`의 근거 필드(1.3): `finding_ids`(그 지점·계열의 규칙이 실제로 낸 확정 지적의 `finding_id`), `evidence_kind`(`finding` 지적이 났다 / `closed_value` 모든 입력이 닫혀 있다 / `guard` 규칙이 인정한 안전 조건(허용 목록·범위 검증·셸을 거치지 않는 호출) / `none`), `suppressed_rules`(이 지점에서 억제된 규칙. 억제는 그 계열 규칙에만 적용한다). `finding`은 `finding_ids`가 비어 있지 않을 때만 참이며, 장부는 흐름을 따로 평가해 지적이 있다고 추정하지 않는다.
상태 계산 순서: 차단 사유가 하나라도 있으면 `unmet`(비적용·충족보다 먼저), 정책 변경이 있으면 `policy_change_review`, 차단 사유가 없고 분석한 파일이 없을 때만 `not_applicable`, 그 밖에는 `met`.

### `execution`(1.3)
`run_id`, `tool_version`, `ruleset_hash`, `config_hash`, `contract_digest`, `code_digest`, `scan_status`, `files_scanned`, `files_skipped`, `error_diagnostics`, `cross_file_limit_hits`. 이 보고서를 만든 점검 실행의 식별과 범위이며, 지적·장부·승인이 같은 실행의 근거인지 확인하는 기준이다. `code_digest`는 `(경로, 본문의 sha256)`을 경로순으로 sha256한 앞 16자다.

### `approval_checks[]`(1.3, `--approvals`를 쓸 때만)
`approval_id`, `status`(`valid` / `needs_review` / `invalid` / `revoked` / `resolved` / `unobserved`), `reasons`, `rule_id`, `path`, `approved_fingerprint`, `finding_id`(이번 실행에서 맺어진 지적), `expires`, `policy`(승인 당시 계약·설정·규칙·도구 지문). `valid`는 같은 코드 모양의 지적에 대한 유효한 승인이라는 뜻이다. 승인 기록 파일의 해시 연결이나 기록 형식이 틀리면 그 승인은 `invalid`이며 유효한 승인으로 쓰지 않는다.

### `diagnostics[]`
`kind`(read, encoding, parse, rule_error, worker, analysis_limit, suppression, baseline, approval, consistency), `severity`(info, warning, error), `message`, `file_path`, `line`.
`error`가 하나라도 있으면 `scan_status`가 `incomplete`다. `consistency`는 보고서를 내보내기 전에 독립 검증기가 찾은 내부 모순이며, 있으면 통과로 내보내지 않고 `incomplete`로 표시한다.

### `metadata`
`tool_version`, `ruleset`(규칙 수·해시·규칙별 버전), `config`·`config_source`·`config_hash`·`fail_on_source`, `files_by_language`, `skipped_files`, `excluded_summary`(제외 패턴별 파일·폴더 수), `unscanned_by_extension`(지원하지 않는 확장자 파일 수), `cross_file`(파일 간 해석 횟수와 한도 초과 수), `repo_relative_prefix`, `scope`(`--changed-since` 사용 시: `mode`·`ref`·`changed_files`·`changed_paths`·`full_findings`), `baseline`.

## SARIF (`audit --format sarif`)
- 버전 2.1.0. 결과 위치는 **저장소 루트(`.git`이 있는 가장 가까운 상위 폴더) 기준 상대 경로**이고 `uriBaseId`는 `%SRCROOT%`, 경로 구간은 URI 인코딩된다.
- `partialFingerprints["ironLaws/v1"]`에 지문, `baselineState`에 기준선 대비 상태(`new`/`unchanged`), `codeFlows`에 입력 유입 → 전파 → 싱크 흐름을 담는다.
- GitHub Code Scanning 업로드 전체 흐름은 이 저장소의 시험에서 실행하지 않았다. 생성물의 구조와 경로 규격만 시험한다.

## 마크다운·검토 의견서·수정 지시문
- 마크다운 보고서에는 점검 완료 상태, 도구·규칙셋 버전, 설정 출처, 점검 진단, 판단 근거, 기준선 대비 상태가 들어간다.
- 수정 지시문(`fix-prompt`)은 `확인 필요` 지적에 "먼저 흐름을 확인하라"는 지침을 붙이고, 기준선을 쓰면 신규·재검토 지적만 담는다. 비밀값은 가려서 담는다.

## 패치 검증 기록 (Receipt, `verify-patch -o`)
`schema_version`(정수 문자열, 현재 `1`), `created`, `options`(재실행에 필요한 입력), `inputs`(원본·후보 트리 해시, patch 해시·파일, 되돌린 신뢰 파일), `digests`, `environment`(실행기·이미지 ID·격리 여부), `target`, `checks[]`(`id`·`title`·`result`·`required`·`executed`·`reason`·`evidence`·`duration_s`·`limit_reached`), `findings`, `evidence`(원본·후보 점검의 `run_id`·`code_digest`·`finding_ids`·`fingerprints`·`scan_status`), `coverage`, `bypass_changes[]`, `verdict`(`overall`: verified / failed / undeterminable), `receipt_digest`.
`result`는 `pass`/`fail`/`not_run`/`unknown`이며 실패와 미실행을 합치지 않는다. `receipt_digest`는 변조 탐지용 무결성 해시다.

## 승인 기록 (`.iron-laws-approvals.jsonl`)
한 줄이 JSON 하나이며 추가 전용이다. `kind`(approve / revoke / forget), `seq`, `prev`·`hash`(앞 줄을 이어받는 해시), `finding`(규칙·버전·경로·함수·지문), `reason`, `reviewer`(인증되지 않은 표기), `expires`, `policy`(승인 당시 정책 해시), `flow`, `dependencies`(의존성 지문), `receipt_digest`, `minutes`. 코드 원문과 비밀값은 담지 않는다.

## 회귀시험 명세 (`regression propose`)
`family`(command / path / sql), `target`(모듈·함수·파일), `source`(request 또는 매개변수), `input`(payload·benign), `expect`, `call_args`, `fake_sink`, `review_notes`, `confirmed`. `confirmed: true`인 명세만 검증에 쓰인다. `input.variants`(1.3)는 같은 결함을 건드리는 다른 입력이며, 시험 입력 하나만 막는 수정을 가려내는 데 쓴다([PATCH_VERIFICATION.md](PATCH_VERIFICATION.md)).

## 검토 묶음 (`review-bundle --format json`)
`schema`(`iron-laws.review-bundle/1`), `run`, `counts`(keep·invalidate·undeterminable·resolved·revoked), `changed_premises[]`(`kind`: file / premise / policy), `approvals[]`(`decision`, `why_changed`, `why_kept`, `boundaries`, `evidence`: 승인·지적·지문·검증 기록 ID와 기록된·현재 정책), `actions[]`, `gaps[]`, `reproduction`, `caveat`. 같은 입력이면 같은 묶음이 나온다.

## 점검 계측 (`--metrics`)
한 줄이 JSON 하나다. `schema`(`iron-laws.metrics/1`), `at`, `command`, `tool_version`, `run_id`, `elapsed_s`, `scan_status`, `files_scanned`, `findings`(건수), `contract`(상태·범위 안 지점 수·공백 수·`unknown_rate`), `approvals`, `review_queue_size`, `diagnostics`(건수), `passed`. 경로·코드·메시지·이름은 담지 않으며 기본은 꺼짐이다.

## 파일럿 기록 (`.iron-laws-pilot.jsonl`)
`assign`(팀·PR 이름표·난도층·조건·블록), `review`(분 단위 시간·추가 시간·위험 수용 여부), `risk`, `dropout`. 식별자와 수치만 담는다.
