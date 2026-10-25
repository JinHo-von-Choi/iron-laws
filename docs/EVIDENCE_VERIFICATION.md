# 보고서 모순 검사 (`evidence verify`)

점검 보고서와 검증 기록(Receipt) 안의 **지적·근거 장부·승인·신뢰 지표**가 서로 맞는지 확인합니다. 점검 엔진과 별도의 코드(`src/iron_laws/evidence/verifier.py`)이며, 표준 라이브러리만 쓰고 규칙·분석 엔진·장부 작성 코드를 부르지 않습니다.

- 읽는 보고서 형식: 1.3·1.4·1.5·1.6·1.7·1.8. 그 밖의 형식은 통과가 아니라 판정 불가(종료코드 2)입니다.
- 먼저 객체·목록·숫자·비율 같은 형식을 검사하고, 형식이 틀린 입력은 오류 추적 대신 판정 불가로 돌려줍니다. 형식이 맞아도 내용 사이의 모순은 따로 검사합니다.
- 보고서에 적힌 계산 결과를 그대로 믿지 않고, 참조·집계·상태·실행 식별자를 직접 다시 계산해 비교합니다.
- 1.5 이후 보고서에서는 지적에 붙은 기준 항목(OWASP 등)이 보고서에 적힌 기준 목록·판본을 가리키는지, 대응표 확인 여부가 그 기준의 값과 같은지도 봅니다.

> 통과는 **보고서 안의 내용이 서로 맞는다**는 뜻입니다. 엔진이 처음부터 잘못 판정해 일관되게 적은 오류(예: 위험한 코드를 처음부터 끝까지 안전하다고 적은 경우)는 잡지 못하며, 코드의 안전성이나 승인자의 진위를 증명하지 않습니다.

## 쓰는 곳

| 소비자 | 동작 |
|---|---|
| `check`·`audit` | 보고서를 내기 전에 검사합니다. 모순이 있으면 통과로 내지 않고 `consistency` 오류 진단과 함께 `incomplete`(종료코드 2)로 표시합니다 |
| `iron-laws evidence verify <파일>` | 보고서 또는 검증 기록 파일을 별도 프로세스에서 검사합니다. 종료코드 0 모순 없음 / 1 모순 발견 / 2 판정 불가(지원하지 않는 형식·필요한 정보 누락·읽기 오류) |
| `evidence verify --checkout DIR` | 다른 폴더에 받아 둔 코드의 지문을 다시 계산해, 보고서가 점검한 코드와 같은지 봅니다. 다른 코드의 보고서를 가져다 쓴 경우를 잡습니다 |
| `evidence verify <Receipt> --report <보고서>` | 검증 기록이 그 보고서의 코드로 실행한 것인지 대조합니다. 보고서는 patch를 적용하기 전 원본 코드로 만든 `audit --format json` 결과여야 하며, 코드가 다르면 `receipt.other_run`이 나옵니다 |
| `evidence upgrade` | 1.0~1.2 형식 보고서를 1.3 형식으로 옮깁니다 |
| `verify-patch` | 검증 기록에 원본·수정본 점검의 `run_id`와 지적 ID를 남깁니다(`evidence`) |

`check`·`audit`와 `verify-patch`는 요구하는 것이 달라 최종 판정이 다를 수 있습니다. 같은 코드·계약·설정이면 지적과 근거 장부의 상태·이유는 같고, `verify-patch`만 하는 격리 시험·회귀시험·지적을 숨기는 변경 검사는 검증 기록에 따로 남습니다.

## 통과 조건

통과하려면 네 가지가 모두 맞아야 합니다.

1. 계약이 이 코드에 적용됩니다.
2. 필요한 검사가 정한 코드·설정으로 끝까지 돌았습니다.
3. 요구한 근거가 있고 유효합니다.
4. 막아야 할 지적이 없습니다.

만료, 손상, 실행 안 함, 범위 불명확 가운데 하나라도 있으면 통과 대신 그 이유를 적습니다.

| 계약 상태 | 조건 | 받는 쪽이 할 일 |
|---|---|---|
| 충족 `met` | 유효한 근거가 있습니다 | 근거 요구를 채운 것으로 기록. 전체 통과는 따로 판정 |
| 미충족 `unmet` | 필수 종류에서 막기로 한 공백이 있습니다 | 막고 해당 호출을 보여 줌 |
| 기준 변경 검토 `policy_change_review` | 계약 파일이 이번 변경에 들어 있습니다 | 따로 검토 |
| 해당 없음 `not_applicable` | 분석한 파일이 없고 막을 이유도 없습니다 | 이유를 남김. 다른 차단을 덮지 않음 |
| 불완전 `incomplete` | 검사 실패·실행 안 함·상한 도달·필수 범위 누락·내부 모순 | 통과 금지, 다시 실행할 조건 제시 |

## 잡는 모순 (문제 코드)

| 영역 | 코드 | 잡는 것 |
|---|---|---|
| 지적 | `finding.id_missing` `finding.id_duplicate` `finding.id_mismatch` | 식별자 없음·중복, 규칙·경로·위치·지문에서 다시 계산한 값과 다름(내용이 바뀐 지적, 다른 실행의 지적) |
| 지적 | `finding.path_not_normalized` `finding.line_invalid` | 절대 경로·`..`·역슬래시가 있는 경로, 올바르지 않은 줄 |
| 실행 | `run.id_mismatch` `run.id_not_derived` `run.code_digest_mismatch` `run.contract_digest_mismatch` `run.config_mismatch` | execution과 장부·metadata가 다른 실행의 값, 지문 묶음에서 나온 값이 아닌 `run_id` |
| 실행 | `run.status_mismatch` `run.contract_status_mismatch` `run.error_count_mismatch` `run.files_mismatch` | 점검 상태·계약 상태·오류 수·점검 파일 수가 서로 다름 |
| 실행 | `run.empty_not_marked` `run.incomplete_not_marked` `run.complete_expected` | 점검한 파일이 0개인데 `empty`가 아님, 오류가 있는데 `incomplete`가 아님 |
| 장부 지점 | `point.finding_flag` `point.finding_missing` `point.finding_elsewhere` `point.finding_other_call` `point.finding_wrong_rule` `point.finding_not_confirmed` | 지적 없이 지적 표시, 존재하지 않는 지적·다른 파일·다른 줄·다른 열(1.5에서는 `linked_columns`에 없는 열)·다른 규칙·확정되지 않은 지적의 연결 |
| 장부 지점 | `point.met_without_evidence` `point.kind_ids_mismatch` `point.unmet_with_kind` `point.unmet_with_ids` | 근거 종류 없는 '근거 충족', 충족이 아닌데 근거 종류나 지적이 붙어 있음 |
| 장부 지점 | `point.suppression_too_wide` `point.excluded_unexplained` `point.file_not_analyzed` `point.id_duplicate` | 다른 규칙으로 번진 억제, 이유 없는 정책 제외, 분석 대상이 아닌 파일의 지점, 중복 id |
| 집계·상태 | `tally.total` `tally.in_scope` `tally.by_state` `ledger.blocker_missing` `ledger.blocker_extra` `ledger.unclassified_mismatch` `ledger.unclassified_not_blocked` `ledger.status_mismatch` | 지점 목록과 집계의 불일치, 차단 상태 지점이 사유 목록에서 빠지거나 근거 없는 사유가 남음, 점검하지 못한 변경 파일이 사유에 없음, 사유·분석 파일에서 계산한 상태와 다름(비적용이나 충족이 차단을 가린 경우) |
| 통과 | `pass.incomplete_passed` `pass.contract_unmet_passed` `pass.gate_exceeded_passed` `pass.unexplained` `summary.total_mismatch` `summary.severity_mismatch` | 불완전한 점검·미충족 계약(차단 모드)·상한을 넘은 점검이 통과로 표시됨, 실패 기준 이상의 지적 유무와 맞지 않는 통과 표시, 지적 수 불일치 |
| 파일 목록 대조(1.8) | `coverage.shape` `coverage.count_mismatch` `coverage.unexplained_mismatch` `coverage.unexplained_hidden` | `metadata.file_coverage` 형식 오류, 상태별 수의 합이 목록 수와 다름, 사유 없이 빠진 파일 목록과 수가 다름, 사유 없이 빠진 파일이 있는데 `coverage` 진단이 없음 |
| 신뢰 지표(1.4) | `trust.unknown_rate_mismatch` `trust.pairs_invalid` `trust.unverified_rate_mismatch` `trust.gate_unknown` `trust.gate_mismatch` `trust.grade_unknown` | 장부에서 다시 계산한 `analysis_unknown_rate`와 다른 값, 미검증 조합 수가 평가한 조합 수보다 큼, 비율이 조합 수와 다름, 상한과 지표의 비교 결과가 `gate_exceeded`와 다름, 알 수 없는 검증 등급 |
| 승인 | `approval.valid_without_finding` `approval.valid_other_rule` `approval.valid_fingerprint_differs` `approval.valid_clone_inherited` `approval.valid_not_applied` `approval.approved_without_valid_row` `approval.valid_duplicate` | 이번 실행의 지적이 아닌 승인, 지문·규칙이 다른 승인, 원본이 남아 있는데 복제본이 물려받은 승인 |
| 승인 | `approval.valid_expired` `approval.expiry_invalid` `approval.valid_other_contract` `approval.valid_other_config` | 만료된 승인, 날짜가 아닌 유효기간, 다른 계약·설정에서 한 승인 |
| 코드 | `snapshot.files_missing` `snapshot.code_mismatch` | 다른 폴더의 코드가 보고서가 점검한 코드와 다름(`--checkout`) |
| 기록 | `receipt.seal_mismatch` `receipt.verdict_mismatch` `receipt.pass_not_executed` `receipt.pass_limit_reached` `receipt.target_still_present` `receipt.target_not_in_original` `receipt.check_duplicate` `receipt.result_unknown` `receipt.other_run` | 내용이 바뀐 기록, 필수 항목 결과에서 계산한 판정과 다른 종합 판정, 실행하지 않은·상한에 닿은 항목의 통과, 대상 지적이 수정본에도 남아 있는데 해소로 통과, 다른 실행의 기록 |
| 형식 | `schema.unsupported` `schema.missing` `receipt.schema_unsupported` | 지원하지 않는 버전·필수 근거 누락 → 통과가 아니라 **판정 불가** |

## 이전 형식 보고서 옮기기

`run_id`는 점검 한 번의 식별자이고 `finding_id`는 그 점검 안의 지적 하나의 식별자입니다([REPORT_FORMATS.md](REPORT_FORMATS.md)). `evidence upgrade old.json -o new.json`은 1.0~1.2 보고서를 1.3 형식으로 옮깁니다. 1.3 이후 보고서는 옮길 필요가 없습니다(`옮길 수 없는 형식 버전` 안내와 종료코드 1).

장부의 호출마다 근거를 되살릴 수 있는지 봅니다. **되살릴 수 없는 호출이 20% 이상이면 옮기지 않고 종료코드 1로 멈춥니다.** 이때는 같은 코드를 다시 점검하십시오(`--limit`로 비율 조정, 1.0은 한도 없음).

- 되살릴 수 있는 것: 같은 줄·같은 규칙의 확정 지적이 보고서에 있는 호출(`finding_ids`), 근거 확인 상태가 아닌 호출.
- 되살릴 수 없는 것: 지적 없이 '근거 확인'이던 호출. 상수 값이라서인지 규칙이 인정한 안전 검사 때문인지 이전 형식으로는 구별할 수 없습니다.
- 옮긴 보고서에는 실행 식별(`execution`)이 없어 `evidence verify`는 `판정 불가`로 끝납니다. 근거 확인에는 다시 점검한 보고서를 쓰십시오.
- 승인 기록(`.iron-laws-approvals.jsonl`)은 유효기간 날짜, 승인 ID, 대상 필드 형식 검증을 통과하지 못하면 `invalid`로 표시되어 재검토 대상이 됩니다. 1.2.0에서 만든 승인 가운데 흐름 안에 호출 대상을 알 수 없는 동적 호출이 있는 것은 한 번 재검토 대상이 될 수 있습니다.

## 한계

- 보고서 안의 모순만 잡습니다. 엔진의 오판이 보고서 전체에 일관되게 적혀 있으면 통과합니다.
- 장부의 `linked_columns`(한 줄에 겹친 호출로 함께 연결한 지적의 열 위치)는 장부에 적힌 값을 그대로 씁니다. 원본 코드를 다시 해석하지 않으므로 두 호출이 실제로 겹쳐 있는지는 확인하지 않습니다.
- 해시는 기록이 바뀌었는지 알아채는 데만 쓰입니다. 승인자나 실행자가 누구인지 증명하지 않습니다.
- `--checkout`의 코드 지문 재계산은 UTF-8 파일만 지원합니다. 그 밖의 인코딩은 `판정 불가`입니다.
- `--changed-since`로 바뀐 파일만 표시한 보고서에는 바뀌지 않은 파일의 지적이 없습니다. 보고서에 바뀐 경로 목록(`metadata.scope.changed_paths`)이 있을 때만 이를 모순으로 보지 않습니다.

## 검증 기록 서명

`verify-patch --out receipt.json --sign ssh:<개인키>`는 기록 파일 옆에 OpenSSH 서명(`receipt.json.sig`, 이름공간 `iron-laws-receipt`)을 남깁니다. `evidence verify receipt.json --allowed-signers <허용 서명자 목록>`은 구조 검사와 함께 서명이 목록의 키로 이 내용에 대해 만들어졌는지 확인하고, 서명이 없거나 내용이 바뀌었으면 `signature.invalid` 모순(종료코드 1)으로 셉니다. 허용 서명자 목록은 OpenSSH `allowed_signers` 형식입니다.

```text
reviewer@example.com namespaces="iron-laws-receipt" ssh-ed25519 AAAA...
```

