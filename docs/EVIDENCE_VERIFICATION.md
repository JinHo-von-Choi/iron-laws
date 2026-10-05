# 근거 검증: 점검 보고서와 검증 기록의 독립 검증기

오철칙 1.3은 같은 실행의 **지적·장부(계약)·승인**이 서로 모순되지 않는지를 엔진과 독립으로 확인하는 검증기를 둡니다.
검증기(`src/iron_laws/evidence/verifier.py`)는 표준 라이브러리만 쓰며 규칙·분석 엔진·장부 작성 코드를 호출하지 않습니다.
생산자가 계산한 값을 복사해 기대값으로 삼지 않고, 보고서에 적힌 참조·범위·정책·실행 지문의 불변식을 직접 계산해 대조합니다.

> 통과는 **구조가 일관된다**는 뜻입니다. 엔진이 일관되게 만든 의미 오류(예: 위험한 코드를 일관되게 안전하다고 판정)는 잡지 못하며,
> 코드의 안전성이나 승인자의 진위를 증명하지 않습니다.

## 쓰는 곳

| 소비자 | 동작 |
|---|---|
| `check`·`audit`(내보내기 관문) | 보고서를 내보내기 전에 검증합니다. 모순이 있으면 통과로 내보내지 않고 `consistency` 오류 진단과 함께 `incomplete`(종료코드 2)로 표시합니다 |
| `iron-laws evidence verify <파일>` | 보고서 또는 검증 기록(Receipt) 파일을 새 process에서 검증합니다. 종료코드 0 모순 없음 / 1 모순 발견 / 2 판정 불가(지원하지 않는 버전·누락·읽기 오류) |
| `evidence verify --checkout DIR` | 다른 checkout의 코드 지문을 다시 계산해 보고서가 점검한 코드와 같은지 봅니다(다른 코드의 근거 사용을 탐지) |
| `evidence verify <Receipt> --report <보고서>` | 검증 기록이 그 보고서의 원본·후보 실행에서 나온 것인지 대조합니다. 보고서는 패치를 적용하기 전의 원본 코드에서 만든 `audit --format json` 결과여야 하며, 코드가 다르면 `receipt.other_run`이 나옵니다 |
| `evidence upgrade` | 이전 형식(1.0~1.2) 보고서를 1.3으로 옮깁니다 |
| `verify-patch` | 검증 기록에 원본·후보의 `run_id`·지적 ID를 남깁니다(`evidence`) |

`check`·`audit`의 정적 검사와 `verify-patch`의 추가 시험은 요구하는 것이 다르므로 최종 판정이 같아야 한다고 강제하지 않습니다. 같은 코드·계약·정책이면 공통 근거(지적과 장부)의 상태와 이유는 같습니다. 명령별로 더 요구하는 항목(격리 시험 실행, 회귀시험, 우회 변경)은 `verify-patch`의 별도 항목으로 Receipt에 남습니다.

## 통과의 선행 조건

통과하려면 네 가지가 모두 필요합니다. 필수 계약이 적용 대상이어야 하고, 필수 검사가 지정한 코드·정책에 대해 끝나 있어야 하며, 요구한 근거가 있고 유효해야 하며, 차단할 위반이 없어야 합니다.
만료·손상·미실행·범위 불명확 중 하나라도 있으면 통과 대신 그 이유를 기록합니다. `not_applicable`은 차단 사유가 없고 분석한 파일이 없을 때만 씁니다(차단 사유를 가리지 않습니다).

| 상태 | 대표 조건 | 소비자의 행동 |
|---|---|---|
| 충족(`met`) | 유효한 분석 근거가 있다 | 요건 충족 기록. 전체 통과는 별도 판정 |
| 미충족(`unmet`) | 필수 계약을 깨는 근거 공백이 확인됨 | 차단하고 관련 지점 제시 |
| 정책 변경 검토(`policy_change_review`) | 계약 파일이 이번 변경에 포함됨 | 별도 검토 |
| 비적용(`not_applicable`) | 분석한 파일이 없고 차단 사유도 없다 | 이유 보존. 다른 차단을 덮지 않음 |
| 불완전(`incomplete`) | 검사 실패·미실행·상한 도달·필수 범위 누락, 내부 모순 | 통과 금지, 재실행 조건 제시 |

## 확인하는 불변식(문제 코드)

| 영역 | 코드 | 잡는 것 |
|---|---|---|
| 지적 | `finding.id_missing` `finding.id_duplicate` `finding.id_mismatch` | 식별자 없음·중복, 규칙·경로·위치·지문에서 다시 계산한 값과 다름(내용이 바뀐 지적, 다른 실행의 지적) |
| 지적 | `finding.path_not_normalized` `finding.line_invalid` | 절대 경로·`..`·역슬래시가 있는 경로, 올바르지 않은 줄 |
| 실행 | `run.id_mismatch` `run.id_not_derived` `run.code_digest_mismatch` `run.contract_digest_mismatch` `run.config_mismatch` | execution과 장부·metadata가 다른 실행의 값, 지문 묶음에서 나온 값이 아닌 `run_id` |
| 실행 | `run.status_mismatch` `run.contract_status_mismatch` `run.error_count_mismatch` `run.files_mismatch` | 점검 상태·계약 상태·오류 수·점검 파일 수가 서로 다름 |
| 실행 | `run.empty_not_marked` `run.incomplete_not_marked` `run.complete_expected` | 점검한 파일이 0개인데 `empty`가 아님, 오류가 있는데 `incomplete`가 아님 |
| 장부 지점 | `point.finding_flag` `point.finding_missing` `point.finding_elsewhere` `point.finding_wrong_rule` `point.finding_not_confirmed` | 지적 없이 지적 표시, 존재하지 않는 지적·다른 파일·다른 줄·다른 규칙·확정되지 않은 지적의 연결 |
| 장부 지점 | `point.met_without_evidence` `point.kind_ids_mismatch` `point.unmet_with_kind` `point.unmet_with_ids` | 근거 종류 없는 '근거 충족', 충족이 아닌데 근거 종류나 지적이 붙어 있음 |
| 장부 지점 | `point.suppression_too_wide` `point.excluded_unexplained` `point.file_not_analyzed` `point.id_duplicate` | 다른 규칙으로 번진 억제, 이유 없는 정책 제외, 분석 대상이 아닌 파일의 지점, 중복 id |
| 집계·상태 | `tally.total` `tally.in_scope` `tally.by_state` `ledger.blocker_missing` `ledger.blocker_extra` `ledger.unclassified_mismatch` `ledger.unclassified_not_blocked` `ledger.status_mismatch` | 지점 목록과 집계의 불일치, 차단 상태 지점이 사유 목록에서 빠지거나 근거 없는 사유가 남음, 점검하지 못한 변경 파일이 사유에 없음, 사유·분석 파일에서 계산한 상태와 다름(비적용이나 충족이 차단을 가린 경우) |
| 통과 | `pass.incomplete_passed` `pass.contract_unmet_passed` `pass.unexplained` `summary.total_mismatch` `summary.severity_mismatch` | 불완전한 점검·미충족 계약(차단 모드)이 통과로 표시됨, 실패 기준 이상의 지적 유무와 맞지 않는 통과 표시, 지적 수 불일치 |
| 승인 | `approval.valid_without_finding` `approval.valid_other_rule` `approval.valid_fingerprint_differs` `approval.valid_clone_inherited` `approval.valid_not_applied` `approval.approved_without_valid_row` `approval.valid_duplicate` | 이번 실행의 지적이 아닌 승인, 지문·규칙이 다른 승인, 원본이 남아 있는데 복제본이 물려받은 승인 |
| 승인 | `approval.valid_expired` `approval.expiry_invalid` `approval.valid_other_contract` `approval.valid_other_config` | 만료된 승인, 날짜가 아닌 유효기간, 다른 계약·설정에서 한 승인 |
| 코드 | `snapshot.files_missing` `snapshot.code_mismatch` | 다른 checkout의 코드가 보고서가 점검한 코드와 다름(`--checkout`) |
| 기록 | `receipt.seal_mismatch` `receipt.verdict_mismatch` `receipt.pass_not_executed` `receipt.pass_limit_reached` `receipt.target_still_present` `receipt.target_not_in_original` `receipt.check_duplicate` `receipt.result_unknown` `receipt.other_run` | 내용이 바뀐 기록, 필수 항목 결과에서 계산한 판정과 다른 종합 판정, 실행하지 않은·상한에 닿은 항목의 통과, 대상 지적이 후보에도 남아 있는데 해소 통과, 다른 실행의 기록 |
| 형식 | `schema.unsupported` `schema.missing` `receipt.schema_unsupported` | 지원하지 않는 버전·필수 근거 누락 → 통과가 아니라 **판정 불가** |

## 이전 형식 기록 옮기기

`run_id`는 점검 한 번의 식별자이고 `finding_id`는 그 실행 안에서 지적 하나의 식별자입니다([REPORT_FORMATS.md](REPORT_FORMATS.md)). `evidence upgrade old.json -o new.json`은 1.0~1.2 보고서를 1.3 형식으로 옮깁니다. 이미 1.3인 보고서는 옮길 필요가 없습니다(`옮길 수 없는 형식 버전` 안내와 종료코드 1이 나옵니다). 장부 지점의 근거를 복원할 수 있는지 하나씩 보고,
**복원할 수 없는 지점이 20% 이상이면 자동으로 옮기지 않고 종료코드 1로 멈춰** 같은 코드를 다시 점검하게 합니다(`--limit`로 비율 조정, 1.0은 한도 없음).

- 복원할 수 있는 것: 같은 줄·같은 규칙의 확정 지적이 보고서에 있는 지점(`finding_ids`), 근거 충족이 아닌 지점.
- 복원할 수 없는 것: 지적 없이 '근거 충족'이던 지점(닫힌 값인지 규칙이 인정한 안전 조건인지 이전 형식으로는 구별할 수 없습니다).
- 옮긴 보고서에는 실행 식별(`execution`)이 없어 `evidence verify`는 `판정 불가`로 끝납니다. 근거 확인에는 다시 점검한 보고서를 쓰십시오.
- 승인 기록(`.iron-laws-approvals.jsonl`)의 형식은 1.2.0과 같습니다. 1.3의 형식 검증(유효기간 날짜, 승인 ID, 대상 필드)을 통과하지 못하는 기록은 `invalid`로 표시되어 재검토 대상이 됩니다.
  1.2.0에서 만든 승인 가운데 흐름 안에 호출 대상을 알 수 없는 동적 호출이 있는 것은, 1.3에서 처음 그 경계를 기록하므로 한 번 재검토 대상이 될 수 있습니다.

## 한계

- 구조적 모순만 잡습니다. 엔진이 같은 오판을 일관되게 보고서 전체에 반영하면 통과합니다.
- 해시는 변조·불일치 탐지 근거이며 승인자나 실행자의 진위를 증명하지 않습니다.
- `--checkout`의 코드 지문 재계산은 UTF-8 파일만 지원합니다. 그 밖의 인코딩은 `판정 불가`입니다.
- 변경 범위(`--changed-since`)만 표시한 보고서에서는 변경되지 않은 파일의 지적이 목록에 없습니다. 보고서가 변경 경로(`metadata.scope.changed_paths`)를 알려 주는 경우에만 그 부재를 허용합니다.
