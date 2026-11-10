# 의존성 점검

잠금 파일을 읽어 세 가지를 합니다.

- 취약한 의존성 찾기(`deps`)
- SBOM 만들기(`sbom`)
- 존재하지 않는 패키지 이름 찾기(`--package-index`)

## 취약한 의존성: `iron-laws deps`

`uv.lock`, `poetry.lock`, `package-lock.json`, `pnpm-lock.yaml`, `requirements.txt`(`==`로 고정한 것)에 적힌 버전이 공개 취약점 데이터베이스(OSV)의 권고에 걸리는지 봅니다. 걸리면 몇 버전 이상으로 올려야 권고가 사라지는지도 알려 줍니다. 잠금 파일이 없으면 버전을 알 수 없어 점검하지 않습니다.

```bash
# 권고 목록을 한 번 받아 둡니다(에코시스템별 all.zip)
mkdir -p osv/PyPI osv/npm
curl -o osv/PyPI/all.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
curl -o osv/npm/all.zip  https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip

iron-laws deps . --advisory-db osv                 # 마크다운 보고서
iron-laws deps . --advisory-db osv --format prompt # 코딩 AI에 붙여 넣을 업그레이드 지시문
iron-laws deps . --advisory-db osv --fail-on high  # HIGH 이상 권고가 있으면 종료코드 1
```

- 점검 중에는 네트워크를 쓰지 않고, 코드나 의존성 목록을 어디로도 보내지 않습니다. 권고 목록은 직접 받아 둔 파일을 씁니다.
- 안내하는 버전은 권고가 "이 버전에서 고쳤다"고 적은 버전입니다. 앱과 호환된다는 보증은 아니니 올린 뒤 테스트를 돌리십시오. 직접 의존인지, 간접 의존이면 어느 패키지가 끌어오는지도 보여 줍니다.
- `--reachability`를 붙이면, 권고가 영향받는 함수를 알려 줄 때 코드가 그 함수를 부르는지 봅니다.

  | 결과 | 뜻 |
  |---|---|
  | `reachable` | 부르는 곳을 찾았습니다 |
  | `no_evidence` | 부르는 곳을 못 찾았습니다. 영향이 없다는 뜻은 아닙니다 |
  | `undetermined` | 판단할 수 없습니다 |

- `--format openvex`는 OpenVEX 0.2.0 문서를 씁니다. 자동으로는 `affected`(영향 함수 호출 확인)와 `under_investigation`만 쓰고, `not_affected`는 `--vex-decisions`로 준 사람의 판정 기록에 근거(justification)가 있을 때만 씁니다.
- 권고가 Git 커밋 범위만 주거나 해석할 수 없으면 "영향 여부 판정 불가"로 따로 표시합니다. 영향이 없다는 뜻은 아닙니다.

## SBOM: `iron-laws sbom`

잠금 파일로 CycloneDX 1.6 또는 SPDX 2.3 JSON 형식의 SBOM(소프트웨어 구성 목록)을 만듭니다. 구성요소는 package URL로 적고, 의존 관계는 잠금 파일에 적힌 버전 단위 관계만 씁니다. npm은 실제 설치 위치를 따르고 pnpm은 버전별로 적습니다. `requirements.txt`처럼 관계 정보가 없는 입력은 관계를 추정하지 않고 비워 둡니다.

```bash
iron-laws sbom . --format cyclonedx -o sbom.cdx.json
iron-laws sbom . --format spdx -o sbom.spdx.json --timestamp 2026-10-12T00:00:00Z
```

## 존재하지 않는 패키지 이름: `--package-index`

AI가 지어낸 패키지 이름은, 나중에 누군가 같은 이름으로 악성 패키지를 올리면 그대로 설치됩니다. 레지스트리의 전체 이름 목록으로 오프라인 색인을 만들어 두면, `check`와 `audit`가 `package.json`, `requirements*.txt`, `pyproject.toml`, 잠금 파일(직접·간접 의존 모두)의 이름을 색인과 맞춥니다.

### 색인 만들기

```bash
# 레지스트리의 전체 이름 목록을 받아 색인으로 만듭니다(네트워크를 쓰는 명령은 이것뿐)
iron-laws index fetch --ecosystem pypi --out pkg-index     # 이름 약 90만 개, 수십 MB
iron-laws index fetch --ecosystem npm  --out pkg-index     # 이름 수백만 개, 수백 MB

# 직접 받아 둔 목록(JSON 배열, PEP 691 JSON, 줄마다 이름)으로 만들 수도 있습니다
curl -H "Accept: application/vnd.pypi.simple.v1+json" -o pypi.json https://pypi.org/simple/
iron-laws index build --ecosystem pypi --source pypi.json --out pkg-index \
  --source-name "pypi.org/simple" --collected-at 2026-10-01T00:00:00Z --complete

iron-laws audit . --package-index pkg-index
```

- `index fetch`는 목록이 끝까지 오지 않았으면(응답 형식 오류, npm의 `total_rows`에 못 미치는 행 수) 색인을 만들지 않습니다.
- npm 목록은 `replicate.npmjs.com`의 `_all_docs` 응답이며, 최초 게시일은 들어 있지 않습니다.
- 색인의 수집 시각이 `policies.package_index_max_age_days`(기본 30일)보다 오래되면 `check`와 `audit`가 표준 오류로 갱신을 권합니다. 보고서의 판정에는 영향이 없고, `0`이면 알리지 않습니다.

### 판정 방식

- 색인에 없는 이름은 `확인 필요`(MEDIUM)로, 인기 패키지와 한 글자 다른 이름은 `확인 필요`(HIGH)로 알립니다. 둘 다 해당하면 한 지적으로 합칩니다.
- 목록에 최초 게시일이 있으면, 색인 수집 시각 기준 90일 안에 처음 올라온 패키지도 알립니다. 실행 날짜가 아니라 색인 시각이 기준이라서 같은 색인이면 결과가 같습니다.
- `--complete`를 붙이지 않은 색인(일부 목록)이거나 프로젝트가 쓰는 에코시스템의 색인이 없으면, "없는 이름"은 판정하지 않고 진단으로 알립니다.
- 색인 파일이 manifest.json의 sha256과 다르면 쓰지 않습니다.
- `workspace:`·`file:`·Git·URL 의존, 그리고 `policies.private_packages`(예: `['@acme/*']`)에 맞는 사내 패키지는 공개 색인과 맞추지 않습니다.
- 코드의 import 이름도 맞춥니다. JavaScript·TypeScript는 npm 색인으로 맞춥니다. Python은 모듈 이름→배포 이름 색인(`--ecosystem pypi-modules`, 한 줄에 `모듈 배포이름`)이 있을 때만 판정합니다. 표준 라이브러리, Node 내장 모듈, 프로젝트 안의 모듈은 제외합니다.
- 색인을 주지 않으면 인기 패키지와 철자가 비슷한 이름만 지적합니다.
