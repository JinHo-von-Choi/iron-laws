# 프로젝트 구조 진단

`iron-laws architecture`는 파일 단위 지적과 별개로 프로젝트 전체의 구조 상태를 `양호`, `주의`, `붕괴`, `판정 불가` 중 하나로 보여 줍니다. 먼저 풀 문제와 단계별 개선안도 함께 냅니다.

```bash
iron-laws architecture .                          # 진단과 단계별 개선안
iron-laws architecture . --format prompt          # 먼저 풀 문제 한 단계를 코딩 AI 지시문으로
iron-laws architecture . --format json -o now.json
iron-laws architecture . --compare before.json    # 이전 진단과 지표 비교
```

## 판단 지표

- 서로 물고 도는 모듈 묶음(순환 의존)의 크기
- 많은 곳이 불러 쓰면서 자신도 많은 곳을 부르는 모듈(허브)
- 큰 함수와 큰 파일의 비율
- 계층 위반 수, 중복 함수 수
- 테스트 모듈의 비율
- 최근 커밋에서 자주 바뀌면서 큰 파일(변경 집중). 최근 100커밋의 git 이력이 있어야 나옵니다. 이력이 없거나 저장소가 아니면 비어 있습니다.
- 두 모듈 이상에 같은 모양으로 정의된 정규식(중복 정규식). Python 파일만 봅니다.

개선안은 한 번에 갈아엎지 않고 "순환 끊기, 허브 쪼개기, 큰 함수 나누기"처럼 작은 단계로 나뉩니다. 지표는 구조의 한 단면이며 설계가 좋은지 나쁜지를 보증하지 않습니다.

## 계층 판단

계약이 없으면 폴더 이름으로 계층을 추정합니다.

| 폴더 이름 | 계층 |
|---|---|
| `core`, `domain` | 서비스 |
| `reporters`, `cli`, `api` | 표현 |
| `repository`, `entities` | 데이터 접근 |

계층 이름이 겹치는 프로젝트에서는 이 지표가 근거 없이 나올 수 있으니 다른 지표와 함께 읽으십시오.

## 구조 계약

폴더 이름 추정이 맞지 않으면 `.iron-laws.yml`의 `architecture`에 계약을 적습니다. 계약이 있으면 그 계약으로 의존 방향(ARC-207)을 판정하고, `architecture` 진단의 계층 위반 지표에도 같은 계약을 씁니다. 계약이 없으면 위의 폴더 이름 추정 그대로입니다.

```yaml
architecture:
  layers:                       # 위에서 아래 순서. 위 계층은 아래 계층을 import할 수 있고 반대는 안 됨
    - {name: handlers, paths: ["app/handlers/**"], kind: presentation}   # kind를 주면 DB 드라이버·웹 프레임워크 import도 점검
    - {name: logic,    paths: ["app/logic/**"],    kind: service}
    - {name: store,    paths: ["app/store/**"],    kind: data}
  forbidden:                    # 금지할 import(출발 → 도착)
    - {from: "app/domain/**", to: "app/infra/**", reason: "도메인은 인프라를 몰라야 한다"}
  independent:                  # 한 묶음 안의 서로 다른 패턴끼리 import 금지
    - ["app/plugins/a/**", "app/plugins/b/**"]
  strict: false                 # true면 계층에 속한 파일이 어느 계층에도 속하지 않는 파일을 import하는 것도 지적
```

패턴은 프로젝트 루트 기준 glob입니다. `*`는 한 폴더 안, `**`는 하위 폴더 전체입니다. 파일이 여러 계층 패턴에 맞으면 먼저 적은 계층에 속합니다.
