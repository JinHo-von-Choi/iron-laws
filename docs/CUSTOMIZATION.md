# 프로젝트에 맞추기

오철칙이 모르는 사내 함수를 알려 주는 사용자 명세, 로그인 검사 구조·소속 경계·감사 기록·기준선 비교 설정, 채택한 판단을 남기는 교훈 기록을 설명합니다.

## 사용자 명세

사내 프레임워크의 입력 함수나 명령 실행을 감싼 함수는 오철칙이 모릅니다. 사용자 명세로 알려 주면 점검에 반영됩니다. 명세에는 다섯 종류를 적습니다.

| 종류 | 키 | 뜻 | 예 |
|---|---|---|---|
| 소스 | `sources` | 외부 입력이 들어오는 함수 | 사내 프레임워크의 요청 값 읽기 |
| 싱크 | `sinks` | 외부 입력이 닿으면 위험한 호출 | 셸 명령을 감싼 사내 함수 |
| 정제 함수 | `sanitizers` | 값을 안전하게 바꾸는 함수 | 사내 이스케이프 함수 |
| 검사 함수 | `validators` | 참·거짓으로 값이 안전한지 알리는 함수 | `if not is_safe_name(n): return` |
| 라이브러리 요약 | `summaries` | 외부 함수가 오염을 옮기는지(`propagate`), 경로를 정규화하는지(`normalize`) | `copy_into(src, dst)`, `FileUtils.resolveFile` |

- 항목마다 `family`(command·sql·path·code·xpath·ldap·xss·redirect)를 적습니다. 싱크는 `family` 대신 `context`(shell·sql·path·code·xpath·ldap·html·url)를 적어도 됩니다.
- 검사 함수는 `name`(호출 이름 정규식), `arg`(검사하는 인자 위치), `success`(참을 돌려주면 안전한지, 기본 true), `context`(막는 문맥)를 적습니다. 검사에 실패하면 실행을 끊는 분기(`if not is_safe_name(n): return`)를 지난 값만 그 문맥에서 안전하다고 봅니다.
- 전달 요약은 `summary: propagate`, `from_arg`(원본 인자), `to`(`return` 또는 인자 위치)를 적습니다.
- 정규화 요약(`summary: normalize`)은 정제가 아닙니다. 정규화 요약을 붙인 값만으로는 지적이 사라지지 않고, 그 값을 기준 폴더와 비교하는 검사가 있을 때 정규화 근거로만 씁니다. 구분자 없는 문자열 접두사 비교라면 확인 필요까지만 낮춥니다.
- 예제는 `positive`(지적되어야 하는 코드)와 `negative`(지적되지 않아야 하는 코드)로 줍니다. 언어가 둘 이상이면 `{python: …, java: …}`처럼 언어별로 줍니다. `expect`(기본 confirmed)는 positive가 받아야 하는 판정, `negative_expect`(기본 review)는 negative가 받을 수 있는 가장 강한 판정입니다. `positive_line`을 주면 그 줄에 지적이 있어야 합니다.
- 예제는 항목 하나만 넣은 명세와 명세 없는 상태로 각각 점검합니다. 판정이 그 항목 때문에 바뀌어야 맞은 것으로 봅니다. 그래서 소스·싱크의 positive는 명세 없이 지적되지 않는 코드여야 하고, 지적을 낮추는 항목의 negative는 명세 없이 확정으로 지적되는 코드여야 합니다.

### 만들기

```bash
iron-laws spec draft . -o iron-laws-spec.yml          # 후보 초안(예는 비어 있음)
iron-laws spec check iron-laws-spec.yml               # 예가 기대대로 판정되는지 확인(어긋나면 종료코드 1)
iron-laws spec check iron-laws-spec.yml --against .   # 이 저장소에 적용하기 전후 비교
```

```yaml
# .iron-laws.yml
policies:
  custom_spec: iron-laws-spec.yml
```

1. `spec draft`가 코드에서 후보를 찾아 초안을 만듭니다. 프로젝트가 import한 외부 패키지 호출 가운데 외부 입력을 받거나, 반환값이 싱크로 가거나, 문자열을 실행·해석하는 호출은 `candidates`에 계열별로 모입니다. `--llm-cmd`를 주면 후보가 있는 계열마다 따로 LLM에 묻고 제안을 더합니다.
2. 사람이 각 항목에 지적되어야 하는 코드 예(`positive`)와 지적되면 안 되는 코드 예(`negative`)를 채웁니다.
3. 모든 예가 기대대로 판정될 때만 명세를 불러옵니다. 하나라도 어긋나면 점검을 시작하지 않습니다.

LLM이 낸 제안은 LLM이 함께 낸 예로 바로 판정합니다. 예가 어긋나는 항목은 `rejected`로 빼고, 지적을 낮추는 항목(정제 함수, 검사 함수, 정규화 요약)은 예가 맞아도 사람이 옮기기 전에는 불러오지 않습니다.

### 채택 전에 확인하기

소스와 싱크, 전달 요약을 더하면 지적은 늘기만 합니다. 지적을 줄일 수 있는 것은 정제 함수·검사 함수·정규화 요약 선언이고, 선언이 너무 넓으면 진짜 문제까지 사라집니다. 그래서 채택 전에 `--against`로 같은 저장소를 명세 없이 한 번, 명세를 넣고 한 번 점검해 무엇이 사라졌는지 봅니다.

| 판정 | 뜻 | 종료코드 |
|---|---|---|
| `ok` | 사라진 지적이 없습니다 | 0 |
| `review` | 정제·검사 함수나 정규화 요약 선언 때문에 사라진 지적이 있어 사람이 확인해야 합니다 | 1 |
| `blocked` | 이유를 알 수 없이 지적이 사라졌거나 점검을 끝까지 하지 못해 채택하면 안 됩니다 | 1 |

비교 결과는 보고서와 별개로 나옵니다(`--format console|markdown|json`, `--output`). 근거 장부의 비교는 장부가 다루는 명령 실행·경로 접근·SQL 조립에서만 하며, 명세에 그 밖의 항목이 있으면 결과에 밝힙니다.

### 근거 장부와 보고서에 미치는 영향

- `policies.ledger_include_spec_points: true`를 켜면 명세가 더한 싱크도 근거 장부에 나타납니다(기본은 꺼짐). 켜면 장부 상태가 바뀔 수 있습니다.
- 명세가 선언한 정제 함수에 기대 안전하다고 본 호출은 장부에 근거 종류 `declared_sanitizer`로 표시됩니다. 그 함수가 정말 안전한지는 사람이 확인해야 합니다.
- 보고서에 명세 내용의 지문(`digests.spec`)이 남고, 명세가 바뀌면 실행 식별자(`run_id`)도 바뀝니다.

## 공개 API 진입점 (`policies.entry_points`)

라이브러리처럼 다른 코드가 불러 쓰는 프로젝트는 웹 요청 대신 공개 함수의 매개변수로 입력을 받습니다. `public_api`로 바꾸면 그 매개변수도 입력으로 봅니다.

```yaml
policies:
  entry_points: public_api   # 기본 web
```

- 공개 함수: Python은 이름이 `_`로 시작하지 않는 함수와 메서드, JavaScript·TypeScript는 export한 함수, Go는 대문자로 시작하는 함수, Java·C#은 public 클래스의 public 메서드입니다. 시험 파일은 빼고 봅니다.
- 문자열·바이트·스트림·경로·URL 형식의 매개변수만 입력으로 봅니다. 형식을 적지 않은 매개변수(Python 주석 없음, JavaScript)는 형식을 따지지 않습니다.
- 경로·명령·코드·XPath·XXE·XSS 규칙에 적용합니다. 이 입력만 닿는 지적은 확인 필요로 내고 문구에 "공개 API 매개변수"를 적습니다. 같은 싱크에 웹 입력도 닿으면 지금처럼 확정입니다.

## 로그인 검사 구조 (`auth`)

Spring Security 대신 인터셉터로 로그인을 검사하고, 사내 애너테이션으로 예외 주소를 두는 프로젝트는 설정으로 알려 줍니다. 코드에서 읽은 근거(보안 애너테이션, `permitAll`, `anyRequest`)가 이 설정보다 우선합니다.

```yaml
auth:
  interceptor_protects: true            # 인터셉터가 로그인을 요구한다(기본 false)
  exempt_markers: ["@SessionExclude"]   # 로그인 검사를 건너뛰는 표지가 붙은 라우트는 인증 no
  exempt_paths: ["/login/**"]           # 코드에서 읽지 못한 예외 경로
  fail_columns: ["pwd_err_cnt"]         # 로그인 실패 횟수·잠금 열 이름(IL-535 기본 목록에 더함)
```

- `interceptor_protects`가 참이면 `WebMvcConfigurer.addInterceptors`의 `addPathPatterns`·`excludePathPatterns`를 읽고, 적용 경로 안에서 예외 표지가 없는 라우트를 인증 yes로 봅니다. 적용 경로를 읽지 못하면 unknown입니다.
- `iron-laws spec draft`가 만드는 초안의 `config_hints`에 인터셉터가 확인하는 애너테이션(`auth.exempt_markers` 후보)이 나옵니다.

## 소속 경계 (`tenancy`)

여러 가맹점·고객사가 한 시스템을 함께 쓰는 프로젝트는 소속 키와 로그인 사용자의 소속을 읽는 식을 적습니다. `keys`와 `principal`을 모두 적어야 AI-129(소속 키 없는 조회·변경)를 판정합니다.

```yaml
tenancy:
  keys: [merchant_id, mid]                    # 소속 열·파라미터 이름
  principal: ["getLoginUser().getMid()"]      # 로그인 사용자의 소속을 읽는 식
  tables: [payout, settlement]                # 소속 격리 대상 테이블. 비우면 DDL·매퍼 조건에서 keys 열이 있는 테이블
```

- MyBatis 매퍼 문장의 WHERE에 소속 열이 없거나, 그 열에 요청 값을 바인딩하면 지적합니다. 동적 절(`<if>` 등) 안에만 있는 조건과 값의 출처를 정할 수 없는 경우는 확인 필요로 냅니다.
- `iron-laws tenancy .`로 매퍼 호출별 판정 표를 보고, `audit --format json`의 `metadata.tenancy`에도 같은 표가 들어갑니다.
- `spec draft`의 `config_hints`에 로그인 사용자의 소속을 읽는 호출식(`tenancy.principal` 후보)이 나옵니다.

요청 값을 바인딩해도, 매퍼를 부르기 전에 그 값이 로그인 사용자의 소속과 다르면 예외를 던지거나 반환하는 분기가 있으면 통과로 봅니다. 이때 `iron-laws tenancy` 표의 값 출처는 `checked`입니다.

- 직접 비교: `if (!mid.equals(getLoginUser().getMid())) throw …`
- 확인 함수: `if (!auth.isOwnedMerchant(mid)) throw …`. 그 함수는 값이 `principal` 식과 같은지 비교한 결과를 돌려줘야 합니다.
- `if (!mid.equals(…) && !force)`처럼 다른 조건과 `&&`로 묶인 분기는 인정하지 않습니다. `force`가 참이면 소속이 달라도 지나가기 때문입니다.

## 감사 기록 (`audit`)

AI-128은 비밀번호 변경, 계정 생성·잠금, 정산·출금·이체, 권한 변경, 접속 IP 정책 변경 라우트와 인증 실패·권한 거부 처리기에 감사 기록이 있는지 봅니다.

```yaml
audit:
  critical_routes: ["(?i)/merchant/key"]      # 감사 기록이 있어야 할 라우트(경로·핸들러 이름 정규식)를 더함
  markers: ["historyService.save"]            # 감사 기록 호출 이름을 더함(기본: audit, securityEvent, security 로거)
  event_types: ["SecurityAuditEvent"]         # 이 타입을 publishEvent로 발행하면 감사 근거로 인정
```

일반 `publishEvent`는 감사 근거로 보지 않습니다.

## 기준선 비교 (`baseline`)

`baseline create`는 지적과 함께 라우트 목록을 기준선에 저장합니다. `--baseline`으로 점검하면 AI-127이 기준선에 없던 공개 라우트, 관리 라우트, 인증이 사라진 라우트를 알립니다.

```yaml
baseline:
  route_name_patterns: ["(?i)/(legacy|old|bak)/"]   # 기준선에 없던 라우트 가운데 이 이름과 맞는 경로도 알림
```

라우트 목록이 없는 기준선은 그대로 읽고, 공격 표면 비교만 하지 않습니다.

## 교훈 기록

채택한 명세와 규칙에 무엇을 왜 넣었는지 적어 두면, 다음 명세 초안과 검토에서 그 내용을 다시 씁니다. 소스 코드는 저장하지 않고 이름, 조건, 이유만 남깁니다. 기록은 추가만 할 수 있고 각 줄이 앞 줄의 해시를 이어받으므로, 무엇이 언제 왜 들어왔는지 사라지지 않습니다.

```bash
iron-laws experience add --spec iron-laws-spec.yml --lesson "이 저장소는 내부 API 응답을 정규화한 뒤 셸에 넘긴다"
iron-laws experience add --rule IL-504 --lesson "인자 배열로 넘기면 셸 해석이 없다"
iron-laws experience list --rule IL-504            # 남긴 교훈 보기
iron-laws experience invalidate E-9f3a2b1c4d5e6 --reason "정규화 함수가 바뀌었다"
iron-laws experience verify                        # 기록의 해시 연결이 온전한지 확인
```

- `iron-laws explain IL-504`는 그 규칙에 남긴 교훈을 함께 보여 줍니다.
- `iron-laws spec draft --llm-cmd`는 관련 교훈을 LLM 지시문에 넣습니다.
- 규칙 버전이나 명세 내용이 바뀌면 그 교훈은 `stale`(다시 볼 것)로 표시됩니다.
