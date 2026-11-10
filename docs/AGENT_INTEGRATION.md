# 코딩 에이전트와 연결하기

Claude Code, Codex CLI, Cursor 같은 코딩 에이전트가 점검 결과를 바로 받도록 연결하는 방법입니다. 방법은 세 가지입니다.

| 방법 | 용도 |
|---|---|
| 훅 | 에이전트가 파일을 고칠 때마다, 그리고 작업을 끝내기 전에 자동으로 점검합니다 |
| MCP 서버 | 에이전트가 점검과 검증을 도구로 직접 부릅니다 |
| 지침 파일 | 규칙을 `CLAUDE.md`·`AGENTS.md`에 넣을 문장으로 내보냅니다 |

Claude Code는 [플러그인](#claude-code-플러그인으로-한-번에-설치)으로 훅과 MCP 서버를 한 번에 켤 수 있습니다.

## 훅

`iron-laws hook <에이전트>`는 에이전트가 보내는 훅 JSON의 `hook_event_name`을 읽어 세 시점을 처리합니다. `<에이전트>`는 `claude-code`, `codex`, `cursor` 중 하나입니다. 입력에 시점이 없으면 `--event`로 지정합니다.

| 시점 | 하는 일 |
|---|---|
| 세션 시작 | 프로젝트 언어에 해당하는 HIGH 이상 규칙을 지침으로 에이전트에게 넘깁니다(`guidelines export`와 같은 내용) |
| 편집 직후 | 바뀐 파일을 점검하고, 기준 이상 지적이 있으면 지적과 고치는 방법을 에이전트에게 돌려줍니다 |
| 종료 직전 | 세션에서 편집한 파일을 다시 점검해, 지적이 남아 있으면 에이전트가 끝내지 못하게 합니다. 앞선 훅 응답으로 이어진 종료에서는 다시 막지 않습니다 |

도구별 설정은 다음과 같습니다.

| 대상 | 설정 | 돌려주는 방식 |
|---|---|---|
| Claude Code | [ci/claude-code-settings.json](ci/claude-code-settings.json)의 `hooks`를 `.claude/settings.json`에 넣습니다 | 편집·종료는 종료코드 2와 표준 오류, 시작은 표준 출력 글 |
| Codex CLI | [ci/codex-hooks.json](ci/codex-hooks.json)을 `.codex/hooks.json`에 둡니다 | 편집·종료는 종료코드 2와 표준 오류, 시작은 표준 출력 글. `apply_patch`의 패치 본문에서 바뀐 파일을 읽습니다 |
| Cursor | [ci/cursor-hooks.json](ci/cursor-hooks.json)을 `.cursor/hooks.json`에 둡니다 | `afterFileEdit`는 응답을 전달할 수 없어 편집한 파일만 기록합니다. `stop`은 `followup_message`로, `sessionStart`는 `additional_context`로 알립니다 |

확인 범위는 다음과 같습니다.

- Claude Code 2.1.296에서 편집 훅을 시험했습니다.
- Codex와 Cursor는 각 도구의 공식 훅 문서에 맞춰 구현하고 고정 입력 샘플로 시험했습니다. 실제 프로그램에서 실행해 보지는 않았습니다.
- 편집한 파일 목록은 사용자 임시 폴더에 세션별로 기록하고, 프로젝트 폴더에는 아무것도 쓰지 않습니다.

### 정책·지침 파일 보호

에이전트가 아래 파일을 고치면 훅이 그 사실을 알립니다. Cursor는 종료 시점에 알립니다.

- `.iron-laws.yml`, 승인·기준선 기록
- `CLAUDE.md`, `AGENTS.md`, `.cursorrules`
- `.claude/settings.json`, `.codex/*`, `.mcp.json`

설정 파일은 마지막 커밋과 비교해서, 점검을 약하게 만드는 변경을 적습니다. `fail_on` 상향, 점검 제외 경로·끈 규칙 추가, `limits` 상향, 보호 경로 제거가 해당합니다.

보호 대상은 `policies.protected_paths`로 더하고 `policies.protected_paths_exclude`로 기본 목록에서 뺍니다. 이 두 설정은 마지막 커밋의 내용을 씁니다. 그래서 에이전트가 같은 세션에서 설정을 고쳐 보호를 풀 수 없습니다. 설정 파일과 승인·기준선 기록은 목록에서 뺄 수 없습니다. 사람이 터미널에서 직접 고치는 편집은 훅을 거치지 않으므로 알리지 않습니다.

## MCP 서버

점검과 검증을 에이전트가 도구로 부르게 합니다(stdio).

```bash
pip install 'iron-laws[mcp]'
iron-laws mcp --root /path/to/project --server-config ~/.config/iron-laws/server.yml
```

```yaml
# server.yml (점검 대상 폴더 밖에 둡니다)
test_presets:
  unit:
    command: [python, -m, pytest, -q]
    image: python:3.13-slim
    timeout: 180
```

- 도구는 `check`, `explain`, `fix_prompt`, `verify_patch`, `deps`입니다. 입력 이름은 CLI 옵션과 같습니다.
- 경로는 `--root` 안에서만 받습니다. 심볼릭 링크가 밖을 가리키면 거부합니다.
- 에이전트는 시험 명령을 직접 넘길 수 없고 `test_presets`에 정의된 이름만 고릅니다. 서버 설정 파일이 점검 폴더 안에 있으면 서버를 띄우지 않습니다.
- `verify_patch`에 `regression_spec`을 주면, 정적 지적이 사라졌는지와 별도로 결함 동작이 사라졌는지도 돌려줍니다.

## Claude Code 플러그인으로 한 번에 설치

저장소 루트가 Claude Code 플러그인입니다. 위 세 시점의 훅과 MCP 서버(`iron-laws mcp --root <프로젝트>`)를 한 번에 켭니다.

```bash
claude plugin marketplace add JinHo-von-Choi/iron-laws
/plugin install iron-laws --marketplace JinHo-von-Choi/iron-laws
```

- `iron-laws` 명령이 PATH에 있어야 합니다. MCP 서버는 `pip install 'iron-laws[mcp]'`도 필요합니다.
- 설치가 됐는지는 훅 명령에 시험 입력을 넣어 확인합니다. 프로젝트 언어의 지침이 출력되면 됩니다.

  ```bash
  echo '{"hook_event_name":"SessionStart","cwd":"."}' | iron-laws hook claude-code
  ```

- `claude plugin validate .`로 매니페스트를 검사했습니다. 실제 설치와 훅 실행은 확인하지 않았습니다.
- 시험 명령(`test_presets`)이 필요한 `verify_patch`는 서버 설정 파일을 프로젝트 밖에 두고 `iron-laws mcp --server-config`로 직접 띄우십시오.

## 지침 파일(CLAUDE.md·AGENTS.md)과 함께 쓰기

지침 파일의 문장은 모델이 읽고 따르는 글이라서, 문장만으로는 지켜졌는지 알 수 없습니다. 오철칙은 지침을 만들고, 각 줄을 무엇이 확인하는지 함께 적습니다.

```bash
iron-laws guidelines export --lang python,typescript -o 지침.md   # 규칙을 지침으로 내보내기
iron-laws guidelines check CLAUDE.md                              # 기존 지침의 문장마다 강제 수단 보기
```

| 꼬리표 | 뜻 |
|---|---|
| 차단 | `iron-laws hook`이나 `check --fail-on`이 지적하면 작업이 멈춥니다 |
| 실행 검증 | `verify-patch`가 수정 전후를 격리 실행해 결함 동작이 사라졌는지 확인합니다(명령 실행·경로·SQL) |
| 보고 | 지적은 하지만 작업을 멈추지 않습니다 |
| 강제 수단 없음 | 대응하는 규칙이 없습니다. 사용자 명세나 에이전트의 훅·권한 설정으로 확인할 수 있는지 보십시오 |

`check`는 주제 대응표로 문장과 규칙을 잇습니다. 대응이 틀리거나 빠질 수 있습니다. 측정 결과는 [ACCURACY.md](ACCURACY.md) §5.4에 있습니다.
