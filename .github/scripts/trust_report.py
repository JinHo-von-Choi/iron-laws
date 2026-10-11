"""독립 검증한 점검 보고서에서 CI 신뢰 지표를 보관한다."""

import json
import sys
from pathlib import Path

from iron_laws.core.trust_metrics import summarize_trust
from iron_laws.evidence.verifier import load_json, verify_report


def main() -> int:
    report = load_json(Path(sys.argv[1]))
    result = verify_report(report)
    if not result.ok:
        print('구조적으로 검증되지 않은 보고서는 신뢰 지표로 보관하지 않습니다', file=sys.stderr)
        return 2
    metrics = summarize_trust(report)
    Path(sys.argv[2]).write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f"관심 지점 {metrics['in_scope_points']}개, 근거 공백 {metrics['gap_points']}개")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
