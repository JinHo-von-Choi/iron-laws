import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from iron_laws.cli import app
from iron_laws.core.scanner import AuditScanner
from iron_laws.core.trust_metrics import summarize_trust
from iron_laws.evidence.verifier import verify_report


@pytest.mark.parametrize('code, expected', [
    ('from pathlib import Path\nfrom flask import request\ndef make():\n    target = Path("/srv") / request.args["p"]\n    target.mkdir()\n', 'finding'),
    ('from pathlib import Path\ndef make():\n    target = Path("/srv/fixed")\n    target.mkdir()\n', 'closed_value'),
    ('def make(target):\n    target.mkdir()\n', 'unresolved'),
    ('import tempfile\nfrom pathlib import Path\ndef make():\n    target = Path(tempfile.mkdtemp())\n    target.mkdir()\n', 'unresolved'),
])
def test_mkdir_has_receiver_evidence_without_assuming_tempfile_safe(tmp_path, code, expected):
    (tmp_path / 'app.py').write_text(code)
    report = AuditScanner(tmp_path).scan()
    assert verify_report(report.model_dump(mode='json')).ok
    point = next(p for p in report.coverage_ledger.points if p.callee.endswith('.mkdir'))
    if expected == 'unresolved':
        assert point.state == expected and point.evidence_kind == 'none'
    else:
        assert point.state == 'evidence_met' and point.evidence_kind == expected


def test_gap_metrics_preserve_denominators_and_all_gap_points(tmp_path):
    (tmp_path / 'app.py').write_text('import tempfile\ndef make(path):\n    tempfile.mkdtemp(dir=path)\n    path.mkdir()\n')
    report = AuditScanner(tmp_path).scan().model_dump(mode='json')
    before = json.dumps(report, sort_keys=True)
    metrics = summarize_trust(report)
    assert metrics['gap_points'] == sum(row['count'] for row in metrics['gaps']) == 2
    assert metrics['total_points'] == metrics['in_scope_points'] + metrics['out_of_scope_points']
    assert metrics['states'] == {'unsupported': 1, 'unresolved': 1}
    assert metrics['analysis_unknown_rate'] == 1.0
    assert json.dumps(report, sort_keys=True) == before


def test_ci_fixed_scope_is_enforced_with_complete_evidence(tmp_path):
    root = Path(__file__).parent / 'fixtures' / 'trust_scope'
    output = tmp_path / 'report.json'
    result = CliRunner().invoke(app, ['audit', str(root), '--contract', str(root / 'contract.yml'),
        '--max-analysis-unknown-rate', '0', '--max-unverified-rule-language-rate', '0', '--format', 'json', '-o', str(output)])
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text())
    assert report['summary']['contract_status'] == 'met'
    assert report['summary']['analysis_unknown_rate'] == 0
    assert report['summary']['unverified_rule_language_rate'] == 0
    assert {p['family'] for p in report['coverage_ledger']['points']} == {'command', 'path', 'sql'}
    assert verify_report(report).ok
