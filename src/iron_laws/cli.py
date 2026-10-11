"""오철칙 CLI 진입점과 기존 공개 import 호환층."""

import sys

from iron_laws.commands.approvals import (
    _store as _store,
)
from iron_laws.commands.approvals import (
    approvals_add_command as approvals_add_command,
)
from iron_laws.commands.approvals import (
    approvals_forget_command as approvals_forget_command,
)
from iron_laws.commands.approvals import (
    approvals_list_command as approvals_list_command,
)
from iron_laws.commands.approvals import (
    approvals_prune_command as approvals_prune_command,
)
from iron_laws.commands.approvals import (
    approvals_queue_command as approvals_queue_command,
)
from iron_laws.commands.approvals import (
    approvals_revoke_command as approvals_revoke_command,
)
from iron_laws.commands.approvals import (
    approvals_stats_command as approvals_stats_command,
)
from iron_laws.commands.approvals import (
    approvals_status_command as approvals_status_command,
)
from iron_laws.commands.approvals import (
    approvals_verify_command as approvals_verify_command,
)
from iron_laws.commands.catalog import (
    coverage_command as coverage_command,
)
from iron_laws.commands.catalog import (
    explain_command as explain_command,
)
from iron_laws.commands.catalog import (
    init_command as init_command,
)
from iron_laws.commands.catalog import (
    rules_command as rules_command,
)
from iron_laws.commands.catalog import (
    support_command as support_command,
)
from iron_laws.commands.common import (
    BASIS_NONE as BASIS_NONE,
)
from iron_laws.commands.common import (
    FEEDBACK_FILE as FEEDBACK_FILE,
)
from iron_laws.commands.common import (
    AllowEmptyOpt as AllowEmptyOpt,
)
from iron_laws.commands.common import (
    ApprovalsOpt as ApprovalsOpt,
)
from iron_laws.commands.common import (
    BaselineOpt as BaselineOpt,
)
from iron_laws.commands.common import (
    ChangedSinceOpt as ChangedSinceOpt,
)
from iron_laws.commands.common import (
    ConfigOpt as ConfigOpt,
)
from iron_laws.commands.common import (
    ContractModeOpt as ContractModeOpt,
)
from iron_laws.commands.common import (
    ContractOpt as ContractOpt,
)
from iron_laws.commands.common import (
    GitignoreOpt as GitignoreOpt,
)
from iron_laws.commands.common import (
    LimitOpt as LimitOpt,
)
from iron_laws.commands.common import (
    MaxUnknownOpt as MaxUnknownOpt,
)
from iron_laws.commands.common import (
    MaxUnverifiedOpt as MaxUnverifiedOpt,
)
from iron_laws.commands.common import (
    MetricsOpt as MetricsOpt,
)
from iron_laws.commands.common import (
    PathArg as PathArg,
)
from iron_laws.commands.common import (
    ReportFormat as ReportFormat,
)
from iron_laws.commands.common import (
    SearchParentsOpt as SearchParentsOpt,
)
from iron_laws.commands.common import (
    _build_scanner as _build_scanner,
)
from iron_laws.commands.common import (
    _changed_files as _changed_files,
)
from iron_laws.commands.common import (
    _check_completion as _check_completion,
)
from iron_laws.commands.common import (
    _emit_report as _emit_report,
)
from iron_laws.commands.common import (
    _gates as _gates,
)
from iron_laws.commands.common import (
    _git as _git,
)
from iron_laws.commands.common import (
    _nul_paths as _nul_paths,
)
from iron_laws.commands.common import (
    _renamed_paths as _renamed_paths,
)
from iron_laws.commands.common import (
    _timed_scan as _timed_scan,
)
from iron_laws.commands.common import (
    _tool_version as _tool_version,
)
from iron_laws.commands.common import (
    _write_or_print as _write_or_print,
)
from iron_laws.commands.common import (
    app as app,
)
from iron_laws.commands.common import (
    approvals_app as approvals_app,
)
from iron_laws.commands.common import (
    baseline_app as baseline_app,
)
from iron_laws.commands.common import (
    console as console,
)
from iron_laws.commands.common import (
    err as err,
)
from iron_laws.commands.common import (
    evidence_app as evidence_app,
)
from iron_laws.commands.common import (
    feedback_app as feedback_app,
)
from iron_laws.commands.common import (
    pilot_app as pilot_app,
)
from iron_laws.commands.common import (
    regression_app as regression_app,
)
from iron_laws.commands.inspect import (
    architecture_command as architecture_command,
)
from iron_laws.commands.inspect import (
    deps_command as deps_command,
)
from iron_laws.commands.pilot import (
    _pilot_call as _pilot_call,
)
from iron_laws.commands.pilot import (
    _pilot_store as _pilot_store,
)
from iron_laws.commands.pilot import (
    pilot_assign_command as pilot_assign_command,
)
from iron_laws.commands.pilot import (
    pilot_close_command as pilot_close_command,
)
from iron_laws.commands.pilot import (
    pilot_dropout_command as pilot_dropout_command,
)
from iron_laws.commands.pilot import (
    pilot_flag_command as pilot_flag_command,
)
from iron_laws.commands.pilot import (
    pilot_record_command as pilot_record_command,
)
from iron_laws.commands.pilot import (
    pilot_summary_command as pilot_summary_command,
)
from iron_laws.commands.records import (
    baseline_create_command as baseline_create_command,
)
from iron_laws.commands.records import (
    baseline_diff_command as baseline_diff_command,
)
from iron_laws.commands.records import (
    baseline_migrate_command as baseline_migrate_command,
)
from iron_laws.commands.records import (
    feedback_add_command as feedback_add_command,
)
from iron_laws.commands.records import (
    feedback_summary_command as feedback_summary_command,
)
from iron_laws.commands.scan import (
    audit_command as audit_command,
)
from iron_laws.commands.scan import (
    check_command as check_command,
)
from iron_laws.commands.scan import (
    fix_prompt_command as fix_prompt_command,
)
from iron_laws.commands.scan import (
    review_bundle_command as review_bundle_command,
)
from iron_laws.commands.verification import (
    evidence_upgrade_command as evidence_upgrade_command,
)
from iron_laws.commands.verification import (
    evidence_verify_command as evidence_verify_command,
)
from iron_laws.commands.verification import (
    regression_check_command as regression_check_command,
)
from iron_laws.commands.verification import (
    regression_propose_command as regression_propose_command,
)
from iron_laws.commands.verification import (
    verify_patch_command as verify_patch_command,
)

# 분리 전 도움말의 명령 등록 순서를 보존한다.
_COMMAND_ORDER = {'check_command': 0, 'audit_command': 1, 'fix_prompt_command': 2, 'baseline_create_command': 3, 'baseline_migrate_command': 4, 'baseline_diff_command': 5, 'feedback_add_command': 6, 'feedback_summary_command': 7, 'regression_propose_command': 8, 'regression_check_command': 9, 'verify_patch_command': 10, 'approvals_add_command': 11, 'approvals_list_command': 12, 'approvals_status_command': 13, 'approvals_revoke_command': 14, 'approvals_verify_command': 15, 'approvals_forget_command': 16, 'approvals_prune_command': 17, 'approvals_queue_command': 18, 'approvals_stats_command': 19, 'pilot_assign_command': 20, 'pilot_record_command': 21, 'pilot_flag_command': 22, 'pilot_close_command': 23, 'pilot_dropout_command': 24, 'pilot_summary_command': 25, 'architecture_command': 26, 'deps_command': 27, 'review_bundle_command': 28, 'evidence_verify_command': 29, 'evidence_upgrade_command': 30, 'rules_command': 31, 'support_command': 32, 'coverage_command': 33, 'explain_command': 34, 'init_command': 35}
for _group in (app, baseline_app, feedback_app, regression_app, approvals_app, pilot_app, evidence_app):
    _group.registered_commands.sort(key=lambda c: _COMMAND_ORDER.get(c.callback.__name__, len(_COMMAND_ORDER)))

def _ensure_utf8_output() -> None:
    """Windows 등 UTF-8이 아닌 출력 인코딩(cp1252·cp949)에서 한글 출력이 UnicodeEncodeError로 죽지 않게 한다."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    _ensure_utf8_output()
    app()


if __name__ == "__main__":
    main()
