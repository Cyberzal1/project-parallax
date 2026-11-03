"""Verification Gate 4: Complete P1 & P2 Hardening and Mutation Test Suite."""

from pathlib import Path

import pytest

from parallax.cross_layer_auditor import (
    evaluate_auditor_precision_recall,
    run_cross_layer_auditor,
    run_exploit_replay_ground_truth,
)
from parallax.graph_analyzer import run_graph_analyzer
from parallax.orchestrator import (
    apply_holistic_architectural_patch,
    apply_symptom_only_ide_patch,
)
from parallax.patch_verifier import (
    evaluate_directory_delta,
    score_directory_layers,
    validate_base_ref,
    validate_worktree_path,
    verify_patch_in_git_worktree,
)
from parallax.schemas import PatchClassification, Severity
from parallax.telemetry_validator import run_telemetry_validator

ROOT_DIR = Path(__file__).resolve().parent.parent


def _copy_baseline_to_tmp(tmp_path: Path) -> None:
    """Copy benchmark_target files into isolated tmp_path."""
    for rel in ("infra/main.tf", "app/service.py", "secops/rules.yaml"):
        src = ROOT_DIR / "benchmark_target" / rel
        dst = tmp_path / "benchmark_target" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")


def test_p1_path_traversal_and_base_ref_option_injection_rejected() -> None:
    """Prove worktree path and base_ref validators block unsafe inputs."""
    for unsafe_name in ("../escape", "..\\escape", "/root/evil", "bad/slash", ""):
        with pytest.raises(ValueError, match="Unsafe worktree_name"):
            validate_worktree_path(ROOT_DIR, unsafe_name)

    for unsafe_ref in ("--upload-pack=evil", "-f", "--detach", ""):
        with pytest.raises(ValueError, match="Unsafe base_ref"):
            validate_base_ref(ROOT_DIR, unsafe_ref)


def test_p1_graph_and_ast_auditor_fail_closed_mutations(tmp_path: Path) -> None:
    """Prove Subagents 01 and 02 fail closed (1.0 CRITICAL) on deleted/corrupt files."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # 1. Empty main.tf -> 1.0 CRITICAL
    tf_path.write_text("   \n", encoding="utf-8")
    r_empty_tf = run_graph_analyzer(tmp_path)
    assert r_empty_tf.risk_score == 1.0
    assert r_empty_tf.findings[0].severity == Severity.CRITICAL

    # 2. Malformed HCL in main.tf -> 1.0 CRITICAL
    tf_path.write_text("resource {{{ unclosed_hcl", encoding="utf-8")
    r_corrupt_tf = run_graph_analyzer(tmp_path)
    assert r_corrupt_tf.risk_score == 1.0
    assert r_corrupt_tf.findings[0].finding_id == "PARALLAX-IAM-CORRUPT"

    # 3. Deleted main.tf -> 1.0 CRITICAL
    tf_path.unlink()
    r_missing_tf = run_graph_analyzer(tmp_path)
    assert r_missing_tf.risk_score == 1.0
    assert r_missing_tf.findings[0].finding_id == "PARALLAX-IAM-MISSING"

    # 4. service.py with execute_agent_tool removed -> 1.0 CRITICAL
    svc_path.write_text("x = 1\n", encoding="utf-8")
    r_no_handler = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_no_handler.risk_score == 1.0
    assert r_no_handler.findings[0].finding_id == "PARALLAX-AST-MISSING-HANDLER"

    # 5. Syntax error in service.py -> 1.0 CRITICAL
    svc_path.write_text("def broken(\n", encoding="utf-8")
    r_syntax = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_syntax.risk_score == 1.0
    assert r_syntax.findings[0].finding_id == "PARALLAX-AST-SYNTAX"

    # 6. Deleted service.py -> 1.0 CRITICAL
    svc_path.unlink()
    r_missing_py = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert r_missing_py.risk_score == 1.0
    assert r_missing_py.findings[0].finding_id == "PARALLAX-AST-MISSING"


def test_p1_exploit_replay_ground_truth(tmp_path: Path) -> None:
    """Prove runtime exploit replay detects baseline flaw and verifies fix."""
    _copy_baseline_to_tmp(tmp_path)
    blocked_before, detail_before = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_before is False
    assert "prod-master-db" in detail_before

    apply_holistic_architectural_patch(tmp_path)
    blocked_after, detail_after = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_after is True
    assert "Blocked" in detail_after


def test_p1_git_status_porcelain_z_handles_spaces() -> None:
    """Prove git status --porcelain -z parses filenames containing spaces."""

    def _mutate_with_spaced_file(wt_root: Path) -> None:
        apply_symptom_only_ide_patch(wt_root)
        spaced = wt_root / "benchmark_target" / "app" / "notes with spaces.txt"
        spaced.write_text("audit log note\n", encoding="utf-8")

    delta, report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-spaced-path", _mutate_with_spaced_file
    )
    assert "benchmark_target/app/notes with spaces.txt" in delta.files_touched
    assert report.findings[0].file_path == "benchmark_target/secops/rules.yaml"


def test_p2_noop_patch_on_already_clean_tree_returns_noop_baseline(
    tmp_path: Path,
) -> None:
    """Prove a no-op patch on an already-clean tree returns NO_OP_BASELINE."""
    _copy_baseline_to_tmp(tmp_path)
    apply_holistic_architectural_patch(tmp_path)
    clean_baseline = score_directory_layers(tmp_path)
    assert clean_baseline == (0.10, 0.05, 0.05)

    clean_noop = evaluate_directory_delta(
        tmp_path, "already-clean-noop", baseline_scores=clean_baseline
    )
    assert clean_noop.patch_state == PatchClassification.NO_OP_BASELINE
    assert clean_noop.split_brain_detected is False


def test_p2_small_code_gain_plus_large_telemetry_regression_is_mixed_regression(
    tmp_path: Path,
) -> None:
    """Prove d_code=-0.20 + d_tel=+0.80 classifies as MIXED_REGRESSION."""
    _copy_baseline_to_tmp(tmp_path)
    baseline = score_directory_layers(tmp_path)

    apply_symptom_only_ide_patch(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    svc_code = svc_path.read_text(encoding="utf-8").replace(
        "if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
        "if False:",
    )
    svc_path.write_text(svc_code, encoding="utf-8")

    mixed_delta = evaluate_directory_delta(
        tmp_path, "small-code-gain-big-reg", baseline_scores=baseline
    )
    assert mixed_delta.delta_code_risk == -0.20
    assert mixed_delta.delta_telemetry_risk == 0.80
    assert mixed_delta.patch_state == PatchClassification.MIXED_REGRESSION


def test_p2_telem_fail_closed_corrupt_input_syntax_and_yaml(
    tmp_path: Path,
) -> None:
    """Prove TELEM_FAIL_CLOSED_CORRUPT_INPUT fires on bad Python and bad YAML."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # 1. Malformed YAML syntax
    rules_path.write_text("rules: [unclosed_yaml_list\n", encoding="utf-8")
    corrupt_yaml = run_telemetry_validator(tmp_path)
    assert corrupt_yaml.risk_score == 1.0
    assert corrupt_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"

    # 2. Syntax-error service.py
    _copy_baseline_to_tmp(tmp_path)
    svc_path.write_text("def unclosed_func(\n", encoding="utf-8")
    corrupt_py = run_telemetry_validator(tmp_path)
    assert corrupt_py.risk_score == 1.0
    assert corrupt_py.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"


def test_p2_telem_fail_closed_empty_and_missing_rules(tmp_path: Path) -> None:
    """Prove empty rules list, empty YAML, and deleted rules.yaml fail closed."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"

    rules_path.write_text("rules: []\n", encoding="utf-8")
    zero_rules = run_telemetry_validator(tmp_path)
    assert zero_rules.risk_score == 1.0
    assert zero_rules.findings[0].finding_id == "TELEM_FAIL_CLOSED_ZERO_RULES"

    rules_path.write_text("", encoding="utf-8")
    empty_yaml = run_telemetry_validator(tmp_path)
    assert empty_yaml.risk_score == 1.0
    assert empty_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_EMPTY_RULES"

    rules_path.unlink()
    missing_yaml = run_telemetry_validator(tmp_path)
    assert missing_yaml.risk_score == 1.0
    assert missing_yaml.findings[0].finding_id == "TELEM_FAIL_CLOSED_MISSING_FILE"


def test_p2_telem_audit_event_class_removed_and_zero_emissions(
    tmp_path: Path,
) -> None:
    """Prove removing AuditEvent class OR removing emissions fails closed (1.0)."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")

    # 1. AuditEvent class renamed/removed
    svc_path.write_text(
        orig_code.replace("class AuditEvent(", "class OtherEvent("),
        encoding="utf-8",
    )
    no_class = run_telemetry_validator(tmp_path)
    assert no_class.risk_score == 1.0
    assert no_class.findings[0].finding_id == "TELEM_FAIL_CLOSED_MISSING_AUDIT_CLASS"

    # 2. AuditEvent class kept, but zero AuditEvent(...) calls in code
    svc_path.write_text(
        orig_code.replace("audit = AuditEvent(", "audit = dict("),
        encoding="utf-8",
    )
    no_emission = run_telemetry_validator(tmp_path)
    assert no_emission.risk_score == 1.0
    assert no_emission.findings[0].finding_id == "TELEM_FAIL_CLOSED_NO_EMISSION"


def test_p2_telem_null_match_non_dict_missing_and_duplicate_rule_id(
    tmp_path: Path,
) -> None:
    """Prove non-dict rule, null match, missing rule_id, and duplicate rule_id fire."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                '  - "not_a_dict_entry"',
                "  - severity: 'MEDIUM'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "  - rule_id: 'SECOPS_DUP'",
                "    severity: 'HIGH'",
                "    match: null",
                "  - rule_id: 'SECOPS_DUP'",
                "    severity: 'CRITICAL'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
            ]
        ),
        encoding="utf-8",
    )
    report = run_telemetry_validator(tmp_path)
    f_ids = {f.finding_id for f in report.findings}
    assert "TELEM_MALFORMED_RULE_ENTRY_1" in f_ids
    assert "TELEM_MISSING_RULE_ID_2" in f_ids
    assert "TELEM_INVALID_MATCH_SECOPS_DUP" in f_ids
    assert "TELEM_DUPLICATE_RULE_ID_SECOPS_DUP" in f_ids


def test_p2_telem_predicate_mismatch_on_allowed_and_caller_identity(
    tmp_path: Path,
) -> None:
    """Prove rule predicates on allowed/caller_identity fail when sample differs."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                "  - rule_id: 'SECOPS_DENY_ONLY'",
                "    severity: 'HIGH'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "      allowed: false",
                "  - rule_id: 'SECOPS_ADMIN_CALLER'",
                "    severity: 'CRITICAL'",
                "    match:",
                "      event_type: 'SECRET_MANAGER_ACCESS'",
                "      tool_name: 'read_workspace_context'",
                "      caller_identity: 'user:root_admin'",
            ]
        ),
        encoding="utf-8",
    )
    report = run_telemetry_validator(tmp_path)
    f_ids = {f.finding_id for f in report.findings}
    assert "TELEM_CONTRACT_MISMATCH_SECOPS_DENY_ONLY" in f_ids
    assert "TELEM_CONTRACT_MISMATCH_SECOPS_ADMIN_CALLER" in f_ids
    assert report.risk_score >= 0.85


def test_p2_telemetry_bidirectional_unmonitored_tool_and_dynamic_ast(
    tmp_path: Path,
) -> None:
    """Prove reverse coverage check catches unmonitored tools and dynamic AST."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    code = svc_path.read_text(encoding="utf-8")

    extra_code = "\n".join(
        [
            "",
            "",
            "def unmonitored_helper(mode: str) -> AuditEvent:",
            "    _ = AuditEvent(",
            "        event_type='SECRET_MANAGER_ACCESS',",
            "        caller_identity='user:alice',",
            "        service_account='sa@project.iam.gserviceaccount.com',",
            "        tool_name=f'dynamic_{mode}',",
            "        target_secret='workspace-doc-1',",
            "        allowed=True,",
            "    )",
            "    return AuditEvent(",
            "        event_type='SECRET_MANAGER_ACCESS',",
            "        caller_identity='user:alice',",
            "        service_account='sa@project.iam.gserviceaccount.com',",
            "        tool_name='export_bigquery_dataset',",
            "        target_secret='workspace-doc-1',",
            "        allowed=True,",
            "    )",
            "",
        ]
    )
    svc_path.write_text(code + extra_code, encoding="utf-8")

    report = run_telemetry_validator(tmp_path)
    assert report.risk_score > 0.05
    finding_ids = {f.finding_id for f in report.findings}
    assert "TELEM_UNMONITORED_TOOL_EXPORT_BIGQUERY_DATASET" in finding_ids
    assert any("dynamic AuditEvent.tool_name" in q for q in report.open_questions)


def test_p2_telemetry_proportional_scoring_and_field_drift(
    tmp_path: Path,
) -> None:
    """Prove breaking 1 of 2 rules scores proportionally and catches field drift."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_text = rules_path.read_text(encoding="utf-8")

    broken_one = rules_text.replace(
        'tool_name: "read_workspace_context"',
        'tool_name: "legacy_tool_name"',
        1,
    )
    rules_path.write_text(broken_one, encoding="utf-8")
    partial_report = run_telemetry_validator(tmp_path)
    assert 0.35 <= partial_report.risk_score < 0.85

    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    svc_text = svc_path.read_text(encoding="utf-8").replace(
        "target_secret: str", "secret_uri: str"
    )
    svc_path.write_text(svc_text, encoding="utf-8")
    drift_report = run_telemetry_validator(tmp_path)
    assert any("TELEM_SCHEMA_DRIFT" in f.finding_id for f in drift_report.findings)


def test_p2_auditor_adversarial_seeds_beyond_10() -> None:
    """Prove 16-case AST benchmark measures true precision/recall boundaries."""
    metrics = evaluate_auditor_precision_recall()
    assert metrics["total_cases"] == 16.0
    assert metrics["true_positives"] >= 5.0
    assert metrics["true_negatives"] >= 7.0
    assert metrics["false_positives"] >= 1.0
    assert metrics["false_negatives"] >= 1.0
    assert 0.70 <= metrics["precision"] < 1.0
    assert 0.65 <= metrics["recall"] < 1.0


def test_p1_ai_attack_malicious_patch_blocked_before_exec_module(
    tmp_path: Path,
) -> None:
    """Prove AST sandbox guardrail blocks malicious LLM patches before exec."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    malicious_os_patch = (
        "import os\n"
        "os.system('echo PWNED')\n"
        "def execute_agent_tool(auth_header, tool_payload):\n"
        "    raise PermissionError('blocked')\n"
    )
    svc_path.write_text(malicious_os_patch, encoding="utf-8")
    blocked_os, detail_os = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_os is False
    assert "Disallowed" in detail_os

    malicious_open_patch = (
        "import re\n"
        "def execute_agent_tool(auth_header, tool_payload):\n"
        "    _ = open('.env').read()\n"
        "    raise PermissionError('blocked')\n"
    )
    svc_path.write_text(malicious_open_patch, encoding="utf-8")
    blocked_open, detail_open = run_exploit_replay_ground_truth(tmp_path)
    assert blocked_open is False
    assert "Disallowed builtin call" in detail_open


def test_v5_replay_catches_seeded_bad_fixes_and_broken_positive_control(
    tmp_path: Path,
) -> None:
    """Prove 5-probe replay catches dropped '$', substring 'in', and deny-all."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")

    # 1. Seeded Bad Fix A: flash-lite's dropped '$' anchor + prefix check
    dropped_dollar = orig_code.replace(
        'SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\\-]+$")',
        'SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+")',
    ).replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    svc_path.write_text(dropped_dollar, encoding="utf-8")
    ok_a, reason_a = run_exploit_replay_ground_truth(tmp_path)
    assert ok_a is False
    assert "regex_anchor_traversal_fallback" in reason_a
    # Also verify Subagent 02 static AST flags PARALLAX-AST-002
    ast_rep_a = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    assert any(f.finding_id == "PARALLAX-AST-002" for f in ast_rep_a.findings)

    # 2. Seeded Bad Fix B: naive 'ALLOWED_WORKSPACE_PREFIX in fallback_id' check
    substring_in_fix = orig_code.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or "
            "ALLOWED_WORKSPACE_PREFIX not in fallback_id:"
        ),
    )
    svc_path.write_text(substring_in_fix, encoding="utf-8")
    ok_b, reason_b = run_exploit_replay_ground_truth(tmp_path)
    assert ok_b is False
    assert "substring_in_bypass_probe" in reason_b

    # 3. Seeded Bad Fix C: Handler rejects EVERYTHING (breaks positive control)
    deny_all = orig_code.replace(
        "effective_secret_id = primary_id",
        "raise PermissionError('deny all')",
    )
    svc_path.write_text(deny_all, encoding="utf-8")
    ok_c, reason_c = run_exploit_replay_ground_truth(tmp_path)
    assert ok_c is False
    assert "Positive control" in reason_c


def test_v5_graph_analyzer_catches_sa_rename_iam_binding_and_placeholder_secret(
    tmp_path: Path,
) -> None:
    """Prove Subagent 01 catches SA renames, iam_binding swaps, and placeholders."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"
    orig_tf = tf_path.read_text(encoding="utf-8")

    # 1. Rename service account resource & Cloud Run service -> still 0.95!
    renamed_tf = orig_tf.replace("sa_agent_runner", "sa_custom_bot").replace(
        "vertex_ops_agent", "custom_cloud_run_gw"
    )
    tf_path.write_text(renamed_tf, encoding="utf-8")
    r_renamed = run_graph_analyzer(tmp_path)
    assert r_renamed.risk_score == 0.95
    assert len(r_renamed.findings) == 2

    # 2. Swap google_project_iam_member for google_project_iam_binding -> still 0.95!
    binding_tf = """
resource "google_service_account" "custom_sa" {
  account_id = "custom-sa"
}
resource "google_cloud_run_v2_service" "app" {
  name    = "app"
  ingress = "INGRESS_TRAFFIC_ALL"
}
resource "google_project_iam_binding" "secret_bind" {
  role    = "roles/secretmanager.secretAccessor"
  members = ["serviceAccount:${google_service_account.custom_sa.email}"]
}
resource "google_project_iam_binding" "token_bind" {
  role    = "roles/iam.serviceAccountTokenCreator"
  members = ["serviceAccount:${google_service_account.custom_sa.email}"]
}
"""
    tf_path.write_text(binding_tf, encoding="utf-8")
    r_binding = run_graph_analyzer(tmp_path)
    assert r_binding.risk_score == 0.95

    # 3. Placeholder scoped secret_id = "workspace-doc-" -> flagged (risk 0.65)!
    placeholder_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
}
resource "google_secret_manager_secret_iam_member" "bad_placeholder" {
  secret_id = "workspace-doc-"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(placeholder_tf, encoding="utf-8")
    r_placeholder = run_graph_analyzer(tmp_path)
    assert r_placeholder.risk_score == 0.65
    assert any(
        "PARALLAX-IAM-INVALID-SCOPED-SECRET" in f.finding_id
        for f in r_placeholder.findings
    )


def test_v5_telemetry_catches_canary_rule_predicate_narrowing(
    tmp_path: Path,
) -> None:
    """Prove narrowing SECOPS_GCP_002 from prod- to workspace-doc- is flagged."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    narrowed_yaml = rules_path.read_text(encoding="utf-8").replace(
        'target_secret_prefix: "prod-"',
        'target_secret_prefix: "workspace-doc-"',
    )
    rules_path.write_text(narrowed_yaml, encoding="utf-8")
    report = run_telemetry_validator(tmp_path)
    assert report.risk_score >= 0.50
    assert any(
        f.finding_id == "TELEM_RULE_PREDICATE_NARROWING_SECOPS_GCP_002"
        for f in report.findings
    )
