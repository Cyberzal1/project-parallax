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


def test_v6_misspelled_resource_undeclared_secret_and_dedicated_sa(
    tmp_path: Path,
) -> None:
    """Prove P0 #1-#3: unknown resource, undeclared secret, and SA move."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"

    # (a) Misspelled resource type google_secret_iam_member (Trials 12 & 28 bug)
    misspelled_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_secret_iam_member" "hallucinated_type" {
  secret_id = "workspace-doc-context"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(misspelled_tf, encoding="utf-8")
    r_mis = run_graph_analyzer(tmp_path)
    assert r_mis.risk_score >= 0.85
    assert any(
        "PARALLAX-IAM-UNKNOWN-RESOURCE-GOOGLE_SECRET_IAM_MEMBER" in f.finding_id
        for f in r_mis.findings
    )

    # (b) Binding on an undeclared secret + placeholder comment (Trial 12 bug)
    undeclared_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_secret_manager_secret_iam_member" "undeclared_sec" {
  secret_id = "workspace-doc-example-secret" # Replace with actual secret name
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(undeclared_tf, encoding="utf-8")
    r_undec = run_graph_analyzer(tmp_path)
    assert r_undec.risk_score == 0.65
    assert any(
        "PARALLAX-IAM-INVALID-SCOPED-SECRET" in f.finding_id for f in r_undec.findings
    )

    # (c) Token-creator granted to the service account on itself (Trial 14/16/18/20 bug)
    sa_impersonation_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_secret_manager_secret" "workspace_sec" {
  secret_id = "workspace-doc-context"
}
resource "google_secret_manager_secret_iam_member" "valid_sec" {
  secret_id = google_secret_manager_secret.workspace_sec.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
resource "google_service_account_iam_member" "self_token" {
  service_account_id = google_service_account.sa_agent_runner.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(sa_impersonation_tf, encoding="utf-8")
    r_self = run_graph_analyzer(tmp_path)
    assert r_self.risk_score == 0.65
    assert any("PARALLAX-IAM-SA-TOKEN-CREATOR" in f.finding_id for f in r_self.findings)

    # (d) Moving Cloud Run to a dedicated least-privilege SA severing exposure
    dedicated_sa_tf = """
resource "google_service_account" "sa_legacy_overpriv" {
  account_id = "sa-legacy-overpriv"
}
resource "google_service_account" "sa_dedicated_least_priv" {
  account_id = "sa-dedicated-least-priv"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_dedicated_least_priv.email
  }
}
resource "google_project_iam_member" "legacy_binding" {
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.sa_legacy_overpriv.email}"
}
resource "google_secret_manager_secret" "workspace_sec" {
  secret_id = "workspace-doc-context"
}
resource "google_secret_manager_secret_iam_member" "dedicated_scoped" {
  secret_id = google_secret_manager_secret.workspace_sec.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_dedicated_least_priv.email}"
}
"""
    tf_path.write_text(dedicated_sa_tf, encoding="utf-8")
    r_ded = run_graph_analyzer(tmp_path)
    assert r_ded.risk_score == 0.10
    assert len(r_ded.findings) == 0


def test_v6_seeded_renamed_variable_bypass_caught_by_replay_and_discrepancy(
    tmp_path: Path,
) -> None:
    """Prove P0 #6: renamed variable evades static AST but replay forces risk=1.0."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")

    # Rename fallback_id and effective_secret_id assignment so static string
    # check ('effective_secret_id = fallback_id') is evaded while flaw remains
    evasive_code = orig_code.replace(
        'fallback_id = str(tool_payload.get("fallback_secret_id", ""))',
        'alt_sec = str(tool_payload.get("fallback_secret_id", ""))',
    ).replace(
        "if use_fallback and fallback_id:\n"
        "        if not SAFE_ID_PATTERN.match(fallback_id):\n"
        '            raise ValueError("Invalid fallback_secret_id format.")\n'
        "        effective_secret_id = fallback_id",
        "if use_fallback and alt_sec:\n        effective_secret_id = str(alt_sec)",
    )
    svc_path.write_text(evasive_code, encoding="utf-8")

    # Static-only score would have been 0.05, but with replay integrated it is 1.0!
    rep_static_only = run_cross_layer_auditor(
        tmp_path, enable_llm_enrichment=False, enforce_replay_in_score=False
    )
    assert rep_static_only.risk_score == 0.05

    rep_with_replay = run_cross_layer_auditor(
        tmp_path, enable_llm_enrichment=False, enforce_replay_in_score=True
    )
    assert rep_with_replay.risk_score == 1.0
    assert any(
        f.finding_id == "PARALLAX-AST-REPLAY-DISCREPANCY"
        for f in rep_with_replay.findings
    )


def test_v7_iac_positive_control_access_revoked_and_non_iam_resource_allowed(
    tmp_path: Path,
) -> None:
    """Prove Round 5 #1, #4, #6: revoke-all -> 0.60, non-IAM resource allowed."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # Fix service.py so code layer is clean (0.05)
    svc_code = svc_path.read_text(encoding="utf-8").replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    svc_path.write_text(svc_code, encoding="utf-8")

    # 1. Comment out project bindings, add commented placeholder (Trials 14/16/20)
    revoked_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
# resource "google_secret_manager_secret_iam_member" "commented_out" {
#   secret_id = "workspace-doc-example" # Replace with actual secret name
# }
"""
    tf_path.write_text(revoked_tf, encoding="utf-8")
    r_rev = run_graph_analyzer(tmp_path)
    assert r_rev.risk_score == 0.60
    f_ids = {f.finding_id for f in r_rev.findings}
    assert "PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT" in f_ids
    assert "PARALLAX-IAM-COMMENTED-OUT-PLACEHOLDER" in f_ids

    delta_rev = evaluate_directory_delta(
        tmp_path,
        "test-revoked",
        baseline_scores=(0.95, 0.95, 0.05),
        files_touched=[
            "benchmark_target/app/service.py",
            "benchmark_target/infra/main.tf",
        ],
    )
    assert delta_rev.patch_state == PatchClassification.ACCESS_REVOKED_NO_REPLACEMENT

    # 2. Unrelated non-IAM resources (google_project_service, cloud_run_iam) allowed
    valid_with_extra_res_tf = """
resource "google_project_service" "secretmanager_api" {
  service = "secretmanager.googleapis.com"
}
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  name   = google_cloud_run_v2_service.vertex_ops_agent.name
  role   = "roles/run.invoker"
  member = "allUsers"
}
resource "google_secret_manager_secret" "workspace_doc_quarterly_notes" {
  secret_id = "workspace-doc-quarterly-notes"
}
resource "google_secret_manager_secret_iam_member" "scoped_ok" {
  secret_id = google_secret_manager_secret.workspace_doc_quarterly_notes.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(valid_with_extra_res_tf, encoding="utf-8")
    r_valid = run_graph_analyzer(tmp_path)
    assert r_valid.risk_score == 0.10
    assert len(r_valid.findings) == 0


def test_v7_telemetry_aggregate_coverage_and_secops002_rename_or_delete(
    tmp_path: Path,
) -> None:
    """Prove Round 5 #3: aggregate corpus coverage and SECOPS_GCP_002 rename."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    orig_rules = rules_path.read_text(encoding="utf-8")

    # 1. Narrow SECOPS_GCP_001 while SECOPS_GCP_002 still covers prod-
    old_m = (
        "    match:\n"
        '      event_type: "SECRET_MANAGER_ACCESS"\n'
        '      tool_name: "read_workspace_context"\n'
    )
    new_m = old_m + '      target_secret_prefix: "workspace-doc-"\n'
    narrow_001 = orig_rules.replace(old_m, new_m, 1)
    rules_path.write_text(narrow_001, encoding="utf-8")
    rep_001 = run_telemetry_validator(tmp_path)
    # Minor redundancy penalty (0.15), NOT a >0.35 blindspot!
    assert rep_001.risk_score == 0.15
    assert any(
        f.finding_id == "TELEM_RULE_PREDICATE_NARROWING_SECOPS_GCP_001"
        for f in rep_001.findings
    )

    # 2. Rename SECOPS_GCP_002 -> SECOPS_CUSTOM_999 and narrow it (evasion attempt)
    renamed_002 = orig_rules.replace(
        'rule_id: "SECOPS_GCP_002"', 'rule_id: "SECOPS_CUSTOM_999"'
    ).replace(
        'target_secret_prefix: "prod-"',
        'target_secret_prefix: "workspace-doc-"',
    )
    rules_path.write_text(renamed_002, encoding="utf-8")
    rep_renamed = run_telemetry_validator(tmp_path)
    assert rep_renamed.risk_score >= 0.50
    assert any(
        "TELEM_CRITICAL_ALERT_LOST_PROD_DB_EXFILTRATION" in f.finding_id
        for f in rep_renamed.findings
    )


def test_v7_pathlib_rejected_with_screen_rejected_status(
    tmp_path: Path,
) -> None:
    """Prove Round 5 #5: pathlib emits screen_rejected, not discrepancy."""
    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")
    patched = "import pathlib\n" + orig_code.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    svc_path.write_text(patched, encoding="utf-8")
    rep = run_cross_layer_auditor(tmp_path, enable_llm_enrichment=False)
    f_ids = {f.finding_id for f in rep.findings}
    assert "PARALLAX-AST-REPLAY-UNVERIFIABLE-SCREEN_REJECTED" in f_ids
    assert "PARALLAX-AST-REPLAY-DISCREPANCY" not in f_ids


def test_v8_positive_control_rejects_prod_secret_and_allusers_binding(
    tmp_path: Path,
) -> None:
    """Prove Round 6 #1: prod-* secret binding and allUsers binding score 0.95 CRITICAL."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"

    # (a) Patch declares prod-master-db and binds workload SA to it -> CRITICAL 0.95!
    prod_bound_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_secret_manager_secret" "prod_db" {
  secret_id = "prod-master-db"
}
resource "google_secret_manager_secret_iam_member" "evil_prod_bind" {
  secret_id = google_secret_manager_secret.prod_db.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(prod_bound_tf, encoding="utf-8")
    r_prod = run_graph_analyzer(tmp_path)
    assert r_prod.risk_score == 0.95
    assert any(
        "PARALLAX-IAM-OUT-OF-SCOPE-SECRET-EVIL_PROD_BIND" in f.finding_id
        for f in r_prod.findings
    )

    # (b) Patch binds workspace secret to allUsers -> CRITICAL 0.95!
    allusers_tf = """
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_secret_manager_secret" "ws_sec" {
  secret_id = "workspace-doc-quarterly-notes"
}
resource "google_secret_manager_secret_iam_member" "public_bind" {
  secret_id = google_secret_manager_secret.ws_sec.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "allUsers"
}
"""
    tf_path.write_text(allusers_tf, encoding="utf-8")
    r_pub = run_graph_analyzer(tmp_path)
    assert r_pub.risk_score == 0.95
    assert any(
        "PARALLAX-IAM-PUBLIC-SECRET-EXPOSURE-PUBLIC_BIND" in f.finding_id
        for f in r_pub.findings
    )


def test_v8_bucket_pubsub_iam_allowed_and_per_binding_comment_scoping(
    tmp_path: Path,
) -> None:
    """Prove Round 6 #3 & #5: bucket/pubsub IAM allowed; per-binding comments."""
    _copy_baseline_to_tmp(tmp_path)
    tf_path = tmp_path / "benchmark_target" / "infra" / "main.tf"

    # Unrelated comment at top + bucket/pubsub IAM + secret named workspace-doc-todo-notes
    clean_tf = """
# Replace with actual bucket name in staging if needed
resource "google_service_account" "sa_agent_runner" {
  account_id = "sa-agent-runner"
}
resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name    = "vertex-ops-agent"
  ingress = "INGRESS_TRAFFIC_ALL"
  template {
    service_account = google_service_account.sa_agent_runner.email
  }
}
resource "google_storage_bucket_iam_member" "bucket_viewer" {
  bucket = "my-workspace-bucket"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
resource "google_pubsub_topic_iam_member" "pubsub_pub" {
  topic  = "agent-events"
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
resource "google_secret_manager_secret" "todo_notes" {
  secret_id = "workspace-doc-todo-notes"
}
resource "google_secret_manager_secret_iam_member" "scoped_ok" {
  secret_id = google_secret_manager_secret.todo_notes.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(clean_tf, encoding="utf-8")
    rep = run_graph_analyzer(tmp_path)
    assert rep.risk_score == 0.10
    assert len(rep.findings) == 0


def test_v8_telemetry_baseline_isolated_and_overbroad_benign_corpus(
    tmp_path: Path,
) -> None:
    """Prove Round 6 #2 & #6: custom baseline_rules_path and benign corpus check."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    orig_rules = rules_path.read_text(encoding="utf-8")

    # 1. Over-broaden SECOPS_GCP_002 by removing target_secret_prefix: "prod-"
    # so CRITICAL canary fires on benign workspace-doc reads!
    overbroad_rules = orig_rules.replace('      target_secret_prefix: "prod-"\n', "")
    rules_path.write_text(overbroad_rules, encoding="utf-8")
    rep_broad = run_telemetry_validator(tmp_path)
    assert rep_broad.risk_score >= 0.50
    assert any(
        f.finding_id == "TELEM_OVERBROAD_RULE_FALSE_POSITIVE_SECOPS_GCP_002"
        for f in rep_broad.findings
    )

    # 2. Prove baseline_rules_path overrides any external checkout file
    custom_base = tmp_path / "custom_baseline_rules.yaml"
    custom_base.write_text(orig_rules, encoding="utf-8")
    rules_path.write_text(orig_rules, encoding="utf-8")
    rep_custom = run_telemetry_validator(tmp_path, baseline_rules_path=custom_base)
    assert rep_custom.risk_score == 0.05


def test_v8_unverifiable_state_and_readme_sync_and_pyc_gitignore(
    tmp_path: Path,
) -> None:
    """Prove Round 6 #4 & #8: UNVERIFIABLE state, README sync, and *.pyc gitignored."""
    import subprocess as _sp

    from parallax.readme_sync import render_readme_from_artifacts

    _copy_baseline_to_tmp(tmp_path)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    orig_code = svc_path.read_text(encoding="utf-8")

    # 1. Patch importing unlisted module 'pathlib' -> UNVERIFIABLE (not exploit!)
    unverifiable_code = "import pathlib\n" + orig_code.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    svc_path.write_text(unverifiable_code, encoding="utf-8")
    delta_unv = evaluate_directory_delta(
        tmp_path,
        "test-unverifiable",
        baseline_scores=(0.95, 0.95, 0.05),
        files_touched=["benchmark_target/app/service.py"],
    )
    assert delta_unv.patch_state == PatchClassification.UNVERIFIABLE
    assert delta_unv.split_brain_detected is False

    # 2. Verify README.md matches parallax_audit_proof.json byte-for-byte
    proof_data = json.loads(
        (ROOT_DIR / "artifacts" / "parallax_audit_proof.json").read_text(
            encoding="utf-8"
        )
    )
    expected_readme = render_readme_from_artifacts(proof_data)
    actual_readme = (ROOT_DIR / "README.md").read_text(encoding="utf-8")
    assert actual_readme == expected_readme

    # 3. Verify *.pyc and __pycache__/ are gitignored
    chk = _sp.run(  # noqa: S603
        ["git", "check-ignore", "parallax/__pycache__/schemas.cpython-313.pyc"],  # noqa: S607
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    assert chk.returncode == 0
