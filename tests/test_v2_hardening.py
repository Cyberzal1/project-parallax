"""Verification Gate 4: Hardening, Delta Math, and Telemetry Mutation Suite."""

from pathlib import Path

import pytest

from parallax.cross_layer_auditor import evaluate_auditor_precision_recall
from parallax.orchestrator import (
    apply_holistic_architectural_patch,
    apply_symptom_only_ide_patch,
)
from parallax.patch_verifier import (
    evaluate_directory_delta,
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


def test_v2_path_traversal_and_base_ref_option_injection_rejected() -> None:
    """Prove worktree path and base_ref validators block unsafe inputs."""
    for unsafe_name in ("../escape", "..\\escape", "/root/evil", "bad/slash", ""):
        with pytest.raises(ValueError, match="Unsafe worktree_name"):
            validate_worktree_path(ROOT_DIR, unsafe_name)

    for unsafe_ref in ("--upload-pack=evil", "-f", "--detach", ""):
        with pytest.raises(ValueError, match="Unsafe base_ref"):
            validate_base_ref(ROOT_DIR, unsafe_ref)


def test_v2_true_before_after_delta_and_classifications(tmp_path: Path) -> None:
    """Prove 5-state classification handles no-op on clean repo and regressions."""
    _copy_baseline_to_tmp(tmp_path)

    # 1. No-op patch on baseline (measured dynamically when baseline_scores omitted)
    noop_delta = evaluate_directory_delta(tmp_path, "test-noop")
    assert noop_delta.patch_state == PatchClassification.NO_OP_BASELINE
    assert noop_delta.split_brain_detected is False
    assert noop_delta.delta_code_risk == 0.0
    assert noop_delta.files_touched == []

    # 2. No-op patch on an ALREADY holistic clean repo -> NO_OP_BASELINE (not HOLISTIC!)
    apply_holistic_architectural_patch(tmp_path)
    clean_noop = evaluate_directory_delta(
        tmp_path, "already-clean-noop", baseline_scores=(0.10, 0.05, 0.05)
    )
    assert clean_noop.patch_state == PatchClassification.NO_OP_BASELINE
    assert clean_noop.split_brain_detected is False

    # 3. Holistic patch compared against vulnerable baseline -> HOLISTIC_REMEDIATION
    holistic_delta = evaluate_directory_delta(
        tmp_path, "test-holistic", baseline_scores=(0.95, 0.95, 0.05)
    )
    assert holistic_delta.patch_state == PatchClassification.HOLISTIC_REMEDIATION
    assert holistic_delta.split_brain_detected is False

    # 4. Small code gain (-0.20) + large telemetry regression (+0.80) -> PURE_REGRESSION
    _copy_baseline_to_tmp(tmp_path)
    apply_symptom_only_ide_patch(tmp_path)
    # Simulate a partial code state (0.75) by removing primary prefix check while
    # keeping fallback read, plus broken telemetry (0.85)
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"
    svc_code = svc_path.read_text(encoding="utf-8").replace(
        "if not primary_id.startswith(ALLOWED_WORKSPACE_PREFIX):",
        "if False:",
    )
    svc_path.write_text(svc_code, encoding="utf-8")
    reg_delta = evaluate_directory_delta(
        tmp_path, "small-code-gain-big-reg", baseline_scores=(0.95, 0.95, 0.05)
    )
    assert reg_delta.delta_code_risk == -0.20
    assert reg_delta.delta_telemetry_risk == 0.80
    assert reg_delta.patch_state == PatchClassification.PURE_REGRESSION


def test_v2_telemetry_fail_closed_on_deleted_corrupt_or_missing_class(
    tmp_path: Path,
) -> None:
    """Prove deleting rules, corrupt syntax/YAML, or removing AuditEvent scores 1.0."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    svc_path = tmp_path / "benchmark_target" / "app" / "service.py"

    # Case A: Empty YAML file
    rules_path.write_text("", encoding="utf-8")
    empty_report = run_telemetry_validator(tmp_path)
    assert empty_report.risk_score == 1.0
    assert empty_report.findings[0].finding_id == "TELEM_FAIL_CLOSED_EMPTY_RULES"

    # Case B: Malformed YAML syntax (exercises TELEM_FAIL_CLOSED_CORRUPT_INPUT)
    rules_path.write_text("rules: [unclosed_list\n", encoding="utf-8")
    corrupt_yaml_report = run_telemetry_validator(tmp_path)
    assert corrupt_yaml_report.risk_score == 1.0
    assert (
        corrupt_yaml_report.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"
    )

    # Case C: Syntax error in service.py (exercises TELEM_FAIL_CLOSED_CORRUPT_INPUT)
    _copy_baseline_to_tmp(tmp_path)
    svc_path.write_text("def broken_syntax(\n", encoding="utf-8")
    corrupt_py_report = run_telemetry_validator(tmp_path)
    assert corrupt_py_report.risk_score == 1.0
    assert corrupt_py_report.findings[0].finding_id == "TELEM_FAIL_CLOSED_CORRUPT_INPUT"

    # Case D: AuditEvent class removed from service.py (fail-closed check)
    _copy_baseline_to_tmp(tmp_path)
    svc_no_class = svc_path.read_text(encoding="utf-8").replace(
        "class AuditEvent(BaseModel):", "class LegacyEvent(BaseModel):"
    )
    svc_path.write_text(svc_no_class, encoding="utf-8")
    no_class_report = run_telemetry_validator(tmp_path)
    assert no_class_report.risk_score == 1.0
    assert (
        no_class_report.findings[0].finding_id
        == "TELEM_FAIL_CLOSED_MISSING_AUDIT_CLASS"
    )

    # Case E: Deleted rules.yaml
    rules_path.unlink()
    deleted_report = run_telemetry_validator(tmp_path)
    assert deleted_report.risk_score == 1.0
    assert deleted_report.findings[0].finding_id == "TELEM_FAIL_CLOSED_MISSING_FILE"


def test_v2_telemetry_malformed_rule_entries_and_duplicates(
    tmp_path: Path,
) -> None:
    """Prove non-dict rules, null match blocks, and duplicate rule_ids are caught."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"
    rules_path.write_text(
        "\n".join(
            [
                "rules:",
                '  - "not_a_dict_entry"',
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
    assert "TELEM_INVALID_MATCH_SECOPS_DUP" in f_ids
    assert "TELEM_DUPLICATE_RULE_ID_SECOPS_DUP" in f_ids
    assert report.risk_score > 0.50


def test_v2_telemetry_bidirectional_unmonitored_tool_and_dynamic_ast(
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


def test_v2_telemetry_proportional_scoring_and_field_drift(tmp_path: Path) -> None:
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


def test_v2_auditor_seeded_precision_and_recall() -> None:
    """Prove deterministic AST auditor achieves 100% precision/recall on 10 seeds."""
    metrics = evaluate_auditor_precision_recall()
    assert metrics["total_cases"] == 10.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


def test_v2_dynamic_files_touched_and_clean_finding_id_in_worktree() -> None:
    """Prove worktree verifier reports exact touched files and clean finding IDs."""
    symptom_delta, symptom_report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-v2-symptom", apply_symptom_only_ide_patch
    )
    assert symptom_report.files_touched == ["benchmark_target/app/service.py"]
    assert symptom_delta.files_touched == ["benchmark_target/app/service.py"]
    assert symptom_report.findings[0].finding_id == "PARALLAX-WT-V2-SYMPTOM"
    assert symptom_report.findings[0].severity == Severity.CRITICAL

    _, arch_report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-v2-arch", apply_holistic_architectural_patch
    )
    assert sorted(arch_report.files_touched) == [
        "benchmark_target/app/service.py",
        "benchmark_target/infra/main.tf",
    ]
