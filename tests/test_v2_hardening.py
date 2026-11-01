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


def test_v2_path_traversal_rejected() -> None:
    """Prove worktree path validator blocks '../' and absolute paths."""
    for unsafe_name in ("../escape", "..\\escape", "/root/evil", "bad/slash", ""):
        with pytest.raises(ValueError, match="Unsafe worktree_name"):
            validate_worktree_path(ROOT_DIR, unsafe_name)


def test_v2_true_before_after_delta_and_classifications(tmp_path: Path) -> None:
    """Prove 5-state classification distinguishes no-op, split-brain, holistic."""
    _copy_baseline_to_tmp(tmp_path)

    noop_delta = evaluate_directory_delta(
        tmp_path, "test-noop", baseline_scores=(0.95, 0.95, 0.05)
    )
    assert noop_delta.patch_state == PatchClassification.NO_OP_BASELINE
    assert noop_delta.split_brain_detected is False
    assert noop_delta.delta_code_risk == 0.0

    apply_symptom_only_ide_patch(tmp_path)
    already_patched_noop = evaluate_directory_delta(
        tmp_path, "already-low-code", baseline_scores=(0.95, 0.05, 0.85)
    )
    assert already_patched_noop.patch_state == PatchClassification.NO_OP_BASELINE
    assert already_patched_noop.split_brain_detected is False

    symptom_delta = evaluate_directory_delta(
        tmp_path, "test-symptom", baseline_scores=(0.95, 0.95, 0.05)
    )
    assert symptom_delta.patch_state == PatchClassification.SPLIT_BRAIN_REMEDIATION
    assert symptom_delta.split_brain_detected is True
    assert symptom_delta.delta_code_risk == -0.90
    assert symptom_delta.delta_telemetry_risk > 0.0

    _copy_baseline_to_tmp(tmp_path)
    apply_holistic_architectural_patch(tmp_path)
    holistic_delta = evaluate_directory_delta(
        tmp_path, "test-holistic", baseline_scores=(0.95, 0.95, 0.05)
    )
    assert holistic_delta.patch_state == PatchClassification.HOLISTIC_REMEDIATION
    assert holistic_delta.split_brain_detected is False


def test_v2_telemetry_fail_closed_on_deleted_or_corrupt_rules(
    tmp_path: Path,
) -> None:
    """Prove deleting or emptying rules.yaml scores 1.0 CRITICAL."""
    _copy_baseline_to_tmp(tmp_path)
    rules_path = tmp_path / "benchmark_target" / "secops" / "rules.yaml"

    rules_path.write_text("", encoding="utf-8")
    empty_report = run_telemetry_validator(tmp_path)
    assert empty_report.risk_score == 1.0
    assert empty_report.findings[0].severity == Severity.CRITICAL

    rules_path.unlink()
    deleted_report = run_telemetry_validator(tmp_path)
    assert deleted_report.risk_score == 1.0
    assert deleted_report.findings[0].finding_id == "TELEM_FAIL_CLOSED_MISSING_FILE"


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
    assert len(report.open_questions) == 1
    assert "dynamic AuditEvent.tool_name" in report.open_questions[0]


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
    """Prove deterministic AST auditor achieves 100% precision/recall on seeds."""
    metrics = evaluate_auditor_precision_recall()
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0


def test_v2_dynamic_files_touched_in_worktree() -> None:
    """Prove worktree verifier reports only files actually touched by mutator."""
    symptom_delta, symptom_report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-v2-symptom", apply_symptom_only_ide_patch
    )
    assert symptom_report.files_touched == ["benchmark_target/app/service.py"]
    assert symptom_delta.files_touched == ["benchmark_target/app/service.py"]
    assert symptom_report.findings[0].severity == Severity.CRITICAL

    _, arch_report = verify_patch_in_git_worktree(
        ROOT_DIR, "wt-v2-arch", apply_holistic_architectural_patch
    )
    assert sorted(arch_report.files_touched) == [
        "benchmark_target/app/service.py",
        "benchmark_target/infra/main.tf",
    ]
