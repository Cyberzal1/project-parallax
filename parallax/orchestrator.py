"""Main Thread Orchestrator: Coordinates Subagents 01-04 and Worktrees."""

from pathlib import Path

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.patch_verifier import (
    evaluate_directory_delta,
    verify_patch_in_git_worktree,
)
from parallax.schemas import OrchestratorReport, SplitBrainDelta, SubagentReport
from parallax.telemetry_validator import run_telemetry_validator


def apply_symptom_only_ide_patch(wt_root: Path) -> None:
    """Simulate a fast IDE/AI patch that fixes Python but drifts tool_name."""
    service_path = wt_root / "benchmark_target" / "app" / "service.py"
    code = service_path.read_text(encoding="utf-8")
    code = code.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    code = code.replace(
        'tool_name="read_workspace_context"',
        'tool_name="read_workspace_context_v2"',
    )
    service_path.write_text(code, encoding="utf-8")


def apply_holistic_architectural_patch(wt_root: Path) -> None:
    """Simulate a holistic Cloud Architect fix across Code, IAM, and SecOps."""
    service_path = wt_root / "benchmark_target" / "app" / "service.py"
    code = service_path.read_text(encoding="utf-8")
    code = code.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    service_path.write_text(code, encoding="utf-8")

    tf_path = wt_root / "benchmark_target" / "infra" / "main.tf"
    scoped_tf = """terraform {
  required_version = ">= 1.6.0"
}

resource "google_service_account" "sa_agent_runner" {
  account_id   = "sa-agent-runner"
  display_name = "Vertex AI Ops Agent Service Account"
}

resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name     = "vertex-ops-agent"
  location = "asia-southeast1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.sa_agent_runner.email
    containers {
      image = "asia-southeast1-docker.pkg.dev/gcp-sg-parallax-sandbox/agents/v:1"
    }
  }
}

resource "google_secret_manager_secret" "workspace_doc_context" {
  secret_id = "workspace-doc-context"
}

resource "google_secret_manager_secret_iam_member" "scoped_workspace_secret" {
  secret_id = google_secret_manager_secret.workspace_doc_context.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(scoped_tf, encoding="utf-8")


def run_parallax_orchestrator(
    target_root: Path,
    run_worktree_simulations: bool = True,
) -> OrchestratorReport:
    """Execute the 4-stage adversarial audit and Git worktree simulations."""
    r1_graph = run_graph_analyzer(target_root)
    r2_ast = run_cross_layer_auditor(target_root, r1_graph.risk_score)
    r4_secops = run_telemetry_validator(target_root)

    measured_baseline = (
        r1_graph.risk_score,
        r2_ast.risk_score,
        r4_secops.risk_score,
    )

    reports: list[SubagentReport] = [r1_graph, r2_ast, r4_secops]
    evaluations: list[SplitBrainDelta] = [
        evaluate_directory_delta(
            target_root,
            "baseline-unpatched",
            baseline_scores=measured_baseline,
            files_touched=[],
        )
    ]

    if run_worktree_simulations:
        symptom_delta, symptom_report = verify_patch_in_git_worktree(
            target_root, "wt-symptom-patch", apply_symptom_only_ide_patch
        )
        reports.append(symptom_report)
        evaluations.append(symptom_delta)

        arch_delta, arch_report = verify_patch_in_git_worktree(
            target_root,
            "wt-architectural-patch",
            apply_holistic_architectural_patch,
        )
        reports.append(arch_report)
        evaluations.append(arch_delta)

    has_split_brain = any(ev.split_brain_detected for ev in evaluations)
    posture = (
        "CRITICAL_SPLIT_BRAIN_RISK_PROVEN" if has_split_brain else "BASELINE_EVALUATED"
    )

    return OrchestratorReport(
        target_root=".",
        subagent_reports=reports,
        split_brain_evaluations=evaluations,
        overall_posture=posture,
    )
