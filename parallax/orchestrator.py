"""Main Thread Orchestrator coordinating Subagents 01-04."""

from pathlib import Path

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.patch_verifier import (
    evaluate_directory_delta,
    verify_patch_in_git_worktree,
)
from parallax.schemas import OrchestratorReport, SplitBrainDelta, SubagentReport
from parallax.telemetry_validator import run_telemetry_validator

OLD_FALLBACK_CHECK = "if not SAFE_ID_PATTERN.match(fallback_id):"
NEW_FALLBACK_CHECK = (
    "if not SAFE_ID_PATTERN.match(fallback_id) "
    "or not fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
)


def apply_symptom_only_ide_patch(wt_root: Path) -> None:
    """Simulate a hurried IDE AI patch that fixes prefix check but renames tool_name
    and ignores the over-permissive GCP Terraform IAM bindings (Split-Brain Fix).
    """
    service_path = wt_root / "benchmark_target" / "app" / "service.py"
    code = service_path.read_text(encoding="utf-8")

    code = code.replace(OLD_FALLBACK_CHECK, NEW_FALLBACK_CHECK)
    code = code.replace(
        'tool_name="read_workspace_context"',
        'tool_name="read_workspace_context_v2"',
    )
    service_path.write_text(code, encoding="utf-8")


def apply_holistic_architectural_patch(wt_root: Path) -> None:
    """Simulate a Cloud Architect fix across Code AST, Terraform IAM, and SecOps."""
    service_path = wt_root / "benchmark_target" / "app" / "service.py"
    code = service_path.read_text(encoding="utf-8")
    code = code.replace(OLD_FALLBACK_CHECK, NEW_FALLBACK_CHECK)
    service_path.write_text(code, encoding="utf-8")

    tf_path = wt_root / "benchmark_target" / "infra" / "main.tf"
    scoped_tf = """terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" {
  type    = string
  default = "gcp-sg-parallax-sandbox"
}

resource "google_service_account" "sa_agent_runner" {
  account_id   = "sa-agent-runner"
  display_name = "Vertex AI Workspace Ops Agent Service Account"
}

resource "google_cloud_run_v2_service" "vertex_ops_agent" {
  name     = "vertex-ops-agent"
  location = "asia-southeast1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.sa_agent_runner.email
    containers {
      image = "asia-southeast1-docker.pkg.dev/gcp-sg-parallax/agents/ops:1.0"
    }
  }
}

resource "google_secret_manager_secret_iam_member" "scoped_workspace_secret_accessor" {
  project   = var.project_id
  secret_id = "workspace-doc-shared-index"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.sa_agent_runner.email}"
}
"""
    tf_path.write_text(scoped_tf, encoding="utf-8")


def run_parallax_orchestrator(
    target_root: Path,
    run_worktree_simulations: bool = True,
) -> OrchestratorReport:
    """Run all 4 subagents and optional Git worktree patch-verification loops."""
    subagent_01 = run_graph_analyzer(target_root)
    subagent_02 = run_cross_layer_auditor(target_root, subagent_01.risk_score)
    subagent_04 = run_telemetry_validator(target_root)

    reports: list[SubagentReport] = [subagent_01, subagent_02, subagent_04]
    deltas: list[SplitBrainDelta] = [
        evaluate_directory_delta(target_root, patch_name="baseline-unpatched")
    ]

    if run_worktree_simulations:
        symptom_delta, symptom_report = verify_patch_in_git_worktree(
            target_root,
            worktree_name="wt-symptom-patch",
            patch_mutator=apply_symptom_only_ide_patch,
        )
        holistic_delta, holistic_report = verify_patch_in_git_worktree(
            target_root,
            worktree_name="wt-architectural-patch",
            patch_mutator=apply_holistic_architectural_patch,
        )
        reports.extend([symptom_report, holistic_report])
        deltas.extend([symptom_delta, holistic_delta])

    overall = (
        "CRITICAL_SPLIT_BRAIN_RISK_PROVEN"
        if any(d.split_brain_detected for d in deltas)
        else "SECURE"
    )
    return OrchestratorReport(
        target_root=str(target_root.as_posix()),
        subagent_reports=reports,
        split_brain_evaluations=deltas,
        overall_posture=overall,
    )
