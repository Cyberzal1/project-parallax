"""Verification Gate 3: Unit & Integration Tests for Subagents 01-04."""

import subprocess
from pathlib import Path

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.orchestrator import (
    apply_holistic_architectural_patch,
    apply_symptom_only_ide_patch,
    run_parallax_orchestrator,
)
from parallax.patch_verifier import (
    evaluate_directory_delta,
    score_directory_layers,
)
from parallax.telemetry_validator import run_telemetry_validator

ROOT_DIR = Path(__file__).resolve().parent.parent


def _ensure_git_commit_exists(repo_dir: Path) -> None:
    """Ensure local repo has at least one commit so git worktree add HEAD works."""
    check = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--verify", "HEAD"],  # noqa: S607
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if check.returncode != 0:
        cmds = [
            ["git", "config", "user.email", "parallax@local.test"],
            ["git", "config", "user.name", "Parallax Auditor"],
            ["git", "add", "."],
            [
                "git",
                "commit",
                "-m",
                "chore: baseline snapshot for worktree testing",
            ],
        ]
        for cmd in cmds:
            subprocess.run(cmd, cwd=str(repo_dir), check=True)  # noqa: S603


def test_gate3_subagent01_graph_analyzer_detects_nhi_escalation() -> None:
    """Verify Subagent 01 finds Cloud Run -> SA -> project Secret Manager path."""
    report = run_graph_analyzer(ROOT_DIR)
    assert report.risk_score >= 0.90
    assert len(report.findings) == 2
    titles = " | ".join(f.title for f in report.findings)
    assert "roles/secretmanager.secretAccessor" in titles
    assert "roles/iam.serviceAccountTokenCreator" in titles


def test_gate3_subagent02_ast_auditor_detects_fallback_bypass() -> None:
    """Verify Subagent 02 detects unvalidated fallback_secret_id in service.py."""
    report = run_cross_layer_auditor(ROOT_DIR, iam_risk_score=0.95)
    assert report.risk_score == 0.95
    assert len(report.findings) == 1
    assert report.findings[0].finding_id == "PARALLAX-AST-001"


def test_gate3_subagent04_telemetry_validator_baseline_clean() -> None:
    """Verify baseline service.py matches secops/rules.yaml before refactor."""
    report = run_telemetry_validator(ROOT_DIR)
    assert report.risk_score < 0.2
    assert len(report.findings) == 0


def test_gate3_split_brain_differential_mathematics(tmp_path: Path) -> None:
    """Prove symptom patch triggers Split-Brain while holistic patch resolves all."""
    for rel in ("infra/main.tf", "app/service.py", "secops/rules.yaml"):
        src = ROOT_DIR / "benchmark_target" / rel
        dst = tmp_path / "benchmark_target" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

    baseline_scores = score_directory_layers(tmp_path)

    apply_symptom_only_ide_patch(tmp_path)
    symptom_delta = evaluate_directory_delta(
        tmp_path, "unit-symptom-patch", baseline_scores=baseline_scores
    )
    assert symptom_delta.code_dataflow_risk < 0.2
    assert symptom_delta.iac_reachability_risk >= 0.9
    assert symptom_delta.telemetry_blindspot_risk >= 0.8
    assert symptom_delta.split_brain_detected is True

    orig_service = ROOT_DIR / "benchmark_target" / "app" / "service.py"
    (tmp_path / "benchmark_target" / "app" / "service.py").write_text(
        orig_service.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    apply_holistic_architectural_patch(tmp_path)
    holistic_delta = evaluate_directory_delta(
        tmp_path, "unit-holistic-patch", baseline_scores=baseline_scores
    )
    assert holistic_delta.code_dataflow_risk < 0.2
    assert holistic_delta.iac_reachability_risk < 0.2
    assert holistic_delta.telemetry_blindspot_risk < 0.2
    assert holistic_delta.split_brain_detected is False


def test_gate3_end_to_end_orchestrator_with_git_worktrees() -> None:
    """Verify full Orchestrator execution with real isolated Git worktrees."""
    _ensure_git_commit_exists(ROOT_DIR)
    orchestrator_report = run_parallax_orchestrator(
        ROOT_DIR, run_worktree_simulations=True
    )

    assert orchestrator_report.overall_posture == "CRITICAL_SPLIT_BRAIN_RISK_PROVEN"
    assert len(orchestrator_report.split_brain_evaluations) == 3

    by_name = {d.patch_name: d for d in orchestrator_report.split_brain_evaluations}
    assert by_name["wt-symptom-patch"].split_brain_detected is True
    assert by_name["wt-architectural-patch"].split_brain_detected is False
    assert (
        by_name["wt-architectural-patch"].weighted_residual_risk
        < by_name["wt-symptom-patch"].weighted_residual_risk
    )
