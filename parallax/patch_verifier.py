"""Subagent 03: Isolated Git Worktree Patch Verifier (Countering 03 Remediate)."""

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.schemas import (
    Finding,
    Layer,
    Severity,
    SplitBrainDelta,
    SubagentReport,
)
from parallax.telemetry_validator import run_telemetry_validator


def _run_git_command(
    repo_dir: Path, args: list[str]
) -> subprocess.CompletedProcess[str]:
    """Execute git safely with shell=False and explicit argument list."""
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=True,
    )


def evaluate_directory_delta(worktree_root: Path, patch_name: str) -> SplitBrainDelta:
    """Compute Split-Brain Security Delta across IaC, Code AST, and SecOps rules."""
    iam_report = run_graph_analyzer(worktree_root)
    ast_report = run_cross_layer_auditor(worktree_root, iam_report.risk_score)
    secops_report = run_telemetry_validator(worktree_root)

    iac_risk = iam_report.risk_score
    code_risk = ast_report.risk_score
    telemetry_risk = secops_report.risk_score

    effective_delta = round(
        (iac_risk * 0.45) + (code_risk * 0.35) + (telemetry_risk * 0.20),
        4,
    )
    high_infra_or_secops = iac_risk >= 0.7 or telemetry_risk >= 0.7
    split_brain = (code_risk < 0.5) and high_infra_or_secops

    if iac_risk < 0.2 and code_risk < 0.2 and telemetry_risk < 0.2:
        split_brain = False
        summary = (
            f"[{patch_name}] Full Root-Cause Architectural Remediation verified across "
            "Code AST, GCP Terraform IAM, and SecOps Telemetry."
        )
    elif split_brain:
        summary = (
            f"[{patch_name}] SPLIT-BRAIN REMEDIATION DETECTED: Fast patch left "
            f"IaC Risk={iac_risk:.2f}, Code Risk={code_risk:.2f}, "
            f"Telemetry Drift Risk={telemetry_risk:.2f}."
        )
    else:
        summary = (
            f"[{patch_name}] Baseline unpatched state "
            f"(Residual Index={effective_delta:.2f})."
        )

    return SplitBrainDelta(
        patch_name=patch_name,
        iac_reachability_risk=iac_risk,
        code_dataflow_risk=code_risk,
        telemetry_blindspot_risk=telemetry_risk,
        effective_security_delta=effective_delta,
        split_brain_detected=split_brain,
        summary=summary,
    )


def verify_patch_in_git_worktree(
    repo_root: Path,
    worktree_name: str,
    patch_mutator: Callable[[Path], None],
) -> tuple[SplitBrainDelta, SubagentReport]:
    """Create isolated git worktree, apply candidate patch, and audit divergence."""
    wt_dir = repo_root / ".worktrees" / worktree_name
    if wt_dir.exists():
        _run_git_command(repo_root, ["worktree", "remove", "--force", str(wt_dir)])
        shutil.rmtree(wt_dir, ignore_errors=True)

    wt_dir.parent.mkdir(parents=True, exist_ok=True)
    _run_git_command(repo_root, ["worktree", "add", "--detach", str(wt_dir), "HEAD"])

    try:
        patch_mutator(wt_dir)
        delta = evaluate_directory_delta(wt_dir, patch_name=worktree_name)

        findings: list[Finding] = []
        if delta.split_brain_detected:
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-WT-{worktree_name.upper()}",
                    layer=Layer.PATCH_WORKTREE,
                    severity=Severity.HIGH,
                    title=f"Split-Brain AI Patch Divergence in '{worktree_name}'",
                    description=delta.summary,
                    remediation_hint=(
                        "Coordinate code remediation with Terraform least-privilege "
                        "IAM and SecOps rule synchronization before merging."
                    ),
                )
            )

        report = SubagentReport(
            subagent_name=f"Subagent 03: Worktree Patch Verifier ({worktree_name})",
            countered_defense_step="03 Remediate (Autonomous IDE/CLI Fix Verification)",
            findings=findings,
            files_touched=[
                "benchmark_target/app/service.py",
                "benchmark_target/infra/main.tf",
                "benchmark_target/secops/rules.yaml",
            ],
            open_questions=[],
            risk_score=delta.effective_security_delta,
        )
        return delta, report
    finally:
        _run_git_command(repo_root, ["worktree", "remove", "--force", str(wt_dir)])
        shutil.rmtree(wt_dir, ignore_errors=True)
