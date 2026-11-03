"""Project PARALLAX Interactive CLI Demo Runner."""

from pathlib import Path

from parallax.orchestrator import run_parallax_orchestrator


def main() -> None:
    """Execute 4-stage audit and Git worktree simulation."""
    root = Path(__file__).resolve().parent.parent
    print("============================================================")
    print("Project PARALLAX: Adversarial Cloud Architecture & Patch Engine")
    print("============================================================")
    print(f"Target Workspace: {root.name}")
    print("Executing 4-Stage Audit & Git Worktree Patch Simulation...\n")

    report = run_parallax_orchestrator(root, run_worktree_simulations=True)

    print(f"Overall Posture: {report.overall_posture}")
    print(f"Total Subagent Reports: {len(report.subagent_reports)}")
    for sub in report.subagent_reports:
        print(
            f"  - [{sub.subagent_name}] Risk: {sub.risk_score:.2f} | "
            f"Findings: {len(sub.findings)}"
        )

    print("\n--- Split-Brain Remediation Evaluation (Git Worktrees) ---")
    for delta in report.split_brain_evaluations:
        print(f"  * Patch Worktree: {delta.patch_name}")
        print(f"    Weighted Residual Risk   : {delta.weighted_residual_risk:.2f}")
        print(f"    Split-Brain Detected     : {delta.split_brain_detected}")
        print(f"    Classification           : {delta.patch_state.value}")
        print(f"    Summary                  : {delta.summary}\n")


if __name__ == "__main__":
    main()
