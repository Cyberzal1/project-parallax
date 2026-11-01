"""Subagent 03: Isolated Git Worktree Split-Brain Patch Verifier."""

import re
import shutil
import subprocess
import uuid
from collections.abc import Callable
from pathlib import Path

from parallax.cross_layer_auditor import run_cross_layer_auditor
from parallax.graph_analyzer import run_graph_analyzer
from parallax.schemas import (
    Finding,
    Layer,
    PatchClassification,
    Severity,
    SplitBrainDelta,
    SubagentReport,
)
from parallax.telemetry_validator import run_telemetry_validator

WEIGHT_IAC: float = 0.45
WEIGHT_CODE: float = 0.35
WEIGHT_TELEMETRY: float = 0.20
MIN_CODE_IMPROVEMENT: float = 0.30
HIGH_RISK_THRESHOLD: float = 0.70
CLEAN_RISK_THRESHOLD: float = 0.20

WORKTREE_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)
DEFAULT_BENCHMARK_FILES: list[str] = [
    "benchmark_target/app/service.py",
    "benchmark_target/infra/main.tf",
    "benchmark_target/secops/rules.yaml",
]


def validate_worktree_path(repo_root: Path, worktree_name: str) -> Path:
    """Validate worktree_name against traversal and return resolved path."""
    if not WORKTREE_NAME_PATTERN.match(worktree_name):
        raise ValueError(
            f"Unsafe worktree_name '{worktree_name}': must match "
            f"{WORKTREE_NAME_PATTERN.pattern}"
        )
    worktrees_base = (repo_root / ".worktrees").resolve()
    candidate = (worktrees_base / worktree_name).resolve()
    if not candidate.is_relative_to(worktrees_base):
        raise ValueError(
            f"Path traversal blocked: '{candidate}' escapes '{worktrees_base}'."
        )
    return candidate


def _run_git_command(
    repo_dir: Path,
    args: list[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Execute git safely with shell=False and surface stderr on failure."""
    try:
        return subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            check=check,
            encoding="utf-8",
        )
    except subprocess.CalledProcessError as exc:
        stderr_msg = (exc.stderr or "").strip()
        raise RuntimeError(
            f"Git command {' '.join(['git', *args])} failed in {repo_dir}: {stderr_msg}"
        ) from exc


def _score_directory_layers(target_dir: Path) -> tuple[float, float, float]:
    """Compute independent (iac_risk, code_risk, telemetry_risk) for a tree."""
    iam_report = run_graph_analyzer(target_dir)
    ast_report = run_cross_layer_auditor(target_dir, iam_report.risk_score)
    secops_report = run_telemetry_validator(target_dir)
    return (
        iam_report.risk_score,
        ast_report.risk_score,
        secops_report.risk_score,
    )


def _detect_git_touched_files(wt_dir: Path) -> list[str]:
    """Inspect git status --porcelain in worktree to list modified files."""
    proc = _run_git_command(wt_dir, ["status", "--porcelain", "-uall"], check=False)
    if proc.returncode != 0:
        return list(DEFAULT_BENCHMARK_FILES)
    touched: list[str] = []
    for raw_line in proc.stdout.splitlines():
        if len(raw_line) > 3:
            path_part = raw_line[3:].strip().replace("\\", "/")
            if " -> " in path_part:
                path_part = path_part.split(" -> ", maxsplit=1)[1].strip()
            touched.append(path_part)
    return sorted(set(touched))


def evaluate_directory_delta(
    worktree_root: Path,
    patch_name: str,
    baseline_scores: tuple[float, float, float] | None = None,
    files_touched: list[str] | None = None,
) -> SplitBrainDelta:
    """Compute before/after Split-Brain Security Delta across all 3 layers."""
    before_iac, before_code, before_tel = (
        baseline_scores if baseline_scores is not None else (0.95, 0.95, 0.05)
    )
    after_iac, after_code, after_tel = _score_directory_layers(worktree_root)

    d_iac = round(after_iac - before_iac, 2)
    d_code = round(after_code - before_code, 2)
    d_tel = round(after_tel - before_tel, 2)

    effective_delta = round(
        (after_iac * WEIGHT_IAC)
        + (after_code * WEIGHT_CODE)
        + (after_tel * WEIGHT_TELEMETRY),
        2,
    )

    code_improved = d_code <= -MIN_CODE_IMPROVEMENT and after_code < 0.50
    iac_unfixed = d_iac >= 0.0 and after_iac >= HIGH_RISK_THRESHOLD
    telemetry_degraded = d_tel > 0.0 or after_tel >= HIGH_RISK_THRESHOLD
    split_brain = code_improved and (iac_unfixed or telemetry_degraded)

    if (
        after_iac < CLEAN_RISK_THRESHOLD
        and after_code < CLEAN_RISK_THRESHOLD
        and after_tel < CLEAN_RISK_THRESHOLD
    ):
        patch_state = PatchClassification.HOLISTIC_REMEDIATION
        summary = (
            f"[{patch_name}] Full Root-Cause Architectural Remediation verified "
            "across Code AST, GCP Terraform IAM, and SecOps Telemetry."
        )
    elif split_brain:
        patch_state = PatchClassification.SPLIT_BRAIN_REMEDIATION
        summary = (
            f"[{patch_name}] SPLIT-BRAIN REMEDIATION DETECTED: Fast patch left "
            f"IaC Risk={after_iac:.2f} (d={d_iac:+.2f}), Code Risk={after_code:.2f} "
            f"(d={d_code:+.2f}), Telemetry Drift Risk={after_tel:.2f} "
            f"(d={d_tel:+.2f})."
        )
    elif d_iac == 0.0 and d_code == 0.0 and d_tel == 0.0:
        patch_state = PatchClassification.NO_OP_BASELINE
        summary = (
            f"[{patch_name}] Baseline unpatched state "
            f"(Residual Index={effective_delta:.2f})."
        )
    elif (d_iac > 0.0 or d_code > 0.0 or d_tel > 0.0) and d_code >= 0.0:
        patch_state = PatchClassification.PURE_REGRESSION
        summary = (
            f"[{patch_name}] Security regression detected without code "
            f"remediation (d_iac={d_iac:+.2f}, d_code={d_code:+.2f}, "
            f"d_tel={d_tel:+.2f})."
        )
    else:
        patch_state = PatchClassification.PARTIAL_REMEDIATION
        summary = (
            f"[{patch_name}] Partial remediation (Residual Index="
            f"{effective_delta:.2f}, d_iac={d_iac:+.2f}, d_code={d_code:+.2f}, "
            f"d_tel={d_tel:+.2f})."
        )

    observed_files = (
        files_touched if files_touched is not None else list(DEFAULT_BENCHMARK_FILES)
    )

    return SplitBrainDelta(
        patch_name=patch_name,
        iac_reachability_risk=after_iac,
        code_dataflow_risk=after_code,
        telemetry_blindspot_risk=after_tel,
        effective_security_delta=effective_delta,
        split_brain_detected=split_brain,
        summary=summary,
        patch_state=patch_state,
        before_iac_risk=before_iac,
        before_code_risk=before_code,
        before_telemetry_risk=before_tel,
        delta_iac_risk=d_iac,
        delta_code_risk=d_code,
        delta_telemetry_risk=d_tel,
        files_touched=observed_files,
    )


def verify_patch_in_git_worktree(
    repo_root: Path,
    worktree_name: str,
    patch_mutator: Callable[[Path], None],
    base_ref: str = "HEAD",
) -> tuple[SplitBrainDelta, SubagentReport]:
    """Create isolated git worktree, score before/after delta, and clean up."""
    base_wt_dir = validate_worktree_path(repo_root, worktree_name)
    base_wt_dir.parent.mkdir(parents=True, exist_ok=True)
    run_suffix = uuid.uuid4().hex[:8]
    wt_dir = base_wt_dir.parent / f"{worktree_name}-{run_suffix}"

    if wt_dir.exists():
        _run_git_command(
            repo_root, ["worktree", "remove", "--force", str(wt_dir)], check=False
        )
        shutil.rmtree(wt_dir, ignore_errors=True)

    _run_git_command(
        repo_root, ["worktree", "add", "--detach", str(wt_dir), base_ref], check=True
    )

    try:
        before_scores = _score_directory_layers(wt_dir)
        patch_mutator(wt_dir)
        touched = _detect_git_touched_files(wt_dir)
        delta = evaluate_directory_delta(
            wt_dir,
            patch_name=worktree_name,
            baseline_scores=before_scores,
            files_touched=touched,
        )

        findings: list[Finding] = []
        if delta.split_brain_detected or (
            delta.patch_state == PatchClassification.PURE_REGRESSION
        ):
            finding_sev = (
                Severity.CRITICAL
                if (
                    delta.delta_telemetry_risk > 0.0
                    and delta.iac_reachability_risk >= 0.80
                )
                else Severity.HIGH
            )
            findings.append(
                Finding(
                    finding_id=f"PARALLAX-WT-{worktree_name.upper()}",
                    layer=Layer.PATCH_WORKTREE,
                    severity=finding_sev,
                    title=f"Split-Brain AI Patch Divergence in '{worktree_name}'",
                    description=delta.summary,
                    remediation_hint=(
                        "Coordinate code remediation with Terraform least-privilege "
                        "IAM and SecOps rule synchronization before merging."
                    ),
                    file_path=touched[0] if touched else "benchmark_target/",
                )
            )

        report = SubagentReport(
            subagent_name=f"Subagent 03: Worktree Patch Verifier ({worktree_name})",
            countered_defense_step=(
                "03 Remediate (Autonomous IDE/CLI Fix Verification)"
            ),
            findings=findings,
            files_touched=touched,
            open_questions=[],
            risk_score=delta.effective_security_delta,
        )
        return delta, report
    finally:
        _run_git_command(
            repo_root, ["worktree", "remove", "--force", str(wt_dir)], check=False
        )
        if wt_dir.exists():
            shutil.rmtree(wt_dir, ignore_errors=True)
        _run_git_command(repo_root, ["worktree", "prune"], check=False)
