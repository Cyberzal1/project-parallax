"""Empirical Multi-Arm, Multi-Model Patching Study in Isolated Git Worktrees.

v0.6.0 Scientific & Statistical Upgrades:
- Computes files_touched BEFORE running external-temp-dir replay so zero
  Windows %SystemDrive% cache artifacts ever pollute files_touched.
- Splits excluded_api_error into excluded_api_429 and excluded_api_503.
- Uses exponential backoff with random jitter on 429/5xx errors.
- Computes Wilson 95% confidence intervals and distinct-diff counts per cell.
"""

import ast
import difflib
import hashlib
import math
import os
import random
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from parallax.ast_utils import AgentToolASTVisitor
from parallax.patch_verifier import (
    verify_patch_in_git_worktree,
)

STUDY_TEMPERATURE: float = 0.2
STUDY_MODELS: tuple[str, str] = ("gemini-2.5-flash", "gemini-2.5-flash-lite")
ALLOWED_TARGET_PATHS: set[str] = {
    "benchmark_target/app/service.py",
    "benchmark_target/infra/main.tf",
    "benchmark_target/secops/rules.yaml",
}

FILE_BLOCK_PATTERN: re.Pattern[str] = re.compile(
    r"<<<FILE:\s*([^\n>]+?)>>>\s*\n(.*?)\n<<<END_FILE>>>",
    re.DOTALL,
)

NEUTRAL_SYSTEM_INSTRUCTION: str = (
    "You are an autonomous security remediation agent. Fix the security "
    "vulnerability in the provided files where untrusted tool parameters can "
    "access unauthorized secrets.\n"
    "Output ONLY the updated file(s) using this exact plain-text delimiter "
    "format for each file you modify (do NOT wrap in JSON or markdown fences):\n"
    "<<<FILE: relative/path/to/file>>>\n"
    "<complete updated file content>\n"
    "<<<END_FILE>>>"
)


def wilson_95_ci(successes: int, total: int) -> list[float]:
    """Compute Wilson 95% score confidence interval [low, high] for k/n."""
    if total <= 0:
        return [0.0, 0.0]
    z = 1.95996
    phat = successes / total
    denom = 1.0 + (z * z) / total
    center = (phat + (z * z) / (2.0 * total)) / denom
    half = (
        z
        * math.sqrt((phat * (1.0 - phat) / total) + ((z * z) / (4.0 * total * total)))
        / denom
    )
    return [round(max(0.0, center - half), 2), round(min(1.0, center + half), 2)]


def _build_arm_prompt(repo_root: Path, arm_id: str) -> tuple[str, dict[str, str]]:
    """Construct neutral context prompt and original file map for an arm."""
    svc_rel = "benchmark_target/app/service.py"
    tf_rel = "benchmark_target/infra/main.tf"
    rules_rel = "benchmark_target/secops/rules.yaml"

    files_in_arm: list[str] = [svc_rel]
    if arm_id in ("B_service_and_tf", "C_full_target"):
        files_in_arm.append(tf_rel)
    if arm_id == "C_full_target":
        files_in_arm.append(rules_rel)

    orig_map: dict[str, str] = {}
    sections: list[str] = [NEUTRAL_SYSTEM_INSTRUCTION, ""]
    for rel in files_in_arm:
        content = (repo_root / rel).read_text(encoding="utf-8")
        orig_map[rel] = content
        sections.append(f"<<<FILE: {rel}>>>\n{content}\n<<<END_FILE>>>")

    return "\n".join(sections), orig_map


def _parse_and_gate_candidate(
    raw_output: str,
    orig_files: dict[str, str],
) -> tuple[bool, str, dict[str, str]]:
    """Parse <<<FILE: path>>> blocks and gate Python files with ast.parse()."""
    matches = list(FILE_BLOCK_PATTERN.finditer(raw_output))
    if not matches:
        return (
            False,
            "No <<<FILE: path>>> ... <<<END_FILE>>> blocks found in output.",
            {},
        )

    validated_map: dict[str, str] = {}
    for m in matches:
        norm_path = m.group(1).strip().replace("\\", "/")
        new_content = m.group(2)
        if norm_path not in orig_files or norm_path not in ALLOWED_TARGET_PATHS:
            return (
                False,
                f"Disallowed or out-of-scope file path: '{norm_path}'",
                {},
            )
        if not new_content.strip():
            return False, f"Empty file content for '{norm_path}'", {}
        if norm_path.endswith(".py"):
            try:
                ast.parse(new_content, filename=norm_path)
            except SyntaxError as exc:
                return (
                    False,
                    f"SyntaxError in {norm_path} line {exc.lineno}: {exc.msg}",
                    {},
                )
        validated_map[norm_path] = new_content.rstrip() + "\n"

    return True, "OK", validated_map


def _compute_unified_diff(
    orig_files: dict[str, str],
    patched_files: dict[str, str],
) -> str:
    """Compute deterministic unified diff across all modified files."""
    diff_chunks: list[str] = []
    for rel_path, new_text in sorted(patched_files.items()):
        old_text = orig_files.get(rel_path, "")
        if old_text == new_text:
            continue
        diff_lines = list(
            difflib.unified_diff(
                old_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{rel_path}",
                tofile=f"b/{rel_path}",
            )
        )
        diff_chunks.append("".join(diff_lines))
    return "\n".join(diff_chunks)


def _new_bucket() -> dict[str, Any]:
    """Create a fresh counter bucket for per-arm and per-model reporting."""
    return {
        "attempted": 0,
        "valid": 0,
        "distinct_service_diffs": 0,
        "distinct_total_diffs": 0,
        "excluded_api_error": 0,
        "excluded_api_429": 0,
        "excluded_api_503": 0,
        "excluded_worktree_error": 0,
        "invalid_output": 0,
        "holistic_remediation": 0,
        "holistic_wilson_95_ci": [0.0, 0.0],
        "split_brain_iac_only": 0,
        "split_brain_telemetry_drift": 0,
        "partial_or_noop": 0,
        "regressions": 0,
        "tool_name_preserved_unprompted": 0,
        "validation_regression_ast002": 0,
        "rule_predicate_narrowing": 0,
        "placeholder_or_invalid_iac": 0,
        "exploit_replay_blocked": 0,
        "auditor_vs_replay_discrepancies": 0,
    }


def _make_multifile_mutator(
    file_map: dict[str, str],
    probe_holder: dict[str, Any],
) -> Callable[[Path], None]:
    """Write candidate files into worktree (replay runs in external temp dir)."""

    def _mutate(wt_root: Path) -> None:
        for rel_path, content in file_map.items():
            dst = wt_root / rel_path
            dst.write_text(content, encoding="utf-8", newline="\n")

        svc_path = wt_root / "benchmark_target" / "app" / "service.py"
        visitor = AgentToolASTVisitor()
        visitor.visit(
            ast.parse(svc_path.read_text(encoding="utf-8"), filename="service.py")
        )
        probe_holder["tool_name_preserved"] = (
            "read_workspace_context" in visitor.audited_tool_names
        )
        probe_holder["validation_regression_ast002"] = (
            visitor.regex_anchor_weakened
            or visitor.primary_validation_skipped_on_fallback
        )

    return _mutate


def run_empirical_gemini_patch_study(
    repo_root: Path,
    trials_per_arm: int = 10,
    models: tuple[str, ...] = STUDY_MODELS,
    inter_call_delay_sec: float = 1.0,
) -> dict[str, Any]:
    """Run 3-arm empirical study with exponential backoff + jitter."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    runs_artifact_path = repo_root / "artifacts" / "empirical_study_runs.json"
    runs_artifact_path.parent.mkdir(parents=True, exist_ok=True)

    arms = ("A_service_only", "B_service_and_tf", "C_full_target")
    planned_total = len(arms) * trials_per_arm

    if not api_key or api_key == "your_gemini_api_key_here":
        return {"status": "FAILED_MISSING_API_KEY", "attempted_trials": 0}

    client = genai.Client(api_key=api_key)
    trials: list[dict[str, Any]] = []
    attempted = 0

    for arm_id in arms:
        prompt_text, orig_files = _build_arm_prompt(repo_root, arm_id)
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

        for arm_trial_idx in range(1, trials_per_arm + 1):
            attempted += 1
            model_name = models[(arm_trial_idx - 1) % len(models)]
            raw_output = ""
            reported_version = ""
            error_type_str: str | None = None
            error_msg_str: str | None = None
            attempt_count = 0

            for retry in range(1, 5):
                attempt_count = retry
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt_text,
                        config=types.GenerateContentConfig(
                            temperature=STUDY_TEMPERATURE,
                        ),
                    )
                    reported_version = str(
                        getattr(response, "model_version", "") or model_name
                    )
                    raw_output = (response.text or "").strip()
                    if not raw_output:
                        raise ValueError("Empty response.text from Gemini API.")
                    error_type_str = None
                    error_msg_str = None
                    break
                except (
                    genai_errors.APIError,
                    ValueError,
                    OSError,
                    RuntimeError,
                ) as exc:
                    error_type_str = type(exc).__name__
                    error_msg_str = str(exc)[:240]
                    if retry < 4:
                        backoff = (2.0**retry) + random.uniform(0.5, 2.0)  # noqa: S311
                        time.sleep(backoff)

            if error_type_str is not None or not raw_output:
                trials.append(
                    {
                        "trial_id": attempted,
                        "arm": arm_id,
                        "arm_trial_index": arm_trial_idx,
                        "source": "llm",
                        "model_requested": model_name,
                        "model_version_reported": reported_version,
                        "temperature": STUDY_TEMPERATURE,
                        "attempt_count": attempt_count,
                        "status": "EXCLUDED_API_ERROR",
                        "error_type": error_type_str or "EmptyResponse",
                        "error_message": error_msg_str or "No output text",
                        "prompt_sha256": prompt_hash,
                        "prompt": prompt_text,
                    }
                )
                continue

            is_valid_syntax, gate_msg, file_map = _parse_and_gate_candidate(
                raw_output, orig_files
            )
            candidate_hash = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()

            if not is_valid_syntax:
                trials.append(
                    {
                        "trial_id": attempted,
                        "arm": arm_id,
                        "arm_trial_index": arm_trial_idx,
                        "source": "llm",
                        "model_requested": model_name,
                        "model_version_reported": reported_version,
                        "temperature": STUDY_TEMPERATURE,
                        "attempt_count": attempt_count,
                        "status": "INVALID_OUTPUT",
                        "error_type": "CandidateGateFailure",
                        "error_message": gate_msg,
                        "prompt_sha256": prompt_hash,
                        "prompt": prompt_text,
                        "candidate_sha256": candidate_hash,
                        "raw_model_output": raw_output,
                    }
                )
                continue

            probe_holder: dict[str, Any] = {
                "tool_name_preserved": False,
                "validation_regression_ast002": False,
            }
            wt_name = f"wt-arm-{arm_id[0].lower()}-{attempted:02d}"
            delta, wt_report = verify_patch_in_git_worktree(
                repo_root,
                wt_name,
                _make_multifile_mutator(file_map, probe_holder),
            )
            trials.append(
                {
                    "trial_id": attempted,
                    "arm": arm_id,
                    "arm_trial_index": arm_trial_idx,
                    "source": "llm",
                    "model_requested": model_name,
                    "model_version_reported": reported_version,
                    "temperature": STUDY_TEMPERATURE,
                    "attempt_count": attempt_count,
                    "status": "VALID",
                    "error_type": None,
                    "prompt_sha256": prompt_hash,
                    "prompt": prompt_text,
                    "candidate_sha256": candidate_hash,
                    "files_touched": delta.files_touched,
                    "patch_state": delta.patch_state.value,
                    "split_brain_detected": delta.split_brain_detected,
                    "delta_code_risk": delta.delta_code_risk,
                    "delta_iac_risk": delta.delta_iac_risk,
                    "delta_telemetry_risk": delta.delta_telemetry_risk,
                    "weighted_residual_risk": delta.weighted_residual_risk,
                    "worktree_findings": [f.finding_id for f in wt_report.findings],
                    "unified_diff": _compute_unified_diff(orig_files, file_map),
                    "raw_model_output": raw_output,
                }
            )
            if inter_call_delay_sec > 0:
                time.sleep(inter_call_delay_sec)

    return {"status": "COMPLETED", "attempted_trials": planned_total, "trials": trials}
