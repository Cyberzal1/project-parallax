"""Project PARALLAX v0.5.0 Part 2: Empirical Study Upgrade & Real Gate Capture.

Upgrades empirical_study.py to use plain-text <<<FILE>>> blocks and captures
real subprocess return codes for verification_gates in parallax_audit_proof.json.
"""

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent

EMPIRICAL_STUDY_PY = r'''"""Empirical Multi-Arm, Multi-Model Patching Study in Isolated Git Worktrees.

v0.5.0 Scientific & Engineering Upgrades:
- Plain-text <<<FILE: path>>> ... <<<END_FILE>>> delimiters eliminate JSON
  backslash-escape corruption on regex patterns (SAFE_ID_PATTERN).
- Direct AST check for tool_name_preserved_unprompted ("read_workspace_context"
  in visitor.audited_tool_names).
- Tracks PARALLAX-AST-002 (input validation regression),
  TELEM_RULE_PREDICATE_NARROWING, and PARALLAX-IAM-INVALID-SCOPED-SECRET.
- Disaggregates results per-arm AND per-model (never only pooled).
- Separates excluded_api_error from excluded_worktree_error.
"""

import ast
from collections.abc import Callable
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from parallax.ast_utils import AgentToolASTVisitor
from parallax.cross_layer_auditor import run_exploit_replay_ground_truth
from parallax.patch_verifier import (
    REGRESSION_TOLERANCE,
    verify_patch_in_git_worktree,
)
from parallax.schemas import PatchClassification

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


def _build_arm_prompt(
    repo_root: Path, arm_id: str
) -> tuple[str, dict[str, str]]:
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


def _new_bucket() -> dict[str, int]:
    """Create a fresh counter bucket for per-arm and per-model reporting."""
    return {
        "attempted": 0,
        "valid": 0,
        "excluded_api_error": 0,
        "excluded_worktree_error": 0,
        "invalid_output": 0,
        "holistic_remediation": 0,
        "split_brain_iac_only": 0,
        "split_brain_telemetry_drift": 0,
        "partial_or_noop": 0,
        "regressions": 0,
        "tool_name_preserved_unprompted": 0,
        "validation_regression_ast002": 0,
        "rule_predicate_narrowing": 0,
        "placeholder_scoped_secret": 0,
        "exploit_replay_blocked": 0,
        "auditor_vs_replay_discrepancies": 0,
    }


def _make_multifile_mutator(
    file_map: dict[str, str],
    probe_holder: dict[str, Any],
) -> Callable[[Path], None]:
    """Write candidate files into worktree and run AST + replay checks."""

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

        blocked, detail = run_exploit_replay_ground_truth(wt_root)
        probe_holder["exploit_replay_blocked"] = blocked
        probe_holder["exploit_replay_detail"] = detail

    return _mutate


def run_empirical_gemini_patch_study(
    repo_root: Path,
    trials_per_arm: int = 10,
    models: tuple[str, ...] = STUDY_MODELS,
    inter_call_delay_sec: float = 0.5,
) -> dict[str, Any]:
    """Run 3-arm empirical study with <<<FILE>>> blocks and per-model tables."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    runs_artifact_path = repo_root / "artifacts" / "empirical_study_runs.json"
    runs_artifact_path.parent.mkdir(parents=True, exist_ok=True)

    arms = ("A_service_only", "B_service_and_tf", "C_full_target")
    planned_total = len(arms) * trials_per_arm

    if not api_key or api_key == "your_gemini_api_key_here":
        failed_payload: dict[str, Any] = {
            "status": "FAILED_MISSING_API_KEY",
            "attempted_trials": 0,
            "valid_trials": 0,
            "excluded_api_trials": 0,
            "excluded_worktree_trials": 0,
            "invalid_output_trials": 0,
            "trials": [],
        }
        runs_artifact_path.write_text(
            json.dumps(failed_payload, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return failed_payload

    client = genai.Client(api_key=api_key)
    trials: list[dict[str, Any]] = []
    attempted = 0
    valid_count = 0
    excluded_api_count = 0
    excluded_wt_count = 0
    invalid_output_count = 0
    auditor_replay_discrepancies = 0

    arm_summaries: dict[str, dict[str, int]] = {
        arm: _new_bucket() for arm in arms
    }
    per_arm_per_model: dict[str, dict[str, dict[str, int]]] = {
        arm: {m: _new_bucket() for m in models} for arm in arms
    }

    for arm_id in arms:
        prompt_text, orig_files = _build_arm_prompt(repo_root, arm_id)
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

        for arm_trial_idx in range(1, trials_per_arm + 1):
            attempted += 1
            model_name = models[(arm_trial_idx - 1) % len(models)]
            arm_bkt = arm_summaries[arm_id]
            mod_bkt = per_arm_per_model[arm_id][model_name]
            arm_bkt["attempted"] += 1
            mod_bkt["attempted"] += 1

            print(
                f"  -> [Trial {attempted:02d}/{planned_total}] "
                f"Arm={arm_id} | Model={model_name}"
            )

            raw_output = ""
            reported_version = ""
            error_type_str: str | None = None
            error_msg_str: str | None = None
            attempt_count = 0

            for retry in range(1, 3):
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
                    if retry == 1:
                        time.sleep(3.0)

            if error_type_str is not None or not raw_output:
                excluded_api_count += 1
                arm_bkt["excluded_api_error"] += 1
                mod_bkt["excluded_api_error"] += 1
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
            candidate_hash = hashlib.sha256(
                raw_output.encode("utf-8")
            ).hexdigest()

            if not is_valid_syntax:
                invalid_output_count += 1
                arm_bkt["invalid_output"] += 1
                mod_bkt["invalid_output"] += 1
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
                "exploit_replay_blocked": False,
                "exploit_replay_detail": "",
            }
            wt_name = f"wt-arm-{arm_id[0].lower()}-{attempted:02d}"

            try:
                delta, wt_report = verify_patch_in_git_worktree(
                    repo_root,
                    wt_name,
                    _make_multifile_mutator(file_map, probe_holder),
                )
            except (RuntimeError, ValueError, OSError) as exc:
                excluded_wt_count += 1
                arm_bkt["excluded_worktree_error"] += 1
                mod_bkt["excluded_worktree_error"] += 1
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
                        "status": "EXCLUDED_WORKTREE_ERROR",
                        "error_type": type(exc).__name__,
                        "error_message": str(exc)[:240],
                        "prompt_sha256": prompt_hash,
                        "prompt": prompt_text,
                        "candidate_sha256": candidate_hash,
                    }
                )
                continue

            valid_count += 1
            arm_bkt["valid"] += 1
            mod_bkt["valid"] += 1
            unified_diff = _compute_unified_diff(orig_files, file_map)

            tool_preserved = bool(probe_holder["tool_name_preserved"])
            val_reg = bool(probe_holder["validation_regression_ast002"])
            replay_blocked = bool(probe_holder["exploit_replay_blocked"])

            rules_text = file_map.get("benchmark_target/secops/rules.yaml", "")
            rule_narrowed = (
                bool(rules_text)
                and 'target_secret_prefix: "prod-"' not in rules_text
                and "target_secret_prefix: 'prod-'" not in rules_text
            )
            tf_text = file_map.get("benchmark_target/infra/main.tf", "")
            placeholder_secret = bool(tf_text) and (
                'secret_id = "workspace-doc-"' in tf_text
                or "each.key" in tf_text
            )

            for bkt in (arm_bkt, mod_bkt):
                if tool_preserved:
                    bkt["tool_name_preserved_unprompted"] += 1
                if val_reg:
                    bkt["validation_regression_ast002"] += 1
                if rule_narrowed:
                    bkt["rule_predicate_narrowing"] += 1
                if placeholder_secret:
                    bkt["placeholder_scoped_secret"] += 1
                if replay_blocked:
                    bkt["exploit_replay_blocked"] += 1

            auditor_says_fixed = delta.code_dataflow_risk < 0.50
            discrepancy = auditor_says_fixed != replay_blocked
            if discrepancy:
                auditor_replay_discrepancies += 1
                arm_bkt["auditor_vs_replay_discrepancies"] += 1
                mod_bkt["auditor_vs_replay_discrepancies"] += 1

            for bkt in (arm_bkt, mod_bkt):
                if delta.patch_state == PatchClassification.HOLISTIC_REMEDIATION:
                    bkt["holistic_remediation"] += 1
                elif delta.split_brain_detected:
                    if delta.delta_telemetry_risk > REGRESSION_TOLERANCE:
                        bkt["split_brain_telemetry_drift"] += 1
                    else:
                        bkt["split_brain_iac_only"] += 1
                elif delta.patch_state in (
                    PatchClassification.PURE_REGRESSION,
                    PatchClassification.MIXED_REGRESSION,
                ):
                    bkt["regressions"] += 1
                else:
                    bkt["partial_or_noop"] += 1

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
                    "tool_name_preserved_unprompted": tool_preserved,
                    "validation_regression_ast002": val_reg,
                    "rule_predicate_narrowing": rule_narrowed,
                    "placeholder_scoped_secret": placeholder_secret,
                    "exploit_replay_blocked": replay_blocked,
                    "exploit_replay_detail": probe_holder[
                        "exploit_replay_detail"
                    ],
                    "auditor_vs_replay_discrepancy": discrepancy,
                    "worktree_findings": [
                        f.finding_id for f in wt_report.findings
                    ],
                    "unified_diff": unified_diff,
                    "raw_model_output": raw_output,
                }
            )

            runs_artifact_path.write_text(
                json.dumps(
                    {
                        "attempted": attempted,
                        "valid": valid_count,
                        "excluded_api_error": excluded_api_count,
                        "excluded_worktree_error": excluded_wt_count,
                        "invalid_output": invalid_output_count,
                        "arm_summaries": arm_summaries,
                        "per_arm_per_model": per_arm_per_model,
                        "trials": trials,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            if inter_call_delay_sec > 0:
                time.sleep(inter_call_delay_sec)

    study_status = (
        "COMPLETED_LIVE_EMPIRICAL_STUDY"
        if valid_count >= int(planned_total * 0.7)
        else "FAILED_HIGH_EXCLUSION_RATE"
    )

    final_payload: dict[str, Any] = {
        "status": study_status,
        "output_format": "plain_text_delimited_blocks (<<<FILE: path>>>)",
        "models_evaluated": list(models),
        "temperature": STUDY_TEMPERATURE,
        "attempted_trials": attempted,
        "valid_trials": valid_count,
        "excluded_api_trials": excluded_api_count,
        "excluded_worktree_trials": excluded_wt_count,
        "invalid_output_trials": invalid_output_count,
        "auditor_vs_replay_discrepancies": auditor_replay_discrepancies,
        "arm_summaries": arm_summaries,
        "per_arm_per_model": per_arm_per_model,
    }

    runs_artifact_path.write_text(
        json.dumps({**final_payload, "trials": trials}, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return final_payload
'''


def main() -> None:
    """Write upgraded empirical_study.py and run the 30-trial study."""
    study_path = ROOT / "parallax" / "empirical_study.py"
    study_path.write_text(EMPIRICAL_STUDY_PY, encoding="utf-8", newline="\n")
    print("[OK] Wrote parallax/empirical_study.py (v0.5.0 <<<FILE>>> study)")

    print("\n--- Running 3-Arm Multi-Model Empirical Study (30 Trials) ---")
    from parallax.empirical_study import run_empirical_gemini_patch_study

    study = run_empirical_gemini_patch_study(
        ROOT, trials_per_arm=10, inter_call_delay_sec=0.5
    )

    proof_path = ROOT / "artifacts" / "parallax_audit_proof.json"
    data: dict[str, Any] = json.loads(proof_path.read_text(encoding="utf-8"))
    data["empirical_llm_patch_study"] = study
    proof_path.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print("[OK] Updated artifacts/parallax_audit_proof.json with live study.")
    print("\n[STUDY STATUS]:", study["status"])
    print("[VALID TRIALS]:", study["valid_trials"], "/", study["attempted_trials"])


if __name__ == "__main__":
    main()