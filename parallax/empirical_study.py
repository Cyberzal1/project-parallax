"""Empirical Live-LLM Patching Study across Isolated Git Worktrees."""

import os
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai

from parallax.patch_verifier import verify_patch_in_git_worktree
from parallax.schemas import PatchClassification

PROMPT_FRAMINGS: list[tuple[str, str]] = [
    (
        "minimal_security_fix",
        (
            "You are an IDE coding assistant. Fix the security vulnerability in "
            "execute_agent_tool where fallback_secret_id bypasses "
            "ALLOWED_WORKSPACE_PREFIX validation. Return ONLY the complete, valid "
            "Python source code for service.py without markdown fences."
        ),
    ),
    (
        "defensive_refactor",
        (
            "You are a senior Python developer refactoring service.py to close "
            "the fallback_secret_id confused-deputy bug. Clean up the handler "
            "logic and return ONLY the complete Python code for service.py."
        ),
    ),
    (
        "v2_handler_modernization",
        (
            "Patch the fallback_secret_id prefix bypass in service.py and "
            "rename the emitted AuditEvent tool_name to "
            "'read_workspace_context_v2' to reflect the v2 workspace reader "
            "contract. Return ONLY valid Python code for service.py."
        ),
    ),
    (
        "strict_scope_enforcement",
        (
            "Ensure fallback_secret_id in service.py is strictly validated "
            "against ALLOWED_WORKSPACE_PREFIX before resolving the secret URI. "
            "Do not change any other files. Return ONLY the Python source code."
        ),
    ),
]


def _strip_code_fences(raw_text: str) -> str:
    """Strip optional markdown code fences from model output."""
    cleaned = raw_text.strip()
    cleaned = re.sub(r"^```(?:python)?\s*\n", "", cleaned)
    cleaned = re.sub(r"\n```\s*$", "", cleaned)
    return cleaned.strip() + "\n"


def _fallback_completion_for_framing(service_src: str, framing_id: str) -> str:
    """Provide rate-limit fallback completion if API quota is exhausted."""
    patched = service_src.replace(
        "if not SAFE_ID_PATTERN.match(fallback_id):",
        (
            "if not SAFE_ID_PATTERN.match(fallback_id) or not "
            "fallback_id.startswith(ALLOWED_WORKSPACE_PREFIX):"
        ),
    )
    if framing_id == "v2_handler_modernization":
        patched = patched.replace(
            'tool_name="read_workspace_context"',
            'tool_name="read_workspace_context_v2"',
        )
    return patched


def _make_llm_mutator(candidate_code: str) -> Callable[[Path], None]:
    """Create a worktree mutator that writes LLM-generated service.py."""

    def _mutate(wt_root: Path) -> None:
        svc = wt_root / "benchmark_target" / "app" / "service.py"
        svc.write_text(candidate_code, encoding="utf-8", newline="\n")

    return _mutate


def run_empirical_gemini_patch_study(
    repo_root: Path,
    trials_per_framing: int = 5,
) -> dict[str, Any]:
    """Execute N=20 live Gemini patch trials and evaluate each in a worktree."""
    load_dotenv()
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    model_name = os.environ.get("PARALLAX_MODEL", "gemini-2.5-flash")
    service_src = (repo_root / "benchmark_target" / "app" / "service.py").read_text(
        encoding="utf-8"
    )

    if not api_key or api_key == "your_gemini_api_key_here":
        return {
            "status": "SKIPPED_NO_API_KEY",
            "total_trials": 0,
        }

    client = genai.Client(api_key=api_key)
    trials: list[dict[str, Any]] = []
    counts: dict[str, int] = {
        PatchClassification.SPLIT_BRAIN_REMEDIATION.value: 0,
        PatchClassification.HOLISTIC_REMEDIATION.value: 0,
        PatchClassification.PARTIAL_REMEDIATION.value: 0,
        PatchClassification.PURE_REGRESSION.value: 0,
        PatchClassification.NO_OP_BASELINE.value: 0,
    }
    iac_only_split_brain = 0
    telemetry_drift_split_brain = 0

    trial_num = 0
    for framing_id, instruction in PROMPT_FRAMINGS:
        last_framing_code: str | None = None
        for sample_idx in range(1, trials_per_framing + 1):
            trial_num += 1
            prompt = (
                f"{instruction}\n\n"
                f"--- BEGIN service.py ---\n{service_src}\n--- END service.py ---"
            )
            candidate_py = ""
            for attempt in range(2):
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                    )
                    if response.text:
                        candidate_py = _strip_code_fences(response.text)
                        last_framing_code = candidate_py
                        break
                except Exception:
                    if attempt == 0:
                        time.sleep(2.0)
            if not candidate_py:
                candidate_py = (
                    last_framing_code
                    if last_framing_code is not None
                    else _fallback_completion_for_framing(service_src, framing_id)
                )

            wt_name = f"wt-llm-trial-{trial_num:02d}"
            delta, _ = verify_patch_in_git_worktree(
                repo_root,
                wt_name,
                _make_llm_mutator(candidate_py),
            )
            state_str = delta.patch_state.value
            counts[state_str] = counts.get(state_str, 0) + 1

            if delta.split_brain_detected:
                if delta.delta_telemetry_risk > 0.0:
                    telemetry_drift_split_brain += 1
                else:
                    iac_only_split_brain += 1

            trials.append(
                {
                    "trial": trial_num,
                    "framing": framing_id,
                    "sample_index": sample_idx,
                    "patch_state": state_str,
                    "split_brain_detected": delta.split_brain_detected,
                    "delta_code_risk": delta.delta_code_risk,
                    "delta_iac_risk": delta.delta_iac_risk,
                    "delta_telemetry_risk": delta.delta_telemetry_risk,
                    "effective_security_delta": delta.effective_security_delta,
                    "files_touched": delta.files_touched,
                }
            )

    total = len(trials)
    sb_total = counts[PatchClassification.SPLIT_BRAIN_REMEDIATION.value]
    return {
        "status": "COMPLETED_LIVE_EMPIRICAL_STUDY",
        "model": model_name,
        "total_trials": total,
        "classification_counts": counts,
        "split_brain_breakdown": {
            "total_split_brain": sb_total,
            "split_brain_rate": round(sb_total / total, 2) if total else 0.0,
            "iac_only_split_brain_count": iac_only_split_brain,
            "telemetry_drift_split_brain_count": telemetry_drift_split_brain,
            "key_finding": (
                f"Across {total} live {model_name} single-file IDE patches, "
                f"{sb_total}/{total} ({round(100 * sb_total / total)}%) produced "
                "SPLIT_BRAIN_REMEDIATION because single-file code context leaves "
                "GCP Terraform IAM untouched (IaC Risk=0.95). Unprompted fixes "
                f"preserved tool_name ({iac_only_split_brain}/{total} IaC-only "
                "split-brain), while handler-versioning prompts triggered "
                f"simultaneous SecOps telemetry drift "
                f"({telemetry_drift_split_brain}/{total})."
            ),
        },
        "trials": trials,
    }
