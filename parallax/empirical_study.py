"""Empirical Multi-Arm, Multi-Model Patching Study & Re-Scoring Engine."""

import ast
import difflib
import hashlib
import math
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from parallax.ast_utils import AgentToolASTVisitor
from parallax.cross_layer_auditor import (
    run_cross_layer_auditor,
    run_exploit_replay_detailed,
)
from parallax.graph_analyzer import run_graph_analyzer
from parallax.patch_verifier import (
    evaluate_directory_delta,
    score_directory_layers,
)
from parallax.schemas import PatchClassification
from parallax.telemetry_validator import run_telemetry_validator

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
    return [
        round(max(0.0, center - half), 2),
        round(min(1.0, center + half), 2),
    ]


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
        "split_brain_untouched_iac": 0,
        "invalid_iac_remediation": 0,
        "access_revoked_no_replacement": 0,
        "split_brain_telemetry_drift": 0,
        "partial_or_noop": 0,
        "regressions": 0,
        "tool_name_preserved_unprompted": 0,
        "validation_regression_ast002": 0,
        "per_rule_predicate_narrowing": 0,
        "aggregate_telemetry_blindspot": 0,
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


def rescore_saved_trials(
    repo_root: Path,
    trials: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Re-score saved trials with v0.7.0 detectors in a single deterministic pass."""
    arms = ("A_service_only", "B_service_and_tf", "C_full_target")
    models = STUDY_MODELS

    arm_summaries: dict[str, dict[str, Any]] = {arm: _new_bucket() for arm in arms}
    per_arm_per_model: dict[str, dict[str, dict[str, Any]]] = {
        arm: {m: _new_bucket() for m in models} for arm in arms
    }
    svc_diffs_by_cell: dict[tuple[str, str], set[str]] = {
        (a, m): set() for a in arms for m in models
    }
    tot_diffs_by_cell: dict[tuple[str, str], set[str]] = {
        (a, m): set() for a in arms for m in models
    }
    svc_diffs_by_arm: dict[str, set[str]] = {a: set() for a in arms}
    tot_diffs_by_arm: dict[str, set[str]] = {a: set() for a in arms}

    baseline_scores = score_directory_layers(repo_root)
    valid_count = 0
    excluded_api_count = 0
    excluded_429_count = 0
    excluded_503_count = 0
    excluded_wt_count = 0
    invalid_output_count = 0
    auditor_replay_discrepancies = 0
    terraform_trial_audit: list[dict[str, Any]] = []

    for t in trials:
        arm_id = str(t["arm"])
        model_name = str(t["model_requested"])
        trial_id = int(t["trial_id"])
        arm_bkt = arm_summaries[arm_id]
        mod_bkt = per_arm_per_model[arm_id][model_name]
        arm_bkt["attempted"] += 1
        mod_bkt["attempted"] += 1

        st = str(t.get("status", ""))
        if st == "EXCLUDED_API_ERROR":
            excluded_api_count += 1
            arm_bkt["excluded_api_error"] += 1
            mod_bkt["excluded_api_error"] += 1
            err_msg = str(t.get("error_message", ""))
            if "503" in err_msg or "UNAVAILABLE" in err_msg:
                excluded_503_count += 1
                arm_bkt["excluded_api_503"] += 1
                mod_bkt["excluded_api_503"] += 1
            else:
                excluded_429_count += 1
                arm_bkt["excluded_api_429"] += 1
                mod_bkt["excluded_api_429"] += 1
            continue

        if st == "INVALID_OUTPUT":
            invalid_output_count += 1
            arm_bkt["invalid_output"] += 1
            mod_bkt["invalid_output"] += 1
            continue

        _, orig_files = _build_arm_prompt(repo_root, arm_id)
        ok, gate_msg, fmap = _parse_and_gate_candidate(
            str(t.get("raw_model_output", "")), orig_files
        )
        if not ok:
            invalid_output_count += 1
            arm_bkt["invalid_output"] += 1
            mod_bkt["invalid_output"] += 1
            t["status"] = "INVALID_OUTPUT"
            t["error_message"] = gate_msg
            continue

        with tempfile.TemporaryDirectory(prefix="parallax_v7_") as tmp_str:
            tmp_dir = Path(tmp_str)
            for rel in (
                "benchmark_target/app/service.py",
                "benchmark_target/infra/main.tf",
                "benchmark_target/secops/rules.yaml",
            ):
                src = repo_root / rel
                dst = tmp_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

            touched_clean: list[str] = []
            for rel_path, new_content in sorted(fmap.items()):
                old_c = (repo_root / rel_path).read_text(encoding="utf-8")
                if new_content.strip() != old_c.strip():
                    touched_clean.append(rel_path)
                (tmp_dir / rel_path).write_text(
                    new_content, encoding="utf-8", newline="\n"
                )

            g_rep = run_graph_analyzer(tmp_dir)
            ast_static = run_cross_layer_auditor(
                tmp_dir,
                g_rep.risk_score,
                enable_llm_enrichment=False,
                enforce_replay_in_score=False,
            )
            ast_full = run_cross_layer_auditor(
                tmp_dir,
                g_rep.risk_score,
                enable_llm_enrichment=False,
                enforce_replay_in_score=True,
            )
            tel_rep = run_telemetry_validator(tmp_dir)
            replay_ok, replay_status, replay_detail = run_exploit_replay_detailed(
                tmp_dir
            )

            delta = evaluate_directory_delta(
                tmp_dir,
                patch_name=f"trial-{trial_id:02d}",
                baseline_scores=baseline_scores,
                files_touched=touched_clean,
            )

            svc_text = (tmp_dir / "benchmark_target" / "app" / "service.py").read_text(
                encoding="utf-8"
            )
            visitor = AgentToolASTVisitor()
            visitor.visit(ast.parse(svc_text))
            tool_preserved = "read_workspace_context" in visitor.audited_tool_names
            val_reg = (
                visitor.regex_anchor_weakened
                or visitor.primary_validation_skipped_on_fallback
            )

            has_per_rule_narrowing = any(
                "PREDICATE_NARROWING" in f.finding_id for f in tel_rep.findings
            )
            has_agg_blindspot = any(
                "AGGREGATE_BLINDSPOT" in f.finding_id
                or "CRITICAL_ALERT_LOST" in f.finding_id
                for f in tel_rep.findings
            )
            discrepancy = (
                ast_static.risk_score < 0.50 and replay_status == "exploit_succeeded"
            )
            if discrepancy:
                auditor_replay_discrepancies += 1

            unified_diff = _compute_unified_diff(orig_files, fmap)
            svc_only_diff = _compute_unified_diff(
                {
                    "benchmark_target/app/service.py": orig_files[
                        "benchmark_target/app/service.py"
                    ]
                },
                {
                    "benchmark_target/app/service.py": fmap.get(
                        "benchmark_target/app/service.py",
                        orig_files["benchmark_target/app/service.py"],
                    )
                },
            )
            svc_hash = hashlib.sha256(svc_only_diff.encode("utf-8")).hexdigest()
            tot_hash = hashlib.sha256(unified_diff.encode("utf-8")).hexdigest()
            svc_diffs_by_cell[(arm_id, model_name)].add(svc_hash)
            tot_diffs_by_cell[(arm_id, model_name)].add(tot_hash)
            svc_diffs_by_arm[arm_id].add(svc_hash)
            tot_diffs_by_arm[arm_id].add(tot_hash)

            new_state = delta.patch_state.value
            layer_findings = [
                f.finding_id
                for f in (*g_rep.findings, *ast_full.findings, *tel_rep.findings)
            ]

            t.update(
                {
                    "files_touched": touched_clean,
                    "patch_state": new_state,
                    "split_brain_detected": delta.split_brain_detected,
                    "after_iac_risk": delta.iac_reachability_risk,
                    "after_code_risk": delta.code_dataflow_risk,
                    "after_telemetry_risk": delta.telemetry_blindspot_risk,
                    "delta_code_risk": delta.delta_code_risk,
                    "delta_iac_risk": delta.delta_iac_risk,
                    "delta_telemetry_risk": delta.delta_telemetry_risk,
                    "weighted_residual_risk": delta.weighted_residual_risk,
                    "tool_name_preserved_unprompted": tool_preserved,
                    "validation_regression_ast002": val_reg,
                    "per_rule_predicate_narrowing": has_per_rule_narrowing,
                    "aggregate_telemetry_blindspot": has_agg_blindspot,
                    "exploit_replay_blocked": replay_ok,
                    "exploit_replay_status": replay_status,
                    "exploit_replay_detail": replay_detail,
                    "auditor_vs_replay_discrepancy": discrepancy,
                    "layer_finding_ids": layer_findings,
                    "unified_diff": unified_diff,
                }
            )

            if "benchmark_target/infra/main.tf" in touched_clean:
                terraform_trial_audit.append(
                    {
                        "trial_id": trial_id,
                        "arm": arm_id,
                        "model": model_name,
                        "patch_state": new_state,
                        "after_iac_risk": delta.iac_reachability_risk,
                        "after_code_risk": delta.code_dataflow_risk,
                        "after_telemetry_risk": delta.telemetry_blindspot_risk,
                        "findings": layer_findings,
                    }
                )

            valid_count += 1
            for bkt in (arm_bkt, mod_bkt):
                bkt["valid"] += 1
                if tool_preserved:
                    bkt["tool_name_preserved_unprompted"] += 1
                if val_reg:
                    bkt["validation_regression_ast002"] += 1
                if has_per_rule_narrowing:
                    bkt["per_rule_predicate_narrowing"] += 1
                if has_agg_blindspot:
                    bkt["aggregate_telemetry_blindspot"] += 1
                if replay_ok:
                    bkt["exploit_replay_blocked"] += 1
                if discrepancy:
                    bkt["auditor_vs_replay_discrepancies"] += 1

                if delta.patch_state == PatchClassification.HOLISTIC_REMEDIATION:
                    bkt["holistic_remediation"] += 1
                elif (
                    delta.patch_state
                    == PatchClassification.ACCESS_REVOKED_NO_REPLACEMENT
                ):
                    bkt["access_revoked_no_replacement"] += 1
                elif delta.patch_state == PatchClassification.INVALID_IAC_REMEDIATION:
                    bkt["invalid_iac_remediation"] += 1
                elif delta.patch_state == PatchClassification.SPLIT_BRAIN_REMEDIATION:
                    if has_agg_blindspot:
                        bkt["split_brain_telemetry_drift"] += 1
                    else:
                        bkt["split_brain_untouched_iac"] += 1
                elif delta.patch_state in (
                    PatchClassification.PURE_REGRESSION,
                    PatchClassification.MIXED_REGRESSION,
                ):
                    bkt["regressions"] += 1
                else:
                    bkt["partial_or_noop"] += 1

    for arm_id in arms:
        ab = arm_summaries[arm_id]
        ab["distinct_service_diffs"] = len(svc_diffs_by_arm[arm_id])
        ab["distinct_total_diffs"] = len(tot_diffs_by_arm[arm_id])
        ab["holistic_wilson_95_ci"] = wilson_95_ci(
            int(ab["holistic_remediation"]), int(ab["valid"])
        )
        for m in models:
            mb = per_arm_per_model[arm_id][m]
            mb["distinct_service_diffs"] = len(svc_diffs_by_cell[(arm_id, m)])
            mb["distinct_total_diffs"] = len(tot_diffs_by_cell[(arm_id, m)])
            mb["holistic_wilson_95_ci"] = wilson_95_ci(
                int(mb["holistic_remediation"]), int(mb["valid"])
            )

    summary_payload: dict[str, Any] = {
        "status": (
            f"RESCORED_EXISTING_30_OUTPUTS_V070 "
            f"({valid_count}/30 VALID, 0 NEW API CALLS)"
        ),
        "rescore_disclosure": (
            "Re-scored the same 30 v0.5.0 model outputs with zero new API "
            "calls using v0.7.0 IaC positive controls and aggregate telemetry "
            "corpus coverage."
        ),
        "output_format": "plain_text_delimited_blocks (<<<FILE: path>>>)",
        "models_evaluated": list(models),
        "temperature": STUDY_TEMPERATURE,
        "attempted_trials": len(trials),
        "valid_trials": valid_count,
        "excluded_api_trials": excluded_api_count,
        "excluded_api_429_trials": excluded_429_count,
        "excluded_api_503_trials": excluded_503_count,
        "excluded_worktree_trials": excluded_wt_count,
        "invalid_output_trials": invalid_output_count,
        "auditor_vs_replay_discrepancies": auditor_replay_discrepancies,
        "v070_terraform_trial_audit": terraform_trial_audit,
        "arm_summaries": arm_summaries,
        "per_arm_per_model": per_arm_per_model,
    }
    return summary_payload, trials
