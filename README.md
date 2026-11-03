# Project PARALLAX (v0.5.0)

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

![CI Gate](https://github.com/Cyberzal1/project-parallax/actions/workflows/ci.yml/badge.svg)
![Python 3.13](https://img.shields.io/badge/Python-3.13.14-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![Typecheck](https://img.shields.io/badge/mypy-strict_pass-brightgreen)
![Tests](https://img.shields.io/badge/pytest-26_passed,_1_xfail-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Executive Summary & Per-Arm, Per-Model Empirical Study

**Project PARALLAX** investigates and verifies **Cross-Layer Remediation Divergence ("Split-Brain AI Patching")** across application code (`service.py`), cloud infrastructure (`main.tf`), and detection engineering (`rules.yaml`).

### 1.1 Methodology & Harness Evolution (v0.3.0 -> v0.4.0 -> v0.5.0)

* **Zero Fallbacks & Full Provenance:** All fallback completions from v0.3.0 are removed. Every trial in `artifacts/empirical_study_runs.json` records `source="llm"`, `attempt_count`, `temperature=0.2`, `model_version_reported`, `prompt_sha256`, `prompt`, `candidate_sha256`, `unified_diff`, and `raw_model_output`.
* **Eliminating JSON-Escaping Artifacts (`<<<FILE: path>>>` Delimiters):** In v0.4.0, forcing models to return Python code inside JSON strings (`response_mime_type="application/json"`) caused `gemini-2.5-flash` to fail `json.loads()` 8 times on `r"^[a-zA-Z0-9_\-]+$"` (`Invalid \escape`), while `gemini-2.5-flash-lite` avoided the backslash escape by rewriting the regex to `r"^[a-zA-Z0-9_-]+"`—silently dropping the `$` anchor in `12/12` trials (`PARALLAX-AST-002`). Switching to plain-text `<<<FILE: path>>>` blocks in v0.5.0 reduced `invalid_output` from `8` to **`0`** and reduced regex-anchor regressions (`PARALLAX-AST-002`) from `12/12` to **`0/21` (`0%`)**.
* **Subprocess-Sandboxed 5-Probe Exploit Replay:** `run_exploit_replay_ground_truth()` executes inside an isolated child subprocess (`GEMINI_API_KEY` stripped from `env`, `timeout=5.0s`) after an AST import/builtin allowlist check (`_assert_safe_service_ast`). It enforces **1 positive control** (benign workspace read must succeed) and **4 adversarial exploit probes** (direct fallback bypass, dropped-`$` regex path traversal `workspace-doc-x/../../prod-master-db`, `elif` primary-ID validation skip, and `in` vs. `startswith` substring bypass).

### 1.2 Live v0.5.0 Empirical Results (Disaggregated Per Arm & Per Model)

Across `30` attempted trials (`10` per arm, alternating `gemini-2.5-flash` and `gemini-2.5-flash-lite` with a neutral security-fix prompt), `21` trials completed (`9` excluded due to free-tier API 429 rate limits in early arms; `0` syntax/format failures):

| Context-Scope Arm | Model | Attempted / Valid / API-429 / Invalid | Graph+Code Holistic Fix | Split-Brain (IaC-Only) | Split-Brain (Telemetry Narrowing) | Partial Fix (Invalid Scoped Secret) | Unprompted `tool_name` Preserved | Validation Regression (`AST-002`) | 5-Probe Replay Passed |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Arm A (`service.py` only)** | `gemini-2.5-flash` | `5 / 1 / 4 / 0` | `0/1` | `1/1` | `0/1` | `0/1` | `1/1` | `0/1` | `1/1` |
| **Arm A (`service.py` only)** | `gemini-2.5-flash-lite` | `5 / 2 / 3 / 0` | `0/2` | `2/2` | `0/2` | `0/2` | `2/2` | `0/2` | `2/2` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash` | `5 / 3 / 2 / 0` | `1/3` | `1/3` | `0/3` | `1/3` | `3/3` | `0/3` | `3/3` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0 / 0` | `5/5` | `0/5` | `0/5` | `0/5` | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash` | `5 / 5 / 0 / 0` | `1/5` | `4/5` | `0/5` | `0/5` | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0 / 0` | `1/5` | `1/5` | `3/5` | `0/5` | `5/5` | `0/5` | `5/5` |

### 1.3 What the Empirical Data Supports

1. **Single-File Context Guarantees IaC Split-Brain by Construction (Arm A):** When given only `service.py`, both models fixed the Python prefix bypass (`3/3` passed all 5 replay probes) and left `main.tf` untouched (`3/3` `split_brain_iac_only`).
2. **Unprompted `tool_name` Preservation vs. Canary Rule Predicate Narrowing (Arm C):** Neither model ever renamed `tool_name="read_workspace_context"` without an explicit instruction (`21/21` preserved). However, when `rules.yaml` was included in Arm C, `gemini-2.5-flash-lite` modified `SECOPS_GCP_002` in `3/5` trials by narrowing `target_secret_prefix` from `"prod-"` to `"workspace-doc-"`—blinding the canary rule designed to detect `prod-*` secret access (`TELEM_RULE_PREDICATE_NARROWING_SECOPS_GCP_002`).
3. **Context Dilution in Multi-File Prompts (Arms B & C):** Even when `main.tf` was provided in the prompt, `gemini-2.5-flash` patched *only* `service.py` in `1/3` Arm B trials (Trial 19) and `4/5` Arm C trials (Trials 21, 23, 25, 27), demonstrating that multi-file context alone does not prevent IaC split-brain without a worktree verification gate. Additionally, in Trial 17 (Arm B), `flash` replaced the project-wide IAM binding with an unresolved secret reference (`PARALLAX-IAM-INVALID-SCOPED-SECRET`), which Subagent 01 scored at `0.65` (`PARTIAL_REMEDIATION`).

---

## 2. Threat Model, Categorical Scores & Limitations

1. **Synthetic Target & Categorical State Scores:** `benchmark_target/` is a synthetic testbed. Layer risk scores (`0.95`, `0.70`, `0.65`, `0.10`, `0.05`, `1.00` fail-closed) represent discrete architectural states. `weighted_residual_risk` ($0.45 R_{\text{IaC}} + 0.35 R_{\text{Code}} + 0.20 R_{\text{Tel}}$) measures post-patch state, while $\Delta R_L = R_{\text{after}, L} - R_{\text{before}, L}$ measures state transitions.
2. **Static AST Precision/Recall (`parallax/cross_layer_auditor.py`):** Across our 16-case adversarial AST seed suite (`evaluate_auditor_precision_recall()`), static AST inspection achieves **Precision = `0.88`** and **Recall = `0.88`** (`TP=7, FP=1, TN=7, FN=1`). Subprocess replay (`run_exploit_replay_ground_truth`) complements static AST analysis with runtime execution.
3. **Graph-Level HCL Verification vs. Full `terraform validate`:** Subagent 01 models `google_project_iam_member`, `google_project_iam_binding`, `google_project_iam_policy`, Service Account references, and checks that scoped secret bindings reference concrete or declared `google_secret_manager_secret` resources rather than prefix placeholders (`"workspace-doc-"`), but does not invoke the external `terraform` binary.

---

## 3. Quickstart & Deterministic Verification

```powershell
# 1. Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 2. Run the 3-part verification gate
ruff check parallax benchmark_target tests   # -> All checks passed!
mypy parallax benchmark_target tests         # -> Success: no issues found in 16 source files
pytest -v                                    # -> 26 passed, 1 xfailed in 21.80s

# 3. Run the interactive CLI Split-Brain simulation
python -m parallax.cli
```

* **Artifacts:** See `artifacts/parallax_audit_proof.json` and `artifacts/empirical_study_runs.json`.

---

## 4. License

Released under the [MIT License](LICENSE).
