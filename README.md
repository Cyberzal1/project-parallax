# Project PARALLAX (v0.6.0)

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

[![PARALLAX Verification Gate](https://github.com/Cyberzal1/project-parallax/actions/workflows/ci.yml/badge.svg)](https://github.com/Cyberzal1/project-parallax/actions/workflows/ci.yml)
![Python 3.13](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Project Overview & System Architecture

When a cloud vulnerability spans application code (`service.py`), cloud infrastructure (`main.tf`), and runtime detection (`rules.yaml`), automated fixes often operate in **silos**:
1. **The Code Silo (IDE/CLI Patching):** A coding agent patches a Python dataflow flaw so unit tests and SAST checks pass.
2. **The Infrastructure Silo (Terraform / IAM):** Over-permissive Non-Human Identity (NHI) Service Account bindings remain open in the GCP graph—or the model hallucinates invalid/placeholder Terraform resources.
3. **The Telemetry Silo (Google SecOps):** The patch narrows or drifts detection rule predicates in `rules.yaml`, silently blinding runtime alerts.

**Project PARALLAX** is a pre-merge verification engine that spins up isolated `git worktree` sandboxes, evaluates candidate patches before and after mutation across all three layers, and blocks **Cross-Layer Remediation Divergence ("Split-Brain Patching")**.

### 1.1 Benchmark Target Architecture (`benchmark_target/`)

```text
+-----------------------------------------------------------------------------------+
|                        EXTERNAL UNTRUSTED CALLER (HTTPS)                          |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | 1. Bearer Auth + Tool Payload:
                                          |    resource_id = "workspace-doc-notes"
                                          |    use_fallback = True
                                          |    fallback_secret_id = "prod-master-db"
                                          v
+-----------------------------------------------------------------------------------+
| GCP CLOUD RUN v2 SERVICE: "vertex-ops-agent" (ingress = INGRESS_TRAFFIC_ALL)      |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | APPLICATION LAYER: benchmark_target/app/service.py                        |   |
|   | - Enforces verify_caller_auth() upfront                                   |   |
|   | - Checks primary_id.startswith("workspace-doc-")                   [OK]   |   |
|   | - FLAW: Overwrites effective_secret_id = fallback_id without prefix [!]   |   |
|   +-------------------------------------+-------------------------------------+   |
|                                         |                                         |
|                                         | 2. Assumes Non-Human Identity (NHI)     |
|                                         v                                         |
|   +---------------------------------------------------------------------------+   |
|   | GCP SERVICE ACCOUNT: sa-agent-runner@gcp-sg-parallax-sandbox.iam...       |   |
|   +-------------------------------------+-------------------------------------+   |
+-----------------------------------------|-----------------------------------------+
                                          |
            +-----------------------------+-----------------------------+
            |                                                           |
            | 3a. Over-Permissive IAM Binding (main.tf)                 | 3b. Telemetry Emission
            v                                                           v
+-----------------------------------------------+   +-----------------------------------------------+
| GCP INFRASTRUCTURE LAYER (Terraform HCL2)     |   | GOOGLE SECOPS LAYER (secops/rules.yaml)       |
| - google_project_iam_member:                  |   | - Rule SECOPS_GCP_001 & SECOPS_GCP_002        |
|   * roles/secretmanager.secretAccessor [CRIT] |   | - Watches tool_name="read_workspace_context"  |
|   * roles/iam.serviceAccountTokenCreator[HIGH]|   |   and target_secret_prefix="prod-"            |
| - Allows reading ANY "prod-*" secret across   |   | - BLINDSPOT: Predicate narrowing or tool      |
|   the entire GCP project!                     |   |   rename silently blinds runtime alerts!      |
+-----------------------------------------------+   +-----------------------------------------------+
```

### 1.2 PARALLAX 4-Subagent Verification Engine (`parallax/`)

```text
+===================================================================================+
|                   MAIN THREAD ORCHESTRATOR (parallax/orchestrator.py)             |
+=========================================+=========================================+
                                          |
        +---------------------------------+---------------------------------+
        |                                 |                                 |
        v                                 v                                 v
+---------------+                 +---------------+                 +---------------+
|  Subagent 01  | ---IAM Context->|  Subagent 02  |                 |  Subagent 04  |
| Graph Analyzer|                 | AST + Replay  |                 |SecOps Vlidator|
| (NetworkX/HCL)|                 | Cross-Auditor |                 | (Corpus/YAML) |
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
+===================================================================================+
|          SUBAGENT 03: GIT WORKTREE PATCH VERIFIER (parallax/patch_verifier.py)    |
+===================================================================================+
```

---

## 2. Multi-Arm, Multi-Model Empirical Study (v0.6.0 Re-Scored Results)

### 2.1 Methodology & Harness Controls

* **Zero Fallbacks & Provenance:** Every trial in `artifacts/empirical_study_runs.json` records `source="llm"`, `attempt_count`, `temperature=0.2`, `model_version_reported`, `prompt_sha256`, `prompt`, `candidate_sha256`, `unified_diff`, and `raw_model_output`.
* **JSON vs. Delimited Format Finding:** Under our earlier v0.4.0 JSON output prompt (`response_mime_type="application/json"`), `gemini-2.5-flash-lite` dropped the trailing `$` anchor on `SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")` in `12/12` valid trials (keeping `\-` while removing `$`), and `8/30` trials failed JSON parsing (`5` on `flash`, `3` on `flash-lite`). Under v0.5.0/v0.6.0's plain-text `<<<FILE: path>>>` delimiter format (note: the system instruction wording also changed to specify delimiters), `flash-lite`'s dropped-`$` regression rate fell from `12/12` to **`0/12`**, and format/syntax failures fell from `8/30` to **`0/21`** (`9/30` trials were excluded due to free-tier API errors: `8` HTTP 429 rate-limit errors and `1` HTTP 503 error). The internal model mechanism behind the JSON `$` removal is not established.
* **Replay Integration & Reduced-Environment Subprocess:** `run_exploit_replay_ground_truth()` copies `service.py` into an external temp directory outside the repository (`cwd=ext_tmp`, `GEMINI_API_KEY` stripped, `timeout=5.0s`, AST pre-screened; no OS/network containment) so Windows never writes cache files into the worktree. It executes **1 positive control** (benign workspace read must succeed) + **4 exploit probes** (direct fallback bypass, dropped-`$` path traversal, `elif` primary-ID skip, and `in` vs. `startswith` bypass). `code_dataflow_risk` is computed as `max(static_risk, 1.0 if replay_failed)`.

### 2.2 Disaggregated Per-Arm, Per-Model Results (With Distinct Diffs & Wilson 95% CIs)

| Context-Scope Arm | Model | Attempt / Valid / 429+503 / Invalid | Distinct Diffs (Total / Py) | True Holistic Fix (95% Wilson CI) | Split-Brain (IaC-Only) | Split-Brain (Telemetry Narrowing) | Partial Fix | Unprompted `tool_name` Preserved | Validation Regression (`AST-002`) | 1 Control + 4 Probes Passed |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Arm A (`service.py` only)** | `gemini-2.5-flash` | `5 / 1 / 4+0 / 0` | `1` (`1` py) | `0/1` (`[0.00, 0.79]`) | `1/1` | `0/1` | `0/1` (`0` IaC err) | `1/1` | `0/1` | `1/1` |
| **Arm A (`service.py` only)** | `gemini-2.5-flash-lite` | `5 / 2 / 3+0 / 0` | `2` (`2` py) | `0/2` (`[0.00, 0.66]`) | `2/2` | `0/2` | `0/2` (`0` IaC err) | `2/2` | `0/2` | `2/2` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash` | `5 / 3 / 1+1 / 0` | `3` (`3` py) | `1/3` (`[0.06, 0.79]`) | `2/3` | `0/3` | `0/3` (`0` IaC err) | `3/3` | `0/3` | `3/3` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0+0 / 0` | `5` (`1` py) | `4/5` (`[0.38, 0.96]`) | `1/5` | `0/5` | `0/5` (`1` IaC err) | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash` | `5 / 5 / 0+0 / 0` | `5` (`4` py) | `1/5` (`[0.04, 0.62]`) | `4/5` | `0/5` | `0/5` (`0` IaC err) | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0+0 / 0` | `5` (`2` py) | `0/5` (`[0.00, 0.43]`) | `2/5` | `3/5` | `0/5` (`4` IaC err) | `5/5` | `0/5` | `5/5` |

### 2.3 Key Empirical Observations After v0.6.0 Terraform & Corpus Re-Scoring

1. **Audit of the 12 Trials That Edited `main.tf` (Arms B & C):**
   * **Hallucinated Provider Resource Type (`Trials 12, 26, 28, 30` — `flash-lite`):** Used `google_secret_iam_member` (not a valid `hashicorp/google` resource; real resource is `google_secret_manager_secret_iam_member`), with Trial 12 also embedding a placeholder secret comment (`workspace-doc-example-secret # Replace with actual secret name`) and Trial 28 also granting `roles/iam.serviceAccountTokenCreator` to the SA (`PARALLAX-IAM-SA-TOKEN-CREATOR`). Re-scoring flipped **Trial 12** (Arm B) and **Trial 28** (Arm C) from `HOLISTIC_REMEDIATION` to `SPLIT_BRAIN_REMEDIATION` (`IaC Risk = 0.90`).
   * **Undeclared Scoped Secret (`Trial 22` — `flash-lite` in Arm C):** Bound `google_secret_manager_secret_iam_member` to a secret without declaring a `google_secret_manager_secret` resource (`PARALLAX-IAM-INVALID-SCOPED-SECRET`, `IaC Risk = 0.65`) while also narrowing `SECOPS_GCP_001` in `rules.yaml`.
   * **Incomplete Project-Role Removal (`Trial 17` — `flash` in Arm B):** Removed `roles/iam.serviceAccountTokenCreator` from `main.tf` but left project-wide `roles/secretmanager.secretAccessor` intact (`PARALLAX-IAM-001`, `IaC Risk = 0.75`, classified as `SPLIT_BRAIN_REMEDIATION`).
   * **Valid Declared Secret + Scoped IAM (`Trials 14, 15, 16, 18, 20, 29` — `4 flash-lite` in Arm B [1 distinct diff repeated 4 times], `1 flash` in Arm B [Trial 15], `1 flash` in Arm C [Trial 29]):** Declared both a `google_secret_manager_secret` resource block and a matching `google_secret_manager_secret_iam_member` binding while removing project-wide roles (`IaC Risk = 0.10`, `HOLISTIC_REMEDIATION`).
2. **Single-File Edits When Multi-File Context Is Provided (`flash` in Arms B & C):** `gemini-2.5-flash` edited only `service.py` in `4/5` Arm C trials (`Trials 21, 23, 25, 27`) and `1/3` Arm B trials (`Trial 19`), leaving `main.tf` untouched (`split_brain_iac_only`).
3. **Before/After Corpus Replay Catches Rule Predicate Narrowing (`flash-lite` in Arm C):** Neither model ever renamed `tool_name` (`21/21` preserved). In `3/5` Arm C trials (`Trials 22, 24, 30`), `flash-lite` narrowed a detection rule in `rules.yaml` by adding `target_secret_prefix: "workspace-doc-"`, which Subagent 04's before/after event corpus replay flagged (`TELEM_RULE_PREDICATE_NARROWING`).

---

## 3. Threat Model, Categorical Scores & Limitations

1. **Synthetic Single-Target Scope & Gemini-Only Evaluation:** `benchmark_target/` is a single synthetic testbed modeling a GCP Cloud Run + Secret Manager + SecOps pattern, and the empirical study evaluates two Gemini models (`gemini-2.5-flash` and `gemini-2.5-flash-lite`) at `temperature=0.2` (where repeated trials often produce identical diffs, reducing effective sample size $n_{\text{eff}}$). Generalizing across bug classes requires additional benchmark targets (e.g., SSRF allowlist bypasses) and non-Gemini model families.
2. **Categorical State Scores:** Layer risk scores (`0.95`, `0.90`, `0.75`, `0.65`, `0.10`, `0.05`, `1.00` fail-closed) represent discrete architectural states rather than continuous probabilities.
3. **16-Case Seeded AST Benchmark Scope:** The `0.88` precision and `0.88` recall reported by `evaluate_auditor_precision_recall()` (`TP=7, FP=1, TN=7, FN=1`) come from 16 project-authored AST seeds, two of which are intentionally labeled static AST boundaries (Case 13 `re.match` false positive; Case 14 tuple-unpacking false negative). Runtime replay (`enforce_replay_in_score=True`) closes static false negatives on the benchmark target by forcing `code_risk = 1.0` whenever any of the 1 positive control + 4 exploit probes fails.
4. **Reduced-Environment Subprocess Replay:** Replay runs in a separate Python process with an external temp directory as `cwd`, a 5-second timeout, stripped API keys, and an AST pre-screen, but does not enforce OS container or network isolation.

---

## 4. Quickstart & Deterministic Verification

```powershell
# 1. Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 2. Run the 3-part verification gate
ruff check parallax benchmark_target tests   # -> All checks passed!
mypy parallax benchmark_target tests         # -> Success: no issues found in 16 source files
pytest -v                                    # -> 28 passed, 1 xfailed in 25.99s

# 3. Run the interactive CLI Split-Brain simulation
python -m parallax.cli
```

* **Artifacts:** See `artifacts/parallax_audit_proof.json` and `artifacts/empirical_study_runs.json`.

---

## 5. License

Released under the [MIT License](LICENSE).
