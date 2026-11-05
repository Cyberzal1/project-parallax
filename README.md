# Project PARALLAX (v0.8.0)

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
2. **The Infrastructure Silo (Terraform / IAM):** Over-permissive Non-Human Identity (NHI) Service Account bindings remain untouched (`SPLIT_BRAIN_REMEDIATION`), all access is revoked without a working replacement (`ACCESS_REVOKED_NO_REPLACEMENT`), or the model writes invalid Terraform (`INVALID_IAC_REMEDIATION`).
3. **The Telemetry Silo (Google SecOps):** The patch narrows or breaks detection rules in `rules.yaml`.

**Project PARALLAX** spins up isolated `git worktree` sandboxes, evaluates candidate patches before and after mutation across all three layers, and classifies patches into 9 states (including `UNVERIFIABLE` when runtime replay is rejected by the AST pre-screen, times out, or crashes).

### 1.1 Benchmark Target Architecture (`benchmark_target/`)

```text
+-----------------------------------------------------------------------------------+
|                        EXTERNAL UNTRUSTED CALLER (HTTPS)                          |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          | 1. Bearer Auth + Tool Payload:
                                          |    resource_id = "workspace-doc-quarterly-notes"
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
| - Declared Secret:                            |   | - Rule SECOPS_GCP_001 (HIGH, broad tool access)|
|   * workspace-doc-quarterly-notes             |   | - Rule SECOPS_GCP_002 (CRITICAL, prod-* canary)|
| - google_project_iam_member:                  |   | - Evaluated via pre-patch vs post-patch       |
|   * roles/secretmanager.secretAccessor [CRIT] |   |   malicious + benign event corpus replay.     |
|   * roles/iam.serviceAccountTokenCreator[HIGH]|   |                                               |
+-----------------------------------------------+   +-----------------------------------------------+
```

---

## 2. Multi-Arm, Multi-Model Empirical Study (v0.8.0 Re-Scored Results)

### 2.1 Methodology & Re-Scoring Disclosure

* **Re-Scoring Disclosure:** The tables below re-score the **same 30 model outputs** collected in v0.5.0 with **zero new API calls** (`21/30` valid responses; `8` HTTP 429 rate-limit exclusions and `1` HTTP 503 exclusion). During that run, the baseline `main.tf` did not yet declare `google_secret_manager_secret.workspace_doc_quarterly_notes` (added in v0.7.0+ so future runs have an expressible secret target).
* **JSON vs. Delimited Format Finding:** Under our earlier v0.4.0 JSON output prompt (`28` non-429 responses), `8/28` failed candidate gating (`5` on `flash`: `3` Python syntax errors + `2` JSON escape errors; `3` on `flash-lite`: JSON escape/control-character errors), and `flash-lite` dropped the trailing `$` anchor on `SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")` in `12/12` valid trials (keeping `\-` while removing `$`). Under plain-text `<<<FILE: path>>>` delimiters (with updated system instruction wording), format/syntax failures fell from `8/28` to **`0/21`**, and `flash-lite`'s dropped-`$` regression rate fell from `12/12` to **`0/12`**.

### 2.2 Disaggregated Per-Arm, Per-Model Results (CI-Verified via `parallax.readme_sync`)

| Context-Scope Arm | Model | Attempt / Valid / 429+503 / Invalid | Distinct Diffs (Total / Py) | Working Holistic Fix (95% Wilson CI) | Split-Brain (Untouched IaC) | Access Revoked (No Replacement) | Invalid IaC Edit | Rule Narrowed (Agg Blindspot) | `tool_name` Preserved | Validation Regression (`AST-002`) | 1 Control + 4 Probes Passed |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Arm A (`service.py` only)** | `gemini-2.5-flash` | `5 / 1 / 4+0 / 0` | `1` (`1` py) | `0/1` (`[0.00, 0.79]`) | `1/1` | `0/1` | `0/1` | `0/1` (`0` blind) | `1/1` | `0/1` | `1/1` |
| **Arm A (`service.py` only)** | `gemini-2.5-flash-lite` | `5 / 2 / 3+0 / 0` | `2` (`2` py) | `0/2` (`[0.00, 0.66]`) | `2/2` | `0/2` | `0/2` | `0/2` (`0` blind) | `2/2` | `0/2` | `2/2` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash` | `5 / 3 / 1+1 / 0` | `3` (`3` py) | `0/3` (`[0.00, 0.56]`) | `1/3` | `1/3` | `1/3` | `0/3` (`0` blind) | `3/3` | `0/3` | `3/3` |
| **Arm B (`service.py` + `main.tf`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0+0 / 0` | `5` (`1` py) | `0/5` (`[0.00, 0.43]`) | `0/5` | `4/5` | `1/5` | `0/5` (`0` blind) | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash` | `5 / 5 / 0+0 / 0` | `5` (`4` py) | `0/5` (`[0.00, 0.43]`) | `4/5` | `1/5` | `0/5` | `0/5` (`0` blind) | `5/5` | `0/5` | `5/5` |
| **Arm C (`service.py` + `main.tf` + `rules.yaml`)** | `gemini-2.5-flash-lite` | `5 / 5 / 0+0 / 0` | `5` (`2` py) | `0/5` (`[0.00, 0.43]`) | `1/5` | `0/5` | `4/5` | `0/5` (`0` blind) | `5/5` | `0/5` | `5/5` |

### 2.3 Per-Trial Audit of All 12 Trials That Edited `main.tf` (`v070_terraform_trial_audit`)

Across the 12 valid trials that modified `main.tf` in Arms B and C, **0/12 produced a working least-privilege replacement**:

| Trial | Arm | Model | `patch_state` | Post-Patch IaC Risk | Post-Patch Code Risk | Post-Patch Tel Risk | Deterministic Subagent Findings |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `Trial 12` | `B_service_and_tf` | `gemini-2.5-flash-lite` | **`INVALID_IAC_REMEDIATION`** | `0.90` | `0.05` | `0.05` | `PARALLAX-IAM-UNKNOWN-RESOURCE-GOOGLE_SECRET_IAM_MEMBER, PARALLAX-IAM-INVALID-SCOPED-SECRET-GOOGLE_SECRET_IAM_MEMBER` |
| `Trial 14` | `B_service_and_tf` | `gemini-2.5-flash-lite` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-COMMENTED-OUT-PLACEHOLDER, PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 15` | `B_service_and_tf` | `gemini-2.5-flash` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 16` | `B_service_and_tf` | `gemini-2.5-flash-lite` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 17` | `B_service_and_tf` | `gemini-2.5-flash` | **`INVALID_IAC_REMEDIATION`** | `0.75` | `0.05` | `0.05` | `PARALLAX-IAM-001` |
| `Trial 18` | `B_service_and_tf` | `gemini-2.5-flash-lite` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 20` | `B_service_and_tf` | `gemini-2.5-flash-lite` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 22` | `C_full_target` | `gemini-2.5-flash-lite` | **`INVALID_IAC_REMEDIATION`** | `0.65` | `0.05` | `0.05` | `PARALLAX-IAM-INVALID-SCOPED-SECRET-WORKSPACE_DOC_SECRETS_ACCESSOR` |
| `Trial 26` | `C_full_target` | `gemini-2.5-flash-lite` | **`INVALID_IAC_REMEDIATION`** | `0.90` | `0.05` | `0.05` | `PARALLAX-IAM-001, PARALLAX-IAM-UNKNOWN-RESOURCE-GOOGLE_SECRET_IAM_MEMBER` |
| `Trial 28` | `C_full_target` | `gemini-2.5-flash-lite` | **`INVALID_IAC_REMEDIATION`** | `0.90` | `0.05` | `0.05` | `PARALLAX-IAM-UNKNOWN-RESOURCE-GOOGLE_SECRET_IAM_MEMBER, PARALLAX-IAM-SA-TOKEN-CREATOR-SA_TOKEN_CREATOR` |
| `Trial 29` | `C_full_target` | `gemini-2.5-flash` | **`ACCESS_REVOKED_NO_REPLACEMENT`** | `0.60` | `0.05` | `0.05` | `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` |
| `Trial 30` | `C_full_target` | `gemini-2.5-flash-lite` | **`INVALID_IAC_REMEDIATION`** | `0.90` | `0.05` | `0.05` | `PARALLAX-IAM-001, PARALLAX-IAM-UNKNOWN-RESOURCE-GOOGLE_SECRET_IAM_MEMBER` |

* **Access Revoked, Nothing Added (`Trials 14, 15, 16, 18, 20, 29`):** All 6 removed or commented out the two `google_project_iam_member` blocks and added **zero live Terraform resources** (`Trials 15, 18` only commented out the bindings; `Trials 14, 16, 20` commented them out and added commented-out `# Replace with actual secret name` blocks; `Trial 29` deleted them). Because the Service Account is left with no Secret Manager access, Subagent 01's IaC positive control flags `PARALLAX-IAM-ACCESS-REVOKED-NO-REPLACEMENT` (`IaC Risk = 0.60`, state `ACCESS_REVOKED_NO_REPLACEMENT`).
* **Invalid Resource Type (`Trials 12, 26, 28, 30` — `flash-lite`):** Used `google_secret_iam_member` (not a valid `hashicorp/google` resource), scored `IaC Risk = 0.90` (`INVALID_IAC_REMEDIATION`).
* **Valid Resource Type, Undeclared Secret (`Trial 22` — `flash-lite`):** Used `google_secret_manager_secret_iam_member` on an undeclared secret (`IaC Risk = 0.65`, `INVALID_IAC_REMEDIATION`).
* **Left Project-Wide `secretAccessor` in Place (`Trial 17` — `flash`):** Removed `serviceAccountTokenCreator` but kept project-wide `roles/secretmanager.secretAccessor` (`IaC Risk = 0.75`, `INVALID_IAC_REMEDIATION`).
* **Per-Rule Narrowing vs. Aggregate Telemetry Coverage (`Trials 22, 26, 30`):** In Trials `22, 26, 30`, `flash-lite` narrowed `SECOPS_GCP_001` (the broad rule) by adding `target_secret_prefix: "workspace-doc-"`. Because `SECOPS_GCP_002` (`target_secret_prefix: "prod-"`) remained intact, aggregate corpus coverage for `prod-*` secret exfiltration did not drop (`0` aggregate blindspots; `telemetry_risk = 0.15`).

---

## 3. Threat Model, Categorical Scores & Limitations

1. **Synthetic Single-Target Scope & Effective Sample Size:** `benchmark_target/` is a synthetic testbed, and at `temperature=0.2`, `flash-lite`'s 4 `ACCESS_REVOKED_NO_REPLACEMENT` trials in Arm B (`14, 16, 18, 20`) share `1` distinct `service.py` diff.
2. **16-Case Seeded AST Benchmark & 5-Check Runtime Replay:** `evaluate_auditor_precision_recall()` reports `0.88` precision and `0.88` recall on 16 project-authored AST seeds (including 2 labeled static boundaries). Runtime replay catches what its 1 positive control + 4 exploit probes test; across the 21 valid study trials, static AST and runtime replay had `0` discrepancies.
3. **Reduced-Environment Subprocess Replay:** Replay runs in an external temp directory (`cwd=ext_tmp`, `5.0s` timeout, API keys stripped, AST pre-screen blocking `pathlib`, `logging`, `open`, `getattr`, and dunders), without OS container or network isolation.

---

## 4. Quickstart & Deterministic Verification

```powershell
# 1. Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# 2. Run the 4-part verification gate (Lint, Strict Typecheck, README Sync, Tests)
ruff check parallax benchmark_target tests      # -> All checks passed!
mypy parallax benchmark_target tests            # -> Success: no issues found in 17 source files
python -m parallax.readme_sync --check          # -> [OK] README.md is 100% in sync
pytest -q                                       # -> 35 passed, 1 xfailed

# 3. Run the interactive CLI Split-Brain simulation
python -m parallax.cli
```

* **Security Audit Summary (Computed):** `scanned_file_count=33`, `forbidden_files_found=0`, `secret_regex_matches_in_tree=0`, `bandit_s_rule_returncode=0`.

---

## 5. License

Released under the [MIT License](LICENSE).
