# Project PARALLAX (v0.2.0)

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

![CI Gate](https://github.com/Cyberzal1/project-parallax/actions/workflows/ci.yml/badge.svg)
![Python 3.13](https://img.shields.io/badge/Python-3.13.14-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Reasoning-Gemini_2.5_Flash-8E75B2?logo=googlegemini&logoColor=white)
![Typecheck](https://img.shields.io/badge/mypy-strict_100%25_pass-brightgreen)
![Tests](https://img.shields.io/badge/pytest-15_passed,_1_xfail-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Executive Summary & Testable Architectural Hypothesis

Modern security teams are adopting autonomous AI defense platforms—combining cloud exposure mapping (**Wiz**), frontier model code analysis (**Gemini**), automated IDE/CLI code patching (**CodeMender**), and machine-speed runtime detection (**Google Security Operations**).

**Project PARALLAX** formulates and tests a critical architectural hypothesis across those boundaries: **Cross-Layer Remediation Divergence ("Split-Brain AI Patching")**.

When a vulnerability spans application code, cloud infrastructure, and detection engineering, automated fixes often operate in **silos**:
1. **The Code Silo (IDE/CLI Autofix):** An AI coding assistant rapidly patches a Python dataflow bug in the developer's IDE so unit tests and SAST scanners turn green ($\Delta R_{\text{Code}} = -0.90$).
2. **The Cloud Infrastructure Silo (Terraform / IAM):** Because the IDE patch does not modify the Terraform repository, over-permissive Non-Human Identity (NHI) Service Account bindings remain wide open in the GCP graph ($R_{\text{IaC}} = 0.95, \Delta R_{\text{IaC}} = 0.00$).
3. **The Runtime Telemetry Silo (Google SecOps):** Minor refactoring inside the AI code patch (such as renaming `read_workspace_context` to `read_workspace_context_v2`) silently breaks downstream detection rules ($\Delta R_{\text{Telemetry}} = +0.80$).

### At-a-Glance Empirical Results (Before vs. After Worktree Differential)

| Worktree Simulation | Files Touched (`git status`) | Code AST Risk ($R_{\text{Code}}$ / $\Delta$) | GCP IaC Risk ($R_{\text{IaC}}$ / $\Delta$) | SecOps Telemetry Risk ($R_{\text{Tel}}$ / $\Delta$) | Effective Delta ($\Delta S$) | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`baseline-unpatched`** | *Baseline HEAD* | `0.95` (`+0.00`) | `0.95` (`+0.00`) | `0.05` (`+0.00`) | **`0.77`** | `NO_OP_BASELINE` |
| **`wt-symptom-patch`** *(Fast IDE Code Fix)* | `service.py` | `0.05` (**`-0.90`**) | `0.95` (`+0.00`) | `0.85` (**`+0.80`**) | **`0.61`** | **`SPLIT_BRAIN_REMEDIATION` [!]** |
| **`wt-architectural-patch`** *(Holistic Fix)* | `service.py`, `main.tf` | `0.05` (**`-0.90`**) | `0.10` (**`-0.85`**) | `0.05` (`+0.00`) | **`0.07`** | **`HOLISTIC_REMEDIATION` [OK]** |

*Note on Synthetic Benchmark Target:* `benchmark_target/` is a synthetic, deterministic testbed engineered to make cross-layer split-brain remediation reproducible and measurable in local Git worktrees and CI pipelines.

---

## 2. The 4-Step Defense vs. Adversarial Counter-Framework

| Google AI Threat Defense Pillar | Adversarial Counter-Step (Attacker Model) | Project PARALLAX Subagent | Technical Verification Mechanism |
| :--- | :--- | :--- | :--- |
| **01 Prepare** (Harden foundation & build live exposure maps via Wiz) | **01 Infiltrate the Trusted Graph** (Abuse Non-Human Identities & transitive IAM paths) | `Subagent 01: Graph Analyzer` (`parallax/graph_analyzer.py`) | Parses GCP Terraform (`hcl2`) into a `networkx.DiGraph` to trace public Cloud Run ingress to project-wide IAM blast radius. |
| **02 Scan** (Multi-AI Gemini code analysis + Wiz runtime context) | **02 Chain Cross-Context Logic Flaws** (Exploit seams between app AST and cloud IAM) | `Subagent 02: Cross-Layer Auditor` (`parallax/cross_layer_auditor.py`) | Performs independent Python `ast` dataflow analysis (100% precision/recall on seeded benchmark cases) with optional **Gemini 2.5** root-cause enrichment. |
| **03 Remediate** (Shrink fixes from weeks to minutes via CodeMender) | **03 Exploit the Supervision & Patch Gap** (Weaponize symptom-only AI code patches) | `Subagent 03: Worktree Patch Verifier` (`parallax/patch_verifier.py`) | Spins up path-validated `git worktree` sandboxes, scores before/after deltas ($\Delta R$), tracks modified files via `git status --porcelain`, and classifies patches into 5 states. |
| **04 Monitor** (Machine-speed runtime hunting via Google SecOps) | **04 Blend into Agentic Telemetry** (Evade alerts via schema & tool-signature drift) | `Subagent 04: Telemetry Validator` (`parallax/telemetry_validator.py`) | Enforces fail-closed parsing, bidirectional `tool_name` coverage, `AuditEvent` field-level drift checks, dynamic AST uncertainty reporting, and synthetic event replay. |

---

## 3. System & Target Architecture

### 3.1 Benchmark Target: GCP Cloud Run AI Agent (`benchmark_target/`)

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
|   * roles/iam.serviceAccountTokenCreator[HIGH]|   | - BLINDSPOT: If an IDE patch renames          |
| - Allows reading ANY "prod-*" secret across   |   |   tool_name to "..._v2", alerts likely fail!  |
|   the entire GCP project!                     |   |                                               |
+-----------------------------------------------+   +-----------------------------------------------+
```

### 3.2 Project PARALLAX Orchestrator & Dual Git Worktree Engine (`parallax/`)

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
| Graph Analyzer|   (Annotation)  | AST + Gemini  |                 |SecOps Vlidator|
| (NetworkX/HCL)|                 | Cross-Auditor |                 | (Replay/YAML) |
+-------+-------+                 +-------+-------+                 +-------+-------+
        |                                 |                                 |
        +---------------------------------+---------------------------------+
                                          |
                                          v
+===================================================================================+
|          SUBAGENT 03: GIT WORKTREE PATCH VERIFIER (parallax/patch_verifier.py)    |
+=========================================+=========================================+
                                          |
              +---------------------------+---------------------------+
              |                                                       |
              | git worktree add --detach (Before/After Delta)        | git worktree add --detach
              v                                                       v
+-------------------------------------------+   +-------------------------------------------+
| Worktree A: .worktrees/wt-symptom-patch   |   | Worktree B: .worktrees/wt-architectural   |
| (Simulates Fast IDE / AI Code Fix)        |   | (Simulates Cloud Architect Holistic Fix)  |
|-------------------------------------------|   |-------------------------------------------|
| - Fixes Python prefix check (d_code=-0.90)|   | - Fixes Python prefix check (d_code=-0.90)|
| - Leaves Project IAM open   (d_iac =+0.00)|   | - Scopes Secret IAM in .tf  (d_iac =-0.85)|
| - Drifts tool_name_v2       (d_tel =+0.80)|   | - Preserves SecOps contract (d_tel =+0.00)|
|                                           |   |                                           |
| => Effective Security Delta : 0.61        |   | => Effective Security Delta : 0.07        |
| => STATE: SPLIT_BRAIN_REMEDIATION [!]     |   | => STATE: HOLISTIC_REMEDIATION    [OK]    |
+-------------------------------------------+   +-------------------------------------------+
```

---

## 4. Mathematical Model: True Differential & Layer Independence

Each architectural layer is scored independently on $[0.0, 1.0]$ so IAM risk is never double-counted inside Code AST risk. When verifying a candidate patch in an isolated Git worktree, PARALLAX scores the worktree **before** ($R_{\text{before}}$) and **after** ($R_{\text{after}}$) applying the patch mutator:

$$\Delta R_L = R_{\text{after}, L} - R_{\text{before}, L} \quad \text{for } L \in \{\text{IaC}, \text{Code}, \text{Telemetry}\}$$

$$\Delta S_{\text{effective}} = 0.45 \cdot R_{\text{after, IaC}} + 0.35 \cdot R_{\text{after, Code}} + 0.20 \cdot R_{\text{after, Telemetry}}$$

* **Weight Rationale (`0.45 / 0.35 / 0.20`):** Cloud IAM blast radius (`0.45`) governs the maximum architectural damage if any container or dependency is compromised; application dataflow (`0.35`) controls direct request-level exploitability; runtime telemetry (`0.20`) determines whether post-exploitation is detectable by SecOps.
* **Differential Split-Brain Condition:**
  $$\text{SplitBrain} \iff (\Delta R_{\text{Code}} \le -0.30 \land R_{\text{after, Code}} < 0.50) \land \left[(R_{\text{after, IaC}} \ge 0.70 \land \Delta R_{\text{IaC}} \ge 0) \lor (\Delta R_{\text{Telemetry}} > 0 \lor R_{\text{after, Telemetry}} \ge 0.70)\right]$$

---

## 5. Why `pytest` Reports `15 passed, 1 xfailed`

In `tests/test_phase1_and_2.py`, `test_gate2_architectural_security_invariant` is decorated with `@pytest.mark.xfail(strict=True)`:
* **Purpose:** This test asserts that the baseline unpatched repository (`benchmark_target/`) satisfies least-privilege IAM and fallback prefix enforcement.
* **Why `strict=True` Matters:** Because `benchmark_target/` is intentionally vulnerable at `HEAD` so the orchestrator can demonstrate live remediation diffs, this invariant *must* fail on the unpatched baseline. Under `strict=True`, if someone accidentally patches the baseline target directly on `main` (breaking the benchmark), `pytest` will fail the suite (`XPASS(strict)`).

---

## 6. Threat Model, Scope & Limitations

1. **Synthetic Benchmark vs. Production Pipelines:** `benchmark_target/` models a representative Cloud Run + Secret Manager + SecOps pattern. While `verify_patch_in_git_worktree` can evaluate any Git branch or PR commit via `base_ref`, Subagents 01, 02, and 04 currently target Python (`ast`), Terraform (`hcl2`), and structured YAML rules.
2. **Simplified YAML Detection Format vs. Production YARA-L:** `benchmark_target/secops/rules.yaml` uses a declarative YAML schema (`event_type`, `tool_name`, `target_secret_prefix`) rather than full Google SecOps YARA-L 2.0 syntax. Subagent 04 pairs static AST/schema contract checks with a deterministic synthetic event replay evaluator.
3. **Static AST Resolution Boundaries:** Static AST inspection cannot resolve `tool_name` values computed dynamically at runtime (e.g., environment variables or f-strings). When `AgentToolASTVisitor` encounters a non-literal `AuditEvent(tool_name=...)` expression, it records the exact file line and expression in `SubagentReport.open_questions` and applies a conservative uncertainty penalty.
4. **Deterministic Core vs. Optional LLM Enrichment:** All risk scores, graph traversals, and `SplitBrainDelta` classifications are 100% deterministic. Gemini 2.5 (`google-genai`) is used strictly to synthesize human-readable architectural remediation notes when `GEMINI_API_KEY` is present. Seeded evaluation (`evaluate_auditor_precision_recall()`) verifies `1.00` precision and `1.00` recall across true-positive and decoy ASTs.
5. **Untrusted Patch Input Hardening:** Because candidate patches and worktree names may originate from autonomous coding agents, `patch_verifier.py` enforces a strict regex allowlist (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`) and `Path.is_relative_to()` containment before creating or removing worktrees, and `telemetry_validator.py` fails closed (`risk_score = 1.0`) if a patch deletes or corrupts `service.py` or `rules.yaml`.

---

## 7. Quickstart & Deterministic Verification

```powershell
# 1. Create and activate virtual environment (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install pinned dependencies
pip install -r requirements.txt

# 3. Run the 3-part staff-engineering verification gate (Lint, Strict Typecheck, Tests)
ruff check parallax benchmark_target tests
mypy parallax benchmark_target tests
pytest

# 4. Run the interactive CLI Split-Brain simulation
python -m parallax.cli
```

* **Empirical Evidence Artifact:** See `artifacts/parallax_audit_proof.json` for the complete machine-verifiable Pydantic report generated by the live orchestrator.

---

## 8. License

Released under the [MIT License](LICENSE).
