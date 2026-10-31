# Project PARALLAX

**Adversarial Cloud Architecture & Split-Brain Patch Verification Engine for Google Cloud (GCP)**

![Python 3.13](https://img.shields.io/badge/Python-3.13.14-3776AB?logo=python&logoColor=white)
![GCP Terraform](https://img.shields.io/badge/GCP_IaC-Terraform_HCL2-4285F4?logo=googlecloud&logoColor=white)
![Gemini AI](https://img.shields.io/badge/Reasoning-Gemini_2.5_SDK-8E75B2?logo=googlegemini&logoColor=white)
![Typecheck](https://img.shields.io/badge/mypy-strict_100%25_pass-brightgreen)
![Code Style](https://img.shields.io/badge/ruff-checked_&_formatted-brightgreen)
![Tests](https://img.shields.io/badge/pytest-8_passed,_1_xfail-brightgreen)

> *"Why finding vulnerabilities faster won't save you, and what will."*
> — Inspired by the **Google AI Threat Defense** 4-Step Framework (**Prepare, Scan, Remediate, Monitor**).

---

## 1. Executive Summary & The Breakthrough Discovery

Modern security teams are adopting autonomous AI defense platforms—combining cloud exposure mapping (**Wiz**), frontier model code analysis (**Gemini**), automated IDE/CLI code patching (**CodeMender**), and machine-speed runtime detection (**Google Security Operations**).

While studying this paradigm from both a **Google Cloud Architect** and **Offensive Security (Red-Team)** perspective, a critical architectural blind spot emerged: **Cross-Layer Remediation Divergence ("Split-Brain AI Patching")**.

When a vulnerability spans both application code and cloud infrastructure, automated remediation often operates in **silos**:
1. **The Code Silo (IDE/CLI Autofix):** An AI coding assistant rapidly patches a Python dataflow bug in the developer's IDE so unit tests and static code scanners turn green.
2. **The Cloud Infrastructure Silo (Terraform / IAM):** Because the IDE patch does not modify the cloud infrastructure repo, over-permissive Non-Human Identity (NHI) Service Account bindings remain wide open in the GCP graph.
3. **The Runtime Telemetry Silo (Google SecOps):** Minor refactoring inside the AI code patch (such as renaming a tool identifier) silently breaks downstream Cloud Audit Log detection signatures—leaving the "patched" system blinder to attack than before.

**Project PARALLAX** is an autonomous adversarial architecture and purple-team verification engine built to detect, prove, and resolve **Split-Brain AI Remediation** across **Python ASTs**, **GCP Terraform IAM Graphs**, and **Google SecOps Detection Rules** using isolated local **Git Worktrees**.

---

## 2. The 4-Step Defense vs. Adversarial Counter-Framework

Project PARALLAX models the offensive counterpart to each pillar of **Google AI Threat Defense** via four specialized subagents orchestrated by a central main thread:

| Google AI Threat Defense Pillar | Adversarial Counter-Step (Attacker Model) | Project PARALLAX Subagent | Technical Verification Mechanism |
| :--- | :--- | :--- | :--- |
| **01 Prepare** (Harden foundation & build live exposure maps via Wiz) | **01 Infiltrate the Trusted Graph** (Abuse Non-Human Identities & transitive IAM paths) | `Subagent 01: Graph Analyzer` (`parallax/graph_analyzer.py`) | Parses GCP Terraform (`hcl2`) into a `networkx.DiGraph` to trace public Cloud Run ingress to project-wide IAM blast radius. |
| **02 Scan** (Multi-AI Gemini code analysis + Wiz runtime context) | **02 Chain Cross-Context Logic Flaws** (Exploit seams between app AST and cloud IAM) | `Subagent 02: Cross-Layer Auditor` (`parallax/cross_layer_auditor.py`) | Combines Python `ast` dataflow inspection with Gemini 2.5 reasoning and IAM risk context to flag Confused Deputy bypasses. |
| **03 Remediate** (Shrink fixes from weeks to minutes via CodeMender) | **03 Exploit the Supervision & Patch Gap** (Weaponize symptom-only AI code patches) | `Subagent 03: Worktree Patch Verifier` (`parallax/patch_verifier.py`) | Spins up isolated `git worktree` sandboxes to diff candidate fixes across Code, Terraform, and SecOps rules simultaneously. |
| **04 Monitor** (Machine-speed runtime hunting via Google SecOps) | **04 Blend into Agentic Telemetry** (Evade alerts via schema & tool-signature drift) | `Subagent 04: Telemetry Validator` (`parallax/telemetry_validator.py`) | Audits emitted `AuditEvent` AST structures against SecOps YAML rules (`rules.yaml`) to catch silent detection blind spots. |

---

## 3. System & Target Architecture (ASCII Diagrams)

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
| - Allows reading ANY "prod-*" secret across   |   |   tool_name to "..._v2", alerts silently fail!|
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
|  Subagent 01  | ---IAM Risk---> |  Subagent 02  |                 |  Subagent 04  |
| Graph Analyzer|    (0.95)       | AST + Gemini  |                 |SecOps Vlidator|
| (NetworkX/HCL)|                 | Cross-Auditor |                 |  (AST/YAML)   |
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
              | git worktree add --detach                             | git worktree add --detach
              v                                                       v
+-------------------------------------------+   +-------------------------------------------+
| Worktree A: .worktrees/wt-symptom-patch   |   | Worktree B: .worktrees/wt-architectural   |
| (Simulates Fast IDE / AI Code Fix)        |   | (Simulates Cloud Architect Holistic Fix)  |
|-------------------------------------------|   |-------------------------------------------|
| - Fixes Python prefix check (Code = 0.05) |   | - Fixes Python prefix check (Code = 0.05) |
| - Leaves Project IAM open   (IaC  = 0.95) |   | - Scopes Secret IAM in .tf  (IaC  = 0.10) |
| - Drifts tool_name_v2       (Tele = 0.85) |   | - Preserves SecOps contract (Tele = 0.05) |
|                                           |   |                                           |
| => Effective Security Delta : 0.61        |   | => Effective Security Delta : 0.07        |
| => SPLIT-BRAIN DETECTED     : TRUE  [!]   |   | => SPLIT-BRAIN DETECTED     : FALSE [OK]  |
+-------------------------------------------+   +-------------------------------------------+
```

---

## 4. Mathematical Model: Split-Brain Effective Security Delta

```text
Effective_Security_Delta = (0.45 * IaC_Reachability_Risk)
                         + (0.35 * Code_Dataflow_Risk)
                         + (0.20 * Telemetry_Blindspot_Risk)

Split_Brain_Detected     = (Code_Dataflow_Risk < 0.50)
                           AND (IaC_Reachability_Risk >= 0.70 OR Telemetry_Blindspot_Risk >= 0.70)
```

---

## 5. Verified Live CLI Output & Benchmark Results

```text
================================================================
Project PARALLAX: Adversarial Cloud Architecture & Patch Engine
================================================================
Target Workspace: D:\AI EXPERIMENTS\Project PARALLAX
Executing 4-Stage Audit & Git Worktree Patch Simulation...

Overall Posture: CRITICAL_SPLIT_BRAIN_RISK_PROVEN
Total Subagent Reports: 5
  - [Subagent 01: Graph Analyzer] Risk: 0.95 | Findings: 2
  - [Subagent 02: Cross-Layer Code-to-Cloud Auditor] Risk: 0.95 | Findings: 1
  - [Subagent 04: Telemetry & SecOps Validator] Risk: 0.05 | Findings: 0
  - [Subagent 03: Worktree Patch Verifier (wt-symptom-patch)] Risk: 0.61 | Findings: 1
  - [Subagent 03: Worktree Patch Verifier (wt-architectural-patch)] Risk: 0.07 | Findings: 0

--- Split-Brain Remediation Evaluation (Git Worktrees) ---
  * Patch Worktree: baseline-unpatched
    Effective Security Delta : 0.77
    Split-Brain Detected     : False
    Summary                  : [baseline-unpatched] Baseline unpatched state (Residual Index=0.77).

  * Patch Worktree: wt-symptom-patch
    Effective Security Delta : 0.61
    Split-Brain Detected     : True
    Summary                  : [wt-symptom-patch] SPLIT-BRAIN REMEDIATION DETECTED: Fast patch left IaC Risk=0.95, Code Risk=0.05, Telemetry Drift Risk=0.85.

  * Patch Worktree: wt-architectural-patch
    Effective Security Delta : 0.07
    Split-Brain Detected     : False
    Summary                  : [wt-architectural-patch] Full Root-Cause Architectural Remediation verified across Code AST, GCP Terraform IAM, and SecOps Telemetry.
```

---

## 6. Quickstart & Deterministic Verification

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